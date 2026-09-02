package io.github.serengil.lightphe.commons;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.math.BigInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Direct coverage for the plaintext conversions. The expected values were taken from the Python
 * implementation, whose {@code Decimal} arithmetic this class reproduces with {@link
 * java.math.BigDecimal}.
 */
class PheUtilsTest {

    private static final BigInteger MODULO = BigInteger.valueOf(1_000_003);

    @ParameterizedTest(name = "str({0}) has {1} decimal places")
    @CsvSource({
        "1.05, 2",
        "1.005, 3",
        "1.0, 1",
        "10000.0, 1",
        "7.003005, 6",
        "0.5, 1",
    })
    @DisplayName("Decimal places are counted from the shortest representation, as Python does")
    void testDecimalPlaces(double value, int expected) {
        assertThat(PheUtils.decimalPlaces(value)).isEqualTo(expected);
    }

    @Test
    @DisplayName("Fractionizing truncates the exact binary value, matching Python's Decimal")
    void testFractionizeDerivesScale() {
        // Decimal(1.005) is 1.00499999999999989... so int(Decimal(1.005) * 1000) is 1004
        PheUtils.Fractionized fraction = PheUtils.fractionize(1.005, MODULO);
        assertThat(fraction.divisor()).isEqualTo(BigInteger.valueOf(1000));
        assertThat(fraction.dividend()).isEqualTo(BigInteger.valueOf(1004));

        PheUtils.Fractionized exact = PheUtils.fractionize(1.05, MODULO);
        assertThat(exact.divisor()).isEqualTo(BigInteger.valueOf(100));
        assertThat(exact.dividend()).isEqualTo(BigInteger.valueOf(105));
    }

    @Test
    @DisplayName("An explicit precision fixes the scaling factor")
    void testFractionizeWithPrecision() {
        PheUtils.Fractionized fraction = PheUtils.fractionize(1.05, MODULO, 5);
        assertThat(fraction.divisor()).isEqualTo(BigInteger.valueOf(100000));
        assertThat(fraction.dividend()).isEqualTo(BigInteger.valueOf(105000));
    }

    @Test
    @DisplayName("The dividend is reduced into the message space")
    void testFractionizeReducesModuloThePlaintextSpace() {
        BigInteger small = BigInteger.valueOf(97);
        PheUtils.Fractionized fraction = PheUtils.fractionize(1.05, small, 5);
        assertThat(fraction.dividend()).isEqualTo(BigInteger.valueOf(105000).mod(small));
    }

    @Test
    @DisplayName("An integer is normalised by reduction")
    void testNormalizeInteger() {
        assertThat(PheUtils.normalizeInput(BigInteger.valueOf(17), MODULO))
                .isEqualTo(BigInteger.valueOf(17));

        // values above the modulus wrap around
        assertThat(PheUtils.normalizeInput(MODULO.add(BigInteger.TEN), MODULO))
                .isEqualTo(BigInteger.TEN);

        // negative values land in the upper half of the message space
        assertThat(PheUtils.normalizeInput(BigInteger.valueOf(-1), MODULO))
                .isEqualTo(MODULO.subtract(BigInteger.ONE));
    }

    @Test
    @DisplayName("A real value is normalised to dividend times the inverse divisor")
    void testNormalizeReal() {
        BigInteger normalized = PheUtils.normalizeInput(1.05, MODULO);

        BigInteger expected =
                BigInteger.valueOf(105)
                        .multiply(BigInteger.valueOf(100).modInverse(MODULO))
                        .mod(MODULO);
        assertThat(normalized).isEqualTo(expected);

        // and it multiplies back out to the original value
        assertThat(normalized.multiply(BigInteger.valueOf(100)).mod(MODULO))
                .isEqualTo(BigInteger.valueOf(105));
    }

    @Test
    @DisplayName("A negative real value is rejected, as it is in the reference implementation")
    void testNormalizeNegativeRealIsRejected() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> PheUtils.normalizeInput(-1.05, MODULO))
                .withMessageContaining("negative not implemented yet");
    }
}
