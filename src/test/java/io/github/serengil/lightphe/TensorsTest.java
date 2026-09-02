package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.serengil.lightphe.commons.PheUtils;
import io.github.serengil.lightphe.model.EncryptedTensor;
import io.github.serengil.lightphe.model.Fraction;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Port of {@code tests/test_tensors.py}. */
class TensorsTest {

    private static final double THRESHOLD = 1;

    private static final Map<String, LightPHE> cryptosystems = new HashMap<>();

    private static LightPHE buildCryptosystem(String algorithmName) {
        return buildCryptosystem(algorithmName, algorithmName, 50);
    }

    private static synchronized LightPHE buildCryptosystem(
            String cacheKey, String algorithmName, int keySize) {
        return cryptosystems.computeIfAbsent(
                cacheKey,
                key -> LightPHE.builder().algorithmName(algorithmName).keySize(keySize).build());
    }

    /**
     * Reproduces the Python helper that maps a negative float onto the positive representative the
     * cryptosystem actually restores.
     */
    private static double convertNegativeFloatToInt(double value, BigInteger modulo) {
        double wrapped = value % modulo.doubleValue();
        if (wrapped < 0) {
            wrapped += modulo.doubleValue();
        }
        PheUtils.Fractionized fraction = PheUtils.fractionize(wrapped, modulo, 5);
        return fraction.dividend().divide(fraction.divisor()).doubleValue();
    }

    @Test
    @DisplayName("A tensor survives an encrypt and decrypt round trip")
    void testTensorEncryption() {
        LightPHE cs = buildCryptosystem("Paillier");

        List<Number> tensor = List.of(1.005, 2.05, 3.005, 4.005, -5.05, 6, 7.003005, -3.5 * 7.002);

        EncryptedTensor encryptedTensors = cs.encryptTensor(tensor);
        List<Double> decryptedTensors = cs.decryptTensor(encryptedTensors);

        assertThat(decryptedTensors).hasSameSizeAs(tensor);
        for (int i = 0; i < decryptedTensors.size(); i++) {
            assertThat(Math.abs(tensor.get(i).doubleValue() - decryptedTensors.get(i)))
                    .isLessThanOrEqualTo(THRESHOLD);
        }
    }

    @Test
    @DisplayName("Two encrypted tensors multiply element-wise under RSA")
    void testHomomorphicMultiplication() {
        LightPHE cs = buildCryptosystem("RSA");

        List<Number> t1 = List.of(1.005, 2.05, -3.5, 3.1, -4);
        List<Number> t2 = List.of(5, 6.2, -7.002, -7.1, 8.02);

        EncryptedTensor c1 = cs.encryptTensor(t1);
        EncryptedTensor c2 = cs.encryptTensor(t2);

        EncryptedTensor c3 = c1.multiply(c2);

        List<Double> restored = cs.decryptTensor(c3);
        for (int i = 0; i < restored.size(); i++) {
            double expected = t1.get(i).doubleValue() * t2.get(i).doubleValue();
            assertThat(Math.abs(expected - restored.get(i))).isLessThan(THRESHOLD);
        }

        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.add(c2));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c2.multiply(2L));
    }

    @Test
    @DisplayName("A tensor scales by a positive integer constant")
    void testHomomorphicMultiplyByAPositiveConstant() {
        LightPHE cs = buildCryptosystem("Paillier");

        List<Number> t1 = List.of(5, 6.2, 7.002, 7.002, 8.02);
        long constant = 2;
        EncryptedTensor c1 = cs.encryptTensor(t1);

        List<Double> t2 = cs.decryptTensor(c1.multiply(constant));
        for (int i = 0; i < t2.size(); i++) {
            assertThat(Math.abs(t1.get(i).doubleValue() * constant - t2.get(i)))
                    .isLessThan(THRESHOLD);
        }
    }

    @Test
    @DisplayName("A tensor scales by a negative integer constant")
    void testHomomorphicMultiplyByANegativeConstant() {
        LightPHE cs = buildCryptosystem("Paillier");

        List<Number> t1 = List.of(5, 6.2, 7.002, 7.002, 8.02);
        long constant = -2;
        EncryptedTensor c1 = cs.encryptTensor(t1);

        List<Double> t2 = cs.decryptTensor(c1.multiply(constant));
        for (int i = 0; i < t2.size(); i++) {
            assertThat(Math.abs(t1.get(i).doubleValue() * constant - t2.get(i)))
                    .isLessThan(THRESHOLD);
        }
    }

    @Test
    @DisplayName("A tensor scales by a positive fractional constant")
    void testHomomorphicMultiplyWithPositiveFloatConstant() {
        LightPHE cs = buildCryptosystem("Paillier");

        List<Number> t1 = List.of(10000.0, 15000, 20000);
        double constant = 1.05;
        EncryptedTensor c1 = cs.encryptTensor(t1);

        List<Double> t2 = cs.decryptTensor(c1.multiply(constant));
        for (int i = 0; i < t2.size(); i++) {
            assertThat(Math.abs(t1.get(i).doubleValue() * constant - t2.get(i)))
                    .isLessThan(THRESHOLD);
        }
    }

    @Test
    @DisplayName("A tensor scales by a negative fractional constant")
    void testHomomorphicMultiplyWithNegativeFloatConstant() {
        LightPHE cs = buildCryptosystem("Paillier");

        List<Number> t1 = List.of(10000.0, 15000, 20000);
        double constant = -1.05;
        EncryptedTensor c1 = cs.encryptTensor(t1);

        List<Double> t2 = cs.decryptTensor(c1.multiply(constant));
        for (int i = 0; i < t2.size(); i++) {
            assertThat(Math.abs(t1.get(i).doubleValue() * constant - t2.get(i)))
                    .isLessThan(THRESHOLD);
        }
    }

    @Test
    @DisplayName("Two encrypted tensors add element-wise")
    void testHomomorphicAddition() {
        LightPHE cs = LightPHE.builder().algorithmName("Paillier").keySize(30).build();

        List<Number> t1 = List.of(1.005, 2.05, 3.6, -4, 4.02, -3.5);
        List<Number> t2 = List.of(5, 6.2, -7.5, 8.02, -8.02, -4.5);

        EncryptedTensor c1 = cs.encryptTensor(t1);
        EncryptedTensor c2 = cs.encryptTensor(t2);

        List<Double> restored = cs.decryptTensor(c1.add(c2));

        for (int i = 0; i < restored.size(); i++) {
            double a = t1.get(i).doubleValue();
            double b = t2.get(i).doubleValue();

            if ((a >= 0 && b >= 0) || (a < 0 && b < 0) || (a + b >= 0)) {
                assertThat(Math.abs(a + b - restored.get(i))).isLessThan(THRESHOLD);
            } else {
                double expected = convertNegativeFloatToInt(a + b, cs.cs().plaintextModulo());
                assertThat(Math.abs(expected - restored.get(i))).isLessThan(THRESHOLD);
            }
        }

        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.multiply(c2));
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"Paillier", "Damgard-Jurik"})
    @DisplayName("An encrypted tensor multiplies with, and dots against, a plain tensor")
    void testForIntegerTensor(String algorithmName) {
        // The Python original reuses the shared 50-bit cryptosystem here. The dot product below
        // needs about 40 bits of message space (the sum, scaled by 10^precision twice), and a
        // 50-bit key draws its two primes uniformly, so roughly 1% of runs end up with a modulus
        // too small to hold the result and the assertion fails for reasons that have nothing to do
        // with the code under test. Giving this one test enough headroom removes the coin flip
        // without weakening what it checks.
        LightPHE cs = buildCryptosystem(algorithmName + "@100", algorithmName, 100);

        // suppose that these are normalized vectors
        List<Number> a = List.of(7.11, 5.22, 5.33, 2.44, 3.55, 4.66);
        List<Number> b = List.of(5.66, 3.77, 2.88, 4, 0, 5.99);

        double expectedSimilarity = 0;
        for (int i = 0; i < a.size(); i++) {
            expectedSimilarity += a.get(i).doubleValue() * b.get(i).doubleValue();
        }

        // guard the precondition explicitly, so a future change fails with a clear reason
        BigInteger scaledSimilarity =
                BigInteger.valueOf((long) Math.ceil(expectedSimilarity))
                        .multiply(BigInteger.TEN.pow(2 * cs.precision()));
        assertThat(cs.cs().plaintextModulo())
                .as("the message space must hold the scaled dot product")
                .isGreaterThan(scaledSimilarity);

        EncryptedTensor encA = cs.encryptTensor(a);

        // we expect to have the same divisor for all items
        List<Fraction> fractions = encA.fractions();
        for (Fraction fraction : fractions.subList(1, fractions.size())) {
            assertThat(fraction.divisor()).isEqualTo(fractions.get(0).divisor());
        }

        List<Double> aTimesB = cs.decryptTensor(encA.multiply(b));
        for (int i = 0; i < a.size(); i++) {
            double expected = a.get(i).doubleValue() * b.get(i).doubleValue();
            assertThat(Math.abs(expected - aTimesB.get(i)))
                    .as("Expected %s, got %s", expected, aTimesB.get(i))
                    .isLessThan(0.1);
        }

        // dot product
        List<Double> decryptedSimilarities = cs.decryptTensor(encA.matmul(b));
        assertThat(decryptedSimilarities).isNotEmpty();
        double decryptedSimilarity = decryptedSimilarities.get(0);

        assertThat(Math.abs(decryptedSimilarity - expectedSimilarity))
                .as("expected %s but got %s", expectedSimilarity, decryptedSimilarity)
                .isLessThan(0.1);
    }
}
