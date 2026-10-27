package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.serengil.lightphe.commons.MathUtils;
import io.github.serengil.lightphe.cryptosystems.MLKEM;
import io.github.serengil.lightphe.model.Ciphertext;
import io.github.serengil.lightphe.model.value.TupleValue;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Port of {@code tests/test_mlkem.py}. Structure of keys and noise of ciphertexts are tested in
 * {@code cryptosystems.LatticeInternalsTest}.
 */
class MlKemTest {

    private static LightPHE build(int parameterSet) {
        return LightPHE.builder().algorithmName("ML-KEM").keySize(parameterSet).build();
    }

    private static BigInteger randomMessage() {
        return MathUtils.getRandomBits(256);
    }

    @ParameterizedTest(name = "ML-KEM-{0}")
    @ValueSource(ints = {512, 768, 1024})
    @DisplayName("ML-KEM is homomorphic with respect to the exclusive or")
    void testApi(int parameterSet) {
        LightPHE cs = build(parameterSet);
        Ciphertext c1 = null;
        BigInteger m1 = null;
        for (int round = 0; round < 5; round++) {
            m1 = randomMessage();
            BigInteger m2 = randomMessage();
            c1 = cs.encrypt(m1);
            Ciphertext c2 = cs.encrypt(m2);

            // proof of decryption
            assertThat(cs.decrypt(c1)).isEqualTo(m1);
            assertThat(cs.decrypt(c2)).isEqualTo(m2);

            // homomorphic exclusive or
            assertThat(cs.decrypt(c1.xor(c2))).isEqualTo(m1.xor(m2));
            assertThat(cs.decrypt(c1.xor(c1))).isZero();
        }

        // edge plaintexts and plaintexts exceeding 256 bits
        BigInteger limit = BigInteger.ONE.shiftLeft(256);
        for (BigInteger m :
                List.of(
                        BigInteger.ZERO,
                        BigInteger.ONE,
                        BigInteger.ONE.shiftLeft(255),
                        limit.subtract(BigInteger.ONE))) {
            assertThat(cs.decrypt(cs.encrypt(m))).isEqualTo(m);
        }
        assertThat(cs.decrypt(cs.encrypt(limit.add(BigInteger.valueOf(5)))))
                .isEqualTo(BigInteger.valueOf(5));
        assertThat(cs.decrypt(cs.encrypt(-1L))).isEqualTo(limit.subtract(BigInteger.ONE));

        // re-randomization
        Ciphertext c1Prime = cs.regenerateCiphertext(c1);
        assertThat(c1Prime.value()).isNotEqualTo(c1.value());
        assertThat(cs.decrypt(c1Prime)).isEqualTo(m1);

        // unsupported homomorphic operations
        Ciphertext c = c1;
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c.add(c));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c.multiply(c));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c.multiply(3));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c.and(c));
    }

    @ParameterizedTest(name = "ML-KEM-{0}")
    @ValueSource(ints = {512, 768, 1024})
    @DisplayName("Parameters and ciphertext shapes follow FIPS 203")
    void testParametersOfFips203(int parameterSet) {
        // FIPS 203, table 2
        assertThat(MLKEM.Q).isEqualTo(3329);
        assertThat(MLKEM.N).isEqualTo(256);
        assertThat(MLKEM.PARAMETER_SETS.get(512)).isEqualTo(new MLKEM.ParameterSet(2, 3, 2));
        assertThat(MLKEM.PARAMETER_SETS.get(768)).isEqualTo(new MLKEM.ParameterSet(3, 2, 2));
        assertThat(MLKEM.PARAMETER_SETS.get(1024)).isEqualTo(new MLKEM.ParameterSet(4, 2, 2));

        LightPHE cs = build(parameterSet);
        int k = MLKEM.PARAMETER_SETS.get(parameterSet).k();
        List<TupleValue> polynomials = ((TupleValue) cs.encrypt(1).value()).asTuples();
        assertThat(polynomials).hasSize(k + 1);
        for (TupleValue polynomial : polynomials) {
            assertThat(polynomial.asIntegers())
                    .hasSize(MLKEM.N)
                    .allMatch(x -> x.signum() >= 0 && x.intValueExact() < MLKEM.Q);
        }
    }

    @ParameterizedTest(name = "ML-KEM-{0}")
    @ValueSource(ints = {512, 768, 1024})
    @DisplayName("Exclusive or of 6 ciphertexts is decrypted correctly")
    void testExclusiveOrOfManyCiphertexts(int parameterSet) {
        // failure probability of combining 6 ciphertexts is about 2^-36 or less
        LightPHE cs = build(parameterSet);
        BigInteger expected = randomMessage();
        Ciphertext total = cs.encrypt(expected);
        for (int i = 1; i < 6; i++) {
            BigInteger m = randomMessage();
            total = total.xor(cs.encrypt(m));
            expected = expected.xor(m);
        }
        assertThat(cs.decrypt(total)).isEqualTo(expected);
    }

    @Test
    @DisplayName("Floats, tensors and unknown parameter sets are rejected")
    void testFloatsAndTensorsAreNotSupported() {
        LightPHE cs = build(512);
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.encrypt(1.5))
                .withMessageContaining("ML-KEM does not support float");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.encryptTensor(List.of(1, 2, 3)))
                .withMessageContaining("ML-KEM does not support float");

        for (int keySize : new int[] {256, 1000, 2048}) {
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> build(keySize))
                    .withMessageContaining("parameter sets of ML-KEM");
        }
    }

    @Test
    @DisplayName("Default parameter set is ML-KEM-768")
    void testDefaultParameterSet() {
        LightPHE cs = LightPHE.builder().algorithmName("ML-KEM").build();
        assertThat(cs.cs().keys().publicNumber("parameter_set")).isEqualTo(BigInteger.valueOf(768));
    }

    @Test
    @DisplayName("Exported keys are restored")
    void testExportedKeys(@TempDir Path tmp) {
        LightPHE cs = build(768);
        Path publicFile = tmp.resolve("public.txt");
        Path privateFile = tmp.resolve("private.txt");
        cs.exportKeys(publicFile, true);
        cs.exportKeys(privateFile);

        BigInteger m1 = randomMessage();
        BigInteger m2 = randomMessage();
        LightPHE publicCs = LightPHE.builder().algorithmName("ML-KEM").keyFile(publicFile).build();
        Ciphertext c = publicCs.encrypt(m1).xor(publicCs.encrypt(m2));

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> publicCs.decrypt(c))
                .withMessageContaining("private key");

        LightPHE restored = LightPHE.builder().algorithmName("ML-KEM").keyFile(privateFile).build();
        assertThat(restored.decrypt(c)).isEqualTo(m1.xor(m2));
        assertThat(cs.decrypt(c)).isEqualTo(m1.xor(m2));
    }
}
