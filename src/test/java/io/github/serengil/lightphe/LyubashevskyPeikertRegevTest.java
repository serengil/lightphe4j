package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.serengil.lightphe.model.Ciphertext;
import io.github.serengil.lightphe.model.value.TupleValue;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Port of {@code tests/test_lyubashevskypeikertregev.py}. Structure of keys and ciphertexts is
 * tested in {@code cryptosystems.LatticeInternalsTest}.
 */
class LyubashevskyPeikertRegevTest {

    private static final String ALGORITHM = "Lyubashevsky-Peikert-Regev";

    private static final LightPHE cs =
            LightPHE.builder().algorithmName(ALGORITHM).keySize(64).build();

    private static LightPHE build(int keySize, BigInteger plaintextLimit) {
        return LightPHE.builder()
                .algorithmName(ALGORITHM)
                .keySize(keySize)
                .plaintextLimit(plaintextLimit)
                .build();
    }

    private static BigInteger big(long value) {
        return BigInteger.valueOf(value);
    }

    @Test
    @DisplayName("Lyubashevsky-Peikert-Regev supports addition and scalar multiplication")
    void testApi() {
        BigInteger modulo = cs.cs().plaintextModulo();
        long m1 = 17;
        long m2 = 21;
        Ciphertext c1 = cs.encrypt(m1);
        Ciphertext c2 = cs.encrypt(m2);

        // proof of decryption
        assertThat(cs.decrypt(c1)).isEqualTo(big(m1));
        assertThat(cs.decrypt(c2)).isEqualTo(big(m2));

        // homomorphic addition
        assertThat(cs.decrypt(c1.add(c2))).isEqualTo(big(m1 + m2));

        // homomorphic scalar multiplication
        assertThat(cs.decrypt(c1.multiply(m2))).isEqualTo(big(m1 * m2));

        // negative plaintexts and addition wrapping around the plaintext modulo
        Ciphertext c3 = cs.encrypt(-5L);
        assertThat(cs.decrypt(c3)).isEqualTo(modulo.subtract(big(5)));
        assertThat(cs.decrypt(c1.add(c3))).isEqualTo(big(m1 - 5));
        assertThat(cs.decrypt(cs.encrypt(modulo.subtract(BigInteger.ONE)).add(c1)))
                .isEqualTo(big(m1 - 1));

        // re-randomization
        Ciphertext c1Prime = cs.regenerateCiphertext(c1);
        assertThat(c1Prime.value()).isNotEqualTo(c1.value());
        assertThat(cs.decrypt(c1Prime)).isEqualTo(big(m1));

        // unsupported homomorphic operations
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.multiply(c2));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.xor(c2));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.and(c2));
    }

    @Test
    @DisplayName("Every plaintext of a small plaintext space is restored")
    void testAllPlaintextsOfSmallSpace() {
        LightPHE small = build(32, big(16));
        assertThat(small.cs().plaintextModulo()).isEqualTo(big(16));
        for (long m = 0; m < 16; m++) {
            assertThat(small.decrypt(small.encrypt(m))).isEqualTo(big(m));
        }
    }

    @Test
    @DisplayName("Plaintext limit is rounded up to a power of 2 and must leave room for noise")
    void testPlaintextLimit() {
        assertThat(build(32, big(1000)).cs().plaintextModulo()).isEqualTo(big(1024));
        assertThat(build(32, null).cs().plaintextModulo()).isEqualTo(BigInteger.ONE.shiftLeft(24));

        LightPHE big = build(32, BigInteger.ONE.shiftLeft(32));
        BigInteger m = BigInteger.ONE.shiftLeft(32).subtract(big(7));
        assertThat(big.decrypt(big.encrypt(m))).isEqualTo(m);

        // no room for noise
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> build(32, BigInteger.ONE.shiftLeft(45)))
                .withMessageContaining("too large for Lyubashevsky-Peikert-Regev");
    }

    @ParameterizedTest
    @ValueSource(ints = {4, 48, 100})
    @DisplayName("Ring degree must be a power of 2")
    void testRingDegreeMustBePowerOfTwo(int keySize) {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> build(keySize, null))
                .withMessageContaining("must be a power of 2");
    }

    @Test
    @DisplayName("Noise budget allows many additions and large constants")
    void testNoiseBudget() {
        BigInteger modulo = cs.cs().plaintextModulo();
        long m = 4567;
        Ciphertext c = cs.encrypt(m);

        // many additions
        Ciphertext total = cs.encrypt(0);
        for (int i = 0; i < 1000; i++) {
            total = total.add(c);
        }
        assertThat(cs.decrypt(total)).isEqualTo(big(1000 * m).mod(modulo));

        // large and negative constants
        assertThat(cs.decrypt(c.multiply(4000))).isEqualTo(big(4000 * m).mod(modulo));
        assertThat(cs.decrypt(c.multiply(-3))).isEqualTo(big(-3 * m).mod(modulo));
        assertThat(cs.decrypt(c.multiply(modulo.subtract(BigInteger.ONE))))
                .isEqualTo(big(-m).mod(modulo));

        // random linear combinations
        Random random = new Random(0);
        for (int round = 0; round < 20; round++) {
            List<Long> values = new ArrayList<>();
            List<Long> weights = new ArrayList<>();
            for (int i = 0; i < 5; i++) {
                values.add((long) random.nextInt(1001));
                weights.add((long) random.nextInt(101) - 50);
            }
            Ciphertext result = cs.encrypt(values.get(0)).multiply(weights.get(0));
            long expected = values.get(0) * weights.get(0);
            for (int i = 1; i < 5; i++) {
                result = result.add(cs.encrypt(values.get(i)).multiply(weights.get(i)));
                expected += values.get(i) * weights.get(i);
            }
            assertThat(cs.decrypt(result)).isEqualTo(big(expected).mod(modulo));
        }
    }

    @Test
    @DisplayName("Floats and tensors are not supported")
    void testFloatsAndTensorsAreNotSupported() {
        Ciphertext c = cs.encrypt(5);
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.encrypt(1.5))
                .withMessageContaining("Lyubashevsky-Peikert-Regev does not support float");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.encryptTensor(List.of(1, 2, 3)))
                .withMessageContaining("Lyubashevsky-Peikert-Regev does not support float");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> c.multiply(1.5))
                .withMessageContaining("Lyubashevsky-Peikert-Regev does not support float");
    }

    @Test
    @DisplayName("Predefined keys work across cryptosystems")
    void testApiWithPredefinedKeys() {
        LightPHE restored =
                LightPHE.builder().algorithmName(ALGORITHM).keys(cs.cs().keys()).build();
        Ciphertext c1 = cs.encrypt(11);
        Ciphertext c2 = restored.encrypt(7);
        assertThat(restored.decrypt(c1.add(c2))).isEqualTo(big(18));
        assertThat(cs.decrypt(c1.add(c2))).isEqualTo(big(18));
    }

    @Test
    @DisplayName("Exported public key encrypts but cannot decrypt")
    void testExportedKeys(@TempDir Path tmp) {
        Path publicFile = tmp.resolve("public.txt");
        cs.exportKeys(publicFile, true);

        LightPHE publicCs = LightPHE.builder().algorithmName(ALGORITHM).keyFile(publicFile).build();
        Ciphertext c = publicCs.encrypt(42).multiply(2);
        assertThat(cs.decrypt(c)).isEqualTo(big(84));

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> publicCs.decrypt(c))
                .withMessageContaining("private key");
    }

    @Test
    @DisplayName("Degree 2048 keys give about 128-bit security")
    void testLargeKeys() {
        LightPHE large = LightPHE.builder().algorithmName(ALGORITHM).keySize(2048).build();
        BigInteger modulo = large.cs().plaintextModulo();
        long m1 = 1234567;
        long m2 = 7654321;
        Ciphertext c1 = large.encrypt(m1);
        Ciphertext c2 = large.encrypt(m2);
        assertThat(((TupleValue) c1.value()).size()).isEqualTo(2048 + 1);

        assertThat(large.decrypt(c1)).isEqualTo(big(m1));
        assertThat(large.decrypt(c1.add(c2))).isEqualTo(big(m1 + m2));
        assertThat(large.decrypt(c1.multiply(1000))).isEqualTo(big(m1 * 1000).mod(modulo));
        assertThat(large.decrypt(c1.multiply(-1000).add(c2.multiply(3))))
                .isEqualTo(big(-1000 * m1 + 3 * m2).mod(modulo));

        Ciphertext total = large.encrypt(0);
        for (int i = 0; i < 1000; i++) {
            total = total.add(c1);
        }
        assertThat(large.decrypt(total)).isEqualTo(big(1000 * m1).mod(modulo));
    }
}
