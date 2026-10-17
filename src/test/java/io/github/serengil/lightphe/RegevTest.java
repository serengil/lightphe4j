package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.serengil.lightphe.commons.Shake128;
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

/** Port of {@code tests/test_regev.py}. */
class RegevTest {

    private static final String ALGORITHM = "Regev";

    /** Bit length of the ciphertext modulus q. */
    private static final int LOG_Q = 50;

    /** Bound of the coefficients of the secret and errors. */
    private static final int ETA = 21;

    private static final LightPHE cs =
            LightPHE.builder().algorithmName(ALGORITHM).keySize(64).build();

    /** Dimension giving about 128-bit security against quantum attacks. */
    private static final LightPHE largeCs =
            LightPHE.builder().algorithmName(ALGORITHM).keySize(2048).build();

    private static LightPHE build(int keySize, BigInteger plaintextLimit) {
        return LightPHE.builder()
                .algorithmName(ALGORITHM)
                .keySize(keySize)
                .plaintextLimit(plaintextLimit)
                .build();
    }

    @Test
    @DisplayName("Regev supports homomorphic addition and scalar multiplication")
    void testApi() {
        BigInteger modulo = cs.cs().plaintextModulo();

        long m1 = 17;
        long m2 = 21;

        Ciphertext c1 = cs.encrypt(m1);
        Ciphertext c2 = cs.encrypt(m2);

        // proof of decryption
        assertThat(cs.decrypt(c1)).isEqualTo(BigInteger.valueOf(m1));
        assertThat(cs.decrypt(c2)).isEqualTo(BigInteger.valueOf(m2));

        // homomorphic addition
        assertThat(cs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(m1 + m2));

        // homomorphic scalar multiplication
        assertThat(cs.decrypt(c1.multiply(m2))).isEqualTo(BigInteger.valueOf(m1 * m2));

        // negative plaintexts and addition wrapping around the plaintext modulo
        Ciphertext c3 = cs.encrypt(-5L);
        assertThat(cs.decrypt(c3)).isEqualTo(modulo.subtract(BigInteger.valueOf(5)));
        assertThat(cs.decrypt(c1.add(c3))).isEqualTo(BigInteger.valueOf(m1 - 5));
        assertThat(cs.decrypt(cs.encrypt(modulo.subtract(BigInteger.ONE)).add(c1)))
                .isEqualTo(BigInteger.valueOf(m1 - 1));

        // re-randomization
        Ciphertext c1Prime = cs.regenerateCiphertext(c1);
        assertThat(c1Prime.value()).isNotEqualTo(c1.value());
        assertThat(cs.decrypt(c1Prime)).isEqualTo(BigInteger.valueOf(m1));

        // unsupported homomorphic operations
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.multiply(c2));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.xor(c2));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.and(c2));
    }

    @Test
    @DisplayName("Regev keys satisfy b = A s + e for small e, with A expanded as in Python")
    void testKeysAreWellFormed() {
        // b = A s + e mod q where e is small. A is expanded from the seed entry by entry.
        int n = cs.cs().keys().publicNumber("n").intValueExact();
        BigInteger q = cs.cs().keys().publicNumber("q");
        BigInteger seed = cs.cs().keys().publicNumber("seed");
        List<BigInteger> b = cs.cs().keys().publicNumbers("b");
        List<BigInteger> s = cs.cs().keys().privateNumbers("s");

        assertThat(q).isEqualTo(BigInteger.TWO.pow(LOG_Q));
        assertThat(b).hasSize(n);
        assertThat(s).hasSize(n);
        assertThat(s)
                .allSatisfy(x -> assertThat(x.abs()).isLessThanOrEqualTo(BigInteger.valueOf(ETA)));

        int width = (LOG_Q + BigInteger.valueOf((long) ETA * n).bitLength() + 7) / 8;
        byte[] seedBytes = new byte[32];
        byte[] raw = seed.toByteArray();
        int copy = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - copy, seedBytes, 32 - copy, copy);
        byte[] stream = Shake128.digest(seedBytes, n * n * width);
        for (int i = 0; i < n; i++) {
            BigInteger dot = BigInteger.ZERO;
            for (int j = 0; j < n; j++) {
                byte[] slot = new byte[width];
                for (int k = 0; k < width; k++) {
                    slot[width - 1 - k] = stream[(i * n + j) * width + k];
                }
                dot = dot.add(new BigInteger(1, slot).mod(q).multiply(s.get(j)));
            }
            BigInteger error = b.get(i).subtract(dot).mod(q);
            if (error.compareTo(q.shiftRight(1)) > 0) {
                error = error.subtract(q);
            }
            assertThat(error.abs()).isLessThanOrEqualTo(BigInteger.valueOf(ETA));
        }
    }

    @Test
    @DisplayName("Regev restores every plaintext of a small space")
    void testAllPlaintextsOfSmallSpace() {
        LightPHE smallCs = build(32, BigInteger.valueOf(16));
        assertThat(smallCs.cs().plaintextModulo()).isEqualTo(BigInteger.valueOf(16));
        for (long m = 0; m < 16; m++) {
            assertThat(smallCs.decrypt(smallCs.encrypt(m))).isEqualTo(BigInteger.valueOf(m));
        }
    }

    @Test
    @DisplayName("Regev rounds the plaintext limit up to a power of 2 within its noise budget")
    void testPlaintextLimit() {
        // rounded up to a power of 2
        assertThat(build(32, BigInteger.valueOf(1000)).cs().plaintextModulo())
                .isEqualTo(BigInteger.valueOf(1024));
        assertThat(build(32, null).cs().plaintextModulo()).isEqualTo(BigInteger.TWO.pow(24));

        LightPHE bigCs = build(32, BigInteger.TWO.pow(32));
        BigInteger m = BigInteger.TWO.pow(32).subtract(BigInteger.valueOf(7));
        assertThat(bigCs.decrypt(bigCs.encrypt(m))).isEqualTo(m);

        // no room for noise
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> build(32, BigInteger.TWO.pow(45)))
                .withMessageContaining("too large for Regev");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> build(4, null))
                .withMessageContaining("too small for Regev");
    }

    @Test
    @DisplayName("Regev has room for many additions and multiplications with constants")
    void testNoiseBudget() {
        BigInteger modulo = cs.cs().plaintextModulo();
        long m = 4567;
        Ciphertext c = cs.encrypt(m);

        // many additions
        Ciphertext total = cs.encrypt(0);
        for (int i = 0; i < 1000; i++) {
            total = total.add(c);
        }
        assertThat(cs.decrypt(total)).isEqualTo(BigInteger.valueOf(1000 * m).mod(modulo));

        // large and negative constants
        assertThat(cs.decrypt(c.multiply(4000L)))
                .isEqualTo(BigInteger.valueOf(4000 * m).mod(modulo));
        assertThat(cs.decrypt(c.multiply(-3L))).isEqualTo(BigInteger.valueOf(-3 * m).mod(modulo));
        assertThat(cs.decrypt(c.multiply(modulo.subtract(BigInteger.ONE))))
                .isEqualTo(BigInteger.valueOf(-m).mod(modulo));

        // random linear combinations
        Random random = new Random();
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
            assertThat(cs.decrypt(result)).isEqualTo(BigInteger.valueOf(expected).mod(modulo));
        }
    }

    @Test
    @DisplayName("Regev does not support floats and tensors")
    void testFloatsAndTensorsAreNotSupported() {
        Ciphertext c = cs.encrypt(5);
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.encrypt(1.5))
                .withMessageContaining("Regev does not support float");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.encryptTensor(List.of(1, 2, 3)))
                .withMessageContaining("Regev does not support float");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> c.multiply(1.5))
                .withMessageContaining("Regev does not support float");
    }

    @Test
    @DisplayName("Regev works with predefined keys")
    void testApiWithPredefinedKeys() {
        LightPHE restoredCs =
                LightPHE.builder().algorithmName(ALGORITHM).keys(cs.cs().keys()).build();
        long m1 = 11;
        long m2 = 7;
        Ciphertext c1 = cs.encrypt(m1);
        Ciphertext c2 = restoredCs.encrypt(m2);
        assertThat(restoredCs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(m1 + m2));
        assertThat(cs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(m1 + m2));
    }

    @Test
    @DisplayName("Regev works with exported public keys")
    void testExportedKeys(@TempDir Path tempDir) {
        Path publicKeyFile = tempDir.resolve("public.txt");
        cs.exportKeys(publicKeyFile, true);

        LightPHE publicCs =
                LightPHE.builder().algorithmName(ALGORITHM).keyFile(publicKeyFile).build();
        Ciphertext c = publicCs.encrypt(42).multiply(2L);
        assertThat(cs.decrypt(c)).isEqualTo(BigInteger.valueOf(84));

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> publicCs.decrypt(c))
                .withMessageContaining("private key");
    }

    @Test
    @DisplayName("Regev works with dimension 2048")
    void testLargeKeys() {
        BigInteger modulo = largeCs.cs().plaintextModulo();
        long m1 = 1234567;
        long m2 = 7654321;
        Ciphertext c1 = largeCs.encrypt(m1);
        Ciphertext c2 = largeCs.encrypt(m2);
        assertThat(((TupleValue) c1.value()).size()).isEqualTo(2048 + 1);

        assertThat(largeCs.decrypt(c1)).isEqualTo(BigInteger.valueOf(m1));
        assertThat(largeCs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(m1 + m2));
        assertThat(largeCs.decrypt(c1.multiply(1000L)))
                .isEqualTo(BigInteger.valueOf(m1 * 1000).mod(modulo));
        assertThat(largeCs.decrypt(c1.multiply(-1000L).add(c2.multiply(3L))))
                .isEqualTo(BigInteger.valueOf(-1000 * m1 + 3 * m2).mod(modulo));

        Ciphertext total = largeCs.encrypt(0);
        for (int i = 0; i < 1000; i++) {
            total = total.add(c1);
        }
        assertThat(largeCs.decrypt(total)).isEqualTo(BigInteger.valueOf(1000 * m1).mod(modulo));
    }

    @Test
    @DisplayName("Regev runs the example in the readme")
    void testReadmeExample() {
        Ciphertext c1 = largeCs.encrypt(1500);
        Ciphertext c2 = largeCs.encrypt(2500);

        assertThat(largeCs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(4000));
        assertThat(largeCs.decrypt(c1.multiply(3L))).isEqualTo(BigInteger.valueOf(4500));
    }
}
