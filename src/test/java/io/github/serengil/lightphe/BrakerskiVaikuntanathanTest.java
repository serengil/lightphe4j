package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.serengil.lightphe.commons.MathUtils;
import io.github.serengil.lightphe.model.Ciphertext;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Port of {@code tests/test_brakerskivaikuntanathan.py}. The tests reaching into the polynomial
 * arithmetic live in {@code cryptosystems.BrakerskiVaikuntanathanPolynomialTest}.
 */
class BrakerskiVaikuntanathanTest {

    private static final String ALGORITHM = "Brakerski-Vaikuntanathan";

    private static final LightPHE cs =
            LightPHE.builder().algorithmName(ALGORITHM).keySize(64).build();

    /** Ring degree giving about 128-bit security against quantum attacks. */
    private static final LightPHE largeCs =
            LightPHE.builder().algorithmName(ALGORITHM).keySize(4096).build();

    private static LightPHE build(int keySize, BigInteger plaintextLimit) {
        return LightPHE.builder()
                .algorithmName(ALGORITHM)
                .keySize(keySize)
                .plaintextLimit(plaintextLimit)
                .build();
    }

    @Test
    @DisplayName("Brakerski-Vaikuntanathan supports addition, one multiplication and constants")
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

        // homomorphic multiplication
        assertThat(cs.decrypt(c1.multiply(c2))).isEqualTo(BigInteger.valueOf(m1 * m2));

        // homomorphic scalar multiplication
        assertThat(cs.decrypt(c1.multiply(m2))).isEqualTo(BigInteger.valueOf(m1 * m2));

        // negative plaintexts and addition wrapping around the plaintext modulo
        Ciphertext c3 = cs.encrypt(-5L);
        assertThat(cs.decrypt(c3)).isEqualTo(modulo.subtract(BigInteger.valueOf(5)));
        assertThat(cs.decrypt(c1.add(c3))).isEqualTo(BigInteger.valueOf(m1 - 5));
        assertThat(cs.decrypt(c1.multiply(c3)))
                .isEqualTo(modulo.subtract(BigInteger.valueOf(5 * m1)));
        assertThat(cs.decrypt(cs.encrypt(modulo.subtract(BigInteger.ONE)).add(c1)))
                .isEqualTo(BigInteger.valueOf(m1 - 1));

        // re-randomization
        Ciphertext c1Prime = cs.regenerateCiphertext(c1);
        assertThat(c1Prime.value()).isNotEqualTo(c1.value());
        assertThat(cs.decrypt(c1Prime)).isEqualTo(BigInteger.valueOf(m1));

        // unsupported homomorphic operations
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.xor(c2));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.and(c2));
    }

    @Test
    @DisplayName("Brakerski-Vaikuntanathan evaluates degree-2 functions")
    void testDegree2Functions() {
        BigInteger modulo = cs.cs().plaintextModulo();
        BigInteger upper = modulo.subtract(BigInteger.ONE);
        for (int round = 0; round < 50; round++) {
            BigInteger x = MathUtils.randomInt(BigInteger.ZERO, upper);
            BigInteger y = MathUtils.randomInt(BigInteger.ZERO, upper);
            BigInteger z = MathUtils.randomInt(BigInteger.ZERO, upper);
            BigInteger k = MathUtils.randomInt(BigInteger.ZERO, upper);
            Ciphertext cx = cs.encrypt(x);
            Ciphertext cy = cs.encrypt(y);
            Ciphertext cz = cs.encrypt(z);

            assertThat(cs.decrypt(cx.multiply(cx))).isEqualTo(x.multiply(x).mod(modulo));

            // product of sums, sums of products, and mixing products with fresh ciphertexts
            assertThat(cs.decrypt(cx.add(cy).multiply(cz)))
                    .isEqualTo(x.add(y).multiply(z).mod(modulo));
            assertThat(cs.decrypt(cx.multiply(cy).add(cz.multiply(cz)).add(cx)))
                    .isEqualTo(x.multiply(y).add(z.multiply(z)).add(x).mod(modulo));
            assertThat(cs.decrypt(cx.add(cx.multiply(cy))))
                    .isEqualTo(x.add(x.multiply(y)).mod(modulo));

            // constants before and after multiplication
            assertThat(cs.decrypt(cx.multiply(3L).multiply(cy).multiply(k)))
                    .isEqualTo(
                            BigInteger.valueOf(3).multiply(x).multiply(y).multiply(k).mod(modulo));
            assertThat(cs.decrypt(cx.multiply(cy).multiply(-1L)))
                    .isEqualTo(x.multiply(y).negate().mod(modulo));
        }
    }

    @Test
    @DisplayName("Brakerski-Vaikuntanathan supports only one multiplication")
    void testOnlyOneMultiplication() {
        Ciphertext c1 = cs.encrypt(2);
        Ciphertext c2 = cs.encrypt(3);
        Ciphertext c3 = cs.encrypt(4);
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> c1.multiply(c2).multiply(c3))
                .withMessageContaining("only one multiplication");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> c1.multiply(c2.multiply(c3)))
                .withMessageContaining("only one multiplication");
    }

    @Test
    @DisplayName("Brakerski-Vaikuntanathan rounds the plaintext limit up to a power of 2")
    void testPlaintextLimit() {
        // rounded up to a power of 2
        assertThat(build(16, BigInteger.valueOf(1000)).cs().plaintextModulo())
                .isEqualTo(BigInteger.valueOf(1024));
        assertThat(cs.cs().plaintextModulo()).isEqualTo(BigInteger.TWO.pow(24));

        LightPHE bigCs = build(16, BigInteger.TWO.pow(32));
        BigInteger x = BigInteger.TWO.pow(32).subtract(BigInteger.valueOf(7));
        BigInteger y = BigInteger.TWO.pow(31).add(BigInteger.valueOf(5));
        assertThat(bigCs.decrypt(bigCs.encrypt(x).multiply(bigCs.encrypt(y))))
                .isEqualTo(x.multiply(y).mod(BigInteger.TWO.pow(32)));

        // product of ciphertexts would not be decrypted correctly
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> build(16, BigInteger.TWO.pow(45)))
                .withMessageContaining("too large for Brakerski-Vaikuntanathan");

        for (int keySize : new int[] {4, 100}) {
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> build(keySize, null))
                    .withMessageContaining("must be a power of 2");
        }
    }

    @Test
    @DisplayName("Brakerski-Vaikuntanathan does not support floats and tensors")
    void testFloatsAndTensorsAreNotSupported() {
        Ciphertext c = cs.encrypt(5);
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.encrypt(1.5))
                .withMessageContaining("Brakerski-Vaikuntanathan does not support float");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.encryptTensor(List.of(1, 2, 3)))
                .withMessageContaining("Brakerski-Vaikuntanathan does not support float");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> c.multiply(1.5))
                .withMessageContaining("Brakerski-Vaikuntanathan does not support float");
    }

    @Test
    @DisplayName("Brakerski-Vaikuntanathan does not need the Catalano-Fiore transform")
    void testCatalanoFioreIsNotNeeded() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                LightPHE.builder()
                                        .algorithmName(ALGORITHM)
                                        .keys(cs.cs().keys())
                                        .boost("Catalano-Fiore")
                                        .build())
                .withMessageContaining("already supports one multiplication");
    }

    @Test
    @DisplayName("Brakerski-Vaikuntanathan works with predefined keys")
    void testApiWithPredefinedKeys() {
        LightPHE restoredCs =
                LightPHE.builder().algorithmName(ALGORITHM).keys(cs.cs().keys()).build();
        long m1 = 11;
        long m2 = 7;
        Ciphertext c1 = cs.encrypt(m1);
        Ciphertext c2 = restoredCs.encrypt(m2);
        assertThat(restoredCs.decrypt(c1.multiply(c2))).isEqualTo(BigInteger.valueOf(m1 * m2));
        assertThat(cs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(m1 + m2));
    }

    @Test
    @DisplayName("Brakerski-Vaikuntanathan multiplies with the public key only")
    void testExportedKeys(@TempDir Path tempDir) {
        Path publicKeyFile = tempDir.resolve("public.txt");
        cs.exportKeys(publicKeyFile, true);

        // multiplication requires the public key only
        LightPHE publicCs =
                LightPHE.builder().algorithmName(ALGORITHM).keyFile(publicKeyFile).build();
        Ciphertext c = publicCs.encrypt(42).multiply(publicCs.encrypt(2));
        assertThat(cs.decrypt(c)).isEqualTo(BigInteger.valueOf(84));

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> publicCs.decrypt(c))
                .withMessageContaining("private key");
    }

    @Test
    @DisplayName("Brakerski-Vaikuntanathan works with ring degree 4096")
    void testLargeKeys() {
        BigInteger modulo = largeCs.cs().plaintextModulo();
        Random random = new Random();
        List<Long> xs = new ArrayList<>();
        List<Long> ys = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            xs.add((long) random.nextInt(1001));
            ys.add((long) random.nextInt(1001));
        }

        // dot product of encrypted vectors
        Ciphertext encryptedDot = largeCs.encrypt(xs.get(0)).multiply(largeCs.encrypt(ys.get(0)));
        long expected = xs.get(0) * ys.get(0);
        for (int i = 1; i < 5; i++) {
            encryptedDot =
                    encryptedDot.add(
                            largeCs.encrypt(xs.get(i)).multiply(largeCs.encrypt(ys.get(i))));
            expected += xs.get(i) * ys.get(i);
        }
        assertThat(largeCs.decrypt(encryptedDot)).isEqualTo(BigInteger.valueOf(expected));

        // full range plaintexts with constants after multiplication
        BigInteger upper = modulo.subtract(BigInteger.ONE);
        BigInteger x = MathUtils.randomInt(BigInteger.ZERO, upper);
        BigInteger y = MathUtils.randomInt(BigInteger.ZERO, upper);
        Ciphertext product = largeCs.encrypt(x).multiply(largeCs.encrypt(y)).multiply(1000L);
        assertThat(largeCs.decrypt(product))
                .isEqualTo(BigInteger.valueOf(1000).multiply(x).multiply(y).mod(modulo));
    }

    @Test
    @DisplayName("Brakerski-Vaikuntanathan runs the example in the readme")
    void testReadmeExample() {
        Ciphertext c1 = largeCs.encrypt(15);
        Ciphertext c2 = largeCs.encrypt(25);
        Ciphertext c3 = largeCs.encrypt(100);

        // one multiplication, then additions and multiplications with constants
        assertThat(largeCs.decrypt(c1.multiply(c2).add(c3))).isEqualTo(BigInteger.valueOf(475));
        assertThat(largeCs.decrypt(c1.multiply(c2).multiply(2L).add(c1.multiply(c3))))
                .isEqualTo(BigInteger.valueOf(2250));
    }
}
