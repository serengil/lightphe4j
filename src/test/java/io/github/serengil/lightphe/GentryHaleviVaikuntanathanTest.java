package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.serengil.lightphe.commons.MathUtils;
import io.github.serengil.lightphe.cryptosystems.GentryHaleviVaikuntanathan;
import io.github.serengil.lightphe.model.Ciphertext;
import io.github.serengil.lightphe.model.Keys;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Port of {@code tests/test_gentryhalevivaikuntanathan.py}. */
class GentryHaleviVaikuntanathanTest {

    private static final String ALGORITHM = "Gentry-Halevi-Vaikuntanathan";

    /** Smallest lattice dimension keeps tests fast. It is for learning purposes only anyway. */
    private static final LightPHE cs =
            LightPHE.builder().algorithmName(ALGORITHM).keySize(2).build();

    private static LightPHE build(Integer keySize, BigInteger plaintextLimit) {
        return LightPHE.builder()
                .algorithmName(ALGORITHM)
                .keySize(keySize)
                .plaintextLimit(plaintextLimit)
                .build();
    }

    @Test
    @DisplayName("Gentry-Halevi-Vaikuntanathan supports addition, one multiplication and constants")
    void testApi() {
        BigInteger modulo = cs.cs().plaintextModulo();

        long m1 = 7;
        long m2 = 9;

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
        assertThat(cs.decrypt(c1.multiply(3L))).isEqualTo(BigInteger.valueOf(m1 * 3));

        // negative plaintexts and wrapping around the plaintext modulo
        Ciphertext c3 = cs.encrypt(-5L);
        assertThat(cs.decrypt(c3)).isEqualTo(modulo.subtract(BigInteger.valueOf(5)));
        assertThat(cs.decrypt(c1.add(c3))).isEqualTo(BigInteger.valueOf(m1 - 5));
        assertThat(cs.decrypt(c1.multiply(c3)))
                .isEqualTo(modulo.subtract(BigInteger.valueOf(5 * m1)));

        // re-randomization
        Ciphertext c1Prime = cs.regenerateCiphertext(c1);
        assertThat(c1Prime.value()).isNotEqualTo(c1.value());
        assertThat(cs.decrypt(c1Prime)).isEqualTo(BigInteger.valueOf(m1));

        // unsupported homomorphic operations
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.xor(c2));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.and(c2));
    }

    @Test
    @DisplayName("Gentry-Halevi-Vaikuntanathan warns that it is for learning purposes only")
    void testInsecurityWarning() {
        // the Python test intercepts the logger; here the logged message itself is checked
        assertThat(GentryHaleviVaikuntanathan.INSECURE_WARNING_MSG)
                .contains("learning purposes only");
        assertThat(LightPHE.builder().algorithmName(ALGORITHM).keys(cs.cs().keys()).build().cs())
                .isInstanceOf(GentryHaleviVaikuntanathan.class);
    }

    @Test
    @DisplayName("Gentry-Halevi-Vaikuntanathan keys are well formed")
    void testKeysAreWellFormed() {
        Keys keys = cs.cs().keys();
        List<List<BigInteger>> a = keys.publicMatrix("A");
        BigInteger q = keys.publicNumber("q");
        BigInteger p = keys.publicNumber("p");
        List<List<BigInteger>> t = keys.privateMatrix("T");
        List<BigInteger> u = keys.privateNumbers("u");
        int m = a.size();

        // trapdoor T is square, short, and T A = 0 mod q
        assertThat(t).hasSize(m).allSatisfy(row -> assertThat(row).hasSize(m));
        BigInteger bound = BigInteger.valueOf((long) q.bitLength() * m);
        for (List<BigInteger> row : t) {
            for (BigInteger x : row) {
                assertThat(x.abs()).isLessThan(bound);
            }
            for (int column = 0; column < a.get(0).size(); column++) {
                BigInteger dot = BigInteger.ZERO;
                for (int i = 0; i < m; i++) {
                    dot = dot.add(row.get(i).multiply(a.get(i).get(column)));
                }
                assertThat(dot.mod(q)).isEqualTo(BigInteger.ZERO);
            }
        }

        // u is the first row of T^-1 modulo p
        for (int j = 0; j < m; j++) {
            BigInteger dot = BigInteger.ZERO;
            for (int i = 0; i < m; i++) {
                dot = dot.add(u.get(i).multiply(t.get(i).get(j)));
            }
            assertThat(dot.mod(p)).isEqualTo(j == 0 ? BigInteger.ONE : BigInteger.ZERO);
        }

        assertThat(q.bitCount()).isEqualTo(1);
        assertThat(p.testBit(0)).isTrue();
    }

    @Test
    @DisplayName("Gentry-Halevi-Vaikuntanathan evaluates degree-2 functions")
    void testDegree2Functions() {
        BigInteger modulo = cs.cs().plaintextModulo();
        BigInteger upper = modulo.subtract(BigInteger.ONE);
        BigInteger half = modulo.shiftRight(1);
        for (int round = 0; round < 10; round++) {
            BigInteger x = MathUtils.randomInt(BigInteger.ZERO, upper);
            BigInteger y = MathUtils.randomInt(BigInteger.ZERO, upper);
            BigInteger z = MathUtils.randomInt(BigInteger.ZERO, upper);
            BigInteger k = MathUtils.randomInt(half.add(BigInteger.ONE).negate(), half);
            Ciphertext cx = cs.encrypt(x);
            Ciphertext cy = cs.encrypt(y);
            Ciphertext cz = cs.encrypt(z);

            assertThat(cs.decrypt(cx.multiply(cx))).isEqualTo(x.multiply(x).mod(modulo));
            assertThat(cs.decrypt(cx.add(cy).multiply(cz)))
                    .isEqualTo(x.add(y).multiply(z).mod(modulo));

            // multiplied ciphertexts can be added with each other and with fresh ciphertexts
            assertThat(cs.decrypt(cx.multiply(cy).add(cz.multiply(cz)).add(cx)))
                    .isEqualTo(x.multiply(y).add(z.multiply(z)).add(x).mod(modulo));

            // constants before and after multiplication
            assertThat(cs.decrypt(cx.multiply(k).multiply(cy)))
                    .isEqualTo(k.multiply(x).multiply(y).mod(modulo));
            assertThat(cs.decrypt(cx.multiply(cy).multiply(k)))
                    .isEqualTo(k.multiply(x).multiply(y).mod(modulo));
        }
    }

    @Test
    @DisplayName("Gentry-Halevi-Vaikuntanathan supports only one multiplication")
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
    @DisplayName("Gentry-Halevi-Vaikuntanathan limits the key size and picks a prime modulus")
    void testKeySizeAndPlaintextLimit() {
        for (int keySize : new int[] {1, 9, 1024}) {
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> build(keySize, null))
                    .withMessageContaining("for learning purposes only");
        }

        assertThat(cs.cs().plaintextModulo()).isEqualTo(BigInteger.valueOf(101));

        // plaintext modulus is the smallest prime greater than or equal to the limit
        LightPHE bigCs = build(2, BigInteger.valueOf(1000));
        assertThat(bigCs.cs().plaintextModulo()).isEqualTo(BigInteger.valueOf(1009));
        long x = 1000;
        long y = 999;
        assertThat(bigCs.decrypt(bigCs.encrypt(x).multiply(bigCs.encrypt(y))))
                .isEqualTo(BigInteger.valueOf((x * y) % 1009));
    }

    @Test
    @DisplayName("Gentry-Halevi-Vaikuntanathan does not support floats and tensors")
    void testFloatsAndTensorsAreNotSupported() {
        Ciphertext c = cs.encrypt(5);
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.encrypt(1.5))
                .withMessageContaining("does not support float");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.encryptTensor(List.of(1, 2, 3)))
                .withMessageContaining("does not support float");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> c.multiply(1.5))
                .withMessageContaining("does not support float");
    }

    @Test
    @DisplayName("Gentry-Halevi-Vaikuntanathan does not need the Catalano-Fiore transform")
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
    @DisplayName("Gentry-Halevi-Vaikuntanathan works with exported keys")
    void testExportedKeys(@TempDir Path tempDir) {
        Path publicKeyFile = tempDir.resolve("public.txt");
        cs.exportKeys(publicKeyFile, true);

        // multiplication requires the public key only
        LightPHE publicCs =
                LightPHE.builder().algorithmName(ALGORITHM).keyFile(publicKeyFile).build();
        Ciphertext c = publicCs.encrypt(4).multiply(publicCs.encrypt(5)).add(publicCs.encrypt(1));
        assertThat(cs.decrypt(c)).isEqualTo(BigInteger.valueOf(21));

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> publicCs.decrypt(c))
                .withMessageContaining("private key");

        // private key restored from file
        Path privateKeyFile = tempDir.resolve("private.txt");
        cs.exportKeys(privateKeyFile);
        LightPHE restoredCs =
                LightPHE.builder().algorithmName(ALGORITHM).keyFile(privateKeyFile).build();
        assertThat(restoredCs.decrypt(c)).isEqualTo(BigInteger.valueOf(21));
    }

    @Test
    @DisplayName("Gentry-Halevi-Vaikuntanathan works with the default key size")
    void testDefaultKeySize() {
        LightPHE defaultCs = build(null, null);
        assertThat(defaultCs.cs().keys().publicMatrix("A").get(0)).hasSize(4);

        Ciphertext c1 = defaultCs.encrypt(12);
        Ciphertext c2 = defaultCs.encrypt(34);
        Ciphertext c3 = defaultCs.encrypt(56);
        assertThat(defaultCs.decrypt(c1.multiply(c2).add(c3)))
                .isEqualTo(BigInteger.valueOf((12 * 34 + 56) % 101));
    }
}
