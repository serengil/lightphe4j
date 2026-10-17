package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.within;

import io.github.serengil.lightphe.commons.MathUtils;
import io.github.serengil.lightphe.model.Ciphertext;
import io.github.serengil.lightphe.model.EncryptedTensor;
import io.github.serengil.lightphe.model.KeyValue;
import io.github.serengil.lightphe.model.value.IntValue;
import io.github.serengil.lightphe.model.value.TupleValue;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Port of {@code tests/test_ellipticcurvepaillier.py}. */
class EllipticCurvePaillierTest {

    private static final String ALGORITHM = "EllipticCurve-Paillier";

    private static final LightPHE cs =
            LightPHE.builder().algorithmName(ALGORITHM).keySize(50).build();

    @Test
    @DisplayName("Elliptic Curve Paillier supports homomorphic addition and scalar multiplication")
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
    @DisplayName("Elliptic Curve Paillier keys are well formed")
    void testKeysAreWellFormed() {
        BigInteger n = cs.cs().keys().publicNumber("n");
        BigInteger b = cs.cs().keys().publicNumber("b");
        KeyValue.Point g = cs.cs().keys().publicPoint("g");
        BigInteger p = cs.cs().keys().privateNumber("p");
        BigInteger q = cs.cs().keys().privateNumber("q");
        BigInteger order = cs.cs().keys().privateNumber("order");
        BigInteger nSquare = n.multiply(n);
        BigInteger three = BigInteger.valueOf(3);

        assertThat(n).isEqualTo(p.multiply(q));
        assertThat(p.mod(three)).isEqualTo(BigInteger.TWO);
        assertThat(q.mod(three)).isEqualTo(BigInteger.TWO);

        // g is on the curve y^2 = x^3 + b mod n^2
        assertThat(g.y().multiply(g.y()).subtract(g.x().pow(3)).subtract(b).mod(nSquare))
                .isEqualTo(BigInteger.ZERO);

        // order is odd and divides the group exponent modulo n
        assertThat(order.testBit(0)).isTrue();
        assertThat(p.add(BigInteger.ONE).multiply(q.add(BigInteger.ONE)).mod(order))
                .isEqualTo(BigInteger.ZERO);
    }

    @Test
    @DisplayName("Elliptic Curve Paillier handles doubling, inverses and the point at infinity")
    void testEdgeCases() {
        BigInteger modulo = cs.cs().plaintextModulo();
        for (BigInteger m :
                List.of(
                        BigInteger.ZERO,
                        BigInteger.ONE,
                        BigInteger.TWO,
                        modulo.subtract(BigInteger.ONE))) {
            Ciphertext c = cs.encrypt(m);
            assertThat(cs.decrypt(c)).isEqualTo(m);

            // doubling, i.e. adding a ciphertext to itself
            assertThat(cs.decrypt(c.add(c))).isEqualTo(m.shiftLeft(1).mod(modulo));

            // adding inverse brings point back to the encryption of 0
            assertThat(cs.decrypt(c.add(c.multiply(modulo.subtract(BigInteger.ONE)))))
                    .isEqualTo(BigInteger.ZERO);

            // multiplying by 0 gives the point at infinity, which is the encryption of 0
            assertThat(cs.decrypt(c.multiply(0L))).isEqualTo(BigInteger.ZERO);
            assertThat(cs.decrypt(c.multiply(0L).add(c))).isEqualTo(m);
        }
    }

    @Test
    @DisplayName("Elliptic Curve Paillier is correct for random operations")
    void testRandomOperations() {
        BigInteger modulo = cs.cs().plaintextModulo();
        BigInteger upper = modulo.subtract(BigInteger.ONE);
        for (int i = 0; i < 50; i++) {
            BigInteger m1 = MathUtils.randomInt(BigInteger.ZERO, upper);
            BigInteger m2 = MathUtils.randomInt(BigInteger.ZERO, upper);
            BigInteger k = MathUtils.randomInt(BigInteger.ZERO, upper);
            Ciphertext c1 = cs.encrypt(m1);
            Ciphertext c2 = cs.encrypt(m2);
            assertThat(cs.decrypt(c1.add(c2))).isEqualTo(m1.add(m2).mod(modulo));
            assertThat(cs.decrypt(c1.multiply(k).add(c2)))
                    .isEqualTo(m1.multiply(k).add(m2).mod(modulo));
        }
    }

    @Test
    @DisplayName("Elliptic Curve Paillier rejects points that are not ciphertexts")
    void testInvalidCiphertext() {
        BigInteger n = cs.cs().plaintextModulo();
        Ciphertext c = cs.encrypt(5);
        List<BigInteger> xyz = ((TupleValue) c.value()).asIntegers();

        // a point that is not a ciphertext
        TupleValue shifted =
                TupleValue.ofIntegers(
                        List.of(xyz.get(0).add(BigInteger.ONE), xyz.get(1), xyz.get(2)));
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.cs().decrypt(shifted))
                .withMessageContaining("invalid");

        TupleValue arbitrary =
                TupleValue.of(IntValue.of(1), IntValue.of(1), IntValue.of(BigInteger.ONE.add(n)));
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.cs().decrypt(arbitrary))
                .withMessageContaining("invalid");
    }

    @Test
    @DisplayName("Elliptic Curve Paillier works with predefined keys")
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
    @DisplayName("Elliptic Curve Paillier works with exported keys")
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

        // private key restored from file
        Path privateKeyFile = tempDir.resolve("private.txt");
        cs.exportKeys(privateKeyFile);
        LightPHE restoredCs =
                LightPHE.builder().algorithmName(ALGORITHM).keyFile(privateKeyFile).build();
        assertThat(restoredCs.decrypt(c.add(publicCs.encrypt(1))))
                .isEqualTo(BigInteger.valueOf(85));
    }

    @Test
    @DisplayName("Elliptic Curve Paillier works with 1024-bit keys, floats and tensors")
    void testLargeKeys() {
        LightPHE largeCs = LightPHE.builder().algorithmName(ALGORITHM).keySize(1024).build();
        long m1 = 123456789;
        long m2 = 987654321;
        Ciphertext c1 = largeCs.encrypt(m1);
        Ciphertext c2 = largeCs.encrypt(m2);
        assertThat(largeCs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(m1 + m2));
        assertThat(largeCs.decrypt(c1.multiply(1000L))).isEqualTo(BigInteger.valueOf(m1 * 1000));

        // floats and tensors
        Ciphertext c3 = largeCs.encrypt(1.5);
        assertThat(largeCs.decrypt(c3.multiply(4L))).isEqualTo(BigInteger.valueOf(6));
        EncryptedTensor encTensor = largeCs.encryptTensor(List.of(1.5, 2.25, 3.5));
        List<Double> decrypted = largeCs.decryptTensor(encTensor);
        assertThat(decrypted.get(0)).isCloseTo(1.5, within(1e-9));
        assertThat(decrypted.get(1)).isCloseTo(2.25, within(1e-9));
        assertThat(decrypted.get(2)).isCloseTo(3.5, within(1e-9));
        assertThat(largeCs.decryptTensor(encTensor.matmul(List.of(2, 4, 1))).get(0))
                .isCloseTo(15.5, within(1e-9));
    }
}
