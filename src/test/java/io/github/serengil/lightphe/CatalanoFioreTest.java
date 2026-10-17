package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.serengil.lightphe.commons.MathUtils;
import io.github.serengil.lightphe.model.CatalanoFiore;
import io.github.serengil.lightphe.model.CatalanoFioreCiphertext;
import io.github.serengil.lightphe.model.Ciphertext;
import io.github.serengil.lightphe.model.Keys;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

/** Port of {@code tests/test_catalanofiore.py}. */
class CatalanoFioreTest {

    private static final String BOOST = CatalanoFiore.BOOST_NAME;

    /** Plain cryptosystem, and the one supporting multiplication with the same keys. */
    private static final LightPHE cs =
            LightPHE.builder().algorithmName("Paillier").keySize(128).build();

    private static final LightPHE cf =
            LightPHE.builder().algorithmName("Paillier").keys(cs.cs().keys()).boost(BOOST).build();

    static Stream<Arguments> supportedAlgorithms() {
        return CatalanoFiore.SUPPORTED_ALGORITHMS.stream()
                .map(algorithm -> Arguments.of(algorithm.algorithmName()));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("supportedAlgorithms")
    @DisplayName("Catalano-Fiore evaluates degree-2 functions on every supported algorithm")
    void testDegree2Functions(String algorithmName) {
        LightPHE transform =
                LightPHE.builder().algorithmName(algorithmName).keySize(64).boost(BOOST).build();
        BigInteger modulo = transform.cs().plaintextModulo();
        BigInteger upper = modulo.subtract(BigInteger.ONE);

        for (int round = 0; round < 5; round++) {
            BigInteger x = MathUtils.randomInt(BigInteger.ZERO, upper);
            BigInteger y = MathUtils.randomInt(BigInteger.ZERO, upper);
            BigInteger z = MathUtils.randomInt(BigInteger.ZERO, upper);
            BigInteger k = MathUtils.randomInt(BigInteger.ZERO, upper);
            CatalanoFioreCiphertext cx = transform.encryptBoosted(x);
            CatalanoFioreCiphertext cy = transform.encryptBoosted(y);
            CatalanoFioreCiphertext cz = transform.encryptBoosted(z);

            assertThat(transform.decrypt(cx)).isEqualTo(x);
            assertThat(transform.decrypt(cx.add(cy))).isEqualTo(x.add(y).mod(modulo));
            assertThat(transform.decrypt(cx.multiply(k))).isEqualTo(x.multiply(k).mod(modulo));
            assertThat(transform.decrypt(cx.multiply(cy))).isEqualTo(x.multiply(y).mod(modulo));
            assertThat(transform.decrypt(cx.multiply(cx))).isEqualTo(x.multiply(x).mod(modulo));

            // x * y + k * z * x - y + 7
            CatalanoFioreCiphertext result =
                    cx.multiply(cy).add(cz.multiply(cx).multiply(k)).subtract(cy).add(7);
            BigInteger expected =
                    x.multiply(y)
                            .add(k.multiply(z).multiply(x))
                            .subtract(y)
                            .add(BigInteger.valueOf(7))
                            .mod(modulo);
            assertThat(transform.decrypt(result)).isEqualTo(expected);
        }
    }

    @Test
    @DisplayName("Catalano-Fiore ciphertexts support additions, constants and negation")
    void testOperations() {
        BigInteger modulo = cf.cs().plaintextModulo();
        CatalanoFioreCiphertext c3 = cf.encryptBoosted(3);
        CatalanoFioreCiphertext c4 = cf.encryptBoosted(4);
        CatalanoFioreCiphertext c5 = cf.encryptBoosted(5);

        // one multiplication, then additions and scalar multiplications
        assertThat(cf.decrypt(c3.multiply(c4).add(c5))).isEqualTo(BigInteger.valueOf(17));
        assertThat(cf.decrypt(c3.multiply(c4).multiply(2).add(c3.multiply(c5))))
                .isEqualTo(BigInteger.valueOf(39));
        assertThat(cf.decrypt(c3.multiply(c4).multiply(2))).isEqualTo(BigInteger.valueOf(24));

        // plain constants
        assertThat(cf.decrypt(c3.add(10))).isEqualTo(BigInteger.valueOf(13));
        assertThat(cf.decrypt(c3.multiply(c4).add(10))).isEqualTo(BigInteger.valueOf(22));
        assertThat(cf.decrypt(c3.multiply(c4).subtract(2))).isEqualTo(BigInteger.valueOf(10));

        // subtraction, negation and wrapping around the plaintext modulo
        assertThat(cf.decrypt(c3.subtract(c4))).isEqualTo(modulo.subtract(BigInteger.ONE));
        assertThat(cf.decrypt(c3.negate())).isEqualTo(modulo.subtract(BigInteger.valueOf(3)));
        assertThat(cf.decrypt(c3.multiply(c4).subtract(c5.multiply(c5))))
                .isEqualTo(modulo.subtract(BigInteger.valueOf(13)));
        assertThat(cf.decrypt(c3.multiply(c4).negate().add(20))).isEqualTo(BigInteger.valueOf(8));

        // summing products and fresh ciphertexts
        CatalanoFioreCiphertext sum =
                Stream.of(c3.multiply(c4), c5, c3)
                        .reduce(CatalanoFioreCiphertext::add)
                        .orElseThrow();
        assertThat(cf.decrypt(sum)).isEqualTo(BigInteger.valueOf(20));

        // negative and zero plaintexts, and multiplication with zero
        assertThat(cf.decrypt(cf.encryptBoosted(-6)))
                .isEqualTo(modulo.subtract(BigInteger.valueOf(6)));
        assertThat(cf.decrypt(cf.encryptBoosted(-6).multiply(c4)))
                .isEqualTo(modulo.subtract(BigInteger.valueOf(24)));
        assertThat(cf.decrypt(cf.encryptBoosted(0).multiply(c4))).isEqualTo(BigInteger.ZERO);
        assertThat(cf.decrypt(c3.multiply(c4).multiply(0))).isEqualTo(BigInteger.ZERO);
    }

    @Test
    @DisplayName("Catalano-Fiore ciphertexts are randomized")
    void testCiphertextsAreRandomized() {
        CatalanoFioreCiphertext c1 = cf.encryptBoosted(5);
        CatalanoFioreCiphertext c2 = cf.encryptBoosted(5);
        assertThat(c1.a()).isNotEqualTo(c2.a());
        assertThat(c1.beta().value()).isNotEqualTo(c2.beta().value());
        assertThat(cf.decrypt(c1)).isEqualTo(BigInteger.valueOf(5));
        assertThat(cf.decrypt(c2)).isEqualTo(BigInteger.valueOf(5));
    }

    @Test
    @DisplayName("Catalano-Fiore ciphertexts do not carry the private key")
    void testCiphertextsDoNotCarryPrivateKey() {
        CatalanoFioreCiphertext c =
                cf.encryptBoosted(5).multiply(cf.encryptBoosted(6)).add(cf.encryptBoosted(7));
        assertThat(c.alpha().keys().hasPrivateKey()).isFalse();
        for (Ciphertext[] pair : c.pairs()) {
            assertThat(pair[0].keys().hasPrivateKey()).isFalse();
            assertThat(pair[1].keys().hasPrivateKey()).isFalse();
        }
        assertThat(cf.decrypt(c.add(cf.encryptBoosted(1)))).isEqualTo(BigInteger.valueOf(38));
    }

    @Test
    @DisplayName("Catalano-Fiore computes the dot product of encrypted vectors")
    void testDotProductOfEncryptedVectors() {
        Random random = new Random();
        List<CatalanoFioreCiphertext> products = new ArrayList<>();
        long expected = 0;
        for (int i = 0; i < 10; i++) {
            long x = random.nextInt(1001);
            long y = random.nextInt(1001);
            products.add(cf.encryptBoosted(x).multiply(cf.encryptBoosted(y)));
            expected += x * y;
        }

        CatalanoFioreCiphertext result =
                products.stream().reduce(CatalanoFioreCiphertext::add).orElseThrow();
        assertThat(cf.decrypt(result)).isEqualTo(BigInteger.valueOf(expected));

        // a pair of ciphertexts is kept for every product
        assertThat(result.pairs()).hasSize(10);
    }

    @Test
    @DisplayName("Catalano-Fiore supports only one multiplication")
    void testOnlyOneMultiplication() {
        CatalanoFioreCiphertext c1 = cf.encryptBoosted(2);
        CatalanoFioreCiphertext c2 = cf.encryptBoosted(3);
        CatalanoFioreCiphertext c3 = cf.encryptBoosted(4);
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> c1.multiply(c2).multiply(c3))
                .withMessageContaining("only one multiplication");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> c1.multiply(c2.multiply(c3)))
                .withMessageContaining("only one multiplication");
    }

    @Test
    @DisplayName("Catalano-Fiore encrypts and evaluates with the public key only")
    void testPublicKeyOnly(@TempDir Path tempDir) {
        Path publicKeyFile = tempDir.resolve("public.txt");
        cs.exportKeys(publicKeyFile, true);

        // server encrypts and evaluates with the public key only
        LightPHE serverCf =
                LightPHE.builder()
                        .algorithmName("Paillier")
                        .keyFile(publicKeyFile)
                        .boost(BOOST)
                        .build();
        CatalanoFioreCiphertext c1 = cf.encryptBoosted(6);
        CatalanoFioreCiphertext c2 = serverCf.encryptBoosted(7);
        CatalanoFioreCiphertext result = c1.multiply(c2).add(serverCf.encryptBoosted(8));

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> serverCf.decrypt(result))
                .withMessageContaining("You must have private key");

        assertThat(cf.decrypt(result)).isEqualTo(BigInteger.valueOf(50));
    }

    @Test
    @DisplayName("Catalano-Fiore rejects floats, regeneration and mixing cryptosystems")
    void testInvalidInputs() {
        CatalanoFioreCiphertext c = cf.encryptBoosted(5);

        // floats and tensors cannot reach the transform
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cf.encrypt(1.5))
                .withMessageContaining("integers only");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cf.encryptTensor(List.of(1, 2)))
                .withMessageContaining("integers only");

        // regular ciphertexts would not support multiplication, so they are not handed out
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cf.encrypt(5))
                .withMessageContaining("encryptBoosted");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cf.regenerateCiphertext(c))
                .withMessageContaining("cannot be regenerated");

        LightPHE otherCf =
                LightPHE.builder().algorithmName("Paillier").keySize(128).boost(BOOST).build();
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> c.add(otherCf.encryptBoosted(1)))
                .withMessageContaining("different cryptosystems");
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource({
        "Exponential-ElGamal, discrete logarithm",
        "EllipticCurve-ElGamal, discrete logarithm",
        "Okamoto-Uchiyama, plaintext modulus p is secret",
        "Regev, noise budget",
        "Goldwasser-Micali, xor only",
        "Boneh-Goh-Nissim, already supports one multiplication",
        "RSA, not additively homomorphic",
        "ElGamal, not additively homomorphic",
    })
    @DisplayName("Catalano-Fiore explains why an algorithm is not supported")
    void testUnsupportedAlgorithms(String algorithmName, String reason) {
        int keySize = "Regev".equals(algorithmName) ? 16 : 64;
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                LightPHE.builder()
                                        .algorithmName(algorithmName)
                                        .keySize(keySize)
                                        .boost(BOOST)
                                        .build())
                .withMessageMatching(
                        "(?s).*does not support " + algorithmName + " because .*" + reason + ".*");
    }

    @Test
    @DisplayName("Unknown boosts are rejected")
    void testUnknownBoost() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                LightPHE.builder()
                                        .algorithmName("Paillier")
                                        .keySize(64)
                                        .boost("something")
                                        .build())
                .withMessageContaining("Unknown boost");
    }

    @Test
    @DisplayName("Without the boost, cryptosystems behave as before")
    void testDefaultBehaviourIsUnchanged() {
        // no boost by default, so ciphertexts are regular ones
        Keys keys = cs.cs().keys().deepCopy();
        Ciphertext c1 = cs.encrypt(5);
        cf.encryptBoosted(5).multiply(cf.encryptBoosted(6));
        assertThat(cs.cs().keys().toString()).isEqualTo(keys.toString());
        assertThat(cs.decrypt(c1.add(cs.encrypt(3)))).isEqualTo(BigInteger.valueOf(8));
        assertThat(cs.decrypt(cs.encrypt(1.5).multiply(2L))).isEqualTo(BigInteger.valueOf(3));
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> c1.multiply(cs.encrypt(3)));

        // each one decrypts ciphertexts of the other, as they have the same keys
        assertThat(cf.decrypt(c1)).isEqualTo(BigInteger.valueOf(5));
        assertThat(cs.decrypt(cf.encryptBoosted(5).multiply(cf.encryptBoosted(6))))
                .isEqualTo(BigInteger.valueOf(30));
    }

    @Test
    @DisplayName("Catalano-Fiore works with 1024-bit keys")
    void testLargeKeys() {
        LightPHE largeCf =
                LightPHE.builder().algorithmName("Paillier").keySize(1024).boost(BOOST).build();
        BigInteger x = MathUtils.getRandomBits(400);
        BigInteger y = MathUtils.getRandomBits(400);
        assertThat(largeCf.decrypt(largeCf.encryptBoosted(x).multiply(largeCf.encryptBoosted(y))))
                .isEqualTo(x.multiply(y));
    }

    @Test
    @DisplayName("Catalano-Fiore runs the example in the readme")
    void testReadmeExample() {
        // client builds a cryptosystem supporting multiplication, and encrypts its private vectors
        LightPHE clientCs =
                LightPHE.builder().algorithmName("Paillier").keySize(256).boost(BOOST).build();

        long[] x = {3, 1, 4};
        long[] y = {1, 5, 9};
        List<CatalanoFioreCiphertext> encryptedX = new ArrayList<>();
        List<CatalanoFioreCiphertext> encryptedY = new ArrayList<>();
        for (int i = 0; i < x.length; i++) {
            encryptedX.add(clientCs.encryptBoosted(x[i]));
            encryptedY.add(clientCs.encryptBoosted(y[i]));
        }

        // server computes dot product of encrypted vectors, ciphertexts carry the public key only
        CatalanoFioreCiphertext encryptedDot = encryptedX.get(0).multiply(encryptedY.get(0));
        for (int i = 1; i < x.length; i++) {
            encryptedDot = encryptedDot.add(encryptedX.get(i).multiply(encryptedY.get(i)));
        }

        // squared euclidean distance is also a degree-2 function
        CatalanoFioreCiphertext encryptedDistance = null;
        for (int i = 0; i < x.length; i++) {
            CatalanoFioreCiphertext difference = encryptedX.get(i).subtract(encryptedY.get(i));
            CatalanoFioreCiphertext square = difference.multiply(difference);
            encryptedDistance = encryptedDistance == null ? square : encryptedDistance.add(square);
        }

        // client decrypts the results
        assertThat(clientCs.decrypt(encryptedDot)).isEqualTo(BigInteger.valueOf(44));
        assertThat(clientCs.decrypt(encryptedDistance)).isEqualTo(BigInteger.valueOf(45));

        // multiplying again is not supported
        CatalanoFioreCiphertext dot = encryptedDot;
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> dot.multiply(encryptedX.get(0)))
                .withMessageContaining("only one multiplication");
    }
}
