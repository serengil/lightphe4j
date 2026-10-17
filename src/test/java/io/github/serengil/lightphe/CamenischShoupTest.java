package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.within;

import io.github.serengil.lightphe.commons.MathUtils;
import io.github.serengil.lightphe.cryptosystems.CamenischShoup;
import io.github.serengil.lightphe.ecc.CurvePoint;
import io.github.serengil.lightphe.ecc.LightECC;
import io.github.serengil.lightphe.model.Ciphertext;
import io.github.serengil.lightphe.model.EncryptedTensor;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.VerifiableCiphertext;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.TupleValue;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.List;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Port of {@code tests/test_camenischshoup.py}. */
class CamenischShoupTest {

    private static final String ALGORITHM = "Camenisch-Shoup";

    private static final LightPHE cs =
            LightPHE.builder().algorithmName(ALGORITHM).keySize(50).build();

    /** Verifiable encryption of secp256k1 secrets requires keys larger than 467 bits. */
    private static final LightPHE largeCs =
            LightPHE.builder().algorithmName(ALGORITHM).keySize(1024).build();

    private static final LightECC secp256k1 = LightECC.of("weierstrass", "secp256k1");

    private static BigInteger randomSecret(LightECC ecc) {
        return MathUtils.randomInt(BigInteger.ONE, ecc.n().subtract(BigInteger.ONE));
    }

    @Test
    @DisplayName("Camenisch-Shoup supports homomorphic addition and scalar multiplication")
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
    @DisplayName("Camenisch-Shoup keys are well formed")
    void testKeysAreWellFormed() {
        Keys keys = cs.cs().keys();
        BigInteger n = keys.publicNumber("n");
        BigInteger nSquare = n.multiply(n);

        for (int i = 1; i <= 3; i++) {
            assertThat(keys.publicNumber("y" + i))
                    .isEqualTo(keys.publicNumber("g").modPow(keys.privateNumber("x" + i), nSquare));
        }

        assertThat(keys.publicNumber("g")).isNotEqualTo(BigInteger.ONE);
        assertThat(keys.publicNumber("h_bar")).isNotEqualTo(BigInteger.ONE);
        assertThat(keys.publicNumber("g_bar")).isNotEqualTo(BigInteger.ONE);
        assertThat(keys.publicNumber("n_bar")).isNotEqualTo(n);
    }

    @Test
    @DisplayName("Labeled ciphertexts are bound to their labels")
    void testLabeledEncryption() {
        CamenischShoup scheme = (CamenischShoup) cs.cs();
        BigInteger modulo = scheme.plaintextModulo();
        BigInteger nSquare = scheme.ciphertextModulo();
        for (BigInteger m :
                List.of(
                        BigInteger.ZERO,
                        BigInteger.ONE,
                        BigInteger.valueOf(17),
                        modulo.subtract(BigInteger.ONE))) {
            CipherValue ciphertext = scheme.encryptWithLabel(m, "some label");
            assertThat(scheme.decryptWithLabel(ciphertext, "some label")).isEqualTo(m);

            // different label
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> scheme.decryptWithLabel(ciphertext, "other label"))
                    .withMessageContaining("different label");

            // modified ciphertext
            List<BigInteger> parts = ((TupleValue) ciphertext).asIntegers();
            BigInteger u = parts.get(0);
            BigInteger e = parts.get(1);
            BigInteger v = parts.get(2);
            for (List<BigInteger> modified :
                    List.of(
                            List.of(u, e.multiply(BigInteger.ONE.add(modulo)).mod(nSquare), v),
                            List.of(u, e, v.add(BigInteger.ONE)))) {
                assertThatExceptionOfType(IllegalArgumentException.class)
                        .isThrownBy(
                                () ->
                                        scheme.decryptWithLabel(
                                                TupleValue.ofIntegers(modified), "some label"))
                        .withMessageContaining("invalid");
            }

            // labeled ciphertexts cannot be decrypted without label
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> scheme.decrypt(ciphertext))
                    .withMessageContaining("labels");

            // homomorphic operations drop the validity tag
            Ciphertext c = cs.createCiphertextObj(ciphertext).add(cs.encrypt(3));
            assertThat(((TupleValue) c.value()).size()).isEqualTo(2);
            assertThat(cs.decrypt(c)).isEqualTo(m.add(BigInteger.valueOf(3)).mod(modulo));
        }
    }

    @Test
    @DisplayName("Camenisch-Shoup works with predefined keys")
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
    @DisplayName("Camenisch-Shoup works with exported public keys")
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
    @DisplayName("Verifiable encryption proves the ciphertext contains the secret")
    void testVerifiableEncryption() {
        BigInteger secret = randomSecret(secp256k1);
        CurvePoint publicPoint = secp256k1.g().multiply(secret);
        String label = "release if alice loses access";

        VerifiableCiphertext verifiableCiphertext = largeCs.encryptVerifiably(secret, label);

        assertThat(largeCs.verifyEncryption(verifiableCiphertext, publicPoint, label)).isTrue();
        // a point rebuilt from coordinates on another instance of the same curve is accepted too
        LightECC otherInstance = LightECC.of("weierstrass", "secp256k1");
        CurvePoint coordinates = otherInstance.point(publicPoint.x(), publicPoint.y());
        assertThat(largeCs.verifyEncryption(verifiableCiphertext, coordinates, label)).isTrue();
        assertThat(largeCs.decryptVerifiableCiphertext(verifiableCiphertext, label))
                .isEqualTo(secret);

        // wrong label or wrong public point
        assertThat(largeCs.verifyEncryption(verifiableCiphertext, publicPoint, "other")).isFalse();
        CurvePoint otherPoint = secp256k1.g().multiply(secret.add(BigInteger.ONE));
        assertThat(largeCs.verifyEncryption(verifiableCiphertext, otherPoint, label)).isFalse();
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () -> largeCs.decryptVerifiableCiphertext(verifiableCiphertext, "other"))
                .withMessageContaining("different label");
    }

    @Test
    @DisplayName("Verifiable encryption rejects tampered ciphertexts and proofs")
    void testVerifiableEncryptionRejectsTampering() {
        BigInteger secret = randomSecret(secp256k1);
        CurvePoint publicPoint = secp256k1.g().multiply(secret);
        VerifiableCiphertext vc = largeCs.encryptVerifiably(secret);
        assertThat(largeCs.verifyEncryption(vc, publicPoint)).isTrue();

        UnaryOperator<BigInteger> plusOne = x -> x.add(BigInteger.ONE);
        VerifiableCiphertext.Proof proof = vc.proof();

        // modify each part of the ciphertext, commitment and proof
        List<VerifiableCiphertext> tampered =
                List.of(
                        new VerifiableCiphertext(
                                plusOne.apply(vc.u()), vc.e(), vc.v(), vc.commitment(), proof),
                        new VerifiableCiphertext(
                                vc.u(), plusOne.apply(vc.e()), vc.v(), vc.commitment(), proof),
                        new VerifiableCiphertext(
                                vc.u(), vc.e(), plusOne.apply(vc.v()), vc.commitment(), proof),
                        new VerifiableCiphertext(
                                vc.u(), vc.e(), vc.v(), plusOne.apply(vc.commitment()), proof),
                        withProof(
                                vc,
                                new VerifiableCiphertext.Proof(
                                        plusOne.apply(proof.challenge()),
                                        proof.r(),
                                        proof.s(),
                                        proof.m())),
                        withProof(
                                vc,
                                new VerifiableCiphertext.Proof(
                                        proof.challenge(),
                                        plusOne.apply(proof.r()),
                                        proof.s(),
                                        proof.m())),
                        withProof(
                                vc,
                                new VerifiableCiphertext.Proof(
                                        proof.challenge(),
                                        proof.r(),
                                        plusOne.apply(proof.s()),
                                        proof.m())),
                        withProof(
                                vc,
                                new VerifiableCiphertext.Proof(
                                        proof.challenge(),
                                        proof.r(),
                                        proof.s(),
                                        plusOne.apply(proof.m()))));
        for (VerifiableCiphertext candidate : tampered) {
            assertThat(largeCs.verifyEncryption(candidate, publicPoint)).isFalse();
        }

        // ciphertext of another secret with the proof of this secret
        VerifiableCiphertext other = largeCs.encryptVerifiably(secret.add(BigInteger.ONE));
        VerifiableCiphertext swapped =
                new VerifiableCiphertext(other.u(), other.e(), other.v(), vc.commitment(), proof);
        assertThat(largeCs.verifyEncryption(swapped, publicPoint)).isFalse();

        // proof of another secret for this public point
        assertThat(largeCs.verifyEncryption(other, publicPoint)).isFalse();

        // malformed inputs: components out of range
        VerifiableCiphertext outOfRange =
                new VerifiableCiphertext(BigInteger.ZERO, vc.e(), vc.v(), vc.commitment(), proof);
        assertThat(largeCs.verifyEncryption(outOfRange, publicPoint)).isFalse();
    }

    private static VerifiableCiphertext withProof(
            VerifiableCiphertext vc, VerifiableCiphertext.Proof proof) {
        return new VerifiableCiphertext(vc.u(), vc.e(), vc.v(), vc.commitment(), proof);
    }

    @Test
    @DisplayName("Verifiable encryption reduces secrets to the order of the curve")
    void testVerifiableEncryptionSecretRange() {
        BigInteger order = secp256k1.n();
        for (BigInteger secret :
                List.of(BigInteger.ONE, BigInteger.TWO, order.subtract(BigInteger.ONE))) {
            VerifiableCiphertext vc = largeCs.encryptVerifiably(secret);
            assertThat(largeCs.verifyEncryption(vc, secp256k1.g().multiply(secret))).isTrue();
            assertThat(largeCs.decryptVerifiableCiphertext(vc)).isEqualTo(secret);
        }

        // secrets are reduced to the order of the curve
        for (BigInteger secret :
                List.of(order.add(BigInteger.valueOf(5)), BigInteger.valueOf(-5))) {
            VerifiableCiphertext vc = largeCs.encryptVerifiably(secret);
            assertThat(largeCs.verifyEncryption(vc, secp256k1.g().multiply(secret.mod(order))))
                    .isTrue();
            assertThat(largeCs.decryptVerifiableCiphertext(vc)).isEqualTo(secret.mod(order));
        }

        // public point would be the point at infinity
        for (BigInteger secret : List.of(BigInteger.ZERO, order)) {
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> largeCs.encryptVerifiably(secret))
                    .withMessageContaining("multiple of the order");
        }
        VerifiableCiphertext vc = largeCs.encryptVerifiably(BigInteger.ONE);
        assertThat(largeCs.verifyEncryption(vc, secp256k1.o())).isFalse();
    }

    @Test
    @DisplayName("Verifiable encryption supports secrets of other curves")
    void testVerifiableEncryptionOtherCurve() {
        LightPHE edwardsCs =
                LightPHE.builder()
                        .algorithmName(ALGORITHM)
                        .keys(largeCs.cs().keys())
                        .form("edwards")
                        .curve("ed25519")
                        .build();
        LightECC ecc = LightECC.of("edwards", "ed25519");
        BigInteger secret = randomSecret(ecc);

        VerifiableCiphertext vc = edwardsCs.encryptVerifiably(secret);
        assertThat(edwardsCs.verifyEncryption(vc, ecc.g().multiply(secret))).isTrue();
        assertThat(edwardsCs.decryptVerifiableCiphertext(vc)).isEqualTo(secret);
    }

    @Test
    @DisplayName("Prover and verifier need the public key only")
    void testVerifiableEncryptionWithPublicKeyOnly(@TempDir Path tempDir) {
        Path publicKeyFile = tempDir.resolve("public.txt");
        largeCs.exportKeys(publicKeyFile, true);
        LightPHE publicCs =
                LightPHE.builder().algorithmName(ALGORITHM).keyFile(publicKeyFile).build();

        BigInteger secret = randomSecret(secp256k1);

        // prover and verifier need the public key only
        VerifiableCiphertext vc = publicCs.encryptVerifiably(secret);
        assertThat(publicCs.verifyEncryption(vc, secp256k1.g().multiply(secret))).isTrue();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> publicCs.decryptVerifiableCiphertext(vc))
                .withMessageContaining("You must have private key");

        assertThat(largeCs.decryptVerifiableCiphertext(vc)).isEqualTo(secret);
    }

    @Test
    @DisplayName("Verifiable encryption requires a large enough key")
    void testVerifiableEncryptionSmallKey() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.encryptVerifiably(BigInteger.valueOf(5)))
                .withMessageContaining("too small for verifiable encryption");

        VerifiableCiphertext dummy =
                new VerifiableCiphertext(
                        BigInteger.ONE,
                        BigInteger.ONE,
                        BigInteger.ONE,
                        BigInteger.ONE,
                        new VerifiableCiphertext.Proof(
                                BigInteger.ONE, BigInteger.ONE, BigInteger.ONE, BigInteger.ONE));
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.verifyEncryption(dummy, secp256k1.g().multiply(5)))
                .withMessageContaining("too small for verifiable encryption");
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"Paillier", "Bresson-Catalano-Pointcheval"})
    @DisplayName("Other algorithms do not support verifiable encryption")
    void testVerifiableEncryptionUnsupportedAlgorithms(String algorithmName) {
        LightPHE otherCs = LightPHE.builder().algorithmName(algorithmName).keySize(50).build();
        CurvePoint point = secp256k1.g().multiply(5);
        VerifiableCiphertext dummy =
                new VerifiableCiphertext(
                        BigInteger.ONE,
                        BigInteger.ONE,
                        BigInteger.ONE,
                        BigInteger.ONE,
                        new VerifiableCiphertext.Proof(
                                BigInteger.ONE, BigInteger.ONE, BigInteger.ONE, BigInteger.ONE));

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> otherCs.encryptVerifiably(BigInteger.valueOf(5)))
                .withMessageContaining("does not support verifiable encryption");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> otherCs.verifyEncryption(dummy, point))
                .withMessageContaining("does not support verifiable encryption");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> otherCs.decryptVerifiableCiphertext(dummy))
                .withMessageContaining("does not support verifiable encryption");
    }

    @Test
    @DisplayName("Camenisch-Shoup works with 1024-bit keys, floats and tensors")
    void testLargeKeys() {
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

    @Test
    @DisplayName("Camenisch-Shoup runs the verifiable encryption example in the readme")
    void testReadmeVerifiableEncryption(@TempDir Path tempDir) {
        Path publicKeyFile = tempDir.resolve("public.txt");

        // trusted third party builds the cryptosystem and publishes its public key
        LightPHE ttpCs = largeCs;
        ttpCs.exportKeys(publicKeyFile, true);

        // alice's wallet key pair on secp256k1
        LightECC ecc = LightECC.of("weierstrass", "secp256k1");
        BigInteger privateKey = BigInteger.valueOf(123456789);
        CurvePoint publicKey = ecc.g().multiply(privateKey);

        // alice encrypts her private key for the trusted third party with a proof
        String label = "release only if alice loses access to her wallet";
        LightPHE aliceCs =
                LightPHE.builder().algorithmName(ALGORITHM).keyFile(publicKeyFile).build();
        VerifiableCiphertext escrow = aliceCs.encryptVerifiably(privateKey, label);

        // bank verifies it with public keys only, without learning alice's private key
        LightPHE bankCs =
                LightPHE.builder().algorithmName(ALGORITHM).keyFile(publicKeyFile).build();
        assertThat(bankCs.verifyEncryption(escrow, publicKey, label)).isTrue();

        // trusted third party recovers the private key under the same label only
        assertThat(ttpCs.decryptVerifiableCiphertext(escrow, label)).isEqualTo(privateKey);
    }
}
