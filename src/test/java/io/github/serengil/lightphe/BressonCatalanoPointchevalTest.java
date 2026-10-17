package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.within;

import io.github.serengil.lightphe.model.Ciphertext;
import io.github.serengil.lightphe.model.EncryptedTensor;
import io.github.serengil.lightphe.model.Keys;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Port of {@code tests/test_bressoncatalanopointcheval.py}. */
class BressonCatalanoPointchevalTest {

    private static final String ALGORITHM = "Bresson-Catalano-Pointcheval";

    private static final LightPHE cs =
            LightPHE.builder().algorithmName(ALGORITHM).keySize(50).build();

    private static LightPHE withKeys(Keys keys) {
        return LightPHE.builder().algorithmName(ALGORITHM).keys(keys).build();
    }

    @Test
    @DisplayName(
            "Bresson-Catalano-Pointcheval supports homomorphic addition and scalar multiplication")
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
    @DisplayName("Bresson-Catalano-Pointcheval keys are built from safe primes")
    void testKeysAreWellFormed() {
        BigInteger n = cs.cs().keys().publicNumber("n");
        BigInteger p = cs.cs().keys().privateNumber("p");
        BigInteger q = cs.cs().keys().privateNumber("q");
        assertThat(n).isEqualTo(p.multiply(q));
        assertThat(p).isNotEqualTo(q);

        // p and q are safe primes
        for (BigInteger prime : List.of(p, q)) {
            assertThat(BigInteger.TWO.modPow(prime.subtract(BigInteger.ONE), prime))
                    .isEqualTo(BigInteger.ONE);
            BigInteger pPrime = prime.subtract(BigInteger.ONE).shiftRight(1);
            assertThat(BigInteger.TWO.modPow(pPrime.subtract(BigInteger.ONE), pPrime))
                    .isEqualTo(BigInteger.ONE);
        }
    }

    @Test
    @DisplayName("The master trapdoor decrypts without the local trapdoor")
    void testMasterTrapdoor() {
        // factorization of n decrypts without the local trapdoor a
        for (BigInteger m :
                List.of(
                        BigInteger.ZERO,
                        BigInteger.ONE,
                        BigInteger.valueOf(17),
                        BigInteger.valueOf(12345),
                        cs.cs().plaintextModulo().subtract(BigInteger.ONE))) {
            Ciphertext c = cs.encrypt(m);
            assertThat(cs.decryptWithMasterKey(c)).isEqualTo(m);
            assertThat(cs.decryptWithMasterKey(c.multiply(3L).add(c)))
                    .isEqualTo(cs.decrypt(c.multiply(4L)));
        }
    }

    @Test
    @DisplayName("The master key decrypts ciphertexts of all users")
    void testMasterKeyDecryptsAllUsers() {
        // authority generates the master key, and publishes n and g with its public key
        LightPHE authorityCs = LightPHE.builder().algorithmName(ALGORITHM).keySize(50).build();
        LightPHE authorityPublicCs = withKeys(authorityCs.cs().keys().publicOnly());

        // each user generates its own key pair with the public key of the authority
        Keys aliceKeys = authorityPublicCs.generateUserKeys();
        Keys bobKeys = authorityPublicCs.generateUserKeys();
        assertThat(aliceKeys.privateKey().keySet()).containsExactly("a");
        assertThat(aliceKeys.publicNumber("n"))
                .isEqualTo(authorityCs.cs().keys().publicNumber("n"));
        assertThat(aliceKeys.publicNumber("g"))
                .isEqualTo(authorityCs.cs().keys().publicNumber("g"));
        assertThat(aliceKeys.publicNumber("h")).isNotEqualTo(bobKeys.publicNumber("h"));

        LightPHE aliceCs = withKeys(aliceKeys);
        LightPHE bobCs = withKeys(bobKeys);

        Ciphertext aliceC = aliceCs.encrypt(123).add(aliceCs.encrypt(456));
        Ciphertext bobC = bobCs.encrypt(1000).multiply(3L);

        // users decrypt their own ciphertexts
        assertThat(aliceCs.decrypt(aliceC)).isEqualTo(BigInteger.valueOf(579));
        assertThat(bobCs.decrypt(bobC)).isEqualTo(BigInteger.valueOf(3000));

        // but not each other's
        assertThat(aliceCs.decrypt(bobC)).isNotEqualTo(BigInteger.valueOf(3000));
        assertThat(bobCs.decrypt(aliceC)).isNotEqualTo(BigInteger.valueOf(579));

        // users do not have the master key
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> aliceCs.decryptWithMasterKey(bobC))
                .withMessageContaining("master trapdoor");

        // authority decrypts ciphertexts of all users without knowing their local trapdoors
        assertThat(authorityCs.decryptWithMasterKey(aliceC)).isEqualTo(BigInteger.valueOf(579));
        assertThat(authorityCs.decryptWithMasterKey(bobC)).isEqualTo(BigInteger.valueOf(3000));

        // authority may keep the master trapdoor only
        Keys masterKeys = authorityCs.cs().keys().deepCopy();
        masterKeys.privateKey().remove("a");
        LightPHE masterCs = withKeys(masterKeys);
        assertThat(masterCs.decryptWithMasterKey(aliceC)).isEqualTo(BigInteger.valueOf(579));
        assertThat(masterCs.decryptWithMasterKey(bobC)).isEqualTo(BigInteger.valueOf(3000));
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> masterCs.decrypt(aliceC))
                .withMessageContaining("local trapdoor");

        // encryption with public key of a user restored from a file is still decryptable
        LightPHE restoredCs = withKeys(bobKeys.publicOnly());
        assertThat(masterCs.decryptWithMasterKey(restoredCs.encrypt(7)))
                .isEqualTo(BigInteger.valueOf(7));
    }

    @Test
    @DisplayName("The master key decrypts tensors of users")
    void testMasterKeyDecryptsTensors() {
        LightPHE userCs = withKeys(cs.generateUserKeys());
        EncryptedTensor encTensor = userCs.encryptTensor(List.of(1.5, -2.25, 3));
        assertTensor(cs.decryptTensorWithMasterKey(encTensor), 1.5, -2.25, 3);
        assertTensor(cs.decryptTensorWithMasterKey(encTensor.multiply(2L)), 3, -4.5, 6);
        assertThat(cs.decryptTensor(encTensor)).isNotEqualTo(List.of(1.5, -2.25, 3.0));
    }

    private static void assertTensor(List<Double> actual, double... expected) {
        assertThat(actual).hasSize(expected.length);
        for (int i = 0; i < expected.length; i++) {
            assertThat(actual.get(i)).isCloseTo(expected[i], within(1e-9));
        }
    }

    @Test
    @DisplayName("The master key rejects ciphertexts of another system")
    void testMasterKeyOfAnotherSystem() {
        LightPHE otherCs = LightPHE.builder().algorithmName(ALGORITHM).keySize(50).build();
        Ciphertext c = otherCs.encrypt(5);
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.decryptWithMasterKey(c))
                .withMessageContaining("does not share the same n and g");
    }

    @Test
    @DisplayName("Master key decryption requires the private key")
    void testMasterKeyRequiresPrivateKey(@TempDir Path tempDir) {
        Path publicKeyFile = tempDir.resolve("public.txt");
        cs.exportKeys(publicKeyFile, true);
        LightPHE publicCs =
                LightPHE.builder().algorithmName(ALGORITHM).keyFile(publicKeyFile).build();
        Ciphertext c = publicCs.encrypt(5);

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> publicCs.decryptWithMasterKey(c))
                .withMessageContaining("You must have private key");

        // public key is enough to generate user keys
        LightPHE userCs = withKeys(publicCs.generateUserKeys());
        assertThat(cs.decryptWithMasterKey(userCs.encrypt(9))).isEqualTo(BigInteger.valueOf(9));
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"Paillier", "RSA", "Damgard-Geisler-Kroigaard"})
    @DisplayName("Other algorithms do not support master keys")
    void testMasterKeyUnsupportedAlgorithms(String algorithmName) {
        LightPHE otherCs = LightPHE.builder().algorithmName(algorithmName).keySize(50).build();
        Ciphertext c = otherCs.encrypt(5);

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> otherCs.decryptWithMasterKey(c))
                .withMessageContaining("does not support master key decryption");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(otherCs::generateUserKeys)
                .withMessageContaining("does not support generating user keys");
    }

    @Test
    @DisplayName("Bresson-Catalano-Pointcheval works with predefined keys")
    void testApiWithPredefinedKeys() {
        LightPHE restoredCs = withKeys(cs.cs().keys());
        long m1 = 11;
        long m2 = 7;
        Ciphertext c1 = cs.encrypt(m1);
        Ciphertext c2 = restoredCs.encrypt(m2);
        assertThat(restoredCs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(m1 + m2));
        assertThat(cs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(m1 + m2));
    }

    @Test
    @DisplayName("Bresson-Catalano-Pointcheval works with exported public keys")
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
    @DisplayName("Bresson-Catalano-Pointcheval works with 1024-bit keys, floats and tensors")
    void testLargeKeys() {
        LightPHE largeCs = LightPHE.builder().algorithmName(ALGORITHM).keySize(1024).build();
        long m1 = 123456789;
        long m2 = 987654321;
        Ciphertext c1 = largeCs.encrypt(m1);
        Ciphertext c2 = largeCs.encrypt(m2);
        assertThat(largeCs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(m1 + m2));
        assertThat(largeCs.decrypt(c1.multiply(1000L))).isEqualTo(BigInteger.valueOf(m1 * 1000));
        assertThat(largeCs.decryptWithMasterKey(c1.add(c2))).isEqualTo(BigInteger.valueOf(m1 + m2));

        // floats and tensors
        Ciphertext c3 = largeCs.encrypt(1.5);
        assertThat(largeCs.decrypt(c3.multiply(4L))).isEqualTo(BigInteger.valueOf(6));
        EncryptedTensor encTensor = largeCs.encryptTensor(List.of(1.5, 2.25, 3.5));
        assertTensor(largeCs.decryptTensor(encTensor), 1.5, 2.25, 3.5);
        assertTensor(largeCs.decryptTensor(encTensor.matmul(List.of(2, 4, 1))), 15.5);
    }

    @Test
    @DisplayName("Bresson-Catalano-Pointcheval runs the master key example in the readme")
    void testReadmeMasterKey(@TempDir Path tempDir) {
        Path publicKeyFile = tempDir.resolve("public.txt");

        // authority generates the master key and publishes its public key
        LightPHE authorityCs = LightPHE.builder().algorithmName(ALGORITHM).keySize(256).build();
        authorityCs.exportKeys(publicKeyFile, true);

        // each user generates its own key pair with the public key of the authority
        LightPHE publicCs =
                LightPHE.builder().algorithmName(ALGORITHM).keyFile(publicKeyFile).build();
        LightPHE aliceCs = withKeys(publicCs.generateUserKeys());
        LightPHE bobCs = withKeys(publicCs.generateUserKeys());

        Ciphertext aliceCiphertext = aliceCs.encrypt(100).add(aliceCs.encrypt(50));
        Ciphertext bobCiphertext = bobCs.encrypt(200);

        // users decrypt their own ciphertexts only
        assertThat(aliceCs.decrypt(aliceCiphertext)).isEqualTo(BigInteger.valueOf(150));
        assertThat(aliceCs.decrypt(bobCiphertext)).isNotEqualTo(BigInteger.valueOf(200));

        // authority decrypts ciphertexts of all users
        assertThat(authorityCs.decryptWithMasterKey(aliceCiphertext))
                .isEqualTo(BigInteger.valueOf(150));
        assertThat(authorityCs.decryptWithMasterKey(bobCiphertext))
                .isEqualTo(BigInteger.valueOf(200));
    }
}
