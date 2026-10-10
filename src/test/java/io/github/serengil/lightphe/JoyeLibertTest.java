package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.serengil.lightphe.model.Ciphertext;
import io.github.serengil.lightphe.model.EncryptedTensor;
import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Port of {@code tests/test_joyelibert.py}. */
class JoyeLibertTest {

    private static final LightPHE cs =
            LightPHE.builder().algorithmName("Joye-Libert").keySize(50).build();

    @Test
    @DisplayName("Joye-Libert supports homomorphic addition and scalar multiplication")
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

        // powers of 10 are not invertible in Z_{2^k}, so floats are not supported
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> c1.multiply(1.5))
                .withMessageContaining("Joye-Libert does not support float");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.encrypt(1.5))
                .withMessageContaining("Joye-Libert does not support float");
    }

    @Test
    @DisplayName("Joye-Libert restores every plaintext of a small key space")
    void testAllPlaintextsInSmallSpace() {
        LightPHE smallCs = LightPHE.builder().algorithmName("Joye-Libert").keySize(24).build();
        long modulo = smallCs.cs().plaintextModulo().longValueExact();
        for (long m = 0; m < modulo; m++) {
            assertThat(smallCs.decrypt(smallCs.encrypt(m))).isEqualTo(BigInteger.valueOf(m));
        }
    }

    @Test
    @DisplayName("Joye-Libert works with predefined keys")
    void testApiWithPredefinedKeys() {
        LightPHE restoredCs =
                LightPHE.builder().algorithmName("Joye-Libert").keys(cs.cs().keys()).build();
        Ciphertext c1 = cs.encrypt(11L);
        Ciphertext c2 = restoredCs.encrypt(7L);
        assertThat(restoredCs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(18));
        assertThat(cs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(18));
    }

    @Test
    @DisplayName("Joye-Libert works with 1024-bit keys")
    void testLargeKeys() {
        LightPHE largeCs = LightPHE.builder().algorithmName("Joye-Libert").keySize(1024).build();
        long m1 = 123456789;
        long m2 = 987654321;
        Ciphertext c1 = largeCs.encrypt(m1);
        Ciphertext c2 = largeCs.encrypt(m2);
        assertThat(largeCs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(m1 + m2));
        assertThat(largeCs.decrypt(c1.multiply(1000L))).isEqualTo(BigInteger.valueOf(m1 * 1000));

        // tensors are still supported because division happens after decryption
        EncryptedTensor encryptedTensor = largeCs.encryptTensor(List.of(1.5, 2.25, 3.5));
        assertThat(largeCs.decryptTensor(encryptedTensor)).containsExactly(1.5, 2.25, 3.5);
        assertThat(largeCs.decryptTensor(encryptedTensor.matmul(List.of(2, 4, 1))))
                .containsExactly(15.5);

        // but multiplying a tensor with a float constant is not
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> encryptedTensor.multiply(1.5))
                .withMessageContaining("Joye-Libert does not support float");
    }
}
