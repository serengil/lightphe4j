package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.serengil.lightphe.model.Ciphertext;
import java.math.BigInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Port of {@code tests/test_rsa.py}. */
class RsaTest {

    @Test
    @DisplayName("RSA is homomorphic with respect to the multiplication only")
    void testApi() {
        LightPHE cs = LightPHE.builder().algorithmName("RSA").keySize(50).build();

        long m1 = 17;
        long m2 = 21;

        Ciphertext c1 = cs.encrypt(m1);
        Ciphertext c2 = cs.encrypt(m2);

        // homomorphic multiplication
        assertThat(cs.decrypt(c1.multiply(c2))).isEqualTo(BigInteger.valueOf(m1 * m2));

        // unsupported homomorphic operations
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.add(c2));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.xor(c2));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.multiply(5L));
    }

    @Test
    @DisplayName("RSA multiplies an encrypted integer by an encrypted fraction")
    void testFloatMultiplication() {
        LightPHE cs = LightPHE.builder().algorithmName("RSA").build();

        long m1 = 10000;
        double m2 = 1.05;

        Ciphertext c1 = cs.encrypt(m1);
        Ciphertext c2 = cs.encrypt(m2);

        assertThat(cs.decrypt(c1.multiply(c2))).isEqualTo(BigInteger.valueOf(10500));
    }
}
