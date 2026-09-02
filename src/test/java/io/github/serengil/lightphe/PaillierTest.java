package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.serengil.lightphe.model.Ciphertext;
import java.math.BigInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Port of {@code tests/test_paillier.py}. */
class PaillierTest {

    private static final LightPHE cs =
            LightPHE.builder().algorithmName("Paillier").keySize(50).build();

    @Test
    @DisplayName("Paillier supports homomorphic addition and scalar multiplication")
    void testApi() {
        long m1 = 17;
        long m2 = 21;

        Ciphertext c1 = cs.encrypt(m1);
        Ciphertext c2 = cs.encrypt(m2);

        // homomorphic addition
        assertThat(cs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(m1 + m2));

        // homomorphic scalar multiplication
        assertThat(cs.decrypt(c1.multiply(m2))).isEqualTo(BigInteger.valueOf(m1 * m2));
        assertThat(cs.decrypt(c2.multiply(m1))).isEqualTo(BigInteger.valueOf(m1 * m2));

        Ciphertext c1Prime = cs.regenerateCiphertext(c1);
        assertThat(c1Prime.value()).isNotEqualTo(c1.value());
        assertThat(cs.decrypt(c1Prime)).isEqualTo(cs.decrypt(c1));

        // unsupported homomorphic operations
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.multiply(c2));

        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.xor(c2));
    }

    @Test
    @DisplayName("Paillier handles negative and fractional constants")
    void testFloatOperations() {
        long m1 = 1000;
        long m2 = -10;

        Ciphertext c1 = cs.encrypt(m1);
        Ciphertext c2 = cs.encrypt(m2);

        assertThat(cs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(m1 + m2));
        assertThat(cs.decrypt(c2.add(c1))).isEqualTo(BigInteger.valueOf(m1 + m2));

        long k1 = 20;
        assertThat(cs.decrypt(c1.multiply(k1))).isEqualTo(BigInteger.valueOf(m1 * k1));

        double k2 = 1.05;
        assertThat(cs.decrypt(c1.multiply(k2))).isEqualTo(BigInteger.valueOf(1050));

        // a negative constant wraps around the plaintext modulus
        long k3 = -20;
        BigInteger expected = BigInteger.valueOf(m1 * k3).mod(cs.cs().plaintextModulo());
        assertThat(cs.decrypt(c1.multiply(k3))).isEqualTo(expected);
    }
}
