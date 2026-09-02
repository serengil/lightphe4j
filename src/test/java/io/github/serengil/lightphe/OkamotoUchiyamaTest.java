package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.serengil.lightphe.model.Ciphertext;
import java.math.BigInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Port of {@code tests/test_okamoto.py}. */
class OkamotoUchiyamaTest {

    @Test
    @DisplayName("Okamoto-Uchiyama supports homomorphic addition and scalar multiplication")
    void testApi() {
        LightPHE cs = LightPHE.builder().algorithmName("Okamoto-Uchiyama").keySize(50).build();

        long m1 = 17;
        long m2 = 21;

        Ciphertext c1 = cs.encrypt(m1);
        Ciphertext c2 = cs.encrypt(m2);

        // homomorphic addition
        assertThat(cs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(m1 + m2));

        // homomorphic scalar multiplication
        assertThat(cs.decrypt(c1.multiply(m2))).isEqualTo(BigInteger.valueOf(m1 * m2));
        assertThat(cs.decrypt(c2.multiply(m1))).isEqualTo(BigInteger.valueOf(m1 * m2));

        // unsupported homomorphic operations
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.multiply(c2));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.xor(c2));
    }
}
