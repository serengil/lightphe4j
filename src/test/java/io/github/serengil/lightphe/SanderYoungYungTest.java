package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.serengil.lightphe.model.Ciphertext;
import io.github.serengil.lightphe.model.value.CipherValue;
import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Port of {@code tests/test_sanderyoungyung.py}. */
class SanderYoungYungTest {

    @Test
    @DisplayName("Sander-Young-Yung works without a plaintext limit")
    void testApiWithNoPlaintextLimit() {
        runApi(null);
    }

    @Test
    @DisplayName("Sander-Young-Yung works with a plaintext limit")
    void testApiWithPlaintextLimit() {
        runApi(BigInteger.valueOf(200));
    }

    private void runApi(BigInteger plaintextLimit) {
        LightPHE cs =
                LightPHE.builder()
                        .algorithmName("Sander-Young-Yung")
                        .keySize(50)
                        .plaintextLimit(plaintextLimit)
                        .build();

        BigInteger modulo = cs.cs().plaintextModulo();

        // try different bit size messages
        List<long[]> messages =
                List.of(new long[] {17, 22}, new long[] {117, 23}, new long[] {23, 117});

        for (long[] pair : messages) {
            BigInteger m1 = BigInteger.valueOf(pair[0]);
            BigInteger m2 = BigInteger.valueOf(pair[1]);

            Ciphertext c1 = cs.encrypt(m1);
            Ciphertext c2 = cs.encrypt(m2);

            // proof of decryption
            assertThat(cs.decrypt(c1)).isEqualTo(m1.mod(modulo));
            assertThat(cs.decrypt(c2)).isEqualTo(m2.mod(modulo));

            // re-randomization
            CipherValue c1Prime = cs.cs().reencrypt(c1.value());
            CipherValue c2Prime = cs.cs().reencrypt(c2.value());
            assertThat(c1Prime).isNotEqualTo(c1.value());
            assertThat(c2Prime).isNotEqualTo(c2.value());
            assertThat(cs.cs().decrypt(c1Prime)).isEqualTo(m1.mod(modulo));
            assertThat(cs.cs().decrypt(c2Prime)).isEqualTo(m2.mod(modulo));

            // homomorphic bitwise AND
            assertThat(cs.decrypt(c1.and(c2))).isEqualTo(m1.mod(modulo).and(m2.mod(modulo)));

            // unsupported homomorphic operations
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> c1.multiply(c2));
            assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.add(c2));
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> c1.multiply(5L));
        }
    }
}
