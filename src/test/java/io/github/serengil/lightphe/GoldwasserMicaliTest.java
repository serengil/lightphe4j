package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.serengil.lightphe.model.Ciphertext;
import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Port of {@code tests/test_goldwasser.py}. */
class GoldwasserMicaliTest {

    @Test
    @DisplayName("Goldwasser-Micali is homomorphic with respect to the exclusive or")
    void testApi() {
        LightPHE cs = LightPHE.builder().algorithmName("Goldwasser-Micali").keySize(50).build();

        // try different bit size messages
        List<long[]> messages =
                List.of(
                        new long[] {17, 21},
                        new long[] {117, 23},
                        new long[] {23, 117},
                        new long[] {1117, 23},
                        new long[] {12, 1118});

        for (long[] pair : messages) {
            long m1 = pair[0];
            long m2 = pair[1];

            Ciphertext c1 = cs.encrypt(m1);
            Ciphertext c2 = cs.encrypt(m2);

            // homomorphic exclusive or
            assertThat(cs.decrypt(c1.xor(c2))).isEqualTo(BigInteger.valueOf(m1 ^ m2));

            // unsupported homomorphic operations
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> c1.multiply(c2));
            assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.add(c2));
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> c1.multiply(5L));
        }
    }
}
