package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.serengil.lightphe.model.Ciphertext;
import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Port of {@code tests/test_large_keys.py}.
 *
 * <p>Disabled for the same reason as in the Python suite: this is an experimental benchmark for
 * large key sizes rather than a regression test.
 *
 * <pre>
 * Algorithm         | Key Size | Key Generation | Encryption | Homomorphic | Decryption
 * ---               | ---      | ---            | ---        | ---         | ---
 * Goldwasser-Micali | 1024     | 0.01           | 0.00       | 0.00        | 0.00
 * Goldwasser-Micali | 2048     | 0.08           | 0.00       | 0.00        | 0.03
 * Goldwasser-Micali | 3072     | 0.45           | 0.00       | 0.00        | 0.08
 * Goldwasser-Micali | 7680     | 11.30          | 0.00       | 0.00        | 1.21
 *
 * Benaloh           | 1024     | 4.91           | 0.00       | 0.00        | 0.01
 * Benaloh           | 2048     | 140.54         | 0.00       | 0.00        | 0.03
 * Benaloh           | 3072     | 439.46         | 0.00       | 0.00        | 0.08
 *
 * Naccache-Stern    | 1024     | 19.97          | 0.00       | 0.00        | 0.06
 * </pre>
 */
@Disabled("This is an experimental test for large key sizes.")
class LargeKeysTest {

    @Test
    @DisplayName("Larger key sizes still round trip")
    void testLargeKeys() {
        List<String> algorithms = List.of("Naccache-Stern", "Goldwasser-Micali", "Benaloh");
        List<Integer> keySizes = List.of(1024, 2048, 3072, 7680);

        for (int keySize : keySizes) {
            for (String algorithmName : algorithms) {
                LightPHE cs =
                        LightPHE.builder().algorithmName(algorithmName).keySize(keySize).build();

                long m1 = 17;
                long m2 = 23;

                Ciphertext c1 = cs.encrypt(m1);
                Ciphertext c2 = cs.encrypt(m2);

                if ("Goldwasser-Micali".equals(algorithmName)) {
                    assertThat(cs.decrypt(c1.xor(c2))).isEqualTo(BigInteger.valueOf(m1 ^ m2));
                } else {
                    assertThat(cs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(m1 + m2));
                }
            }
        }
    }
}
