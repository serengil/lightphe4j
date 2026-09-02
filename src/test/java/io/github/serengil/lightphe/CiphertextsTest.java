package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.serengil.lightphe.model.Ciphertext;
import io.github.serengil.lightphe.model.EncryptedTensor;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Port of {@code tests/test_ciphertexts.py}. */
class CiphertextsTest {

    private static final LightPHE onpremCs =
            LightPHE.builder().algorithmName("Paillier").keySize(50).build();

    @Test
    @DisplayName("A ciphertext never carries the private key")
    void testPrivateKeyNotAvailableInCiphertext() {
        Ciphertext c = onpremCs.encrypt(17);

        assertThat(c.cs().keys().hasPrivateKey()).isFalse();
        assertThat(onpremCs.cs().keys().hasPrivateKey()).isTrue();
    }

    @Test
    @DisplayName("An encrypted tensor never carries the private key")
    void testPrivateKeyNotAvailableInEncryptedTensor() {
        EncryptedTensor c = onpremCs.encryptTensor(List.of(1.5, 2.4, 3.3, 4.2, 5.1));

        assertThat(c.cs().keys().hasPrivateKey()).isFalse();
        assertThat(onpremCs.cs().keys().hasPrivateKey()).isTrue();
    }
}
