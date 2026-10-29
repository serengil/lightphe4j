package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.KeysCodec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Port of {@code tests/test_exporting_keys.py}. */
class ExportingKeysTest {

    @Test
    @DisplayName("Exporting the public key leaves the private key in place")
    void testPrivateAvailableAfterExport(@TempDir Path tempDir) throws IOException {
        Path targetFile = tempDir.resolve("my_public_key.lphe");
        LightPHE cs = LightPHE.builder().algorithmName("RSA").keySize(50).build();

        // we are dropping the private key while exporting the public key
        cs.exportKeys(targetFile, true);
        assertThat(cs.cs().keys().hasPrivateKey())
                .as("private key is still available in the cryptosystem after export")
                .isTrue();

        String keyString = Files.readString(targetFile, StandardCharsets.UTF_8);
        Keys exported = KeysCodec.fromJson(keyString);
        assertThat(exported.hasPrivateKey())
                .as("private key is not available in the public key file")
                .isFalse();
        assertThat(exported.publicKey()).containsKeys("n", "e");
    }

    @Test
    @DisplayName("Content of a key file is not executed while restoring keys")
    void testMaliciousKeyFileIsNotExecuted(@TempDir Path tempDir) throws IOException {
        Path markerFile = tempDir.resolve("pwned.txt");
        Path keyFile = tempDir.resolve("malicious.lphe");
        String payload = "__import__('pathlib').Path('" + markerFile + "').write_text('pwned')";
        Files.writeString(keyFile, payload, StandardCharsets.UTF_8);

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> LightPHE.builder().algorithmName("RSA").keyFile(keyFile).build());

        assertThat(markerFile).doesNotExist();
    }
}
