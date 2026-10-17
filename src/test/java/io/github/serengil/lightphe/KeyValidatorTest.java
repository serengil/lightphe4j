package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.serengil.lightphe.commons.KeyValidator;
import io.github.serengil.lightphe.model.Algorithm;
import io.github.serengil.lightphe.model.KeyValue;
import io.github.serengil.lightphe.model.Keys;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** Port of {@code tests/test_key_validator.py}. */
class KeyValidatorTest {

    @ParameterizedTest(name = "{0}")
    @CsvSource({
        "RSA, 50",
        "ElGamal, 50",
        "Exponential-ElGamal, 50",
        "EllipticCurve-ElGamal, 50",
        "Paillier, 50",
        "Damgard-Jurik, 50",
        "Okamoto-Uchiyama, 50",
        "Benaloh, 50",
        "Naccache-Stern, 50",
        "Goldwasser-Micali, 50",
        "Sander-Young-Yung, 50",
        "Boneh-Goh-Nissim, 50",
        "Joye-Libert, 50",
        "Castagnos-Laguillaumie, 50",
        "Ishai-Paskin, 50",
        "Damgard-Geisler-Kroigaard, 50",
        "Bresson-Catalano-Pointcheval, 50",
        "Camenisch-Shoup, 50",
        "EllipticCurve-Paillier, 50",
        "Regev, 50",
        "Brakerski-Vaikuntanathan, 64",
        "Freeman-Boneh-Goh-Nissim, 64",
        "Gentry-Halevi-Vaikuntanathan, 2",
    })
    @DisplayName("Dropping a required public_key sub-field is rejected")
    void testMissingPublicKeyFieldIsRejected(String algorithmName, int keySize) {
        LightPHE cs =
                LightPHE.builder()
                        .algorithmName(algorithmName)
                        .keySize(keySize)
                        .maxTries(10000)
                        .build();

        String field = cs.cs().requiredKeys().publicKey().get(0);

        Keys broken = cs.cs().keys().deepCopy();
        broken.publicKey().remove(field);

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () -> LightPHE.builder().algorithmName(algorithmName).keys(broken).build())
                .withMessageContaining("missing required fields")
                .withMessageContaining(field);
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource({
        "RSA, 50",
        "ElGamal, 50",
        "Exponential-ElGamal, 50",
        "EllipticCurve-ElGamal, 50",
        "Paillier, 50",
        "Damgard-Jurik, 50",
        "Okamoto-Uchiyama, 50",
        "Benaloh, 50",
        "Naccache-Stern, 50",
        "Goldwasser-Micali, 50",
        "Sander-Young-Yung, 50",
        "Boneh-Goh-Nissim, 50",
        "Joye-Libert, 50",
        "Castagnos-Laguillaumie, 50",
        "Ishai-Paskin, 50",
        "Damgard-Geisler-Kroigaard, 50",
        "Bresson-Catalano-Pointcheval, 50",
        "Camenisch-Shoup, 50",
        "EllipticCurve-Paillier, 50",
        "Regev, 50",
        "Brakerski-Vaikuntanathan, 64",
        "Freeman-Boneh-Goh-Nissim, 64",
        "Gentry-Halevi-Vaikuntanathan, 2",
    })
    @DisplayName("Dropping a required private_key sub-field is rejected")
    void testMissingPrivateKeyFieldIsRejected(String algorithmName, int keySize) {
        LightPHE cs =
                LightPHE.builder()
                        .algorithmName(algorithmName)
                        .keySize(keySize)
                        .maxTries(10000)
                        .build();

        List<String> required = cs.cs().requiredKeys().privateKey();
        String field = required.get(0);

        // keep required fields only, otherwise alternative fields may satisfy validation
        Keys broken = cs.cs().keys().deepCopy();
        broken.privateKey().keySet().retainAll(required);
        broken.privateKey().remove(field);

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () -> LightPHE.builder().algorithmName(algorithmName).keys(broken).build())
                .withMessageContaining("missing required fields")
                .withMessageContaining(field);
    }

    @Test
    @DisplayName("A key pair without a public key is rejected")
    void testMissingPublicKeyDictIsRejected() {
        Keys empty = Keys.of(null, null);
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> LightPHE.builder().algorithmName("RSA").keys(empty).build())
                .withMessageContaining("must contain 'public_key'");
    }

    @Test
    @DisplayName("Supplying a private key without a public key is rejected")
    void testPrivateKeyOnlyIsRejected() {
        LightPHE cs = LightPHE.builder().algorithmName("RSA").keySize(50).build();
        Keys privateOnly = Keys.of(null, cs.cs().keys().deepCopy().privateKey());

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> LightPHE.builder().algorithmName("RSA").keys(privateOnly).build())
                .withMessageContaining("must contain 'public_key'");
    }

    @Test
    @DisplayName("A null key pair is rejected")
    void testNullKeysIsRejected() {
        // Java's type system already rules out the Python test's string-instead-of-dict case, so
        // the remaining "not a key pair" input is a null reference.
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> KeyValidator.validateKeys(Algorithm.RSA, null))
                .withMessageContaining("keys must be a dict");
    }

    @Test
    @DisplayName("A full public key on its own is accepted for encryption-only use")
    void testPublicKeyOnlyIsAccepted() {
        LightPHE cs = LightPHE.builder().algorithmName("RSA").keySize(50).build();
        Keys publicOnly = cs.cs().keys().publicOnly();

        // should not raise
        LightPHE encryptionOnly = LightPHE.builder().algorithmName("RSA").keys(publicOnly).build();
        assertThat(encryptionOnly.cs().keys().hasPrivateKey()).isFalse();
    }

    @Test
    @DisplayName("Dropping a required Boneh-Goh-Nissim nested curve field is rejected")
    void testBgnNestedCurveFieldIsRejected() {
        LightPHE cs =
                LightPHE.builder()
                        .algorithmName("Boneh-Goh-Nissim")
                        .keySize(50)
                        .maxTries(10000)
                        .build();

        List<String> nested = cs.cs().requiredKeys().nested().get("curve");
        assertThat(nested).as("BGN must declare nested curve required fields").isNotEmpty();
        String field = nested.get(0);

        Keys broken = cs.cs().keys().deepCopy();
        ((KeyValue.Nested) broken.publicKey().get("curve")).entries().remove(field);

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                LightPHE.builder()
                                        .algorithmName("Boneh-Goh-Nissim")
                                        .keys(broken)
                                        .build())
                .withMessageContaining("public_key.curve")
                .withMessageContaining("missing required fields")
                .withMessageContaining(field);
    }

    @Test
    @DisplayName(
            "Bresson-Catalano-Pointcheval accepts a private key having the master trapdoor only")
    void testAlternativePrivateKeyIsAccepted() {
        LightPHE cs =
                LightPHE.builder()
                        .algorithmName("Bresson-Catalano-Pointcheval")
                        .keySize(50)
                        .build();
        Keys masterOnly = cs.cs().keys().deepCopy();
        masterOnly.privateKey().remove("a");
        // should not raise
        LightPHE.builder().algorithmName("Bresson-Catalano-Pointcheval").keys(masterOnly).build();

        // neither the required nor the alternative fields
        masterOnly.privateKey().remove("q");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                LightPHE.builder()
                                        .algorithmName("Bresson-Catalano-Pointcheval")
                                        .keys(masterOnly)
                                        .build())
                .withMessageMatching("(?s).*missing required fields.*a.*alternatively.*");
    }
}
