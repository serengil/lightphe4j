package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.serengil.lightphe.model.Ciphertext;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Port of {@code tests/test_keys.py}. */
class KeysTest {

    private static final List<String> MULTIPLICATIVE = List.of("RSA", "ElGamal");

    /**
     * ElGamal's message space is a single prime drawn below {@code 2^(keySize/2)}, so at the
     * original 37 bits about 1.75% of key pairs cannot hold the 217 * 23 this test asserts. Only
     * that family needs more room: the other schemes build their modulus from two primes, cap it by
     * design, or do not multiply at all. Naccache-Stern in particular gets much slower as the key
     * grows, so it stays at the original size.
     */
    private static final List<String> NEEDS_HEADROOM = List.of("ElGamal", "Exponential-ElGamal");

    private static int keySizeFor(String algorithmName) {
        return NEEDS_HEADROOM.contains(algorithmName) ? 64 : 37;
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(
            strings = {
                "RSA",
                "ElGamal",
                "Exponential-ElGamal",
                "Paillier",
                "Damgard-Jurik",
                "Okamoto-Uchiyama",
                "Benaloh",
                "Naccache-Stern",
                "Goldwasser-Micali",
                "EllipticCurve-ElGamal",
            })
    @DisplayName("Keys survive an export and restore round trip")
    void testKeyRestoration(String algorithmName, @TempDir Path tempDir) {
        Path privateKeyFile = tempDir.resolve(algorithmName + "_secret.json");
        Path publicKeyFile = tempDir.resolve(algorithmName + "_public.json");

        LightPHE onpremCs = LightPHE.builder().algorithmName(algorithmName).keySize(37).build();

        onpremCs.exportKeys(privateKeyFile);
        onpremCs.exportKeys(publicKeyFile, true);

        LightPHE cloudCs =
                LightPHE.builder().algorithmName(algorithmName).keyFile(publicKeyFile).build();

        long m1 = 217;
        long m2 = 23;
        long k = 3;

        // Guard the precondition explicitly, so a future change fails with a clear reason. The
        // bound depends on the branch taken below: the multiplicative schemes assert m1 * m2,
        // Goldwasser-Micali works bit by bit and has no bound, and the rest assert m1 + m2 and
        // k * m1. Benaloh in particular caps its message space at a prime below 2000 by design.
        BigInteger required;
        if (MULTIPLICATIVE.contains(algorithmName)) {
            required = BigInteger.valueOf(m1 * m2);
        } else if ("Goldwasser-Micali".equals(algorithmName)) {
            required = BigInteger.ZERO;
        } else {
            required = BigInteger.valueOf(Math.max(m1 + m2, k * m1));
        }
        assertThat(cloudCs.cs().plaintextModulo())
                .as("the message space must hold the values this test asserts")
                .isGreaterThan(required);

        Ciphertext c1 = cloudCs.encrypt(m1);
        Ciphertext c2 = cloudCs.encrypt(m2);

        Ciphertext c3;
        Ciphertext c4 = null;
        if (MULTIPLICATIVE.contains(algorithmName)) {
            c3 = c1.multiply(c2);
        } else if ("Goldwasser-Micali".equals(algorithmName)) {
            c3 = c1.xor(c2);
        } else {
            c3 = c1.add(c2);
            c4 = c1.multiply(k);
        }

        // restore the on-premise cryptosystem
        LightPHE restored =
                LightPHE.builder().algorithmName(algorithmName).keyFile(privateKeyFile).build();

        if (MULTIPLICATIVE.contains(algorithmName)) {
            assertThat(restored.decrypt(c3)).isEqualTo(BigInteger.valueOf(m1 * m2));
        } else if ("Goldwasser-Micali".equals(algorithmName)) {
            assertThat(restored.decrypt(c3)).isEqualTo(BigInteger.valueOf(m1 ^ m2));
        } else {
            assertThat(restored.decrypt(c3)).isEqualTo(BigInteger.valueOf(m1 + m2));
            assertThat(restored.decrypt(c4)).isEqualTo(BigInteger.valueOf(k * m1));
        }
    }
}
