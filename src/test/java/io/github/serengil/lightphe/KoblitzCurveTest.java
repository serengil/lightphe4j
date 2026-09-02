package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.serengil.lightphe.model.Ciphertext;
import java.math.BigInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Coverage for the Koblitz form over binary fields, which the Python suite leaves out of its
 * elliptic curve tests to keep continuous integration fast. A couple of small curves are cheap
 * enough to exercise here, and they are the only place the {@code GF(2^m)} arithmetic is reached.
 */
class KoblitzCurveTest {

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"k163", "sect113r1"})
    @DisplayName("Elliptic curve ElGamal is additively homomorphic over a binary field")
    void testApi(String curve) {
        LightPHE cs =
                LightPHE.builder()
                        .algorithmName("EllipticCurve-ElGamal")
                        .form("koblitz")
                        .curve(curve)
                        .build();

        long m1 = 10;
        long m2 = 5;

        Ciphertext c1 = cs.encrypt(m1);
        Ciphertext c2 = cs.encrypt(m2);

        // proof of decryption
        assertThat(cs.decrypt(c1)).isEqualTo(BigInteger.valueOf(m1));
        assertThat(cs.decrypt(c2)).isEqualTo(BigInteger.valueOf(m2));

        // homomorphic addition and scalar multiplication
        assertThat(cs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(m1 + m2));
        assertThat(cs.decrypt(c1.multiply(m2))).isEqualTo(BigInteger.valueOf(m1 * m2));
    }
}
