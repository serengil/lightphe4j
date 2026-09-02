package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.serengil.lightphe.model.Ciphertext;
import io.github.serengil.lightphe.model.value.CipherValue;
import java.math.BigInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Port of {@code tests/test_ellipticcurveelgamal.py}.
 *
 * <p>The Koblitz form is excluded, as in the Python suite, because of the longer key generation
 * times it would add to continuous integration.
 */
class EllipticCurveElGamalTest {

    @ParameterizedTest(name = "{0} form")
    @ValueSource(strings = {"weierstrass", "edwards"})
    @DisplayName("Elliptic curve ElGamal is additively homomorphic")
    void testApi(String form) {
        LightPHE cs = LightPHE.builder().algorithmName("EllipticCurve-ElGamal").form(form).build();

        long m1 = 10;
        long m2 = 5;

        Ciphertext c1 = cs.encrypt(m1);
        Ciphertext c2 = cs.encrypt(m2);

        // proof of decryption
        assertThat(cs.decrypt(c1)).isEqualTo(BigInteger.valueOf(m1));
        assertThat(cs.decrypt(c2)).isEqualTo(BigInteger.valueOf(m2));

        // proof of re-randomization: different point values, same plaintext
        CipherValue c1Prime = cs.cs().reencrypt(c1.value());
        CipherValue c2Prime = cs.cs().reencrypt(c2.value());

        assertThat(c1Prime).isNotEqualTo(c1.value());
        assertThat(cs.cs().decrypt(c1Prime)).isEqualTo(BigInteger.valueOf(m1));
        assertThat(cs.cs().decrypt(c2Prime)).isEqualTo(BigInteger.valueOf(m2));

        // homomorphic addition
        assertThat(cs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(m1 + m2));
        assertThat(cs.decrypt(c1.multiply(m2))).isEqualTo(BigInteger.valueOf(m1 * m2));
        assertThat(cs.decrypt(c2.multiply(m1))).isEqualTo(BigInteger.valueOf(m1 * m2));

        // unsupported homomorphic operations
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.multiply(c2));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.xor(c2));
    }
}
