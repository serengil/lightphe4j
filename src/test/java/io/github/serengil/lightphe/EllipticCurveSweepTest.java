package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.serengil.lightphe.cryptosystems.EllipticCurveElGamal;
import io.github.serengil.lightphe.ecc.curves.CurveForm;
import io.github.serengil.lightphe.ecc.curves.CurveRegistry;
import io.github.serengil.lightphe.model.value.CipherValue;
import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Port of the two sweep tests of {@code tests/test_ellipticcurveelgamal.py} that the Python suite
 * keeps switched off by prefixing them with a double underscore. They walk the whole curve
 * inventory, which is far too slow for continuous integration but useful when the elliptic curve
 * layer changes.
 */
@Disabled("Sweeps the entire curve inventory; too slow for CI, as in the Python suite.")
class EllipticCurveSweepTest {

    /**
     * The Python suite excludes Koblitz because of its longer key generation times. This test is
     * switched off anyway, so it sweeps all three forms.
     */
    private static final List<CurveForm> FORMS =
            List.of(CurveForm.WEIERSTRASS, CurveForm.EDWARDS, CurveForm.KOBLITZ);

    @Test
    @DisplayName("Every curve in the inventory can be built")
    void testBuildCurves() {
        for (CurveForm form : FORMS) {
            for (String curve : CurveRegistry.listCurves(form)) {
                EllipticCurveElGamal cs =
                        new EllipticCurveElGamal(null, null, form.formName(), curve);
                assertThat(cs.ecc().n().bitLength()).isPositive();
            }
        }
    }

    @Test
    @DisplayName("Elliptic curve ElGamal round trips on every curve in the inventory")
    void testEllipticCurveElGamal() {
        for (CurveForm form : FORMS) {
            for (String curve : CurveRegistry.listCurves(form)) {
                if ("test-curve".equals(curve)) {
                    continue;
                }

                EllipticCurveElGamal cs =
                        new EllipticCurveElGamal(null, null, form.formName(), curve);

                BigInteger m1 = BigInteger.valueOf(10);
                BigInteger m2 = BigInteger.valueOf(5);

                CipherValue c1 = cs.encrypt(m1);
                CipherValue c2 = cs.encrypt(m2);

                // encryption and decryption
                assertThat(cs.decrypt(c1)).isEqualTo(m1);
                assertThat(cs.decrypt(c2)).isEqualTo(m2);

                // homomorphic operations
                assertThat(cs.decrypt(cs.add(c1, c2))).isEqualTo(m1.add(m2));
                assertThat(cs.decrypt(cs.multiplyByConstant(c1, m2))).isEqualTo(m1.multiply(m2));

                // unsupported operations
                assertThatExceptionOfType(IllegalArgumentException.class)
                        .isThrownBy(() -> cs.multiply(c1, c2));
                assertThatExceptionOfType(IllegalArgumentException.class)
                        .isThrownBy(() -> cs.xor(c1, c2));
            }
        }
    }
}
