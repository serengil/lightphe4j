package io.github.serengil.lightphe.ecc;

import io.github.serengil.lightphe.ecc.curves.CurveForm;
import io.github.serengil.lightphe.ecc.curves.CurveRegistry;
import io.github.serengil.lightphe.ecc.curves.KoblitzParams;
import java.math.BigInteger;

/**
 * An elliptic curve satisfying {@code y^2 + x*y = x^3 + a*x^2 + b} over the binary field {@code
 * F_{2^m}}.
 *
 * <p>Field elements are polynomials packed into {@link BigInteger}s and reduced modulo the
 * irreducible polynomial derived from the curve's coefficient list.
 *
 * <p>References:
 *
 * <ol>
 *   <li><a href="https://sefiks.com/2016/03/13/the-math-behind-elliptic-curves-over-binary-field/">
 *       The math behind elliptic curves over binary field</a>
 *   <li><a
 *       href="https://sefiks.com/2025/01/16/a-gentle-introduction-to-elliptic-curves-over-binary-fields/">
 *       A gentle introduction to elliptic curves over binary fields</a>
 *   <li>Susantio, D. R., &amp; Muchtadi-Alamsyah, I. (2016, April). Implementation of elliptic
 *       curve cryptography in binary field. In Journal of Physics: Conference Series (Vol. 710, No.
 *       1, p. 012022).
 * </ol>
 */
public final class KoblitzCurve implements EllipticCurve {

    private final String name;
    private final int m;
    private final int[] coefficients;
    private final BigInteger a;
    private final BigInteger b;
    private final BigInteger gx;
    private final BigInteger gy;
    private final BigInteger n;
    private final BigInteger modulo;

    private KoblitzCurve(
            String name,
            int m,
            int[] coefficients,
            BigInteger a,
            BigInteger b,
            BigInteger gx,
            BigInteger gy,
            BigInteger n) {
        this.name = name;
        this.m = m;
        this.coefficients = coefficients;
        this.a = a;
        this.b = b;
        this.gx = gx;
        this.gy = gy;
        this.n = n;

        // The irreducible polynomial has a set bit at every listed exponent.
        BigInteger fx = BigInteger.ZERO;
        for (int exponent : coefficients) {
            fx = fx.setBit(exponent);
        }
        this.modulo = fx;

        if (!isOnCurve(base())) {
            throw new PointNotOnCurveException(
                    "Base point (" + gx + ", " + gy + ") is not on the curve!");
        }
    }

    /**
     * Builds a named Koblitz curve from the standard inventory.
     *
     * @param curveName the curve name; {@code null} or blank selects {@code k163}
     * @return the curve
     */
    public static KoblitzCurve named(String curveName) {
        KoblitzParams params = CurveRegistry.koblitz(curveName);
        return new KoblitzCurve(
                params.name(),
                params.m(),
                params.coefficients(),
                params.a(),
                params.b(),
                params.gx(),
                params.gy(),
                params.n());
    }

    /**
     * Builds a Koblitz curve from explicit parameters.
     *
     * @param m degree of the irreducible reduction polynomial
     * @param coefficients exponents of the set bits of the reduction polynomial
     * @param a first equation coefficient
     * @param b second equation coefficient
     * @param gx x coordinate of the base point
     * @param gy y coordinate of the base point
     * @param n order of the base point
     * @return the custom curve
     */
    public static KoblitzCurve custom(
            int m,
            int[] coefficients,
            BigInteger a,
            BigInteger b,
            BigInteger gx,
            BigInteger gy,
            BigInteger n) {
        return new KoblitzCurve("custom", m, coefficients.clone(), a, b, gx, gy, n);
    }

    /**
     * Returns the degree of the irreducible reduction polynomial.
     *
     * @return the field degree {@code m}
     */
    public int m() {
        return m;
    }

    /**
     * Returns the exponents of the set bits of the reduction polynomial.
     *
     * @return a copy of the coefficient list
     */
    public int[] coefficients() {
        return coefficients.clone();
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public CurveForm form() {
        return CurveForm.KOBLITZ;
    }

    @Override
    public BigInteger modulo() {
        return modulo;
    }

    @Override
    public BigInteger order() {
        return n;
    }

    @Override
    public BigInteger a() {
        return a;
    }

    @Override
    public BigInteger b() {
        return b;
    }

    @Override
    public BigInteger d() {
        return BigInteger.ZERO;
    }

    @Override
    public CurvePoint identity() {
        return CurvePoint.infinity(this);
    }

    @Override
    public CurvePoint base() {
        return CurvePoint.unchecked(this, gx, gy);
    }

    @Override
    public boolean isOnCurve(CurvePoint point) {
        if (point.isInfinity()) {
            return true;
        }
        BigInteger x = point.x();
        BigInteger y = point.y();

        BigInteger lhs =
                BinaryOperations.mod(
                        BinaryOperations.square(y).xor(BinaryOperations.multiply(x, y)), modulo);
        BigInteger rhs =
                BinaryOperations.mod(
                        BinaryOperations.powerMod(x, 3, modulo)
                                .xor(BinaryOperations.multiply(a, BinaryOperations.square(x)))
                                .xor(b),
                        modulo);
        return lhs.equals(rhs);
    }

    @Override
    public CurvePoint addPoints(CurvePoint pPoint, CurvePoint qPoint) {
        if (pPoint.isInfinity()) {
            return qPoint;
        }
        if (qPoint.isInfinity()) {
            return pPoint;
        }
        if (pPoint.equals(negativePoint(qPoint))) {
            return identity();
        }
        if (pPoint.equals(qPoint)) {
            return doublePoint(pPoint);
        }
        if (pPoint.x().equals(qPoint.x())) {
            return identity();
        }

        BigInteger x1 = pPoint.x();
        BigInteger y1 = pPoint.y();
        BigInteger x2 = qPoint.x();
        BigInteger y2 = qPoint.y();

        // beta = (y1 + y2) / (x1 + x2), where + is XOR
        BigInteger beta = BinaryOperations.divide(y1.xor(y2), x1.xor(x2), modulo);

        // x3 = beta^2 + beta + x1 + x2 + a
        BigInteger x3 = BinaryOperations.square(beta).xor(beta).xor(x1).xor(x2).xor(a);

        // y3 = beta * (x1 + x3) + x3 + y1
        BigInteger y3 = BinaryOperations.multiply(x1.xor(x3), beta).xor(x3).xor(y1);

        return CurvePoint.unchecked(
                this, BinaryOperations.mod(x3, modulo), BinaryOperations.mod(y3, modulo));
    }

    @Override
    public CurvePoint doublePoint(CurvePoint point) {
        if (point.isInfinity()) {
            return identity();
        }
        if (point.equals(negativePoint(point))) {
            return identity();
        }

        BigInteger x1 = point.x();
        BigInteger y1 = point.y();

        if (x1.signum() == 0) {
            return identity();
        }

        // beta = x1 + (y1 / x1)
        BigInteger beta = x1.xor(BinaryOperations.divide(y1, x1, modulo));

        // x2 = beta^2 + beta + a
        BigInteger x2 = BinaryOperations.square(beta).xor(beta).xor(a);

        // y2 = x1^2 + beta * x2 + x2
        BigInteger y2 =
                BinaryOperations.square(x1).xor(BinaryOperations.multiply(beta, x2)).xor(x2);

        return CurvePoint.unchecked(
                this, BinaryOperations.mod(x2, modulo), BinaryOperations.mod(y2, modulo));
    }

    /**
     * {@inheritDoc}
     *
     * <p>If {@code P} is {@code (x, y)} then {@code -P} is {@code (x, x XOR y)}; over {@code
     * F_{2^n}}, {@code -x} equals {@code x} because negation is exclusive-or.
     */
    @Override
    public CurvePoint negativePoint(CurvePoint point) {
        if (point.isInfinity()) {
            return point;
        }
        return CurvePoint.unchecked(this, point.x(), point.x().xor(point.y()));
    }
}
