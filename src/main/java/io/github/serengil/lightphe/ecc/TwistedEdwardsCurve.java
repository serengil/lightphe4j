package io.github.serengil.lightphe.ecc;

import io.github.serengil.lightphe.ecc.curves.CurveForm;
import io.github.serengil.lightphe.ecc.curves.CurveRegistry;
import io.github.serengil.lightphe.ecc.curves.EdwardsParams;
import java.math.BigInteger;

/**
 * A (twisted) Edwards curve satisfying {@code (a*x^2 + y^2) mod p = (1 + d*x^2*y^2) mod p}.
 *
 * <p>Unlike the Weierstrass form the addition law is complete, so doubling needs no special case
 * and the neutral element {@code (0, 1)} is an ordinary point on the curve rather than a point at
 * infinity.
 *
 * <p>Refs:
 *
 * <ul>
 *   <li><a href="https://sefiks.com/2018/12/19/a-gentle-introduction-to-edwards-curves/">A gentle
 *       introduction to Edwards curves</a>
 *   <li><a href="https://sefiks.com/2018/12/26/twisted-edwards-curves/">Twisted Edwards curves</a>
 * </ul>
 */
public final class TwistedEdwardsCurve implements EllipticCurve {

    private final String name;
    private final BigInteger a;
    private final BigInteger d;
    private final BigInteger p;
    private final BigInteger gx;
    private final BigInteger gy;
    private final BigInteger n;

    private TwistedEdwardsCurve(
            String name,
            BigInteger a,
            BigInteger d,
            BigInteger p,
            BigInteger gx,
            BigInteger gy,
            BigInteger n) {
        this.name = name;
        this.a = a;
        this.d = d;
        this.p = p;
        this.gx = gx;
        this.gy = gy;
        this.n = n;
    }

    /**
     * Builds a named twisted Edwards curve from the standard inventory.
     *
     * @param curveName the curve name; {@code null} or blank selects {@code ed25519}
     * @return the curve
     */
    public static TwistedEdwardsCurve named(String curveName) {
        EdwardsParams params = CurveRegistry.edwards(curveName);
        return new TwistedEdwardsCurve(
                params.name(),
                params.a(),
                params.d(),
                params.p(),
                params.gx(),
                params.gy(),
                params.n());
    }

    /**
     * Builds a twisted Edwards curve from explicit parameters.
     *
     * @param a first equation coefficient
     * @param d second equation coefficient
     * @param p field modulus
     * @param gx x coordinate of the base point
     * @param gy y coordinate of the base point
     * @param n order of the base point
     * @return the custom curve
     */
    public static TwistedEdwardsCurve custom(
            BigInteger a, BigInteger d, BigInteger p, BigInteger gx, BigInteger gy, BigInteger n) {
        return new TwistedEdwardsCurve("custom", a, d, p, gx, gy, n);
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public CurveForm form() {
        return CurveForm.EDWARDS;
    }

    @Override
    public BigInteger modulo() {
        return p;
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
        return BigInteger.ZERO;
    }

    @Override
    public BigInteger d() {
        return d;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Edwards curves carry a neutral element on the curve itself instead of a point at infinity.
     * Ref: <a
     * href="https://sefiks.com/2023/09/29/understanding-identity-element-in-elliptic-curves/">
     * Understanding identity element in elliptic curves</a>
     */
    @Override
    public CurvePoint identity() {
        return CurvePoint.unchecked(this, BigInteger.ZERO, BigInteger.ONE);
    }

    @Override
    public CurvePoint base() {
        return CurvePoint.unchecked(this, gx, gy);
    }

    @Override
    public boolean isOnCurve(CurvePoint point) {
        if (point.isInfinity()) {
            return false;
        }
        BigInteger x = point.x();
        BigInteger y = point.y();
        BigInteger lhs = a.multiply(x).multiply(x).add(y.multiply(y)).mod(p);
        BigInteger rhs =
                BigInteger.ONE.add(d.multiply(x).multiply(x).multiply(y).multiply(y)).mod(p);
        return lhs.equals(rhs);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Uses the complete twisted Edwards addition law:
     *
     * <pre>
     * x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
     * y3 = (y1*y2 - a*x1*x2) / (1 - d*x1*x2*y1*y2)
     * </pre>
     */
    @Override
    public CurvePoint addPoints(CurvePoint pPoint, CurvePoint qPoint) {
        BigInteger x1 = pPoint.x();
        BigInteger y1 = pPoint.y();
        BigInteger x2 = qPoint.x();
        BigInteger y2 = qPoint.y();

        // common = d * x1 * x2 * y1 * y2
        BigInteger common = d.multiply(x1).multiply(x2).multiply(y1).multiply(y2);

        BigInteger x3 =
                x1.multiply(y2)
                        .add(y1.multiply(x2))
                        .mod(p)
                        .multiply(BigInteger.ONE.add(common).mod(p).modInverse(p))
                        .mod(p);

        BigInteger y3 =
                y1.multiply(y2)
                        .subtract(a.multiply(x1).multiply(x2))
                        .mod(p)
                        .multiply(BigInteger.ONE.subtract(common).mod(p).modInverse(p))
                        .mod(p);

        return CurvePoint.unchecked(this, x3, y3);
    }

    /**
     * {@inheritDoc}
     *
     * <p>The addition law is complete, so doubling is just addition with equal operands.
     */
    @Override
    public CurvePoint doublePoint(CurvePoint point) {
        return addPoints(point, point);
    }

    /**
     * {@inheritDoc}
     *
     * <p>The negated x coordinate is reduced into {@code [0, p)} so that a negated point still
     * compares equal to the reduced representative of the same point.
     */
    @Override
    public CurvePoint negativePoint(CurvePoint point) {
        return CurvePoint.unchecked(this, point.x().negate().mod(p), point.y());
    }
}
