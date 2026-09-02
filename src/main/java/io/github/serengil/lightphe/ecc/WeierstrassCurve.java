package io.github.serengil.lightphe.ecc;

import io.github.serengil.lightphe.ecc.curves.CurveForm;
import io.github.serengil.lightphe.ecc.curves.CurveRegistry;
import io.github.serengil.lightphe.ecc.curves.WeierstrassParams;
import java.math.BigInteger;
import java.util.Objects;

/**
 * An elliptic curve satisfying {@code y^2 = x^3 + a*x + b} over the prime field {@code F_p}.
 *
 * <p>This is the most popular elliptic curve form; Bitcoin depends on it.
 *
 * <p>Ref: <a href="https://sefiks.com/2016/03/13/the-math-behind-elliptic-curve-cryptography/">The
 * math behind elliptic curve cryptography</a>
 */
public final class WeierstrassCurve implements EllipticCurve {

    private static final BigInteger THREE = BigInteger.valueOf(3);

    private final String name;
    private final BigInteger a;
    private final BigInteger b;
    private final BigInteger p;
    private final BigInteger gx;
    private final BigInteger gy;
    private final BigInteger n;

    private WeierstrassCurve(
            String name,
            BigInteger a,
            BigInteger b,
            BigInteger p,
            BigInteger gx,
            BigInteger gy,
            BigInteger n) {
        this.name = name;
        this.a = a;
        this.b = b;
        this.p = p;
        this.gx = gx;
        this.gy = gy;
        this.n = n;
    }

    /**
     * Builds a named short Weierstrass curve from the standard inventory.
     *
     * @param curveName the curve name; {@code null} or blank selects {@code secp256k1}
     * @return the curve
     */
    public static WeierstrassCurve named(String curveName) {
        WeierstrassParams params = CurveRegistry.weierstrass(curveName);
        return new WeierstrassCurve(
                params.name(),
                params.a(),
                params.b(),
                params.p(),
                params.gx(),
                params.gy(),
                params.n());
    }

    /**
     * Builds a short Weierstrass curve from explicit parameters.
     *
     * <p>Boneh-Goh-Nissim uses this to build a fresh supersingular curve for every key pair.
     *
     * @param a first equation coefficient
     * @param b second equation coefficient
     * @param p field modulus
     * @param gx x coordinate of the base point
     * @param gy y coordinate of the base point
     * @param n order of the base point
     * @return the custom curve
     * @throws IllegalArgumentException when the modulus is not positive
     */
    public static WeierstrassCurve custom(
            BigInteger a, BigInteger b, BigInteger p, BigInteger gx, BigInteger gy, BigInteger n) {
        Objects.requireNonNull(p, "p");
        if (p.signum() <= 0) {
            throw new IllegalArgumentException(
                    "Weierstrass custom curve requires a positive modulus");
        }
        return new WeierstrassCurve("custom", a.mod(p), b.mod(p), p, gx.mod(p), gy.mod(p), n);
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public CurveForm form() {
        return CurveForm.WEIERSTRASS;
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
        return b;
    }

    @Override
    public BigInteger d() {
        return BigInteger.ZERO;
    }

    /**
     * {@inheritDoc}
     *
     * <p>The neutral element is the point at infinity. Ref: <a
     * href="https://sefiks.com/2023/09/29/understanding-identity-element-in-elliptic-curves/">
     * Understanding identity element in elliptic curves</a>
     */
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
        BigInteger lhs = y.multiply(y).mod(p);
        BigInteger rhs = x.modPow(THREE, p).add(a.multiply(x)).add(b).mod(p);
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

        BigInteger x1 = pPoint.x();
        BigInteger y1 = pPoint.y();
        BigInteger x2 = qPoint.x();
        BigInteger y2 = qPoint.y();

        // beta = (y2 - y1) / (x2 - x1)
        BigInteger beta = y2.subtract(y1).multiply(x2.subtract(x1).mod(p).modInverse(p));

        return fromSlope(beta, x1, y1, x2);
    }

    @Override
    public CurvePoint doublePoint(CurvePoint point) {
        if (point.isInfinity()) {
            return identity();
        }

        BigInteger x1 = point.x();
        BigInteger y1 = point.y();

        if (y1.signum() == 0) {
            return identity();
        }

        // beta = (3 * x1^2 + a) / (2 * y1)
        BigInteger beta =
                THREE.multiply(x1)
                        .multiply(x1)
                        .add(a)
                        .multiply(y1.shiftLeft(1).mod(p).modInverse(p));

        return fromSlope(beta, x1, y1, x1);
    }

    /**
     * Finishes a chord or tangent computation: {@code x3 = beta^2 - x1 - x2} and {@code y3 = beta *
     * (x1 - x3) - y1}.
     */
    private CurvePoint fromSlope(BigInteger beta, BigInteger x1, BigInteger y1, BigInteger x2) {
        BigInteger x3 = beta.multiply(beta).subtract(x1).subtract(x2).mod(p);
        BigInteger y3 = beta.multiply(x1.subtract(x3)).subtract(y1).mod(p);

        CurvePoint result = CurvePoint.unchecked(this, x3, y3);
        if (!isOnCurve(result)) {
            throw new PointNotOnCurveException(result + " is not on the curve " + name + "!");
        }
        return result;
    }

    @Override
    public CurvePoint negativePoint(CurvePoint point) {
        if (point.isInfinity()) {
            return point;
        }
        return CurvePoint.unchecked(this, point.x(), point.y().negate().mod(p));
    }
}
