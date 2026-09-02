package io.github.serengil.lightphe.ecc;

import java.math.BigInteger;
import java.util.Objects;

/**
 * A point on an elliptic curve, in affine coordinates.
 *
 * <p>This is the Java counterpart of {@code lightecc.interfaces.elliptic_curve.EllipticCurvePoint}.
 * Points are immutable: {@link #add}, {@link #multiply} and friends always return a fresh instance.
 *
 * <p>Weierstrass and Koblitz curves represent their identity element as the point at infinity,
 * flagged by {@link #isInfinity()}; Edwards curves use the ordinary point {@code (0, 1)} instead.
 */
public final class CurvePoint {

    private final BigInteger x;
    private final BigInteger y;
    private final boolean infinity;
    private final EllipticCurve curve;

    private CurvePoint(BigInteger x, BigInteger y, boolean infinity, EllipticCurve curve) {
        this.x = x;
        this.y = y;
        this.infinity = infinity;
        this.curve = curve;
    }

    /**
     * Builds a point after validating that it lies on the curve.
     *
     * @param curve the owning curve
     * @param x x coordinate
     * @param y y coordinate
     * @return the validated point
     * @throws PointNotOnCurveException when the coordinates do not satisfy the curve equation
     */
    public static CurvePoint of(EllipticCurve curve, BigInteger x, BigInteger y) {
        CurvePoint point = unchecked(curve, x, y);
        if (!curve.isOnCurve(point)) {
            throw new PointNotOnCurveException("(" + x + ", " + y + ") is not on the curve!");
        }
        return point;
    }

    /**
     * Builds a point without validating it against the curve equation. Reserved for internal use by
     * curve implementations, which validate the result of an operation themselves where the Python
     * reference does.
     *
     * @param curve the owning curve
     * @param x x coordinate
     * @param y y coordinate
     * @return the point
     */
    static CurvePoint unchecked(EllipticCurve curve, BigInteger x, BigInteger y) {
        return new CurvePoint(
                Objects.requireNonNull(x, "x"),
                Objects.requireNonNull(y, "y"),
                false,
                Objects.requireNonNull(curve, "curve"));
    }

    /**
     * Returns the point at infinity of a curve.
     *
     * @param curve the owning curve
     * @return the point at infinity
     */
    static CurvePoint infinity(EllipticCurve curve) {
        return new CurvePoint(null, null, true, Objects.requireNonNull(curve, "curve"));
    }

    /**
     * Returns the x coordinate.
     *
     * @return the x coordinate, or {@code null} at infinity
     */
    public BigInteger x() {
        return x;
    }

    /**
     * Returns the y coordinate.
     *
     * @return the y coordinate, or {@code null} at infinity
     */
    public BigInteger y() {
        return y;
    }

    /**
     * Reports whether this is the point at infinity.
     *
     * @return {@code true} for the point at infinity
     */
    public boolean isInfinity() {
        return infinity;
    }

    /**
     * Returns the curve this point belongs to.
     *
     * @return the owning curve
     */
    public EllipticCurve curve() {
        return curve;
    }

    /**
     * Reports whether this point is the neutral element of its curve.
     *
     * @return {@code true} for the identity element
     */
    public boolean isIdentity() {
        return equals(curve.identity());
    }

    /**
     * Calculates {@code P + Q} for this point and another.
     *
     * @param other the point to add
     * @return the sum
     * @throws IllegalArgumentException when the points live on different curves
     */
    public CurvePoint add(CurvePoint other) {
        Objects.requireNonNull(other, "other");
        if (!curve.sameCurve(other.curve)) {
            throw new IllegalArgumentException("Points are not on the same curve");
        }
        return curve.addPoints(this, other);
    }

    /**
     * Calculates {@code P - Q} for this point and another.
     *
     * @param other the point to subtract
     * @return the difference
     */
    public CurvePoint subtract(CurvePoint other) {
        return add(other.negate());
    }

    /**
     * Calculates {@code -P}.
     *
     * @return the additive inverse of this point
     */
    public CurvePoint negate() {
        return curve.negativePoint(this);
    }

    /**
     * Calculates {@code 2P}.
     *
     * @return this point doubled
     */
    public CurvePoint doubled() {
        return curve.doublePoint(this);
    }

    /**
     * Calculates {@code k * P} for a scalar {@code k}.
     *
     * @param k the scalar
     * @return the scalar multiple
     */
    public CurvePoint multiply(BigInteger k) {
        return curve.doubleAndAdd(this, k);
    }

    /**
     * Calculates {@code k * P} for a scalar {@code k}.
     *
     * @param k the scalar
     * @return the scalar multiple
     */
    public CurvePoint multiply(long k) {
        return multiply(BigInteger.valueOf(k));
    }

    /**
     * Solves the elliptic curve discrete logarithm problem: finds {@code k} such that {@code this =
     * k * base}.
     *
     * <p>This is the hard problem the security of every elliptic curve scheme rests on. It is only
     * tractable here because partially homomorphic schemes keep their plaintexts small. The search
     * is exhaustive and gives up once {@code k} exceeds the curve order.
     *
     * <p>Mirroring {@code EllipticCurvePoint.__truediv__} of the Python implementation, the
     * identity element resolves to the curve order rather than to zero.
     *
     * @param base the base point
     * @return the scalar behind this point
     * @throws IllegalArgumentException when the scalar cannot be recovered
     */
    public BigInteger divide(CurvePoint base) {
        if (equals(base)) {
            return BigInteger.ONE;
        }
        if (isIdentity()) {
            return curve.order();
        }

        // The reference implementation recomputes k*base from scratch on every step; accumulating
        // it incrementally yields the same sequence of candidates at a fraction of the cost.
        BigInteger n = curve.order();
        BigInteger k = BigInteger.TWO;
        CurvePoint candidate = curve.addPoints(base, base);
        while (true) {
            if (candidate.equals(this)) {
                return k;
            }
            k = k.add(BigInteger.ONE);
            if (n != null && k.compareTo(n) > 0) {
                throw new IllegalArgumentException(
                        "Cannot restore scalar from " + this + " = k x " + base);
            }
            candidate = curve.addPoints(candidate, base);
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof CurvePoint other)) {
            return false;
        }
        if (!curve.sameCurve(other.curve)) {
            return false;
        }
        if (infinity || other.infinity) {
            return infinity == other.infinity;
        }
        return x.equals(other.x) && y.equals(other.y);
    }

    @Override
    public int hashCode() {
        return infinity ? 0 : Objects.hash(x, y);
    }

    @Override
    public String toString() {
        return infinity ? "𝒪" : "(" + x + ", " + y + ")";
    }
}
