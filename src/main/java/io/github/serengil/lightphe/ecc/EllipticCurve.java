package io.github.serengil.lightphe.ecc;

import io.github.serengil.lightphe.ecc.curves.CurveForm;
import java.math.BigInteger;

/**
 * The arithmetic backend of a single elliptic curve.
 *
 * <p>Implementations are immutable and therefore safe to share between threads. This is the Java
 * counterpart of the abstract {@code EllipticCurve} class of LightECC.
 */
public interface EllipticCurve {

    /**
     * Returns the curve identifier, e.g. {@code "secp256k1"}.
     *
     * @return the curve name
     */
    String name();

    /**
     * Returns the shape of the curve equation.
     *
     * @return the curve form
     */
    CurveForm form();

    /**
     * Returns the field modulus: the prime {@code p} for prime fields, or the reduction polynomial
     * packed into an integer for binary fields.
     *
     * @return the modulus
     */
    BigInteger modulo();

    /**
     * Returns the order {@code n} of the base point.
     *
     * @return the order, or {@code null} when the curve does not declare one
     */
    BigInteger order();

    /**
     * Returns the first equation coefficient {@code a}.
     *
     * @return coefficient {@code a}
     */
    BigInteger a();

    /**
     * Returns the second Weierstrass or Koblitz coefficient {@code b}. Edwards curves report zero.
     *
     * @return coefficient {@code b}
     */
    BigInteger b();

    /**
     * Returns the twisted Edwards coefficient {@code d}. Other forms report zero.
     *
     * @return coefficient {@code d}
     */
    BigInteger d();

    /**
     * Returns the neutral element: the point at infinity for Weierstrass and Koblitz curves, {@code
     * (0, 1)} for Edwards curves.
     *
     * @return the identity element
     */
    CurvePoint identity();

    /**
     * Returns the base point {@code G}.
     *
     * @return the generator
     */
    CurvePoint base();

    /**
     * Reports whether a point satisfies the curve equation.
     *
     * @param point the point to check
     * @return {@code true} when the point lies on the curve
     */
    boolean isOnCurve(CurvePoint point);

    /**
     * Finds the third point from two given points on the curve.
     *
     * @param p first point
     * @param q second point
     * @return {@code p + q}
     */
    CurvePoint addPoints(CurvePoint p, CurvePoint q);

    /**
     * Finds the double of a given point on the curve.
     *
     * @param p the point to double
     * @return {@code 2 * p}
     */
    CurvePoint doublePoint(CurvePoint p);

    /**
     * Returns the additive inverse of a point.
     *
     * @param p the point to negate
     * @return {@code -p}
     */
    CurvePoint negativePoint(CurvePoint p);

    /**
     * Reports whether two curves share the same form and defining parameters.
     *
     * <p>This is a value-based comparison rather than object identity, mirroring {@code
     * EllipticCurve.__eq__} of the Python implementation, so that a point keeps comparing equal to
     * itself after its curve has been rebuilt from the same configuration.
     *
     * @param other the curve to compare against
     * @return {@code true} when the two curves are equivalent
     */
    default boolean sameCurve(EllipticCurve other) {
        if (this == other) {
            return true;
        }
        if (other == null || form() != other.form()) {
            return false;
        }
        BigInteger thisOrder = order();
        BigInteger otherOrder = other.order();
        boolean sameOrder =
                thisOrder == null || otherOrder == null
                        ? thisOrder == otherOrder
                        : thisOrder.equals(otherOrder);
        return modulo().equals(other.modulo())
                && sameOrder
                && a().equals(other.a())
                && b().equals(other.b())
                && d().equals(other.d());
    }

    /**
     * Performs scalar multiplication with the left-to-right double-and-add algorithm.
     *
     * <p>Scalars are first reduced modulo the curve order when one is declared; a zero scalar
     * yields the identity element and a negative scalar negates the result of its absolute value.
     *
     * @param g the point to multiply
     * @param k the scalar
     * @return {@code k * g}
     */
    default CurvePoint doubleAndAdd(CurvePoint g, BigInteger k) {
        BigInteger scalar = k;
        BigInteger n = order();
        if (n != null && scalar.compareTo(n) >= 0) {
            scalar = scalar.mod(n);
        }
        if (scalar.signum() == 0) {
            return identity();
        }
        if (scalar.signum() < 0) {
            return negativePoint(doubleAndAdd(g, scalar.negate()));
        }

        CurvePoint target = g;
        for (int i = scalar.bitLength() - 2; i >= 0; i--) {
            target = doublePoint(target);
            if (scalar.testBit(i)) {
                target = addPoints(target, g);
            }
        }

        if (!isOnCurve(target)) {
            throw new PointNotOnCurveException(target + " is not on the curve!");
        }
        return target;
    }
}
