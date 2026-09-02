package io.github.serengil.lightphe.ecc;

import io.github.serengil.lightphe.ecc.curves.CurveForm;
import java.math.BigInteger;

/**
 * An elliptic curve over a finite field (prime or binary), bundled with its base point, neutral
 * element and order.
 *
 * <p>This is the entry point cryptosystems use, and the Java counterpart of the {@code LightECC}
 * class of the LightECC library. Instances are immutable and safe to share between threads.
 *
 * <h2>Example</h2>
 *
 * <pre>{@code
 * LightECC ecc = LightECC.of(CurveForm.EDWARDS, "ed25519");
 * CurvePoint doubled = ecc.g().multiply(BigInteger.TWO);
 * }</pre>
 */
public final class LightECC {

    private final EllipticCurve curve;
    private final CurvePoint g;
    private final CurvePoint o;
    private final BigInteger n;
    private final BigInteger modulo;

    private LightECC(EllipticCurve curve) {
        this.curve = curve;

        // base point
        this.g = curve.base();

        // order of the curve
        this.n = curve.order();

        // point at infinity or neutral / identity element
        this.o = curve.identity();

        // In EllipticCurve.doubleAndAdd, returning the identity element when n is given as a
        // scalar implicitly assumes that n is the correct order of the base point (or of the curve
        // subgroup). That assumption is only valid if n * G = O; if n is not the true order then
        // n * G should yield a non-identity point.
        //
        // To validate n we therefore compute (n - 1) * G + G, which equals O if and only if n is
        // the correct order. Notice that (n - 1) * G is a point, and we do not know the (n - 1)
        // multiplier of the result.
        if (n != null) {
            CurvePoint nMinusOneG = g.multiply(n.subtract(BigInteger.ONE));
            CurvePoint nG = nMinusOneG.add(g);
            if (!nG.equals(o)) {
                String label =
                        curve.form() == CurveForm.EDWARDS
                                ? "neutral element / identity element"
                                : "point at infinity / identity element";
                throw new InvalidCurveOrderException(
                        "Invalid curve order: n x G does not equal to the " + label + ".");
            }
        }

        // modulo
        this.modulo = curve.modulo();
    }

    /**
     * Constructs an elliptic curve of the given form and name.
     *
     * @param form the curve form; {@code null} defaults to {@link CurveForm#WEIERSTRASS}
     * @param curveName the curve name; {@code null} or blank selects the form's default curve
     * @return the constructed curve
     * @throws IllegalArgumentException when the form or curve name is unsupported
     */
    public static LightECC of(CurveForm form, String curveName) {
        CurveForm resolved = form == null ? CurveForm.WEIERSTRASS : form;
        EllipticCurve built =
                switch (resolved) {
                    case WEIERSTRASS -> WeierstrassCurve.named(curveName);
                    case EDWARDS -> TwistedEdwardsCurve.named(curveName);
                    case KOBLITZ -> KoblitzCurve.named(curveName);
                };
        return new LightECC(built);
    }

    /**
     * Constructs an elliptic curve of the given form and name.
     *
     * @param formName the curve form name, e.g. {@code "edwards"}; {@code null} defaults to {@code
     *     "weierstrass"}
     * @param curveName the curve name; {@code null} or blank selects the form's default curve
     * @return the constructed curve
     * @throws IllegalArgumentException when the form or curve name is unsupported
     */
    public static LightECC of(String formName, String curveName) {
        return of(CurveForm.of(formName), curveName);
    }

    /**
     * Wraps an already built curve and validates its declared order.
     *
     * @param curve the curve to wrap
     * @return the wrapped curve
     * @throws InvalidCurveOrderException when {@code n * G} is not the identity element
     */
    public static LightECC fromCurve(EllipticCurve curve) {
        return new LightECC(curve);
    }

    /**
     * Builds and validates a custom short Weierstrass curve in one step.
     *
     * @param a first equation coefficient
     * @param b second equation coefficient
     * @param p field modulus
     * @param gx x coordinate of the base point
     * @param gy y coordinate of the base point
     * @param n order of the base point
     * @return the constructed curve
     * @throws InvalidCurveOrderException when {@code n * G} is not the identity element
     * @throws PointNotOnCurveException when the base point is off the curve
     */
    public static LightECC customWeierstrass(
            BigInteger a, BigInteger b, BigInteger p, BigInteger gx, BigInteger gy, BigInteger n) {
        WeierstrassCurve built = WeierstrassCurve.custom(a, b, p, gx, gy, n);
        if (!built.isOnCurve(built.base())) {
            throw new PointNotOnCurveException("(" + gx + ", " + gy + ") is not on the curve!");
        }
        return new LightECC(built);
    }

    /**
     * Returns the underlying curve.
     *
     * @return the curve
     */
    public EllipticCurve curve() {
        return curve;
    }

    /**
     * Returns the base point {@code G}.
     *
     * @return the generator
     */
    public CurvePoint g() {
        return g;
    }

    /**
     * Returns the neutral element {@code O}.
     *
     * @return the identity element
     */
    public CurvePoint o() {
        return o;
    }

    /**
     * Returns the order {@code n} of the base point.
     *
     * @return the order
     */
    public BigInteger n() {
        return n;
    }

    /**
     * Returns the field modulus.
     *
     * @return the modulus
     */
    public BigInteger modulo() {
        return modulo;
    }

    /**
     * Validates the coordinates and returns the corresponding curve point.
     *
     * @param x x coordinate
     * @param y y coordinate
     * @return the point
     * @throws PointNotOnCurveException when the coordinates are off the curve
     */
    public CurvePoint point(BigInteger x, BigInteger y) {
        return CurvePoint.of(curve, x, y);
    }

    /**
     * Computes the pairing {@code e_n(P, Q)} using the curve order as the torsion order.
     *
     * @param p first {@code n}-torsion point
     * @param q second {@code n}-torsion point
     * @return an {@code n}-th root of unity
     */
    public PairingResult pairing(CurvePoint p, CurvePoint q) {
        return pairing(p, q, n);
    }

    /**
     * Computes the pairing {@code e_r(P, Q)} for an explicit torsion order.
     *
     * <p>For standard curves this computes the Weil pairing over {@code F_p}; for supersingular
     * curves with embedding degree two it computes the modified Tate pairing over {@code F_{p^2}}
     * using a distortion map.
     *
     * @param p first {@code r}-torsion point
     * @param q second {@code r}-torsion point
     * @param r torsion order; {@code r*P = O} and {@code r*Q = O} must hold
     * @return an {@code r}-th root of unity
     * @throws IllegalArgumentException when the curve form is not Weierstrass
     */
    public PairingResult pairing(CurvePoint p, CurvePoint q, BigInteger r) {
        if (curve.form() != CurveForm.WEIERSTRASS) {
            throw new IllegalArgumentException(
                    "Pairing is only supported for Weierstrass form curves.");
        }
        return Pairing.pairing(p, q, r == null ? n : r);
    }

    /**
     * Computes the order of the base point by brute force.
     *
     * <p>This is only for demonstration purposes and should not be used for large curves. When the
     * curve already declares an order, that order is returned without computation.
     *
     * @return the order of the base point
     */
    public BigInteger findOrder() {
        if (n != null) {
            return n;
        }
        CurvePoint current = g;
        BigInteger order = BigInteger.ONE;
        while (!current.equals(o)) {
            current = current.add(g);
            order = order.add(BigInteger.ONE);
        }
        return order;
    }
}
