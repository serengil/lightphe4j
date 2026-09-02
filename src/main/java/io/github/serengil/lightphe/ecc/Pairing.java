package io.github.serengil.lightphe.ecc;

import io.github.serengil.lightphe.ecc.curves.CurveForm;
import java.math.BigInteger;

/**
 * Pairings computed with Miller's algorithm on short Weierstrass curves.
 *
 * <p>Two flavours are implemented:
 *
 * <ul>
 *   <li>the Weil pairing over {@code F_p}, for curves whose full {@code r}-torsion already lives in
 *       {@code E(F_p)};
 *   <li>the modified Tate pairing over {@code F_{p^2}} with the distortion map {@code phi(x, y) =
 *       (-x, i*y)}, for supersingular curves {@code y^2 = x^3 + a*x} with embedding degree two.
 *       This is the flavour Boneh-Goh-Nissim needs.
 * </ul>
 *
 * <p>The pairing {@code e_r(P, Q)} maps two {@code r}-torsion points to an {@code r}-th root of
 * unity. It is bilinear ({@code e(aP, bQ) = e(P, Q)^(ab)}), alternating ({@code e(P, P) = 1}) and
 * non-degenerate.
 *
 * <p>Reference: Washington, "Elliptic Curves: Number Theory and Cryptography", Chapter 11.
 */
public final class Pairing {

    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger FOUR = BigInteger.valueOf(4);

    private Pairing() {
        throw new AssertionError("no instances");
    }

    /**
     * Reports whether a Weierstrass curve {@code y^2 = x^3 + a*x + b} is supersingular with
     * embedding degree two.
     *
     * <p>For {@code y^2 = x^3 + a*x} (that is {@code b == 0} and {@code a != 0}) with {@code p = 3
     * (mod 4)}, the curve is supersingular with embedding degree two, meaning {@code p^2 = 1 (mod
     * r)} but {@code p != 1 (mod r)} for the relevant torsion orders.
     *
     * @param curve the curve to inspect
     * @return {@code true} when the curve is supersingular with embedding degree two
     */
    public static boolean isSupersingularEmbedding2(EllipticCurve curve) {
        if (curve.form() != CurveForm.WEIERSTRASS) {
            return false;
        }
        return curve.b().signum() == 0
                && curve.a().signum() != 0
                && curve.modulo().mod(FOUR).equals(THREE);
    }

    /**
     * Computes the pairing {@code e_r(P, Q)}.
     *
     * <p>For supersingular curves with embedding degree two ({@code y^2 = x^3 + a*x}, {@code p = 3
     * mod 4}) this automatically uses the modified Tate pairing with the distortion map over {@code
     * F_{p^2}}; for other curves it uses the standard Weil pairing over {@code F_p}.
     *
     * @param p first {@code r}-torsion point
     * @param q second {@code r}-torsion point
     * @param r torsion order; {@code r*P = O} and {@code r*Q = O} must hold
     * @return an {@code r}-th root of unity, in {@code F_p} or in {@code F_{p^2}}
     * @throws IllegalArgumentException when the curve form is unsupported, the points live on
     *     different curves, either point is not {@code r}-torsion, or the computation is degenerate
     */
    public static PairingResult pairing(CurvePoint p, CurvePoint q, BigInteger r) {
        EllipticCurve curve = p.curve();
        if (curve.form() != CurveForm.WEIERSTRASS) {
            throw new IllegalArgumentException(
                    "Pairing is only supported for Weierstrass form curves.");
        }
        if (!curve.sameCurve(q.curve())) {
            throw new IllegalArgumentException("Points are not on the same curve");
        }
        if (p.isIdentity() || q.isIdentity()) {
            return PairingResult.ofBase(BigInteger.ONE);
        }

        BigInteger modulus = curve.modulo();

        // Use the modified Tate pairing for supersingular curves with embedding degree two, but
        // only when the full r-torsion is NOT in E(F_p). If r divides p-1 the full r-torsion is in
        // E(F_p) and the standard Weil pairing works.
        // Note: P == Q is allowed here because the distortion map phi(Q) != Q, so e(P, phi(P)) is
        // non-trivial and the alternating property does not apply.
        if (isSupersingularEmbedding2(curve)
                && modulus.subtract(BigInteger.ONE).mod(r).signum() != 0) {
            requireTorsion(p, r, "P");
            if (!p.equals(q)) {
                requireTorsion(q, r, "Q");
            }
            return PairingResult.ofExtended(tatePairingSupersingular(p, q, r));
        }

        if (p.equals(q)) {
            // The Weil pairing is alternating.
            return PairingResult.ofBase(BigInteger.ONE);
        }
        requireTorsion(p, r, "P");
        requireTorsion(q, r, "Q");

        return PairingResult.ofBase(weilPairing(p, q, r));
    }

    private static void requireTorsion(CurvePoint point, BigInteger r, String label) {
        CurvePoint scaled = point.multiply(r);
        if (!scaled.isIdentity()) {
            throw new IllegalArgumentException(
                    label
                            + " = "
                            + point
                            + " is not an "
                            + r
                            + "-torsion point"
                            + " (r*"
                            + label
                            + " = "
                            + scaled
                            + ")");
        }
    }

    // -----------------------------------------------------------------------
    // Weil pairing over F_p
    // -----------------------------------------------------------------------

    /**
     * Evaluates the Miller line function {@code g_{T,P}(R) = l_{T,P}(R) / v_{T+P}(R)} in {@code
     * F_p}, where {@code l_{T,P}} is the line through {@code T} and {@code P} (the tangent when
     * they coincide) and {@code v_{T+P}} is the vertical line through their sum.
     */
    private static BigInteger lineEval(CurvePoint t, CurvePoint p, CurvePoint r) {
        if (t.isIdentity() || p.isIdentity() || r.isIdentity()) {
            return BigInteger.ONE;
        }
        BigInteger modulus = t.curve().modulo();

        CurvePoint sum = t.add(p);
        if (sum.isIdentity()) {
            // Vertical line through T.
            return r.x().subtract(t.x()).mod(modulus);
        }

        BigInteger lambda = slope(t, p);

        // numerator = yR - yT - lambda * (xR - xT)
        BigInteger num =
                r.y().subtract(t.y()).subtract(lambda.multiply(r.x().subtract(t.x()))).mod(modulus);

        // denominator = xR - x_{T+P}
        BigInteger den = r.x().subtract(sum.x()).mod(modulus);
        if (den.signum() == 0) {
            return num.signum() != 0 ? num : BigInteger.ONE;
        }
        return num.multiply(den.modInverse(modulus)).mod(modulus);
    }

    /**
     * Returns the slope of the chord through {@code t} and {@code p}, or of the tangent at {@code
     * t} when the two points coincide.
     */
    private static BigInteger slope(CurvePoint t, CurvePoint p) {
        EllipticCurve curve = t.curve();
        BigInteger modulus = curve.modulo();

        BigInteger num;
        BigInteger den;
        if (t.equals(p)) {
            num = THREE.multiply(t.x()).multiply(t.x()).add(curve.a());
            den = t.y().shiftLeft(1);
        } else {
            num = p.y().subtract(t.y());
            den = p.x().subtract(t.x());
        }
        return num.multiply(den.mod(modulus).modInverse(modulus)).mod(modulus);
    }

    /** Computes {@code f_{r,P}(R)} over {@code F_p} with Miller's algorithm. */
    private static BigInteger miller(CurvePoint p, CurvePoint r, BigInteger order) {
        if (p.isIdentity() || r.isIdentity()) {
            return BigInteger.ONE;
        }
        BigInteger modulus = p.curve().modulo();

        BigInteger f = BigInteger.ONE;
        CurvePoint t = p;

        for (int i = order.bitLength() - 2; i >= 0; i--) {
            if (t.isIdentity()) {
                f = f.multiply(f).mod(modulus);
            } else {
                BigInteger g = lineEval(t, t, r);
                f = f.multiply(f).multiply(g).mod(modulus);
                t = t.add(t);
            }

            if (order.testBit(i)) {
                if (t.isIdentity()) {
                    t = p;
                } else {
                    BigInteger g = lineEval(t, p, r);
                    f = f.multiply(g).mod(modulus);
                    t = t.add(p);
                }
            }
        }
        return f.mod(modulus);
    }

    /** Picks a point {@code S} that avoids the degenerate cases of the Weil pairing. */
    private static CurvePoint auxiliaryPoint(CurvePoint p, CurvePoint q) {
        EllipticCurve curve = p.curve();
        CurvePoint g = curve.base();

        CurvePoint[] bad = {
            p, p.negate(), q, q.negate(), p.subtract(q), q.subtract(p), p.add(q),
        };

        int limit = 1000;
        BigInteger n = curve.order();
        if (n != null && n.bitLength() < 32 && n.intValue() < limit) {
            limit = n.intValue();
        }

        CurvePoint s = curve.identity();
        for (int k = 1; k < limit; k++) {
            s = s.add(g);
            if (s.isIdentity()) {
                continue;
            }
            boolean degenerate = false;
            for (CurvePoint candidate : bad) {
                if (s.equals(candidate)) {
                    degenerate = true;
                    break;
                }
            }
            if (degenerate) {
                continue;
            }
            if (q.add(s).isIdentity() || p.subtract(s).isIdentity()) {
                continue;
            }
            return s;
        }
        throw new IllegalArgumentException(
                "No suitable auxiliary point for the Weil pairing on " + curve.name());
    }

    /** Computes the standard Weil pairing over {@code F_p}. */
    private static BigInteger weilPairing(CurvePoint p, CurvePoint q, BigInteger r) {
        BigInteger modulus = p.curve().modulo();

        CurvePoint s = auxiliaryPoint(p, q);
        CurvePoint negS = s.negate();
        CurvePoint qPlusS = q.add(s);
        CurvePoint pMinusS = p.subtract(s);

        BigInteger fpQpS = miller(p, qPlusS, r);
        BigInteger fpS = miller(p, s, r);
        BigInteger fqPmS = miller(q, pMinusS, r);
        BigInteger fqNegS = miller(q, negS, r);

        if (fpS.signum() == 0 || fqPmS.signum() == 0) {
            throw new IllegalArgumentException(
                    "Degenerate case in Weil pairing computation. Try different input points.");
        }

        BigInteger num = fpQpS.multiply(fqNegS).mod(modulus);
        BigInteger den = fpS.multiply(fqPmS).mod(modulus);
        if (den.signum() == 0) {
            throw new IllegalArgumentException(
                    "Degenerate case: denominator is zero in Weil pairing.");
        }
        return num.multiply(den.modInverse(modulus)).mod(modulus);
    }

    // -----------------------------------------------------------------------
    // Modified Tate pairing over F_{p^2}
    // -----------------------------------------------------------------------

    /** Evaluates the Miller line function at a point whose coordinates live in {@code F_{p^2}}. */
    private static Fp2 lineEvalFp2(CurvePoint t, CurvePoint p, Fp2 xr, Fp2 yr) {
        if (t.isIdentity() || p.isIdentity()) {
            return Fp2.one();
        }
        BigInteger modulus = t.curve().modulo();

        CurvePoint sum = t.add(p);
        if (sum.isIdentity()) {
            return xr.subtract(Fp2.fromBase(t.x()), modulus);
        }

        BigInteger lambda = slope(t, p);

        // numerator = yR - yT - lambda * (xR - xT)
        Fp2 num =
                yr.subtract(Fp2.fromBase(t.y()), modulus)
                        .subtract(
                                Fp2.fromBase(lambda)
                                        .multiply(
                                                xr.subtract(Fp2.fromBase(t.x()), modulus), modulus),
                                modulus);

        Fp2 den = xr.subtract(Fp2.fromBase(sum.x()), modulus);
        if (den.isZero()) {
            return num.isZero() ? Fp2.one() : num;
        }
        return num.multiply(den.inverse(modulus), modulus);
    }

    /** Computes {@code f_{r,P}(R)} where {@code R} has coordinates in {@code F_{p^2}}. */
    private static Fp2 millerFp2(CurvePoint p, Fp2 xr, Fp2 yr, BigInteger r) {
        if (p.isIdentity()) {
            return Fp2.one();
        }
        BigInteger modulus = p.curve().modulo();

        Fp2 f = Fp2.one();
        CurvePoint t = p;

        for (int i = r.bitLength() - 2; i >= 0; i--) {
            if (t.isIdentity()) {
                f = f.multiply(f, modulus);
            } else {
                Fp2 g = lineEvalFp2(t, t, xr, yr);
                f = f.multiply(f, modulus).multiply(g, modulus);
                t = t.add(t);
            }

            if (r.testBit(i)) {
                if (t.isIdentity()) {
                    t = p;
                } else {
                    Fp2 g = lineEvalFp2(t, p, xr, yr);
                    f = f.multiply(g, modulus);
                    t = t.add(p);
                }
            }
        }
        return f;
    }

    /**
     * Modified Tate pairing for supersingular curves {@code y^2 = x^3 + a*x} with embedding degree
     * two, using the distortion map {@code phi(x, y) = (-x, i*y)}: {@code e_r(P, Q) =
     * f_{r,P}(phi(Q))^((p^2-1)/r)}.
     */
    private static Fp2 tatePairingSupersingular(CurvePoint p, CurvePoint q, BigInteger r) {
        BigInteger modulus = p.curve().modulo();

        // Apply the distortion map: phi(Q) = (-x_Q, i * y_Q).
        // In F_{p^2}: x_phi = (-x_Q mod p, 0), y_phi = (0, y_Q).
        Fp2 xPhi = Fp2.of(q.x().negate().mod(modulus), BigInteger.ZERO);
        Fp2 yPhi = Fp2.of(BigInteger.ZERO, q.y().mod(modulus));

        // Run Miller's algorithm over F_{p^2}.
        Fp2 f = millerFp2(p, xPhi, yPhi, r);

        // Final exponentiation: f^((p^2 - 1) / r).
        BigInteger exponent = modulus.multiply(modulus).subtract(BigInteger.ONE).divide(r);
        return f.pow(exponent, modulus);
    }
}
