package io.github.serengil.lightphe.ecc.curves;

import java.math.BigInteger;

/**
 * Parameters of a Koblitz curve {@code y^2 + x*y = x^3 + a*x^2 + b} over the binary field {@code
 * F_{2^m}}.
 *
 * @param name curve identifier, e.g. {@code "k163"}
 * @param m degree of the irreducible reduction polynomial
 * @param coefficients exponents of the set bits of the reduction polynomial, most significant first
 * @param a first equation coefficient
 * @param b second equation coefficient
 * @param gx x coordinate of the base point
 * @param gy y coordinate of the base point
 * @param n order of the base point
 */
public record KoblitzParams(
        String name,
        int m,
        int[] coefficients,
        BigInteger a,
        BigInteger b,
        BigInteger gx,
        BigInteger gy,
        BigInteger n) {

    /** Copies the reduction polynomial exponents so the inventory cannot be mutated by a caller. */
    public KoblitzParams {
        coefficients = coefficients.clone();
    }

    /**
     * Returns a defensive copy of the reduction polynomial exponents.
     *
     * @return the exponents of the set bits, most significant first
     */
    @Override
    public int[] coefficients() {
        return coefficients.clone();
    }
}
