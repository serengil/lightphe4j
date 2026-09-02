package io.github.serengil.lightphe.ecc.curves;

import java.math.BigInteger;

/**
 * Parameters of a twisted Edwards curve {@code a*x^2 + y^2 = 1 + d*x^2*y^2} over {@code F_p}.
 *
 * @param name curve identifier, e.g. {@code "ed25519"}
 * @param a first equation coefficient
 * @param d second equation coefficient
 * @param p field modulus
 * @param gx x coordinate of the base point
 * @param gy y coordinate of the base point
 * @param n order of the base point
 */
public record EdwardsParams(
        String name,
        BigInteger a,
        BigInteger d,
        BigInteger p,
        BigInteger gx,
        BigInteger gy,
        BigInteger n) {}
