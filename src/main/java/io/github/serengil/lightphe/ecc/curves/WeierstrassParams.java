package io.github.serengil.lightphe.ecc.curves;

import java.math.BigInteger;

/**
 * Parameters of a short Weierstrass curve {@code y^2 = x^3 + a*x + b} over {@code F_p}.
 *
 * @param name curve identifier, e.g. {@code "secp256k1"}
 * @param a first equation coefficient
 * @param b second equation coefficient
 * @param p field modulus
 * @param gx x coordinate of the base point
 * @param gy y coordinate of the base point
 * @param n order of the base point
 */
public record WeierstrassParams(
        String name,
        BigInteger a,
        BigInteger b,
        BigInteger p,
        BigInteger gx,
        BigInteger gy,
        BigInteger n) {}
