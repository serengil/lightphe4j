package io.github.serengil.lightphe.ecc;

import java.math.BigInteger;

/**
 * Carry-less polynomial arithmetic in {@code GF(2^m)}.
 *
 * <p>Field elements are bit strings packed into a {@link BigInteger}: bit {@code i} of the integer
 * is the coefficient of {@code x^i}. Addition is exclusive-or, so no operation in this class ever
 * produces a carry.
 *
 * <p>This module is heavily inspired by the repository <a
 * href="https://github.com/dimitrijray/ecc-binary-field">github.com/dimitrijray/ecc-binary-field</a>.
 */
public final class BinaryOperations {

    private BinaryOperations() {
        throw new AssertionError("no instances");
    }

    /**
     * Adds two binary field elements, which in {@code GF(2)} is exclusive-or.
     *
     * @param a first operand
     * @param b second operand
     * @return {@code a XOR b}
     */
    public static BigInteger add(BigInteger a, BigInteger b) {
        return a.xor(b);
    }

    /**
     * Multiplies two binary numbers in {@code GF(2)} without carries.
     *
     * @param a first operand
     * @param b second operand
     * @return the carry-less product of {@code a} and {@code b}
     */
    public static BigInteger multiply(BigInteger a, BigInteger b) {
        BigInteger result = BigInteger.ZERO;
        for (int i = 0; i < b.bitLength(); i++) {
            if (b.testBit(i)) {
                result = result.xor(a.shiftLeft(i));
            }
        }
        return result;
    }

    /**
     * Squares a binary number, which spreads the bits of {@code num} to even positions.
     *
     * @param num the operand
     * @return {@code num * num} in {@code GF(2)}
     */
    public static BigInteger square(BigInteger num) {
        BigInteger result = BigInteger.ZERO;
        for (int i = 0; i < num.bitLength(); i++) {
            if (num.testBit(i)) {
                result = result.setBit(2 * i);
            }
        }
        return result;
    }

    /**
     * Reduces {@code num} modulo the polynomial {@code modulo}.
     *
     * @param num the polynomial to reduce
     * @param modulo the reduction polynomial
     * @return {@code num mod modulo}
     */
    public static BigInteger mod(BigInteger num, BigInteger modulo) {
        int degR = modulo.bitLength() - 1;
        if (degR <= 0) {
            return num;
        }
        BigInteger remainder = num;
        int degP = remainder.bitLength() - 1;
        while (degP >= degR) {
            remainder = remainder.xor(modulo.shiftLeft(degP - degR));
            degP = remainder.bitLength() - 1;
        }
        return remainder;
    }

    /**
     * Returns the quotient of the polynomial division {@code num / modulo} in {@code GF(2)}.
     *
     * @param num numerator
     * @param modulo denominator
     * @return the quotient
     */
    public static BigInteger div(BigInteger num, BigInteger modulo) {
        int degR = modulo.bitLength() - 1;
        BigInteger quotient = BigInteger.ZERO;
        BigInteger remainder = num;
        int degP = remainder.bitLength() - 1;
        while (degP >= degR && remainder.signum() != 0) {
            int shift = degP - degR;
            quotient = quotient.setBit(shift);
            remainder = remainder.xor(modulo.shiftLeft(shift));
            degP = remainder.bitLength() - 1;
        }
        return quotient;
    }

    /**
     * Computes the multiplicative inverse of {@code num} modulo a polynomial, using the extended
     * Euclidean algorithm over {@code GF(2)}.
     *
     * @param num the element to invert
     * @param modulo the reduction polynomial
     * @return {@code num^-1 mod modulo}
     * @throws ArithmeticException when {@code num} is not invertible
     */
    public static BigInteger inverse(BigInteger num, BigInteger modulo) {
        BigInteger a = num;
        BigInteger b = modulo;
        BigInteger p1 = BigInteger.ONE;
        BigInteger p2 = BigInteger.ZERO;

        while (!b.equals(BigInteger.ONE)) {
            if (b.signum() == 0) {
                throw new ArithmeticException(num + " is not invertible modulo " + modulo);
            }
            BigInteger q = div(a, b);
            BigInteger r = mod(a, b);
            a = b;
            b = r;
            BigInteger pa = p1.xor(multiply(q, p2));
            p1 = p2;
            p2 = pa;
        }
        return p2;
    }

    /**
     * Returns {@code a * b^-1 mod p} in {@code GF(2)}.
     *
     * @param a nominator
     * @param b denominator
     * @param p reduction polynomial
     * @return the quotient reduced modulo {@code p}
     */
    public static BigInteger divide(BigInteger a, BigInteger b, BigInteger p) {
        return mod(multiply(a, inverse(b, p)), p);
    }

    /**
     * Computes {@code num^exp mod modulo} in {@code GF(2)}.
     *
     * @param num base
     * @param exp non-negative exponent
     * @param modulo reduction polynomial
     * @return {@code num^exp mod modulo}
     */
    public static BigInteger powerMod(BigInteger num, int exp, BigInteger modulo) {
        BigInteger result = BigInteger.ONE;
        BigInteger base = mod(num, modulo);
        int e = exp;
        while (e > 0) {
            if ((e & 1) == 1) {
                result = mod(multiply(base, result), modulo);
            }
            base = mod(square(base), modulo);
            e >>= 1;
        }
        return result;
    }
}
