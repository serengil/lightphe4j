package io.github.serengil.lightphe.cryptosystems;

import io.github.serengil.lightphe.commons.Shake128;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.TupleValue;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Arithmetic in the polynomial ring {@code Z_q[x] / (x^d + 1)} for {@code q = 2^50}, shared by
 * Lyubashevsky-Peikert-Regev and Gentry-Sahai-Waters.
 *
 * <p>q is a power of 2 dividing {@code 2^64}, so coefficients are computed with wrapping {@code
 * long} arithmetic and reduced by masking their low bits, which is exact.
 */
final class PowerOfTwoRing {

    /** Bit length of the ciphertext modulus {@code q = 2^LOG_Q}. */
    static final int LOG_Q = 50;

    /** Ciphertext modulus. */
    static final BigInteger Q = BigInteger.ONE.shiftLeft(LOG_Q);

    /** Reduces a wrapping long modulo q. */
    static final long MASK = (1L << LOG_Q) - 1;

    private PowerOfTwoRing() {
        throw new AssertionError("no instances");
    }

    /**
     * Validates a ring degree.
     *
     * @param d the ring degree
     * @param algorithm name of the algorithm for the error message
     * @throws IllegalArgumentException when d is not a power of 2 or less than 8
     */
    static void validateDegree(int d, String algorithm) {
        if (d < 8 || (d & (d - 1)) != 0) {
            throw new IllegalArgumentException(
                    "Key size " + d + " must be a power of 2 and at least 8 for " + algorithm);
        }
    }

    /**
     * Multiplies two polynomials in {@code Z_q[x] / (x^d + 1)}.
     *
     * @param poly1 d coefficients, any representative modulo q
     * @param poly2 d coefficients, any representative modulo q
     * @return d coefficients in {@code [0, q)}
     */
    static long[] multiply(long[] poly1, long[] poly2) {
        int d = poly1.length;
        long[] product = new long[d];
        for (int i = 0; i < d; i++) {
            long x = poly1[i];
            if (x == 0) {
                continue;
            }
            // x^d = -1
            for (int j = 0; j < d - i; j++) {
                product[i + j] += x * poly2[j];
            }
            for (int j = d - i; j < d; j++) {
                product[i + j - d] -= x * poly2[j];
            }
        }
        for (int i = 0; i < d; i++) {
            product[i] &= MASK;
        }
        return product;
    }

    /**
     * Constant term of the product of two polynomials in {@code Z_q[x] / (x^d + 1)}, i.e. {@code
     * p1_0 p2_0 - sum of p1_i p2_(d-i)} for i in {@code [1, d)}.
     *
     * @param poly1 d coefficients
     * @param poly2 d coefficients
     * @return the constant term in {@code [0, q)}
     */
    static long constantTerm(long[] poly1, long[] poly2) {
        int d = poly1.length;
        long result = poly1[0] * poly2[0];
        for (int i = 1; i < d; i++) {
            result -= poly1[i] * poly2[d - i];
        }
        return result & MASK;
    }

    /**
     * Expands the public polynomial a from its seed with SHAKE-128. q is a power of 2, so each
     * coefficient is uniform in {@code [0, q)} when its bits are masked.
     *
     * @param seed the public seed
     * @param d the ring degree
     * @return d coefficients in {@code [0, q)}
     */
    static long[] expand(BigInteger seed, int d) {
        int width = (LOG_Q + 7) / 8;
        byte[] stream = Shake128.digest(Regev.toBytes(seed, 32), d * width);
        long[] coefficients = new long[d];
        for (int i = 0; i < d; i++) {
            long value = 0;
            for (int k = width - 1; k >= 0; k--) {
                value = (value << 8) | (stream[i * width + k] & 0xFF);
            }
            coefficients[i] = value & MASK;
        }
        return coefficients;
    }

    /** Converts integers into longs. */
    static long[] toLongs(List<BigInteger> values) {
        long[] out = new long[values.size()];
        for (int i = 0; i < out.length; i++) {
            out[i] = values.get(i).longValue();
        }
        return out;
    }

    /** Converts longs into integers. */
    static List<BigInteger> toBigIntegers(long[] values) {
        List<BigInteger> out = new ArrayList<>(values.length);
        for (long value : values) {
            out.add(BigInteger.valueOf(value));
        }
        return out;
    }

    /** Wraps coefficients as a tuple of integer ciphertexts. */
    static TupleValue toValue(long[] coefficients) {
        return TupleValue.ofIntegers(toBigIntegers(coefficients));
    }

    /** Unwraps a tuple of integer ciphertexts into coefficients. */
    static long[] toCoefficients(CipherValue value) {
        return toLongs(AbstractHomomorphic.asTuple(value).asIntegers());
    }
}
