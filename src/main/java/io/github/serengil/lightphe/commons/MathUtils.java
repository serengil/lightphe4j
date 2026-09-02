package io.github.serengil.lightphe.commons;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;

/**
 * Number-theoretic helpers standing in for the SymPy and {@code random} functions the Python
 * implementation relies on.
 *
 * <p>Every method is deterministic given its inputs except those that explicitly draw randomness,
 * which use a shared {@link SecureRandom}.
 */
public final class MathUtils {

    /** Miller-Rabin certainty used for probabilistic primality testing. */
    private static final int PRIME_CERTAINTY = 40;

    private static final BigInteger TWO = BigInteger.TWO;
    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger FOUR = BigInteger.valueOf(4);
    private static final BigInteger EIGHT = BigInteger.valueOf(8);

    private static final Random RANDOM = new SecureRandom();

    private MathUtils() {
        throw new AssertionError("no instances");
    }

    /**
     * Returns the shared source of randomness used for key generation.
     *
     * @return a cryptographically strong random generator
     */
    public static Random random() {
        return RANDOM;
    }

    // -----------------------------------------------------------------------
    // Randomness
    // -----------------------------------------------------------------------

    /**
     * Draws a uniformly random integer in the inclusive range {@code [low, high]}, the semantics of
     * Python's {@code random.randint}.
     *
     * @param low inclusive lower bound
     * @param high inclusive upper bound
     * @return a random integer in the range
     * @throws IllegalArgumentException when {@code low > high}
     */
    public static BigInteger randomInt(BigInteger low, BigInteger high) {
        if (low.compareTo(high) > 0) {
            throw new IllegalArgumentException(
                    "empty range for randomInt: [" + low + ", " + high + "]");
        }
        BigInteger span = high.subtract(low).add(BigInteger.ONE);
        BigInteger draw;
        int bits = span.bitLength();
        do {
            draw = new BigInteger(bits, RANDOM);
        } while (draw.compareTo(span) >= 0);
        return low.add(draw);
    }

    /**
     * Draws a uniformly random integer in the inclusive range {@code [low, high]}.
     *
     * @param low inclusive lower bound
     * @param high inclusive upper bound
     * @return a random integer in the range
     */
    public static BigInteger randomInt(long low, long high) {
        return randomInt(BigInteger.valueOf(low), BigInteger.valueOf(high));
    }

    /**
     * Draws a random non-negative integer with at most {@code bits} bits, the semantics of Python's
     * {@code random.getrandbits}.
     *
     * @param bits the number of bits
     * @return a random integer in {@code [0, 2^bits)}
     */
    public static BigInteger getRandomBits(int bits) {
        if (bits <= 0) {
            return BigInteger.ZERO;
        }
        return new BigInteger(bits, RANDOM);
    }

    /**
     * Draws {@code k} distinct elements from {@code population} without replacement, the semantics
     * of Python's {@code random.sample}.
     *
     * @param population the values to draw from
     * @param k how many to draw
     * @param <T> element type
     * @return the drawn elements
     * @throws IllegalArgumentException when {@code k} exceeds the population size
     */
    public static <T> List<T> sample(List<T> population, int k) {
        if (k > population.size()) {
            throw new IllegalArgumentException("sample larger than population");
        }
        List<T> copy = new ArrayList<>(population);
        Collections.shuffle(copy, RANDOM);
        return new ArrayList<>(copy.subList(0, k));
    }

    // -----------------------------------------------------------------------
    // Primes
    // -----------------------------------------------------------------------

    /**
     * Probabilistic primality test, the counterpart of {@code sympy.isprime}.
     *
     * @param n the candidate
     * @return {@code true} when {@code n} is prime
     */
    public static boolean isPrime(BigInteger n) {
        return n.signum() > 0 && n.isProbablePrime(PRIME_CERTAINTY);
    }

    /**
     * Returns the smallest prime strictly greater than {@code n}, the counterpart of {@code
     * sympy.nextprime}.
     *
     * @param n the lower bound
     * @return the next prime after {@code n}
     */
    public static BigInteger nextPrime(BigInteger n) {
        if (n.compareTo(TWO) < 0) {
            return TWO;
        }
        return n.nextProbablePrime();
    }

    /**
     * Returns the largest prime strictly smaller than {@code n}, the counterpart of {@code
     * sympy.prevprime}.
     *
     * @param n the upper bound
     * @return the previous prime before {@code n}
     * @throws IllegalArgumentException when no prime is smaller than {@code n}
     */
    public static BigInteger prevPrime(BigInteger n) {
        if (n.compareTo(THREE) <= 0) {
            if (n.compareTo(THREE) == 0) {
                return TWO;
            }
            throw new IllegalArgumentException("no primes below " + n);
        }
        BigInteger candidate = n.subtract(BigInteger.ONE);
        if (!candidate.testBit(0)) {
            candidate = candidate.subtract(BigInteger.ONE);
        }
        while (candidate.compareTo(TWO) > 0) {
            if (candidate.isProbablePrime(PRIME_CERTAINTY)) {
                return candidate;
            }
            candidate = candidate.subtract(TWO);
        }
        return TWO;
    }

    /**
     * Returns a random prime in the half-open interval {@code [low, high)}, the counterpart of
     * {@code sympy.randprime}.
     *
     * <p>The algorithm mirrors SymPy's: draw a random integer in {@code [low - 1, high]}, take the
     * next prime after it, and fall back to the largest prime below {@code high} when that
     * overshoots.
     *
     * @param low inclusive lower bound
     * @param high exclusive upper bound
     * @return a random prime in the range
     * @throws IllegalArgumentException when the range holds no prime
     */
    public static BigInteger randomPrime(BigInteger low, BigInteger high) {
        if (low.compareTo(high) >= 0) {
            throw new IllegalArgumentException(
                    "empty range for randomPrime: [" + low + ", " + high + ")");
        }
        BigInteger seed = randomInt(low.subtract(BigInteger.ONE), high);
        BigInteger prime = nextPrime(seed);
        if (prime.compareTo(high) >= 0) {
            prime = prevPrime(high);
        }
        if (prime.compareTo(low) < 0) {
            throw new IllegalArgumentException("no primes exist in the specified range");
        }
        return prime;
    }

    /**
     * Returns a random prime in the half-open interval {@code [2^lowExponent, high)}.
     *
     * <p>The Python implementation writes lower bounds as {@code 2 ** (key_size // 2 - 300)}, which
     * silently becomes a fraction below one for small key sizes; this helper reproduces that by
     * clamping non-positive exponents to a lower bound of zero.
     *
     * @param lowExponent exponent of the power-of-two lower bound; non-positive means "no bound"
     * @param high exclusive upper bound
     * @return a random prime in the range
     */
    public static BigInteger randomPrimeFromExponent(int lowExponent, BigInteger high) {
        BigInteger low = lowExponent > 0 ? TWO.pow(lowExponent) : BigInteger.ZERO;
        return randomPrime(low, high);
    }

    /**
     * Returns the distinct prime factors of {@code n}, the counterpart of {@code
     * sympy.factorint(n).keys()}.
     *
     * @param n the value to factor; must be positive
     * @return the distinct prime factors in ascending order
     */
    public static Set<BigInteger> primeFactors(BigInteger n) {
        Set<BigInteger> factors = new TreeSet<>();
        if (n.signum() <= 0) {
            return factors;
        }
        BigInteger remainder = n;

        // Strip the small factors by trial division first: this alone settles every value the
        // library actually factors (Benaloh's block size r and Naccache-Stern's sigma).
        for (BigInteger candidate = TWO;
                candidate.multiply(candidate).compareTo(remainder) <= 0
                        && candidate.compareTo(BigInteger.valueOf(1_000_000)) <= 0;
                candidate = candidate.add(candidate.equals(TWO) ? BigInteger.ONE : TWO)) {
            while (remainder.mod(candidate).signum() == 0) {
                factors.add(candidate);
                remainder = remainder.divide(candidate);
            }
        }

        if (remainder.equals(BigInteger.ONE)) {
            return factors;
        }
        if (isPrime(remainder)) {
            factors.add(remainder);
            return factors;
        }

        // Whatever survives trial division is split with Pollard's rho.
        factors.addAll(pollardFactors(remainder));
        return factors;
    }

    private static Set<BigInteger> pollardFactors(BigInteger n) {
        Set<BigInteger> factors = new LinkedHashSet<>();
        if (n.equals(BigInteger.ONE)) {
            return factors;
        }
        if (isPrime(n)) {
            factors.add(n);
            return factors;
        }
        BigInteger divisor = pollardRho(n);
        factors.addAll(pollardFactors(divisor));
        factors.addAll(pollardFactors(n.divide(divisor)));
        return factors;
    }

    private static BigInteger pollardRho(BigInteger n) {
        if (!n.testBit(0)) {
            return TWO;
        }
        while (true) {
            BigInteger x = randomInt(TWO, n.subtract(BigInteger.ONE));
            BigInteger y = x;
            BigInteger c = randomInt(BigInteger.ONE, n.subtract(BigInteger.ONE));
            BigInteger divisor = BigInteger.ONE;
            while (divisor.equals(BigInteger.ONE)) {
                x = x.multiply(x).add(c).mod(n);
                y = y.multiply(y).add(c).mod(n);
                y = y.multiply(y).add(c).mod(n);
                divisor = x.subtract(y).abs().gcd(n);
            }
            if (!divisor.equals(n)) {
                return divisor;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Modular arithmetic
    // -----------------------------------------------------------------------

    /**
     * Computes the Jacobi symbol {@code (a / n)}, the counterpart of {@code sympy.jacobi_symbol}.
     * When {@code n} is an odd prime this is the Legendre symbol.
     *
     * @param a the numerator
     * @param n an odd positive modulus
     * @return {@code -1}, {@code 0} or {@code 1}
     * @throws IllegalArgumentException when {@code n} is not odd and positive
     */
    public static int jacobiSymbol(BigInteger a, BigInteger n) {
        if (n.signum() <= 0 || !n.testBit(0)) {
            throw new IllegalArgumentException("n should be an odd positive integer, got " + n);
        }
        BigInteger num = a.mod(n);
        BigInteger den = n;
        int result = 1;

        while (num.signum() != 0) {
            while (!num.testBit(0)) {
                num = num.shiftRight(1);
                BigInteger denMod8 = den.mod(EIGHT);
                if (denMod8.equals(THREE) || denMod8.equals(BigInteger.valueOf(5))) {
                    result = -result;
                }
            }
            BigInteger swap = num;
            num = den;
            den = swap;
            if (num.mod(FOUR).equals(THREE) && den.mod(FOUR).equals(THREE)) {
                result = -result;
            }
            num = num.mod(den);
        }
        return den.equals(BigInteger.ONE) ? result : 0;
    }

    /**
     * Returns every square root of {@code a} modulo the odd prime {@code p}, in ascending order.
     * This is the counterpart of {@code sympy.ntheory.residue_ntheory.sqrt_mod} with {@code
     * all_roots=True}.
     *
     * @param a the value whose square roots are sought
     * @param p an odd prime modulus
     * @return the roots in ascending order; empty when {@code a} is a quadratic non-residue
     */
    public static List<BigInteger> sqrtMod(BigInteger a, BigInteger p) {
        BigInteger value = a.mod(p);
        List<BigInteger> roots = new ArrayList<>(2);

        if (value.signum() == 0) {
            roots.add(BigInteger.ZERO);
            return roots;
        }
        if (p.equals(TWO)) {
            roots.add(value);
            return roots;
        }
        if (!value.modPow(p.subtract(BigInteger.ONE).divide(TWO), p).equals(BigInteger.ONE)) {
            // quadratic non-residue
            return roots;
        }

        BigInteger root = tonelliShanks(value, p);
        BigInteger other = p.subtract(root);
        if (root.compareTo(other) <= 0) {
            roots.add(root);
            if (!root.equals(other)) {
                roots.add(other);
            }
        } else {
            roots.add(other);
            roots.add(root);
        }
        return roots;
    }

    private static BigInteger tonelliShanks(BigInteger a, BigInteger p) {
        // The common shortcut for p = 3 (mod 4).
        if (p.mod(FOUR).equals(THREE)) {
            return a.modPow(p.add(BigInteger.ONE).divide(FOUR), p);
        }

        BigInteger q = p.subtract(BigInteger.ONE);
        int s = 0;
        while (!q.testBit(0)) {
            q = q.shiftRight(1);
            s++;
        }

        BigInteger z = TWO;
        while (z.modPow(p.subtract(BigInteger.ONE).divide(TWO), p).equals(BigInteger.ONE)) {
            z = z.add(BigInteger.ONE);
        }

        int m = s;
        BigInteger c = z.modPow(q, p);
        BigInteger t = a.modPow(q, p);
        BigInteger r = a.modPow(q.add(BigInteger.ONE).divide(TWO), p);

        while (!t.equals(BigInteger.ONE)) {
            int i = 0;
            BigInteger temp = t;
            while (!temp.equals(BigInteger.ONE)) {
                temp = temp.multiply(temp).mod(p);
                i++;
            }
            BigInteger b = c.modPow(TWO.pow(m - i - 1), p);
            m = i;
            c = b.multiply(b).mod(p);
            t = t.multiply(c).mod(p);
            r = r.multiply(b).mod(p);
        }
        return r;
    }

    /**
     * Solves a system of simultaneous congruences {@code x = remainder_i (mod modulus_i)} with the
     * Chinese remainder theorem, the counterpart of {@code sympy.ntheory.modular.solve_congruence}.
     *
     * @param remainders the residues
     * @param moduli the pairwise coprime moduli
     * @return the smallest non-negative solution, or {@code null} when the system is inconsistent
     * @throws IllegalArgumentException when the two arrays differ in length or are empty
     */
    public static BigInteger solveCongruence(List<BigInteger> remainders, List<BigInteger> moduli) {
        if (remainders.size() != moduli.size() || remainders.isEmpty()) {
            throw new IllegalArgumentException(
                    "remainders and moduli must be non-empty and equal in size");
        }

        BigInteger x = remainders.get(0).mod(moduli.get(0));
        BigInteger modulus = moduli.get(0);

        for (int i = 1; i < moduli.size(); i++) {
            BigInteger nextModulus = moduli.get(i);
            BigInteger nextRemainder = remainders.get(i);

            BigInteger gcd = modulus.gcd(nextModulus);
            BigInteger difference = nextRemainder.subtract(x);
            if (difference.mod(gcd).signum() != 0) {
                return null;
            }

            BigInteger lcm = modulus.divide(gcd).multiply(nextModulus);
            BigInteger step =
                    difference
                            .divide(gcd)
                            .multiply(modulus.divide(gcd).modInverse(nextModulus.divide(gcd)))
                            .mod(nextModulus.divide(gcd));
            x = x.add(modulus.multiply(step)).mod(lcm);
            modulus = lcm;
        }
        return x.mod(modulus);
    }
}
