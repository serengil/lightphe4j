package io.github.serengil.lightphe.commons;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Finds safe primes, the counterpart of {@code lightphe.commons.safe_primes}.
 *
 * <p>A safe prime is {@code p = 2p' + 1} where {@code p'} is also prime.
 * Bresson-Catalano-Pointcheval and Camenisch-Shoup build their moduli from them.
 */
public final class SafePrimes {

    /** Small primes to sieve safe prime candidates before primality tests. */
    private static final List<Integer> SMALL_PRIMES = smallPrimes(2000);

    private SafePrimes() {
        throw new AssertionError("no instances");
    }

    /**
     * Finds a safe prime {@code p = 2p' + 1} where {@code p'} is also prime.
     *
     * @param bits bit length of p
     * @param maxTries maximum number of tries, scaled by 100 as safe primes are rare
     * @return the safe prime
     * @throws IllegalArgumentException when no safe prime is found
     */
    public static BigInteger findSafePrime(int bits, int maxTries) {
        for (long attempt = 0; attempt < (long) maxTries * 100; attempt++) {
            BigInteger pPrime = MathUtils.getRandomBits(bits - 1).setBit(bits - 2).setBit(0);
            BigInteger p = pPrime.shiftLeft(1).add(BigInteger.ONE);
            // sieve with small primes first, as primality tests are expensive
            if (hasSmallFactor(pPrime, p)) {
                continue;
            }
            if (MathUtils.isPrime(pPrime) && MathUtils.isPrime(p)) {
                return p;
            }
        }
        throw new IllegalArgumentException("Failed to find a " + bits + "-bit safe prime");
    }

    private static boolean hasSmallFactor(BigInteger pPrime, BigInteger p) {
        for (int prime : SMALL_PRIMES) {
            BigInteger s = BigInteger.valueOf(prime);
            if (s.compareTo(pPrime) >= 0) {
                return false;
            }
            if (pPrime.mod(s).signum() == 0 || p.mod(s).signum() == 0) {
                return true;
            }
        }
        return false;
    }

    private static List<Integer> smallPrimes(int limit) {
        List<Integer> primes = new ArrayList<>();
        for (int candidate = 3; candidate < limit; candidate += 2) {
            if (BigInteger.valueOf(candidate).isProbablePrime(20)) {
                primes.add(candidate);
            }
        }
        return List.copyOf(primes);
    }
}
