package io.github.serengil.lightphe.commons;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Direct coverage for the number-theory helpers standing in for SymPy. The Python suite only
 * reaches these through the cryptosystems, so the expected values here were taken from SymPy
 * itself.
 */
class MathUtilsTest {

    private static BigInteger big(long value) {
        return BigInteger.valueOf(value);
    }

    @ParameterizedTest(name = "jacobi({0}/{1}) = {2}")
    @CsvSource({
        // reference values from sympy.jacobi_symbol
        "1, 1, 1",
        "0, 3, 0",
        "2, 3, -1",
        "3, 3, 0",
        "4, 3, 1",
        "2, 7, 1",
        "3, 7, -1",
        "45, 77, -1",
        "60, 121, 1",
        "1001, 9907, -1",
        "19, 45, 1",
        "8, 21, -1",
        "5, 21, 1",
    })
    @DisplayName("The Jacobi symbol matches SymPy")
    void testJacobiSymbol(long a, long n, int expected) {
        assertThat(MathUtils.jacobiSymbol(big(a), big(n))).isEqualTo(expected);
    }

    @Test
    @DisplayName("The Jacobi symbol rejects an even or non-positive modulus")
    void testJacobiSymbolRejectsInvalidModulus() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> MathUtils.jacobiSymbol(big(3), big(4)))
                .withMessageContaining("odd positive integer");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> MathUtils.jacobiSymbol(big(3), big(0)));
    }

    @Test
    @DisplayName("Modular square roots come back in ascending order")
    void testSqrtMod() {
        // sympy.sqrt_mod(4, 7, all_roots=True) == [2, 5]
        assertThat(MathUtils.sqrtMod(big(4), big(7))).containsExactly(big(2), big(5));

        // 3 is a quadratic non-residue modulo 7
        assertThat(MathUtils.sqrtMod(big(3), big(7))).isEmpty();

        // zero has a single root
        assertThat(MathUtils.sqrtMod(BigInteger.ZERO, big(7))).containsExactly(BigInteger.ZERO);

        // p = 1 (mod 4) exercises the full Tonelli-Shanks path
        assertThat(MathUtils.sqrtMod(big(2), big(17))).containsExactly(big(6), big(11));
    }

    @Test
    @DisplayName("Every square root actually squares back to its input")
    void testSqrtModRoundTrips() {
        List<BigInteger> primes = List.of(big(7), big(11), big(13), big(17), big(23), big(29));
        for (BigInteger p : primes) {
            for (long a = 0; a < p.longValueExact(); a++) {
                for (BigInteger root : MathUtils.sqrtMod(big(a), p)) {
                    assertThat(root.multiply(root).mod(p))
                            .as("sqrt(%d) mod %d", a, p)
                            .isEqualTo(big(a).mod(p));
                }
            }
        }
    }

    @Test
    @DisplayName("Distinct prime factors match SymPy's factorint keys")
    void testPrimeFactors() {
        assertThat(MathUtils.primeFactors(big(255255)))
                .containsExactly(big(3), big(5), big(7), big(11), big(13), big(17));
        assertThat(MathUtils.primeFactors(big(1024))).containsExactly(big(2));
        assertThat(MathUtils.primeFactors(big(1013))).containsExactly(big(1013));
        assertThat(MathUtils.primeFactors(BigInteger.ONE)).isEmpty();

        // a semiprime beyond the trial-division cut-off, which falls through to Pollard's rho
        BigInteger p = big(1_000_003);
        BigInteger q = big(1_000_033);
        assertThat(MathUtils.primeFactors(p.multiply(q))).containsExactly(p, q);
    }

    @Test
    @DisplayName("The Chinese remainder theorem solves a consistent system")
    void testSolveCongruence() {
        // sympy.ntheory.modular.solve_congruence((2, 3), (3, 5), (2, 7)) == (23, 105)
        BigInteger solution =
                MathUtils.solveCongruence(
                        List.of(big(2), big(3), big(2)), List.of(big(3), big(5), big(7)));
        assertThat(solution).isEqualTo(big(23));
    }

    @Test
    @DisplayName("The Chinese remainder theorem reports an inconsistent system")
    void testSolveCongruenceInconsistent() {
        // x = 1 (mod 4) and x = 2 (mod 6) have no common solution
        BigInteger solution =
                MathUtils.solveCongruence(List.of(big(1), big(2)), List.of(big(4), big(6)));
        assertThat(solution).isNull();
    }

    @Test
    @DisplayName("Random primes land inside the requested range")
    void testRandomPrime() {
        BigInteger low = big(1000);
        BigInteger high = big(2000);
        for (int i = 0; i < 50; i++) {
            BigInteger prime = MathUtils.randomPrime(low, high);
            assertThat(prime).isBetween(low, high);
            assertThat(MathUtils.isPrime(prime)).isTrue();
        }
    }

    @Test
    @DisplayName("A power-of-two lower bound below one behaves as no bound at all")
    void testRandomPrimeFromExponent() {
        // key_size 50 makes the Python lower bound 2 ** (25 - 300), a fraction that truncates to 0
        BigInteger high = BigInteger.TWO.pow(25).subtract(BigInteger.ONE);
        for (int i = 0; i < 20; i++) {
            BigInteger prime = MathUtils.randomPrimeFromExponent(25 - 300, high);
            assertThat(prime).isLessThan(high);
            assertThat(MathUtils.isPrime(prime)).isTrue();
        }
    }

    @Test
    @DisplayName("Random integers cover an inclusive range")
    void testRandomInt() {
        Set<BigInteger> seen = new HashSet<>();
        for (int i = 0; i < 500; i++) {
            BigInteger draw = MathUtils.randomInt(big(1), big(3));
            assertThat(draw).isBetween(big(1), big(3));
            seen.add(draw);
        }
        assertThat(seen).containsExactlyInAnyOrder(big(1), big(2), big(3));
    }

    @Test
    @DisplayName("Sampling draws distinct elements without replacement")
    void testSample() {
        List<BigInteger> population =
                List.of(big(3), big(5), big(7), big(11), big(13), big(17), big(19), big(23));
        List<BigInteger> drawn = MathUtils.sample(population, 4);

        assertThat(drawn).hasSize(4).doesNotHaveDuplicates();
        assertThat(population).containsAll(drawn);

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> MathUtils.sample(population, population.size() + 1));
    }

    @Test
    @DisplayName("Next and previous primes bracket a value")
    void testNextAndPrevPrime() {
        assertThat(MathUtils.nextPrime(big(13))).isEqualTo(big(17));
        assertThat(MathUtils.nextPrime(big(14))).isEqualTo(big(17));
        assertThat(MathUtils.nextPrime(BigInteger.ZERO)).isEqualTo(big(2));

        assertThat(MathUtils.prevPrime(big(17))).isEqualTo(big(13));
        assertThat(MathUtils.prevPrime(big(18))).isEqualTo(big(17));
        assertThat(MathUtils.prevPrime(big(3))).isEqualTo(big(2));
    }
}
