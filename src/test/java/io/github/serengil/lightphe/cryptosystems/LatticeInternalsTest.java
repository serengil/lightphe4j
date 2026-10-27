package io.github.serengil.lightphe.cryptosystems;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.serengil.lightphe.commons.MathUtils;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.TupleValue;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Structure of keys and ciphertexts of Lyubashevsky-Peikert-Regev, ML-KEM and Gentry-Sahai-Waters,
 * ported from the tests of the Python library that reach into private members.
 */
class LatticeInternalsTest {

    private static final long Q = 1L << PowerOfTwoRing.LOG_Q;

    /** Schoolbook multiplication in {@code Z_q[x] / (x^d + 1)} with exact integers. */
    private static long[] negacyclicProduct(long[] poly1, long[] poly2, long q) {
        int d = poly1.length;
        BigInteger[] result = new BigInteger[d];
        java.util.Arrays.fill(result, BigInteger.ZERO);
        for (int i = 0; i < d; i++) {
            for (int j = 0; j < d; j++) {
                BigInteger term =
                        BigInteger.valueOf(poly1[i]).multiply(BigInteger.valueOf(poly2[j]));
                if (i + j < d) {
                    result[i + j] = result[i + j].add(term);
                } else {
                    result[i + j - d] = result[i + j - d].subtract(term);
                }
            }
        }
        long[] reduced = new long[d];
        for (int i = 0; i < d; i++) {
            reduced[i] = result[i].mod(BigInteger.valueOf(q)).longValueExact();
        }
        return reduced;
    }

    private static long centered(long x, long q) {
        long value = Math.floorMod(x, q);
        return value > q / 2 ? value - q : value;
    }

    private static long[] longs(List<BigInteger> values) {
        return PowerOfTwoRing.toLongs(values);
    }

    // -----------------------------------------------------------------------
    // Lyubashevsky-Peikert-Regev
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Polynomial multiplication matches schoolbook multiplication")
    void testPolynomialMultiplication() {
        Random random = new Random(0);
        for (int d : new int[] {8, 64}) {
            for (int round = 0; round < 10; round++) {
                long[] poly1 = new long[d];
                long[] poly2 = new long[d];
                for (int i = 0; i < d; i++) {
                    poly1[i] = random.nextLong() & PowerOfTwoRing.MASK;
                    poly2[i] = random.nextLong() & PowerOfTwoRing.MASK;
                }
                assertThat(PowerOfTwoRing.multiply(poly1, poly2))
                        .isEqualTo(negacyclicProduct(poly1, poly2, Q));
            }
        }
    }

    @Test
    @DisplayName("Lyubashevsky-Peikert-Regev keys are b = a s + e for small s and e")
    void testLyubashevskyPeikertRegevKeysAreWellFormed() {
        LyubashevskyPeikertRegev cs = new LyubashevskyPeikertRegev(null, 64, null);
        Keys keys = cs.keys();
        long[] a = cs.publicA();
        long[] b = longs(keys.publicNumbers("b"));
        long[] s = longs(keys.privateNumbers("s"));

        assertThat(keys.publicNumber("q")).isEqualTo(BigInteger.valueOf(Q));
        assertThat(a).hasSize(64);
        assertThat(java.util.Arrays.stream(a).allMatch(x -> x >= 0 && x < Q)).isTrue();
        assertThat(b).hasSize(64);
        assertThat(s).hasSize(64);
        assertThat(java.util.Arrays.stream(s).allMatch(x -> Math.abs(x) <= Regev.ETA)).isTrue();

        long[] as = negacyclicProduct(a, s, Q);
        for (int i = 0; i < b.length; i++) {
            assertThat(Math.abs(centered(b[i] - as[i], Q))).isLessThanOrEqualTo(Regev.ETA);
        }
    }

    @Test
    @DisplayName("Lyubashevsky-Peikert-Regev ciphertexts are a u + e1 and b u + e2 + m q / t")
    void testLyubashevskyPeikertRegevCiphertextsAreWellFormed() {
        LyubashevskyPeikertRegev cs = new LyubashevskyPeikertRegev(null, 64, null);
        Keys keys = cs.keys();
        long t = keys.publicNumber("t").longValueExact();
        long[] a = cs.publicA();
        long[] b = longs(keys.publicNumbers("b"));
        long[] u = cs.generateRandomPolynomial();
        long m = 12345;

        long[] ciphertext = longs(((TupleValue) cs.encrypt(BigInteger.valueOf(m), u)).asIntegers());
        assertThat(ciphertext).hasSize(65);

        long[] au = negacyclicProduct(a, u, Q);
        for (int i = 0; i < 64; i++) {
            assertThat(Math.abs(centered(ciphertext[i] - au[i], Q))).isLessThanOrEqualTo(Regev.ETA);
        }
        long[] bu = negacyclicProduct(b, u, Q);
        assertThat(Math.abs(centered(ciphertext[64] - bu[0] - m * (Q / t), Q)))
                .isLessThanOrEqualTo(Regev.ETA);
    }

    // -----------------------------------------------------------------------
    // ML-KEM
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("ML-KEM polynomial multiplication matches schoolbook multiplication")
    void testMlKemPolynomialMultiplication() {
        Random random = new Random(1);
        for (int round = 0; round < 5; round++) {
            int[] poly1 = new int[MLKEM.N];
            int[] poly2 = new int[MLKEM.N];
            long[] wide1 = new long[MLKEM.N];
            long[] wide2 = new long[MLKEM.N];
            for (int i = 0; i < MLKEM.N; i++) {
                poly1[i] = random.nextInt(MLKEM.Q);
                poly2[i] = random.nextInt(7) - 3;
                wide1[i] = poly1[i];
                wide2[i] = poly2[i];
            }
            long[] expected = negacyclicProduct(wide1, wide2, MLKEM.Q);
            int[] actual = MLKEM.multiply(poly1, poly2);
            for (int i = 0; i < MLKEM.N; i++) {
                assertThat((long) actual[i]).isEqualTo(expected[i]);
            }
        }
    }

    @ParameterizedTest(name = "ML-KEM-{0}")
    @ValueSource(ints = {512, 768, 1024})
    @DisplayName("ML-KEM keys are t = A s + e for small s and e")
    void testMlKemKeysAreWellFormed(int parameterSet) {
        MLKEM cs = new MLKEM(null, parameterSet);
        MLKEM.ParameterSet parameters = MLKEM.PARAMETER_SETS.get(parameterSet);
        int k = parameters.k();
        int[][][] a = cs.publicA();
        List<List<BigInteger>> s = cs.keys().privateMatrix("s");
        List<List<BigInteger>> t = cs.keys().publicMatrix("t");

        assertThat(a).hasNumberOfRows(k);
        for (int[][] row : a) {
            assertThat(row).hasNumberOfRows(k);
            for (int[] polynomial : row) {
                assertThat(java.util.Arrays.stream(polynomial).allMatch(x -> x >= 0 && x < MLKEM.Q))
                        .isTrue();
            }
        }
        for (List<BigInteger> polynomial : s) {
            assertThat(polynomial).allMatch(x -> x.abs().intValueExact() <= parameters.eta1());
        }

        for (int i = 0; i < k; i++) {
            long[] as = new long[MLKEM.N];
            for (int j = 0; j < k; j++) {
                long[] wide = new long[MLKEM.N];
                for (int x = 0; x < MLKEM.N; x++) {
                    wide[x] = a[i][j][x];
                }
                long[] product = negacyclicProduct(wide, longs(s.get(j)), MLKEM.Q);
                for (int x = 0; x < MLKEM.N; x++) {
                    as[x] += product[x];
                }
            }
            for (int x = 0; x < MLKEM.N; x++) {
                long error = centered(t.get(i).get(x).longValueExact() - as[x], MLKEM.Q);
                assertThat(Math.abs(error)).isLessThanOrEqualTo(parameters.eta1());
            }
        }
    }

    @ParameterizedTest(name = "ML-KEM-{0}")
    @ValueSource(ints = {512, 768, 1024})
    @DisplayName("ML-KEM noise matches the estimate and is far below q / 4")
    void testMlKemNoiseMatchesTheEstimate(int parameterSet) {
        // noise e^T r + e2 - s^T e1 has variance k * 256 * (var1^2 + var1 * var2) + var2
        MLKEM cs = new MLKEM(null, parameterSet);
        MLKEM.ParameterSet parameters = MLKEM.PARAMETER_SETS.get(parameterSet);
        double var1 = parameters.eta1() / 2.0;
        double var2 = parameters.eta2() / 2.0;
        double sigma = Math.sqrt(parameters.k() * MLKEM.N * (var1 * var1 + var1 * var2) + var2);

        List<Long> samples = new ArrayList<>();
        for (int round = 0; round < 4; round++) {
            BigInteger m = MathUtils.getRandomBits(256);
            samples.addAll(noiseOf(cs, cs.encrypt(m), m));
        }
        double measured =
                Math.sqrt(samples.stream().mapToDouble(x -> (double) x * x).sum() / samples.size());
        assertThat(Math.abs(measured - sigma) / sigma).isLessThan(0.15);

        // fresh noise is far below q / 4
        assertThat(samples.stream().mapToLong(Math::abs).max().getAsLong())
                .isLessThan(MLKEM.Q / 4 / 3);
    }

    /** {@code v - s^T u - m q / 2} for each coefficient. */
    private static List<Long> noiseOf(MLKEM cs, CipherValue ciphertext, BigInteger plaintext) {
        List<TupleValue> polynomials = ((TupleValue) ciphertext).asTuples();
        List<List<BigInteger>> s = cs.keys().privateMatrix("s");
        int k = polynomials.size() - 1;
        long[] w = longs(polynomials.get(k).asIntegers());
        for (int j = 0; j < k; j++) {
            long[] product =
                    negacyclicProduct(
                            longs(polynomials.get(j).asIntegers()), longs(s.get(j)), MLKEM.Q);
            for (int x = 0; x < MLKEM.N; x++) {
                w[x] -= product[x];
            }
        }
        List<Long> noise = new ArrayList<>(MLKEM.N);
        for (int x = 0; x < MLKEM.N; x++) {
            long bit = plaintext.testBit(x) ? MLKEM.HALF_Q : 0;
            noise.add(centered(w[x] - bit, MLKEM.Q));
        }
        return noise;
    }

    // -----------------------------------------------------------------------
    // Gentry-Sahai-Waters
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Gentry-Sahai-Waters keys are b = -(a s) + e for small s and e")
    void testGentrySahaiWatersKeysAreWellFormed() {
        GentrySahaiWaters cs = new GentrySahaiWaters(null, 64);
        Keys keys = cs.keys();
        long[] a = cs.publicA();
        long[] b = longs(keys.publicNumbers("b"));
        long[] s = longs(keys.privateNumbers("s"));

        assertThat(keys.publicNumber("q")).isEqualTo(BigInteger.valueOf(Q));
        assertThat(java.util.Arrays.stream(s).allMatch(x -> Math.abs(x) <= Regev.ETA)).isTrue();
        long[] as = negacyclicProduct(a, s, Q);
        for (int i = 0; i < b.length; i++) {
            assertThat(Math.abs(centered(as[i] + b[i], Q))).isLessThanOrEqualTo(Regev.ETA);
        }
    }

    @Test
    @DisplayName("Gadget decomposition restores the polynomial up to rounding")
    void testGadgetDecomposition() {
        int ell = GentrySahaiWaters.ELL;
        int logB = GentrySahaiWaters.LOG_B;
        int offset = GentrySahaiWaters.OFFSET;
        assertThat(offset + logB * (ell - 1)).isEqualTo(PowerOfTwoRing.LOG_Q - 1);

        Random random = new Random(2);
        long[] poly = new long[69];
        for (int i = 0; i < 64; i++) {
            poly[i] = random.nextLong() & PowerOfTwoRing.MASK;
        }
        long[] edges = {0, 1, Q - 1, Q / 2, Q / 2 - 1};
        System.arraycopy(edges, 0, poly, 64, edges.length);

        long[][] digits = GentrySahaiWaters.decompose(poly);
        assertThat(digits).hasNumberOfRows(ell);
        long halfB = 1L << (logB - 1);
        for (int i = 0; i < poly.length; i++) {
            long restored = 0;
            for (int j = 0; j < ell; j++) {
                assertThat(digits[j][i]).isBetween(-halfB, halfB - 1);
                restored += digits[j][i] * GentrySahaiWaters.gadget(j);
            }
            assertThat(Math.abs(centered(poly[i] - restored, Q)))
                    .isLessThanOrEqualTo(1L << (offset - 1));
        }
    }

    /** Bit length of the phase of the decrypted row minus {@code m q / 2}. */
    private static int noiseBits(GentrySahaiWaters cs, CipherValue ciphertext, long bit) {
        long[] s = longs(cs.keys().privateNumbers("s"));
        List<TupleValue> row =
                ((TupleValue) ciphertext).asTuples().get(GentrySahaiWaters.ELL - 1).asTuples();
        long[] c0 = longs(row.get(0).asIntegers());
        long[] c1 = longs(row.get(1).asIntegers());
        long phase = centered(c0[0] + negacyclicProduct(c1, s, Q)[0] - bit * (Q / 2), Q);
        return 64 - Long.numberOfLeadingZeros(Math.abs(phase));
    }

    @Test
    @DisplayName("Products of products of depth 2 stay below q / 4 for degree 2048")
    void testGentrySahaiWatersNoiseBudgetOfLargeKeys() {
        GentrySahaiWaters cs = new GentrySahaiWaters(null, 2048);
        List<CipherValue> ones = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            ones.add(cs.encrypt(BigInteger.ONE));
        }
        assertThat(noiseBits(cs, ones.get(0), 1)).isLessThanOrEqualTo(16);

        CipherValue ab = cs.homomorphicAnd(ones.get(0), ones.get(1));
        CipherValue cd = cs.homomorphicAnd(ones.get(2), ones.get(3));
        assertThat(noiseBits(cs, ab, 1)).isLessThanOrEqualTo(32);

        CipherValue abcd = cs.homomorphicAnd(ab, cd);
        assertThat(cs.decrypt(abcd)).isEqualTo(BigInteger.ONE);
        assertThat(noiseBits(cs, abcd, 1)).isLessThanOrEqualTo(46);

        // a chain with a fresh ciphertext on the right adds a small noise
        CipherValue chain = cs.homomorphicAnd(abcd, cs.encrypt(BigInteger.ZERO));
        assertThat(cs.decrypt(chain)).isZero();
    }
}
