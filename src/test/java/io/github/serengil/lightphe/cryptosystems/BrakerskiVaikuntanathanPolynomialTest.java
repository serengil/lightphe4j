package io.github.serengil.lightphe.cryptosystems;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.serengil.lightphe.commons.MathUtils;
import io.github.serengil.lightphe.model.Keys;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Port of the tests of {@code tests/test_brakerskivaikuntanathan.py} that reach into the private
 * polynomial arithmetic of the cryptosystem.
 */
class BrakerskiVaikuntanathanPolynomialTest {

    /** Bit length of the ciphertext modulus q. */
    private static final int LOG_Q = 100;

    /** Bound of the coefficients of the secret and errors. */
    private static final int ETA = 21;

    private static final BrakerskiVaikuntanathan cs = new BrakerskiVaikuntanathan(null, 64, null);

    /** Schoolbook multiplication in {@code Z_q[x] / (x^d + 1)}. */
    private static BigInteger[] negacyclicProduct(
            BigInteger[] poly1, BigInteger[] poly2, BigInteger q) {
        int d = poly1.length;
        BigInteger[] result = new BigInteger[d];
        Arrays.fill(result, BigInteger.ZERO);
        for (int i = 0; i < d; i++) {
            for (int j = 0; j < d; j++) {
                BigInteger product = poly1[i].multiply(poly2[j]);
                if (i + j < d) {
                    result[i + j] = result[i + j].add(product);
                } else {
                    result[i + j - d] = result[i + j - d].subtract(product);
                }
            }
        }
        for (int i = 0; i < d; i++) {
            result[i] = result[i].mod(q);
        }
        return result;
    }

    @Test
    @DisplayName("Brakerski-Vaikuntanathan keys satisfy b = -(a s + t e) for small e")
    void testKeysAreWellFormed() {
        Keys keys = cs.keys();
        int d = keys.publicNumber("d").intValueExact();
        BigInteger q = keys.publicNumber("q");
        BigInteger t = keys.publicNumber("t");
        List<BigInteger> b = keys.publicNumbers("b");
        List<BigInteger> s = keys.privateNumbers("s");
        BigInteger[] a = BrakerskiVaikuntanathan.expand(keys.publicNumber("seed"), d);

        assertThat(q.bitLength()).isEqualTo(LOG_Q);
        assertThat(q.testBit(0)).isTrue();
        assertThat(t.bitCount()).isEqualTo(1);
        assertThat(s)
                .allSatisfy(x -> assertThat(x.abs()).isLessThanOrEqualTo(BigInteger.valueOf(ETA)));

        BigInteger[] sModQ = s.stream().map(x -> x.mod(q)).toArray(BigInteger[]::new);
        BigInteger[] as = negacyclicProduct(a, sModQ, q);
        for (int i = 0; i < d; i++) {
            // t e = -(b + a s)
            BigInteger te = as[i].add(b.get(i)).negate().mod(q);
            if (te.compareTo(q.shiftRight(1)) > 0) {
                te = te.subtract(q);
            }
            assertThat(te.mod(t)).isEqualTo(BigInteger.ZERO);
            assertThat(te.divide(t).abs()).isLessThanOrEqualTo(BigInteger.valueOf(ETA));
        }
    }

    @Test
    @DisplayName("Kronecker substitution multiplies polynomials as schoolbook multiplication")
    void testPolynomialMultiplication() {
        BigInteger q = cs.ciphertextModulo();
        BigInteger upper = q.subtract(BigInteger.ONE);
        for (int d : new int[] {8, 64}) {
            for (int round = 0; round < 10; round++) {
                BigInteger[] poly1 = new BigInteger[d];
                BigInteger[] poly2 = new BigInteger[d];
                for (int i = 0; i < d; i++) {
                    poly1[i] = MathUtils.randomInt(BigInteger.ZERO, upper);
                    poly2[i] = MathUtils.randomInt(BigInteger.ZERO, upper);
                }
                assertThat(BrakerskiVaikuntanathan.polyMultiply(poly1, poly2, d))
                        .containsExactly(negacyclicProduct(poly1, poly2, q));
            }
        }
    }
}
