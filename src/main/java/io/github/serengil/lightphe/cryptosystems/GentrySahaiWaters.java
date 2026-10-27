package io.github.serengil.lightphe.cryptosystems;

import io.github.serengil.lightphe.commons.Logger;
import io.github.serengil.lightphe.commons.MathUtils;
import io.github.serengil.lightphe.model.Algorithm;
import io.github.serengil.lightphe.model.KeySpec;
import io.github.serengil.lightphe.model.KeyValue;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.TupleValue;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Gentry-Sahai-Waters encrypts bits, and it is homomorphic with respect to both the exclusive or
 * and the and. Unlike Boneh-Goh-Nissim or Brakerski-Vaikuntanathan, it supports more than one
 * multiplication, so boolean circuits of a small depth can be evaluated on encrypted bits. It is
 * quantum resistant, and its security relies on the ring learning with errors (Ring-LWE) problem.
 *
 * <p>This is the ring variant of GSW. It works in the polynomial ring {@code R_q = Z_q[x] / (x^d +
 * 1)}.
 *
 * <ul>
 *   <li>private key: polynomial s with small coefficients
 *   <li>public key: a and {@code b = -(a s) + e}, where e is a small error polynomial
 *   <li>an encryption of zero is {@code (b u + e1, a u + e2)}, whose phase {@code c0 + c1 s} is
 *       small
 *   <li>encryption of a bit m: {@code 2 * ELL} encryptions of zero Z, and {@code C = Z + m G},
 *       where G is the gadget matrix having powers of B in its first and second columns
 *   <li>decryption: phase of the last row is {@code m q / 2 + noise}, so m is restored by rounding
 *   <li>and: {@code C1 x G^-1(C2)} where {@code G^-1} decomposes entries of C2 into small digits,
 *       so the noise of C2 is multiplied by small digits only
 *   <li>exclusive or: {@code C1 + C2} encrypts {@code m1 + m2}, whose parity is restored by
 *       decryption
 * </ul>
 *
 * <p>a is expanded from a public seed with SHAKE-128, so the public key is the seed and b.
 *
 * <p>Key size is the ring degree d, a power of 2. Default is 2048. With {@code q = 2^50}, degree
 * 2048 gives about 128-bit security against quantum attacks according to the tables of Homomorphic
 * Encryption Standard (log q must be at most 51 for d = 2048). Smaller degrees are not secure, and
 * are for testing only.
 *
 * <p>Every ciphertext has noise. Exclusive or adds the noises of ciphertexts, so it is almost free.
 * Noise of {@code C1 & C2} is the noise of C2 times small digits plus the noise of C1, so it
 * depends on the order of operands:
 *
 * <ul>
 *   <li>chains: {@code acc = acc & c} where c is a fresh ciphertext adds a fixed noise of about
 *       {@code 2^17} each time, so long chains of ands, e.g. carries of a ripple carry adder, work.
 *   <li>products of products: noise is multiplied by about {@code 2^15} in each level, so circuits
 *       of multiplicative depth 2 work, e.g. {@code (a & b) & (c & d)}, but depth 3 does not.
 *       Decryption returns a wrong result without any error when the noise exceeds {@code q / 4 =
 *       2^48}. Fresh noise is about {@code 2^10}.
 * </ul>
 *
 * <p>Ciphertexts have {@code 2 * ELL x 2} polynomials of d coefficients of 50 bits, about 256 KB
 * for d = 2048. Floats, tensors and integers other than bits are not supported.
 *
 * <p>Ref: Gentry, C., Sahai, A., Waters, B. (2013). Homomorphic Encryption from Learning with
 * Errors: Conceptually-Simpler, Asymptotically-Faster, Attribute-Based. CRYPTO 2013.
 *
 * <p>Ref: Ducas, L., Micciancio, D. (2015). FHEW: Bootstrapping Homomorphic Encryption in less than
 * a second. EUROCRYPT 2015.
 *
 * <p>Ref: Albrecht, M. et al. (2018). Homomorphic Encryption Security Standard.
 * HomomorphicEncryption.org.
 */
public final class GentrySahaiWaters extends AbstractHomomorphic {

    /** The key fields Gentry-Sahai-Waters requires. */
    public static final KeySpec REQUIRED_KEYS =
            KeySpec.of(List.of("d", "q", "seed", "b"), List.of("s"));

    /** Floats, tensors and integers other than bits cannot be encrypted. */
    public static final String FLOAT_NOT_SUPPORTED_MSG =
            "Gentry-Sahai-Waters encrypts bits, i.e. 0 or 1, and it does not support float values,"
                    + " tensors or other integers. Encrypt integers bit by bit instead.";

    /** Gadget decomposition is in base {@code B = 2^LOG_B}. */
    public static final int LOG_B = 10;

    /** Number of digits of the gadget decomposition. */
    public static final int ELL = 5;

    /**
     * Gadget is approximate: its entries are {@code 2^OFFSET, 2^OFFSET * B, ..., 2^OFFSET * B^(ELL
     * - 1) = q / 2}, so the lowest OFFSET bits are dropped by rounding, and decryption reads the
     * parity of the message.
     */
    public static final int OFFSET = PowerOfTwoRing.LOG_Q - 1 - LOG_B * (ELL - 1);

    private static final long QUARTER_Q = 1L << (PowerOfTwoRing.LOG_Q - 2);

    private static final Logger logger = Logger.forModule(GentrySahaiWaters.class);

    /** a expanded from the seed, built when needed. */
    private volatile long[] a;

    /**
     * Builds a Gentry-Sahai-Waters cryptosystem.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param keySize ring degree, a power of 2; {@code null} defaults to 2048
     */
    public GentrySahaiWaters(Keys keys, Integer keySize) {
        super(
                Algorithm.GENTRY_SAHAI_WATERS,
                keys != null ? keys : generateKeys(keySize == null ? 2048 : keySize));
        this.plaintextModulo = BigInteger.TWO;
        this.ciphertextModulo = this.keys.publicNumber("q");
    }

    /**
     * Builds a Gentry-Sahai-Waters cryptosystem around an existing key pair.
     *
     * @param keys the private-public key pair
     */
    public GentrySahaiWaters(Keys keys) {
        this(keys, null);
    }

    /**
     * Generates the public and private keys of the Gentry-Sahai-Waters cryptosystem.
     *
     * @param keySize ring degree
     * @return the generated key pair
     * @throws IllegalArgumentException when the degree is invalid
     */
    public static Keys generateKeys(int keySize) {
        int d = keySize;
        PowerOfTwoRing.validateDegree(d, "Gentry-Sahai-Waters");

        BigInteger seed = MathUtils.getRandomBits(256);
        long[] a = PowerOfTwoRing.expand(seed, d);
        long[] s = Regev.sampleSmall(d);
        long[] e = Regev.sampleSmall(d);

        // b = -(a s) + e
        long[] b = PowerOfTwoRing.multiply(a, s);
        for (int i = 0; i < d; i++) {
            b[i] = (e[i] - b[i]) & PowerOfTwoRing.MASK;
        }

        Keys keys = Keys.empty();
        keys.publicKey().put("d", KeyValue.of(d));
        keys.publicKey().put("q", KeyValue.of(PowerOfTwoRing.Q));
        keys.publicKey().put("seed", KeyValue.of(seed));
        keys.publicKey().put("b", KeyValue.numbers(PowerOfTwoRing.toBigIntegers(b)));
        keys.privateKey().put("s", KeyValue.numbers(PowerOfTwoRing.toBigIntegers(s)));
        return keys;
    }

    @Override
    public KeySpec requiredKeys() {
        return REQUIRED_KEYS;
    }

    /**
     * {@inheritDoc}
     *
     * @throws UnsupportedOperationException always: the random key of Gentry-Sahai-Waters is a list
     *     of polynomials, see {@link #generateRandomPolynomials()}
     */
    @Override
    public BigInteger generateRandomKey() {
        throw new UnsupportedOperationException(
                "Gentry-Sahai-Waters requires a small random polynomial for each row."
                        + " Use generateRandomPolynomials.");
    }

    /**
     * Generates the one-time small random polynomial u of each row, required per encryption.
     *
     * @return {@code 2 * ELL} small random polynomials
     */
    public long[][] generateRandomPolynomials() {
        int d = degree();
        long[][] us = new long[2 * ELL][];
        for (int i = 0; i < us.length; i++) {
            us[i] = Regev.sampleSmall(d);
        }
        return us;
    }

    @Override
    public CipherValue encrypt(BigInteger plaintext) {
        return encrypt(plaintext, generateRandomPolynomials());
    }

    /**
     * Encrypts a bit with explicit random polynomials.
     *
     * @param plaintext the bit to encrypt, 0 or 1
     * @param randomPolynomials {@code 2 * ELL} small random polynomials u
     * @return the ciphertext: {@code 2 * ELL} rows of polynomial pairs {@code Z + m G}
     */
    public CipherValue encrypt(BigInteger plaintext, long[][] randomPolynomials) {
        int d = degree();
        long[] b = PowerOfTwoRing.toLongs(keys.publicNumbers("b"));

        BigInteger bit = plaintext;
        if (bit.signum() < 0 || bit.compareTo(BigInteger.ONE) > 0) {
            bit = bit.mod(BigInteger.TWO);
            BigInteger normalized = bit;
            logger.debug(
                    () ->
                            "Gentry-Sahai-Waters can encrypt bits only. "
                                    + "Seems plaintext exceeded this limit. New plaintext is "
                                    + normalized);
        }
        long m = bit.longValue();

        long[] publicA = publicA();
        List<CipherValue> rows = new ArrayList<>(2 * ELL);
        for (int i = 0; i < randomPolynomials.length; i++) {
            long[] u = randomPolynomials[i];
            long[] e1 = Regev.sampleSmall(d);
            long[] e2 = Regev.sampleSmall(d);
            long[] c0 = PowerOfTwoRing.multiply(b, u);
            long[] c1 = PowerOfTwoRing.multiply(publicA, u);
            for (int x = 0; x < d; x++) {
                c0[x] = (c0[x] + e1[x]) & PowerOfTwoRing.MASK;
                c1[x] = (c1[x] + e2[x]) & PowerOfTwoRing.MASK;
            }

            // first ELL rows carry m g_i in c0, and last ELL rows carry it in c1
            if (i < ELL) {
                c0[0] = (c0[0] + m * gadget(i)) & PowerOfTwoRing.MASK;
            } else {
                c1[0] = (c1[0] + m * gadget(i - ELL)) & PowerOfTwoRing.MASK;
            }
            rows.add(TupleValue.of(PowerOfTwoRing.toValue(c0), PowerOfTwoRing.toValue(c1)));
        }
        return TupleValue.of(rows);
    }

    @Override
    public BigInteger decrypt(CipherValue ciphertext) {
        long[] s = PowerOfTwoRing.toLongs(keys.privateNumbers("s"));

        // phase of the last row of the first half is m q / 2 + noise
        long[][] row = toRows(ciphertext)[ELL - 1];
        long phase = (row[0][0] + PowerOfTwoRing.constantTerm(row[1], s)) & PowerOfTwoRing.MASK;
        return phase >= QUARTER_Q && phase < PowerOfTwoRing.MASK + 1 - QUARTER_Q
                ? BigInteger.ONE
                : BigInteger.ZERO;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Noise of the result is the noise of ciphertext2 times small digits plus the noise of
     * ciphertext1, so keep ciphertext2 fresh in long chains, e.g. {@code acc = acc & fresh}.
     */
    @Override
    public CipherValue homomorphicAnd(CipherValue ciphertext1, CipherValue ciphertext2) {
        return product(ciphertext1, ciphertext2);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Multiplication of bits is the and of them.
     */
    @Override
    public CipherValue multiply(CipherValue ciphertext1, CipherValue ciphertext2) {
        return product(ciphertext1, ciphertext2);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Sum of ciphertexts encrypts {@code m1 + m2}, and decryption restores its parity. Noise of
     * the result is the sum of noises of the ciphertexts.
     */
    @Override
    public CipherValue xor(CipherValue ciphertext1, CipherValue ciphertext2) {
        long[][][] first = toRows(ciphertext1);
        long[][][] second = toRows(ciphertext2);
        long[][][] sum = new long[first.length][2][];
        for (int i = 0; i < first.length; i++) {
            for (int column = 0; column < 2; column++) {
                long[] poly1 = first[i][column];
                long[] poly2 = second[i][column];
                long[] total = new long[poly1.length];
                for (int x = 0; x < total.length; x++) {
                    total[x] = (poly1[x] + poly2[x]) & PowerOfTwoRing.MASK;
                }
                sum[i][column] = total;
            }
        }
        return toValue(sum);
    }

    @Override
    public CipherValue reencrypt(CipherValue ciphertext) {
        return xor(ciphertext, encrypt(BigInteger.ZERO));
    }

    /**
     * Computes {@code G^-1(C1) x C2}, i.e. each row of C1 is decomposed into {@code 2 * ELL} small
     * digit polynomials, and the row of the result is their weighted sum of rows of C2. Its phase
     * is {@code G^-1(C1) x noise of C2 + m2 * phase of C1}, so it encrypts {@code m1 m2}.
     */
    private CipherValue product(CipherValue ciphertext1, CipherValue ciphertext2) {
        long[][][] first = toRows(ciphertext1);
        long[][][] second = toRows(ciphertext2);
        int d = first[0][0].length;

        long[][][] result = new long[first.length][2][];
        for (int i = 0; i < first.length; i++) {
            long[][] digits = new long[2 * ELL][];
            System.arraycopy(decompose(first[i][0]), 0, digits, 0, ELL);
            System.arraycopy(decompose(first[i][1]), 0, digits, ELL, ELL);
            for (int column = 0; column < 2; column++) {
                long[] accumulator = new long[d];
                for (int k = 0; k < digits.length; k++) {
                    long[] term = PowerOfTwoRing.multiply(digits[k], second[k][column]);
                    for (int x = 0; x < d; x++) {
                        accumulator[x] += term[x];
                    }
                }
                for (int x = 0; x < d; x++) {
                    accumulator[x] &= PowerOfTwoRing.MASK;
                }
                result[i][column] = accumulator;
            }
        }
        return toValue(result);
    }

    /**
     * Entry of the approximate gadget, {@code 2^OFFSET * B^index}.
     *
     * @param index index of the entry in {@code [0, ELL)}
     * @return the entry
     */
    static long gadget(int index) {
        return 1L << (OFFSET + LOG_B * index);
    }

    /**
     * Decomposes a polynomial into ELL polynomials of signed digits in {@code [-B / 2, B / 2)}, so
     * that the sum of {@code digits_i * gadget_i} is the polynomial up to a rounding error less
     * than {@code 2^OFFSET} in each coefficient.
     *
     * @param poly d coefficients in {@code [0, q)}
     * @return ELL polynomials of digits
     */
    static long[][] decompose(long[] poly) {
        long half = 1L << (PowerOfTwoRing.LOG_Q - 1);
        long base = 1L << LOG_B;
        long halfB = base >> 1;
        long[][] digits = new long[ELL][poly.length];
        for (int i = 0; i < poly.length; i++) {
            // centered representative, rounded to a multiple of 2^OFFSET
            long x = poly[i] >= half ? poly[i] - (PowerOfTwoRing.MASK + 1) : poly[i];
            x = (x + (1L << (OFFSET - 1))) >> OFFSET;
            for (int j = 0; j < ELL; j++) {
                long digit = Math.floorMod(x, base);
                if (digit >= halfB) {
                    digit -= base;
                }
                digits[j][i] = digit;
                x = (x - digit) >> LOG_B;
            }
        }
        return digits;
    }

    /**
     * Returns the public polynomial a expanded from the seed.
     *
     * @return d coefficients in {@code [0, q)}
     */
    long[] publicA() {
        long[] expanded = a;
        if (expanded == null) {
            expanded = PowerOfTwoRing.expand(keys.publicNumber("seed"), degree());
            a = expanded;
        }
        return expanded;
    }

    private int degree() {
        return keys.publicNumber("d").intValueExact();
    }

    private static long[][][] toRows(CipherValue value) {
        List<TupleValue> rows = asTuple(value).asTuples();
        long[][][] out = new long[rows.size()][][];
        for (int i = 0; i < rows.size(); i++) {
            List<TupleValue> columns = rows.get(i).asTuples();
            out[i] = new long[columns.size()][];
            for (int column = 0; column < columns.size(); column++) {
                out[i][column] = PowerOfTwoRing.toLongs(columns.get(column).asIntegers());
            }
        }
        return out;
    }

    private static CipherValue toValue(long[][][] rows) {
        List<CipherValue> items = new ArrayList<>(rows.length);
        for (long[][] row : rows) {
            items.add(
                    TupleValue.of(PowerOfTwoRing.toValue(row[0]), PowerOfTwoRing.toValue(row[1])));
        }
        return TupleValue.of(items);
    }
}
