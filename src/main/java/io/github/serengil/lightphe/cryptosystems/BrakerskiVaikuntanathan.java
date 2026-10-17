package io.github.serengil.lightphe.cryptosystems;

import io.github.serengil.lightphe.commons.Logger;
import io.github.serengil.lightphe.commons.MathUtils;
import io.github.serengil.lightphe.commons.Shake128;
import io.github.serengil.lightphe.model.Algorithm;
import io.github.serengil.lightphe.model.KeySpec;
import io.github.serengil.lightphe.model.KeyValue;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.TupleValue;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Brakerski-Vaikuntanathan, homomorphic with respect to the addition, and supports one
 * multiplication of ciphertexts like Boneh-Goh-Nissim. Unlike Boneh-Goh-Nissim, it does not need
 * pairings, and it is quantum resistant. Its security relies on the ring learning with errors
 * (Ring-LWE) problem, which is believed to be hard for quantum computers.
 *
 * <p>It works in the polynomial ring {@code R_q = Z_q[x] / (x^d + 1)}.
 *
 * <ul>
 *   <li>private key: polynomial s with small coefficients
 *   <li>public key: a and {@code b = -(a s + t e)}, where e is a small error polynomial
 *   <li>encryption: {@code c0 = b u + t g + m}, {@code c1 = a u + t f} where u, f, g are small
 *   <li>decryption: {@code c0 + c1 s = m + t (g + f s - e u) mod q}, so m is its constant term mod
 *       t
 *   <li>multiplication: {@code (c0, c1) x (c0', c1') = (c0 c0', c0 c1' + c1 c0', c1 c1')}, which is
 *       decrypted with {@code (1, s, s^2)} as {@code (c0 + c1 s)(c0' + c1' s) = m m' + t (...)}
 * </ul>
 *
 * <p>Multiplied ciphertexts are triples of polynomials. They can be added with each other and with
 * fresh ciphertexts, and multiplied with constants, but cannot be multiplied with ciphertexts
 * again. a is expanded from a public seed with SHAKE-128.
 *
 * <p>Key size is the ring degree d, a power of 2. Default is 4096. With q around {@code 2^100},
 * degree 4096 gives about 128-bit security against quantum attacks according to the tables of
 * Homomorphic Encryption Standard (log q must be at most 101 for d = 4096). Smaller degrees are not
 * secure, and are for testing only.
 *
 * <p>Notice that its plaintext space is small, {@code 2^24} by default, and every ciphertext has
 * noise growing with homomorphic operations: addition adds the noises, multiplying with a constant
 * k multiplies the noise by {@code |k|}, and multiplication of ciphertexts multiplies their noises.
 * Decryption returns a wrong result without any error when the noise exceeds {@code q / 2}. With
 * default settings, a multiplied ciphertext still has room for millions of times more noise, i.e.
 * for many additions and multiplications with constants. A greater plaintext space can be set with
 * the plaintext limit in exchange of a smaller room. Floats and tensors are not supported, as they
 * are scaled by powers of 10. Ciphertexts have 2 polynomials of d coefficients of 100 bits, about
 * 100 KB for d = 4096.
 *
 * <p>Ref: Brakerski, Z., Vaikuntanathan, V. (2011). Fully Homomorphic Encryption from Ring-LWE and
 * Security for Key Dependent Messages. CRYPTO 2011.
 *
 * <p>Ref: Albrecht, M. et al. (2018). Homomorphic Encryption Security Standard.
 * HomomorphicEncryption.org.
 */
public final class BrakerskiVaikuntanathan extends AbstractHomomorphic {

    /** The key fields Brakerski-Vaikuntanathan requires. */
    public static final KeySpec REQUIRED_KEYS =
            KeySpec.of(List.of("d", "q", "t", "seed", "b"), List.of("s"));

    /**
     * Floats are scaled by powers of 10, which exceeds the small plaintext space, and multiplies
     * the noise in ciphertexts by the same factor.
     */
    public static final String FLOAT_NOT_SUPPORTED_MSG =
            "Brakerski-Vaikuntanathan does not support float values or tensors, because they are"
                    + " scaled by powers of 10, which exceed its small plaintext space and noise"
                    + " budget. Use integers instead.";

    /** Bit length of the ciphertext modulus. */
    private static final int LOG_Q = 100;

    /**
     * Ciphertext modulus q is the greatest prime less than {@code 2^LOG_Q}. It must be co-prime to
     * t, otherwise public key reveals the secret modulo t.
     */
    private static final BigInteger Q = new BigInteger("1267650600228229401496703205361");

    /** Default plaintext modulus {@code t = 2^DEFAULT_LOG_T}. */
    private static final int DEFAULT_LOG_T = 24;

    /** Noise must stay below this many standard deviations for correct decryption. */
    private static final int NOISE_TAIL = 12;

    /** A ciphertext is a pair of polynomials. */
    private static final int FRESH_SIZE = 2;

    /** A multiplied ciphertext is a triple of polynomials. */
    private static final int MULTIPLIED_SIZE = 3;

    private static final Logger logger = Logger.forModule(BrakerskiVaikuntanathan.class);

    /** a expanded from the seed, built when needed. */
    private volatile BigInteger[] a;

    /** {@code s^2}, built when a multiplied ciphertext is decrypted. */
    private volatile BigInteger[] sSquare;

    /**
     * Builds a Brakerski-Vaikuntanathan cryptosystem.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param keySize ring degree, a power of 2; {@code null} defaults to 4096
     * @param plaintextLimit upper bound for plaintext values, rounded up to a power of 2; {@code
     *     null} defaults to {@code 2^24}. Greater values leave less room for noise.
     */
    public BrakerskiVaikuntanathan(Keys keys, Integer keySize, BigInteger plaintextLimit) {
        super(
                Algorithm.BRAKERSKI_VAIKUNTANATHAN,
                keys != null
                        ? keys
                        : generateKeys(keySize == null ? 4096 : keySize, plaintextLimit));
        this.plaintextModulo = this.keys.publicNumber("t");
        this.ciphertextModulo = this.keys.publicNumber("q");
    }

    /**
     * Builds a Brakerski-Vaikuntanathan cryptosystem around an existing key pair.
     *
     * @param keys the private-public key pair
     */
    public BrakerskiVaikuntanathan(Keys keys) {
        this(keys, null, null);
    }

    /**
     * Generates the public and private keys of the Brakerski-Vaikuntanathan cryptosystem.
     *
     * @param keySize ring degree
     * @param plaintextLimit upper bound for plaintext values, or {@code null} for the default
     * @return the generated key pair
     * @throws IllegalArgumentException when the degree is invalid or the limit too large
     */
    public static Keys generateKeys(int keySize, BigInteger plaintextLimit) {
        int d = keySize;
        if (d < 8 || (d & (d - 1)) != 0) {
            throw new IllegalArgumentException(
                    "Key size "
                            + d
                            + " must be a power of 2 and at least 8 for Brakerski-Vaikuntanathan");
        }

        BigInteger t = BigInteger.ONE.shiftLeft(DEFAULT_LOG_T);
        if (plaintextLimit != null) {
            if (plaintextLimit.compareTo(BigInteger.TWO) < 0) {
                throw new IllegalArgumentException("Plaintext limit must be at least 2");
            }
            t = BigInteger.ONE.shiftLeft(plaintextLimit.subtract(BigInteger.ONE).bitLength());
        }

        // product of two fresh ciphertexts must be decrypted correctly
        double multipliedNoise = multipliedNoiseBound(d, t);
        double halfQ = Q.shiftRight(1).doubleValue();
        if (multipliedNoise >= halfQ) {
            throw new IllegalArgumentException(
                    "Plaintext limit "
                            + plaintextLimit
                            + " is too large for Brakerski-Vaikuntanathan,"
                            + " because product of two ciphertexts cannot be decrypted correctly.");
        }
        logger.debug(
                () ->
                        "noise of multiplied ciphertexts can grow "
                                + Math.round(halfQ / multipliedNoise)
                                + " times");

        BigInteger seed = MathUtils.getRandomBits(256);
        BigInteger[] a = expand(seed, d);
        long[] s = Regev.sampleSmall(d);
        long[] e = Regev.sampleSmall(d);

        // b = -(a s + t e)
        BigInteger[] as = polyMultiply(a, reduce(s), d);
        List<BigInteger> b = new ArrayList<>(d);
        for (int i = 0; i < d; i++) {
            b.add(as[i].add(t.multiply(BigInteger.valueOf(e[i]))).negate().mod(Q));
        }

        Keys keys = Keys.empty();
        keys.publicKey().put("d", KeyValue.of(d));
        keys.publicKey().put("q", KeyValue.of(Q));
        keys.publicKey().put("t", KeyValue.of(t));
        keys.publicKey().put("seed", KeyValue.of(seed));
        keys.publicKey().put("b", KeyValue.numbers(b));

        List<BigInteger> secret = new ArrayList<>(d);
        for (long value : s) {
            secret.add(BigInteger.valueOf(value));
        }
        keys.privateKey().put("s", KeyValue.numbers(secret));
        return keys;
    }

    @Override
    public KeySpec requiredKeys() {
        return REQUIRED_KEYS;
    }

    /**
     * {@inheritDoc}
     *
     * @throws UnsupportedOperationException always: the random key of Brakerski-Vaikuntanathan is a
     *     polynomial, see {@link #generateRandomPolynomial()}
     */
    @Override
    public BigInteger generateRandomKey() {
        throw new UnsupportedOperationException(
                "Brakerski-Vaikuntanathan requires a small random polynomial per encryption."
                        + " Use generateRandomPolynomial.");
    }

    /**
     * Generates the coefficients of the one-time small random polynomial u required per encryption.
     *
     * @return the coefficients
     */
    public long[] generateRandomPolynomial() {
        return Regev.sampleSmall(degree());
    }

    @Override
    public CipherValue encrypt(BigInteger plaintext) {
        return encrypt(plaintext, generateRandomPolynomial());
    }

    /**
     * Encrypts a plaintext with an explicit random polynomial.
     *
     * @param plaintext the message to encrypt in {@code [0, t)}
     * @param randomPolynomial coefficients of the small random polynomial u
     * @return the ciphertext, the pair of polynomials {@code c0 = b u + t g + m} and {@code c1 = a
     *     u + t f}
     */
    public CipherValue encrypt(BigInteger plaintext, long[] randomPolynomial) {
        int d = degree();
        BigInteger t = plaintextModulo;
        BigInteger[] b = keys.publicNumbers("b").toArray(new BigInteger[0]);

        BigInteger message = plaintext;
        if (message.compareTo(t) >= 0) {
            message = message.mod(t);
            BigInteger normalized = message;
            logger.debug(
                    () ->
                            "Brakerski-Vaikuntanathan can encrypt messages [0, "
                                    + t
                                    + "). Seems plaintext exceeded this limit. New plaintext is "
                                    + normalized);
        }

        BigInteger[] u = reduce(randomPolynomial);
        long[] f = Regev.sampleSmall(d);
        long[] g = Regev.sampleSmall(d);

        BigInteger[] c0 = polyMultiply(b, u, d);
        BigInteger[] c1 = polyMultiply(publicA(), u, d);
        for (int i = 0; i < d; i++) {
            c0[i] = c0[i].add(t.multiply(BigInteger.valueOf(g[i]))).mod(Q);
            c1[i] = c1[i].add(t.multiply(BigInteger.valueOf(f[i]))).mod(Q);
        }
        c0[0] = c0[0].add(message).mod(Q);
        return toValue(c0, c1);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Accepts a pair of polynomials, or a triple for a multiplied ciphertext.
     */
    @Override
    public BigInteger decrypt(CipherValue ciphertext) {
        BigInteger[][] polynomials = toPolynomials(ciphertext);
        if (polynomials.length != FRESH_SIZE && polynomials.length != MULTIPLIED_SIZE) {
            throw new IllegalArgumentException(
                    "Ciphertext must be a pair or triple of polynomials");
        }
        BigInteger[] s = keys.privateNumbers("s").toArray(new BigInteger[0]);

        // only the constant term carries the message: c0 + c1 s (+ c2 s^2)
        BigInteger result = polynomials[0][0].add(constantTerm(polynomials[1], s));
        if (polynomials.length == MULTIPLIED_SIZE) {
            result = result.add(constantTerm(polynomials[2], secretSquare(s)));
        }

        // centered representative is m + t * noise
        result = result.mod(Q);
        if (result.compareTo(Q.shiftRight(1)) > 0) {
            result = result.subtract(Q);
        }
        return result.mod(plaintextModulo);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Fresh and multiplied ciphertexts can be added.
     */
    @Override
    public CipherValue add(CipherValue ciphertext1, CipherValue ciphertext2) {
        int d = degree();
        BigInteger[][] first = toPolynomials(ciphertext1);
        BigInteger[][] second = toPolynomials(ciphertext2);
        int size = Math.max(first.length, second.length);
        BigInteger[][] sum = new BigInteger[size][];
        for (int k = 0; k < size; k++) {
            sum[k] = new BigInteger[d];
            for (int i = 0; i < d; i++) {
                BigInteger x = k < first.length ? first[k][i] : BigInteger.ZERO;
                BigInteger y = k < second.length ? second[k][i] : BigInteger.ZERO;
                sum[k][i] = x.add(y).mod(Q);
            }
        }
        return toValue(sum);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Only fresh ciphertexts (or sums of them) can be multiplied, and the result is a triple of
     * polynomials.
     */
    @Override
    public CipherValue multiply(CipherValue ciphertext1, CipherValue ciphertext2) {
        BigInteger[][] first = toPolynomials(ciphertext1);
        BigInteger[][] second = toPolynomials(ciphertext2);
        if (first.length != FRESH_SIZE || second.length != FRESH_SIZE) {
            throw new IllegalArgumentException(
                    "Brakerski-Vaikuntanathan supports only one multiplication. "
                            + "Multiplied ciphertexts cannot be multiplied with"
                            + " ciphertexts again.");
        }
        int d = degree();

        // Karatsuba: c0 c1' + c1 c0' = (c0 + c1)(c0' + c1') - c0 c0' - c1 c1'
        BigInteger[] low = polyMultiply(first[0], second[0], d);
        BigInteger[] high = polyMultiply(first[1], second[1], d);
        BigInteger[] cross =
                polyMultiply(addMod(first[0], first[1]), addMod(second[0], second[1]), d);
        BigInteger[] middle = new BigInteger[d];
        for (int i = 0; i < d; i++) {
            middle[i] = cross[i].subtract(low[i]).subtract(high[i]).mod(Q);
        }
        return toValue(low, middle, high);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Noise of the result is the noise of the ciphertext times {@code |constant|}.
     */
    @Override
    public CipherValue multiplyByConstant(CipherValue ciphertext, BigInteger constant) {
        // centered representative keeps the noise small for negative constants.
        // it is congruent to the constant mod t, so the result does not change.
        BigInteger t = plaintextModulo;
        BigInteger scalar = constant.mod(t);
        if (scalar.compareTo(t.shiftRight(1)) > 0) {
            scalar = scalar.subtract(t);
        }

        BigInteger[][] polynomials = toPolynomials(ciphertext);
        for (BigInteger[] polynomial : polynomials) {
            for (int i = 0; i < polynomial.length; i++) {
                polynomial[i] = polynomial[i].multiply(scalar).mod(Q);
            }
        }
        return toValue(polynomials);
    }

    @Override
    public CipherValue reencrypt(CipherValue ciphertext) {
        return add(ciphertext, encrypt(BigInteger.ZERO));
    }

    private int degree() {
        return keys.publicNumber("d").intValueExact();
    }

    private BigInteger[] publicA() {
        BigInteger[] expanded = a;
        if (expanded == null) {
            expanded = expand(keys.publicNumber("seed"), degree());
            a = expanded;
        }
        return expanded;
    }

    private BigInteger[] secretSquare(BigInteger[] s) {
        BigInteger[] square = sSquare;
        if (square == null) {
            BigInteger[] sModQ = new BigInteger[s.length];
            for (int i = 0; i < s.length; i++) {
                sModQ[i] = s[i].mod(Q);
            }
            square = polyMultiply(sModQ, sModQ, degree());
            sSquare = square;
        }
        return square;
    }

    private static BigInteger[] addMod(BigInteger[] poly1, BigInteger[] poly2) {
        BigInteger[] sum = new BigInteger[poly1.length];
        for (int i = 0; i < poly1.length; i++) {
            sum[i] = poly1[i].add(poly2[i]).mod(Q);
        }
        return sum;
    }

    private static BigInteger[] reduce(long[] small) {
        BigInteger[] reduced = new BigInteger[small.length];
        for (int i = 0; i < small.length; i++) {
            reduced[i] = BigInteger.valueOf(small[i]).mod(Q);
        }
        return reduced;
    }

    /**
     * Multiplies two polynomials in {@code Z_q[x] / (x^d + 1)} with Kronecker substitution.
     * Coefficients are packed into big integers, so that a single big integer multiplication
     * computes all coefficients of the product.
     *
     * @param poly1 d coefficients in {@code [0, q)}
     * @param poly2 d coefficients in {@code [0, q)}
     * @param d ring degree
     * @return d coefficients in {@code [0, q)}
     */
    static BigInteger[] polyMultiply(BigInteger[] poly1, BigInteger[] poly2, int d) {
        // each coefficient of the product is a sum of d products less than q^2
        int width = (2 * LOG_Q + Integer.toBinaryString(d).length() + 7) / 8;
        BigInteger product = pack(poly1, width).multiply(pack(poly2, width));

        // unpack 2d little endian slots from the big endian bytes of the product
        byte[] raw = product.toByteArray();
        int length = 2 * d * width;
        byte[] littleEndian = new byte[length];
        for (int k = 0; k < Math.min(raw.length, length); k++) {
            littleEndian[k] = raw[raw.length - 1 - k];
        }

        BigInteger[] coefficients = new BigInteger[2 * d];
        byte[] slot = new byte[width];
        for (int i = 0; i < 2 * d; i++) {
            for (int k = 0; k < width; k++) {
                slot[width - 1 - k] = littleEndian[i * width + k];
            }
            coefficients[i] = new BigInteger(1, slot);
        }

        // x^d = -1
        BigInteger[] reduced = new BigInteger[d];
        for (int i = 0; i < d; i++) {
            reduced[i] = coefficients[i].subtract(coefficients[i + d]).mod(Q);
        }
        return reduced;
    }

    /** Packs coefficients into one integer, coefficient i taking the i-th slot of width bytes. */
    private static BigInteger pack(BigInteger[] coefficients, int width) {
        int length = coefficients.length * width;
        byte[] bigEndian = new byte[length];
        for (int i = 0; i < coefficients.length; i++) {
            byte[] raw = coefficients[i].toByteArray();
            int end = length - i * width;
            for (int k = 0; k < Math.min(raw.length, width); k++) {
                bigEndian[end - 1 - k] = raw[raw.length - 1 - k];
            }
        }
        return new BigInteger(1, bigEndian);
    }

    /**
     * Constant term of the product of two polynomials in {@code Z[x] / (x^d + 1)}, i.e. {@code p1_0
     * p2_0 - sum of p1_i p2_(d-i)} for i in {@code [1, d)}.
     */
    private static BigInteger constantTerm(BigInteger[] poly1, BigInteger[] poly2) {
        int d = poly1.length;
        BigInteger result = poly1[0].multiply(poly2[0]);
        for (int i = 1; i < d; i++) {
            result = result.subtract(poly1[i].multiply(poly2[d - i]));
        }
        return result;
    }

    /**
     * Expands the public polynomial a from its seed with SHAKE-128. Each coefficient is reduced
     * from 64 more bits than q, so it is statistically uniform in {@code [0, q)}.
     */
    static BigInteger[] expand(BigInteger seed, int d) {
        int width = (LOG_Q + 64 + 7) / 8;
        byte[] stream = Shake128.digest(Regev.toBytes(seed, 32), d * width);
        BigInteger[] coefficients = new BigInteger[d];
        byte[] slot = new byte[width];
        for (int i = 0; i < d; i++) {
            for (int k = 0; k < width; k++) {
                slot[width - 1 - k] = stream[i * width + k];
            }
            coefficients[i] = new BigInteger(1, slot).mod(Q);
        }
        return coefficients;
    }

    /**
     * Bound of the noise in the product of two fresh ciphertexts. A fresh ciphertext decrypts to
     * {@code m + t v} where {@code v = g + f s - e u}, whose coefficients have standard deviation
     * about {@code sigma^2 sqrt(2d)}. The product multiplies two such polynomials, whose constant
     * term sums d products of coefficients.
     */
    private static double multipliedNoiseBound(int d, BigInteger t) {
        double variance = Regev.ETA / 2.0;
        double freshDeviation = t.doubleValue() * (variance * Math.sqrt(2.0 * d) + 1);
        return Math.ceil(NOISE_TAIL * Math.sqrt(d) * freshDeviation * freshDeviation);
    }

    private static CipherValue toValue(BigInteger[]... polynomials) {
        List<CipherValue> items = new ArrayList<>(polynomials.length);
        for (BigInteger[] polynomial : polynomials) {
            items.add(TupleValue.ofIntegers(Arrays.asList(polynomial)));
        }
        return TupleValue.of(items);
    }

    private static BigInteger[][] toPolynomials(CipherValue value) {
        List<TupleValue> tuples = asTuple(value).asTuples();
        BigInteger[][] polynomials = new BigInteger[tuples.size()][];
        for (int k = 0; k < tuples.size(); k++) {
            polynomials[k] = tuples.get(k).asIntegers().toArray(new BigInteger[0]);
        }
        return polynomials;
    }
}
