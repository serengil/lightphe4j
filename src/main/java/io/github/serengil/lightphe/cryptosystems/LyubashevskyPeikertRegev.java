package io.github.serengil.lightphe.cryptosystems;

import io.github.serengil.lightphe.commons.Logger;
import io.github.serengil.lightphe.commons.MathUtils;
import io.github.serengil.lightphe.model.Algorithm;
import io.github.serengil.lightphe.model.KeySpec;
import io.github.serengil.lightphe.model.KeyValue;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.value.CipherValue;
import java.math.BigInteger;
import java.util.List;

/**
 * Lyubashevsky-Peikert-Regev, homomorphic with respect to the addition. Also, it supports
 * multiplying a ciphertext with a plain constant. It is Regev's cryptosystem over a polynomial
 * ring, and it is quantum resistant. Its security relies on the ring learning with errors
 * (Ring-LWE) problem like Brakerski-Vaikuntanathan.
 *
 * <p>It works in the polynomial ring {@code R_q = Z_q[x] / (x^d + 1)}.
 *
 * <ul>
 *   <li>private key: polynomial s with small coefficients
 *   <li>public key: a and {@code b = a s + e}, where e is a small error polynomial
 *   <li>encryption: {@code c1 = a u + e1}, and {@code c2 = constant term of (b u) + e2 + m * q / t}
 *   <li>decryption: {@code c2 - constant term of (c1 s) = m * q / t + noise}, so m is restored by
 *       rounding
 * </ul>
 *
 * <p>a is expanded from a public seed with SHAKE-128, so the public key is the seed and b.
 *
 * <p>Regev uses a random n x n matrix A, whereas this uses the negacyclic matrix of a single
 * polynomial a, so the public structure is n times smaller, and {@code c1 = a u} is a single
 * polynomial multiplication instead of a matrix-vector product. Message is encoded into the
 * constant term only, which is the only coefficient decryption reads, so other coefficients of c2
 * are dropped. Thus, a ciphertext has {@code d + 1} coefficients like Regev, instead of 2d of the
 * original scheme. Dropping parts of a ciphertext does not help an attacker, so the security is the
 * same.
 *
 * <p>Key size is the ring degree d, a power of 2. Default is 2048. With {@code q = 2^50}, degree
 * 2048 gives about 128-bit security against quantum attacks according to the tables of Homomorphic
 * Encryption Standard (log q must be at most 51 for d = 2048). Smaller degrees are not secure, and
 * are for testing only.
 *
 * <p>Notice that its plaintext space is small, {@code 2^24} by default, and every ciphertext has
 * noise. Noise grows with homomorphic operations: addition adds the noise of ciphertexts, and
 * multiplying with a constant k multiplies the noise by {@code |k|}. Decryption returns a wrong
 * result without any error when the noise exceeds {@code q / 2t}. Fresh noise is about {@code 2^13}
 * for d = 2048, and the limit is {@code 2^25} by default, so there is room for thousands of
 * additions or multiplication with constants up to a few thousands. A greater plaintext space can
 * be set with the plaintext limit in exchange of a smaller room for noise. Floats and tensors are
 * not supported, as they are scaled by powers of 10. Ciphertexts have {@code d + 1} entries of 50
 * bits each, about 12.8 KB for d = 2048.
 *
 * <p>Ref: Lyubashevsky, V., Peikert, C., Regev, O. (2010). On Ideal Lattices and Learning with
 * Errors over Rings. EUROCRYPT 2010.
 *
 * <p>Ref: Albrecht, M. et al. (2018). Homomorphic Encryption Security Standard.
 * HomomorphicEncryption.org.
 */
public final class LyubashevskyPeikertRegev extends AbstractHomomorphic {

    /** The key fields Lyubashevsky-Peikert-Regev requires. */
    public static final KeySpec REQUIRED_KEYS =
            KeySpec.of(List.of("d", "q", "t", "seed", "b"), List.of("s"));

    /**
     * Floats are scaled by powers of 10, which exceeds the small plaintext space, and multiplies
     * the noise in ciphertexts by the same factor.
     */
    public static final String FLOAT_NOT_SUPPORTED_MSG =
            "Lyubashevsky-Peikert-Regev does not support float values or tensors, because they"
                    + " are scaled by powers of 10, which exceed its small plaintext space and"
                    + " noise budget. Use integers instead.";

    /** Default plaintext modulus {@code t = 2^DEFAULT_LOG_T}. */
    private static final int DEFAULT_LOG_T = 24;

    /** Fresh noise must stay below this many standard deviations for correct decryption. */
    private static final int NOISE_TAIL = 12;

    private static final Logger logger = Logger.forModule(LyubashevskyPeikertRegev.class);

    /** a expanded from the seed, built when needed. */
    private volatile long[] a;

    /**
     * Builds a Lyubashevsky-Peikert-Regev cryptosystem.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param keySize ring degree, a power of 2; {@code null} defaults to 2048
     * @param plaintextLimit upper bound for plaintext values, rounded up to a power of 2; {@code
     *     null} defaults to {@code 2^24}. Greater values leave less room for noise.
     */
    public LyubashevskyPeikertRegev(Keys keys, Integer keySize, BigInteger plaintextLimit) {
        super(
                Algorithm.LYUBASHEVSKY_PEIKERT_REGEV,
                keys != null
                        ? keys
                        : generateKeys(keySize == null ? 2048 : keySize, plaintextLimit));
        this.plaintextModulo = this.keys.publicNumber("t");
        this.ciphertextModulo = this.keys.publicNumber("q");
    }

    /**
     * Builds a Lyubashevsky-Peikert-Regev cryptosystem around an existing key pair.
     *
     * @param keys the private-public key pair
     */
    public LyubashevskyPeikertRegev(Keys keys) {
        this(keys, null, null);
    }

    /**
     * Generates the public and private keys of the Lyubashevsky-Peikert-Regev cryptosystem.
     *
     * @param keySize ring degree
     * @param plaintextLimit upper bound for plaintext values, or {@code null} for the default
     * @return the generated key pair
     * @throws IllegalArgumentException when the degree is invalid or the limit too large
     */
    public static Keys generateKeys(int keySize, BigInteger plaintextLimit) {
        int d = keySize;
        PowerOfTwoRing.validateDegree(d, "Lyubashevsky-Peikert-Regev");

        BigInteger q = PowerOfTwoRing.Q;
        BigInteger t = BigInteger.ONE.shiftLeft(DEFAULT_LOG_T);
        if (plaintextLimit != null) {
            if (plaintextLimit.compareTo(BigInteger.TWO) < 0) {
                throw new IllegalArgumentException("Plaintext limit must be at least 2");
            }
            t = BigInteger.ONE.shiftLeft(plaintextLimit.subtract(BigInteger.ONE).bitLength());
        }

        // fresh ciphertexts must be decrypted correctly
        BigInteger noiseBound = BigInteger.valueOf(noiseBound(d));
        BigInteger room = q.divide(t).shiftRight(1);
        if (room.compareTo(noiseBound) <= 0) {
            throw new IllegalArgumentException(
                    "Plaintext limit "
                            + plaintextLimit
                            + " is too large for Lyubashevsky-Peikert-Regev. It must be less than "
                            + q.divide(noiseBound.shiftLeft(1))
                            + " for degree "
                            + d
                            + ".");
        }
        logger.debug(
                () ->
                        "noise of fresh ciphertexts can grow "
                                + Math.round(room.doubleValue() / noiseBound.doubleValue())
                                + " times");

        BigInteger seed = MathUtils.getRandomBits(256);
        long[] a = PowerOfTwoRing.expand(seed, d);
        long[] s = Regev.sampleSmall(d);
        long[] e = Regev.sampleSmall(d);

        // b = a s + e
        long[] b = PowerOfTwoRing.multiply(a, s);
        for (int i = 0; i < d; i++) {
            b[i] = (b[i] + e[i]) & PowerOfTwoRing.MASK;
        }

        Keys keys = Keys.empty();
        keys.publicKey().put("d", KeyValue.of(d));
        keys.publicKey().put("q", KeyValue.of(q));
        keys.publicKey().put("t", KeyValue.of(t));
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
     * @throws UnsupportedOperationException always: the random key of Lyubashevsky-Peikert-Regev is
     *     a polynomial, see {@link #generateRandomPolynomial()}
     */
    @Override
    public BigInteger generateRandomKey() {
        throw new UnsupportedOperationException(
                "Lyubashevsky-Peikert-Regev requires a small random polynomial per encryption."
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
     * @return the ciphertext: d coefficients of {@code c1 = a u + e1}, and {@code c2 = constant
     *     term of (b u) + e2 + m q / t}
     */
    public CipherValue encrypt(BigInteger plaintext, long[] randomPolynomial) {
        int d = degree();
        BigInteger t = plaintextModulo;
        long[] b = PowerOfTwoRing.toLongs(keys.publicNumbers("b"));

        BigInteger message = plaintext;
        if (message.compareTo(t) >= 0) {
            message = message.mod(t);
            BigInteger normalized = message;
            logger.debug(
                    () ->
                            "Lyubashevsky-Peikert-Regev can encrypt messages [0, "
                                    + t
                                    + "). Seems plaintext exceeded this limit. New plaintext is "
                                    + normalized);
        }

        long[] e1 = Regev.sampleSmall(d);
        long e2 = Regev.sampleSmall(1)[0];

        long[] c1 = PowerOfTwoRing.multiply(publicA(), randomPolynomial);
        long[] ciphertext = new long[d + 1];
        for (int i = 0; i < d; i++) {
            ciphertext[i] = (c1[i] + e1[i]) & PowerOfTwoRing.MASK;
        }
        long delta = PowerOfTwoRing.Q.divide(t).longValue();
        ciphertext[d] =
                (PowerOfTwoRing.constantTerm(b, randomPolynomial)
                                + e2
                                + message.longValue() * delta)
                        & PowerOfTwoRing.MASK;
        return PowerOfTwoRing.toValue(ciphertext);
    }

    @Override
    public BigInteger decrypt(CipherValue ciphertext) {
        long[] coefficients = PowerOfTwoRing.toCoefficients(ciphertext);
        int d = coefficients.length - 1;
        long[] c1 = new long[d];
        System.arraycopy(coefficients, 0, c1, 0, d);
        long[] s = PowerOfTwoRing.toLongs(keys.privateNumbers("s"));
        long delta = PowerOfTwoRing.Q.divide(plaintextModulo).longValue();

        // m * q / t + noise
        long noisyMessage =
                (coefficients[d] - PowerOfTwoRing.constantTerm(c1, s)) & PowerOfTwoRing.MASK;
        return BigInteger.valueOf((noisyMessage + delta / 2) / delta).mod(plaintextModulo);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Noise of the result is the sum of noises of the ciphertexts.
     */
    @Override
    public CipherValue add(CipherValue ciphertext1, CipherValue ciphertext2) {
        long[] first = PowerOfTwoRing.toCoefficients(ciphertext1);
        long[] second = PowerOfTwoRing.toCoefficients(ciphertext2);
        long[] sum = new long[first.length];
        for (int i = 0; i < sum.length; i++) {
            sum[i] = (first[i] + second[i]) & PowerOfTwoRing.MASK;
        }
        return PowerOfTwoRing.toValue(sum);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Noise of the result is the noise of the ciphertext times {@code |constant|}.
     */
    @Override
    public CipherValue multiplyByConstant(CipherValue ciphertext, BigInteger constant) {
        // centered representative keeps the noise small for negative constants, e.g. t - 1 is
        // multiplied as -1. as t divides q, this does not change the result.
        BigInteger t = plaintextModulo;
        BigInteger scalar = constant.mod(t);
        if (scalar.compareTo(t.shiftRight(1)) > 0) {
            scalar = scalar.subtract(t);
        }
        long k = scalar.longValue();

        long[] coefficients = PowerOfTwoRing.toCoefficients(ciphertext);
        for (int i = 0; i < coefficients.length; i++) {
            coefficients[i] = (coefficients[i] * k) & PowerOfTwoRing.MASK;
        }
        return PowerOfTwoRing.toValue(coefficients);
    }

    @Override
    public CipherValue reencrypt(CipherValue ciphertext) {
        return add(ciphertext, encrypt(BigInteger.ZERO));
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

    /**
     * Bound of the noise {@code constant term of (e u) + e2 - constant term of (e1 s)} in fresh
     * ciphertexts. It sums 2d products of small coefficients like Regev.
     */
    private static long noiseBound(int d) {
        double variance = Regev.ETA / 2.0;
        return (long) Math.ceil(NOISE_TAIL * variance * Math.sqrt(2.0 * d)) + Regev.ETA;
    }
}
