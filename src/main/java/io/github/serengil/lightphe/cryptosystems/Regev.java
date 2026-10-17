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
import java.util.List;

/**
 * Regev, homomorphic with respect to the addition. It also supports multiplying a ciphertext with a
 * plain constant.
 *
 * <p>It is the first quantum resistant algorithm in LightPHE. Its security relies on the learning
 * with errors (LWE) problem, which is believed to be hard for quantum computers, unlike factoring
 * and discrete logarithm problems that other algorithms rely on.
 *
 * <p>This is the Lindner-Peikert form of Regev's cryptosystem, which is the one used in practice,
 * e.g. by FrodoKEM. Original form requires a public key matrix with about {@code n log q} rows,
 * whereas this needs an {@code n x n} matrix A.
 *
 * <ul>
 *   <li>private key: secret vector s with small entries
 *   <li>public key: A and {@code b = A s + e mod q}, where e is a small error vector
 *   <li>encryption: {@code c1 = A^T r + e1} and {@code c2 = dot(b, r) + e2 + m * q / t mod q}
 *   <li>decryption: {@code c2 - <c1, s> = m * q / t + noise}, so m is restored by rounding
 * </ul>
 *
 * <p>A is expanded from a public seed with SHAKE-128, so the public key is the seed and b.
 *
 * <p>Key size is the lattice dimension n. Default is 2048. With {@code q = 2^50}, dimension 2048 or
 * more gives about 128-bit security against quantum attacks according to the tables of Homomorphic
 * Encryption Standard (log q must be at most 51 for n = 2048). Smaller dimensions are not secure,
 * and are for testing only.
 *
 * <p>Notice that its plaintext space is small, {@code 2^24} by default, and every ciphertext has
 * noise. Noise grows with homomorphic operations: addition adds the noise of ciphertexts, and
 * multiplying with a constant k multiplies the noise by {@code |k|}. Decryption returns a wrong
 * result without any error when the noise exceeds {@code q / 2t}. Fresh noise is about {@code 2^13}
 * for n = 2048, and the limit is {@code 2^25} by default, so there is room for thousands of
 * additions or multiplication with constants up to a few thousands. A greater plaintext space can
 * be set with the plaintext limit in exchange of a smaller room for noise. Floats and tensors are
 * not supported, as they are scaled by powers of 10. Ciphertexts have {@code n + 1} entries of 50
 * bits each, about 12.8 KB for n = 2048.
 *
 * <p>Since q is a power of 2 dividing {@code 2^64}, arithmetic modulo q is carried out on wrapping
 * {@code long} values and masked, which is exact.
 *
 * <p>Ref: Regev, O. (2005). On Lattices, Learning with Errors, Random Linear Codes, and
 * Cryptography. STOC 2005.
 *
 * <p>Ref: Lindner, R., Peikert, C. (2011). Better Key Sizes (and Attacks) for LWE-Based Encryption.
 * CT-RSA 2011.
 *
 * <p>Ref: Albrecht, M. et al. (2018). Homomorphic Encryption Security Standard.
 * HomomorphicEncryption.org.
 */
public final class Regev extends AbstractHomomorphic {

    /** The key fields Regev requires. */
    public static final KeySpec REQUIRED_KEYS =
            KeySpec.of(List.of("n", "q", "t", "seed", "b"), List.of("s"));

    /**
     * Floats are scaled by powers of 10, which exceeds the small plaintext space of Regev, and
     * multiplies the noise in ciphertexts by the same factor.
     */
    public static final String FLOAT_NOT_SUPPORTED_MSG =
            "Regev does not support float values or tensors, because they are scaled by powers"
                    + " of 10, which exceed its small plaintext space and noise budget."
                    + " Use integers instead.";

    /** Ciphertext modulus {@code q = 2^LOG_Q}. */
    static final int LOG_Q = 50;

    /** Default plaintext modulus {@code t = 2^DEFAULT_LOG_T}. */
    static final int DEFAULT_LOG_T = 24;

    /**
     * Secret and errors are sampled from centered binomial distribution with this parameter. Its
     * standard deviation is {@code sqrt(ETA / 2) = 3.24}, and its values are in {@code [-ETA,
     * ETA]}.
     */
    static final int ETA = 21;

    /** Fresh noise must stay below this many standard deviations for correct decryption. */
    private static final int NOISE_TAIL = 12;

    private static final long MASK = (1L << LOG_Q) - 1;

    private static final Logger logger = Logger.forModule(Regev.class);

    /** Entries of A in row-major order, expanded from the seed when needed. */
    private volatile long[] matrix;

    /**
     * Builds a Regev cryptosystem.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param keySize lattice dimension; {@code null} defaults to 2048
     * @param plaintextLimit upper bound for plaintext values, rounded up to a power of 2; {@code
     *     null} defaults to {@code 2^24}. Greater values leave less room for noise.
     */
    public Regev(Keys keys, Integer keySize, BigInteger plaintextLimit) {
        super(
                Algorithm.REGEV,
                keys != null
                        ? keys
                        : generateKeys(keySize == null ? 2048 : keySize, plaintextLimit));
        this.plaintextModulo = this.keys.publicNumber("t");
        this.ciphertextModulo = this.keys.publicNumber("q");
    }

    /**
     * Builds a Regev cryptosystem around an existing key pair.
     *
     * @param keys the private-public key pair
     */
    public Regev(Keys keys) {
        this(keys, null, null);
    }

    /**
     * Generates the public and private keys of the Regev cryptosystem.
     *
     * @param keySize lattice dimension
     * @param plaintextLimit upper bound for plaintext values, or {@code null} for the default
     * @return the generated key pair
     * @throws IllegalArgumentException when the dimension is too small or the limit too large
     */
    public static Keys generateKeys(int keySize, BigInteger plaintextLimit) {
        int n = keySize;
        if (n < 8) {
            throw new IllegalArgumentException("Key size " + n + " is too small for Regev");
        }

        long q = 1L << LOG_Q;
        long t = 1L << DEFAULT_LOG_T;
        if (plaintextLimit != null) {
            if (plaintextLimit.compareTo(BigInteger.TWO) < 0) {
                throw new IllegalArgumentException("Plaintext limit must be at least 2");
            }
            int bits = plaintextLimit.subtract(BigInteger.ONE).bitLength();
            t = bits >= LOG_Q ? q : 1L << bits;
        }

        // fresh ciphertexts must be decrypted correctly
        long noiseBound = noiseBound(n);
        // largest noise a ciphertext can carry and still be decrypted correctly
        long noiseRoom = q / t / 2;
        if (noiseRoom <= noiseBound) {
            throw new IllegalArgumentException(
                    "Plaintext limit "
                            + plaintextLimit
                            + " is too large for Regev. It must be less than "
                            + q / (2 * noiseBound)
                            + " for dimension "
                            + n
                            + ".");
        }
        double growth = (double) noiseRoom / noiseBound;
        logger.debug(() -> "noise of fresh ciphertexts can grow " + Math.round(growth) + " times");

        BigInteger seed = MathUtils.getRandomBits(256);
        long[] s = sampleSmall(n);
        long[] e = sampleSmall(n);

        // b = A s + e mod q
        long[] a = expand(seed, n);
        List<BigInteger> b = new ArrayList<>(n);
        for (int j = 0; j < n; j++) {
            long sum = e[j];
            int row = j * n;
            for (int i = 0; i < n; i++) {
                sum += a[row + i] * s[i];
            }
            b.add(BigInteger.valueOf(sum & MASK));
        }

        Keys keys = Keys.empty();
        keys.publicKey().put("n", KeyValue.of(n));
        keys.publicKey().put("q", KeyValue.of(q));
        keys.publicKey().put("t", KeyValue.of(t));
        keys.publicKey().put("seed", KeyValue.of(seed));
        keys.publicKey().put("b", KeyValue.numbers(b));

        keys.privateKey().put("s", KeyValue.numbers(toBigIntegers(s)));
        return keys;
    }

    @Override
    public KeySpec requiredKeys() {
        return REQUIRED_KEYS;
    }

    /**
     * {@inheritDoc}
     *
     * @throws UnsupportedOperationException always: the random key of Regev is a vector, see {@link
     *     #generateRandomVector()}
     */
    @Override
    public BigInteger generateRandomKey() {
        throw new UnsupportedOperationException(
                "Regev requires a small random vector per encryption. Use generateRandomVector.");
    }

    /**
     * Generates the one-time small random vector r Regev requires per encryption.
     *
     * @return the random vector
     */
    public long[] generateRandomVector() {
        return sampleSmall(dimension());
    }

    @Override
    public CipherValue encrypt(BigInteger plaintext) {
        return encrypt(plaintext, generateRandomVector());
    }

    /**
     * Encrypts a plaintext with an explicit random vector.
     *
     * @param plaintext the message to encrypt in {@code [0, t)}
     * @param randomVector the small random vector r
     * @return the ciphertext: n entries of {@code c1 = A^T r + e1}, and {@code c2 = dot(b, r) + e2
     *     + m q / t}
     */
    public CipherValue encrypt(BigInteger plaintext, long[] randomVector) {
        int n = dimension();
        long t = plaintextModulo.longValueExact();
        List<BigInteger> b = keys.publicNumbers("b");

        BigInteger message = plaintext;
        if (message.compareTo(plaintextModulo) >= 0) {
            message = message.mod(plaintextModulo);
            BigInteger normalized = message;
            logger.debug(
                    () ->
                            "Regev can encrypt messages [0, "
                                    + t
                                    + "). Seems plaintext exceeded this limit. New plaintext is "
                                    + normalized);
        }

        long[] a = matrix();
        long[] e1 = sampleSmall(n);
        long e2 = sampleSmall(1)[0];

        // c1 = A^T r + e1, accumulated row by row of A
        long[] c1 = e1.clone();
        for (int i = 0; i < n; i++) {
            long weight = randomVector[i];
            if (weight == 0) {
                continue;
            }
            int row = i * n;
            for (int j = 0; j < n; j++) {
                c1[j] += a[row + j] * weight;
            }
        }

        long c2 = e2 + message.longValueExact() * ((1L << LOG_Q) / t);
        for (int i = 0; i < n; i++) {
            c2 += b.get(i).longValue() * randomVector[i];
        }

        List<BigInteger> ciphertext = new ArrayList<>(n + 1);
        for (long value : c1) {
            ciphertext.add(BigInteger.valueOf(value & MASK));
        }
        ciphertext.add(BigInteger.valueOf(c2 & MASK));
        return TupleValue.ofIntegers(ciphertext);
    }

    @Override
    public BigInteger decrypt(CipherValue ciphertext) {
        long t = plaintextModulo.longValueExact();
        List<BigInteger> s = keys.privateNumbers("s");
        long delta = (1L << LOG_Q) / t;

        List<BigInteger> c = asTuple(ciphertext).asIntegers();
        int n = c.size() - 1;

        // m * q / t + noise
        long noisyMessage = c.get(n).longValue();
        for (int i = 0; i < n; i++) {
            noisyMessage -= c.get(i).longValue() * s.get(i).longValue();
        }
        noisyMessage &= MASK;
        return BigInteger.valueOf(((noisyMessage + delta / 2) / delta) % t);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Noise of the result is the sum of noises of the ciphertexts.
     */
    @Override
    public CipherValue add(CipherValue ciphertext1, CipherValue ciphertext2) {
        List<BigInteger> first = asTuple(ciphertext1).asIntegers();
        List<BigInteger> second = asTuple(ciphertext2).asIntegers();
        List<BigInteger> sum = new ArrayList<>(first.size());
        for (int i = 0; i < Math.min(first.size(), second.size()); i++) {
            sum.add(
                    BigInteger.valueOf(
                            (first.get(i).longValue() + second.get(i).longValue()) & MASK));
        }
        return TupleValue.ofIntegers(sum);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Noise of the result is the noise of the ciphertext times {@code |constant|}.
     */
    @Override
    public CipherValue multiplyByConstant(CipherValue ciphertext, BigInteger constant) {
        long scalar = centered(constant);
        List<BigInteger> values = asTuple(ciphertext).asIntegers();
        List<BigInteger> scaled = new ArrayList<>(values.size());
        for (BigInteger value : values) {
            scaled.add(BigInteger.valueOf((value.longValue() * scalar) & MASK));
        }
        return TupleValue.ofIntegers(scaled);
    }

    @Override
    public CipherValue reencrypt(CipherValue ciphertext) {
        return add(ciphertext, encrypt(BigInteger.ZERO));
    }

    /**
     * Returns the centered representative of a constant modulo t, which keeps the noise small for
     * negative constants, e.g. {@code t - 1} is multiplied as -1. As t divides q, this does not
     * change the result.
     */
    private long centered(BigInteger constant) {
        long t = plaintextModulo.longValueExact();
        long scalar = constant.mod(plaintextModulo).longValueExact();
        return scalar > t / 2 ? scalar - t : scalar;
    }

    private int dimension() {
        return keys.publicNumber("n").intValueExact();
    }

    private long[] matrix() {
        long[] expanded = matrix;
        if (expanded == null) {
            expanded = expand(keys.publicNumber("seed"), dimension());
            matrix = expanded;
        }
        return expanded;
    }

    /**
     * Samples from centered binomial distribution with cryptographically secure randomness.
     *
     * @param size number of samples
     * @return integers in {@code [-ETA, ETA]}
     */
    static long[] sampleSmall(int size) {
        long[] samples = new long[size];
        long mask = (1L << ETA) - 1;
        for (int i = 0; i < size; i++) {
            long bits = MathUtils.random().nextLong();
            samples[i] = Long.bitCount(bits & mask) - Long.bitCount((bits >>> ETA) & mask);
        }
        return samples;
    }

    /** Bound of the noise {@code dot(e, r) + e2 - dot(s, e1)} in fresh ciphertexts. */
    private static long noiseBound(int n) {
        double variance = ETA / 2.0;
        return (long) Math.ceil(NOISE_TAIL * variance * Math.sqrt(2.0 * n)) + ETA;
    }

    /**
     * Size of a slot of the expanded stream, which in the Python library must hold a sum of n
     * products of an entry of A and a small number without overflow.
     */
    private static int slotBytes(int n) {
        int bits = LOG_Q + BigInteger.valueOf((long) ETA * n).bitLength();
        return (bits + 7) / 8;
    }

    /**
     * Expands the public matrix A from its seed with SHAKE-128. Entry {@code (i, j)} is the low 50
     * bits of the little endian slot {@code i * n + j} of the stream, exactly as the Python library
     * packs it.
     *
     * @param seed the public seed
     * @param n the lattice dimension
     * @return the entries of A in row-major order
     */
    private static long[] expand(BigInteger seed, int n) {
        int width = slotBytes(n);
        Shake128 stream = new Shake128(toBytes(seed, 32));
        long[] a = new long[n * n];
        byte[] slot = new byte[width];
        for (int index = 0; index < a.length; index++) {
            stream.squeeze(slot, 0, width);
            long value = 0;
            for (int k = Math.min(width, 8) - 1; k >= 0; k--) {
                value = (value << 8) | (slot[k] & 0xFFL);
            }
            a[index] = value & MASK;
        }
        return a;
    }

    /** Big endian encoding of a non-negative integer in exactly {@code length} bytes. */
    static byte[] toBytes(BigInteger value, int length) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[length];
        int copy = Math.min(raw.length, length);
        System.arraycopy(raw, raw.length - copy, out, length - copy, copy);
        return out;
    }

    private static List<BigInteger> toBigIntegers(long[] values) {
        List<BigInteger> out = new ArrayList<>(values.length);
        for (long value : values) {
            out.add(BigInteger.valueOf(value));
        }
        return out;
    }
}
