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
import java.util.Map;

/**
 * ML-KEM, homomorphic with respect to the exclusive or of 256-bit messages like Goldwasser-Micali,
 * but quantum resistant. It uses the parameter sets standardized by NIST in FIPS 203: ML-KEM-512,
 * ML-KEM-768 and ML-KEM-1024. Its security relies on the module learning with errors (Module-LWE)
 * problem.
 *
 * <p>ML-KEM is a key encapsulation mechanism built on a public key encryption scheme K-PKE. This is
 * K-PKE, which works in modules of rank k over the ring {@code R_q = Z_q[x] / (x^256 + 1)}.
 *
 * <ul>
 *   <li>private key: vector s of k polynomials with small coefficients
 *   <li>public key: k x k matrix A of polynomials and {@code t = A s + e}, where e is small
 *   <li>encryption of 256 message bits {@code m_i}: {@code u = A^T r + e1}, and {@code v = t^T r +
 *       e2 + m q / 2} where {@code m q / 2} is the polynomial whose i-th coefficient is {@code m_i
 *       * round(q / 2)}
 *   <li>decryption: {@code v - s^T u = m q / 2 + noise}, so {@code m_i} is 1 if the i-th
 *       coefficient is closer to {@code q / 2} than to 0
 *   <li>exclusive or: adding ciphertexts adds the bits modulo 2
 * </ul>
 *
 * <p>A is expanded from a public seed with SHAKE-128, so the public key is the seed and t.
 *
 * <p>Notice that this is not a FIPS 203 compliant implementation of ML-KEM:
 *
 * <ul>
 *   <li>It is the CPA secure K-PKE, without the Fujisaki-Okamoto transform of ML-KEM that makes it
 *       CCA secure, because a CCA secure scheme cannot be homomorphic.
 *   <li>Ciphertexts are not compressed, because compression adds rounding noise that leaves no room
 *       for homomorphic operations. Security of K-PKE does not depend on compression, which only
 *       drops information from ciphertexts.
 *   <li>Byte encodings, the sampling of A and the NTT representation are not the ones in FIPS 203,
 *       so its keys and ciphertexts are not interoperable with other libraries.
 *   <li>It is not validated by NIST under FIPS 140-3.
 * </ul>
 *
 * <p>It uses the standardized parameters q, n, k, eta1 and eta2 only.
 *
 * <p>Key size is the parameter set: 512, 768 or 1024. Default is 768, i.e. ML-KEM-768, which NIST
 * categorizes as at least as hard to break as AES-192.
 *
 * <p>Every ciphertext has noise, and exclusive or adds the noises of ciphertexts. Decryption
 * returns a wrong result without any error when the noise exceeds {@code q / 4}. Fresh ciphertexts
 * practically never fail, but q is small, so only a few ciphertexts can be combined. Failure
 * probability of decrypting the exclusive or of c ciphertexts of ML-KEM-768 is about {@code 2^-77}
 * for c = 4, {@code 2^-50} for c = 6, and {@code 2^-36} for c = 8. Regenerating a ciphertext counts
 * as combining it with one more ciphertext. Ciphertexts have {@code k + 1} polynomials of 256
 * coefficients of 12 bits, about 1.5 KB for ML-KEM-768. Floats and tensors are not supported.
 *
 * <p>Ref: National Institute of Standards and Technology (2024). Module-Lattice-Based
 * Key-Encapsulation Mechanism Standard. FIPS 203.
 *
 * <p>Ref: Bos, J. et al. (2018). CRYSTALS - Kyber: a CCA-secure module-lattice-based KEM. IEEE
 * EuroS&amp;P 2018.
 */
public final class MLKEM extends AbstractHomomorphic {

    /** The key fields ML-KEM requires. */
    public static final KeySpec REQUIRED_KEYS =
            KeySpec.of(List.of("parameter_set", "seed", "t"), List.of("s"));

    /** Floats are scaled by powers of 10, and xor of their encodings is meaningless. */
    public static final String FLOAT_NOT_SUPPORTED_MSG =
            "ML-KEM does not support float values or tensors, because it is homomorphic with"
                    + " respect to the exclusive or of 256-bit messages. Use integers instead.";

    /** Ciphertext modulus of FIPS 203. */
    public static final int Q = 3329;

    /** Ring degree of FIPS 203. */
    public static final int N = 256;

    /** Bits of a message are encoded as 0 or {@code round(q / 2)}. */
    public static final int HALF_Q = (Q + 1) / 2;

    /**
     * Parameters of a parameter set of FIPS 203.
     *
     * @param k module rank
     * @param eta1 parameter of centered binomial distributions of secret and error vectors
     * @param eta2 parameter of centered binomial distributions of errors of encryption
     */
    public record ParameterSet(int k, int eta1, int eta2) {}

    /** Parameter sets of FIPS 203, table 2. */
    public static final Map<Integer, ParameterSet> PARAMETER_SETS =
            Map.of(
                    512, new ParameterSet(2, 3, 2),
                    768, new ParameterSet(3, 2, 2),
                    1024, new ParameterSet(4, 2, 2));

    private static final BigInteger PLAINTEXT_MODULO = BigInteger.ONE.shiftLeft(N);

    private static final Logger logger = Logger.forModule(MLKEM.class);

    /** A expanded from the seed, built when needed. */
    private volatile int[][][] a;

    /**
     * Builds an ML-KEM cryptosystem.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param keySize the parameter set, 512, 768 or 1024; {@code null} defaults to 768
     */
    public MLKEM(Keys keys, Integer keySize) {
        super(
                Algorithm.ML_KEM,
                keys != null ? keys : generateKeys(keySize == null ? 768 : keySize));
        this.plaintextModulo = PLAINTEXT_MODULO;
        this.ciphertextModulo = BigInteger.valueOf(Q);
    }

    /**
     * Builds an ML-KEM cryptosystem around an existing key pair.
     *
     * @param keys the private-public key pair
     */
    public MLKEM(Keys keys) {
        this(keys, null);
    }

    /**
     * Generates the public and private keys of ML-KEM's K-PKE.
     *
     * @param keySize the parameter set, 512, 768 or 1024
     * @return the generated key pair
     * @throws IllegalArgumentException when the parameter set is unknown
     */
    public static Keys generateKeys(int keySize) {
        ParameterSet parameters = PARAMETER_SETS.get(keySize);
        if (parameters == null) {
            throw new IllegalArgumentException(
                    "Key size "
                            + keySize
                            + " must be one of the parameter sets of ML-KEM: [512, 768, 1024]");
        }
        int k = parameters.k();

        BigInteger seed = MathUtils.getRandomBits(256);
        int[][][] a = expand(seed, k);
        int[][] s = new int[k][];
        int[][] e = new int[k][];
        for (int i = 0; i < k; i++) {
            s[i] = sampleSmall(parameters.eta1());
        }
        for (int i = 0; i < k; i++) {
            e[i] = sampleSmall(parameters.eta1());
        }

        // t = A s + e
        List<List<BigInteger>> t = new ArrayList<>(k);
        for (int i = 0; i < k; i++) {
            int[] row = e[i].clone();
            for (int j = 0; j < k; j++) {
                addInPlace(row, multiply(a[i][j], s[j]));
            }
            t.add(toBigIntegers(reduce(row)));
        }

        List<List<BigInteger>> secret = new ArrayList<>(k);
        for (int[] polynomial : s) {
            secret.add(toBigIntegers(polynomial));
        }

        Keys keys = Keys.empty();
        keys.publicKey().put("parameter_set", KeyValue.of(keySize));
        keys.publicKey().put("seed", KeyValue.of(seed));
        keys.publicKey().put("t", KeyValue.matrix(t));
        keys.privateKey().put("s", KeyValue.matrix(secret));
        return keys;
    }

    @Override
    public KeySpec requiredKeys() {
        return REQUIRED_KEYS;
    }

    /**
     * {@inheritDoc}
     *
     * @throws UnsupportedOperationException always: the random key of ML-KEM is a vector of
     *     polynomials, see {@link #generateRandomVector()}
     */
    @Override
    public BigInteger generateRandomKey() {
        throw new UnsupportedOperationException(
                "ML-KEM requires a small random vector of polynomials per encryption."
                        + " Use generateRandomVector.");
    }

    /**
     * Generates the one-time small random vector of k polynomials r required per encryption.
     *
     * @return coefficients of the k polynomials
     */
    public int[][] generateRandomVector() {
        ParameterSet parameters = parameters();
        int[][] r = new int[parameters.k()][];
        for (int i = 0; i < r.length; i++) {
            r[i] = sampleSmall(parameters.eta1());
        }
        return r;
    }

    @Override
    public CipherValue encrypt(BigInteger plaintext) {
        return encrypt(plaintext, generateRandomVector());
    }

    /**
     * Encrypts a plaintext with an explicit random vector.
     *
     * @param plaintext the message to encrypt in {@code [0, 2^256)}
     * @param randomVector k polynomials r with small coefficients
     * @return the ciphertext: k polynomials of {@code u = A^T r + e1}, and {@code v = t^T r + e2 +
     *     m q / 2}
     */
    public CipherValue encrypt(BigInteger plaintext, int[][] randomVector) {
        ParameterSet parameters = parameters();
        int k = parameters.k();
        List<List<BigInteger>> t = keys.publicMatrix("t");

        BigInteger message = plaintext;
        if (message.compareTo(PLAINTEXT_MODULO) >= 0) {
            message = message.mod(PLAINTEXT_MODULO);
            BigInteger normalized = message;
            logger.debug(
                    () ->
                            "ML-KEM can encrypt messages [0, 2^"
                                    + N
                                    + "). Seems plaintext exceeded this limit. New plaintext is "
                                    + normalized);
        }

        int[][][] matrix = publicA();
        List<CipherValue> polynomials = new ArrayList<>(k + 1);

        // u = A^T r + e1
        for (int i = 0; i < k; i++) {
            int[] u = sampleSmall(parameters.eta2());
            for (int j = 0; j < k; j++) {
                addInPlace(u, multiply(matrix[j][i], randomVector[j]));
            }
            polynomials.add(toValue(reduce(u)));
        }

        // v = t^T r + e2 + m q / 2
        int[] v = sampleSmall(parameters.eta2());
        for (int j = 0; j < k; j++) {
            addInPlace(v, multiply(toInts(t.get(j)), randomVector[j]));
        }
        for (int x = 0; x < N; x++) {
            if (message.testBit(x)) {
                v[x] += HALF_Q;
            }
        }
        polynomials.add(toValue(reduce(v)));
        return TupleValue.of(polynomials);
    }

    @Override
    public BigInteger decrypt(CipherValue ciphertext) {
        List<TupleValue> polynomials = asTuple(ciphertext).asTuples();
        List<List<BigInteger>> s = keys.privateMatrix("s");
        int k = polynomials.size() - 1;

        // v - s^T u = m q / 2 + noise
        int[] w = toInts(polynomials.get(k).asIntegers());
        for (int j = 0; j < k; j++) {
            int[] product = multiply(toInts(polynomials.get(j).asIntegers()), toInts(s.get(j)));
            for (int x = 0; x < N; x++) {
                w[x] -= product[x];
            }
        }

        BigInteger plaintext = BigInteger.ZERO;
        for (int x = 0; x < N; x++) {
            int value = Math.floorMod(w[x], Q);
            // bit is 1 if w is closer to q / 2 than to 0
            if (value > Q / 4 && value < Q - Q / 4) {
                plaintext = plaintext.setBit(x);
            }
        }
        return plaintext;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Bits are added modulo 2, as {@code 2 * round(q / 2) = q + 1} is close to 0 modulo q. Noise
     * of the result is the sum of noises of the ciphertexts.
     */
    @Override
    public CipherValue xor(CipherValue ciphertext1, CipherValue ciphertext2) {
        List<TupleValue> first = asTuple(ciphertext1).asTuples();
        List<TupleValue> second = asTuple(ciphertext2).asTuples();
        List<CipherValue> polynomials = new ArrayList<>(first.size());
        for (int i = 0; i < first.size(); i++) {
            int[] sum = toInts(first.get(i).asIntegers());
            addInPlace(sum, toInts(second.get(i).asIntegers()));
            polynomials.add(toValue(reduce(sum)));
        }
        return TupleValue.of(polynomials);
    }

    @Override
    public CipherValue reencrypt(CipherValue ciphertext) {
        return xor(ciphertext, encrypt(BigInteger.ZERO));
    }

    /**
     * Returns the public matrix A expanded from the seed.
     *
     * @return k x k polynomials
     */
    int[][][] publicA() {
        int[][][] expanded = a;
        if (expanded == null) {
            expanded = expand(keys.publicNumber("seed"), parameters().k());
            a = expanded;
        }
        return expanded;
    }

    private ParameterSet parameters() {
        return PARAMETER_SETS.get(keys.publicNumber("parameter_set").intValueExact());
    }

    /**
     * Multiplies two polynomials in {@code Z_q[x] / (x^256 + 1)}.
     *
     * @param poly1 256 coefficients, any representative modulo q
     * @param poly2 256 coefficients, any representative modulo q
     * @return 256 coefficients in {@code [0, q)}
     */
    static int[] multiply(int[] poly1, int[] poly2) {
        long[] product = new long[N];
        for (int i = 0; i < N; i++) {
            long x = poly1[i];
            if (x == 0) {
                continue;
            }
            // x^256 = -1
            for (int j = 0; j < N - i; j++) {
                product[i + j] += x * poly2[j];
            }
            for (int j = N - i; j < N; j++) {
                product[i + j - N] -= x * poly2[j];
            }
        }
        int[] reduced = new int[N];
        for (int i = 0; i < N; i++) {
            reduced[i] = (int) Math.floorMod(product[i], (long) Q);
        }
        return reduced;
    }

    /**
     * Samples a polynomial from centered binomial distribution with cryptographically secure
     * randomness.
     *
     * @param eta parameter of the distribution
     * @return 256 integers in {@code [-eta, eta]}
     */
    static int[] sampleSmall(int eta) {
        int mask = (1 << eta) - 1;
        int[] samples = new int[N];
        for (int i = 0; i < N; i++) {
            int bits = MathUtils.random().nextInt();
            samples[i] = Integer.bitCount(bits & mask) - Integer.bitCount((bits >>> eta) & mask);
        }
        return samples;
    }

    /**
     * Expands the public matrix A from its seed with SHAKE-128. Every 3 bytes give two 12-bit
     * values, which are accepted if they are less than q, so coefficients are uniform in {@code [0,
     * q)}. Each entry of A has its own stream.
     *
     * @param seed the public seed
     * @param k the module rank
     * @return k x k polynomials
     */
    static int[][][] expand(BigInteger seed, int k) {
        byte[] seedBytes = Regev.toBytes(seed, 32);
        int[][][] matrix = new int[k][k][];
        for (int i = 0; i < k; i++) {
            for (int j = 0; j < k; j++) {
                byte[] input = new byte[seedBytes.length + 2];
                System.arraycopy(seedBytes, 0, input, 0, seedBytes.length);
                input[seedBytes.length] = (byte) j;
                input[seedBytes.length + 1] = (byte) i;

                int[] coefficients = new int[N];
                int count = 0;
                int length = 3 * N;
                while (count < N) {
                    byte[] stream = Shake128.digest(input, length);
                    count = 0;
                    for (int x = 0; x + 2 < length && count < N; x += 3) {
                        int b0 = stream[x] & 0xFF;
                        int b1 = stream[x + 1] & 0xFF;
                        int b2 = stream[x + 2] & 0xFF;
                        int d1 = b0 | ((b1 & 0x0F) << 8);
                        int d2 = (b1 >> 4) | (b2 << 4);
                        if (d1 < Q) {
                            coefficients[count++] = d1;
                        }
                        if (d2 < Q && count < N) {
                            coefficients[count++] = d2;
                        }
                    }
                    length *= 2;
                }
                matrix[i][j] = coefficients;
            }
        }
        return matrix;
    }

    private static void addInPlace(int[] target, int[] other) {
        for (int i = 0; i < target.length; i++) {
            target[i] += other[i];
        }
    }

    private static int[] reduce(int[] polynomial) {
        int[] reduced = new int[polynomial.length];
        for (int i = 0; i < polynomial.length; i++) {
            reduced[i] = Math.floorMod(polynomial[i], Q);
        }
        return reduced;
    }

    private static int[] toInts(List<BigInteger> values) {
        int[] out = new int[values.size()];
        for (int i = 0; i < out.length; i++) {
            out[i] = values.get(i).intValueExact();
        }
        return out;
    }

    private static List<BigInteger> toBigIntegers(int[] values) {
        List<BigInteger> out = new ArrayList<>(values.length);
        for (int value : values) {
            out.add(BigInteger.valueOf(value));
        }
        return out;
    }

    private static CipherValue toValue(int[] coefficients) {
        return TupleValue.ofIntegers(toBigIntegers(coefficients));
    }
}
