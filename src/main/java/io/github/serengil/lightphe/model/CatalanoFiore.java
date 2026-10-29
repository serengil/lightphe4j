package io.github.serengil.lightphe.model;

import io.github.serengil.lightphe.commons.MathUtils;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Catalano-Fiore transform upgrades a linearly homomorphic cryptosystem to support one homomorphic
 * multiplication, i.e. evaluating degree-2 functions such as dot products of two encrypted vectors,
 * variances or squared distances. It wraps a built cryptosystem, and uses its public operations
 * only: encryption, decryption, homomorphic addition and multiplication with a constant. So, the
 * underlying cryptosystem is used as is, and the transform is as secure as it is.
 *
 * <p>Plaintext space is {@code Z_M}, where M is the plaintext modulo of the underlying
 * cryptosystem.
 *
 * <ul>
 *   <li>encryption of m: {@code (a, Enc(b))} where b is uniformly random in {@code Z_M} and {@code
 *       a = m - b}. a is in clear, but reveals nothing as b is uniformly random and secret.
 *   <li>addition: {@code (a1 + a2, Enc(b1) + Enc(b2))}
 *   <li>multiplication: {@code m1 m2 = a1 a2 + a1 b2 + a2 b1 + b1 b2}, so the result is {@code
 *       alpha = Enc(a1 a2) + a1 Enc(b2) + a2 Enc(b1)}, which encrypts {@code m1 m2 - b1 b2},
 *       together with the pair {@code (Enc(b1), Enc(b2))} to restore {@code b1 b2} in decryption.
 *   <li>decryption of a multiplied ciphertext: {@code Dec(alpha)} plus the sum of {@code
 *       Dec(Enc(b1)) Dec(Enc(b2))} for all pairs.
 * </ul>
 *
 * <p>Multiplied ciphertexts can be added with each other, with non-multiplied ciphertexts and with
 * plain constants, and they can be multiplied with plain constants. But they cannot be multiplied
 * with ciphertexts again.
 *
 * <p>Notice that a multiplied ciphertext keeps a pair of ciphertexts for every product it contains,
 * so its size grows with the number of products summed. For instance, dot product of two encrypted
 * vectors of length d has d pairs. The pairs also reveal which ciphertexts were multiplied, but not
 * their values.
 *
 * <p>Encryption and homomorphic operations require the public key only, and decryption requires the
 * private key of the underlying cryptosystem. Only integers are supported.
 *
 * <p>It is enabled with the boost option of {@code LightPHE}, e.g. {@code
 * LightPHE.builder().algorithmName("Paillier").boost("Catalano-Fiore").build()}.
 *
 * <p>Ref: Catalano, D., Fiore, D. (2015). Using Linearly-Homomorphic Encryption to Evaluate
 * Degree-2 Functions on Encrypted Data. ACM CCS 2015.
 */
public final class CatalanoFiore {

    /** Name of the transform as the boost option of {@code LightPHE}. */
    public static final String BOOST_NAME = "Catalano-Fiore";

    /**
     * Additively homomorphic algorithms whose plaintext space {@code Z_M} is public, and which can
     * decrypt any value in it.
     */
    public static final List<Algorithm> SUPPORTED_ALGORITHMS =
            List.of(
                    Algorithm.PAILLIER,
                    Algorithm.DAMGARD_JURIK,
                    Algorithm.BRESSON_CATALANO_POINTCHEVAL,
                    Algorithm.CAMENISCH_SHOUP,
                    Algorithm.ELLIPTIC_CURVE_PAILLIER,
                    Algorithm.JOYE_LIBERT,
                    Algorithm.CASTAGNOS_LAGUILLAUMIE,
                    Algorithm.NACCACHE_STERN,
                    Algorithm.BENALOH,
                    Algorithm.DAMGARD_GEISLER_KROIGAARD);

    private static final String DISCRETE_LOG_REASON =
            "its decryption solves discrete logarithm, which is"
                    + " infeasible for the uniformly random values the transform encrypts";

    private static final String NOISE_BUDGET_REASON =
            "multiplying with uniformly random constants exceeds its noise budget";

    private static final String NATIVE_MULTIPLICATION_REASON =
            "it already supports one multiplication natively";

    /** Reasons of algorithms that cannot be upgraded. */
    private static final Map<Algorithm, String> UNSUPPORTED_REASONS =
            Map.ofEntries(
                    Map.entry(Algorithm.EXPONENTIAL_EL_GAMAL, DISCRETE_LOG_REASON),
                    Map.entry(Algorithm.ELLIPTIC_CURVE_EL_GAMAL, DISCRETE_LOG_REASON),
                    Map.entry(
                            Algorithm.OKAMOTO_UCHIYAMA,
                            "its plaintext modulus p is secret, so the encryptor cannot"
                                    + " compute m - b mod p"),
                    Map.entry(Algorithm.REGEV, NOISE_BUDGET_REASON),
                    Map.entry(Algorithm.LYUBASHEVSKY_PEIKERT_REGEV, NOISE_BUDGET_REASON),
                    Map.entry(
                            Algorithm.ML_KEM,
                            "it is homomorphic with respect to xor only, without addition"),
                    Map.entry(
                            Algorithm.GOLDWASSER_MICALI,
                            "it encrypts integers bit by bit and supports xor only,"
                                    + " without multiplication with a constant"),
                    Map.entry(Algorithm.BONEH_GOH_NISSIM, NATIVE_MULTIPLICATION_REASON),
                    Map.entry(Algorithm.BRAKERSKI_VAIKUNTANATHAN, NATIVE_MULTIPLICATION_REASON),
                    Map.entry(Algorithm.FREEMAN_BONEH_GOH_NISSIM, NATIVE_MULTIPLICATION_REASON),
                    Map.entry(Algorithm.GENTRY_HALEVI_VAIKUNTANATHAN, NATIVE_MULTIPLICATION_REASON),
                    Map.entry(
                            Algorithm.GENTRY_SAHAI_WATERS,
                            "it already supports multiplications of bits natively"));

    private final Homomorphic cs;
    private final Homomorphic publicCs;
    private final BigInteger plaintextModulo;

    /**
     * Wraps a built cryptosystem of a supported additively homomorphic algorithm.
     *
     * @param cs the cryptosystem
     * @throws IllegalArgumentException when the algorithm is not supported
     */
    public CatalanoFiore(Homomorphic cs) {
        Algorithm algorithm = cs.algorithm();
        if (!SUPPORTED_ALGORITHMS.contains(algorithm)) {
            String reason =
                    UNSUPPORTED_REASONS.getOrDefault(algorithm, "it is not additively homomorphic");
            throw new IllegalArgumentException(
                    "Catalano-Fiore transform does not support "
                            + algorithm
                            + " because "
                            + reason
                            + ". Supported algorithms are "
                            + SUPPORTED_ALGORITHMS.stream()
                                    .map(Algorithm::algorithmName)
                                    .collect(Collectors.joining(", "))
                            + ".");
        }
        this.cs = cs;
        // ciphertexts keep a reference to the cryptosystem for homomorphic operations.
        // they must not carry the private key, as they are sent to other parties.
        this.publicCs = PublicOnlyView.of(cs);
        this.plaintextModulo = cs.plaintextModulo();
    }

    /**
     * Returns the plaintext modulo M of the underlying cryptosystem.
     *
     * @return the plaintext modulo
     */
    public BigInteger plaintextModulo() {
        return plaintextModulo;
    }

    /**
     * Encrypts a plaintext as {@code (a, Enc(b))} where {@code a = m - b} and b is uniformly
     * random.
     *
     * @param plaintext the message to encrypt; it is reduced modulo M
     * @return the non-multiplied ciphertext
     */
    public CatalanoFioreCiphertext encrypt(BigInteger plaintext) {
        BigInteger b =
                MathUtils.randomInt(BigInteger.ZERO, plaintextModulo.subtract(BigInteger.ONE));
        return CatalanoFioreCiphertext.nonMultiplied(
                publicCs,
                plaintext.subtract(b).mod(plaintextModulo),
                Ciphertext.of(publicCs, publicCs.encrypt(b)));
    }

    /**
     * Restores a non-multiplied ciphertext received from another party.
     *
     * @param a the plain part {@code m - b} in {@code [0, M)}
     * @param beta the encryption of b
     * @return the non-multiplied ciphertext
     */
    public CatalanoFioreCiphertext restore(BigInteger a, Ciphertext beta) {
        return CatalanoFioreCiphertext.nonMultiplied(publicCs, a, beta);
    }

    /**
     * Restores a multiplied ciphertext received from another party.
     *
     * @param alpha the encryption of the folded plain terms
     * @param pairs the pairs of encrypted b values
     * @return the multiplied ciphertext
     */
    public CatalanoFioreCiphertext restore(Ciphertext alpha, List<Ciphertext[]> pairs) {
        return CatalanoFioreCiphertext.multiplied(publicCs, alpha, pairs);
    }

    /**
     * Decrypts a ciphertext created by the transform. Requires the private key.
     *
     * @param ciphertext a non-multiplied or multiplied ciphertext
     * @return the restored message in {@code [0, M)}
     * @throws IllegalArgumentException when the private key is missing
     */
    public BigInteger decrypt(CatalanoFioreCiphertext ciphertext) {
        if (!cs.hasPrivateKey()) {
            throw new IllegalArgumentException("You must have private key to perform decryption");
        }

        if (!ciphertext.isMultiplied()) {
            return ciphertext.a().add(cs.decrypt(ciphertext.beta().value())).mod(plaintextModulo);
        }

        BigInteger result = cs.decrypt(ciphertext.alpha().value());
        for (Ciphertext[] pair : ciphertext.pairs()) {
            result = result.add(cs.decrypt(pair[0].value()).multiply(cs.decrypt(pair[1].value())));
        }
        return result.mod(plaintextModulo);
    }
}
