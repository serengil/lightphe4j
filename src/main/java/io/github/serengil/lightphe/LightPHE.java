package io.github.serengil.lightphe;

import io.github.serengil.lightphe.commons.KeyValidator;
import io.github.serengil.lightphe.commons.Logger;
import io.github.serengil.lightphe.commons.PheUtils;
import io.github.serengil.lightphe.cryptosystems.CryptosystemFactory;
import io.github.serengil.lightphe.ecc.CurvePoint;
import io.github.serengil.lightphe.model.Algorithm;
import io.github.serengil.lightphe.model.ArgmaxMessage;
import io.github.serengil.lightphe.model.CatalanoFiore;
import io.github.serengil.lightphe.model.CatalanoFioreCiphertext;
import io.github.serengil.lightphe.model.Ciphertext;
import io.github.serengil.lightphe.model.DecisionTree;
import io.github.serengil.lightphe.model.EncryptedTensor;
import io.github.serengil.lightphe.model.Fraction;
import io.github.serengil.lightphe.model.Homomorphic;
import io.github.serengil.lightphe.model.KeyValue;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.KeysCodec;
import io.github.serengil.lightphe.model.NumericDecisionTree;
import io.github.serengil.lightphe.model.PublicOnlyView;
import io.github.serengil.lightphe.model.VerifiableCiphertext;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.IntValue;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.IntStream;
import lombok.Builder;

/**
 * The entry point of the library: a partially or somewhat homomorphic cryptosystem you can encrypt
 * with, compute on, and decrypt with.
 *
 * <p>Java counterpart of the Python {@code LightPHE} class. Because Java dispatches on static types
 * rather than runtime ones, the single Python {@code encrypt}/{@code decrypt} pair is split into
 * {@link #encrypt(BigInteger)} / {@link #decrypt(Ciphertext)} for scalars and {@link
 * #encryptTensor(List)} / {@link #decryptTensor(EncryptedTensor)} for vectors.
 *
 * <h2>Example</h2>
 *
 * <pre>{@code
 * LightPHE cs = LightPHE.builder()
 *         .algorithmName("Paillier")
 *         .keySize(1024)
 *         .build();
 *
 * Ciphertext salary = cs.encrypt(10_000);
 * Ciphertext raise = cs.encrypt(1_000);
 * BigInteger total = cs.decrypt(salary.add(raise));   // 11000
 * }</pre>
 */
public final class LightPHE {

    /** Library version, tracking the Python release this port is based on. */
    public static final String VERSION = "0.0.28";

    /** Default number of digits kept after the decimal point in tensor operations. */
    public static final int DEFAULT_PRECISION = 5;

    private static final Logger logger = Logger.forModule(LightPHE.class);

    private static final MathContext DIVISION_CONTEXT = new MathContext(50);

    private final Algorithm algorithmName;
    private final int precision;
    private final String form;
    private final String curve;
    private final Homomorphic cs;

    /** Catalano-Fiore transform wrapping the cryptosystem, or {@code null} without the boost. */
    private final CatalanoFiore catalanoFiore;

    /**
     * Public-key-only cryptosystem shared by ciphertexts, built on first use as constructing one
     * can be expensive.
     */
    private volatile Homomorphic publicCs;

    /**
     * Builds a LightPHE cryptosystem.
     *
     * @param algorithmName one of {@code RSA}, {@code ElGamal}, {@code Exponential-ElGamal}, {@code
     *     EllipticCurve-ElGamal}, {@code Paillier}, {@code Damgard-Jurik}, {@code
     *     Okamoto-Uchiyama}, {@code Benaloh}, {@code Naccache-Stern}, {@code Goldwasser-Micali},
     *     {@code Sander-Young-Yung}, {@code Boneh-Goh-Nissim}, {@code Joye-Libert}, {@code
     *     Castagnos-Laguillaumie}, {@code Ishai-Paskin}, {@code Damgard-Geisler-Kroigaard}, {@code
     *     Bresson-Catalano-Pointcheval}, {@code Camenisch-Shoup}, {@code EllipticCurve-Paillier},
     *     {@code Regev}, {@code Brakerski-Vaikuntanathan}, {@code Freeman-Boneh-Goh-Nissim} or
     *     {@code Gentry-Halevi-Vaikuntanathan}
     * @param keys optional private-public key pair
     * @param keyFile if keys were exported already, the file to load them from
     * @param keySize key size in bits. For Regev, it is the lattice dimension. For
     *     Brakerski-Vaikuntanathan, it is the ring degree. For Freeman-Boneh-Goh-Nissim, it is the
     *     bit length of the field size. For Gentry-Halevi-Vaikuntanathan, it is the lattice
     *     dimension in {@code [2, 8]}.
     * @param precision precision for homomorphic operations on tensors; zero or less selects the
     *     default of {@value #DEFAULT_PRECISION}
     * @param form the form of the elliptic curve: {@code weierstrass} (default), {@code edwards} or
     *     {@code koblitz}. Only used when {@code algorithmName} is {@code EllipticCurve-ElGamal} or
     *     {@code Camenisch-Shoup}, which uses it for verifiable encryption.
     * @param curve the elliptic curve to use, for example {@code ed25519} or {@code ed448} for the
     *     Edwards form, {@code secp256k1} for the Weierstrass form and {@code k-409} for the
     *     Koblitz form. The full list of available curves is at <a
     *     href="https://github.com/serengil/LightECC?tab=readme-ov-file#supported-curves">
     *     LightECC</a>. Only used when {@code algorithmName} is {@code EllipticCurve-ElGamal} or
     *     {@code Camenisch-Shoup}, which uses it for verifiable encryption.
     * @param plaintextLimit upper bound for plaintext values. Only used when {@code algorithmName}
     *     is {@code Benaloh}, {@code Sander-Young-Yung}, {@code Regev}, {@code
     *     Brakerski-Vaikuntanathan}, {@code Freeman-Boneh-Goh-Nissim} or {@code
     *     Gentry-Halevi-Vaikuntanathan}.
     * @param maxTries maximum attempts to generate keys; zero or less selects the default of 10000.
     *     RSA, Benaloh, Naccache-Stern, Goldwasser-Micali, Boneh-Goh-Nissim, Joye-Libert,
     *     Castagnos-Laguillaumie, Damgard-Geisler-Kroigaard, Bresson-Catalano-Pointcheval and
     *     Camenisch-Shoup need multiple attempts to generate valid keys, and the other algorithms
     *     discard it.
     * @param boost upgrades the algorithm with a transform; {@code null} for none. The only option
     *     is {@code Catalano-Fiore}, which lets ciphertexts of an additively homomorphic algorithm
     *     be multiplied once. Then, {@link #encryptBoosted} returns ciphertexts supporting one
     *     multiplication, and only integers are supported. Supported for Paillier, Damgard-Jurik,
     *     Bresson-Catalano-Pointcheval, Camenisch-Shoup, EllipticCurve-Paillier, Joye-Libert,
     *     Castagnos-Laguillaumie, Naccache-Stern, Benaloh and Damgard-Geisler-Kroigaard.
     * @throws IllegalArgumentException when the boost is unknown or does not support the algorithm
     */
    @Builder
    public LightPHE(
            String algorithmName,
            Keys keys,
            Path keyFile,
            Integer keySize,
            int precision,
            String form,
            String curve,
            BigInteger plaintextLimit,
            int maxTries,
            String boost) {
        this.algorithmName = Algorithm.of(algorithmName);
        this.precision = precision > 0 ? precision : DEFAULT_PRECISION;
        this.form = form;
        this.curve = curve;

        Keys resolved = keys;
        if (keyFile != null) {
            resolved = restoreKeys(keyFile);
        }

        if (resolved != null) {
            KeyValidator.validateKeys(this.algorithmName, resolved);
        }

        this.cs =
                CryptosystemFactory.build(
                        this.algorithmName,
                        new CryptosystemFactory.Options(
                                resolved,
                                keySize,
                                form,
                                curve,
                                plaintextLimit,
                                maxTries > 0 ? maxTries : CryptosystemFactory.DEFAULT_MAX_TRIES));

        // Catalano-Fiore transform wraps the cryptosystem without changing it
        if (boost == null) {
            this.catalanoFiore = null;
        } else {
            if (!CatalanoFiore.BOOST_NAME.equals(boost)) {
                throw new IllegalArgumentException(
                        "Unknown boost " + boost + ". Options are: " + CatalanoFiore.BOOST_NAME);
            }
            this.catalanoFiore = new CatalanoFiore(cs);
        }
    }

    /**
     * Returns the algorithm this cryptosystem implements.
     *
     * @return the algorithm
     */
    public Algorithm algorithmName() {
        return algorithmName;
    }

    /**
     * Returns the underlying cryptosystem.
     *
     * @return the cryptosystem
     */
    public Homomorphic cs() {
        return cs;
    }

    /**
     * Returns the precision used for tensor operations.
     *
     * @return the number of digits kept after the decimal point
     */
    public int precision() {
        return precision;
    }

    // -----------------------------------------------------------------------
    // Encryption and decryption
    // -----------------------------------------------------------------------

    /**
     * Encrypts a plaintext with the built cryptosystem.
     *
     * @param plaintext the message
     * @return the encrypted message
     * @throws IllegalArgumentException when no public key is available, or when the Catalano-Fiore
     *     boost is set - use {@link #encryptBoosted(BigInteger)} then
     */
    public Ciphertext encrypt(BigInteger plaintext) {
        requirePublicKey("encryption");
        requireNoBoost();
        CipherValue ciphertext =
                cs.encrypt(PheUtils.normalizeInput(plaintext, cs.plaintextModulo()));
        return buildCiphertext(ciphertext);
    }

    /**
     * Encrypts a plaintext with the built cryptosystem.
     *
     * @param plaintext the message
     * @return the encrypted message
     */
    public Ciphertext encrypt(long plaintext) {
        return encrypt(BigInteger.valueOf(plaintext));
    }

    /**
     * Encrypts a real plaintext, which is first normalised into the message space.
     *
     * @param plaintext the message
     * @return the encrypted message
     * @throws IllegalArgumentException when no public key is available, when the algorithm or the
     *     boost supports integers only, or when the value is negative - a case the reference
     *     implementation leaves unimplemented
     */
    public Ciphertext encrypt(double plaintext) {
        requirePublicKey("encryption");
        requireIntegersOnlyBoost();
        CryptosystemFactory.requireFloatSupport(algorithmName);
        CipherValue ciphertext =
                cs.encrypt(PheUtils.normalizeInput(plaintext, cs.plaintextModulo()));
        return buildCiphertext(ciphertext);
    }

    /**
     * Decrypts a ciphertext with the built cryptosystem.
     *
     * @param ciphertext the encrypted message
     * @return the restored message
     * @throws IllegalArgumentException when the private key is missing
     */
    public BigInteger decrypt(Ciphertext ciphertext) {
        requireKeysForDecryption();
        return cs.decrypt(ciphertext.value());
    }

    /**
     * Encrypts a plaintext into a ciphertext supporting one multiplication with the Catalano-Fiore
     * boost. Java counterpart of calling {@code encrypt} on a boosted Python cryptosystem.
     *
     * @param plaintext the message; it is reduced modulo the plaintext modulo
     * @return the encrypted message
     * @throws IllegalArgumentException when no public key is available, or when the boost is not
     *     set
     */
    public CatalanoFioreCiphertext encryptBoosted(BigInteger plaintext) {
        requirePublicKey("encryption");
        if (catalanoFiore == null) {
            throw new IllegalArgumentException(
                    "Ciphertexts supporting multiplication require the "
                            + CatalanoFiore.BOOST_NAME
                            + " boost. Build the cryptosystem with boost = \""
                            + CatalanoFiore.BOOST_NAME
                            + "\".");
        }
        return catalanoFiore.encrypt(plaintext);
    }

    /**
     * Encrypts a plaintext into a ciphertext supporting one multiplication with the Catalano-Fiore
     * boost.
     *
     * @param plaintext the message
     * @return the encrypted message
     */
    public CatalanoFioreCiphertext encryptBoosted(long plaintext) {
        return encryptBoosted(BigInteger.valueOf(plaintext));
    }

    /**
     * Decrypts a ciphertext of the Catalano-Fiore transform, multiplied or not.
     *
     * @param ciphertext the encrypted message
     * @return the restored message
     * @throws IllegalArgumentException when the private key is missing
     */
    public BigInteger decrypt(CatalanoFioreCiphertext ciphertext) {
        requireKeysForDecryption();
        CatalanoFiore transform = catalanoFiore != null ? catalanoFiore : new CatalanoFiore(cs);
        return transform.decrypt(ciphertext);
    }

    /**
     * Decrypts a ciphertext with the master key instead of the private key of its owner. The master
     * key can decrypt ciphertexts of all users sharing it. Only supported by
     * Bresson-Catalano-Pointcheval.
     *
     * @param ciphertext the encrypted message of any user
     * @return the restored message
     * @throws IllegalArgumentException when a key is missing, or when the scheme does not support
     *     master key decryption
     */
    public BigInteger decryptWithMasterKey(Ciphertext ciphertext) {
        requirePrivateKey("perform decryption");
        requirePublicKey("decryption");
        return cs.decryptWithMasterKey(ciphertext.value(), ciphertext.keys().publicKey());
    }

    /**
     * Decrypts an encrypted tensor with the master key instead of the private key of its owner.
     * Only supported by Bresson-Catalano-Pointcheval.
     *
     * @param encryptedTensor the encrypted tensor of any user
     * @return the restored values
     * @throws IllegalArgumentException when a key is missing, or when the scheme does not support
     *     master key decryption
     */
    public List<Double> decryptTensorWithMasterKey(EncryptedTensor encryptedTensor) {
        requirePrivateKey("perform decryption");
        requirePublicKey("decryption");
        Map<String, KeyValue> publicKey = encryptedTensor.cs().keys().publicKey();
        return decryptTensor(encryptedTensor, value -> cs.decryptWithMasterKey(value, publicKey));
    }

    /**
     * Generates a key pair for a new user of a master key. Public key of the authority holding the
     * master key is enough to generate it. The master key can decrypt ciphertexts encrypted for the
     * new user, but the new user cannot decrypt ciphertexts of others. Only supported by
     * Bresson-Catalano-Pointcheval.
     *
     * @return the private-public key pair of the new user
     * @throws IllegalArgumentException when no public key is available, or when the scheme does not
     *     support it
     */
    public Keys generateUserKeys() {
        requirePublicKeyTo("generate user keys");
        return cs.generateUserKeys();
    }

    // -----------------------------------------------------------------------
    // Verifiable encryption
    // -----------------------------------------------------------------------

    /**
     * Encrypts the discrete logarithm of an elliptic curve point, e.g. a private key, for the owner
     * of this cryptosystem and proves that the ciphertext contains it. Runs on prover side, e.g.
     * Alice escrowing her wallet key to a trusted third party. Only the prover can call this,
     * because it needs the secret itself. Public key of the trusted third party is enough, the
     * private key is not needed. Output is sent to the verifier, who checks it with {@link
     * #verifyEncryption}. Only supported by Camenisch-Shoup.
     *
     * @param secret the discrete logarithm of the public point, i.e. {@code public point = G *
     *     secret}
     * @param label public data bound to the ciphertext, e.g. decryption conditions. The ciphertext
     *     cannot be decrypted with a different label.
     * @return the ciphertext, commitment and proof
     * @throws IllegalArgumentException when no public key is available, or when the scheme does not
     *     support verifiable encryption
     */
    public VerifiableCiphertext encryptVerifiably(BigInteger secret, String label) {
        requirePublicKey("encryption");
        return cs.encryptVerifiably(secret, label);
    }

    /**
     * Encrypts the discrete logarithm of an elliptic curve point with an empty label.
     *
     * @param secret the discrete logarithm of the public point
     * @return the ciphertext, commitment and proof
     */
    public VerifiableCiphertext encryptVerifiably(BigInteger secret) {
        return encryptVerifiably(secret, "");
    }

    /**
     * Verifies that a verifiable ciphertext contains the discrete logarithm of a public point
     * without decrypting it. Runs on verifier side, e.g. a bank that knows Alice's public key only.
     * The verifier cannot trust the prover's word, because the prover could encrypt 0 or an
     * unrelated key instead. This checks the proof against the public point and the label that the
     * verifier already knows, so it confirms the escrow is real without learning the secret. Public
     * key of the trusted third party is enough, the private key is not needed. Only supported by
     * Camenisch-Shoup.
     *
     * @param verifiableCiphertext the output of {@link #encryptVerifiably}
     * @param publicPoint the public point known by the verifier
     * @param label the label the ciphertext is expected to be bound to
     * @return {@code true} when the ciphertext contains the secret of the public point
     * @throws IllegalArgumentException when no public key is available, or when the scheme does not
     *     support verifiable encryption
     */
    public boolean verifyEncryption(
            VerifiableCiphertext verifiableCiphertext, CurvePoint publicPoint, String label) {
        requirePublicKeyTo("verify encryption");
        return cs.verifyEncryption(verifiableCiphertext, publicPoint, label);
    }

    /**
     * Verifies a verifiable ciphertext created with an empty label.
     *
     * @param verifiableCiphertext the output of {@link #encryptVerifiably}
     * @param publicPoint the public point known by the verifier
     * @return {@code true} when the ciphertext contains the secret of the public point
     */
    public boolean verifyEncryption(
            VerifiableCiphertext verifiableCiphertext, CurvePoint publicPoint) {
        return verifyEncryption(verifiableCiphertext, publicPoint, "");
    }

    /**
     * Restores the secret from a verifiable ciphertext. Runs on the side of the private key owner,
     * e.g. a trusted third party, when the conditions in the label are met. This is the only step
     * requiring the private key, and the only way to restore the secret. It does not check the
     * proof, as {@link #verifyEncryption} does that. Only supported by Camenisch-Shoup.
     *
     * @param verifiableCiphertext the output of {@link #encryptVerifiably}
     * @param label the label used in encryption
     * @return the discrete logarithm of the public point
     * @throws IllegalArgumentException when the private key is missing, the label is different, or
     *     the scheme does not support verifiable encryption
     */
    public BigInteger decryptVerifiableCiphertext(
            VerifiableCiphertext verifiableCiphertext, String label) {
        requirePrivateKey("perform decryption");
        return cs.decryptVerifiableCiphertext(verifiableCiphertext, label);
    }

    /**
     * Restores the secret from a verifiable ciphertext created with an empty label.
     *
     * @param verifiableCiphertext the output of {@link #encryptVerifiably}
     * @return the discrete logarithm of the public point
     */
    public BigInteger decryptVerifiableCiphertext(VerifiableCiphertext verifiableCiphertext) {
        return decryptVerifiableCiphertext(verifiableCiphertext, "");
    }

    /**
     * Encrypts a tensor of real or integer values.
     *
     * <p>Every item is stored as an encrypted dividend over a shared encrypted divisor, so the
     * result supports element-wise multiplication, addition and dot products.
     *
     * @param tensor the values to encrypt
     * @return the encrypted tensor
     * @throws IllegalArgumentException when no public key is available, or when the algorithm or
     *     the boost does not support tensors
     */
    public EncryptedTensor encryptTensor(List<? extends Number> tensor) {
        requirePublicKey("encryption");
        requireIntegersOnlyBoost();
        CryptosystemFactory.requireTensorSupport(algorithmName);

        CipherValue encryptedZero = cs.encrypt(BigInteger.ZERO);
        CipherValue encryptedDivisor = cs.encrypt(BigInteger.TEN.pow(precision));

        List<Fraction> fractions =
                IntStream.range(0, tensor.size())
                        .parallel()
                        .mapToObj(
                                index ->
                                        encryptFloat(
                                                tensor.get(index),
                                                encryptedDivisor,
                                                cs,
                                                precision,
                                                encryptedZero))
                        .toList();

        return new EncryptedTensor(fractions, PublicOnlyView.of(cs), precision);
    }

    /**
     * Decrypts an encrypted tensor.
     *
     * @param encryptedTensor the encrypted tensor
     * @return the restored values
     * @throws IllegalArgumentException when the private key is missing
     */
    public List<Double> decryptTensor(EncryptedTensor encryptedTensor) {
        requireKeysForDecryption();
        return decryptTensor(encryptedTensor, cs::decrypt);
    }

    private static List<Double> decryptTensor(
            EncryptedTensor encryptedTensor, Function<CipherValue, BigInteger> decrypt) {
        List<Double> plainTensor = new ArrayList<>(encryptedTensor.fractions().size());
        for (Fraction fraction : encryptedTensor.fractions()) {
            int sign = fraction.sign();
            BigInteger absDividend = decrypt.apply(fraction.absDividend());
            // TODO: do I really need an encrypted divisor? Could the current precision be stored
            // instead?
            BigInteger divisor = decrypt.apply(fraction.divisor());

            BigDecimal restored =
                    new BigDecimal(absDividend)
                            .divide(new BigDecimal(divisor), DIVISION_CONTEXT)
                            .multiply(BigDecimal.valueOf(sign));
            plainTensor.add(restored.doubleValue());
        }
        return plainTensor;
    }

    // -----------------------------------------------------------------------
    // Decision trees
    // -----------------------------------------------------------------------

    /**
     * Encrypts the input bits (answers to the questions) of a decision tree owned by the server.
     * Only supported by Ishai-Paskin; Damgard-Geisler-Kroigaard expects numeric features through
     * {@link #encryptDecisionTreeFeatures} instead.
     *
     * @param bits the input bits, each 0 or 1
     * @param depth the maximum number of decisions on a path of the decision tree
     * @return the encrypted input, to be sent to the tree owner
     * @throws IllegalArgumentException when no public key is available, or when the scheme does not
     *     support decision trees
     */
    public List<List<BigInteger>> encryptDecisionTreeInput(List<Integer> bits, int depth) {
        requirePublicKey("encryption");
        return cs.encryptDecisionTreeInput(bits, depth);
    }

    /**
     * Evaluates a decision tree on encrypted input. Private key is not required. Only supported by
     * Ishai-Paskin.
     *
     * @param tree the decision tree
     * @param encryptedInput the output of {@link #encryptDecisionTreeInput}
     * @return the encrypted output of the tree
     * @throws IllegalArgumentException when no public key is available, or when the scheme does not
     *     support decision trees
     */
    public Ciphertext evaluateDecisionTree(
            DecisionTree tree, List<List<BigInteger>> encryptedInput) {
        requirePublicKey("decision tree evaluation");
        return buildCiphertext(cs.evaluateDecisionTree(tree, encryptedInput));
    }

    /**
     * Encrypts the client's numeric features of a decision tree owned by the server. 1st step of
     * private decision tree evaluation, runs on client side. Only supported by
     * Damgard-Geisler-Kroigaard. Java counterpart of passing {@code features} and {@code
     * bit_length} to the Python {@code encrypt_decision_tree_input}.
     *
     * @param features the features, each in {@code [0, 2^bitLength)}
     * @param bitLength the number of bits of features and thresholds
     * @return the encrypted features, to be sent to the tree owner
     * @throws IllegalArgumentException when no public key is available, or when the scheme does not
     *     support it
     */
    public List<List<BigInteger>> encryptDecisionTreeFeatures(List<Long> features, int bitLength) {
        requirePublicKey("encryption");
        return cs.encryptDecisionTreeFeatures(features, bitLength);
    }

    /**
     * Compares encrypted features with the thresholds of all decision nodes. 2nd step of private
     * decision tree evaluation, runs on server side. Only supported by Damgard-Geisler-Kroigaard.
     *
     * @param tree the decision tree
     * @param encryptedFeatures the output of {@link #encryptDecisionTreeFeatures}
     * @return the encrypted comparisons to be sent to the client, and the server state that must be
     *     kept secret on server side for the 4th step
     * @throws IllegalArgumentException when no public key is available, or when the scheme does not
     *     support it
     */
    public NumericDecisionTree.Comparisons evaluateDecisionTreeComparisons(
            NumericDecisionTree tree, List<List<BigInteger>> encryptedFeatures) {
        requirePublicKey("decision tree evaluation");
        return cs.evaluateDecisionTreeComparisons(tree, encryptedFeatures);
    }

    /**
     * Answers the server's comparisons in encrypted form. Comparisons are randomly flipped by the
     * server, so the client does not learn the path in the tree. 3rd step of private decision tree
     * evaluation, runs on client side. Only supported by Damgard-Geisler-Kroigaard.
     *
     * @param encryptedComparisons the encrypted comparisons of {@link
     *     #evaluateDecisionTreeComparisons}
     * @return the encrypted answers, to be sent to the server
     * @throws IllegalArgumentException when the private key is missing, or when the scheme does not
     *     support it
     */
    public List<BigInteger> answerDecisionTreeComparisons(
            List<List<BigInteger>> encryptedComparisons) {
        requirePrivateKey("perform decryption");
        return cs.answerDecisionTreeComparisons(encryptedComparisons);
    }

    /**
     * Finds the reached leaf in encrypted form. 4th step of private decision tree evaluation, runs
     * on server side. Only supported by Damgard-Geisler-Kroigaard.
     *
     * @param serverState the server state of {@link #evaluateDecisionTreeComparisons}
     * @param encryptedAnswers the output of {@link #answerDecisionTreeComparisons}
     * @return the encrypted leaves, to be sent to the client
     * @throws IllegalArgumentException when no public key is available, or when the scheme does not
     *     support it
     */
    public List<NumericDecisionTree.EncryptedLeaf> evaluateDecisionTreeLeaves(
            NumericDecisionTree.ServerState serverState, List<BigInteger> encryptedAnswers) {
        requirePublicKey("decision tree evaluation");
        return cs.evaluateDecisionTreeLeaves(serverState, encryptedAnswers);
    }

    /**
     * Restores the label of the reached leaf. The client learns only this label. Last step of
     * private decision tree evaluation, runs on client side. Only supported by
     * Damgard-Geisler-Kroigaard.
     *
     * @param encryptedLeaves the output of {@link #evaluateDecisionTreeLeaves}
     * @return the label of the reached leaf
     * @throws IllegalArgumentException when the private key is missing, or when the scheme does not
     *     support it
     */
    public long decryptDecisionTreeOutput(List<NumericDecisionTree.EncryptedLeaf> encryptedLeaves) {
        requirePrivateKey("perform decryption");
        return cs.decryptDecisionTreeOutput(encryptedLeaves);
    }

    // -----------------------------------------------------------------------
    // Secure comparison
    // -----------------------------------------------------------------------

    /**
     * Encrypts the bits of the client's value x to compare it with the server's value y. 1st step
     * of secure comparison, runs on client side. Only supported by Damgard-Geisler-Kroigaard.
     *
     * @param value the client's value x in {@code [0, 2^bitLength)}
     * @param bitLength the number of bits of compared values
     * @return the encrypted input, to be sent to the server
     * @throws IllegalArgumentException when no public key is available, or when the scheme does not
     *     support secure comparison
     */
    public List<BigInteger> encryptComparisonInput(long value, int bitLength) {
        requirePublicKey("encryption");
        return cs.encryptComparisonInput(value, bitLength);
    }

    /**
     * Compares the client's encrypted value x with the server's value y. 2nd step of secure
     * comparison, runs on server side. Private key is not required and the server learns nothing
     * about x. Only supported by Damgard-Geisler-Kroigaard.
     *
     * @param encryptedInput the output of {@link #encryptComparisonInput}
     * @param value the server's value y in {@code [0, 2^bitLength)}
     * @return the encrypted result, to be sent back to the client
     * @throws IllegalArgumentException when no public key is available, or when the scheme does not
     *     support secure comparison
     */
    public List<BigInteger> evaluateComparison(List<BigInteger> encryptedInput, long value) {
        requirePublicKey("secure comparison");
        return cs.evaluateComparison(encryptedInput, value);
    }

    /**
     * Restores the result of a secure comparison. 3rd step of secure comparison, runs on client
     * side. The client learns only whether {@code x <= y}, but not y. Only supported by
     * Damgard-Geisler-Kroigaard.
     *
     * @param encryptedResult the output of {@link #evaluateComparison}
     * @return {@code true} when {@code x <= y}
     * @throws IllegalArgumentException when the private key is missing, or when the scheme does not
     *     support secure comparison
     */
    public boolean decryptComparison(List<BigInteger> encryptedResult) {
        requirePrivateKey("perform decryption");
        return cs.decryptComparison(encryptedResult);
    }

    // -----------------------------------------------------------------------
    // Encrypted argmax
    // -----------------------------------------------------------------------

    /**
     * Finds the index of the maximum of encrypted values without decrypting them. Runs on server
     * side and talks to the client (private key owner) through the client callable. The client
     * learns only the index, and the server learns nothing. Index of the first maximum is returned
     * on ties. Only supported by Damgard-Geisler-Kroigaard.
     *
     * @param encryptedValues the encrypted values in {@code [0, 2^bitLength)}
     * @param bitLength the number of bits of the values
     * @param client sends a message to the client, and returns the output of the client's {@link
     *     #answerArgmax}. Locally, it can be the client's {@code answerArgmax} directly. Otherwise,
     *     wrap your network call with it.
     * @return the encrypted index, to be decrypted by the client
     * @throws IllegalArgumentException when no public key is available, or when the scheme does not
     *     support encrypted argmax
     */
    public Ciphertext evaluateArgmax(
            List<Ciphertext> encryptedValues,
            int bitLength,
            Function<ArgmaxMessage, List<BigInteger>> client) {
        requirePublicKey("encrypted argmax");
        List<BigInteger> values = new ArrayList<>(encryptedValues.size());
        for (Ciphertext value : encryptedValues) {
            values.add(asInteger(value.value()));
        }
        BigInteger output = cs.evaluateArgmax(values, bitLength, client);
        return buildCiphertext(new IntValue(output));
    }

    /**
     * Answers a message of the server during encrypted argmax. Runs on client side. Every value
     * decrypted here is masked with a uniformly random value. Only supported by
     * Damgard-Geisler-Kroigaard.
     *
     * @param message the message of the server
     * @return the answer, to be sent back to the server
     * @throws IllegalArgumentException when the private key is missing, or when the scheme does not
     *     support encrypted argmax
     */
    public List<BigInteger> answerArgmax(ArgmaxMessage message) {
        requirePrivateKey("perform decryption");
        return cs.answerArgmax(message);
    }

    // -----------------------------------------------------------------------
    // Ciphertext utilities
    // -----------------------------------------------------------------------

    /**
     * Generates a different ciphertext belonging to the same plaintext.
     *
     * @param ciphertext the encrypted message
     * @return a re-randomised encryption of the same message
     * @throws IllegalArgumentException when no public key is available, or when the scheme does not
     *     support re-encryption
     */
    public Ciphertext regenerateCiphertext(Ciphertext ciphertext) {
        requirePublicKey("decryption");
        CipherValue regenerated = cs.reencrypt(ciphertext.value());
        return new Ciphertext(algorithmName, cs.keys(), regenerated, form, curve);
    }

    /**
     * Ciphertexts supporting multiplication cannot be regenerated, so this always fails. It exists
     * to report that clearly rather than to leave the overload missing.
     *
     * @param ciphertext the encrypted message
     * @return never returns
     * @throws IllegalArgumentException always
     */
    public CatalanoFioreCiphertext regenerateCiphertext(CatalanoFioreCiphertext ciphertext) {
        throw new IllegalArgumentException(
                "Ciphertexts supporting multiplication cannot be regenerated. "
                        + "Encrypt the plaintext again instead.");
    }

    /**
     * Wraps a bare ciphertext payload in a {@link Ciphertext}, which carries the keys needed to
     * perform homomorphic operations on it.
     *
     * @param ciphertext the ciphertext content
     * @return the wrapped ciphertext
     */
    public Ciphertext createCiphertextObj(CipherValue ciphertext) {
        return new Ciphertext(algorithmName, cs.keys(), ciphertext, form, curve);
    }

    // -----------------------------------------------------------------------
    // Key management
    // -----------------------------------------------------------------------

    /**
     * Exports the keys to a file.
     *
     * @param targetFile the target file
     * @param publicOnly set this to {@code true} when the file will be published; the private key
     *     is then left out
     * @throws UncheckedIOException when the file cannot be written
     */
    public void exportKeys(Path targetFile, boolean publicOnly) {
        Keys exported = publicOnly ? cs.keys().publicOnly() : cs.keys();

        if (!publicOnly) {
            logger.warn(
                    "You did not set public arg to True. So, exported key has private key "
                            + "information.Do not share this to anyone");
        }

        try {
            Files.writeString(targetFile, KeysCodec.toJson(exported), StandardCharsets.UTF_8);
        } catch (IOException err) {
            throw new UncheckedIOException("Failed to export keys to " + targetFile, err);
        }
    }

    /**
     * Exports the private and public keys to a file.
     *
     * @param targetFile the target file
     */
    public void exportKeys(Path targetFile) {
        exportKeys(targetFile, false);
    }

    /**
     * Restores keys from a file.
     *
     * @param targetFile the file to read
     * @return the restored private-public key pair
     * @throws IllegalArgumentException when the file carries neither a public nor a private key
     * @throws UncheckedIOException when the file cannot be read
     */
    public static Keys restoreKeys(Path targetFile) {
        String content;
        try {
            content = Files.readString(targetFile, StandardCharsets.UTF_8);
        } catch (IOException err) {
            throw new UncheckedIOException("Failed to restore keys from " + targetFile, err);
        }

        Keys keys = KeysCodec.fromJson(content);

        if (keys.hasPrivateKey()) {
            logger.info("private-public key pair is restored from " + targetFile);
        } else if (keys.publicKey() != null && !keys.publicKey().isEmpty()) {
            logger.info("public key is restored from " + targetFile);
        } else {
            throw new IllegalArgumentException("File " + targetFile + " must have public_key key");
        }
        return keys;
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    private Ciphertext buildCiphertext(CipherValue value) {
        Homomorphic shared = publicCs;
        if (shared == null) {
            Ciphertext ciphertext =
                    new Ciphertext(algorithmName, cs.keys().publicOnly(), value, form, curve);
            publicCs = ciphertext.cs();
            return ciphertext;
        }
        return Ciphertext.of(shared, value);
    }

    private void requirePublicKey(String operation) {
        requirePublicKeyTo("perform " + operation);
    }

    private void requirePublicKeyTo(String action) {
        if (cs.keys().publicKey() == null || cs.keys().publicKey().isEmpty()) {
            throw new IllegalArgumentException("You must have public key to " + action);
        }
    }

    private void requirePrivateKey(String action) {
        if (!cs.keys().hasPrivateKey()) {
            throw new IllegalArgumentException("You must have private key to " + action);
        }
    }

    private void requireNoBoost() {
        if (catalanoFiore != null) {
            throw new IllegalArgumentException(
                    "Cryptosystem is boosted with "
                            + CatalanoFiore.BOOST_NAME
                            + ". Use encryptBoosted to encrypt ciphertexts supporting one"
                            + " multiplication.");
        }
    }

    private void requireIntegersOnlyBoost() {
        if (catalanoFiore != null) {
            throw new IllegalArgumentException("Catalano-Fiore transform supports integers only");
        }
    }

    private static BigInteger asInteger(CipherValue value) {
        if (!(value instanceof IntValue integer)) {
            throw new IllegalArgumentException(
                    "expected an integer ciphertext, got " + value.getClass().getSimpleName());
        }
        return integer.value();
    }

    private void requireKeysForDecryption() {
        if (!cs.keys().hasPrivateKey()) {
            throw new IllegalArgumentException("You must have private key to perform decryption");
        }
        if (cs.keys().publicKey() == null || cs.keys().publicKey().isEmpty()) {
            throw new IllegalArgumentException("You must have public key to perform decryption");
        }
    }

    /**
     * Encrypts a single tensor item.
     *
     * <p>Integral and real values take different routes: an integer is scaled by {@code
     * 10^precision} after being reduced into the message space, while a real number is fractionised
     * first. Zero gets its own branch because it is very common in embeddings, and re-using the
     * pre-computed encryption of zero saves a modular exponentiation per occurrence.
     *
     * @param value the item to encrypt
     * @param encryptedDivisor the pre-computed encrypted divisor
     * @param cs the cryptosystem itself
     * @param precision how many digits after the decimal point to keep
     * @param encryptedZero the pre-computed encryption of zero
     * @return the encrypted item
     */
    static Fraction encryptFloat(
            Number value,
            CipherValue encryptedDivisor,
            Homomorphic cs,
            int precision,
            CipherValue encryptedZero) {

        BigInteger modulo = cs.plaintextModulo();

        if (value.doubleValue() == 0.0) {
            // this is very common in VGG-Face embeddings
            return Fraction.builder()
                    .dividend(encryptedZero)
                    .divisor(encryptedDivisor)
                    .absDividend(encryptedZero)
                    .sign(1)
                    .build();
        }

        if (isIntegral(value)) {
            BigInteger integral = toBigInteger(value);
            BigInteger scale = BigInteger.TEN.pow(precision);

            CipherValue dividend = cs.encrypt(integral.mod(modulo).multiply(scale));
            CipherValue absDividend =
                    integral.signum() > 0
                            ? dividend
                            : cs.encrypt(integral.abs().mod(modulo).multiply(scale));

            return Fraction.builder()
                    .dividend(dividend)
                    .divisor(encryptedDivisor)
                    .absDividend(absDividend)
                    .sign(integral.signum() >= 0 ? 1 : -1)
                    .build();
        }

        double real = value.doubleValue();
        // reducing the value first avoids "int too large to convert to float" when the security
        // level is high and the modulus no longer fits a double
        double reduced = exceedsModulo(real, modulo) ? real % modulo.doubleValue() : real;
        BigInteger dividendValue = PheUtils.fractionize(reduced, modulo, precision).dividend();

        CipherValue dividend = cs.encrypt(dividendValue);
        CipherValue absDividend;
        if (real > 0) {
            absDividend = dividend;
        } else {
            double magnitude = Math.abs(real);
            double reducedMagnitude =
                    exceedsModulo(magnitude, modulo) ? magnitude % modulo.doubleValue() : magnitude;
            absDividend =
                    cs.encrypt(
                            PheUtils.fractionize(reducedMagnitude, modulo, precision).dividend());
        }

        return Fraction.builder()
                .dividend(dividend)
                .divisor(encryptedDivisor)
                .absDividend(absDividend)
                .sign(real >= 0 ? 1 : -1)
                .build();
    }

    private static boolean exceedsModulo(double value, BigInteger modulo) {
        return new BigDecimal(value).compareTo(new BigDecimal(modulo)) > 0;
    }

    private static boolean isIntegral(Number value) {
        return value instanceof Integer
                || value instanceof Long
                || value instanceof Short
                || value instanceof Byte
                || value instanceof BigInteger;
    }

    private static BigInteger toBigInteger(Number value) {
        return value instanceof BigInteger big ? big : BigInteger.valueOf(value.longValue());
    }
}
