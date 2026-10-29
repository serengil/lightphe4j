package io.github.serengil.lightphe;

import io.github.serengil.lightphe.commons.Classifiers;
import io.github.serengil.lightphe.commons.Json;
import io.github.serengil.lightphe.commons.KeyValidator;
import io.github.serengil.lightphe.commons.Logger;
import io.github.serengil.lightphe.commons.NearestNeighbors;
import io.github.serengil.lightphe.commons.PheUtils;
import io.github.serengil.lightphe.commons.SecureAggregation;
import io.github.serengil.lightphe.commons.Serialization;
import io.github.serengil.lightphe.commons.Threshold;
import io.github.serengil.lightphe.commons.Zkp;
import io.github.serengil.lightphe.cryptosystems.BonehGohNissim;
import io.github.serengil.lightphe.cryptosystems.CryptosystemFactory;
import io.github.serengil.lightphe.cryptosystems.DamgardGeislerKroigaard;
import io.github.serengil.lightphe.cryptosystems.DamgardJurik;
import io.github.serengil.lightphe.cryptosystems.FreemanBonehGohNissim;
import io.github.serengil.lightphe.cryptosystems.GentrySahaiWaters;
import io.github.serengil.lightphe.ecc.CurvePoint;
import io.github.serengil.lightphe.ecc.LightECC;
import io.github.serengil.lightphe.ecc.PointNotOnCurveException;
import io.github.serengil.lightphe.model.Aggregate;
import io.github.serengil.lightphe.model.AggregationLayout;
import io.github.serengil.lightphe.model.Algorithm;
import io.github.serengil.lightphe.model.ArgmaxMessage;
import io.github.serengil.lightphe.model.CatalanoFiore;
import io.github.serengil.lightphe.model.CatalanoFioreCiphertext;
import io.github.serengil.lightphe.model.Ciphertext;
import io.github.serengil.lightphe.model.DecisionTree;
import io.github.serengil.lightphe.model.EncryptedKnnQuery;
import io.github.serengil.lightphe.model.EncryptedTensor;
import io.github.serengil.lightphe.model.EncryptedUpdate;
import io.github.serengil.lightphe.model.Fraction;
import io.github.serengil.lightphe.model.FractionPartialDecryption;
import io.github.serengil.lightphe.model.Homomorphic;
import io.github.serengil.lightphe.model.KeyValue;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.KeysCodec;
import io.github.serengil.lightphe.model.KnnDistances;
import io.github.serengil.lightphe.model.KnnResult;
import io.github.serengil.lightphe.model.NumericDecisionTree;
import io.github.serengil.lightphe.model.PartialDecryption;
import io.github.serengil.lightphe.model.Proof;
import io.github.serengil.lightphe.model.Proven;
import io.github.serengil.lightphe.model.PublicOnlyView;
import io.github.serengil.lightphe.model.VerifiableCiphertext;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.Fp2Value;
import io.github.serengil.lightphe.model.value.IntValue;
import io.github.serengil.lightphe.model.value.PointValue;
import io.github.serengil.lightphe.model.value.TupleValue;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
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

    /** Catalano-Fiore transform restoring deserialized ciphertexts, built on first use. */
    private volatile CatalanoFiore deserializationCatalanoFiore;

    /**
     * Builds a LightPHE cryptosystem.
     *
     * @param algorithmName one of {@code RSA}, {@code ElGamal}, {@code Exponential-ElGamal}, {@code
     *     EllipticCurve-ElGamal}, {@code Paillier}, {@code Damgard-Jurik}, {@code
     *     Okamoto-Uchiyama}, {@code Benaloh}, {@code Naccache-Stern}, {@code Goldwasser-Micali},
     *     {@code Sander-Young-Yung}, {@code Boneh-Goh-Nissim}, {@code Joye-Libert}, {@code
     *     Castagnos-Laguillaumie}, {@code Ishai-Paskin}, {@code Damgard-Geisler-Kroigaard}, {@code
     *     Bresson-Catalano-Pointcheval}, {@code Camenisch-Shoup}, {@code EllipticCurve-Paillier},
     *     {@code Regev}, {@code Brakerski-Vaikuntanathan}, {@code Freeman-Boneh-Goh-Nissim}, {@code
     *     Gentry-Halevi-Vaikuntanathan}, {@code Lyubashevsky-Peikert-Regev}, {@code ML-KEM} or
     *     {@code Gentry-Sahai-Waters}
     * @param keys optional private-public key pair
     * @param keyFile if keys were exported already, the file to load them from
     * @param keySize key size in bits. For Regev, it is the lattice dimension. For
     *     Brakerski-Vaikuntanathan, Lyubashevsky-Peikert-Regev and Gentry-Sahai-Waters, it is the
     *     ring degree. For ML-KEM, it is the parameter set: 512, 768 or 1024. For
     *     Freeman-Boneh-Goh-Nissim, it is the bit length of the field size. For
     *     Gentry-Halevi-Vaikuntanathan, it is the lattice dimension in {@code [2, 8]}.
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
     *     Brakerski-Vaikuntanathan}, {@code Freeman-Boneh-Goh-Nissim}, {@code
     *     Gentry-Halevi-Vaikuntanathan} or {@code Lyubashevsky-Peikert-Regev}.
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
     * @param primeOrder picks the generator of a known prime order while generating keys. Default
     *     is {@code false}. Threshold decryption and zero-knowledge proofs require this. Only used
     *     when {@code algorithmName} is {@code ElGamal} or {@code Exponential-ElGamal}.
     * @param safePrimes generates the modulus as a product of two safe primes. Default is {@code
     *     false}. Proofs of partial decryption in threshold decryption require this. Only used when
     *     {@code algorithmName} is {@code Paillier} or {@code Damgard-Jurik}.
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
            String boost,
            boolean primeOrder,
            boolean safePrimes) {
        this.algorithmName = Algorithm.of(algorithmName);
        this.precision = precision > 0 ? precision : DEFAULT_PRECISION;
        this.form = form;
        this.curve = curve;
        int tries = maxTries > 0 ? maxTries : CryptosystemFactory.DEFAULT_MAX_TRIES;

        Keys resolved = keys;
        if (keyFile != null) {
            resolved = restoreKeys(keyFile);
        }

        if (safePrimes
                && resolved == null
                && (this.algorithmName == Algorithm.PAILLIER
                        || this.algorithmName == Algorithm.DAMGARD_JURIK)) {
            resolved =
                    Threshold.generateSafePaillierKeys(
                            keySize == null ? CryptosystemFactory.DEFAULT_KEY_SIZE : keySize,
                            tries,
                            this.algorithmName == Algorithm.DAMGARD_JURIK
                                    ? DamgardJurik.DEFAULT_S
                                    : null);
        }

        if (resolved != null) {
            KeyValidator.validateKeys(this.algorithmName, resolved);
        }

        this.cs =
                CryptosystemFactory.build(
                        this.algorithmName,
                        new CryptosystemFactory.Options(
                                resolved, keySize, form, curve, plaintextLimit, tries, primeOrder));

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
        if (algorithmName == Algorithm.GENTRY_SAHAI_WATERS
                && !plaintext.equals(BigInteger.ZERO)
                && !plaintext.equals(BigInteger.ONE)) {
            throw new IllegalArgumentException(GentrySahaiWaters.FLOAT_NOT_SUPPORTED_MSG);
        }
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

    // -----------------------------------------------------------------------
    // Threshold decryption
    // -----------------------------------------------------------------------

    /**
     * Splits the private key into shares for threshold decryption. Any threshold many shareholders
     * can decrypt a ciphertext together, but fewer shareholders cannot. Runs on dealer side.
     * Threshold parameters are added into the public key, and the private key is dropped from this
     * cryptosystem afterwards, so export the public key again. Supported by ElGamal,
     * Exponential-ElGamal, EllipticCurve-ElGamal, Paillier and Damgard-Jurik. ElGamal and
     * Exponential-ElGamal keys must be generated with {@code primeOrder = true}.
     *
     * @param threshold minimum number of shareholders required to decrypt
     * @param parties total number of shareholders
     * @return the public key and share of each shareholder. Each item must be sent to its own
     *     shareholder secretly.
     * @throws IllegalArgumentException when a key is missing, the threshold is invalid, or the
     *     scheme does not support threshold decryption
     */
    public List<Keys> generateThresholdKeys(int threshold, int parties) {
        requirePrivateKey("generate threshold keys");
        requirePublicKeyTo("generate threshold keys");
        Threshold.validateThreshold(threshold, parties);

        List<Keys> shareKeys = cs.generateThresholdKeys(threshold, parties);

        // dealer forgets the private key, and public key now has threshold parameters
        cs.keys().removePrivateKey();
        publicCs = null;

        return shareKeys;
    }

    /**
     * Decrypts a ciphertext partially with the share of a shareholder. Partial decryption reveals
     * nothing about the plaintext alone. Runs on shareholder side.
     *
     * @param ciphertext the encrypted message
     * @param prove set this to {@code true} to attach a zero-knowledge proof that the partial
     *     decryption is computed with the share of this shareholder. Supported by ElGamal,
     *     Exponential-ElGamal, EllipticCurve-ElGamal, and Paillier and Damgard-Jurik with keys
     *     generated with {@code safePrimes = true}.
     * @return the partial decryption, to be sent to the combiner
     * @throws IllegalArgumentException when the threshold key is missing
     */
    public PartialDecryption partialDecrypt(Ciphertext ciphertext, boolean prove) {
        requireThresholdKey();
        return cs.partialDecrypt(ciphertext.value(), prove);
    }

    /**
     * Decrypts a ciphertext partially without a proof.
     *
     * @param ciphertext the encrypted message
     * @return the partial decryption, to be sent to the combiner
     */
    public PartialDecryption partialDecrypt(Ciphertext ciphertext) {
        return partialDecrypt(ciphertext, false);
    }

    /**
     * Ciphertexts supporting multiplication do not support threshold decryption, so this always
     * fails. It exists to report that clearly rather than to leave the overload missing.
     *
     * @param ciphertext the encrypted message
     * @param prove ignored
     * @return never returns
     * @throws IllegalArgumentException always
     */
    public PartialDecryption partialDecrypt(CatalanoFioreCiphertext ciphertext, boolean prove) {
        requireThresholdKey();
        throw new IllegalArgumentException(
                "Ciphertexts supporting multiplication do not support threshold decryption");
    }

    /**
     * Decrypts an encrypted tensor partially with the share of a shareholder.
     *
     * @param encryptedTensor the encrypted tensor
     * @param prove set this to {@code true} to attach zero-knowledge proofs
     * @return the partial decryptions of each item, to be sent to the combiner
     * @throws IllegalArgumentException when the threshold key is missing
     */
    public List<FractionPartialDecryption> partialDecryptTensor(
            EncryptedTensor encryptedTensor, boolean prove) {
        requireThresholdKey();
        List<FractionPartialDecryption> partials = new ArrayList<>();
        for (Fraction fraction : encryptedTensor.fractions()) {
            partials.add(
                    new FractionPartialDecryption(
                            cs.partialDecrypt(fraction.absDividend(), prove),
                            cs.partialDecrypt(fraction.divisor(), prove)));
        }
        return partials;
    }

    /**
     * Restores the plaintext from partial decryptions of at least threshold many shareholders.
     * Public key is enough, so anyone can combine them.
     *
     * @param ciphertext the encrypted message
     * @param partialDecryptions outputs of {@link #partialDecrypt} of shareholders
     * @param verify set this to {@code true} to check zero-knowledge proofs of partial decryptions,
     *     and discard invalid or unproven ones. Otherwise, a cheating shareholder can cause a wrong
     *     plaintext silently.
     * @return the restored message
     * @throws IllegalArgumentException when there are not enough valid partial decryptions
     */
    public BigInteger combinePartialDecryptions(
            Ciphertext ciphertext, List<PartialDecryption> partialDecryptions, boolean verify) {
        requirePublicKeyTo("combine partial decryptions");
        return cs.combinePartialDecryptions(ciphertext.value(), partialDecryptions, verify);
    }

    /**
     * Restores the plaintext from partial decryptions without checking their proofs.
     *
     * @param ciphertext the encrypted message
     * @param partialDecryptions outputs of {@link #partialDecrypt} of shareholders
     * @return the restored message
     */
    public BigInteger combinePartialDecryptions(
            Ciphertext ciphertext, List<PartialDecryption> partialDecryptions) {
        return combinePartialDecryptions(ciphertext, partialDecryptions, false);
    }

    /**
     * Restores an encrypted tensor from partial decryptions of at least threshold many
     * shareholders.
     *
     * @param encryptedTensor the encrypted tensor
     * @param partialDecryptions outputs of {@link #partialDecryptTensor} of shareholders
     * @param verify set this to {@code true} to check zero-knowledge proofs of partial decryptions
     * @return the restored values
     */
    public List<Double> combineTensorPartialDecryptions(
            EncryptedTensor encryptedTensor,
            List<List<FractionPartialDecryption>> partialDecryptions,
            boolean verify) {
        requirePublicKeyTo("combine partial decryptions");
        List<Double> plainTensor = new ArrayList<>();
        List<Fraction> fractions = encryptedTensor.fractions();
        for (int k = 0; k < fractions.size(); k++) {
            Fraction fraction = fractions.get(k);
            List<PartialDecryption> absDividends = new ArrayList<>();
            List<PartialDecryption> divisors = new ArrayList<>();
            for (List<FractionPartialDecryption> partials : partialDecryptions) {
                absDividends.add(partials.get(k).absDividend());
                divisors.add(partials.get(k).divisor());
            }
            BigInteger absDividend =
                    cs.combinePartialDecryptions(fraction.absDividend(), absDividends, verify);
            BigInteger divisor = cs.combinePartialDecryptions(fraction.divisor(), divisors, verify);
            plainTensor.add(
                    new BigDecimal(absDividend)
                            .divide(new BigDecimal(divisor), DIVISION_CONTEXT)
                            .multiply(BigDecimal.valueOf(fraction.sign()))
                            .doubleValue());
        }
        return plainTensor;
    }

    /**
     * Verifies that a partial decryption is computed with the share of its shareholder. Public key
     * is enough. Partial decryption must be created with a proof. {@link
     * #combinePartialDecryptions} does this if verify is set and discards invalid ones, so this is
     * useful to find a cheating shareholder.
     *
     * @param ciphertext the encrypted message
     * @param partialDecryption the output of {@link #partialDecrypt}
     * @return {@code true} when the partial decryption is proven to be correct
     */
    public boolean verifyPartialDecryption(
            Ciphertext ciphertext, PartialDecryption partialDecryption) {
        requirePublicKeyTo("verify partial decryption");
        return cs.verifyPartialDecryption(ciphertext.value(), partialDecryption);
    }

    // -----------------------------------------------------------------------
    // Zero-knowledge proofs
    // -----------------------------------------------------------------------

    /**
     * Decrypts a ciphertext and proves that the decryption is correct, without revealing the
     * private key. Runs on private key owner side, e.g. a tallying authority announcing the result
     * of an election. Supported by ElGamal, Exponential-ElGamal (keys generated with {@code
     * primeOrder = true}), EllipticCurve-ElGamal, Paillier and Damgard-Jurik.
     *
     * @param ciphertext the encrypted message
     * @return the restored message, same as {@link #decrypt(Ciphertext)}, and the proof of correct
     *     decryption to be shared with the verifier
     */
    public Proven<BigInteger> decryptWithProof(Ciphertext ciphertext) {
        requirePrivateKey("perform decryption");
        requirePublicKeyTo("perform decryption");
        return cs.decryptWithProof(ciphertext.value());
    }

    /**
     * Verifies that a ciphertext is decrypted to the given plaintext. Public key is enough, so
     * anyone can check the announced plaintext.
     *
     * @param ciphertext the encrypted message
     * @param plaintext the claimed plaintext
     * @param proof the output of {@link #decryptWithProof}
     * @return {@code true} when the proof is valid
     */
    public boolean verifyDecryption(Ciphertext ciphertext, BigInteger plaintext, Proof proof) {
        requirePublicKeyTo("verify decryption");
        return cs.verifyDecryption(ciphertext.value(), plaintext, proof);
    }

    /**
     * Verifies that a ciphertext is decrypted to the given plaintext.
     *
     * @param ciphertext the encrypted message
     * @param plaintext the claimed plaintext
     * @param proof the output of {@link #decryptWithProof}
     * @return {@code true} when the proof is valid
     */
    public boolean verifyDecryption(Ciphertext ciphertext, long plaintext, Proof proof) {
        return verifyDecryption(ciphertext, BigInteger.valueOf(plaintext), proof);
    }

    /**
     * Encrypts a plaintext and proves that it is one of the allowed values, without revealing which
     * one. For instance, a voter proves that the encrypted vote is 0 or 1, so cannot cheat with a
     * vote of 100 in the homomorphic tally. Public key is enough. Supported by Exponential-ElGamal
     * (keys generated with {@code primeOrder = true}), EllipticCurve-ElGamal, Paillier and
     * Damgard-Jurik.
     *
     * @param plaintext the message to encrypt, one of values
     * @param values the allowed values; {@code null} defaults to {@code [0, 1]}
     * @param context public data bound to the proof, e.g. id of the voter, so that the proof cannot
     *     be copied for another context. A string, number, boolean, list or map of them, or {@code
     *     null}.
     * @return the ciphertext and the proof that it encrypts one of values
     * @throws IllegalArgumentException when the plaintext is not one of the allowed values
     */
    public Proven<Ciphertext> encryptWithProof(
            BigInteger plaintext, List<? extends Number> values, Object context) {
        requirePublicKey("encryption");
        List<BigInteger> normalized = normalizeValues(values);
        BigInteger message = PheUtils.normalizeInput(plaintext, cs.plaintextModulo());
        if (!normalized.contains(message)) {
            throw new IllegalArgumentException("Plaintext must be one of the allowed values");
        }
        Proven<CipherValue> proven = cs.encryptWithProof(message, normalized, context);
        return new Proven<>(buildCiphertext(proven.value()), proven.proof());
    }

    /**
     * Encrypts a plaintext and proves that it is one of the allowed values.
     *
     * @param plaintext the message to encrypt, one of values
     * @param values the allowed values; {@code null} defaults to {@code [0, 1]}
     * @param context public data bound to the proof
     * @return the ciphertext and the proof that it encrypts one of values
     */
    public Proven<Ciphertext> encryptWithProof(
            long plaintext, List<? extends Number> values, Object context) {
        return encryptWithProof(BigInteger.valueOf(plaintext), values, context);
    }

    /**
     * Encrypts a plaintext and proves that it is 0 or 1, without a context.
     *
     * @param plaintext the message to encrypt, 0 or 1
     * @return the ciphertext and the proof that it encrypts 0 or 1
     */
    public Proven<Ciphertext> encryptWithProof(long plaintext) {
        return encryptWithProof(plaintext, null, null);
    }

    /**
     * Verifies that a ciphertext encrypts one of the allowed values without decrypting it. Public
     * key is enough, e.g. anyone can check the ballots of an election.
     *
     * @param ciphertext the encrypted message
     * @param proof the output of {@link #encryptWithProof}
     * @param values the allowed values; {@code null} defaults to {@code [0, 1]}
     * @param context public data that the proof is expected to be bound to
     * @return {@code true} when the proof is valid
     */
    public boolean verifyCiphertext(
            Ciphertext ciphertext, Proof proof, List<? extends Number> values, Object context) {
        requirePublicKeyTo("verify ciphertext");
        List<BigInteger> normalized = normalizeValues(values);
        if (ciphertext == null) {
            return false;
        }
        return cs.verifyCiphertext(ciphertext.value(), proof, normalized, context);
    }

    /**
     * Verifies that a ciphertext encrypts 0 or 1, with a proof created without a context.
     *
     * @param ciphertext the encrypted message
     * @param proof the output of {@link #encryptWithProof}
     * @return {@code true} when the proof is valid
     */
    public boolean verifyCiphertext(Ciphertext ciphertext, Proof proof) {
        return verifyCiphertext(ciphertext, proof, null, null);
    }

    /**
     * Encrypts a plaintext and proves that the encryptor knows it, without revealing it. For
     * instance, a bidder of a sealed-bid auction proves knowledge of the bid, so nobody can outbid
     * by copying someone else's encrypted bid and adding 1 to it homomorphically. Public key is
     * enough. Supported by ElGamal and Exponential-ElGamal (keys generated with {@code primeOrder =
     * true}), EllipticCurve-ElGamal, Paillier and Damgard-Jurik.
     *
     * @param plaintext the message to encrypt
     * @param context public data bound to the proof, e.g. id of the encryptor, so that the proof
     *     cannot be copied for another context
     * @return the ciphertext and the proof of knowledge of the plaintext
     */
    public Proven<Ciphertext> encryptWithProofOfKnowledge(BigInteger plaintext, Object context) {
        requirePublicKey("encryption");
        Proven<CipherValue> proven =
                cs.encryptWithProofOfKnowledge(
                        PheUtils.normalizeInput(plaintext, cs.plaintextModulo()), context);
        return new Proven<>(buildCiphertext(proven.value()), proven.proof());
    }

    /**
     * Encrypts a plaintext and proves that the encryptor knows it.
     *
     * @param plaintext the message to encrypt
     * @param context public data bound to the proof
     * @return the ciphertext and the proof of knowledge of the plaintext
     */
    public Proven<Ciphertext> encryptWithProofOfKnowledge(long plaintext, Object context) {
        return encryptWithProofOfKnowledge(BigInteger.valueOf(plaintext), context);
    }

    /**
     * Encrypts a plaintext and proves that the encryptor knows it, without a context.
     *
     * @param plaintext the message to encrypt
     * @return the ciphertext and the proof of knowledge of the plaintext
     */
    public Proven<Ciphertext> encryptWithProofOfKnowledge(long plaintext) {
        return encryptWithProofOfKnowledge(plaintext, null);
    }

    /**
     * Verifies that the encryptor of a ciphertext knows its plaintext without decrypting it. Public
     * key is enough.
     *
     * @param ciphertext the encrypted message
     * @param proof the output of {@link #encryptWithProofOfKnowledge}
     * @param context public data that the proof is expected to be bound to
     * @return {@code true} when the proof is valid
     */
    public boolean verifyKnowledge(Ciphertext ciphertext, Proof proof, Object context) {
        requirePublicKeyTo("verify knowledge");
        if (ciphertext == null) {
            return false;
        }
        return cs.verifyKnowledge(ciphertext.value(), proof, context);
    }

    /**
     * Verifies that the encryptor of a ciphertext knows its plaintext, with a proof created without
     * a context.
     *
     * @param ciphertext the encrypted message
     * @param proof the output of {@link #encryptWithProofOfKnowledge}
     * @return {@code true} when the proof is valid
     */
    public boolean verifyKnowledge(Ciphertext ciphertext, Proof proof) {
        return verifyKnowledge(ciphertext, proof, null);
    }

    /**
     * Encrypts a choice among options as a one-hot vector, i.e. 1 for the chosen option and 0 for
     * others, and proves that exactly one option is chosen without revealing which one. For
     * instance, a voter votes for one of many parties. Summing slots of all ballots homomorphically
     * counts votes of each option separately, so the number of options is not limited. Public key
     * is enough. Supported by Exponential-ElGamal (keys generated with {@code primeOrder = true}),
     * EllipticCurve-ElGamal, Paillier and Damgard-Jurik.
     *
     * @param choice index of the chosen option in {@code [0, options)}
     * @param options number of options
     * @param context public data bound to the proof, e.g. id of the voter
     * @return the encrypted slots, one per option, and the proof that slots are 0 or 1 and sum to 1
     */
    public Proven<List<Ciphertext>> encryptOneHot(int choice, int options, Object context) {
        requirePublicKey("encryption");
        if (options < 1) {
            throw new IllegalArgumentException("Number of options must be at least 1");
        }
        if (choice < 0 || choice >= options) {
            throw new IllegalArgumentException("Choice must be in [0, " + options + ")");
        }
        if (!cs.supportsMembershipProofs()) {
            throw new IllegalArgumentException(
                    algorithmName
                            + " does not support proving that a ciphertext encrypts one of given"
                            + " values");
        }

        Proven<List<CipherValue>> proven =
                Zkp.proveOneHot(cs, choice, options, normalizeValues(List.of(0, 1)), context);
        List<Ciphertext> ciphertexts = new ArrayList<>(options);
        for (CipherValue value : proven.value()) {
            ciphertexts.add(buildCiphertext(value));
        }
        return new Proven<>(ciphertexts, proven.proof());
    }

    /**
     * Verifies that encrypted slots are a one-hot vector, i.e. exactly one option is chosen,
     * without decrypting them. Public key is enough.
     *
     * @param ciphertexts the encrypted slots, one per option
     * @param proof the output of {@link #encryptOneHot}
     * @param context public data that the proof is expected to be bound to
     * @return {@code true} when the proof is valid
     */
    public boolean verifyOneHot(List<Ciphertext> ciphertexts, Proof proof, Object context) {
        requirePublicKeyTo("verify one-hot ciphertexts");
        if (ciphertexts == null || hasNull(ciphertexts)) {
            return false;
        }
        return Zkp.verifyOneHot(
                cs,
                ciphertexts.stream().map(Ciphertext::value).toList(),
                proof,
                normalizeValues(List.of(0, 1)),
                context);
    }

    /**
     * Encrypts a plaintext and proves that it is in {@code [low, high]}, without revealing it. For
     * instance, an employee proves that the encrypted salary is in a sensible range, so cannot skew
     * the average of salaries with a negative or huge value. Public key is enough. Supported by
     * Exponential-ElGamal (keys generated with {@code primeOrder = true}), EllipticCurve-ElGamal,
     * Paillier and Damgard-Jurik. Proof size grows with the bit length of {@code high - low}.
     *
     * @param plaintext the message to encrypt in {@code [low, high]}
     * @param low lower bound of the range
     * @param high upper bound of the range
     * @param context public data bound to the proof, e.g. id of the employee
     * @return the ciphertext and the proof that it encrypts a value in {@code [low, high]}
     */
    public Proven<Ciphertext> encryptWithRangeProof(
            BigInteger plaintext, BigInteger low, BigInteger high, Object context) {
        requirePublicKey("encryption");
        List<BigInteger> values = normalizeRange(low, high);
        if (plaintext.compareTo(low) < 0 || plaintext.compareTo(high) > 0) {
            throw new IllegalArgumentException("Plaintext must be in [" + low + ", " + high + "]");
        }
        Proven<CipherValue> proven = Zkp.proveRange(cs, plaintext, low, high, values, context);
        return new Proven<>(buildCiphertext(proven.value()), proven.proof());
    }

    /**
     * Encrypts a plaintext and proves that it is in {@code [low, high]}.
     *
     * @param plaintext the message to encrypt in {@code [low, high]}
     * @param low lower bound of the range
     * @param high upper bound of the range
     * @param context public data bound to the proof
     * @return the ciphertext and the proof that it encrypts a value in {@code [low, high]}
     */
    public Proven<Ciphertext> encryptWithRangeProof(
            long plaintext, long low, long high, Object context) {
        return encryptWithRangeProof(
                BigInteger.valueOf(plaintext),
                BigInteger.valueOf(low),
                BigInteger.valueOf(high),
                context);
    }

    /**
     * Verifies that a ciphertext encrypts a value in {@code [low, high]} without decrypting it.
     * Public key is enough.
     *
     * @param ciphertext the encrypted message
     * @param proof the output of {@link #encryptWithRangeProof}
     * @param low lower bound of the range
     * @param high upper bound of the range
     * @param context public data that the proof is expected to be bound to
     * @return {@code true} when the proof is valid
     */
    public boolean verifyRange(
            Ciphertext ciphertext, Proof proof, BigInteger low, BigInteger high, Object context) {
        requirePublicKeyTo("verify range");
        List<BigInteger> values = normalizeRange(low, high);
        if (ciphertext == null) {
            return false;
        }
        return Zkp.verifyRange(cs, ciphertext.value(), proof, low, high, values, context);
    }

    /**
     * Verifies that a ciphertext encrypts a value in {@code [low, high]}.
     *
     * @param ciphertext the encrypted message
     * @param proof the output of {@link #encryptWithRangeProof}
     * @param low lower bound of the range
     * @param high upper bound of the range
     * @param context public data that the proof is expected to be bound to
     * @return {@code true} when the proof is valid
     */
    public boolean verifyRange(
            Ciphertext ciphertext, Proof proof, long low, long high, Object context) {
        return verifyRange(
                ciphertext, proof, BigInteger.valueOf(low), BigInteger.valueOf(high), context);
    }

    /** Validates bounds of a range proof, and normalizes low, 0 and 1 as encrypt does. */
    private List<BigInteger> normalizeRange(BigInteger low, BigInteger high) {
        if (low == null || high == null) {
            throw new IllegalArgumentException("Bounds of the range must be integers");
        }
        if (low.compareTo(high) > 0) {
            throw new IllegalArgumentException(
                    "Lower bound " + low + " must not be greater than upper bound " + high);
        }
        if (high.subtract(low).compareTo(cs.plaintextModulo()) >= 0) {
            throw new IllegalArgumentException("Range must be narrower than the plaintext modulo");
        }
        BigInteger modulo = cs.plaintextModulo();
        return List.of(
                PheUtils.normalizeInput(low, modulo),
                PheUtils.normalizeInput(BigInteger.ZERO, modulo),
                PheUtils.normalizeInput(BigInteger.ONE, modulo));
    }

    /** Validates allowed values of a proof and normalizes them as encrypt does. */
    private List<BigInteger> normalizeValues(List<? extends Number> values) {
        List<? extends Number> allowed = values == null ? List.of(0, 1) : values;
        if (allowed.isEmpty()) {
            throw new IllegalArgumentException(
                    "Allowed values must be a non-empty list of integers");
        }
        List<BigInteger> normalized = new ArrayList<>(allowed.size());
        for (Number value : allowed) {
            if (!isIntegral(value)) {
                throw new IllegalArgumentException(
                        "Allowed values must be a non-empty list of integers");
            }
            normalized.add(PheUtils.normalizeInput(toBigInteger(value), cs.plaintextModulo()));
        }
        if (new HashSet<>(normalized).size() != normalized.size()) {
            throw new IllegalArgumentException("Allowed values must be distinct");
        }
        return normalized;
    }

    private void requireThresholdKey() {
        if (cs.keys().thresholdKey() == null) {
            throw new IllegalArgumentException(
                    "You must have threshold key to perform partial decryption");
        }
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
    // Encrypted k nearest neighbor search
    // -----------------------------------------------------------------------

    /**
     * Encrypts a query vector for encrypted k nearest neighbor search. Runs on client side, e.g. a
     * user searching a face embedding in the gallery of a server. Embeddings must be quantized to
     * integers, e.g. by scaling and rounding. Only supported by Damgard-Geisler-Kroigaard.
     *
     * @param query the query vector
     * @return the encrypted query, to be sent to the server
     */
    public EncryptedKnnQuery encryptKnnQuery(List<Long> query) {
        requirePublicKey("encryption");
        requireKnnSupport();
        if (query == null || query.isEmpty() || hasNull(query)) {
            throw new IllegalArgumentException("Query must be a non-empty list of integers");
        }
        NearestNeighbors.Query encrypted = NearestNeighbors.encryptQuery(cs, query);
        List<Ciphertext> entries = new ArrayList<>(encrypted.query().size());
        for (CipherValue value : encrypted.query()) {
            entries.add(buildCiphertext(value));
        }
        return new EncryptedKnnQuery(entries, buildCiphertext(encrypted.norm()));
    }

    /**
     * Finds the k nearest vectors of a database to an encrypted query by squared euclidean
     * distance. Runs on server side and talks to the client (private key owner) through the client
     * callable. Server learns nothing, and client learns only the indices, or the labels, of the k
     * nearest vectors, but not the distances or the other vectors. Earlier index is returned on
     * ties. Only supported by Damgard-Geisler-Kroigaard.
     *
     * @param encryptedQuery the output of {@link #encryptKnnQuery}
     * @param database vectors of the server, in plain
     * @param k number of nearest vectors to find
     * @param bitLength squared distances between the query and vectors must be less than {@code
     *     2^bitLength}, e.g. 24 for 128-dimensional embeddings of 8-bit entries
     * @param client sends a message to the client, and returns the output of the client's {@link
     *     #answerKnn}. Locally, it can be the client's {@code answerKnn} directly. Otherwise, wrap
     *     your network call with it.
     * @param labels optional labels of vectors, e.g. ids of people, or {@code null}. If set,
     *     encrypted labels of the nearest vectors are returned as well.
     * @return the encrypted indices, and labels if set, of the k nearest vectors from the nearest
     *     one, to be decrypted by the client
     */
    public KnnResult evaluateKnn(
            EncryptedKnnQuery encryptedQuery,
            List<List<Long>> database,
            int k,
            int bitLength,
            Function<ArgmaxMessage, List<BigInteger>> client,
            List<Long> labels) {
        requirePublicKey("encrypted nearest neighbor search");
        requireKnnSupport();

        if (encryptedQuery == null || encryptedQuery.query().isEmpty()) {
            throw new IllegalArgumentException(
                    "Encrypted query must be an output of encryptKnnQuery");
        }
        int dimension = encryptedQuery.query().size();
        if (database == null || database.isEmpty()) {
            throw new IllegalArgumentException("Database must be a non-empty list of vectors");
        }
        for (List<Long> vector : database) {
            if (vector == null || vector.size() != dimension || hasNull(vector)) {
                throw new IllegalArgumentException(
                        "Every vector of the database must be a list of "
                                + dimension
                                + " integers");
            }
        }
        if (k < 1 || k > database.size()) {
            throw new IllegalArgumentException("k must be in [1, " + database.size() + "]");
        }
        if (labels != null && (labels.size() != database.size() || hasNull(labels))) {
            throw new IllegalArgumentException(
                    "Labels must be a list of integers, one for each vector");
        }
        if (bitLength < 1) {
            throw new IllegalArgumentException("Bit length must be a positive integer");
        }
        // argmax validates that lifted values fit into the plaintext space
        BigInteger largestNorm = BigInteger.ZERO;
        for (List<Long> vector : database) {
            BigInteger norm = BigInteger.ZERO;
            for (long x : vector) {
                norm = norm.add(BigInteger.valueOf(x).pow(2));
            }
            largestNorm = largestNorm.max(norm);
        }
        if (largestNorm.bitLength() > bitLength) {
            throw new IllegalArgumentException(
                    "Squared norm "
                            + largestNorm
                            + " of a vector in the database does not fit into "
                            + bitLength
                            + " bits");
        }

        NearestNeighbors.Result result =
                NearestNeighbors.evaluateKnn(
                        cs,
                        new NearestNeighbors.Query(
                                encryptedQuery.query().stream().map(Ciphertext::value).toList(),
                                encryptedQuery.norm().value()),
                        database,
                        k,
                        bitLength,
                        client,
                        labels);

        List<Ciphertext> indices = new ArrayList<>(result.indices().size());
        for (CipherValue value : result.indices()) {
            indices.add(buildCiphertext(value));
        }
        List<Ciphertext> foundLabels = new ArrayList<>();
        if (result.labels() != null) {
            for (CipherValue value : result.labels()) {
                foundLabels.add(buildCiphertext(value));
            }
        }
        return new KnnResult(indices, foundLabels);
    }

    /**
     * Finds the k nearest vectors of a database to an encrypted query, without labels.
     *
     * @param encryptedQuery the output of {@link #encryptKnnQuery}
     * @param database vectors of the server, in plain
     * @param k number of nearest vectors to find
     * @param bitLength squared distances must be less than {@code 2^bitLength}
     * @param client sends a message to the client, and returns its answer
     * @return the encrypted indices of the k nearest vectors from the nearest one
     */
    public KnnResult evaluateKnn(
            EncryptedKnnQuery encryptedQuery,
            List<List<Long>> database,
            int k,
            int bitLength,
            Function<ArgmaxMessage, List<BigInteger>> client) {
        return evaluateKnn(encryptedQuery, database, k, bitLength, client, null);
    }

    /**
     * Answers a message of the server during encrypted k nearest neighbor search. Runs on client
     * side. Every value decrypted here is masked or shuffled, so client learns nothing but the
     * final result. Only supported by Damgard-Geisler-Kroigaard.
     *
     * @param message the message of the server
     * @return the answer, to be sent back to the server
     */
    public List<BigInteger> answerKnn(ArgmaxMessage message) {
        requirePrivateKey("perform decryption");
        requireKnnSupport();
        return NearestNeighbors.answerKnn((DamgardGeislerKroigaard) cs, message);
    }

    /**
     * Computes encrypted squared euclidean distances between an encrypted query and encrypted
     * vectors. Runs on the side of an untrusted cloud storing the encrypted database of an owner,
     * and requires the public key only. Both the query and the vectors are encrypted, so this
     * requires the Catalano-Fiore boost for one multiplication. Cloud learns nothing, and the owner
     * finds the nearest vectors with {@link #decryptKnn}.
     *
     * @param encryptedQuery the encrypted query vector
     * @param encryptedDatabase the encrypted vectors
     * @return one encrypted distance for each vector
     */
    public List<CatalanoFioreCiphertext> evaluateKnnDistances(
            List<CatalanoFioreCiphertext> encryptedQuery,
            List<List<CatalanoFioreCiphertext>> encryptedDatabase) {
        requirePublicKeyTo("compute encrypted distances");
        if (catalanoFiore == null) {
            throw new IllegalArgumentException(
                    "Encrypted distances between encrypted vectors require boost = \""
                            + CatalanoFiore.BOOST_NAME
                            + "\"");
        }
        if (!isEncryptedVector(encryptedQuery)) {
            throw new IllegalArgumentException(
                    "Encrypted query must be a non-empty list of encrypted integers");
        }
        if (encryptedDatabase == null || encryptedDatabase.isEmpty()) {
            throw new IllegalArgumentException(
                    "Encrypted database must be a non-empty list of vectors");
        }
        for (List<CatalanoFioreCiphertext> vector : encryptedDatabase) {
            if (!isEncryptedVector(vector) || vector.size() != encryptedQuery.size()) {
                throw new IllegalArgumentException(
                        "Every vector of the database must be a list of "
                                + encryptedQuery.size()
                                + " encrypted integers");
            }
        }

        List<CatalanoFioreCiphertext> distances = new ArrayList<>(encryptedDatabase.size());
        for (List<CatalanoFioreCiphertext> vector : encryptedDatabase) {
            CatalanoFioreCiphertext total = null;
            for (int i = 0; i < vector.size(); i++) {
                CatalanoFioreCiphertext difference = encryptedQuery.get(i).subtract(vector.get(i));
                CatalanoFioreCiphertext square = difference.multiply(difference);
                total = total == null ? square : total.add(square);
            }
            distances.add(total);
        }
        return distances;
    }

    private static boolean isEncryptedVector(List<CatalanoFioreCiphertext> vector) {
        return vector != null
                && !vector.isEmpty()
                && vector.stream().allMatch(c -> c != null && !c.isMultiplied());
    }

    /**
     * Finds the k nearest vectors from encrypted distances computed by {@link
     * #evaluateKnnDistances}. Runs on owner side, and requires the private key.
     *
     * @param encryptedDistances the output of {@link #evaluateKnnDistances}
     * @param k number of nearest vectors to find
     * @return the indices and distances of the k nearest vectors from the nearest one. Earlier
     *     index is returned on ties.
     */
    public KnnDistances decryptKnn(List<CatalanoFioreCiphertext> encryptedDistances, int k) {
        requirePrivateKey("perform decryption");
        if (encryptedDistances == null || encryptedDistances.isEmpty()) {
            throw new IllegalArgumentException("Encrypted distances must be a non-empty list");
        }
        if (k < 1 || k > encryptedDistances.size()) {
            throw new IllegalArgumentException(
                    "k must be in [1, " + encryptedDistances.size() + "]");
        }

        List<BigInteger> distances = new ArrayList<>(encryptedDistances.size());
        for (CatalanoFioreCiphertext ciphertext : encryptedDistances) {
            distances.add(decrypt(ciphertext));
        }
        List<Integer> indices =
                IntStream.range(0, distances.size())
                        .boxed()
                        .sorted(Comparator.comparing(distances::get))
                        .limit(k)
                        .toList();
        return new KnnDistances(indices, indices.stream().map(distances::get).toList());
    }

    private void requireKnnSupport() {
        if (algorithmName != Algorithm.DAMGARD_GEISLER_KROIGAARD) {
            throw new IllegalArgumentException(
                    algorithmName
                            + " does not support encrypted nearest neighbor search."
                            + " Use Damgard-Geisler-Kroigaard instead.");
        }
    }

    // -----------------------------------------------------------------------
    // Secure aggregation
    // -----------------------------------------------------------------------

    /**
     * Encrypts a model update of a client for secure aggregation in federated learning. Values are
     * quantized with the precision of this cryptosystem, and many of them are packed into a single
     * ciphertext, so an update needs far fewer ciphertexts than its length. Public key is enough.
     * Clients must use the same key, length, precision, maximum value and maximum number of
     * clients. Supported by Paillier and Damgard-Jurik.
     *
     * @param update the model update, e.g. gradients or weights
     * @param maxValue absolute values of the update must be at most this, e.g. the clipping bound
     *     of gradients
     * @param maxClients maximum number of updates to be aggregated. Slots of ciphertexts are wide
     *     enough to sum this many updates without overflow.
     * @return the encrypted update
     */
    public EncryptedUpdate encryptUpdate(
            List<? extends Number> update, Number maxValue, int maxClients) {
        requirePublicKey("encryption");
        requireAggregationSupport();
        if (update == null) {
            throw new IllegalArgumentException("Update must be a list of numbers");
        }

        AggregationLayout layout =
                SecureAggregation.buildLayout(
                        update.size(), precision, maxValue, maxClients, cs.plaintextModulo());
        List<Ciphertext> chunks = new ArrayList<>();
        for (BigInteger plaintext : SecureAggregation.pack(update, layout)) {
            chunks.add(buildCiphertext(cs.encrypt(plaintext)));
        }
        return new EncryptedUpdate(chunks, layout, 1);
    }

    /**
     * Sums encrypted updates of clients chunk by chunk. Runs on server side, and requires the
     * public key only. Server learns nothing about updates or their sum.
     *
     * @param encryptedUpdates outputs of {@link #encryptUpdate} or {@link #aggregateUpdates}
     * @return the encrypted sum
     */
    public EncryptedUpdate aggregateUpdates(List<EncryptedUpdate> encryptedUpdates) {
        requirePublicKeyTo("aggregate updates");
        requireAggregationSupport();
        if (encryptedUpdates == null || encryptedUpdates.isEmpty()) {
            throw new IllegalArgumentException("Encrypted updates must be a non-empty list");
        }

        AggregationLayout layout = encryptedUpdates.get(0).layout();
        for (EncryptedUpdate update : encryptedUpdates) {
            if (!update.layout().equals(layout)) {
                throw new IllegalArgumentException(
                        "Encrypted updates must have the same layout, i.e. the same length,"
                                + " precision, maximum value and maximum number of clients");
            }
        }
        int count = encryptedUpdates.stream().mapToInt(EncryptedUpdate::count).sum();
        if (count > layout.maxClients()) {
            throw new IllegalArgumentException(
                    "Sum of "
                            + count
                            + " updates would overflow slots packed for at most "
                            + layout.maxClients()
                            + " clients");
        }

        List<Ciphertext> chunks = new ArrayList<>(encryptedUpdates.get(0).chunks());
        for (EncryptedUpdate update : encryptedUpdates.subList(1, encryptedUpdates.size())) {
            for (int i = 0; i < chunks.size(); i++) {
                chunks.set(i, chunks.get(i).add(update.chunks().get(i)));
            }
        }
        return new EncryptedUpdate(chunks, layout, count);
    }

    /**
     * Decrypts an encrypted sum of updates partially with the share of a shareholder, e.g. a member
     * of a committee of clients. Shareholders decrypt sums only, never individual updates.
     *
     * @param encryptedSum the output of {@link #aggregateUpdates}
     * @param prove set this to {@code true} to attach proofs of correct partial decryption. Keys
     *     must be generated with {@code safePrimes = true}.
     * @return one partial decryption for each chunk, to be sent to the combiner
     */
    public List<PartialDecryption> partialDecryptAggregate(
            EncryptedUpdate encryptedSum, boolean prove) {
        requireAggregationSupport();
        List<PartialDecryption> partials = new ArrayList<>(encryptedSum.chunks().size());
        for (Ciphertext chunk : encryptedSum.chunks()) {
            partials.add(partialDecrypt(chunk, prove));
        }
        return partials;
    }

    /**
     * Restores the sum and the mean of updates from partial decryptions of at least threshold many
     * shareholders. Public key is enough.
     *
     * @param encryptedSum the output of {@link #aggregateUpdates}
     * @param partialDecryptions outputs of {@link #partialDecryptAggregate} of shareholders
     * @param verify set this to {@code true} to check proofs of partial decryptions, and discard
     *     invalid or unproven ones
     * @return the sum and the mean of updates, and the number of updates
     */
    public Aggregate combineAggregate(
            EncryptedUpdate encryptedSum,
            List<List<PartialDecryption>> partialDecryptions,
            boolean verify) {
        requirePublicKeyTo("combine partial decryptions");
        requireAggregationSupport();
        List<BigInteger> plaintexts = new ArrayList<>(encryptedSum.chunks().size());
        for (int i = 0; i < encryptedSum.chunks().size(); i++) {
            List<PartialDecryption> chunkPartials = new ArrayList<>(partialDecryptions.size());
            for (List<PartialDecryption> partials : partialDecryptions) {
                chunkPartials.add(partials.get(i));
            }
            plaintexts.add(
                    cs.combinePartialDecryptions(
                            encryptedSum.chunks().get(i).value(), chunkPartials, verify));
        }
        return unpackAggregate(encryptedSum, plaintexts);
    }

    /**
     * Restores the sum and the mean of updates with the private key, if a single party holds it
     * instead of a committee.
     *
     * @param encryptedSum the output of {@link #aggregateUpdates}
     * @return the sum and the mean of updates, and the number of updates
     */
    public Aggregate decryptAggregate(EncryptedUpdate encryptedSum) {
        requirePrivateKey("perform decryption");
        requireAggregationSupport();
        List<BigInteger> plaintexts = new ArrayList<>(encryptedSum.chunks().size());
        for (Ciphertext chunk : encryptedSum.chunks()) {
            plaintexts.add(cs.decrypt(chunk.value()));
        }
        return unpackAggregate(encryptedSum, plaintexts);
    }

    private Aggregate unpackAggregate(EncryptedUpdate encryptedSum, List<BigInteger> plaintexts) {
        int count = encryptedSum.count();
        List<Double> total = SecureAggregation.unpack(plaintexts, encryptedSum.layout(), count);
        return new Aggregate(total, total.stream().map(x -> x / count).toList(), count);
    }

    private void requireAggregationSupport() {
        if (algorithmName != Algorithm.PAILLIER && algorithmName != Algorithm.DAMGARD_JURIK) {
            throw new IllegalArgumentException(
                    algorithmName
                            + " does not support secure aggregation."
                            + " Use Paillier or Damgard-Jurik instead.");
        }
    }

    // -----------------------------------------------------------------------
    // Encrypted classification
    // -----------------------------------------------------------------------

    /**
     * Classifies encrypted features with a private linear model, i.e. finds the class of the
     * greatest score {@code <w_i, x> + b_i}, e.g. logistic regression or a linear SVM. Runs on
     * server side and talks to the client (private key owner) through the client callable. Client
     * learns only the predicted class, and server learns nothing. Only supported by
     * Damgard-Geisler-Kroigaard.
     *
     * @param encryptedFeatures features encrypted by the client. Floats must be quantized to
     *     integers, e.g. by scaling and rounding.
     * @param weights integer weights of each class
     * @param bitLength absolute values of scores must be less than {@code 2^bitLength}
     * @param client sends a message to the client, and returns the output of the client's {@link
     *     #answerArgmax}
     * @param biases optional integer bias of each class, or {@code null}
     * @return the encrypted index of the predicted class, to be decrypted by the client. Earlier
     *     class is returned on ties.
     */
    public Ciphertext evaluateHyperplane(
            List<Ciphertext> encryptedFeatures,
            List<? extends List<? extends Number>> weights,
            int bitLength,
            Function<ArgmaxMessage, List<BigInteger>> client,
            List<? extends Number> biases) {
        requirePublicKey("encrypted classification");
        requireClassifierSupport();
        Classifiers.validateWeightsShape(weights);
        List<? extends Number> classBiases =
                biases != null ? biases : Collections.nCopies(weights.size(), 0);

        List<List<BigInteger>> integerWeights = new ArrayList<>(weights.size());
        for (List<? extends Number> classWeights : weights) {
            integerWeights.add(toIntegers(classWeights));
        }
        List<BigInteger> integerBiases = toIntegers(classBiases);
        if (integerBiases.size() != weights.size()) {
            throw new IllegalArgumentException("There must be a bias for each class");
        }
        int features = weights.get(0).size();
        if (encryptedFeatures == null
                || encryptedFeatures.size() != features
                || hasNull(encryptedFeatures)) {
            throw new IllegalArgumentException(
                    "Encrypted features must be a list of " + features + " ciphertexts");
        }
        if (bitLength < 1) {
            throw new IllegalArgumentException("Bit length must be a positive integer");
        }

        CipherValue output =
                Classifiers.evaluateHyperplane(
                        cs,
                        encryptedFeatures.stream().map(Ciphertext::value).toList(),
                        integerWeights,
                        integerBiases,
                        bitLength,
                        client);
        return buildCiphertext(output);
    }

    /**
     * Classifies encrypted features with a private linear model without biases.
     *
     * @param encryptedFeatures features encrypted by the client
     * @param weights integer weights of each class
     * @param bitLength absolute values of scores must be less than {@code 2^bitLength}
     * @param client sends a message to the client, and returns its answer
     * @return the encrypted index of the predicted class
     */
    public Ciphertext evaluateHyperplane(
            List<Ciphertext> encryptedFeatures,
            List<? extends List<? extends Number>> weights,
            int bitLength,
            Function<ArgmaxMessage, List<BigInteger>> client) {
        return evaluateHyperplane(encryptedFeatures, weights, bitLength, client, null);
    }

    /**
     * Encrypts categorical features for naive bayes classification as one-hot vectors. Runs on
     * client side. Only supported by Damgard-Geisler-Kroigaard.
     *
     * @param features value of each feature in {@code [0, domain size)}
     * @param domainSizes number of values of each feature, which the server shares as a part of its
     *     model
     * @return the encrypted input, to be sent to the server
     */
    public List<List<Ciphertext>> encryptNaiveBayesInput(
            List<Integer> features, List<Integer> domainSizes) {
        requirePublicKey("encryption");
        requireClassifierSupport();
        if (features == null
                || domainSizes == null
                || features.isEmpty()
                || features.size() != domainSizes.size()) {
            throw new IllegalArgumentException("There must be a domain size for each feature");
        }
        for (int j = 0; j < features.size(); j++) {
            Integer size = domainSizes.get(j);
            Integer feature = features.get(j);
            if (size == null || size < 1) {
                throw new IllegalArgumentException("Domain sizes must be positive integers");
            }
            if (feature == null || feature < 0 || feature >= size) {
                throw new IllegalArgumentException(
                        "Feature " + feature + " must be an integer in [0, " + size + ")");
            }
        }

        List<List<Ciphertext>> encrypted = new ArrayList<>(features.size());
        for (List<CipherValue> oneHot :
                Classifiers.encryptNaiveBayesInput(cs, features, domainSizes)) {
            List<Ciphertext> ciphertexts = new ArrayList<>(oneHot.size());
            for (CipherValue value : oneHot) {
                ciphertexts.add(buildCiphertext(value));
            }
            encrypted.add(ciphertexts);
        }
        return encrypted;
    }

    /**
     * Classifies encrypted categorical features with a private naive bayes model, i.e. finds the
     * class of the greatest {@code log P(c) + sum of log P(x_j | c)}. Runs on server side and talks
     * to the client (private key owner) through the client callable. Client learns only the
     * predicted class, and server learns nothing. Only supported by Damgard-Geisler-Kroigaard.
     *
     * @param encryptedInput the output of {@link #encryptNaiveBayesInput}
     * @param priors {@code P(c)} of each class
     * @param likelihoods {@code P(x_j = v | c)} for class c, feature j and value v, i.e. {@code
     *     likelihoods[c][j][v]}. Probabilities must be positive, e.g. smoothed with Laplace
     *     smoothing.
     * @param client sends a message to the client, and returns the output of the client's {@link
     *     #answerArgmax}
     * @param precision number of decimal digits kept from log probabilities. Greater values need
     *     more bits for scores.
     * @return the encrypted index of the predicted class, to be decrypted by the client. Earlier
     *     class is returned on ties.
     */
    public Ciphertext evaluateNaiveBayes(
            List<List<Ciphertext>> encryptedInput,
            List<? extends Number> priors,
            List<? extends List<? extends List<? extends Number>>> likelihoods,
            Function<ArgmaxMessage, List<BigInteger>> client,
            int precision) {
        requirePublicKey("encrypted classification");
        requireClassifierSupport();
        Classifiers.validateLikelihoodsShape(likelihoods);
        if (priors == null || priors.size() != likelihoods.size()) {
            throw new IllegalArgumentException("There must be a prior for each class");
        }
        List<Integer> domainSizes = likelihoods.get(0).stream().map(List::size).toList();
        if (encryptedInput == null
                || !encryptedInput.stream().map(List::size).toList().equals(domainSizes)
                || encryptedInput.stream().anyMatch(LightPHE::hasNull)) {
            throw new IllegalArgumentException(
                    "Encrypted input must be one-hot vectors of domain sizes " + domainSizes);
        }
        if (precision < 0) {
            throw new IllegalArgumentException("Precision must be a non-negative integer");
        }

        Classifiers.QuantizedNaiveBayes model =
                Classifiers.quantizeNaiveBayes(priors, likelihoods, precision);
        List<List<CipherValue>> input = new ArrayList<>(encryptedInput.size());
        for (List<Ciphertext> oneHot : encryptedInput) {
            input.add(oneHot.stream().map(Ciphertext::value).toList());
        }
        return buildCiphertext(Classifiers.evaluateNaiveBayes(cs, input, model, client));
    }

    /**
     * Classifies encrypted categorical features with a private naive bayes model, keeping 3 decimal
     * digits of log probabilities.
     *
     * @param encryptedInput the output of {@link #encryptNaiveBayesInput}
     * @param priors {@code P(c)} of each class
     * @param likelihoods {@code P(x_j = v | c)}, i.e. {@code likelihoods[c][j][v]}
     * @param client sends a message to the client, and returns its answer
     * @return the encrypted index of the predicted class
     */
    public Ciphertext evaluateNaiveBayes(
            List<List<Ciphertext>> encryptedInput,
            List<? extends Number> priors,
            List<? extends List<? extends List<? extends Number>>> likelihoods,
            Function<ArgmaxMessage, List<BigInteger>> client) {
        return evaluateNaiveBayes(encryptedInput, priors, likelihoods, client, 3);
    }

    private void requireClassifierSupport() {
        if (algorithmName != Algorithm.DAMGARD_GEISLER_KROIGAARD) {
            throw new IllegalArgumentException(
                    algorithmName
                            + " does not support encrypted classification."
                            + " Use Damgard-Geisler-Kroigaard instead.");
        }
    }

    private static List<BigInteger> toIntegers(List<? extends Number> values) {
        List<BigInteger> integers = new ArrayList<>(values.size());
        for (Number value : values) {
            if (!isIntegral(value)) {
                throw new IllegalArgumentException(
                        "Weights and biases must be integers. Quantize them first.");
            }
            integers.add(toBigInteger(value));
        }
        return integers;
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
    // Serialization
    // -----------------------------------------------------------------------

    /**
     * Serializes ciphertexts, proofs or messages of interactive protocols into json to send them to
     * another party. Keys are never serialized, the receiver restores ciphertexts with its own
     * keys. The json is compatible with the Python library.
     *
     * @param item Ciphertext, CatalanoFioreCiphertext, EncryptedTensor, a proof or a message of an
     *     interactive protocol, e.g. outputs of encryptWithProof, encryptKnnQuery, encryptUpdate or
     *     partialDecrypt and messages sent to the client callable of evaluateArgmax or evaluateKnn,
     *     or null, Boolean, Number, String, List and Map of them
     * @return serialized item
     * @throws IllegalArgumentException when the item cannot be serialized
     */
    public String serialize(Object item) {
        return Json.write(Serialization.encode(item));
    }

    /**
     * Restores ciphertexts, proofs or messages of interactive protocols serialized by another
     * party. Ciphertexts are restored with the public key of this cryptosystem.
     *
     * @param data output of serialize
     * @return restored item. Records such as proofs are restored as maps, integers as BigInteger,
     *     and tuples as lists. Use {@link #deserialize(String, Class)} to restore a record.
     * @throws IllegalArgumentException when the data is malformed
     */
    public Object deserialize(String data) {
        return fromDict(parseSerialized(data));
    }

    /**
     * Restores an item serialized by another party as the given type, e.g. a {@link Proof}, a
     * {@link Proven} ciphertext, a {@link PartialDecryption} or an {@link EncryptedUpdate}.
     *
     * @param data output of serialize
     * @param type expected type of the item
     * @param <T> expected type of the item
     * @return restored item
     * @throws IllegalArgumentException when the data is malformed or not of the given type
     */
    public <T> T deserialize(String data, Class<T> type) {
        return fromDict(parseSerialized(data), type);
    }

    /**
     * Restores a list serialized by another party, converting its items to the given type, e.g.
     * partial decryptions or the answers of the client in encrypted argmax.
     *
     * @param data output of serialize
     * @param type expected type of the items
     * @param <T> expected type of the items
     * @return restored list
     * @throws IllegalArgumentException when the data is malformed or not a list of the given type
     */
    public <T> List<T> deserializeList(String data, Class<T> type) {
        return Serialization.convertList(deserialize(data), type, this::normalizeSerialized);
    }

    /**
     * Restores ciphertexts from their dict forms created by toDict, or any json serializable form
     * created by serialize. Ciphertexts are restored with the public key of this cryptosystem.
     *
     * @param data output of toDict of Ciphertext, CatalanoFioreCiphertext or EncryptedTensor
     * @return restored item
     * @throws IllegalArgumentException when the data is malformed
     */
    public Object fromDict(Object data) {
        return Serialization.decode(data, this::restoreSerialized);
    }

    /**
     * Restores an item from its json serializable form as the given type.
     *
     * @param data output of toDict, or any json serializable form created by serialize
     * @param type expected type of the item
     * @param <T> expected type of the item
     * @return restored item
     * @throws IllegalArgumentException when the data is malformed or not of the given type
     */
    public <T> T fromDict(Object data, Class<T> type) {
        return Serialization.convert(fromDict(data), type, this::normalizeSerialized);
    }

    private static Object parseSerialized(String data) {
        try {
            return Json.read(data);
        } catch (IllegalArgumentException err) {
            throw new IllegalArgumentException("Serialized data is not a valid json", err);
        }
    }

    /** Builds a deserialized object with the keys of this cryptosystem. */
    private Object restoreSerialized(String kind, Map<String, Object> fields) {
        if (Serialization.POINT.equals(kind)) {
            return restorePoint(fields.get("x"), fields.get("y"));
        }

        String expected =
                Serialization.TENSOR.equals(kind)
                        ? Serialization.tensorAlgorithmName(cs.algorithm())
                        : algorithmName.algorithmName();
        if (!expected.equals(fields.get("algorithm_name"))) {
            throw new IllegalArgumentException(
                    "Serialized "
                            + kind
                            + " belongs to "
                            + fields.get("algorithm_name")
                            + ", but this cryptosystem is "
                            + expected);
        }

        if (Serialization.CIPHERTEXT.equals(kind)) {
            return buildCiphertext(normalizeSerialized((CipherValue) fields.get("value")));
        }

        if (Serialization.TENSOR.equals(kind)) {
            List<Fraction> fractions = new ArrayList<>();
            for (Object item : (List<?>) fields.get("fractions")) {
                Fraction fraction = (Fraction) item;
                fractions.add(
                        Fraction.builder()
                                .dividend(normalizeSerialized(fraction.dividend()))
                                .absDividend(normalizeSerialized(fraction.absDividend()))
                                .divisor(normalizeSerialized(fraction.divisor()))
                                .sign(fraction.sign())
                                .build());
            }
            int tensorPrecision;
            try {
                tensorPrecision = ((BigInteger) fields.get("precision")).intValueExact();
            } catch (ArithmeticException err) {
                throw new IllegalArgumentException("Precision of a tensor is out of range", err);
            }
            // builds the public-key-only cryptosystem on first use
            return new EncryptedTensor(
                    fractions, buildCiphertext(IntValue.of(0)).cs(), tensorPrecision);
        }

        return restoreCatalanoFiore(fields);
    }

    private CipherValue restorePoint(Object x, Object y) {
        LightECC ec;
        if (cs instanceof BonehGohNissim bgn) {
            ec = bgn.ec();
        } else if (cs instanceof FreemanBonehGohNissim fbgn) {
            ec = fbgn.ec();
        } else {
            throw new IllegalArgumentException(
                    algorithmName.algorithmName() + " ciphertexts are not elliptic curve points");
        }
        for (Object coordinate : new Object[] {x, y}) {
            if (!(coordinate instanceof BigInteger) && !(coordinate instanceof Double)) {
                throw new IllegalArgumentException(
                        "Coordinates of an elliptic curve point must be integers");
            }
        }
        if (x instanceof Double || y instanceof Double) {
            // identity element of weierstrass and koblitz curves is (inf, inf)
            if (Double.valueOf(Double.POSITIVE_INFINITY).equals(x)
                    && Double.valueOf(Double.POSITIVE_INFINITY).equals(y)
                    && ec.o().isInfinity()) {
                return PointValue.atInfinity();
            }
            throw new IllegalArgumentException("Serialized point is not on the curve");
        }
        try {
            return PointValue.from(ec.point((BigInteger) x, (BigInteger) y));
        } catch (PointNotOnCurveException err) {
            throw new IllegalArgumentException("Serialized point is not on the curve", err);
        }
    }

    private CatalanoFioreCiphertext restoreCatalanoFiore(Map<String, Object> fields) {
        CatalanoFiore cf = deserializationCatalanoFiore;
        if (cf == null) {
            cf = catalanoFiore != null ? catalanoFiore : new CatalanoFiore(cs);
            deserializationCatalanoFiore = cf;
        }
        Object a = fields.get("a");
        Object beta = fields.get("beta");
        Object alpha = fields.get("alpha");
        List<?> pairs = (List<?>) fields.get("pairs");

        if (alpha == null) {
            if (!(a instanceof BigInteger plain)
                    || plain.signum() < 0
                    || plain.compareTo(cf.plaintextModulo()) >= 0) {
                throw new IllegalArgumentException(
                        "a of a Catalano-Fiore ciphertext must be in [0, "
                                + cf.plaintextModulo()
                                + ")");
            }
            if (!(beta instanceof Ciphertext encryptedB) || !pairs.isEmpty()) {
                throw new IllegalArgumentException(
                        "Non-multiplied Catalano-Fiore ciphertext must have a and beta only");
            }
            return cf.restore(plain, encryptedB);
        }

        if (a != null || beta != null || !(alpha instanceof Ciphertext encryptedAlpha)) {
            throw new IllegalArgumentException(
                    "Multiplied Catalano-Fiore ciphertext must have alpha and pairs only");
        }
        List<Ciphertext[]> restoredPairs = new ArrayList<>(pairs.size());
        for (Object pair : pairs) {
            List<?> items = (List<?>) pair;
            if (!(items.get(0) instanceof Ciphertext first)
                    || !(items.get(1) instanceof Ciphertext second)) {
                throw new IllegalArgumentException(
                        "Pairs of a Catalano-Fiore ciphertext must have ciphertexts");
            }
            restoredPairs.add(new Ciphertext[] {first, second});
        }
        return cf.restore(encryptedAlpha, restoredPairs);
    }

    /**
     * Converts a deserialized ciphertext content into the shape this cryptosystem expects. The
     * Python library keeps points of elliptic curve ElGamal and Freeman's Boneh-Goh-Nissim, and
     * elements of {@code F_{p^2}}, as tuples.
     */
    private CipherValue normalizeSerialized(CipherValue value) {
        if (!(value instanceof TupleValue tuple)) {
            return value;
        }
        return switch (algorithmName) {
            case ELLIPTIC_CURVE_EL_GAMAL -> toPoints(tuple);
            case BONEH_GOH_NISSIM -> isIntegerPair(tuple) ? toFp2(tuple) : tuple;
            case FREEMAN_BONEH_GOH_NISSIM -> {
                // 3 points, or 9 elements of F_{p^2} once multiplied
                boolean multiplied =
                        tuple.size()
                                == FreemanBonehGohNissim.DIMENSION
                                        * FreemanBonehGohNissim.DIMENSION;
                List<CipherValue> items = new ArrayList<>(tuple.size());
                for (CipherValue item : tuple.items()) {
                    if (item instanceof TupleValue pair && isIntegerPair(pair)) {
                        items.add(multiplied ? toFp2(pair) : toPoint(pair));
                    } else {
                        items.add(item);
                    }
                }
                yield TupleValue.of(items);
            }
            default -> tuple;
        };
    }

    private static CipherValue toPoints(TupleValue tuple) {
        if (isIntegerPair(tuple)) {
            return toPoint(tuple);
        }
        List<CipherValue> items = new ArrayList<>(tuple.size());
        for (CipherValue item : tuple.items()) {
            items.add(item instanceof TupleValue nested ? toPoints(nested) : item);
        }
        return TupleValue.of(items);
    }

    private static boolean isIntegerPair(TupleValue tuple) {
        return tuple.size() == 2
                && tuple.get(0) instanceof IntValue
                && tuple.get(1) instanceof IntValue;
    }

    private static PointValue toPoint(TupleValue pair) {
        List<BigInteger> coordinates = pair.asIntegers();
        return PointValue.of(coordinates.get(0), coordinates.get(1));
    }

    private static Fp2Value toFp2(TupleValue pair) {
        List<BigInteger> coordinates = pair.asIntegers();
        return new Fp2Value(coordinates.get(0), coordinates.get(1));
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

    /** Null-safe even for immutable lists, whose contains(null) throws. */
    private static boolean hasNull(List<?> items) {
        return items.stream().anyMatch(Objects::isNull);
    }

    private static boolean isIntegral(Number value) {
        return value != null && isIntegralType(value);
    }

    private static boolean isIntegralType(Number value) {
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
