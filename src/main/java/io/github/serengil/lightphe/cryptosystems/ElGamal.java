package io.github.serengil.lightphe.cryptosystems;

import io.github.serengil.lightphe.commons.Logger;
import io.github.serengil.lightphe.commons.MathUtils;
import io.github.serengil.lightphe.commons.Threshold;
import io.github.serengil.lightphe.commons.Zkp;
import io.github.serengil.lightphe.model.Algorithm;
import io.github.serengil.lightphe.model.KeySpec;
import io.github.serengil.lightphe.model.KeyValue;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.PartialDecryption;
import io.github.serengil.lightphe.model.Proof;
import io.github.serengil.lightphe.model.Proven;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.IntValue;
import io.github.serengil.lightphe.model.value.TupleValue;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * ElGamal, either multiplicatively or additively homomorphic.
 *
 * <p>Regular ElGamal encrypts {@code m} and is homomorphic with respect to the multiplication;
 * exponential ElGamal encrypts {@code g^m} instead and is homomorphic with respect to the addition,
 * at the price of having to solve a discrete logarithm during decryption.
 *
 * <p>Ref: <a
 * href="https://sefiks.com/2023/03/27/a-step-by-step-partially-homomorphic-encryption-example-with-elgamal-in-python/">
 * A step by step partially homomorphic encryption example with ElGamal</a>
 */
public final class ElGamal extends AbstractHomomorphic {

    /** The key fields ElGamal requires. */
    public static final KeySpec REQUIRED_KEYS = KeySpec.of(List.of("p", "g", "y"), List.of("x"));

    private static final Logger logger = Logger.forModule(ElGamal.class);

    private static final String DECRYPTION_DOMAIN = "lightphe/elgamal/decryption";
    private static final String PARTIAL_DECRYPTION_DOMAIN = "lightphe/elgamal/partial-decryption";
    private static final String MEMBERSHIP_DOMAIN = "lightphe/exponential-elgamal/membership";

    private final boolean exponential;

    /**
     * Builds an ElGamal cryptosystem.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param exponential set this to {@code true} to make the cryptosystem exponential ElGamal.
     *     Regular ElGamal is homomorphic with respect to the multiplication whereas exponential
     *     ElGamal is homomorphic with respect to the addition.
     * @param keySize key size in bits; {@code null} defaults to 1024
     * @param primeOrder set this to {@code true} to pick g of a known prime order q while
     *     generating keys. Threshold decryption and zero-knowledge proofs require this.
     */
    public ElGamal(Keys keys, boolean exponential, Integer keySize, boolean primeOrder) {
        super(
                exponential ? Algorithm.EXPONENTIAL_EL_GAMAL : Algorithm.EL_GAMAL,
                keys != null
                        ? keys
                        : primeOrder
                                ? generatePrimeOrderKeys(keySize == null ? 1024 : keySize)
                                : generateKeys(keySize == null ? 1024 : keySize));
        this.exponential = exponential;
        this.plaintextModulo = this.keys.publicNumber("p");
        this.ciphertextModulo = this.keys.publicNumber("p");
    }

    /**
     * Builds an ElGamal cryptosystem with a generator of an unknown order.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param exponential set this to {@code true} to make the cryptosystem exponential ElGamal
     * @param keySize key size in bits; {@code null} defaults to 1024
     */
    public ElGamal(Keys keys, boolean exponential, Integer keySize) {
        this(keys, exponential, keySize, false);
    }

    /**
     * Builds a multiplicatively homomorphic ElGamal cryptosystem around an existing key pair.
     *
     * @param keys the private-public key pair
     */
    public ElGamal(Keys keys) {
        this(keys, false, null);
    }

    /**
     * Generates the public and private keys of the ElGamal cryptosystem.
     *
     * @param keySize key size in bits
     * @return the generated key pair
     */
    public static Keys generateKeys(int keySize) {
        Keys keys = Keys.empty();

        // picking a prime modulus p
        BigInteger p =
                MathUtils.randomPrime(
                        BigInteger.valueOf(100),
                        BigInteger.TWO.pow(keySize / 2).subtract(BigInteger.ONE));

        // picking a generator g; the square root keeps g comfortably below p
        BigInteger g = MathUtils.randomInt(BigInteger.TWO, p.sqrt());

        // picking a private key x
        BigInteger x = MathUtils.randomInt(BigInteger.ONE, p.subtract(BigInteger.TWO));

        // public key
        BigInteger y = g.modPow(x, p);

        keys.publicKey().put("p", KeyValue.of(p));
        keys.publicKey().put("g", KeyValue.of(g));
        keys.publicKey().put("y", KeyValue.of(y));
        keys.privateKey().put("x", KeyValue.of(x));
        return keys;
    }

    /**
     * Generates keys where {@code p = k * q + 1} for a large prime q, and g has order q. Threshold
     * decryption and zero-knowledge proofs require the order of g to be known and prime.
     *
     * @param keySize key size in bits
     * @return the generated key pair; the public key has q as well
     */
    public static Keys generatePrimeOrderKeys(int keySize) {
        int bits = Math.max(keySize / 2, 8);
        int kBits = Math.max(1, Math.min(16, bits / 4));
        int qBits = bits - kBits;

        // picking a prime modulus p = k * q + 1 for a prime q
        BigInteger p = null;
        BigInteger q = null;
        BigInteger k = null;
        while (p == null) {
            q =
                    MathUtils.randomPrime(
                            BigInteger.ONE.shiftLeft(qBits - 1), BigInteger.ONE.shiftLeft(qBits));
            for (int attempt = 0; attempt < 1000; attempt++) {
                BigInteger candidateK =
                        MathUtils.randomInt(
                                        BigInteger.ONE.shiftLeft(kBits - 1),
                                        BigInteger.ONE.shiftLeft(kBits))
                                .shiftLeft(1);
                BigInteger candidate = candidateK.multiply(q).add(BigInteger.ONE);
                if (candidate.bitLength() <= bits && MathUtils.isPrime(candidate)) {
                    p = candidate;
                    k = candidateK;
                    break;
                }
            }
        }

        // picking a generator g of the subgroup of prime order q
        BigInteger g;
        do {
            g = MathUtils.randomInt(BigInteger.TWO, p.subtract(BigInteger.TWO)).modPow(k, p);
        } while (g.equals(BigInteger.ONE));

        // picking a private key x
        BigInteger x = MathUtils.randomInt(BigInteger.ONE, q.subtract(BigInteger.ONE));

        Keys keys = Keys.empty();
        keys.publicKey().put("p", KeyValue.of(p));
        keys.publicKey().put("g", KeyValue.of(g));
        keys.publicKey().put("y", KeyValue.of(g.modPow(x, p)));
        keys.publicKey().put("q", KeyValue.of(q));
        keys.privateKey().put("x", KeyValue.of(x));
        return keys;
    }

    /**
     * Reports whether this is the exponential, additively homomorphic variant.
     *
     * @return {@code true} for exponential ElGamal
     */
    public boolean exponential() {
        return exponential;
    }

    @Override
    public KeySpec requiredKeys() {
        return REQUIRED_KEYS;
    }

    /**
     * {@inheritDoc}
     *
     * <p>ElGamal requires a one-time random key per encryption.
     */
    @Override
    public BigInteger generateRandomKey() {
        BigInteger p = keys.publicNumber("p");
        return MathUtils.randomInt(BigInteger.ONE, p.subtract(BigInteger.ONE));
    }

    @Override
    public CipherValue encrypt(BigInteger plaintext) {
        return encrypt(plaintext, generateRandomKey());
    }

    /**
     * Encrypts a plaintext with an explicit random key.
     *
     * @param plaintext the message to encrypt
     * @param randomKey the random key; do not set this to a static value
     * @return the ciphertext pair {@code (c1, c2)}
     */
    public CipherValue encrypt(BigInteger plaintext, BigInteger randomKey) {
        BigInteger p = keys.publicNumber("p");
        BigInteger g = keys.publicNumber("g");
        BigInteger y = keys.publicNumber("y");
        BigInteger r = randomKey;

        BigInteger message = plaintext;
        if (message.compareTo(p) > 0) {
            message = message.mod(p);
            BigInteger normalized = message;
            logger.debug(
                    () ->
                            "ElGamal can encrypt messages [1, "
                                    + p
                                    + "]. "
                                    + "Seems you exceeded this limit. New plaintext is "
                                    + normalized);
        }

        BigInteger c1 = g.modPow(r, p);
        BigInteger c2 =
                exponential
                        ? g.modPow(message, p).multiply(y.modPow(r, p)).mod(p)
                        : message.multiply(y.modPow(r, p)).mod(p);

        return TupleValue.of(IntValue.of(c1), IntValue.of(c2));
    }

    @Override
    public BigInteger decrypt(CipherValue ciphertext) {
        BigInteger[] pair = asIntPair(ciphertext);
        BigInteger c1 = pair[0];
        BigInteger c2 = pair[1];

        BigInteger x = keys.privateNumber("x");
        BigInteger p = keys.publicNumber("p");

        BigInteger mPrime = c2.multiply(c1.modPow(x.negate(), p)).mod(p);
        return restorePlaintext(mPrime);
    }

    /**
     * Restores the plaintext from {@code m' = c2 / c1^x}.
     *
     * @param mPrime m for ElGamal, {@code g^m} for exponential ElGamal
     * @return the restored message
     */
    private BigInteger restorePlaintext(BigInteger mPrime) {
        if (!exponential) {
            return mPrime;
        }

        BigInteger p = keys.publicNumber("p");
        BigInteger g = keys.publicNumber("g");

        // m_prime = g^m. Find m for known m_prime and known g - this is the discrete logarithm
        // problem, tractable here only because plaintexts stay small.
        BigInteger m = BigInteger.ZERO;
        while (true) {
            if (g.modPow(m, p).equals(mPrime)) {
                return m;
            }
            m = m.add(BigInteger.ONE);
            if (m.compareTo(p) > 0) {
                throw new IllegalArgumentException("Cannot restore the message in [0, " + p + "]");
            }
        }
    }

    // -----------------------------------------------------------------------
    // Threshold decryption
    // -----------------------------------------------------------------------

    /**
     * {@inheritDoc}
     *
     * <p>Verification keys {@code g^share} are published to verify partial decryptions. Keys must
     * be generated with a generator of a known prime order.
     */
    @Override
    public List<Keys> generateThresholdKeys(int threshold, int parties) {
        BigInteger q = order();
        if (BigInteger.valueOf(parties).compareTo(q) >= 0) {
            throw new IllegalArgumentException(
                    "Number of parties must be less than the group order " + q);
        }
        Map<Integer, BigInteger> shares =
                Threshold.splitSecret(keys.privateNumber("x"), threshold, parties, q);
        BigInteger p = keys.publicNumber("p");
        BigInteger g = keys.publicNumber("g");
        List<BigInteger> verificationKeys = new ArrayList<>(parties);
        for (int index = 1; index <= parties; index++) {
            verificationKeys.add(g.modPow(shares.get(index), p));
        }
        return Threshold.buildShareKeys(
                keys, shares, threshold, parties, KeyValue.numbers(verificationKeys));
    }

    /**
     * {@inheritDoc}
     *
     * <p>The partial decryption is {@code c1^share}, and its proof shows that {@code log_g(g^share)
     * = log_c1(c1^share)}.
     */
    @Override
    public PartialDecryption partialDecrypt(CipherValue ciphertext, boolean prove) {
        Threshold.ThresholdKey thresholdKey = Threshold.thresholdKey(keys);
        int index = thresholdKey.index();
        BigInteger share = thresholdKey.share();
        BigInteger p = keys.publicNumber("p");
        BigInteger g = keys.publicNumber("g");
        BigInteger c1 = asIntPair(ciphertext)[0];
        BigInteger value = c1.modPow(share, p);
        if (!prove) {
            return new PartialDecryption(index, IntValue.of(value));
        }
        Proof proof =
                Zkp.proveDleq(
                        group(),
                        g,
                        g.modPow(share, p),
                        c1,
                        value,
                        share,
                        PARTIAL_DECRYPTION_DOMAIN,
                        List.of(p, index));
        return new PartialDecryption(index, IntValue.of(value), proof);
    }

    @Override
    public boolean verifyPartialDecryption(
            CipherValue ciphertext, PartialDecryption partialDecryption) {
        if (!keys.publicKey().containsKey("verification_keys")) {
            throw new IllegalArgumentException(
                    "Public key does not have verification keys of shareholders");
        }
        try {
            List<BigInteger> verificationKeys = keys.publicNumbers("verification_keys");
            int index = partialDecryption.index();
            if (index < 1 || index > verificationKeys.size()) {
                return false;
            }
            BigInteger p = keys.publicNumber("p");
            return Zkp.verifyDleq(
                    group(),
                    keys.publicNumber("g"),
                    verificationKeys.get(index - 1),
                    asIntPair(ciphertext)[0],
                    asInt(partialDecryption.value()),
                    partialDecryption.proof(),
                    PARTIAL_DECRYPTION_DOMAIN,
                    List.of(p, index));
        } catch (IllegalArgumentException | ArithmeticException err) {
            return false;
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>{@code c1^x} is restored in the exponent with lagrange interpolation.
     */
    @Override
    public BigInteger combinePartialDecryptions(
            CipherValue ciphertext, List<PartialDecryption> partialDecryptions, boolean verify) {
        List<PartialDecryption> selected =
                Threshold.selectPartialDecryptions(
                        keys,
                        partialDecryptions,
                        verify
                                ? partialDecryption ->
                                        verifyPartialDecryption(ciphertext, partialDecryption)
                                : null);
        BigInteger p = keys.publicNumber("p");
        BigInteger q = order();
        List<Integer> indices = selected.stream().map(PartialDecryption::index).toList();

        // c1^x restored in the exponent with lagrange interpolation
        BigInteger c1x = BigInteger.ONE;
        for (PartialDecryption partialDecryption : selected) {
            BigInteger coefficient =
                    Threshold.lagrangeCoefficient(partialDecryption.index(), indices, q);
            c1x = c1x.multiply(asInt(partialDecryption.value()).modPow(coefficient, p)).mod(p);
        }

        BigInteger mPrime = asIntPair(ciphertext)[1].multiply(c1x.modInverse(p)).mod(p);
        return restorePlaintext(mPrime);
    }

    // -----------------------------------------------------------------------
    // Zero-knowledge proofs
    // -----------------------------------------------------------------------

    /**
     * {@inheritDoc}
     *
     * <p>Chaum-Pedersen proof shows that {@code log_g(y) = log_c1(c1^x)}.
     */
    @Override
    public Proven<BigInteger> decryptWithProof(CipherValue ciphertext) {
        BigInteger p = keys.publicNumber("p");
        BigInteger g = keys.publicNumber("g");
        BigInteger y = keys.publicNumber("y");
        BigInteger x = keys.privateNumber("x");
        BigInteger[] pair = asIntPair(ciphertext);
        BigInteger c1 = pair[0];
        BigInteger c2 = pair[1];
        BigInteger c1x = c1.modPow(x, p);
        Proof proof = Zkp.proveDleq(group(), g, y, c1, c1x, x, DECRYPTION_DOMAIN, List.of(p, c2));
        return new Proven<>(restorePlaintext(c2.multiply(c1x.modInverse(p)).mod(p)), proof);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Exponential ElGamal checks the claimed plaintext in modulo q.
     */
    @Override
    public boolean verifyDecryption(CipherValue ciphertext, BigInteger plaintext, Proof proof) {
        Zkp.ModularGroup group = group();
        try {
            BigInteger p = keys.publicNumber("p");
            BigInteger g = keys.publicNumber("g");
            BigInteger[] pair = asIntPair(ciphertext);
            BigInteger c1 = pair[0];
            BigInteger c2 = pair[1];
            if (plaintext == null
                    || !group.isMember(c1)
                    || c2.signum() <= 0
                    || c2.compareTo(p) >= 0) {
                return false;
            }

            // c1^x implied by the claimed plaintext
            BigInteger c1x;
            if (exponential) {
                c1x = c2.multiply(g.modPow(plaintext.negate(), p)).mod(p);
            } else {
                if (plaintext.mod(p).signum() == 0) {
                    return false;
                }
                c1x = c2.multiply(plaintext.modInverse(p)).mod(p);
            }

            return Zkp.verifyDleq(
                    group,
                    g,
                    keys.publicNumber("y"),
                    c1,
                    c1x,
                    proof,
                    DECRYPTION_DOMAIN,
                    List.of(p, c2));
        } catch (IllegalArgumentException | ArithmeticException err) {
            return false;
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>Exponential ElGamal only. Membership proofs of regular ElGamal report to use exponential
     * ElGamal instead.
     */
    @Override
    public boolean supportsMembershipProofs() {
        return true;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Disjunctive Chaum-Pedersen proof shows that {@code c2 / g^v} is {@code y^r} for one of the
     * values v. Only supported by exponential ElGamal.
     */
    @Override
    public Proven<CipherValue> encryptWithProof(
            BigInteger plaintext, List<BigInteger> values, Object context) {
        requireExponential();
        BigInteger r = generateRandomKey();
        CipherValue ciphertext = encrypt(plaintext, r);
        return new Proven<>(ciphertext, proveMembership(ciphertext, plaintext, r, values, context));
    }

    @Override
    public Proof proveMembership(
            CipherValue ciphertext,
            BigInteger plaintext,
            BigInteger randomKey,
            List<BigInteger> values,
            Object context) {
        requireExponential();
        BigInteger[] pair = asIntPair(ciphertext);
        return Zkp.proveDleqOr(
                group(),
                keys.publicNumber("g"),
                pair[0],
                keys.publicNumber("y"),
                membershipCandidates(pair[1], values),
                randomKey,
                indexOf(values, plaintext),
                MEMBERSHIP_DOMAIN,
                Arrays.asList(keys.publicNumber("p"), pair[1], values, context));
    }

    /**
     * {@inheritDoc}
     *
     * <p>{@code c1 = g^r} multiplies, so random keys add.
     */
    @Override
    public BigInteger combineRandomKeys(List<BigInteger> randomKeys) {
        return randomKeys.stream().reduce(BigInteger.ZERO, BigInteger::add);
    }

    @Override
    public boolean verifyCiphertext(
            CipherValue ciphertext, Proof proof, List<BigInteger> values, Object context) {
        requireExponential();
        Zkp.ModularGroup group = group();
        try {
            BigInteger[] pair = asIntPair(ciphertext);
            return Zkp.verifyDleqOr(
                    group,
                    keys.publicNumber("g"),
                    pair[0],
                    keys.publicNumber("y"),
                    membershipCandidates(pair[1], values),
                    proof,
                    MEMBERSHIP_DOMAIN,
                    Arrays.asList(keys.publicNumber("p"), pair[1], values, context));
        } catch (IllegalArgumentException | ArithmeticException err) {
            return false;
        }
    }

    /**
     * Candidates {@code c2 / g^v} for each value v. Ciphertext encrypts v if and only if its
     * candidate is {@code y^r} where {@code c1 = g^r}.
     */
    private List<BigInteger> membershipCandidates(BigInteger c2, List<BigInteger> values) {
        BigInteger p = keys.publicNumber("p");
        BigInteger g = keys.publicNumber("g");
        List<BigInteger> candidates = new ArrayList<>(values.size());
        for (BigInteger value : values) {
            candidates.add(c2.multiply(g.modPow(value.negate(), p)).mod(p));
        }
        return candidates;
    }

    private void requireExponential() {
        if (!exponential) {
            throw new IllegalArgumentException(
                    "ElGamal does not support proving that a ciphertext encrypts one of given"
                            + " values. Use Exponential-ElGamal instead.");
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>Schnorr proof shows knowledge of r where {@code c1 = g^r}, which reveals the plaintext
     * from c2. It is bound to c2, so a copied, re-randomized or modified ciphertext of someone else
     * cannot be proven.
     */
    @Override
    public Proven<CipherValue> encryptWithProofOfKnowledge(BigInteger plaintext, Object context) {
        Zkp.ModularGroup group = group();
        BigInteger r = generateRandomKey();
        CipherValue ciphertext = encrypt(plaintext, r);
        BigInteger[] pair = asIntPair(ciphertext);
        Proof proof =
                Zkp.proveDlog(
                        group,
                        keys.publicNumber("g"),
                        pair[0],
                        r,
                        knowledgeDomain(),
                        Arrays.asList(keys.publicNumber("p"), pair[1], context));
        return new Proven<>(ciphertext, proof);
    }

    @Override
    public boolean verifyKnowledge(CipherValue ciphertext, Proof proof, Object context) {
        Zkp.ModularGroup group = group();
        try {
            BigInteger p = keys.publicNumber("p");
            BigInteger[] pair = asIntPair(ciphertext);
            if (pair[1].signum() <= 0 || pair[1].compareTo(p) >= 0) {
                return false;
            }
            return Zkp.verifyDlog(
                    group,
                    keys.publicNumber("g"),
                    pair[0],
                    proof,
                    knowledgeDomain(),
                    Arrays.asList(p, pair[1], context));
        } catch (IllegalArgumentException | ArithmeticException err) {
            return false;
        }
    }

    /** Domain of proofs of knowledge, separating ElGamal and exponential ElGamal. */
    private String knowledgeDomain() {
        return exponential
                ? "lightphe/exponential-elgamal/knowledge"
                : "lightphe/elgamal/knowledge";
    }

    /** Subgroup of prime order q generated by g. */
    private Zkp.ModularGroup group() {
        return new Zkp.ModularGroup(keys.publicNumber("p"), order());
    }

    /** Prime order q of the generator g. */
    private BigInteger order() {
        if (!keys.publicKey().containsKey("q")) {
            throw new IllegalArgumentException(
                    "Public key does not have the order q of the generator, which threshold"
                            + " decryption and zero-knowledge proofs require. Generate new keys"
                            + " with primeOrder = true to use them.");
        }
        return keys.publicNumber("q");
    }

    static int indexOf(List<BigInteger> values, BigInteger plaintext) {
        int index = values.indexOf(plaintext);
        if (index < 0) {
            throw new IllegalArgumentException("Plaintext must be one of the allowed values");
        }
        return index;
    }

    /**
     * {@inheritDoc}
     *
     * <p>The result equals {@code E(m1 * m2)}. Only the regular, non-exponential variant supports
     * this.
     */
    @Override
    public CipherValue multiply(CipherValue ciphertext1, CipherValue ciphertext2) {
        if (exponential) {
            throw new IllegalArgumentException(
                    "Exponential ElGamal is not homomorphic with respect to the addition");
        }
        BigInteger p = keys.publicNumber("p");
        BigInteger[] first = asIntPair(ciphertext1);
        BigInteger[] second = asIntPair(ciphertext2);
        return TupleValue.of(
                IntValue.of(first[0].multiply(second[0]).mod(p)),
                IntValue.of(first[1].multiply(second[1]).mod(p)));
    }

    /**
     * {@inheritDoc}
     *
     * <p>The result equals {@code E(m1 + m2)}. Only the exponential variant supports this.
     */
    @Override
    public CipherValue add(CipherValue ciphertext1, CipherValue ciphertext2) {
        if (!exponential) {
            throw new IllegalArgumentException(
                    "Regular ElGamal is not homomorphic with respect to the addition");
        }
        BigInteger p = keys.publicNumber("p");
        BigInteger[] first = asIntPair(ciphertext1);
        BigInteger[] second = asIntPair(ciphertext2);
        return TupleValue.of(
                IntValue.of(first[0].multiply(second[0]).mod(p)),
                IntValue.of(first[1].multiply(second[1]).mod(p)));
    }

    @Override
    public CipherValue multiplyByConstant(CipherValue ciphertext, BigInteger constant) {
        if (!exponential) {
            throw new IllegalArgumentException(
                    "ElGamal is not supporting multiplying ciphertext by a known constant");
        }
        BigInteger p = keys.publicNumber("p");
        BigInteger scalar = constant;
        if (scalar.compareTo(p) > 0) {
            scalar = scalar.mod(p);
            BigInteger normalized = scalar;
            logger.debug(
                    () ->
                            "ElGamal can encrypt messages [1, "
                                    + p
                                    + "]. "
                                    + "Seems constant exceeded this limit. New constant is "
                                    + normalized);
        }
        BigInteger[] pair = asIntPair(ciphertext);
        return TupleValue.of(
                IntValue.of(pair[0].modPow(scalar, p)), IntValue.of(pair[1].modPow(scalar, p)));
    }

    @Override
    public CipherValue reencrypt(CipherValue ciphertext) {
        // The neutral element depends on which operation the variant is homomorphic with respect to
        BigInteger neutralElement = exponential ? BigInteger.ZERO : BigInteger.ONE;
        CipherValue neutralEncrypted = encrypt(neutralElement);
        return exponential
                ? add(ciphertext, neutralEncrypted)
                : multiply(ciphertext, neutralEncrypted);
    }
}
