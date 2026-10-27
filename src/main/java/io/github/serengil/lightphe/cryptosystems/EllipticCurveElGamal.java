package io.github.serengil.lightphe.cryptosystems;

import io.github.serengil.lightphe.commons.Logger;
import io.github.serengil.lightphe.commons.MathUtils;
import io.github.serengil.lightphe.commons.Threshold;
import io.github.serengil.lightphe.commons.Zkp;
import io.github.serengil.lightphe.ecc.CurvePoint;
import io.github.serengil.lightphe.ecc.LightECC;
import io.github.serengil.lightphe.model.Algorithm;
import io.github.serengil.lightphe.model.KeySpec;
import io.github.serengil.lightphe.model.KeyValue;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.PartialDecryption;
import io.github.serengil.lightphe.model.Proof;
import io.github.serengil.lightphe.model.Proven;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.PointValue;
import io.github.serengil.lightphe.model.value.TupleValue;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Elliptic curve ElGamal, an additively homomorphic cryptosystem.
 *
 * <p>Decryption has to solve the elliptic curve discrete logarithm problem, but that stays easy as
 * long as plaintexts are not very large - unlike Benaloh or Naccache-Stern, whose message space is
 * bounded by the key itself.
 *
 * <p>Ref: <a href="https://sefiks.com/2018/08/21/elliptic-curve-elgamal-encryption/">Elliptic curve
 * ElGamal encryption</a>
 */
public final class EllipticCurveElGamal extends AbstractHomomorphic {

    /** The key fields elliptic curve ElGamal requires. */
    public static final KeySpec REQUIRED_KEYS = KeySpec.of(List.of("Qa"), List.of("ka"));

    private static final Logger logger = Logger.forModule(EllipticCurveElGamal.class);

    private static final String DECRYPTION_DOMAIN = "lightphe/elliptic-curve-elgamal/decryption";
    private static final String PARTIAL_DECRYPTION_DOMAIN =
            "lightphe/elliptic-curve-elgamal/partial-decryption";
    private static final String MEMBERSHIP_DOMAIN = "lightphe/elliptic-curve-elgamal/membership";
    private static final String KNOWLEDGE_DOMAIN = "lightphe/elliptic-curve-elgamal/knowledge";

    private final LightECC ecc;

    /**
     * Builds an elliptic curve ElGamal cryptosystem.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param keySize key size in bits; {@code null} defaults to the bit length of the curve order,
     *     which for the default curve is equivalent to 1024-bit RSA
     * @param form the elliptic curve form: {@code "weierstrass"} (default), {@code "edwards"} or
     *     {@code "koblitz"}
     * @param curve the elliptic curve to use, e.g. {@code ed25519} or {@code ed448} for the Edwards
     *     form and {@code secp256k1} for the Weierstrass form
     */
    public EllipticCurveElGamal(Keys keys, Integer keySize, String form, String curve) {
        super(Algorithm.ELLIPTIC_CURVE_EL_GAMAL, resolveKeys(keys, keySize, form, curve));
        this.ecc = LightECC.of(form, curve);

        if (curve != null) {
            this.keys.setCurve(curve);
        }
        if (form != null) {
            this.keys.setForm(form);
        }

        this.plaintextModulo = ecc.modulo();
        this.ciphertextModulo = ecc.modulo();
    }

    /**
     * Builds an elliptic curve ElGamal cryptosystem around an existing key pair.
     *
     * @param keys the private-public key pair
     * @param form the elliptic curve form
     * @param curve the elliptic curve to use
     */
    public EllipticCurveElGamal(Keys keys, String form, String curve) {
        this(keys, null, form, curve);
    }

    private static Keys resolveKeys(Keys keys, Integer keySize, String form, String curve) {
        if (keys != null) {
            return keys;
        }
        LightECC ecc = LightECC.of(form, curve);
        return generateKeys(ecc, keySize == null ? ecc.n().bitLength() : keySize);
    }

    /**
     * Returns the underlying elliptic curve.
     *
     * @return the curve this cryptosystem operates on
     */
    public LightECC ecc() {
        return ecc;
    }

    /**
     * Generates the public and private keys of the elliptic curve ElGamal cryptosystem.
     *
     * @param ecc the curve to generate keys on
     * @param keySize key size in bits
     * @return the generated key pair
     */
    public static Keys generateKeys(LightECC ecc, int keySize) {
        Keys keys = Keys.empty();

        // private key
        BigInteger ka = MathUtils.getRandomBits(keySize);
        logger.debug(() -> keySize + " bit private key generated for Elliptic Curve ElGamal.");

        // public key
        CurvePoint qa = ecc.g().multiply(ka);

        keys.publicKey().put("Qa", KeyValue.point(qa.x(), qa.y()));
        keys.privateKey().put("ka", KeyValue.of(ka));
        return keys;
    }

    @Override
    public KeySpec requiredKeys() {
        return REQUIRED_KEYS;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Elliptic curve ElGamal requires a one-time random key per encryption.
     */
    @Override
    public BigInteger generateRandomKey() {
        return MathUtils.getRandomBits(ecc.n().bitLength());
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
        CurvePoint qa = publicPoint();

        CurvePoint s = ecc.g().multiply(plaintext);
        CurvePoint c1 = ecc.g().multiply(randomKey);
        CurvePoint c2 = qa.multiply(randomKey).add(s);

        return TupleValue.of(PointValue.from(c1), PointValue.from(c2));
    }

    @Override
    public BigInteger decrypt(CipherValue ciphertext) {
        // private key
        BigInteger ka = keys.privateNumber("ka");

        CurvePoint[] pair = asPointPair(ciphertext);
        CurvePoint sPrime = pair[0].negate().multiply(ka).add(pair[1]);

        // s_prime is a point on the elliptic curve with s_prime = k x G; we need to find k from the
        // known s_prime and G, which requires solving the elliptic curve discrete logarithm problem
        return sPrime.divide(ecc.g());
    }

    /**
     * {@inheritDoc}
     *
     * <p>The result equals {@code E(m1 + m2)}.
     */
    @Override
    public CipherValue add(CipherValue ciphertext1, CipherValue ciphertext2) {
        CurvePoint[] first = asPointPair(ciphertext1);
        CurvePoint[] second = asPointPair(ciphertext2);

        CurvePoint a = first[0].add(second[0]);
        CurvePoint b = first[1].add(second[1]);
        return TupleValue.of(PointValue.from(a), PointValue.from(b));
    }

    /**
     * {@inheritDoc}
     *
     * <p>The result equals {@code k x E(m) = E(m * k)}.
     */
    @Override
    public CipherValue multiplyByConstant(CipherValue ciphertext, BigInteger constant) {
        CurvePoint[] pair = asPointPair(ciphertext);
        return TupleValue.of(
                PointValue.from(pair[0].multiply(constant)),
                PointValue.from(pair[1].multiply(constant)));
    }

    @Override
    public CipherValue reencrypt(CipherValue ciphertext) {
        BigInteger rPrime = generateRandomKey();
        CurvePoint qa = publicPoint();

        CurvePoint[] pair = asPointPair(ciphertext);
        CurvePoint c1Prime = pair[0].add(ecc.g().multiply(rPrime));
        CurvePoint c2Prime = pair[1].add(qa.multiply(rPrime));
        return TupleValue.of(PointValue.from(c1Prime), PointValue.from(c2Prime));
    }

    // -----------------------------------------------------------------------
    // Threshold decryption
    // -----------------------------------------------------------------------

    /**
     * {@inheritDoc}
     *
     * <p>Verification keys {@code share x G} are published to verify partial decryptions.
     */
    @Override
    public List<Keys> generateThresholdKeys(int threshold, int parties) {
        BigInteger n = ecc.n();
        if (BigInteger.valueOf(parties).compareTo(n) >= 0) {
            throw new IllegalArgumentException(
                    "Number of parties must be less than the curve order " + n);
        }
        Map<Integer, BigInteger> shares =
                Threshold.splitSecret(keys.privateNumber("ka"), threshold, parties, n);
        List<List<BigInteger>> verificationKeys = new ArrayList<>(parties);
        for (int index = 1; index <= parties; index++) {
            CurvePoint point = ecc.g().multiply(shares.get(index));
            verificationKeys.add(List.of(point.x(), point.y()));
        }
        return Threshold.buildShareKeys(
                keys, shares, threshold, parties, KeyValue.matrix(verificationKeys));
    }

    /**
     * {@inheritDoc}
     *
     * <p>The partial decryption is {@code share x c1}, and its proof shows that {@code log_G(share
     * x G) = log_c1(share x c1)}.
     */
    @Override
    public PartialDecryption partialDecrypt(CipherValue ciphertext, boolean prove) {
        Threshold.ThresholdKey thresholdKey = Threshold.thresholdKey(keys);
        int index = thresholdKey.index();
        BigInteger share = thresholdKey.share();
        CurvePoint c1 = asPointPair(ciphertext)[0];
        CurvePoint value = c1.multiply(share);
        if (!prove) {
            return new PartialDecryption(index, PointValue.from(value));
        }
        Proof proof =
                Zkp.proveDleq(
                        group(),
                        ecc.g(),
                        ecc.g().multiply(share),
                        c1,
                        value,
                        share,
                        PARTIAL_DECRYPTION_DOMAIN,
                        List.of(ecc.n(), index));
        return new PartialDecryption(index, PointValue.from(value), proof);
    }

    @Override
    public boolean verifyPartialDecryption(
            CipherValue ciphertext, PartialDecryption partialDecryption) {
        if (!keys.publicKey().containsKey("verification_keys")) {
            throw new IllegalArgumentException(
                    "Public key does not have verification keys of shareholders");
        }
        try {
            List<List<BigInteger>> verificationKeys = verificationKeys();
            int index = partialDecryption.index();
            if (index < 1 || index > verificationKeys.size()) {
                return false;
            }
            List<BigInteger> verificationKey = verificationKeys.get(index - 1);
            return Zkp.verifyDleq(
                    group(),
                    ecc.g(),
                    ecc.point(verificationKey.get(0), verificationKey.get(1)),
                    asPointPair(ciphertext)[0],
                    toCurvePoint(partialDecryption.value()),
                    partialDecryption.proof(),
                    PARTIAL_DECRYPTION_DOMAIN,
                    List.of(ecc.n(), index));
        } catch (RuntimeException err) {
            // malformed points raise errors of the elliptic curve
            return false;
        }
    }

    /**
     * {@inheritDoc}
     *
     * <p>{@code ka x c1} is restored with lagrange interpolation, and the elliptic curve discrete
     * logarithm of the result is solved.
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
        List<Integer> indices = selected.stream().map(PartialDecryption::index).toList();

        // ka x c1 restored with lagrange interpolation
        CurvePoint sPrime = asPointPair(ciphertext)[1];
        for (PartialDecryption partialDecryption : selected) {
            BigInteger coefficient =
                    Threshold.lagrangeCoefficient(partialDecryption.index(), indices, ecc.n());
            CurvePoint point = toCurvePoint(partialDecryption.value());
            sPrime = point.negate().multiply(coefficient).add(sPrime);
        }

        // s_prime = m x G, solve ECDLP
        return sPrime.divide(ecc.g());
    }

    private List<List<BigInteger>> verificationKeys() {
        KeyValue value = keys.publicKey().get("verification_keys");
        // a single point cannot be told apart from a two-element list in exported JSON
        if (value instanceof KeyValue.Point point) {
            return List.of(List.of(point.x(), point.y()));
        }
        return keys.publicMatrix("verification_keys");
    }

    // -----------------------------------------------------------------------
    // Zero-knowledge proofs
    // -----------------------------------------------------------------------

    /**
     * {@inheritDoc}
     *
     * <p>Chaum-Pedersen proof shows that {@code log_G(Qa) = log_c1(ka x c1)}.
     */
    @Override
    public Proven<BigInteger> decryptWithProof(CipherValue ciphertext) {
        BigInteger ka = keys.privateNumber("ka");
        CurvePoint[] pair = asPointPair(ciphertext);
        CurvePoint c1Ka = pair[0].multiply(ka);
        Proof proof =
                Zkp.proveDleq(
                        group(),
                        ecc.g(),
                        publicPoint(),
                        pair[0],
                        c1Ka,
                        ka,
                        DECRYPTION_DOMAIN,
                        List.of(ecc.n(), PointValue.from(pair[1])));
        return new Proven<>(c1Ka.negate().add(pair[1]).divide(ecc.g()), proof);
    }

    /**
     * {@inheritDoc}
     *
     * <p>The claimed plaintext is checked in modulo of the curve order.
     */
    @Override
    public boolean verifyDecryption(CipherValue ciphertext, BigInteger plaintext, Proof proof) {
        try {
            if (plaintext == null) {
                return false;
            }
            CurvePoint[] pair = asPointPair(ciphertext);

            // ka x c1 implied by the claimed plaintext
            BigInteger m = plaintext.mod(ecc.n());
            CurvePoint c1Ka = m.signum() == 0 ? pair[1] : pair[1].subtract(ecc.g().multiply(m));

            return Zkp.verifyDleq(
                    group(),
                    ecc.g(),
                    publicPoint(),
                    pair[0],
                    c1Ka,
                    proof,
                    DECRYPTION_DOMAIN,
                    List.of(ecc.n(), PointValue.from(pair[1])));
        } catch (RuntimeException err) {
            // malformed points raise errors of the elliptic curve
            return false;
        }
    }

    @Override
    public boolean supportsMembershipProofs() {
        return true;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Disjunctive Chaum-Pedersen proof shows that {@code c2 - v x G} is {@code r x Qa} for one
     * of the values v.
     */
    @Override
    public Proven<CipherValue> encryptWithProof(
            BigInteger plaintext, List<BigInteger> values, Object context) {
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
        CurvePoint[] pair = asPointPair(ciphertext);
        return Zkp.proveDleqOr(
                group(),
                ecc.g(),
                pair[0],
                publicPoint(),
                membershipCandidates(pair[1], values),
                randomKey,
                ElGamal.indexOf(values, plaintext),
                MEMBERSHIP_DOMAIN,
                Arrays.asList(ecc.n(), PointValue.from(pair[1]), values, context));
    }

    /**
     * {@inheritDoc}
     *
     * <p>{@code c1 = r x G} adds, so random keys add.
     */
    @Override
    public BigInteger combineRandomKeys(List<BigInteger> randomKeys) {
        return randomKeys.stream().reduce(BigInteger.ZERO, BigInteger::add);
    }

    @Override
    public boolean verifyCiphertext(
            CipherValue ciphertext, Proof proof, List<BigInteger> values, Object context) {
        try {
            CurvePoint[] pair = asPointPair(ciphertext);
            return Zkp.verifyDleqOr(
                    group(),
                    ecc.g(),
                    pair[0],
                    publicPoint(),
                    membershipCandidates(pair[1], values),
                    proof,
                    MEMBERSHIP_DOMAIN,
                    Arrays.asList(ecc.n(), PointValue.from(pair[1]), values, context));
        } catch (RuntimeException err) {
            // malformed points raise errors of the elliptic curve
            return false;
        }
    }

    /**
     * Candidates {@code c2 - v x G} for each value v. Ciphertext encrypts v if and only if its
     * candidate is {@code r x Qa} where {@code c1 = r x G}.
     */
    private List<CurvePoint> membershipCandidates(CurvePoint c2, List<BigInteger> values) {
        List<CurvePoint> candidates = new ArrayList<>(values.size());
        for (BigInteger value : values) {
            BigInteger m = value.mod(ecc.n());
            candidates.add(m.signum() == 0 ? c2 : c2.subtract(ecc.g().multiply(m)));
        }
        return candidates;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Schnorr proof shows knowledge of r where {@code c1 = r x G}, which reveals the plaintext
     * from c2. It is bound to c2, so a copied, re-randomized or modified ciphertext of someone else
     * cannot be proven.
     */
    @Override
    public Proven<CipherValue> encryptWithProofOfKnowledge(BigInteger plaintext, Object context) {
        BigInteger r = generateRandomKey();
        CipherValue ciphertext = encrypt(plaintext, r);
        TupleValue tuple = asTuple(ciphertext);
        Proof proof =
                Zkp.proveDlog(
                        group(),
                        ecc.g(),
                        toCurvePoint(tuple.get(0)),
                        r,
                        KNOWLEDGE_DOMAIN,
                        Arrays.asList(ecc.n(), tuple.get(1), context));
        return new Proven<>(ciphertext, proof);
    }

    @Override
    public boolean verifyKnowledge(CipherValue ciphertext, Proof proof, Object context) {
        try {
            // c2 must be a point on the curve
            CurvePoint[] pair = asPointPair(ciphertext);
            return Zkp.verifyDlog(
                    group(),
                    ecc.g(),
                    pair[0],
                    proof,
                    KNOWLEDGE_DOMAIN,
                    Arrays.asList(ecc.n(), PointValue.from(pair[1]), context));
        } catch (RuntimeException err) {
            // malformed points raise errors of the elliptic curve
            return false;
        }
    }

    private Zkp.EllipticCurveGroup group() {
        return new Zkp.EllipticCurveGroup(ecc);
    }

    private CurvePoint publicPoint() {
        KeyValue.Point qa = keys.publicPoint("Qa");
        return ecc.point(qa.x(), qa.y());
    }

    private CurvePoint[] asPointPair(CipherValue value) {
        TupleValue tuple = asTuple(value);
        if (tuple.size() != 2) {
            throw new IllegalArgumentException(
                    "expected a ciphertext pair, got " + tuple.size() + " components");
        }
        return new CurvePoint[] {toCurvePoint(tuple.get(0)), toCurvePoint(tuple.get(1))};
    }

    private CurvePoint toCurvePoint(CipherValue value) {
        if (!(value instanceof PointValue point)) {
            throw new IllegalArgumentException(
                    "expected an elliptic curve point, got " + value.getClass().getSimpleName());
        }
        return point.infinity() ? ecc.o() : ecc.point(point.x(), point.y());
    }
}
