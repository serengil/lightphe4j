package io.github.serengil.lightphe.cryptosystems;

import io.github.serengil.lightphe.commons.Logger;
import io.github.serengil.lightphe.commons.MathUtils;
import io.github.serengil.lightphe.commons.SafePrimes;
import io.github.serengil.lightphe.ecc.CurvePoint;
import io.github.serengil.lightphe.ecc.LightECC;
import io.github.serengil.lightphe.ecc.PointNotOnCurveException;
import io.github.serengil.lightphe.model.Algorithm;
import io.github.serengil.lightphe.model.KeySpec;
import io.github.serengil.lightphe.model.KeyValue;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.VerifiableCiphertext;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.IntValue;
import io.github.serengil.lightphe.model.value.TupleValue;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * Camenisch-Shoup, homomorphic with respect to the addition. It also supports raising a ciphertext
 * base to a plaintext exponent, which yields scalar multiplication.
 *
 * <p>It is designed for verifiable encryption of discrete logarithms. A prover encrypts a secret
 * such as the private key of an elliptic curve public key for a trusted third party, and proves
 * that the ciphertext really contains it without revealing it. Anyone having the public key of the
 * trusted third party can verify the proof, and only the trusted third party can decrypt the
 * ciphertext.
 *
 * <p>Verifiable encryption has three steps run by three parties:
 *
 * <ul>
 *   <li>{@link #encryptVerifiably}: prover (e.g. Alice) encrypts her secret and creates the proof
 *   <li>{@link #verifyEncryption}: verifier (e.g. a bank) checks the proof against the public point
 *       it already knows, without learning the secret
 *   <li>{@link #decryptVerifiableCiphertext}: trusted third party restores the secret
 * </ul>
 *
 * <p>Only the last step requires the private key.
 *
 * <p>Ciphertexts for homomorphic operations are {@code (u, e)} pairs. Verifiable ciphertexts
 * additionally have a validity tag v bound to a label, which makes them secure against chosen
 * ciphertext attacks. Homomorphic operations drop that tag, as non-malleability and homomorphism
 * contradict each other.
 *
 * <p>The proof follows the paper with Fiat-Shamir heuristic. Its soundness relies on the auxiliary
 * RSA modulus {@code n_bar}, whose factorization is discarded during key generation and must not be
 * known by the prover.
 *
 * <p>Ref: Camenisch, J., Shoup, V. (2003). Practical Verifiable Encryption and Decryption of
 * Discrete Logarithms. CRYPTO 2003.
 */
public final class CamenischShoup extends AbstractHomomorphic {

    /** The key fields Camenisch-Shoup requires. */
    public static final KeySpec REQUIRED_KEYS =
            KeySpec.of(
                    List.of("n", "g", "y1", "y2", "y3", "n_bar", "g_bar", "h_bar"),
                    List.of("x1", "x2", "x3"));

    /** Challenge length of the proof in bits - soundness error is {@code 2^-CHALLENGE_BITS}. */
    private static final int CHALLENGE_BITS = 128;

    /** Statistical zero-knowledge parameter of the proof in bits. */
    private static final int STATISTICAL_BITS = 80;

    private static final Logger logger = Logger.forModule(CamenischShoup.class);

    private final String form;
    private final String curve;

    /** Elliptic curve of the secrets, built lazily as homomorphic operations do not need it. */
    private volatile LightECC ecc;

    /**
     * Builds a Camenisch-Shoup cryptosystem.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param keySize key size in bits; {@code null} defaults to 1024
     * @param maxTries maximum attempts to generate keys
     * @param form form of the elliptic curve of the secrets to be encrypted verifiably: {@code
     *     weierstrass} (default), {@code edwards} or {@code koblitz}
     * @param curve elliptic curve of the secrets to be encrypted verifiably; defaults to secp256k1
     *     for the Weierstrass form
     */
    public CamenischShoup(Keys keys, Integer keySize, int maxTries, String form, String curve) {
        super(
                Algorithm.CAMENISCH_SHOUP,
                keys != null ? keys : generateKeys(keySize == null ? 1024 : keySize, maxTries));
        this.form = form;
        this.curve = curve;
        BigInteger n = this.keys.publicNumber("n");
        this.plaintextModulo = n;
        this.ciphertextModulo = n.multiply(n);
    }

    /**
     * Builds a Camenisch-Shoup cryptosystem around an existing key pair.
     *
     * @param keys the private-public key pair
     */
    public CamenischShoup(Keys keys) {
        this(keys, null, CryptosystemFactory.DEFAULT_MAX_TRIES, null, null);
    }

    /**
     * Returns the elliptic curve of the secrets to be encrypted verifiably.
     *
     * @return the curve
     */
    public LightECC ecc() {
        LightECC built = ecc;
        if (built == null) {
            built = LightECC.of(form, curve);
            ecc = built;
        }
        return built;
    }

    /**
     * Generates the public and private keys of the Camenisch-Shoup cryptosystem.
     *
     * @param keySize key size in bits
     * @param maxTries maximum number of tries to generate keys
     * @return the generated key pair
     * @throws IllegalArgumentException when the key size is too small or no generator is found
     */
    public static Keys generateKeys(int keySize, int maxTries) {
        if (keySize < 16) {
            throw new IllegalArgumentException(
                    "Key size " + keySize + " is too small for Camenisch-Shoup");
        }

        // n = pq where p = 2p' + 1 and q = 2q' + 1 are safe primes
        BigInteger[] primes = findSafePrimePair(keySize, maxTries);
        BigInteger p = primes[0];
        BigInteger q = primes[1];
        BigInteger n = p.multiply(q);
        BigInteger nSquare = n.multiply(n);
        BigInteger pPrime = p.subtract(BigInteger.ONE).shiftRight(1);
        BigInteger qPrime = q.subtract(BigInteger.ONE).shiftRight(1);

        // g is a 2n-th power in Z_{n^2}*, so its order divides p'q'
        BigInteger g = null;
        for (int attempt = 0; attempt < maxTries; attempt++) {
            BigInteger candidate =
                    MathUtils.randomInt(BigInteger.TWO, nSquare.subtract(BigInteger.ONE))
                            .modPow(n.shiftLeft(1), nSquare);
            if (!candidate.modPow(pPrime, nSquare).equals(BigInteger.ONE)
                    && !candidate.modPow(qPrime, nSquare).equals(BigInteger.ONE)) {
                g = candidate;
                break;
            }
        }
        if (g == null) {
            throw new IllegalArgumentException(
                    "Failed to find a suitable generator in " + maxTries + " tries");
        }

        BigInteger quarter = nSquare.shiftRight(2);
        BigInteger x1 = MathUtils.randomInt(BigInteger.ONE, quarter);
        BigInteger x2 = MathUtils.randomInt(BigInteger.ONE, quarter);
        BigInteger x3 = MathUtils.randomInt(BigInteger.ONE, quarter);

        // auxiliary RSA modulus for the proof. its factorization is discarded.
        BigInteger[] auxiliary = findSafePrimePair(keySize, maxTries);
        BigInteger pBar = auxiliary[0];
        BigInteger qBar = auxiliary[1];
        BigInteger nBar = pBar.multiply(qBar);
        BigInteger hBar = null;
        for (int attempt = 0; attempt < maxTries; attempt++) {
            BigInteger candidate =
                    MathUtils.randomInt(BigInteger.TWO, nBar.subtract(BigInteger.ONE))
                            .modPow(BigInteger.TWO, nBar);
            if (!candidate.mod(pBar).equals(BigInteger.ONE)
                    && !candidate.mod(qBar).equals(BigInteger.ONE)) {
                hBar = candidate;
                break;
            }
        }
        if (hBar == null) {
            throw new IllegalArgumentException(
                    "Failed to find a suitable generator in " + maxTries + " tries");
        }
        BigInteger gBar =
                hBar.modPow(MathUtils.randomInt(BigInteger.TWO, nBar.shiftRight(2)), nBar);

        Keys keys = Keys.empty();
        keys.publicKey().put("n", KeyValue.of(n));
        keys.publicKey().put("g", KeyValue.of(g));
        keys.publicKey().put("y1", KeyValue.of(g.modPow(x1, nSquare)));
        keys.publicKey().put("y2", KeyValue.of(g.modPow(x2, nSquare)));
        keys.publicKey().put("y3", KeyValue.of(g.modPow(x3, nSquare)));
        keys.publicKey().put("n_bar", KeyValue.of(nBar));
        keys.publicKey().put("g_bar", KeyValue.of(gBar));
        keys.publicKey().put("h_bar", KeyValue.of(hBar));

        keys.privateKey().put("x1", KeyValue.of(x1));
        keys.privateKey().put("x2", KeyValue.of(x2));
        keys.privateKey().put("x3", KeyValue.of(x3));
        return keys;
    }

    @Override
    public KeySpec requiredKeys() {
        return REQUIRED_KEYS;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Camenisch-Shoup requires a one-time random key per encryption.
     */
    @Override
    public BigInteger generateRandomKey() {
        BigInteger n = keys.publicNumber("n");
        return MathUtils.randomInt(BigInteger.ONE, n.shiftRight(2).max(BigInteger.ONE));
    }

    @Override
    public CipherValue encrypt(BigInteger plaintext) {
        return encrypt(plaintext, generateRandomKey());
    }

    /**
     * Encrypts a plaintext with an explicit random key.
     *
     * @param plaintext the message to encrypt in {@code [0, n)}
     * @param randomKey the random key
     * @return the ciphertext {@code (u, e)} where {@code u = g^r mod n^2} and {@code e = y1^r (1 +
     *     n)^m mod n^2}
     */
    public CipherValue encrypt(BigInteger plaintext, BigInteger randomKey) {
        BigInteger[] ciphertext = encryptPair(plaintext, randomKey);
        return TupleValue.of(IntValue.of(ciphertext[0]), IntValue.of(ciphertext[1]));
    }

    private BigInteger[] encryptPair(BigInteger plaintext, BigInteger randomKey) {
        BigInteger n = keys.publicNumber("n");
        BigInteger g = keys.publicNumber("g");
        BigInteger y1 = keys.publicNumber("y1");
        BigInteger nSquare = n.multiply(n);

        BigInteger message = plaintext;
        if (message.compareTo(n) >= 0) {
            message = message.mod(n);
            BigInteger normalized = message;
            logger.debug(
                    () ->
                            "Camenisch-Shoup can encrypt messages [0, "
                                    + n
                                    + "). Seems plaintext exceeded this limit. New plaintext is "
                                    + normalized);
        }

        BigInteger u = g.modPow(randomKey, nSquare);
        BigInteger e =
                y1.modPow(randomKey, nSquare)
                        .multiply(BigInteger.ONE.add(message.multiply(n)))
                        .mod(nSquare);
        return new BigInteger[] {u, e};
    }

    /**
     * {@inheritDoc}
     *
     * @throws IllegalArgumentException when the ciphertext is not a {@code (u, e)} pair
     */
    @Override
    public BigInteger decrypt(CipherValue ciphertext) {
        TupleValue tuple = asTuple(ciphertext);
        if (tuple.size() != 2) {
            throw new IllegalArgumentException(
                    "Ciphertext must be a (u, e) pair. "
                            + "Decrypt verifiable ciphertexts with their labels.");
        }
        return recover(asInt(tuple.get(0)), asInt(tuple.get(1)));
    }

    /**
     * Encrypts a plaintext securely against chosen ciphertext attacks. The ciphertext can be
     * decrypted with the same label only.
     *
     * @param plaintext the message to encrypt in {@code [0, n)}
     * @param label public data bound to the ciphertext, e.g. decryption conditions
     * @return the ciphertext {@code (u, e, v)} where v is the validity tag
     */
    public CipherValue encryptWithLabel(BigInteger plaintext, String label) {
        return encryptWithLabel(plaintext, label, generateRandomKey());
    }

    /**
     * Encrypts a plaintext securely against chosen ciphertext attacks with an explicit random key.
     *
     * @param plaintext the message to encrypt in {@code [0, n)}
     * @param label public data bound to the ciphertext, e.g. decryption conditions
     * @param randomKey the random key
     * @return the ciphertext {@code (u, e, v)} where v is the validity tag
     */
    public CipherValue encryptWithLabel(BigInteger plaintext, String label, BigInteger randomKey) {
        BigInteger[] ciphertext = encryptTriple(plaintext, label, randomKey);
        return TupleValue.ofIntegers(List.of(ciphertext));
    }

    private BigInteger[] encryptTriple(BigInteger plaintext, String label, BigInteger randomKey) {
        BigInteger n = keys.publicNumber("n");
        BigInteger nSquare = n.multiply(n);
        BigInteger[] pair = encryptPair(plaintext, randomKey);
        BigInteger tagBase = tagBase(pair[0], pair[1], label);
        BigInteger v = abs(tagBase.modPow(randomKey, nSquare));
        return new BigInteger[] {pair[0], pair[1], v};
    }

    /**
     * Decrypts a ciphertext created with {@link #encryptWithLabel}. It is rejected if it was
     * modified or its label is different.
     *
     * @param ciphertext the {@code (u, e, v)} triple
     * @param label the label used in encryption
     * @return the restored message
     * @throws IllegalArgumentException when the ciphertext is invalid or bound to another label
     */
    public BigInteger decryptWithLabel(CipherValue ciphertext, String label) {
        TupleValue tuple = asTuple(ciphertext);
        if (tuple.size() != 3) {
            throw new IllegalArgumentException("Verifiable ciphertext must be a (u, e, v) triple");
        }
        return decryptWithLabel(
                asInt(tuple.get(0)), asInt(tuple.get(1)), asInt(tuple.get(2)), label);
    }

    private BigInteger decryptWithLabel(BigInteger u, BigInteger e, BigInteger v, String label) {
        BigInteger n = keys.publicNumber("n");
        BigInteger x2 = keys.privateNumber("x2");
        BigInteger x3 = keys.privateNumber("x3");
        BigInteger nSquare = n.multiply(n);

        BigInteger tagExponent = x2.add(hashTag(u, e, label).multiply(x3)).shiftLeft(1);
        if (!v.equals(abs(v))
                || !u.modPow(tagExponent, nSquare).equals(v.modPow(BigInteger.TWO, nSquare))) {
            throw new IllegalArgumentException(
                    "Ciphertext is invalid or was encrypted with a different label");
        }

        return recover(u, e);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Runs on prover side, e.g. Alice escrowing her wallet key to a trusted third party. Only
     * the prover can call this, because it needs the secret itself. Public key of the trusted third
     * party is enough, the private key is not needed. Output is sent to the verifier, who checks it
     * with {@link #verifyEncryption}.
     *
     * @throws IllegalArgumentException when the key size is too small for the curve, or the secret
     *     is a multiple of the order of the curve
     */
    @Override
    public VerifiableCiphertext encryptVerifiably(BigInteger secret, String label) {
        validateVerifiableEncryption();
        BigInteger n = keys.publicNumber("n");
        BigInteger g = keys.publicNumber("g");
        BigInteger y1 = keys.publicNumber("y1");
        BigInteger nBar = keys.publicNumber("n_bar");
        BigInteger gBar = keys.publicNumber("g_bar");
        BigInteger hBar = keys.publicNumber("h_bar");
        BigInteger nSquare = n.multiply(n);
        LightECC curve = ecc();
        BigInteger order = curve.n();
        BigInteger bound = BigInteger.ONE.shiftLeft(CHALLENGE_BITS + STATISTICAL_BITS);

        BigInteger m = secret.mod(order);
        if (m.signum() == 0) {
            throw new IllegalArgumentException(
                    "Secret must not be a multiple of the order of the curve");
        }
        CurvePoint publicPoint = curve.g().multiply(m);

        BigInteger r = generateRandomKey();
        BigInteger[] ciphertext = encryptTriple(m, label, r);
        BigInteger u = ciphertext[0];
        BigInteger e = ciphertext[1];
        BigInteger v = ciphertext[2];
        BigInteger tagBase = tagBase(u, e, label);

        // commitment to the secret in auxiliary group
        BigInteger s = MathUtils.randomInt(BigInteger.ONE, nBar.shiftRight(2));
        BigInteger l = gBar.modPow(m, nBar).multiply(hBar.modPow(s, nBar)).mod(nBar);

        // random masks statistically hiding the secret, r and s
        BigInteger rMask = symmetricRandom(n.shiftRight(2).multiply(bound));
        BigInteger sMask = symmetricRandom(nBar.shiftRight(2).multiply(bound));
        BigInteger mMask = symmetricRandom(order.multiply(bound));

        BigInteger onePlusN = BigInteger.ONE.add(n);
        List<Object> commitments =
                List.of(
                        g.modPow(rMask.shiftLeft(1), nSquare),
                        y1.modPow(rMask.shiftLeft(1), nSquare)
                                .multiply(onePlusN.modPow(mMask.shiftLeft(1), nSquare))
                                .mod(nSquare),
                        tagBase.modPow(rMask.shiftLeft(1), nSquare),
                        curve.g().multiply(mMask.mod(order)),
                        gBar.modPow(mMask, nBar).multiply(hBar.modPow(sMask, nBar)).mod(nBar));

        BigInteger challenge = challenge(publicPoint, label, u, e, v, l, commitments);

        return new VerifiableCiphertext(
                u,
                e,
                v,
                l,
                new VerifiableCiphertext.Proof(
                        challenge,
                        rMask.subtract(challenge.multiply(r)),
                        sMask.subtract(challenge.multiply(s)),
                        mMask.subtract(challenge.multiply(m))));
    }

    /**
     * {@inheritDoc}
     *
     * <p>Runs on verifier side, e.g. a bank that knows Alice's public key only. The verifier cannot
     * trust the prover's word, because the prover could encrypt 0 or an unrelated key instead. This
     * checks the proof against the public point and the label that the verifier already knows, so
     * it confirms the escrow is real without learning the secret. Public key of the trusted third
     * party is enough, the private key is not needed.
     */
    @Override
    public boolean verifyEncryption(
            VerifiableCiphertext verifiableCiphertext, CurvePoint publicPoint, String label) {
        validateVerifiableEncryption();
        BigInteger n = keys.publicNumber("n");
        BigInteger g = keys.publicNumber("g");
        BigInteger y1 = keys.publicNumber("y1");
        BigInteger nBar = keys.publicNumber("n_bar");
        BigInteger gBar = keys.publicNumber("g_bar");
        BigInteger hBar = keys.publicNumber("h_bar");
        BigInteger nSquare = n.multiply(n);
        LightECC curve = ecc();
        BigInteger order = curve.n();

        if (!isWellFormed(verifiableCiphertext)) {
            return false;
        }
        BigInteger u = verifiableCiphertext.u();
        BigInteger e = verifiableCiphertext.e();
        BigInteger v = verifiableCiphertext.v();
        BigInteger l = verifiableCiphertext.commitment();
        BigInteger challenge = verifiableCiphertext.proof().challenge();
        BigInteger rz = verifiableCiphertext.proof().r();
        BigInteger sz = verifiableCiphertext.proof().s();
        BigInteger mz = verifiableCiphertext.proof().m();

        // rebuild the point on this cryptosystem's curve, rejecting points of other curves
        CurvePoint point;
        try {
            if (publicPoint == null || publicPoint.isInfinity()) {
                return false;
            }
            point = curve.point(publicPoint.x(), publicPoint.y());
        } catch (PointNotOnCurveException err) {
            return false;
        }
        if (point.equals(curve.o())) {
            return false;
        }
        BigInteger tagBase = tagBase(u, e, label);

        List<Object> commitments;
        try {
            BigInteger twoChallenge = challenge.shiftLeft(1);
            BigInteger twoRz = rz.shiftLeft(1);
            commitments =
                    List.of(
                            u.modPow(twoChallenge, nSquare)
                                    .multiply(g.modPow(twoRz, nSquare))
                                    .mod(nSquare),
                            e.modPow(twoChallenge, nSquare)
                                    .multiply(y1.modPow(twoRz, nSquare))
                                    .multiply(
                                            BigInteger.ONE.add(n).modPow(mz.shiftLeft(1), nSquare))
                                    .mod(nSquare),
                            v.modPow(twoChallenge, nSquare)
                                    .multiply(tagBase.modPow(twoRz, nSquare))
                                    .mod(nSquare),
                            point.multiply(challenge).add(curve.g().multiply(mz.mod(order))),
                            l.modPow(challenge, nBar)
                                    .multiply(gBar.modPow(mz, nBar))
                                    .multiply(hBar.modPow(sz, nBar))
                                    .mod(nBar));
        } catch (ArithmeticException err) {
            // not invertible
            return false;
        }

        return challenge.equals(challenge(point, label, u, e, v, l, commitments));
    }

    /** Checks the ranges of a verifiable ciphertext before its proof is verified. */
    private boolean isWellFormed(VerifiableCiphertext verifiableCiphertext) {
        BigInteger n = keys.publicNumber("n");
        BigInteger nSquare = n.multiply(n);
        BigInteger nBar = keys.publicNumber("n_bar");
        BigInteger bound = BigInteger.ONE.shiftLeft(CHALLENGE_BITS + STATISTICAL_BITS);

        for (BigInteger x :
                List.of(
                        verifiableCiphertext.u(),
                        verifiableCiphertext.e(),
                        verifiableCiphertext.v())) {
            if (x.signum() <= 0 || x.compareTo(nSquare) >= 0) {
                return false;
            }
        }
        BigInteger l = verifiableCiphertext.commitment();
        BigInteger challenge = verifiableCiphertext.proof().challenge();
        return verifiableCiphertext.v().equals(abs(verifiableCiphertext.v()))
                && l.signum() > 0
                && l.compareTo(nBar) < 0
                && challenge.signum() >= 0
                && challenge.bitLength() <= CHALLENGE_BITS
                // secret must be small enough to be restored from its encryption mod n
                && verifiableCiphertext
                                .proof()
                                .m()
                                .abs()
                                .compareTo(ecc().n().shiftLeft(1).multiply(bound))
                        <= 0;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Runs on the side of the private key owner, e.g. a trusted third party, when the conditions
     * in the label are met. This is the only step requiring the private key, and the only way to
     * restore the secret. It does not check the proof, as {@link #verifyEncryption} does that.
     */
    @Override
    public BigInteger decryptVerifiableCiphertext(
            VerifiableCiphertext verifiableCiphertext, String label) {
        BigInteger n = keys.publicNumber("n");
        BigInteger m =
                decryptWithLabel(
                        verifiableCiphertext.u(),
                        verifiableCiphertext.e(),
                        verifiableCiphertext.v(),
                        label);
        // proof guarantees that the secret is in (-n/2, n/2)
        if (m.compareTo(n.shiftRight(1)) > 0) {
            m = m.subtract(n);
        }
        return m.mod(ecc().n());
    }

    /**
     * {@inheritDoc}
     *
     * <p>The result equals {@code E(m1 + m2)}. Validity tags of verifiable ciphertexts are dropped.
     */
    @Override
    public CipherValue add(CipherValue ciphertext1, CipherValue ciphertext2) {
        BigInteger n = keys.publicNumber("n");
        BigInteger nSquare = n.multiply(n);
        TupleValue first = asTuple(ciphertext1);
        TupleValue second = asTuple(ciphertext2);
        return TupleValue.of(
                IntValue.of(asInt(first.get(0)).multiply(asInt(second.get(0))).mod(nSquare)),
                IntValue.of(asInt(first.get(1)).multiply(asInt(second.get(1))).mod(nSquare)));
    }

    /**
     * {@inheritDoc}
     *
     * <p>The result equals {@code E(m * constant)}. Validity tags of verifiable ciphertexts are
     * dropped.
     */
    @Override
    public CipherValue multiplyByConstant(CipherValue ciphertext, BigInteger constant) {
        BigInteger n = keys.publicNumber("n");
        BigInteger nSquare = n.multiply(n);
        BigInteger scalar = constant;

        if (scalar.compareTo(plaintextModulo) >= 0) {
            scalar = scalar.mod(plaintextModulo);
            BigInteger normalized = scalar;
            logger.debug(
                    () ->
                            "Camenisch-Shoup can encrypt messages [0, "
                                    + n
                                    + "). Seems constant exceeded this limit. New constant is "
                                    + normalized);
        }

        TupleValue tuple = asTuple(ciphertext);
        return TupleValue.of(
                IntValue.of(asInt(tuple.get(0)).modPow(scalar, nSquare)),
                IntValue.of(asInt(tuple.get(1)).modPow(scalar, nSquare)));
    }

    @Override
    public CipherValue reencrypt(CipherValue ciphertext) {
        return add(ciphertext, encrypt(BigInteger.ZERO));
    }

    /** Restores the plaintext from a {@code (u, e)} pair. */
    private BigInteger recover(BigInteger u, BigInteger e) {
        BigInteger n = keys.publicNumber("n");
        BigInteger x1 = keys.privateNumber("x1");
        BigInteger nSquare = n.multiply(n);

        // (e / u^x1)^(2t) = (1 + n)^m where t = 1/2 mod n
        BigInteger twoT = BigInteger.TWO.modInverse(n).shiftLeft(1);
        BigInteger mHat =
                e.multiply(u.modPow(x1, nSquare).modInverse(nSquare))
                        .mod(nSquare)
                        .modPow(twoT, nSquare);
        if (!mHat.mod(n).equals(BigInteger.ONE)) {
            throw new IllegalArgumentException("Ciphertext is invalid");
        }
        return mHat.subtract(BigInteger.ONE).divide(n);
    }

    /** Returns the base of the validity tag v: {@code y2 * y3^H(u, e, label) mod n^2}. */
    private BigInteger tagBase(BigInteger u, BigInteger e, String label) {
        BigInteger n = keys.publicNumber("n");
        BigInteger nSquare = n.multiply(n);
        BigInteger y2 = keys.publicNumber("y2");
        BigInteger y3 = keys.publicNumber("y3");
        return y2.multiply(y3.modPow(hashTag(u, e, label), nSquare)).mod(nSquare);
    }

    /**
     * Hashes a ciphertext and its label for the validity tag. It is smaller than p' and q' as
     * required by the scheme.
     */
    private BigInteger hashTag(BigInteger u, BigInteger e, String label) {
        BigInteger n = keys.publicNumber("n");
        int bits = Math.min(256, Math.max(1, n.bitLength() / 2 - 2));
        return sha256("tag|" + u + "|" + e + "|" + label).mod(BigInteger.ONE.shiftLeft(bits));
    }

    /** Fiat-Shamir challenge of the proof, hashing the same string as the Python library. */
    private BigInteger challenge(
            CurvePoint publicPoint,
            String label,
            BigInteger u,
            BigInteger e,
            BigInteger v,
            BigInteger l,
            List<Object> commitments) {
        List<String> items = new ArrayList<>();
        for (String field : REQUIRED_KEYS.publicKey()) {
            items.add(keys.publicNumber(field).toString());
        }
        items.add(formatPoint(ecc().g()));
        items.add(formatPoint(publicPoint));
        items.add(label);
        for (BigInteger item : List.of(u, e, v, l)) {
            items.add(item.toString());
        }
        for (Object commitment : commitments) {
            items.add(
                    commitment instanceof CurvePoint point
                            ? formatPoint(point)
                            : commitment.toString());
        }
        String data = String.join("|", items);
        return sha256("challenge|" + data).mod(BigInteger.ONE.shiftLeft(CHALLENGE_BITS));
    }

    /** Renders a point as Python renders the tuple returned by {@code get_point}. */
    private static String formatPoint(CurvePoint point) {
        return point.isInfinity() ? "(None, None)" : "(" + point.x() + ", " + point.y() + ")";
    }

    /**
     * Returns the absolute value of an element of {@code Z_(n^2)}, where elements greater than
     * {@code n^2 / 2} are considered negative.
     */
    private BigInteger abs(BigInteger a) {
        BigInteger n = keys.publicNumber("n");
        BigInteger nSquare = n.multiply(n);
        return a.compareTo(nSquare.shiftRight(1)) > 0 ? nSquare.subtract(a) : a;
    }

    /**
     * Secrets must be restorable from their encryption mod n, even if they are extracted from a
     * cheating prover.
     */
    private void validateVerifiableEncryption() {
        BigInteger n = keys.publicNumber("n");
        BigInteger minimum = ecc().n().shiftLeft(CHALLENGE_BITS + STATISTICAL_BITS + 3);
        if (n.compareTo(minimum) <= 0) {
            throw new IllegalArgumentException(
                    "Key size "
                            + n.bitLength()
                            + " is too small for verifiable encryption. "
                            + "It must be greater than "
                            + minimum.bitLength()
                            + " bits for this curve.");
        }
    }

    /** Draws a uniformly random integer in {@code [-bound, bound]}. */
    private static BigInteger symmetricRandom(BigInteger bound) {
        return MathUtils.randomInt(bound.negate(), bound);
    }

    private static BigInteger sha256(String data) {
        try {
            byte[] digest =
                    MessageDigest.getInstance("SHA-256")
                            .digest(data.getBytes(StandardCharsets.UTF_8));
            return new BigInteger(1, digest);
        } catch (NoSuchAlgorithmException err) {
            throw new IllegalStateException("SHA-256 is not available", err);
        }
    }

    /** Finds two different safe primes for a modulus of keySize bits. */
    private static BigInteger[] findSafePrimePair(int keySize, int maxTries) {
        BigInteger p = SafePrimes.findSafePrime(keySize / 2, maxTries);
        BigInteger q = SafePrimes.findSafePrime(keySize / 2, maxTries);
        while (q.equals(p)) {
            q = SafePrimes.findSafePrime(keySize / 2, maxTries);
        }
        return new BigInteger[] {p, q};
    }
}
