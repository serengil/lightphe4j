package io.github.serengil.lightphe.cryptosystems;

import io.github.serengil.lightphe.commons.Logger;
import io.github.serengil.lightphe.commons.MathUtils;
import io.github.serengil.lightphe.model.Algorithm;
import io.github.serengil.lightphe.model.KeySpec;
import io.github.serengil.lightphe.model.KeyValue;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.PartialDecryption;
import io.github.serengil.lightphe.model.Proof;
import io.github.serengil.lightphe.model.Proven;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.IntValue;
import java.math.BigInteger;
import java.util.List;

/**
 * Paillier, homomorphic with respect to the addition. It also supports raising a ciphertext base to
 * a plaintext exponent, which yields scalar multiplication.
 *
 * <p>Ref: <a
 * href="https://sefiks.com/2023/04/03/a-step-by-step-partially-homomorphic-encryption-example-with-paillier-in-python/">
 * A step by step partially homomorphic encryption example with Paillier</a>
 */
public final class Paillier extends AbstractHomomorphic {

    /** The key fields Paillier requires. */
    public static final KeySpec REQUIRED_KEYS = KeySpec.of(List.of("g", "n"), List.of("phi"));

    private static final Logger logger = Logger.forModule(Paillier.class);

    /**
     * Builds a Paillier cryptosystem.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param keySize key size in bits; {@code null} defaults to 1024
     */
    public Paillier(Keys keys, Integer keySize) {
        super(
                Algorithm.PAILLIER,
                keys != null ? keys : generateKeys(keySize == null ? 1024 : keySize));
        BigInteger n = this.keys.publicNumber("n");
        this.plaintextModulo = n;
        this.ciphertextModulo = n.multiply(n);
    }

    /**
     * Builds a Paillier cryptosystem around an existing key pair.
     *
     * @param keys the private-public key pair
     */
    public Paillier(Keys keys) {
        this(keys, null);
    }

    /**
     * Generates the public and private keys of the Paillier cryptosystem.
     *
     * @param keySize key size in bits
     * @return the generated key pair
     */
    public static Keys generateKeys(int keySize) {
        Keys keys = Keys.empty();
        BigInteger lowerBound = BigInteger.valueOf(200);
        BigInteger upperBound = BigInteger.TWO.pow(keySize / 2).subtract(BigInteger.ONE);

        // picking a prime modulus p
        BigInteger p = MathUtils.randomPrime(lowerBound, upperBound);

        // picking a prime modulus q
        BigInteger q = MathUtils.randomPrime(lowerBound, upperBound);

        BigInteger n = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger g = BigInteger.ONE.add(n);

        keys.privateKey().put("phi", KeyValue.of(phi));
        keys.publicKey().put("g", KeyValue.of(g));
        keys.publicKey().put("n", KeyValue.of(n));
        return keys;
    }

    @Override
    public KeySpec requiredKeys() {
        return REQUIRED_KEYS;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Paillier requires a one-time random key co-prime to {@code n} per encryption.
     */
    @Override
    public BigInteger generateRandomKey() {
        BigInteger n = keys.publicNumber("n");
        while (true) {
            BigInteger r = MathUtils.randomInt(BigInteger.ZERO, n);
            if (r.gcd(n).equals(BigInteger.ONE)) {
                return r;
            }
        }
    }

    @Override
    public CipherValue encrypt(BigInteger plaintext) {
        return encrypt(plaintext, generateRandomKey());
    }

    /**
     * Encrypts a plaintext with an explicit random key.
     *
     * @param plaintext the message to encrypt
     * @param randomKey a random key co-prime to {@code n}
     * @return the ciphertext
     * @throws IllegalArgumentException when the random key is not co-prime to {@code n}
     */
    public CipherValue encrypt(BigInteger plaintext, BigInteger randomKey) {
        BigInteger g = keys.publicNumber("g");
        BigInteger n = keys.publicNumber("n");
        BigInteger nSquared = n.multiply(n);

        if (!randomKey.gcd(n).equals(BigInteger.ONE)) {
            throw new IllegalArgumentException("random key must be co-prime to n");
        }

        return IntValue.of(
                g.modPow(plaintext, nSquared)
                        .multiply(randomKey.modPow(n, nSquared))
                        .mod(nSquared));
    }

    @Override
    public BigInteger decrypt(CipherValue ciphertext) {
        BigInteger phi = keys.privateNumber("phi");
        BigInteger n = keys.publicNumber("n");
        BigInteger mu = phi.modInverse(n);
        BigInteger nSquared = n.multiply(n);

        return lx(asInt(ciphertext).modPow(phi, nSquared)).multiply(mu).mod(n);
    }

    /**
     * {@inheritDoc}
     *
     * <p>The result equals {@code E(m1 + m2)}; the arithmetic is done modulo {@code n^2}.
     */
    @Override
    public CipherValue add(CipherValue ciphertext1, CipherValue ciphertext2) {
        BigInteger n = keys.publicNumber("n");
        return IntValue.of(asInt(ciphertext1).multiply(asInt(ciphertext2)).mod(n.multiply(n)));
    }

    /**
     * {@inheritDoc}
     *
     * <p>The result equals {@code E(m * constant)}; the arithmetic is done modulo {@code n^2}.
     */
    @Override
    public CipherValue multiplyByConstant(CipherValue ciphertext, BigInteger constant) {
        BigInteger n = keys.publicNumber("n");
        BigInteger scalar = constant;

        if (scalar.compareTo(plaintextModulo) > 0) {
            scalar = scalar.mod(plaintextModulo);
            BigInteger normalized = scalar;
            logger.debug(
                    () ->
                            "Paillier can encrypt messages [1, "
                                    + n
                                    + "]. "
                                    + "Seems constant exceeded this limit. New constant is "
                                    + normalized);
        }

        return IntValue.of(asInt(ciphertext).modPow(scalar, n.multiply(n)));
    }

    @Override
    public CipherValue reencrypt(CipherValue ciphertext) {
        CipherValue neutralEncrypted = encrypt(BigInteger.ZERO);
        return add(ciphertext, neutralEncrypted);
    }

    // -----------------------------------------------------------------------
    // Threshold decryption
    // -----------------------------------------------------------------------

    /**
     * {@inheritDoc}
     *
     * <p>If keys are generated with safe primes, verification keys are published to verify partial
     * decryptions.
     */
    @Override
    public List<Keys> generateThresholdKeys(int threshold, int parties) {
        return proofs().generateThresholdKeys(threshold, parties);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Partial decryptions can be proven only if keys are generated with safe primes.
     */
    @Override
    public PartialDecryption partialDecrypt(CipherValue ciphertext, boolean prove) {
        return proofs().partialDecrypt(ciphertext, prove);
    }

    @Override
    public boolean verifyPartialDecryption(
            CipherValue ciphertext, PartialDecryption partialDecryption) {
        return proofs().verifyPartialDecryption(ciphertext, partialDecryption);
    }

    @Override
    public BigInteger combinePartialDecryptions(
            CipherValue ciphertext, List<PartialDecryption> partialDecryptions, boolean verify) {
        return proofs().combinePartialDecryptions(ciphertext, partialDecryptions, verify);
    }

    // -----------------------------------------------------------------------
    // Zero-knowledge proofs
    // -----------------------------------------------------------------------

    /**
     * {@inheritDoc}
     *
     * <p>Randomness of the ciphertext is the proof, and anyone having the public key can check it.
     */
    @Override
    public Proven<BigInteger> decryptWithProof(CipherValue ciphertext) {
        BigInteger plaintext = decrypt(ciphertext);
        return new Proven<>(plaintext, proofs().proveDecryption(ciphertext, plaintext));
    }

    @Override
    public boolean verifyDecryption(CipherValue ciphertext, BigInteger plaintext, Proof proof) {
        return proofs().verifyDecryption(ciphertext, plaintext, proof);
    }

    @Override
    public boolean supportsMembershipProofs() {
        return true;
    }

    /**
     * {@inheritDoc}
     *
     * <p>1-out-of-k proof of Damgard and Jurik shows that {@code c * g^-v} is an n-th power for one
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
        return proofs().proveMembership(ciphertext, plaintext, randomKey, values, context);
    }

    /**
     * {@inheritDoc}
     *
     * <p>{@code r^n} multiplies, so random keys multiply.
     */
    @Override
    public BigInteger combineRandomKeys(List<BigInteger> randomKeys) {
        return proofs().combineRandomKeys(randomKeys);
    }

    @Override
    public boolean verifyCiphertext(
            CipherValue ciphertext, Proof proof, List<BigInteger> values, Object context) {
        return proofs().verifyCiphertext(ciphertext, proof, values, context);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Proves knowledge of the plaintext and randomness, so a copied, re-randomized or modified
     * ciphertext of someone else cannot be proven.
     */
    @Override
    public Proven<CipherValue> encryptWithProofOfKnowledge(BigInteger plaintext, Object context) {
        BigInteger r = generateRandomKey();
        return proofs().proveKnowledge(encrypt(plaintext, r), plaintext, r, context);
    }

    @Override
    public boolean verifyKnowledge(CipherValue ciphertext, Proof proof, Object context) {
        return proofs().verifyKnowledge(ciphertext, proof, context);
    }

    private PaillierProofs proofs() {
        return new PaillierProofs(keys, 1, ciphertextModulo, "paillier");
    }

    /**
     * Finds the logarithm over the cyclic group: {@code (x - 1) / n}.
     *
     * @param x some integer
     * @return {@code (x - 1) / n}
     */
    public BigInteger lx(BigInteger x) {
        BigInteger n = keys.publicNumber("n");
        BigInteger[] division = x.subtract(BigInteger.ONE).divideAndRemainder(n);
        if (division[1].signum() != 0) {
            throw new IllegalArgumentException("(" + x + " - 1) is not divisible by " + n);
        }
        return division[0];
    }
}
