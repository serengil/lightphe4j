package io.github.serengil.lightphe.cryptosystems;

import io.github.serengil.lightphe.commons.Logger;
import io.github.serengil.lightphe.commons.MathUtils;
import io.github.serengil.lightphe.model.Algorithm;
import io.github.serengil.lightphe.model.KeySpec;
import io.github.serengil.lightphe.model.KeyValue;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.IntValue;
import java.math.BigInteger;
import java.util.List;

/**
 * Okamoto-Uchiyama, homomorphic with respect to the addition over the modulus {@code n = p^2 * q}.
 *
 * <p>Ref: <a
 * href="https://sefiks.com/2023/10/20/a-step-by-step-partially-homomorphic-encryption-example-with-okamoto-uchiyama-in-python/">
 * A step by step partially homomorphic encryption example with Okamoto-Uchiyama</a>
 */
public final class OkamotoUchiyama extends AbstractHomomorphic {

    /** The key fields Okamoto-Uchiyama requires. */
    public static final KeySpec REQUIRED_KEYS =
            KeySpec.of(List.of("n", "g", "h"), List.of("p", "q"));

    private static final Logger logger = Logger.forModule(OkamotoUchiyama.class);

    /**
     * Builds an Okamoto-Uchiyama cryptosystem.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param keySize key size in bits; {@code null} defaults to 1024
     */
    public OkamotoUchiyama(Keys keys, Integer keySize) {
        super(
                Algorithm.OKAMOTO_UCHIYAMA,
                keys != null ? keys : generateKeys(keySize == null ? 1024 : keySize));
        this.plaintextModulo = this.keys.publicNumber("n");
        this.ciphertextModulo = this.keys.publicNumber("n");
    }

    /**
     * Builds an Okamoto-Uchiyama cryptosystem around an existing key pair.
     *
     * @param keys the private-public key pair
     */
    public OkamotoUchiyama(Keys keys) {
        this(keys, null);
    }

    /**
     * Generates the public and private keys of the Okamoto-Uchiyama cryptosystem.
     *
     * @param keySize key size in bits
     * @return the generated key pair
     * @throws IllegalArgumentException when Fermat's little theorem is violated by the generator
     */
    public static Keys generateKeys(int keySize) {
        Keys keys = Keys.empty();
        BigInteger lowerBound = BigInteger.valueOf(200);
        BigInteger upperBound = BigInteger.TWO.pow(keySize / 2).subtract(BigInteger.ONE);

        // picking a prime modulus p
        BigInteger p = MathUtils.randomPrime(lowerBound, upperBound);

        // picking a prime modulus q
        BigInteger q = MathUtils.randomPrime(lowerBound, upperBound);

        // modulo
        BigInteger n = p.multiply(p).multiply(q);

        // generator
        BigInteger g = MathUtils.randomInt(BigInteger.TWO, n);

        if (g.modPow(p.subtract(BigInteger.ONE), p.multiply(p)).equals(BigInteger.ONE)) {
            throw new IllegalArgumentException("Fermat's Little Theorem must be satisfied");
        }

        BigInteger h = g.modPow(n, n);

        keys.publicKey().put("n", KeyValue.of(n));
        keys.publicKey().put("g", KeyValue.of(g));
        keys.publicKey().put("h", KeyValue.of(h));
        keys.privateKey().put("p", KeyValue.of(p));
        keys.privateKey().put("q", KeyValue.of(q));
        return keys;
    }

    @Override
    public KeySpec requiredKeys() {
        return REQUIRED_KEYS;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Okamoto-Uchiyama requires a one-time random key per encryption.
     */
    @Override
    public BigInteger generateRandomKey() {
        BigInteger n = keys.publicNumber("n");
        return MathUtils.randomInt(BigInteger.ONE, n.subtract(BigInteger.ONE));
    }

    @Override
    public CipherValue encrypt(BigInteger plaintext) {
        return encrypt(plaintext, generateRandomKey());
    }

    /**
     * Encrypts a plaintext with an explicit random key.
     *
     * @param plaintext the message to encrypt
     * @param randomKey the random key
     * @return the ciphertext
     */
    public CipherValue encrypt(BigInteger plaintext, BigInteger randomKey) {
        BigInteger g = keys.publicNumber("g");
        BigInteger n = keys.publicNumber("n");
        BigInteger h = keys.publicNumber("h");

        BigInteger message = plaintext;

        // having the private key is not a must to encrypt, but use it when it is there
        if (keys.hasPrivateKey()) {
            BigInteger p = keys.privateNumber("p");
            if (message.compareTo(p) > 0) {
                message = message.mod(p);
                BigInteger normalized = message;
                logger.debug(
                        () ->
                                "plaintext must be in scale [0, p="
                                        + p
                                        + "] but this is "
                                        + "exceeded. New plaintext is "
                                        + normalized);
            }
        }

        return IntValue.of(g.modPow(message, n).multiply(h.modPow(randomKey, n)).mod(n));
    }

    @Override
    public BigInteger decrypt(CipherValue ciphertext) {
        BigInteger p = keys.privateNumber("p");
        BigInteger g = keys.publicNumber("g");
        BigInteger pSquared = p.multiply(p);

        BigInteger a = lx(asInt(ciphertext).modPow(p.subtract(BigInteger.ONE), pSquared));
        BigInteger b = lx(g.modPow(p.subtract(BigInteger.ONE), pSquared));
        return a.multiply(b.modInverse(p)).mod(p);
    }

    /**
     * {@inheritDoc}
     *
     * <p>The result equals {@code E(m1 + m2)}; the arithmetic is done modulo {@code n}.
     */
    @Override
    public CipherValue add(CipherValue ciphertext1, CipherValue ciphertext2) {
        BigInteger n = keys.publicNumber("n");
        return IntValue.of(asInt(ciphertext1).multiply(asInt(ciphertext2)).mod(n));
    }

    /**
     * {@inheritDoc}
     *
     * <p>The result equals {@code E(m * constant)}.
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
                            "Okamoto-Uchiyama can encrypt messages [1, "
                                    + n
                                    + "]. "
                                    + "Seems constant exceeded this limit. New constant is "
                                    + normalized);
        }
        return IntValue.of(asInt(ciphertext).modPow(scalar, n));
    }

    @Override
    public CipherValue reencrypt(CipherValue ciphertext) {
        CipherValue neutralEncrypted = encrypt(BigInteger.ZERO);
        return add(ciphertext, neutralEncrypted);
    }

    /**
     * Finds the logarithm over the cyclic group: {@code (x - 1) / p}.
     *
     * @param x some integer
     * @return {@code (x - 1) / p}
     * @throws IllegalArgumentException when {@code x} is not congruent to 1 modulo {@code p}, or is
     *     not co-prime to {@code p^2}
     */
    public BigInteger lx(BigInteger x) {
        BigInteger p = keys.privateNumber("p");
        if (!x.mod(p).equals(BigInteger.ONE)) {
            throw new IllegalArgumentException(
                    "Input passed to lx (" + x + ") must be identical to 1 in modulo " + p);
        }
        if (!x.gcd(p.multiply(p)).equals(BigInteger.ONE)) {
            throw new IllegalArgumentException("gcd(" + x + ", " + p + "^2) must be equal to 1");
        }
        return x.subtract(BigInteger.ONE).divide(p);
    }
}
