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
 * RSA, partially homomorphic with respect to the multiplication.
 *
 * <p>Ref: <a
 * href="https://sefiks.com/2023/03/06/a-step-by-step-partially-homomorphic-encryption-example-with-rsa-in-python/">
 * A step by step partially homomorphic encryption example with RSA</a>
 */
public final class RSA extends AbstractHomomorphic {

    /** The key fields RSA requires. */
    public static final KeySpec REQUIRED_KEYS = KeySpec.of(List.of("n", "e"), List.of("d"));

    private static final Logger logger = Logger.forModule(RSA.class);

    private final boolean encryptWithPublic;

    /**
     * Builds an RSA cryptosystem.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param keySize key size in bits; {@code null} defaults to 1024
     * @param encryptWithPublic RSA has two keys, private {@code d} and public {@code e}. If you
     *     encrypt a message with someone's public key then only that person can decrypt it with
     *     their private key (secure message); otherwise, if you encrypt it with your private key,
     *     anyone can decrypt it with your public key (digital signatures). Set this to {@code true}
     *     to encrypt with the public key {@code e} and decrypt with the private key {@code d}.
     * @param maxTries maximum attempts to generate keys
     */
    public RSA(Keys keys, Integer keySize, boolean encryptWithPublic, int maxTries) {
        super(
                Algorithm.RSA,
                keys != null ? keys : generateKeys(keySize == null ? 1024 : keySize, maxTries));
        BigInteger n = this.keys.publicNumber("n");
        this.plaintextModulo = n;
        this.ciphertextModulo = n;
        this.encryptWithPublic = encryptWithPublic;
    }

    /**
     * Builds an RSA cryptosystem that encrypts with the public key.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param keySize key size in bits; {@code null} defaults to 1024
     * @param maxTries maximum attempts to generate keys
     */
    public RSA(Keys keys, Integer keySize, int maxTries) {
        this(keys, keySize, true, maxTries);
    }

    /**
     * Builds an RSA cryptosystem around an existing key pair.
     *
     * @param keys the private-public key pair
     */
    public RSA(Keys keys) {
        this(keys, null, true, 10000);
    }

    /**
     * Generates the public and private keys of the RSA cryptosystem.
     *
     * @param keySize key size in bits
     * @param maxTries maximum number of tries to generate keys
     * @return the generated key pair
     * @throws IllegalArgumentException when no valid key pair is found within {@code maxTries}
     */
    public static Keys generateKeys(int keySize, int maxTries) {
        BigInteger upperBound = BigInteger.TWO.pow(keySize / 2).subtract(BigInteger.ONE);

        for (int attempt = 0; attempt < maxTries; attempt++) {
            // picking a prime modulus p and q
            BigInteger p = MathUtils.randomPrimeFromExponent(keySize / 2 - 300, upperBound);
            BigInteger q = MathUtils.randomPrimeFromExponent(keySize / 2 - 300, upperBound);

            if (p.equals(q)) {
                continue;
            }

            BigInteger n = p.multiply(q);
            BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

            // select public exponent e
            for (int candidate = 0; candidate < 1000; candidate++) {
                BigInteger e = MathUtils.randomInt(BigInteger.TWO, phi.subtract(BigInteger.ONE));
                if (e.gcd(phi).equals(BigInteger.ONE)) {
                    BigInteger d = e.modInverse(phi);
                    Keys keys = Keys.empty();
                    keys.publicKey().put("n", KeyValue.of(n));
                    keys.publicKey().put("e", KeyValue.of(e));
                    keys.privateKey().put("d", KeyValue.of(d));
                    return keys;
                }
            }
        }
        throw new IllegalArgumentException(
                "Failed to generate RSA keys after " + maxTries + " tries");
    }

    @Override
    public KeySpec requiredKeys() {
        return REQUIRED_KEYS;
    }

    /**
     * {@inheritDoc}
     *
     * <p>RSA does not require a random key for encryption; one is still returned for interface
     * symmetry.
     */
    @Override
    public BigInteger generateRandomKey() {
        return MathUtils.randomInt(BigInteger.ONE, keys.publicNumber("n").subtract(BigInteger.ONE));
    }

    @Override
    public CipherValue encrypt(BigInteger plaintext) {
        BigInteger n = keys.publicNumber("n");
        BigInteger message = plaintext;

        if (message.compareTo(n) > 0) {
            message = message.mod(n);
            BigInteger normalized = message;
            logger.debug(
                    () ->
                            "RSA can encrypt messages [1, "
                                    + n
                                    + "]. "
                                    + "Seems you exceeded this limit. New plaintext is "
                                    + normalized);
        }

        BigInteger exponent = encryptWithPublic ? keys.publicNumber("e") : keys.privateNumber("d");
        return IntValue.of(message.modPow(exponent, n));
    }

    /**
     * {@inheritDoc}
     *
     * <p>Decryption uses the private key {@code d} when {@code encryptWithPublic} is set, and the
     * public key {@code e} otherwise.
     */
    @Override
    public BigInteger decrypt(CipherValue ciphertext) {
        BigInteger n = keys.publicNumber("n");
        BigInteger exponent = encryptWithPublic ? keys.privateNumber("d") : keys.publicNumber("e");
        return asInt(ciphertext).modPow(exponent, n);
    }

    /**
     * {@inheritDoc}
     *
     * <p>The result equals {@code E(m1 * m2)}.
     */
    @Override
    public CipherValue multiply(CipherValue ciphertext1, CipherValue ciphertext2) {
        BigInteger n = keys.publicNumber("n");
        return IntValue.of(asInt(ciphertext1).multiply(asInt(ciphertext2)).mod(n));
    }
}
