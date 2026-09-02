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
 * Benaloh, homomorphic with respect to the addition over a small message space {@code [0, r)}.
 *
 * <p>Ref: <a
 * href="https://sefiks.com/2023/10/06/a-step-by-step-partially-homomorphic-encryption-example-with-benaloh-in-python-from-scratch/">
 * A step by step partially homomorphic encryption example with Benaloh</a>
 */
public final class Benaloh extends AbstractHomomorphic {

    /** The key fields Benaloh requires. */
    public static final KeySpec REQUIRED_KEYS =
            KeySpec.of(List.of("y", "r", "n"), List.of("p", "q", "phi", "x"));

    private static final Logger logger = Logger.forModule(Benaloh.class);

    /**
     * Builds a Benaloh cryptosystem.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param keySize key size in bits; {@code null} defaults to 1024
     * @param plaintextLimit upper bound for plaintext values. When provided, {@code r} is set to
     *     the next prime greater than this value; otherwise {@code r} is chosen randomly from a
     *     default range. May be {@code null}.
     * @param maxTries maximum attempts to generate keys
     */
    public Benaloh(Keys keys, Integer keySize, BigInteger plaintextLimit, int maxTries) {
        super(
                Algorithm.BENALOH,
                keys != null
                        ? keys
                        : generateKeys(keySize == null ? 1024 : keySize, plaintextLimit, maxTries));
        this.plaintextModulo = this.keys.publicNumber("r");
        this.ciphertextModulo = this.keys.publicNumber("n");
    }

    /**
     * Builds a Benaloh cryptosystem around an existing key pair.
     *
     * @param keys the private-public key pair
     */
    public Benaloh(Keys keys) {
        this(keys, null, null, 10000);
    }

    /**
     * Generates the public and private keys of the Benaloh cryptosystem.
     *
     * @param keySize key size in bits
     * @param plaintextLimit upper bound for plaintext values, or {@code null} for the default range
     * @param maxTries maximum attempts to generate keys
     * @return the generated key pair
     * @throws IllegalStateException when no valid key pair is found within {@code maxTries}
     */
    public static Keys generateKeys(int keySize, BigInteger plaintextLimit, int maxTries) {
        BigInteger upperBound = BigInteger.TWO.pow(keySize / 2).subtract(BigInteger.ONE);

        for (int attempt = 0; attempt < maxTries; attempt++) {
            // picking a prime p
            BigInteger p = MathUtils.randomPrimeFromExponent(keySize / 2 - 300, upperBound);
            BigInteger q = MathUtils.randomPrimeFromExponent(keySize / 2 - 300, upperBound);

            BigInteger n = p.multiply(q);
            BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

            // generate block size r
            BigInteger r =
                    plaintextLimit == null
                            ? MathUtils.randomPrime(
                                    BigInteger.valueOf(1000), BigInteger.valueOf(2000))
                            : MathUtils.nextPrime(plaintextLimit);
            // plaintexts will be allowed in [0, r-1]

            // block size r checks
            BigInteger pMinusOne = p.subtract(BigInteger.ONE);
            boolean blockSizeValid =
                    // r should divide p-1 without remainder
                    pMinusOne.mod(r).signum() == 0
                            // r and (p - 1) / r must be coprimes
                            && r.gcd(pMinusOne.divide(r)).equals(BigInteger.ONE)
                            // r and q-1 must be coprimes
                            && r.gcd(q.subtract(BigInteger.ONE)).equals(BigInteger.ONE);
            if (!blockSizeValid) {
                continue;
            }

            BigInteger y = MathUtils.randomInt(BigInteger.TWO, n);
            if (!y.gcd(n).equals(BigInteger.ONE)) {
                continue;
            }

            // to guarantee correct decryption, none of r's prime factors may satisfy the condition
            boolean decryptionGuaranteed = true;
            for (BigInteger primeFactor : MathUtils.primeFactors(r)) {
                if (y.modPow(phi.divide(primeFactor), n).equals(BigInteger.ONE)) {
                    decryptionGuaranteed = false;
                }
            }
            if (!decryptionGuaranteed) {
                logger.info("decryption not guaranteed, retrying...");
                continue;
            }

            BigInteger x = y.modPow(phi.divide(r), n);
            if (x.equals(BigInteger.ONE)) {
                continue;
            }

            Keys keys = Keys.empty();
            keys.publicKey().put("y", KeyValue.of(y));
            keys.publicKey().put("r", KeyValue.of(r));
            keys.publicKey().put("n", KeyValue.of(n));
            keys.privateKey().put("p", KeyValue.of(p));
            keys.privateKey().put("q", KeyValue.of(q));
            keys.privateKey().put("phi", KeyValue.of(phi));
            keys.privateKey().put("x", KeyValue.of(x));
            return keys;
        }

        throw new IllegalStateException(
                "Failed to generate Benaloh keys after "
                        + maxTries
                        + " attempts."
                        + "Please try to rerun or consider to decrese plaintextLimit="
                        + plaintextLimit
                        + ".");
    }

    @Override
    public KeySpec requiredKeys() {
        return REQUIRED_KEYS;
    }

    @Override
    public BigInteger generateRandomKey() {
        BigInteger n = keys.publicNumber("n");
        while (true) {
            BigInteger u = MathUtils.randomInt(BigInteger.ONE, n);
            if (u.gcd(n).equals(BigInteger.ONE)) {
                return u;
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
     * @param randomKey the random key Benaloh requires
     * @return the ciphertext
     */
    public CipherValue encrypt(BigInteger plaintext, BigInteger randomKey) {
        BigInteger y = keys.publicNumber("y");
        BigInteger r = keys.publicNumber("r");
        BigInteger n = keys.publicNumber("n");

        BigInteger message = plaintext;
        if (message.compareTo(r) > 0) {
            BigInteger original = message;
            message = message.mod(r);
            logger.info(
                    "Benaloh lets you to encrypt messages in [0, r="
                            + r
                            + ")."
                            + "But your plaintext "
                            + original
                            + " exceeds this limit."
                            + "New plaintext is "
                            + message);
        }

        BigInteger c = y.modPow(message, n).multiply(randomKey.modPow(r, n)).mod(n);

        if (!c.gcd(n).equals(BigInteger.ONE)) {
            logger.debug("ciphertext is not co-prime with n!");
        }
        return IntValue.of(c);
    }

    @Override
    public BigInteger decrypt(CipherValue ciphertext) {
        BigInteger n = keys.publicNumber("n");
        BigInteger r = keys.publicNumber("r");
        BigInteger phi = keys.privateNumber("phi");
        BigInteger x = keys.privateNumber("x");

        BigInteger a = asInt(ciphertext).modPow(phi.divide(r), n);

        BigInteger md = BigInteger.ZERO;
        while (true) {
            if (x.modPow(md, n).equals(a)) {
                return md;
            }
            md = md.add(BigInteger.ONE);
            if (md.compareTo(r) > 0) {
                throw new IllegalArgumentException("Message cannot be restored in [0, " + n + "]");
            }
        }
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
            logger.info(
                    "Benaloh can encrypt messages [1, "
                            + plaintextModulo
                            + "]. "
                            + "Seems constant exceeded this limit. New constant is "
                            + scalar);
        }
        return IntValue.of(asInt(ciphertext).modPow(scalar, n));
    }

    @Override
    public CipherValue reencrypt(CipherValue ciphertext) {
        CipherValue neutralEncrypted = encrypt(BigInteger.ZERO);
        return add(ciphertext, neutralEncrypted);
    }
}
