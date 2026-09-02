package io.github.serengil.lightphe.cryptosystems;

import io.github.serengil.lightphe.commons.Logger;
import io.github.serengil.lightphe.commons.MathUtils;
import io.github.serengil.lightphe.model.Algorithm;
import io.github.serengil.lightphe.model.KeySpec;
import io.github.serengil.lightphe.model.KeyValue;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.IntValue;
import io.github.serengil.lightphe.model.value.TupleValue;
import java.math.BigInteger;
import java.util.List;

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

    private final boolean exponential;

    /**
     * Builds an ElGamal cryptosystem.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param exponential set this to {@code true} to make the cryptosystem exponential ElGamal.
     *     Regular ElGamal is homomorphic with respect to the multiplication whereas exponential
     *     ElGamal is homomorphic with respect to the addition.
     * @param keySize key size in bits; {@code null} defaults to 1024
     */
    public ElGamal(Keys keys, boolean exponential, Integer keySize) {
        super(
                exponential ? Algorithm.EXPONENTIAL_EL_GAMAL : Algorithm.EL_GAMAL,
                keys != null ? keys : generateKeys(keySize == null ? 1024 : keySize));
        this.exponential = exponential;
        this.plaintextModulo = this.keys.publicNumber("p");
        this.ciphertextModulo = this.keys.publicNumber("p");
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
        BigInteger g = keys.publicNumber("g");

        BigInteger mPrime = c2.multiply(c1.modPow(x.negate(), p)).mod(p);

        if (!exponential) {
            return mPrime;
        }

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
