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
 * Damgard-Jurik, a generalisation of Paillier that is homomorphic with respect to the addition.
 *
 * <p>The modulus is {@code n^(s+1)}; with {@code s == 1} the scheme degenerates to Paillier.
 *
 * <p>Ref: <a
 * href="https://sefiks.com/2023/10/20/a-step-by-step-partially-homomorphic-encryption-example-with-damgard-jurik-in-python/">
 * A step by step partially homomorphic encryption example with Damgard-Jurik</a>
 */
public final class DamgardJurik extends AbstractHomomorphic {

    /** The key fields Damgard-Jurik requires. */
    public static final KeySpec REQUIRED_KEYS = KeySpec.of(List.of("g", "n", "s"), List.of("phi"));

    /** Default value of the exponent {@code s}. */
    public static final int DEFAULT_S = 2;

    private static final Logger logger = Logger.forModule(DamgardJurik.class);

    /**
     * Builds a Damgard-Jurik cryptosystem.
     *
     * @param s the cryptosystem's modulus is {@code n^(s+1)}; with {@code s == 1} this is Paillier
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param keySize key size in bits; {@code null} defaults to 1024
     */
    public DamgardJurik(int s, Keys keys, Integer keySize) {
        super(
                Algorithm.DAMGARD_JURIK,
                keys != null ? keys : generateKeys(keySize == null ? 1024 : keySize, s));
        BigInteger n = this.keys.publicNumber("n");
        this.plaintextModulo = n;
        this.ciphertextModulo = n.pow(this.keys.publicNumber("s").intValueExact() + 1);
    }

    /**
     * Builds a Damgard-Jurik cryptosystem with the default exponent.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param keySize key size in bits; {@code null} defaults to 1024
     */
    public DamgardJurik(Keys keys, Integer keySize) {
        this(DEFAULT_S, keys, keySize);
    }

    /**
     * Builds a Damgard-Jurik cryptosystem around an existing key pair.
     *
     * @param keys the private-public key pair
     */
    public DamgardJurik(Keys keys) {
        this(DEFAULT_S, keys, null);
    }

    /**
     * Generates the public and private keys of the Damgard-Jurik cryptosystem.
     *
     * @param keySize key size in bits
     * @param s the cryptosystem's modulus is {@code n^(s+1)}
     * @return the generated key pair
     */
    public static Keys generateKeys(int keySize, int s) {
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
        keys.publicKey().put("s", KeyValue.of(s));
        return keys;
    }

    @Override
    public KeySpec requiredKeys() {
        return REQUIRED_KEYS;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Damgard-Jurik requires a one-time random key co-prime to {@code n} per encryption.
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
     */
    public CipherValue encrypt(BigInteger plaintext, BigInteger randomKey) {
        BigInteger g = keys.publicNumber("g");
        BigInteger n = keys.publicNumber("n");
        BigInteger modulus = ciphertextModulo;

        BigInteger c =
                g.modPow(plaintext, modulus).multiply(randomKey.modPow(n, modulus)).mod(modulus);

        if (!c.gcd(modulus).equals(BigInteger.ONE)) {
            logger.info("WARNING! gcd(c=" + c + ", modulo=" + modulus + ") != 1");
        }
        return IntValue.of(c);
    }

    @Override
    public BigInteger decrypt(CipherValue ciphertext) {
        BigInteger phi = keys.privateNumber("phi");
        BigInteger n = keys.publicNumber("n");
        BigInteger mu = phi.modInverse(n);
        return lx(asInt(ciphertext).modPow(phi, ciphertextModulo)).multiply(mu).mod(n);
    }

    /**
     * {@inheritDoc}
     *
     * <p>The result equals {@code E(m1 + m2)}.
     */
    @Override
    public CipherValue add(CipherValue ciphertext1, CipherValue ciphertext2) {
        return IntValue.of(asInt(ciphertext1).multiply(asInt(ciphertext2)).mod(ciphertextModulo));
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
                            "Damgard-Jurik can encrypt messages [1, "
                                    + n
                                    + "]. "
                                    + "Seems constant exceeded this limit. New constant is "
                                    + normalized);
        }
        return IntValue.of(asInt(ciphertext).modPow(scalar, ciphertextModulo));
    }

    @Override
    public CipherValue reencrypt(CipherValue ciphertext) {
        CipherValue neutralEncrypted = encrypt(BigInteger.ZERO);
        return add(ciphertext, neutralEncrypted);
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
