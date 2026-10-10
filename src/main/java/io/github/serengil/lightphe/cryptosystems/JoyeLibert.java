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
 * Joye-Libert, homomorphic with respect to the addition. It also supports multiplying a ciphertext
 * by a known plain constant.
 *
 * <p>It generalises Goldwasser-Micali from 1 bit to k bit messages by using 2^k-th power residue
 * symbols, so messages live in {@code Z_(2^k)}.
 *
 * <p>Ref: Joye, M., Libert, B. (2013). <a href="https://eprint.iacr.org/2013/435">Efficient
 * Cryptosystems from 2^k-th Power Residue Symbols</a>. EUROCRYPT 2013.
 */
public final class JoyeLibert extends AbstractHomomorphic {

    /** The key fields Joye-Libert requires. */
    public static final KeySpec REQUIRED_KEYS = KeySpec.of(List.of("n", "y", "k"), List.of("p"));

    /**
     * Floats are represented as {@code dividend * divisor^-1} where the divisor is a power of 10,
     * but powers of 10 are not invertible in the plaintext space {@code Z_(2^k)}.
     */
    public static final String FLOAT_NOT_SUPPORTED_MSG =
            "Joye-Libert does not support float values because its plaintext space is Z_{2^k}"
                    + " where powers of 10 have no modular inverse. Use integers instead.";

    private static final Logger logger = Logger.forModule(JoyeLibert.class);

    /**
     * Builds a Joye-Libert cryptosystem.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param keySize key size in bits; {@code null} defaults to 1024
     * @param maxTries maximum attempts to generate keys
     */
    public JoyeLibert(Keys keys, Integer keySize, int maxTries) {
        super(
                Algorithm.JOYE_LIBERT,
                keys != null ? keys : generateKeys(keySize == null ? 1024 : keySize, maxTries));
        this.plaintextModulo = BigInteger.TWO.pow(this.keys.publicNumber("k").intValueExact());
        this.ciphertextModulo = this.keys.publicNumber("n");
    }

    /**
     * Builds a Joye-Libert cryptosystem around an existing key pair.
     *
     * @param keys the private-public key pair
     */
    public JoyeLibert(Keys keys) {
        this(keys, null, CryptosystemFactory.DEFAULT_MAX_TRIES);
    }

    /**
     * Generates the public and private keys of the Joye-Libert cryptosystem.
     *
     * @param keySize key size in bits
     * @param maxTries maximum number of tries to generate keys
     * @return the generated key pair
     */
    public static Keys generateKeys(int keySize, int maxTries) {
        int primeSize = keySize / 2;

        // message space is Z_{2^k}. p - 1 must be divisible by 2^k, and the remaining part of p
        // must be large enough to keep factoring n hard.
        int k = Math.max(1, keySize / 4);
        BigInteger twoK = BigInteger.TWO.pow(k);

        // picking a prime p such that p = 1 mod 2^k
        BigInteger p = null;
        for (int attempt = 0; attempt < maxTries; attempt++) {
            BigInteger t =
                    MathUtils.randomInt(
                            BigInteger.TWO.pow(primeSize - k - 1),
                            BigInteger.TWO.pow(primeSize - k).subtract(BigInteger.ONE));
            BigInteger candidate = t.multiply(twoK).add(BigInteger.ONE);
            if (MathUtils.isPrime(candidate)) {
                p = candidate;
                break;
            }
        }
        if (p == null) {
            throw new IllegalStateException(
                    "Failed to find prime p = 1 mod 2^" + k + " in " + maxTries + " tries");
        }

        // picking a prime modulus q
        BigInteger q;
        do {
            q =
                    MathUtils.randomPrime(
                            BigInteger.TWO.pow(primeSize - 1),
                            BigInteger.TWO.pow(primeSize).subtract(BigInteger.ONE));
        } while (q.equals(p));

        BigInteger n = p.multiply(q);

        // y must be a quadratic non-residue modulo both p and q,
        // so y is in J_n \ QR_n (jacobi symbol 1 but not a square)
        for (int attempt = 0; attempt < maxTries; attempt++) {
            BigInteger y = MathUtils.randomInt(BigInteger.TWO, n.subtract(BigInteger.ONE));
            if (!y.gcd(n).equals(BigInteger.ONE)) {
                continue;
            }
            if (MathUtils.jacobiSymbol(y, p) == -1 && MathUtils.jacobiSymbol(y, q) == -1) {
                Keys keys = Keys.empty();
                keys.privateKey().put("p", KeyValue.of(p));
                keys.publicKey().put("n", KeyValue.of(n));
                keys.publicKey().put("y", KeyValue.of(y));
                keys.publicKey().put("k", KeyValue.of(k));
                return keys;
            }
        }
        throw new IllegalStateException("Failed to find suitable y in " + maxTries + " tries");
    }

    @Override
    public KeySpec requiredKeys() {
        return REQUIRED_KEYS;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Joye-Libert requires a one-time random key co-prime to {@code n} per encryption.
     */
    @Override
    public BigInteger generateRandomKey() {
        BigInteger n = keys.publicNumber("n");
        while (true) {
            BigInteger x = MathUtils.randomInt(BigInteger.ONE, n.subtract(BigInteger.ONE));
            if (x.gcd(n).equals(BigInteger.ONE)) {
                return x;
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
     * @param plaintext the message to encrypt in {@code [0, 2^k)}
     * @param randomKey a random key co-prime to {@code n}
     * @return the ciphertext
     */
    public CipherValue encrypt(BigInteger plaintext, BigInteger randomKey) {
        BigInteger n = keys.publicNumber("n");
        BigInteger y = keys.publicNumber("y");

        BigInteger m = plaintext;
        if (m.compareTo(plaintextModulo) >= 0) {
            m = m.mod(plaintextModulo);
            BigInteger normalized = m;
            logger.debug(
                    () ->
                            "Joye-Libert can encrypt messages [0, "
                                    + plaintextModulo
                                    + "). Seems plaintext exceeded this limit. New plaintext is "
                                    + normalized);
        }

        return IntValue.of(y.modPow(m, n).multiply(randomKey.modPow(plaintextModulo, n)).mod(n));
    }

    @Override
    public BigInteger decrypt(CipherValue ciphertext) {
        BigInteger p = keys.privateNumber("p");
        BigInteger y = keys.publicNumber("y");
        int k = keys.publicNumber("k").intValueExact();
        BigInteger exponent = p.subtract(BigInteger.ONE).shiftRight(k);

        // z = D^m mod p where D = y^((p-1)/2^k) has order exactly 2^k,
        // so m can be restored bit by bit
        BigInteger z = asInt(ciphertext).modPow(exponent, p);
        BigInteger dInv = y.modPow(exponent, p).modInverse(p);

        BigInteger m = BigInteger.ZERO;
        BigInteger b = BigInteger.ONE;
        for (int j = 1; j < k; j++) {
            if (!z.modPow(BigInteger.TWO.pow(k - j), p).equals(BigInteger.ONE)) {
                m = m.add(b);
                z = z.multiply(dInv).mod(p);
            }
            b = b.shiftLeft(1);
            dInv = dInv.multiply(dInv).mod(p);
        }

        if (!z.equals(BigInteger.ONE)) {
            m = m.add(b);
        }
        return m;
    }

    /**
     * {@inheritDoc}
     *
     * <p>The result equals {@code E(m1 + m2)}.
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
        if (scalar.compareTo(plaintextModulo) >= 0) {
            scalar = scalar.mod(plaintextModulo);
            BigInteger normalized = scalar;
            logger.debug(
                    () ->
                            "Joye-Libert can encrypt messages [0, "
                                    + plaintextModulo
                                    + "). Seems constant exceeded this limit. New constant is "
                                    + normalized);
        }
        return IntValue.of(asInt(ciphertext).modPow(scalar, n));
    }

    @Override
    public CipherValue reencrypt(CipherValue ciphertext) {
        CipherValue neutralEncrypted = encrypt(BigInteger.ZERO);
        return add(ciphertext, neutralEncrypted);
    }
}
