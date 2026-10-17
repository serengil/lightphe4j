package io.github.serengil.lightphe.cryptosystems;

import io.github.serengil.lightphe.commons.Logger;
import io.github.serengil.lightphe.commons.MathUtils;
import io.github.serengil.lightphe.commons.SafePrimes;
import io.github.serengil.lightphe.model.Algorithm;
import io.github.serengil.lightphe.model.KeySpec;
import io.github.serengil.lightphe.model.KeyValue;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.IntValue;
import io.github.serengil.lightphe.model.value.TupleValue;
import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Bresson-Catalano-Pointcheval, homomorphic with respect to the addition. It also supports raising
 * a ciphertext base to a plaintext exponent, which yields scalar multiplication.
 *
 * <p>It is an ElGamal-like scheme in {@code Z_(n^2)*} with a double trapdoor decryption mechanism.
 * A ciphertext can be decrypted either with the secret exponent a (local trapdoor), or with the
 * factorization of n (master trapdoor) without knowing a. An authority holding the master key
 * publishes n and g, then every user generates its own key pair on top of them. The authority can
 * decrypt ciphertexts of all those users, so this is a key escrow mechanism by design.
 *
 * <p>Ref: Bresson, E., Catalano, D., Pointcheval, D. (2003). A Simple Public-Key Cryptosystem with
 * a Double Trapdoor Decryption Mechanism and Its Applications. ASIACRYPT 2003.
 */
public final class BressonCatalanoPointcheval extends AbstractHomomorphic {

    /** The key fields Bresson-Catalano-Pointcheval requires; an authority may keep p and q only. */
    public static final KeySpec REQUIRED_KEYS =
            KeySpec.withAlternativePrivateKey(
                    List.of("n", "g", "h"), List.of("a"), List.of("p", "q"));

    private static final Logger logger = Logger.forModule(BressonCatalanoPointcheval.class);

    /**
     * Builds a Bresson-Catalano-Pointcheval cryptosystem.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param keySize key size in bits; {@code null} defaults to 1024
     * @param maxTries maximum attempts to generate keys
     */
    public BressonCatalanoPointcheval(Keys keys, Integer keySize, int maxTries) {
        super(
                Algorithm.BRESSON_CATALANO_POINTCHEVAL,
                keys != null ? keys : generateKeys(keySize == null ? 1024 : keySize, maxTries));
        BigInteger n = this.keys.publicNumber("n");
        this.plaintextModulo = n;
        this.ciphertextModulo = n.multiply(n);
    }

    /**
     * Builds a Bresson-Catalano-Pointcheval cryptosystem around an existing key pair.
     *
     * @param keys the private-public key pair
     */
    public BressonCatalanoPointcheval(Keys keys) {
        this(keys, null, CryptosystemFactory.DEFAULT_MAX_TRIES);
    }

    /**
     * Generates the public and private keys of the Bresson-Catalano-Pointcheval cryptosystem.
     *
     * @param keySize key size in bits
     * @param maxTries maximum number of tries to generate keys
     * @return the generated key pair
     * @throws IllegalArgumentException when the key size is too small or no generator is found
     */
    public static Keys generateKeys(int keySize, int maxTries) {
        if (keySize < 16) {
            throw new IllegalArgumentException(
                    "Key size " + keySize + " is too small for Bresson-Catalano-Pointcheval");
        }

        // p = 2p' + 1 and q = 2q' + 1 are safe primes
        int primeSize = keySize / 2;
        BigInteger p = SafePrimes.findSafePrime(primeSize, maxTries);
        BigInteger q = SafePrimes.findSafePrime(primeSize, maxTries);
        while (q.equals(p)) {
            q = SafePrimes.findSafePrime(primeSize, maxTries);
        }

        BigInteger n = p.multiply(q);
        BigInteger nSquare = n.multiply(n);
        BigInteger pPrime = p.subtract(BigInteger.ONE).shiftRight(1);
        BigInteger qPrime = q.subtract(BigInteger.ONE).shiftRight(1);

        // g is a square in Z_{n^2}* of maximal order, so that g^(p'q') = 1 + kn mod n^2
        // for some k co-prime to n. k is required by the master trapdoor.
        BigInteger g = null;
        for (int attempt = 0; attempt < maxTries; attempt++) {
            BigInteger alpha =
                    MathUtils.randomInt(BigInteger.TWO, nSquare.subtract(BigInteger.ONE));
            if (!alpha.gcd(n).equals(BigInteger.ONE)) {
                continue;
            }
            BigInteger candidate = alpha.modPow(BigInteger.TWO, nSquare);
            BigInteger k =
                    candidate
                            .modPow(pPrime.multiply(qPrime), nSquare)
                            .subtract(BigInteger.ONE)
                            .divide(n);
            if (k.gcd(n).equals(BigInteger.ONE)
                    && !candidate.modPow(pPrime, n).equals(BigInteger.ONE)
                    && !candidate.modPow(qPrime, n).equals(BigInteger.ONE)) {
                g = candidate;
                break;
            }
        }
        if (g == null) {
            throw new IllegalArgumentException(
                    "Failed to find a suitable generator in " + maxTries + " tries");
        }

        // local trapdoor
        BigInteger a = MathUtils.randomInt(BigInteger.ONE, nSquare.shiftRight(1));
        BigInteger h = g.modPow(a, nSquare);

        Keys keys = Keys.empty();
        keys.publicKey().put("n", KeyValue.of(n));
        keys.publicKey().put("g", KeyValue.of(g));
        keys.publicKey().put("h", KeyValue.of(h));

        keys.privateKey().put("a", KeyValue.of(a));
        // master trapdoor
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
     * <p>The new user shares n and g of this cryptosystem, so the public key is enough to generate
     * it. Its private key has the local trapdoor a only, not the master trapdoor.
     */
    @Override
    public Keys generateUserKeys() {
        BigInteger n = keys.publicNumber("n");
        BigInteger g = keys.publicNumber("g");
        BigInteger nSquare = n.multiply(n);
        BigInteger a = MathUtils.randomInt(BigInteger.ONE, nSquare.shiftRight(1));

        Map<String, KeyValue> publicKey = new LinkedHashMap<>();
        publicKey.put("n", KeyValue.of(n));
        publicKey.put("g", KeyValue.of(g));
        publicKey.put("h", KeyValue.of(g.modPow(a, nSquare)));
        return Keys.of(publicKey, Map.of("a", KeyValue.of(a)));
    }

    /**
     * {@inheritDoc}
     *
     * <p>Bresson-Catalano-Pointcheval requires a one-time random key per encryption.
     */
    @Override
    public BigInteger generateRandomKey() {
        BigInteger n = keys.publicNumber("n");
        return MathUtils.randomInt(BigInteger.ONE, n.multiply(n).subtract(BigInteger.ONE));
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
     * @return the ciphertext {@code (A, B)} where {@code A = g^r mod n^2} and {@code B = h^r (1 +
     *     mn) mod n^2}
     */
    public CipherValue encrypt(BigInteger plaintext, BigInteger randomKey) {
        BigInteger n = keys.publicNumber("n");
        BigInteger g = keys.publicNumber("g");
        BigInteger h = keys.publicNumber("h");
        BigInteger nSquare = n.multiply(n);

        BigInteger message = plaintext;
        if (message.compareTo(n) >= 0) {
            message = message.mod(n);
            BigInteger normalized = message;
            logger.debug(
                    () ->
                            "Bresson-Catalano-Pointcheval can encrypt messages [0, "
                                    + n
                                    + "). Seems plaintext exceeded this limit. New plaintext is "
                                    + normalized);
        }

        BigInteger aPart = g.modPow(randomKey, nSquare);
        BigInteger bPart =
                h.modPow(randomKey, nSquare)
                        .multiply(BigInteger.ONE.add(message.multiply(n)))
                        .mod(nSquare);
        return TupleValue.of(IntValue.of(aPart), IntValue.of(bPart));
    }

    /**
     * {@inheritDoc}
     *
     * <p>Uses the local trapdoor a.
     *
     * @throws IllegalArgumentException when the private key does not have the local trapdoor
     */
    @Override
    public BigInteger decrypt(CipherValue ciphertext) {
        if (!keys.privateKey().containsKey("a")) {
            throw new IllegalArgumentException(
                    "Private key does not have the local trapdoor a. "
                            + "Use decrypt_with_master_key if you have the master key.");
        }

        BigInteger n = keys.publicNumber("n");
        BigInteger a = keys.privateNumber("a");
        BigInteger nSquare = n.multiply(n);
        BigInteger[] parts = asIntPair(ciphertext);

        // B / A^a = (1 + mn) mod n^2
        BigInteger restored =
                parts[1].multiply(parts[0].modPow(a, nSquare).modInverse(nSquare)).mod(nSquare);
        return lx(restored);
    }

    /**
     * {@inheritDoc}
     *
     * <p>The master trapdoor is the factorization of n. It does not require the local trapdoor a,
     * so the master key can decrypt ciphertexts of any key pair sharing the same n and g.
     */
    @Override
    public BigInteger decryptWithMasterKey(
            CipherValue ciphertext, Map<String, KeyValue> publicKey) {
        Map<String, KeyValue> privateKey = keys.privateKey();
        if (privateKey == null || !privateKey.containsKey("p") || !privateKey.containsKey("q")) {
            throw new IllegalArgumentException(
                    "Private key does not have the master trapdoor p and q");
        }

        BigInteger n = keys.publicNumber("n");
        BigInteger g = keys.publicNumber("g");
        Keys owner = Keys.of(publicKey == null ? keys.publicKey() : publicKey, null);
        if (!owner.publicNumber("n").equals(n) || !owner.publicNumber("g").equals(g)) {
            throw new IllegalArgumentException(
                    "Ciphertext was not encrypted for a user of this master key "
                            + "as it does not share the same n and g");
        }
        BigInteger h = owner.publicNumber("h");
        BigInteger p = keys.privateNumber("p");
        BigInteger q = keys.privateNumber("q");
        BigInteger nSquare = n.multiply(n);
        BigInteger order =
                p.subtract(BigInteger.ONE)
                        .shiftRight(1)
                        .multiply(q.subtract(BigInteger.ONE).shiftRight(1));
        BigInteger[] parts = asIntPair(ciphertext);

        // g^(p'q') = 1 + kn, so x^(p'q') = 1 + (log_g x) k n for any power x of g
        BigInteger kInverse = lx(g.modPow(order, nSquare)).modInverse(n);
        BigInteger aModN = lx(h.modPow(order, nSquare)).multiply(kInverse).mod(n);
        BigInteger rModN = lx(parts[0].modPow(order, nSquare)).multiply(kInverse).mod(n);
        BigInteger gamma = aModN.multiply(rModN).mod(n);

        // B / g^gamma = g^(n t) (1 + mn) for some t, and g^(n t p'q') = 1 mod n^2
        BigInteger masked =
                parts[1].multiply(g.modPow(gamma, nSquare).modInverse(nSquare)).mod(nSquare);
        return lx(masked.modPow(order, nSquare)).multiply(order.modInverse(n)).mod(n);
    }

    /**
     * {@inheritDoc}
     *
     * <p>The result equals {@code E(m1 + m2)}; the arithmetic is done modulo {@code n^2}.
     */
    @Override
    public CipherValue add(CipherValue ciphertext1, CipherValue ciphertext2) {
        BigInteger n = keys.publicNumber("n");
        BigInteger nSquare = n.multiply(n);
        BigInteger[] first = asIntPair(ciphertext1);
        BigInteger[] second = asIntPair(ciphertext2);
        return TupleValue.of(
                IntValue.of(first[0].multiply(second[0]).mod(nSquare)),
                IntValue.of(first[1].multiply(second[1]).mod(nSquare)));
    }

    /**
     * {@inheritDoc}
     *
     * <p>The result equals {@code E(m * constant)}; the arithmetic is done modulo {@code n^2}.
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
                            "Bresson-Catalano-Pointcheval can encrypt messages [0, "
                                    + n
                                    + "). Seems constant exceeded this limit. New constant is "
                                    + normalized);
        }

        BigInteger[] parts = asIntPair(ciphertext);
        return TupleValue.of(
                IntValue.of(parts[0].modPow(scalar, nSquare)),
                IntValue.of(parts[1].modPow(scalar, nSquare)));
    }

    @Override
    public CipherValue reencrypt(CipherValue ciphertext) {
        return add(ciphertext, encrypt(BigInteger.ZERO));
    }

    /** L function of Paillier-like schemes: {@code (x - 1) / n} for some x equal to 1 mod n. */
    private BigInteger lx(BigInteger x) {
        return x.subtract(BigInteger.ONE).divide(keys.publicNumber("n"));
    }
}
