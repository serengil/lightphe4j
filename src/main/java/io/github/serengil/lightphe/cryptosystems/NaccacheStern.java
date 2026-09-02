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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Naccache-Stern, homomorphic with respect to the addition. It is a generalisation of the Benaloh
 * cryptosystem.
 *
 * <p>Ref: <a
 * href="https://sefiks.com/2023/10/26/a-step-by-step-partially-homomorphic-encryption-example-with-naccache-stern-in-python/">
 * A step by step partially homomorphic encryption example with Naccache-Stern</a>. Original paper:
 * <a href="https://dl.acm.org/doi/pdf/10.1145/288090.288106">Naccache and Stern, A new public-key
 * cryptosystem</a>
 */
public final class NaccacheStern extends AbstractHomomorphic {

    /** The key fields Naccache-Stern requires. */
    public static final KeySpec REQUIRED_KEYS =
            KeySpec.of(List.of("n", "g", "sigma"), List.of("a", "b", "p", "q", "phi"));

    private static final Logger logger = Logger.forModule(NaccacheStern.class);

    private final boolean deterministic;

    /**
     * Builds a Naccache-Stern cryptosystem.
     *
     * <p>Decryption has to solve a discrete logarithm, so a small key is recommended.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param keySize key size in bits; {@code null} defaults to 1024. Smaller than in many
     *     cryptosystems because decryption requires solving a discrete logarithm.
     * @param deterministic {@code true} selects the deterministic version of the cryptosystem,
     *     {@code false} the probabilistic one
     * @param maxTries maximum attempts to generate keys
     */
    public NaccacheStern(Keys keys, Integer keySize, boolean deterministic, int maxTries) {
        super(
                Algorithm.NACCACHE_STERN,
                keys != null ? keys : generateKeys(keySize == null ? 1024 : keySize, maxTries));
        this.plaintextModulo = this.keys.publicNumber("sigma");
        this.ciphertextModulo = this.keys.publicNumber("n");
        this.deterministic = deterministic;
    }

    /**
     * Builds a probabilistic Naccache-Stern cryptosystem around an existing key pair.
     *
     * @param keys the private-public key pair
     */
    public NaccacheStern(Keys keys) {
        this(keys, null, false, 10000);
    }

    /**
     * Reports whether this is the deterministic variant.
     *
     * @return {@code true} for the deterministic version
     */
    public boolean deterministic() {
        return deterministic;
    }

    /**
     * Generates the public and private keys of the Naccache-Stern cryptosystem.
     *
     * @param keySize key size in bits; 1024 or more is recommended
     * @param maxTries maximum attempts to generate keys
     * @return the generated key pair
     * @throws IllegalStateException when no valid key pair is found within {@code maxTries}
     */
    public static Keys generateKeys(int keySize, int maxTries) {
        // Small primes are required so the discrete logarithm remains solvable during decryption.
        // Picking 4 out of these 8 keeps sigma small (at most about 23^4) and splits evenly into
        // u and v.
        List<BigInteger> smallPrimes =
                List.of(
                        BigInteger.valueOf(3),
                        BigInteger.valueOf(5),
                        BigInteger.valueOf(7),
                        BigInteger.valueOf(11),
                        BigInteger.valueOf(13),
                        BigInteger.valueOf(17),
                        BigInteger.valueOf(19),
                        BigInteger.valueOf(23));
        List<BigInteger> primeSet = new ArrayList<>(MathUtils.sample(smallPrimes, 4));
        Collections.sort(primeSet);
        int k = primeSet.size();

        for (BigInteger prime : primeSet) {
            if (!MathUtils.isPrime(prime)) {
                throw new IllegalArgumentException("All items of prime set must be prime!");
            }
        }

        // divide the set in half and find products of primes
        BigInteger u = BigInteger.ONE;
        BigInteger v = BigInteger.ONE;
        for (int i = 0; i < k; i++) {
            if (i < k / 2) {
                u = u.multiply(primeSet.get(i));
            } else {
                v = v.multiply(primeSet.get(i));
            }
        }

        // product of all primes
        BigInteger sigma = u.multiply(v);
        BigInteger upperBound = BigInteger.TWO.pow(keySize / 2).subtract(BigInteger.ONE);

        for (int attempt = 0; attempt < maxTries; attempt++) {
            // Generate large random primes a and b
            BigInteger a = MathUtils.randomPrimeFromExponent(keySize / 2 - 300, upperBound);
            BigInteger b = MathUtils.randomPrimeFromExponent(keySize / 2 - 300, upperBound);

            // calculate two primes from chosen ones
            BigInteger p = BigInteger.TWO.multiply(a).multiply(u).add(BigInteger.ONE);
            BigInteger q = BigInteger.TWO.multiply(b).multiply(v).add(BigInteger.ONE);

            if (!MathUtils.isPrime(p) || !MathUtils.isPrime(q)) {
                continue;
            }

            // recommended n is 768 bits
            BigInteger n = p.multiply(q);
            BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

            if (phi.mod(sigma).signum() != 0) {
                logger.debug("canceled because phi cannot be divisible by sigma");
                continue;
            }

            if (!sigma.gcd(phi.divide(sigma)).equals(BigInteger.ONE)) {
                logger.debug("canceled because sigma and phi/sigma are not coprime");
                continue;
            }

            // p_conditions and q_conditions check omitted for practical large-key generation
            if (keySize < 40 && !smallKeyConditionsHold(primeSet, k, p, q)) {
                continue;
            }

            // Choose generator g
            BigInteger g = null;
            for (int candidate = 0; candidate < 1000; candidate++) {
                BigInteger trial = MathUtils.randomInt(BigInteger.TWO, n.subtract(BigInteger.ONE));

                // it must be co-prime to n
                if (!trial.gcd(n).equals(BigInteger.ONE)) {
                    continue;
                }

                // guarantee it is not a pi-th power
                boolean isPower = false;
                for (BigInteger pi : primeSet) {
                    if (trial.modPow(phi.divide(pi), n).equals(BigInteger.ONE)) {
                        isPower = true;
                        break;
                    }
                }
                if (isPower) {
                    continue;
                }
                g = trial;
                break;
            }
            if (g == null) {
                continue; // if no g found, retry
            }

            // Original phi/4 order check omitted for practical large-key generation
            if (keySize < 40
                    && !g.modPow(phi.divide(BigInteger.valueOf(4)), n).equals(BigInteger.ONE)) {
                continue;
            }

            // Success
            Keys keys = Keys.empty();
            keys.publicKey().put("n", KeyValue.of(n));
            keys.publicKey().put("g", KeyValue.of(g));
            keys.publicKey().put("sigma", KeyValue.of(sigma));
            keys.privateKey().put("a", KeyValue.of(a));
            keys.privateKey().put("b", KeyValue.of(b));
            keys.privateKey().put("p", KeyValue.of(p));
            keys.privateKey().put("q", KeyValue.of(q));
            keys.privateKey().put("phi", KeyValue.of(phi));

            int attempts = attempt + 1;
            logger.debug(
                    () ->
                            "Keys generated after "
                                    + attempts
                                    + " attempts, n bits: "
                                    + n.bitLength());
            return keys;
        }

        throw new IllegalStateException(
                "Failed to generate Naccache-Stern keys after "
                        + maxTries
                        + " attempts.Please try to rerun.");
    }

    /** The original per-prime divisibility conditions, only checked for tiny keys. */
    private static boolean smallKeyConditionsHold(
            List<BigInteger> primeSet, int k, BigInteger p, BigInteger q) {
        BigInteger pMinusOne = p.subtract(BigInteger.ONE);
        BigInteger qMinusOne = q.subtract(BigInteger.ONE);

        for (int i = 0; i < k / 2; i++) {
            BigInteger pi = primeSet.get(i);
            boolean holds =
                    pMinusOne.mod(pi).signum() == 0
                            && pi.gcd(pMinusOne.divide(pi)).equals(BigInteger.ONE)
                            && pi.gcd(qMinusOne).equals(BigInteger.ONE);
            if (!holds) {
                logger.debug("canceled because p_conditions are not satisfied");
                return false;
            }
        }

        for (int i = k / 2; i < k; i++) {
            BigInteger pi = primeSet.get(i);
            boolean holds =
                    qMinusOne.mod(pi).signum() == 0
                            && pi.gcd(qMinusOne.divide(pi)).equals(BigInteger.ONE)
                            && pi.gcd(pMinusOne).signum() != 0;
            if (!holds) {
                logger.debug("canceled because q_conditions are not satisfied");
                return false;
            }
        }
        return true;
    }

    @Override
    public KeySpec requiredKeys() {
        return REQUIRED_KEYS;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Naccache-Stern requires a one-time random key per encryption.
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
     * @param randomKey the random key Naccache-Stern requires
     * @return the ciphertext
     */
    public CipherValue encrypt(BigInteger plaintext, BigInteger randomKey) {
        BigInteger g = keys.publicNumber("g");
        BigInteger n = keys.publicNumber("n");
        BigInteger sigma = keys.publicNumber("sigma");

        BigInteger message = plaintext;
        if (message.compareTo(plaintextModulo) > 0) {
            message = message.mod(plaintextModulo);
            BigInteger normalized = message;
            logger.debug(
                    () ->
                            "plaintext must be in scale [0, "
                                    + plaintextModulo
                                    + "] "
                                    + "but this is exceeded. New plaintext is "
                                    + normalized);
        }

        if (deterministic) {
            return IntValue.of(g.modPow(message, n));
        }

        // Probabilistic
        return IntValue.of(randomKey.modPow(sigma, n).multiply(g.modPow(message, n)).mod(n));
    }

    @Override
    public BigInteger decrypt(CipherValue ciphertext) {
        BigInteger phi = keys.privateNumber("phi");
        BigInteger n = keys.publicNumber("n");
        BigInteger g = keys.publicNumber("g");
        BigInteger sigma = keys.publicNumber("sigma");
        BigInteger value = asInt(ciphertext);

        // sigma is the product of the small primes; recover them by factoring.
        List<BigInteger> primeSet = new ArrayList<>(MathUtils.primeFactors(sigma));

        List<BigInteger> remainders = new ArrayList<>(primeSet.size());
        for (int i = 0; i < primeSet.size(); i++) {
            BigInteger prime = primeSet.get(i);
            BigInteger ci = value.modPow(phi.divide(prime), n);
            int index = i;
            logger.debug(() -> "c_" + index + " = " + ci);

            BigInteger j = BigInteger.ZERO;
            BigInteger bound = prime.multiply(prime);
            while (true) {
                if (ci.equals(g.modPow(j.multiply(phi).divide(prime), n))) {
                    BigInteger found = j;
                    logger.debug(() -> "m_" + index + " = " + found);
                    remainders.add(j);
                    break;
                }
                j = j.add(BigInteger.ONE);
                if (j.compareTo(bound) > 0) {
                    throw new IllegalArgumentException(
                            "c_"
                                    + index
                                    + " cannot be restored from "
                                    + ci
                                    + " = "
                                    + g
                                    + "^(j*"
                                    + phi
                                    + "/"
                                    + prime
                                    + ") mod "
                                    + n);
                }
            }
        }

        for (int i = 0; i < primeSet.size(); i++) {
            int index = i;
            logger.debug(() -> "m mod " + primeSet.get(index) + " = " + remainders.get(index));
        }

        // chinese remainder problem
        BigInteger restored = MathUtils.solveCongruence(remainders, primeSet);
        if (restored == null) {
            throw new IllegalArgumentException(
                    "message cannot be restored with Chinese Remainder!");
        }
        return restored;
    }

    /**
     * {@inheritDoc}
     *
     * <p>The result equals {@code E(m1 + m2)}; the arithmetic is done modulo {@code n}.
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
        BigInteger scalar = constant;
        if (scalar.compareTo(plaintextModulo) > 0) {
            scalar = scalar.mod(plaintextModulo);
            BigInteger normalized = scalar;
            logger.debug(
                    () ->
                            "Naccache-Stern can encrypt messages [1, "
                                    + plaintextModulo
                                    + "]. "
                                    + "Seems constant exceeded this limit. New constant is "
                                    + normalized);
        }
        return IntValue.of(asInt(ciphertext).modPow(scalar, ciphertextModulo));
    }

    @Override
    public CipherValue reencrypt(CipherValue ciphertext) {
        if (deterministic) {
            throw new IllegalArgumentException(
                    "Deterministic version of Naccache-Stern does not support reencryption."
                            + "If you still want to perform ciphertext regeneration, then you may "
                            + "consider to use its probabilistic version.");
        }
        CipherValue neutralEncrypted = encrypt(BigInteger.ZERO);
        return add(ciphertext, neutralEncrypted);
    }
}
