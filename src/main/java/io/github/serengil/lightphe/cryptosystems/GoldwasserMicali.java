package io.github.serengil.lightphe.cryptosystems;

import io.github.serengil.lightphe.commons.Logger;
import io.github.serengil.lightphe.commons.MathUtils;
import io.github.serengil.lightphe.model.Algorithm;
import io.github.serengil.lightphe.model.KeySpec;
import io.github.serengil.lightphe.model.KeyValue;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.TupleValue;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Goldwasser-Micali, homomorphic with respect to the exclusive or.
 *
 * <p>Messages are encrypted bit by bit, so a ciphertext is a list of integers rather than a single
 * one.
 *
 * <p>Ref: <a
 * href="https://sefiks.com/2023/10/27/a-step-by-step-partially-homomorphic-encryption-example-with-goldwasser-micali-in-python/">
 * A step by step partially homomorphic encryption example with Goldwasser-Micali</a>
 */
public final class GoldwasserMicali extends AbstractHomomorphic {

    /** The key fields Goldwasser-Micali requires. */
    public static final KeySpec REQUIRED_KEYS = KeySpec.of(List.of("n", "x"), List.of("p", "q"));

    private static final Logger logger = Logger.forModule(GoldwasserMicali.class);

    /**
     * Builds a Goldwasser-Micali cryptosystem.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param keySize key size in bits; {@code null} defaults to 1024
     * @param maxTries maximum attempts to generate keys
     */
    public GoldwasserMicali(Keys keys, Integer keySize, int maxTries) {
        super(
                Algorithm.GOLDWASSER_MICALI,
                keys != null ? keys : generateKeys(keySize == null ? 1024 : keySize, maxTries));
        this.ciphertextModulo = this.keys.publicNumber("n");

        // Plaintext can be any integer (even larger than n) because it is internally encrypted bit
        // by bit. Internally each bit uses modulo 2, but LightPHE expects integers, not bits. The
        // original integer can be fully restored after decryption even if it is larger than n.
        this.plaintextModulo = this.keys.publicNumber("n");
    }

    /**
     * Builds a Goldwasser-Micali cryptosystem around an existing key pair.
     *
     * @param keys the private-public key pair
     */
    public GoldwasserMicali(Keys keys) {
        this(keys, null, 10000);
    }

    /**
     * Generates the public and private keys of the Goldwasser-Micali cryptosystem.
     *
     * @param keySize key size in bits
     * @param maxTries maximum number of tries to generate keys
     * @return the generated key pair
     * @throws IllegalStateException when no valid key pair is found within {@code maxTries}
     */
    public static Keys generateKeys(int keySize, int maxTries) {
        BigInteger upperBound = BigInteger.TWO.pow(keySize / 2).subtract(BigInteger.ONE);

        for (int attempt = 0; attempt < maxTries; attempt++) {
            // pick large random primes p and q
            BigInteger p = MathUtils.randomPrimeFromExponent(keySize / 2 - 100, upperBound);
            BigInteger q = MathUtils.randomPrimeFromExponent(keySize / 2 - 100, upperBound);

            // to prevent factorization attacks, it is recommended that n should be several hundred
            // bits or more
            BigInteger n = p.multiply(q);

            // find quadratic non-residue x
            BigInteger x = null;
            for (int candidate = 0; candidate < 1000; candidate++) {
                BigInteger trial = MathUtils.randomInt(BigInteger.TWO, n.subtract(BigInteger.ONE));
                if (!trial.gcd(n).equals(BigInteger.ONE)) {
                    continue;
                }
                if (MathUtils.jacobiSymbol(trial, p) == -1
                        && MathUtils.jacobiSymbol(trial, q) == -1) {
                    x = trial;
                    break;
                }
            }
            if (x == null) {
                // If no suitable x is found after 1000 tries, discard the current p-q pair and
                // retry
                continue;
            }

            Keys keys = Keys.empty();
            keys.publicKey().put("n", KeyValue.of(n));
            keys.publicKey().put("x", KeyValue.of(x));
            keys.privateKey().put("p", KeyValue.of(p));
            keys.privateKey().put("q", KeyValue.of(q));

            int attempts = attempt + 1;
            logger.debug(
                    () ->
                            "Goldwasser-Micali keys generated after "
                                    + attempts
                                    + " attempts, n bits: "
                                    + n.bitLength());
            return keys;
        }

        throw new IllegalStateException(
                "Failed to generate Goldwasser-Micali keys after "
                        + maxTries
                        + " attempts.Please try to rerun.");
    }

    @Override
    public KeySpec requiredKeys() {
        return REQUIRED_KEYS;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Goldwasser-Micali requires a one-time random key co-prime to {@code n} per bit.
     */
    @Override
    public BigInteger generateRandomKey() {
        BigInteger n = keys.publicNumber("n");
        while (true) {
            BigInteger r = MathUtils.randomInt(BigInteger.ONE, n);
            if (r.gcd(n).equals(BigInteger.ONE)) {
                return r;
            }
        }
    }

    @Override
    public CipherValue encrypt(BigInteger plaintext) {
        return encrypt(plaintext, (List<BigInteger>) null);
    }

    /**
     * Encrypts a plaintext with explicit per-bit random keys.
     *
     * @param plaintext the message to encrypt
     * @param randomKeys one random key per bit of the plaintext, or {@code null} to generate them
     * @return the per-bit ciphertext
     * @throws IllegalArgumentException when the number of random keys does not match the bit count
     */
    public CipherValue encrypt(BigInteger plaintext, List<BigInteger> randomKeys) {
        BigInteger n = keys.publicNumber("n");
        BigInteger x = keys.publicNumber("x");

        String binary = plaintext.toString(2);

        // number of bits
        int k = binary.length();

        if (randomKeys != null && randomKeys.size() != k) {
            throw new IllegalArgumentException("Random key must be length of " + k);
        }

        List<BigInteger> ciphertext = new ArrayList<>(k);
        for (int i = 0; i < k; i++) {
            BigInteger mi = BigInteger.valueOf(binary.charAt(i) - '0');
            BigInteger ri = randomKeys != null ? randomKeys.get(i) : generateRandomKey();
            ciphertext.add(ri.modPow(BigInteger.TWO, n).multiply(x.modPow(mi, n)).mod(n));
        }
        return TupleValue.ofIntegers(ciphertext);
    }

    @Override
    public BigInteger decrypt(CipherValue ciphertext) {
        BigInteger p = keys.privateNumber("p");
        BigInteger q = keys.privateNumber("q");

        BigInteger pExponent = p.subtract(BigInteger.ONE).divide(BigInteger.TWO);
        BigInteger qExponent = q.subtract(BigInteger.ONE).divide(BigInteger.TWO);

        StringBuilder binary = new StringBuilder();
        for (BigInteger ci : asTuple(ciphertext).asIntegers()) {
            BigInteger xp = ci.mod(p);
            BigInteger xq = ci.mod(q);

            boolean residue =
                    xp.modPow(pExponent, p).equals(BigInteger.ONE)
                            && xq.modPow(qExponent, q).equals(BigInteger.ONE);
            binary.append(residue ? '0' : '1');
        }
        return new BigInteger(binary.toString(), 2);
    }

    /**
     * {@inheritDoc}
     *
     * <p>The result equals {@code E(m1 ^ m2)}. Ciphertexts of unequal length are left-padded with
     * encryptions of zero.
     */
    @Override
    public CipherValue xor(CipherValue ciphertext1, CipherValue ciphertext2) {
        List<BigInteger> first = new ArrayList<>(asTuple(ciphertext1).asIntegers());
        List<BigInteger> second = new ArrayList<>(asTuple(ciphertext2).asIntegers());

        if (first.size() > second.size()) {
            second = padLeft(second, first.size() - second.size());
        } else if (second.size() > first.size()) {
            first = padLeft(first, second.size() - first.size());
        }

        List<BigInteger> result = new ArrayList<>(first.size());
        for (int i = 0; i < first.size(); i++) {
            result.add(first.get(i).multiply(second.get(i)).mod(ciphertextModulo));
        }
        return TupleValue.ofIntegers(result);
    }

    private List<BigInteger> padLeft(List<BigInteger> ciphertext, int padding) {
        BigInteger zeroBit = asTuple(encrypt(BigInteger.ZERO)).asIntegers().get(0);
        List<BigInteger> padded = new ArrayList<>(ciphertext.size() + padding);
        for (int i = 0; i < padding; i++) {
            padded.add(zeroBit);
        }
        padded.addAll(ciphertext);
        return padded;
    }

    @Override
    public CipherValue reencrypt(CipherValue ciphertext) {
        BigInteger n = keys.publicNumber("n");

        List<BigInteger> reencrypted = new ArrayList<>();
        for (BigInteger ci : asTuple(ciphertext).asIntegers()) {
            BigInteger ri = generateRandomKey();
            reencrypted.add(ri.modPow(BigInteger.TWO, n).multiply(ci).mod(n));
        }
        return TupleValue.ofIntegers(reencrypted);
    }
}
