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
 * Sander-Young-Yung, homomorphic with respect to the bitwise and.
 *
 * <p>Each plaintext bit is encrypted as a vector of {@code l} quadratic residues: a one is encoded
 * as the zero vector in {@code Z_2^l} and a zero as some non-zero vector, so multiplying two
 * ciphertext vectors componentwise yields the logical and.
 *
 * <p>Ref: <a
 * href="https://sefiks.com/2026/04/02/a-step-by-step-partially-homomorphic-sander-young-yung-example-in-python/">
 * A step by step partially homomorphic Sander-Young-Yung example</a>
 */
public final class SanderYoungYung extends AbstractHomomorphic {

    /** The key fields Sander-Young-Yung requires. */
    public static final KeySpec REQUIRED_KEYS =
            KeySpec.of(List.of("n", "x", "l"), List.of("p", "q"));

    private static final Logger logger = Logger.forModule(SanderYoungYung.class);

    /**
     * Builds a Sander-Young-Yung cryptosystem.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param keySize key size in bits; {@code null} defaults to 1024
     * @param plaintextLimit lower bound for the vector length {@code l}, or {@code null} for the
     *     default range
     */
    public SanderYoungYung(Keys keys, Integer keySize, Integer plaintextLimit) {
        super(
                Algorithm.SANDER_YOUNG_YUNG,
                keys != null
                        ? keys
                        : generateKeys(keySize == null ? 1024 : keySize, 10000, plaintextLimit));
        this.ciphertextModulo = this.keys.publicNumber("n");
        this.plaintextModulo = this.keys.publicNumber("l");
    }

    /**
     * Builds a Sander-Young-Yung cryptosystem around an existing key pair.
     *
     * @param keys the private-public key pair
     */
    public SanderYoungYung(Keys keys) {
        this(keys, null, null);
    }

    /**
     * Generates the public and private keys of the Sander-Young-Yung cryptosystem.
     *
     * @param keySize key size in bits
     * @param maxTries maximum number of attempts to find suitable keys
     * @param plaintextLimit lower bound for the vector length {@code l}, or {@code null}
     * @return the generated key pair
     * @throws IllegalStateException when no suitable key is found within {@code maxTries}
     */
    public static Keys generateKeys(int keySize, int maxTries, Integer plaintextLimit) {
        BigInteger upperBound = BigInteger.TWO.pow(keySize / 2).subtract(BigInteger.ONE);

        for (int attempt = 0; attempt < maxTries; attempt++) {
            // pick primes p and q
            BigInteger p = MathUtils.randomPrimeFromExponent(keySize / 2 - 100, upperBound);
            BigInteger q = MathUtils.randomPrimeFromExponent(keySize / 2 - 100, upperBound);

            // pick positive integer l
            BigInteger l =
                    plaintextLimit != null
                            ? MathUtils.randomInt(plaintextLimit, plaintextLimit + 100L)
                            : MathUtils.randomInt(100, 200);

            BigInteger n = p.multiply(q);

            for (int inner = 0; inner < maxTries / 10; inner++) {
                BigInteger x = MathUtils.randomInt(BigInteger.ONE, n.subtract(BigInteger.ONE));
                if (!x.gcd(n).equals(BigInteger.ONE)) {
                    continue;
                }
                if (MathUtils.jacobiSymbol(x, p) != -1 || MathUtils.jacobiSymbol(x, q) != -1) {
                    continue;
                }

                Keys keys = Keys.empty();
                keys.publicKey().put("n", KeyValue.of(n));
                keys.publicKey().put("x", KeyValue.of(x));
                keys.publicKey().put("l", KeyValue.of(l));
                keys.privateKey().put("p", KeyValue.of(p));
                keys.privateKey().put("q", KeyValue.of(q));
                return keys;
            }

            // if we cannot find a suitable x in maxTries/10 attempts, we can try different p and q
        }

        throw new IllegalStateException("Failed to find suitable key in " + maxTries + " tries");
    }

    @Override
    public KeySpec requiredKeys() {
        return REQUIRED_KEYS;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Sander-Young-Yung requires a one-time random key co-prime to {@code n} per vector
     * component.
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

    /**
     * {@inheritDoc}
     *
     * <p>The result is a list of per-bit vectors: one vector of {@code l} integers per bit of the
     * plaintext.
     */
    @Override
    public CipherValue encrypt(BigInteger plaintext) {
        BigInteger n = keys.publicNumber("n");
        int l = keys.publicNumber("l").intValueExact();
        BigInteger x = keys.publicNumber("x");

        String binary = plaintext.toString(2);

        // number of bits
        int k = binary.length();

        logger.debug(() -> "plaintext: " + plaintext + ", binary: " + binary + " (" + k + " bits)");

        List<CipherValue> ciphertexts = new ArrayList<>(k);
        for (int bit = 0; bit < k; bit++) {
            int mi = binary.charAt(bit) - '0';
            int index = bit;
            logger.debug(() -> "Encrypting bit " + index + " of plaintext: " + mi);

            List<BigInteger> ciphertext = new ArrayList<>(l);
            if (mi == 1) {
                // one is encoded as the zero vector in Z_2^l
                for (int i = 0; i < l; i++) {
                    BigInteger yi = generateRandomKey();
                    ciphertext.add(yi.multiply(yi).mod(n));
                }
            } else {
                // zero is encoded as a non-zero vector in Z_2^l
                int[] vs = new int[l];
                int sum;
                do {
                    sum = 0;
                    for (int i = 0; i < l; i++) {
                        vs[i] = MathUtils.randomInt(0, 1).intValueExact();
                        sum += vs[i];
                    }
                } while (sum <= 0);

                for (int i = 0; i < l; i++) {
                    BigInteger yi = generateRandomKey();
                    ciphertext.add(
                            yi.multiply(yi)
                                    .multiply(x.modPow(BigInteger.valueOf(vs[i]), n))
                                    .mod(n));
                }
            }
            ciphertexts.add(TupleValue.ofIntegers(ciphertext));
        }

        return TupleValue.of(ciphertexts);
    }

    @Override
    public BigInteger decrypt(CipherValue ciphertext) {
        BigInteger p = keys.privateNumber("p");
        BigInteger q = keys.privateNumber("q");
        int l = keys.publicNumber("l").intValueExact();

        StringBuilder binary = new StringBuilder();
        for (TupleValue ci : asTuple(ciphertext).asTuples()) {
            List<BigInteger> components = ci.asIntegers();
            int sum = 0;
            for (int i = 0; i < l; i++) {
                BigInteger component = components.get(i);
                int vi =
                        MathUtils.jacobiSymbol(component, p) == 1
                                        && MathUtils.jacobiSymbol(component, q) == 1
                                ? 0
                                : 1;
                sum += vi;
            }
            binary.append(sum == 0 ? '1' : '0');
        }
        return new BigInteger(binary.toString(), 2);
    }

    /**
     * {@inheritDoc}
     *
     * <p>The result equals {@code E(m1 & m2)}. Ciphertexts of unequal length are left-padded with
     * encryptions of zero.
     */
    @Override
    public CipherValue homomorphicAnd(CipherValue ciphertext1, CipherValue ciphertext2) {
        List<TupleValue> first = new ArrayList<>(asTuple(ciphertext1).asTuples());
        List<TupleValue> second = new ArrayList<>(asTuple(ciphertext2).asTuples());

        if (first.size() > second.size()) {
            second = padLeft(second, first.size() - second.size());
        }
        if (second.size() > first.size()) {
            first = padLeft(first, second.size() - first.size());
        }

        BigInteger n = keys.publicNumber("n");
        int l = keys.publicNumber("l").intValueExact();

        if (first.size() != second.size()) {
            throw new IllegalArgumentException(
                    "Ciphertexts must have the same length but got "
                            + first.size()
                            + " and "
                            + second.size());
        }

        List<CipherValue> result = new ArrayList<>(first.size());
        for (int bit = 0; bit < first.size(); bit++) {
            List<BigInteger> c1 = first.get(bit).asIntegers();
            List<BigInteger> c2 = second.get(bit).asIntegers();
            if (c1.size() != c2.size()) {
                throw new IllegalArgumentException(
                        "Ciphertexts must have the same length but got "
                                + c1.size()
                                + " and "
                                + c2.size());
            }
            List<BigInteger> combined = new ArrayList<>(l);
            for (int i = 0; i < l; i++) {
                combined.add(c1.get(i).multiply(c2.get(i)).mod(n));
            }
            result.add(TupleValue.ofIntegers(combined));
        }
        return TupleValue.of(result);
    }

    private List<TupleValue> padLeft(List<TupleValue> ciphertext, int padding) {
        List<TupleValue> pad = asTuple(encrypt(BigInteger.ZERO)).asTuples();
        List<TupleValue> padded = new ArrayList<>(ciphertext.size() + padding * pad.size());
        for (int i = 0; i < padding; i++) {
            padded.addAll(pad);
        }
        padded.addAll(ciphertext);
        return padded;
    }

    @Override
    public CipherValue reencrypt(CipherValue ciphertext) {
        int l = keys.publicNumber("l").intValueExact();

        List<CipherValue> reencrypted = new ArrayList<>();
        for (TupleValue ci : asTuple(ciphertext).asTuples()) {
            List<BigInteger> components = ci.asIntegers();
            List<BigInteger> refreshed = new ArrayList<>(l);
            for (int i = 0; i < l; i++) {
                BigInteger r = generateRandomKey();
                refreshed.add(components.get(i).multiply(r).multiply(r).mod(ciphertextModulo));
            }
            reencrypted.add(TupleValue.ofIntegers(refreshed));
        }
        return TupleValue.of(reencrypted);
    }
}
