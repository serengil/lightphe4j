package io.github.serengil.lightphe.commons;

import io.github.serengil.lightphe.model.KeyValue;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.PartialDecryption;
import io.github.serengil.lightphe.model.Proof;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.IntValue;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/**
 * Threshold decryption, the counterpart of {@code lightphe.commons.threshold}.
 *
 * <p>Threshold decryption splits a private key into shares with Shamir's secret sharing. Any {@code
 * threshold} of {@code parties} shareholders decrypt a ciphertext together, whereas fewer
 * shareholders learn nothing about the plaintext.
 *
 * <p>Ref: Shamir, "How to share a secret", 1979
 *
 * <p>Ref: Shoup, "Practical threshold signatures", 2000
 *
 * <p>Ref: Damgard &amp; Jurik, "A generalisation, a simplification and some applications of
 * Paillier's probabilistic public-key system", 2001
 */
public final class Threshold {

    /** Reported when proofs of partial decryption are requested for regular Paillier keys. */
    public static final String SAFE_PRIMES_REQUIRED_MSG =
            "Partial decryptions of Paillier and Damgard-Jurik can be proven only if keys are"
                    + " generated with safePrimes = true";

    private static final Logger logger = Logger.forModule(Threshold.class);

    private Threshold() {
        throw new AssertionError("no instances");
    }

    /**
     * Index and share of a shareholder.
     *
     * @param index the index of the shareholder in {@code [1, parties]}
     * @param share the share of the private key
     */
    public record ThresholdKey(int index, BigInteger share) {}

    /**
     * Checks that a threshold scheme is well defined.
     *
     * @param threshold minimum number of shareholders required to decrypt
     * @param parties total number of shareholders
     * @throws IllegalArgumentException when the scheme is not well defined
     */
    public static void validateThreshold(int threshold, int parties) {
        if (threshold < 1) {
            throw new IllegalArgumentException("threshold must be at least 1, got " + threshold);
        }
        if (parties < threshold) {
            throw new IllegalArgumentException(
                    "parties ("
                            + parties
                            + ") must be greater than or equal to threshold ("
                            + threshold
                            + ")");
        }
    }

    /**
     * Splits a secret into shares with a random polynomial f of degree {@code threshold - 1} where
     * {@code f(0) = secret}. Share of the party with index i is {@code f(i) mod modulo}.
     *
     * @param secret the secret to share
     * @param threshold minimum number of shares required to restore the secret
     * @param parties number of shares
     * @param modulo shares are reduced in this modulo
     * @return party index {@code (1, ..., parties)} to its share
     */
    public static Map<Integer, BigInteger> splitSecret(
            BigInteger secret, int threshold, int parties, BigInteger modulo) {
        validateThreshold(threshold, parties);
        List<BigInteger> coefficients = new ArrayList<>(threshold);
        coefficients.add(secret.mod(modulo));
        for (int i = 1; i < threshold; i++) {
            coefficients.add(MathUtils.randomInt(BigInteger.ZERO, modulo.subtract(BigInteger.ONE)));
        }

        Map<Integer, BigInteger> shares = new LinkedHashMap<>();
        for (int index = 1; index <= parties; index++) {
            // horner's method
            BigInteger share = BigInteger.ZERO;
            BigInteger x = BigInteger.valueOf(index);
            for (int k = coefficients.size() - 1; k >= 0; k--) {
                share = share.multiply(x).add(coefficients.get(k)).mod(modulo);
            }
            shares.put(index, share);
        }
        return shares;
    }

    /**
     * Lagrange coefficient of a party at 0 in a modulo where differences of indices are invertible,
     * e.g. a prime order of a group.
     *
     * @param index the index of the party
     * @param indices the indices of all parties joining decryption
     * @param modulo the modulo of the coefficient
     * @return product of {@code j / (j - index)} over other indices j, in modulo
     */
    public static BigInteger lagrangeCoefficient(
            int index, List<Integer> indices, BigInteger modulo) {
        BigInteger numerator = BigInteger.ONE;
        BigInteger denominator = BigInteger.ONE;
        for (int j : indices) {
            if (j == index) {
                continue;
            }
            numerator = numerator.multiply(BigInteger.valueOf(j)).mod(modulo);
            denominator = denominator.multiply(BigInteger.valueOf(j - index)).mod(modulo);
        }
        return numerator.multiply(denominator.modInverse(modulo)).mod(modulo);
    }

    /**
     * Lagrange coefficient of a party at 0 multiplied by {@code delta = parties!}. This is always
     * an integer, so it works in groups of unknown order.
     *
     * @param index the index of the party
     * @param indices the indices of all parties joining decryption
     * @param delta the factorial of the number of parties
     * @return {@code delta} times the product of {@code j / (j - index)} over other indices j
     */
    public static BigInteger scaledLagrangeCoefficient(
            int index, List<Integer> indices, BigInteger delta) {
        BigInteger numerator = delta;
        BigInteger denominator = BigInteger.ONE;
        for (int j : indices) {
            if (j == index) {
                continue;
            }
            numerator = numerator.multiply(BigInteger.valueOf(j));
            denominator = denominator.multiply(BigInteger.valueOf(j - index));
        }
        BigInteger[] division = numerator.divideAndRemainder(denominator);
        if (division[1].signum() != 0) {
            throw new IllegalStateException("scaled lagrange coefficient is not an integer");
        }
        return division[0];
    }

    /**
     * Returns the factorial of a number.
     *
     * @param number the number
     * @return {@code number!}
     */
    public static BigInteger factorial(int number) {
        BigInteger result = BigInteger.ONE;
        for (int i = 2; i <= number; i++) {
            result = result.multiply(BigInteger.valueOf(i));
        }
        return result;
    }

    /**
     * Adds threshold parameters into the public key, and creates the key of each shareholder
     * consisting of the public key and its own share. Keys of shareholders do not have the private
     * key.
     *
     * @param keys the private-public key pair of the dealer; updated in place
     * @param shares party index to its share
     * @param threshold minimum number of shareholders required to decrypt
     * @param parties total number of shareholders
     * @param verificationKeys public commitments to shares, e.g. {@code g^share}, to verify partial
     *     decryptions, or {@code null}. Item k belongs to the party with index {@code k + 1}.
     * @return the keys of shareholders
     */
    public static List<Keys> buildShareKeys(
            Keys keys,
            Map<Integer, BigInteger> shares,
            int threshold,
            int parties,
            KeyValue verificationKeys) {
        keys.publicKey().put("threshold", KeyValue.of(threshold));
        keys.publicKey().put("parties", KeyValue.of(parties));
        if (verificationKeys != null) {
            keys.publicKey().put("verification_keys", verificationKeys);
        }

        List<Keys> shareKeys = new ArrayList<>(shares.size());
        for (Map.Entry<Integer, BigInteger> entry : shares.entrySet()) {
            Keys shareKey = keys.publicOnly();
            Map<String, KeyValue> thresholdKey = new LinkedHashMap<>();
            thresholdKey.put("index", KeyValue.of(entry.getKey()));
            thresholdKey.put("share", KeyValue.of(entry.getValue()));
            shareKey.setThresholdKey(thresholdKey);
            shareKeys.add(shareKey);
        }
        return shareKeys;
    }

    /**
     * Returns the threshold key of a shareholder.
     *
     * @param keys the keys of the shareholder
     * @return the index and share of the shareholder
     * @throws IllegalArgumentException when the keys do not have a threshold key
     */
    public static ThresholdKey thresholdKey(Keys keys) {
        Map<String, KeyValue> thresholdKey = keys.thresholdKey();
        if (thresholdKey == null) {
            throw new IllegalArgumentException(
                    "You must have threshold key to perform partial decryption");
        }
        if (!(thresholdKey.get("index") instanceof KeyValue.Num index)
                || !(thresholdKey.get("share") instanceof KeyValue.Num share)) {
            throw new IllegalArgumentException("Threshold key must have index and share");
        }
        return new ThresholdKey(index.value().intValueExact(), share.value());
    }

    /**
     * Validates partial decryptions and picks threshold many of them.
     *
     * @param keys the public key having threshold parameters
     * @param partialDecryptions partial decryptions of shareholders
     * @param verify checks the proof of a partial decryption, or {@code null}. Partial decryptions
     *     with invalid proofs are discarded if this is set.
     * @return the selected partial decryptions
     * @throws IllegalArgumentException when there are not enough valid partial decryptions
     */
    public static List<PartialDecryption> selectPartialDecryptions(
            Keys keys,
            List<PartialDecryption> partialDecryptions,
            Predicate<PartialDecryption> verify) {
        Map<String, KeyValue> publicKey = keys.publicKey();
        if (!(publicKey.get("threshold") instanceof KeyValue.Num threshold)
                || !(publicKey.get("parties") instanceof KeyValue.Num parties)) {
            throw new IllegalArgumentException(
                    "Public key does not have threshold parameters. "
                            + "Generate threshold keys first.");
        }
        int required = threshold.value().intValueExact();
        int total = parties.value().intValueExact();

        Map<Integer, PartialDecryption> selected = new LinkedHashMap<>();
        for (PartialDecryption partialDecryption : partialDecryptions) {
            if (verify != null && !verify.test(partialDecryption)) {
                logger.warn(
                        "Partial decryption of party "
                                + partialDecryption.index()
                                + " has an invalid proof. It is discarded.");
                continue;
            }
            int index = partialDecryption.index();
            if (index < 1 || index > total) {
                throw new IllegalArgumentException(
                        "Index of partial decryption must be in [1, " + total + "], got " + index);
            }
            PartialDecryption existing = selected.get(index);
            if (existing != null) {
                if (!existing.value().equals(partialDecryption.value())) {
                    throw new IllegalArgumentException(
                            "Conflicting partial decryptions for index " + index);
                }
                continue;
            }
            selected.put(index, partialDecryption);
        }

        if (selected.size() < required) {
            throw new IllegalArgumentException(
                    "At least "
                            + required
                            + " valid partial decryptions from distinct parties are required, got "
                            + selected.size());
        }
        return new ArrayList<>(selected.values()).subList(0, required);
    }

    // -----------------------------------------------------------------------
    // Paillier and Damgard-Jurik
    // -----------------------------------------------------------------------

    /**
     * Shares the decryption exponent of Paillier and Damgard-Jurik. The exponent d satisfies {@code
     * d = 0 mod phi} and {@code d = 1 mod n^s}, so {@code c^d = (1 + n)^m}.
     *
     * @param n the public modulus
     * @param phi euler's totient of n
     * @param s the ciphertext modulo is {@code n^(s+1)}
     * @param threshold minimum number of shareholders required to decrypt
     * @param parties total number of shareholders
     * @return party index to its share
     */
    public static Map<Integer, BigInteger> sharePaillierKey(
            BigInteger n, BigInteger phi, int s, int threshold, int parties) {
        if (!factorial(parties).gcd(n).equals(BigInteger.ONE)) {
            throw new IllegalArgumentException(
                    "Number of parties " + parties + " is too large for the modulus");
        }
        BigInteger ns = n.pow(s);
        BigInteger d = phi.multiply(phi.modInverse(ns));
        // order of the multiplicative group of n^(s+1)
        return splitSecret(d, threshold, parties, ns.multiply(phi));
    }

    /**
     * Generates Paillier or Damgard-Jurik keys with {@code n = p * q} for safe primes {@code p =
     * 2p' + 1} and {@code q = 2q' + 1}. Then, the group of squares modulo {@code n^(s+1)} is
     * cyclic, which partial decryptions are proven in. Key format is the same as regular keys.
     *
     * @param keySize the bit length of n
     * @param maxTries maximum attempts to find safe primes
     * @param s Damgard-Jurik only, the ciphertext modulo is {@code n^(s+1)}; {@code null} for
     *     Paillier
     * @return the private-public key pair
     */
    public static Keys generateSafePaillierKeys(int keySize, int maxTries, Integer s) {
        BigInteger p = SafePrimes.findSafePrime(keySize / 2, maxTries);
        BigInteger q = SafePrimes.findSafePrime(keySize / 2, maxTries);
        while (q.equals(p)) {
            q = SafePrimes.findSafePrime(keySize / 2, maxTries);
        }
        BigInteger n = p.multiply(q);
        Keys keys = Keys.empty();
        keys.privateKey()
                .put(
                        "phi",
                        KeyValue.of(
                                p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE))));
        keys.publicKey().put("g", KeyValue.of(BigInteger.ONE.add(n)));
        keys.publicKey().put("n", KeyValue.of(n));
        if (s != null) {
            keys.publicKey().put("s", KeyValue.of(s));
        }
        return keys;
    }

    /**
     * Checks whether n is a product of two safe primes, restoring them from n and phi.
     *
     * @param n the public modulus
     * @param phi euler's totient of n
     * @return {@code true} when n is a product of two safe primes
     */
    public static boolean isSafePaillierKey(BigInteger n, BigInteger phi) {
        // p + q = n - phi + 1, and p, q are roots of x^2 - (p + q) x + n
        BigInteger total = n.subtract(phi).add(BigInteger.ONE);
        BigInteger discriminant = total.multiply(total).subtract(n.shiftLeft(2));
        if (discriminant.signum() < 0) {
            return false;
        }
        BigInteger root = discriminant.sqrt();
        if (!root.multiply(root).equals(discriminant)) {
            return false;
        }
        BigInteger p = total.add(root).shiftRight(1);
        BigInteger q = total.subtract(root).shiftRight(1);
        return p.multiply(q).equals(n)
                && p.testBit(0)
                && q.testBit(0)
                && MathUtils.isPrime(p.shiftRight(1))
                && MathUtils.isPrime(q.shiftRight(1));
    }

    /**
     * Splits the private key of Paillier or Damgard-Jurik into shares. If n is a product of safe
     * primes, verification keys {@code v^(delta * share)} are published to prove partial
     * decryptions.
     *
     * @param keys the private-public key pair of the dealer; updated in place
     * @param s the ciphertext modulo is {@code n^(s+1)}
     * @param modulo the ciphertext modulo {@code n^(s+1)}
     * @param threshold minimum number of shareholders required to decrypt
     * @param parties total number of shareholders
     * @return the keys of shareholders
     */
    public static List<Keys> generatePaillierThresholdKeys(
            Keys keys, int s, BigInteger modulo, int threshold, int parties) {
        BigInteger n = keys.publicNumber("n");
        BigInteger phi = keys.privateNumber("phi");
        Map<Integer, BigInteger> shares = sharePaillierKey(n, phi, s, threshold, parties);

        KeyValue verificationKeys = null;
        if (isSafePaillierKey(n, phi)) {
            // a random square generates the cyclic group of squares with high probability
            BigInteger r = MathUtils.randomInt(BigInteger.TWO, modulo.subtract(BigInteger.ONE));
            while (!r.gcd(n).equals(BigInteger.ONE)) {
                r = MathUtils.randomInt(BigInteger.TWO, modulo.subtract(BigInteger.ONE));
            }
            BigInteger v = r.modPow(BigInteger.TWO, modulo);
            BigInteger delta = factorial(parties);
            keys.publicKey().put("verification_base", KeyValue.of(v));
            List<BigInteger> commitments = new ArrayList<>(parties);
            for (int index = 1; index <= parties; index++) {
                commitments.add(v.modPow(delta.multiply(shares.get(index)), modulo));
            }
            verificationKeys = KeyValue.numbers(commitments);
        }

        return buildShareKeys(keys, shares, threshold, parties, verificationKeys);
    }

    /**
     * Decrypts a Paillier or Damgard-Jurik ciphertext partially. Keys with verification keys
     * compute {@code c^(2 * delta * share)} as Shoup does, and can prove it.
     *
     * @param keys the keys of the shareholder
     * @param ciphertext the encrypted message
     * @param modulo the ciphertext modulo {@code n^(s+1)}
     * @param prove attach a proof of correct partial decryption
     * @param domain name of the statement being proven
     * @return the partial decryption
     */
    public static PartialDecryption paillierPartialDecrypt(
            Keys keys, BigInteger ciphertext, BigInteger modulo, boolean prove, String domain) {
        ThresholdKey thresholdKey = thresholdKey(keys);
        int index = thresholdKey.index();
        BigInteger share = thresholdKey.share();
        Map<String, KeyValue> publicKey = keys.publicKey();

        if (!publicKey.containsKey("verification_base")) {
            if (prove) {
                throw new IllegalArgumentException(SAFE_PRIMES_REQUIRED_MSG);
            }
            return new PartialDecryption(index, IntValue.of(ciphertext.modPow(share, modulo)));
        }

        BigInteger delta = factorial(keys.publicNumber("parties").intValueExact());
        BigInteger value =
                ciphertext.modPow(BigInteger.TWO.multiply(delta).multiply(share), modulo);
        if (!prove) {
            return new PartialDecryption(index, IntValue.of(value));
        }

        BigInteger n = keys.publicNumber("n");
        Proof proof =
                Zkp.proveDleqUnknownOrder(
                        n,
                        modulo,
                        ciphertext.modPow(BigInteger.valueOf(4), modulo),
                        value.modPow(BigInteger.TWO, modulo),
                        keys.publicNumber("verification_base"),
                        keys.publicNumbers("verification_keys").get(index - 1),
                        delta.multiply(share),
                        delta.multiply(modulo).bitLength(),
                        domain,
                        List.of(index, ciphertext));
        return new PartialDecryption(index, IntValue.of(value), proof);
    }

    /**
     * Verifies that a partial decryption of Paillier or Damgard-Jurik is computed with the share of
     * its shareholder.
     *
     * @param keys the public key having verification keys
     * @param ciphertext the encrypted message
     * @param partialDecryption the output of {@link #paillierPartialDecrypt} with a proof
     * @param modulo the ciphertext modulo {@code n^(s+1)}
     * @param domain name of the statement being proven
     * @return {@code true} when the partial decryption is proven to be correct
     */
    public static boolean verifyPaillierPartialDecryption(
            Keys keys,
            BigInteger ciphertext,
            PartialDecryption partialDecryption,
            BigInteger modulo,
            String domain) {
        Map<String, KeyValue> publicKey = keys.publicKey();
        if (!publicKey.containsKey("verification_base")) {
            throw new IllegalArgumentException(SAFE_PRIMES_REQUIRED_MSG);
        }
        try {
            List<BigInteger> verificationKeys = keys.publicNumbers("verification_keys");
            int index = partialDecryption.index();
            if (index < 1 || index > verificationKeys.size()) {
                return false;
            }
            if (!(partialDecryption.value() instanceof IntValue intValue)) {
                return false;
            }
            BigInteger value = intValue.value();
            if (value.signum() <= 0 || value.compareTo(modulo) >= 0) {
                return false;
            }
            BigInteger delta = factorial(keys.publicNumber("parties").intValueExact());
            return Zkp.verifyDleqUnknownOrder(
                    keys.publicNumber("n"),
                    modulo,
                    ciphertext.modPow(BigInteger.valueOf(4), modulo),
                    value.modPow(BigInteger.TWO, modulo),
                    keys.publicNumber("verification_base"),
                    verificationKeys.get(index - 1),
                    partialDecryption.proof(),
                    delta.multiply(modulo).bitLength(),
                    domain,
                    List.of(index, ciphertext));
        } catch (IllegalArgumentException | ArithmeticException err) {
            return false;
        }
    }

    /**
     * Combines partial decryptions of Paillier and Damgard-Jurik. Order of the group is secret, so
     * lagrange coefficients are scaled with {@code delta = parties!} to be integers.
     *
     * @param keys the public key having threshold parameters
     * @param ciphertext the encrypted message
     * @param partialDecryptions partial decryptions of shareholders
     * @param modulo the ciphertext modulo {@code n^(s+1)}
     * @param verify check proofs and discard invalid or unproven partial decryptions
     * @param domain name of the statement being proven
     * @return the restored message in modulo n
     */
    public static BigInteger combinePaillierPartialDecryptions(
            Keys keys,
            BigInteger ciphertext,
            List<PartialDecryption> partialDecryptions,
            BigInteger modulo,
            boolean verify,
            String domain) {
        boolean verifiable = keys.publicKey().containsKey("verification_base");
        if (verify && !verifiable) {
            throw new IllegalArgumentException(SAFE_PRIMES_REQUIRED_MSG);
        }

        List<PartialDecryption> selected =
                selectPartialDecryptions(
                        keys,
                        partialDecryptions,
                        verify
                                ? partialDecryption ->
                                        verifyPaillierPartialDecryption(
                                                keys, ciphertext, partialDecryption, modulo, domain)
                                : null);

        BigInteger n = keys.publicNumber("n");
        BigInteger delta = factorial(keys.publicNumber("parties").intValueExact());
        List<Integer> indices = selected.stream().map(PartialDecryption::index).toList();

        // c^(delta * d) = (1 + n)^(delta * m) for regular partial decryptions, and
        // c^(4 * delta^2 * d) = (1 + n)^(4 * delta^2 * m) for c^(2 * delta * share)
        BigInteger exponent = verifiable ? BigInteger.TWO : BigInteger.ONE;
        BigInteger factor =
                verifiable ? BigInteger.valueOf(4).multiply(delta).multiply(delta) : delta;

        BigInteger combined = BigInteger.ONE;
        for (PartialDecryption partialDecryption : selected) {
            BigInteger coefficient =
                    scaledLagrangeCoefficient(partialDecryption.index(), indices, delta);
            BigInteger value = asInteger(partialDecryption.value());
            combined =
                    combined.multiply(value.modPow(exponent.multiply(coefficient), modulo))
                            .mod(modulo);
        }

        BigInteger factorM = combined.subtract(BigInteger.ONE).divide(n).mod(n);
        return factorM.multiply(factor.modInverse(n)).mod(n);
    }

    private static BigInteger asInteger(CipherValue value) {
        if (!(value instanceof IntValue intValue)) {
            throw new IllegalArgumentException("Partial decryption must be an integer");
        }
        return intValue.value();
    }
}
