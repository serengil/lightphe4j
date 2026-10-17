package io.github.serengil.lightphe.cryptosystems;

import io.github.serengil.lightphe.commons.Logger;
import io.github.serengil.lightphe.commons.MathUtils;
import io.github.serengil.lightphe.model.Algorithm;
import io.github.serengil.lightphe.model.ArgmaxMessage;
import io.github.serengil.lightphe.model.KeySpec;
import io.github.serengil.lightphe.model.KeyValue;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.NumericDecisionTree;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.IntValue;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * Damgard-Geisler-Kroigaard (DGK), homomorphic with respect to the addition. It also supports
 * raising a ciphertext base to a plaintext exponent, which yields scalar multiplication.
 *
 * <p>Messages live in {@code Z_u} for a deliberately small prime {@code u} (up to 32 bits), which
 * keeps ciphertexts short and decryption fast. So, it is a good fit for small values such as
 * counters, votes or bits of a secure comparison. Results that exceed this space wrap around, so
 * operations producing large values (e.g. encrypted dot products on float tensors) are not suitable
 * for it.
 *
 * <p>It is a building block of secure comparison protocols, which underlie privacy-preserving
 * machine learning tasks such as private decision tree evaluation and encrypted argmax. All of them
 * are supported here in the semi-honest model, between a client holding the private key and a
 * server.
 *
 * <p>Ref: Damgard, I., Geisler, M., Kroigaard, M. (2007). Efficient and Secure Comparison for
 * On-Line Auctions. ACISP 2007. Correction: <a
 * href="https://eprint.iacr.org/2008/321">https://eprint.iacr.org/2008/321</a>
 *
 * <p>Ref: Tai, R. K. H., Ma, J. P. K., Zhao, Y., Chow, S. S. M. (2017). Privacy-Preserving Decision
 * Trees Evaluation via Linear Functions. ESORICS 2017.
 */
public final class DamgardGeislerKroigaard extends AbstractHomomorphic {

    /** The key fields Damgard-Geisler-Kroigaard requires. */
    public static final KeySpec REQUIRED_KEYS =
            KeySpec.of(List.of("n", "g", "h", "u", "t"), List.of("p", "v_p"));

    private static final Logger logger = Logger.forModule(DamgardGeislerKroigaard.class);

    private static final BigInteger THREE = BigInteger.valueOf(3);

    /**
     * A term {@code (E(m), coefficient)} of a linear combination.
     *
     * @param ciphertext the encrypted value
     * @param coefficient the plain coefficient
     */
    private record Term(BigInteger ciphertext, BigInteger coefficient) {

        Term(BigInteger ciphertext, long coefficient) {
            this(ciphertext, BigInteger.valueOf(coefficient));
        }
    }

    /** Baby-step giant-step lookup table, built once on first decryption. */
    private volatile Map<BigInteger, Integer> babySteps;

    /**
     * Builds a Damgard-Geisler-Kroigaard cryptosystem.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param keySize key size in bits; {@code null} defaults to 1024
     * @param maxTries maximum attempts to generate keys
     */
    public DamgardGeislerKroigaard(Keys keys, Integer keySize, int maxTries) {
        super(
                Algorithm.DAMGARD_GEISLER_KROIGAARD,
                keys != null ? keys : generateKeys(keySize == null ? 1024 : keySize, maxTries));
        this.plaintextModulo = this.keys.publicNumber("u");
        this.ciphertextModulo = this.keys.publicNumber("n");
    }

    /**
     * Builds a Damgard-Geisler-Kroigaard cryptosystem around an existing key pair.
     *
     * @param keys the private-public key pair
     */
    public DamgardGeislerKroigaard(Keys keys) {
        this(keys, null, CryptosystemFactory.DEFAULT_MAX_TRIES);
    }

    /**
     * Generates the public and private keys of the Damgard-Geisler-Kroigaard cryptosystem.
     *
     * @param keySize key size in bits
     * @param maxTries maximum number of tries to generate keys
     * @return the generated key pair
     * @throws IllegalArgumentException when the key size is too small or no key is found
     */
    public static Keys generateKeys(int keySize, int maxTries) {
        int primeSize = keySize / 2;

        // u is the plaintext space. it is kept small because decryption requires
        // solving a discrete logarithm in a subgroup of order u.
        int uSize = Math.min(32, Math.max(4, keySize / 16));

        // v_p and v_q are the orders of the randomizer subgroup. 160 bits in the paper.
        // at least 6 bits so that there are enough primes to pick distinct u, v_p and v_q
        int t = Math.min(160, Math.max(6, keySize / 6));

        // the rest of p and q is filled with a random part
        int rSize = primeSize - uSize - t - 1;
        if (rSize < 2) {
            throw new IllegalArgumentException(
                    "Key size " + keySize + " is too small for Damgard-Geisler-Kroigaard");
        }

        BigInteger u = randomPrimeOfBits(uSize);

        BigInteger vp = randomPrimeOfBits(t);
        while (vp.equals(u)) {
            vp = randomPrimeOfBits(t);
        }

        BigInteger vq = randomPrimeOfBits(t);
        while (vq.equals(u) || vq.equals(vp)) {
            vq = randomPrimeOfBits(t);
        }

        // picking primes p and q such that u * v_p divides p - 1 and u * v_q divides q - 1
        BigInteger p = findPrime(u, vp, rSize, maxTries);
        BigInteger q = findPrime(u, vq, rSize, maxTries);
        while (q.equals(p)) {
            q = findPrime(u, vq, rSize, maxTries);
        }

        BigInteger n = p.multiply(q);

        // g has order u * v_p * v_q, and h has order v_p * v_q in Z_n*.
        // they are built in Z_p* and Z_q* separately, and then combined with CRT
        BigInteger gp = findElementOfOrder(p, List.of(u, vp), maxTries);
        BigInteger gq = findElementOfOrder(q, List.of(u, vq), maxTries);
        BigInteger hp = findElementOfOrder(p, List.of(vp), maxTries);
        BigInteger hq = findElementOfOrder(q, List.of(vq), maxTries);

        BigInteger g = crt(gp, gq, p, q);
        BigInteger h = crt(hp, hq, p, q);

        Keys keys = Keys.empty();
        keys.publicKey().put("n", KeyValue.of(n));
        keys.publicKey().put("g", KeyValue.of(g));
        keys.publicKey().put("h", KeyValue.of(h));
        keys.publicKey().put("u", KeyValue.of(u));
        keys.publicKey().put("t", KeyValue.of(t));

        keys.privateKey().put("p", KeyValue.of(p));
        keys.privateKey().put("q", KeyValue.of(q));
        keys.privateKey().put("v_p", KeyValue.of(vp));
        keys.privateKey().put("v_q", KeyValue.of(vq));
        return keys;
    }

    @Override
    public KeySpec requiredKeys() {
        return REQUIRED_KEYS;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Damgard-Geisler-Kroigaard requires a one-time random key per encryption. In the paper, it
     * is a {@code 2.5t} bit random integer.
     */
    @Override
    public BigInteger generateRandomKey() {
        int t = keys.publicNumber("t").intValueExact();
        return MathUtils.randomInt(BigInteger.ONE, BigInteger.TWO.pow((int) (2.5 * t)));
    }

    @Override
    public CipherValue encrypt(BigInteger plaintext) {
        return IntValue.of(encryptValue(plaintext));
    }

    /**
     * Encrypts a plaintext with an explicit random key.
     *
     * @param plaintext the message to encrypt in {@code [0, u)}
     * @param randomKey the random key
     * @return the ciphertext
     */
    public CipherValue encrypt(BigInteger plaintext, BigInteger randomKey) {
        BigInteger n = keys.publicNumber("n");
        BigInteger g = keys.publicNumber("g");
        BigInteger h = keys.publicNumber("h");

        BigInteger message = plaintext;
        if (message.compareTo(plaintextModulo) >= 0) {
            message = message.mod(plaintextModulo);
            BigInteger normalized = message;
            logger.debug(
                    () ->
                            "Damgard-Geisler-Kroigaard can encrypt messages [0, "
                                    + plaintextModulo
                                    + "). Seems plaintext exceeded this limit. New plaintext is "
                                    + normalized);
        }

        return IntValue.of(g.modPow(message, n).multiply(h.modPow(randomKey, n)).mod(n));
    }

    @Override
    public BigInteger decrypt(CipherValue ciphertext) {
        return decryptValue(asInt(ciphertext));
    }

    @Override
    public CipherValue add(CipherValue ciphertext1, CipherValue ciphertext2) {
        return IntValue.of(addValues(asInt(ciphertext1), asInt(ciphertext2)));
    }

    @Override
    public CipherValue multiplyByConstant(CipherValue ciphertext, BigInteger constant) {
        return IntValue.of(multiplyValue(asInt(ciphertext), constant));
    }

    @Override
    public CipherValue reencrypt(CipherValue ciphertext) {
        return IntValue.of(reencryptValue(asInt(ciphertext)));
    }

    /**
     * Checks that a ciphertext encrypts 0 without solving the discrete logarithm. {@code c^v_p =
     * (g^v_p)^m mod p} and {@code g^v_p} has order u, so it is 1 if and only if {@code m = 0}.
     *
     * @param ciphertext the encrypted message
     * @return {@code true} when the ciphertext encrypts 0
     */
    public boolean isZero(BigInteger ciphertext) {
        BigInteger p = keys.privateNumber("p");
        BigInteger vp = keys.privateNumber("v_p");
        return ciphertext.modPow(vp, p).equals(BigInteger.ONE);
    }

    // -----------------------------------------------------------------------
    // Secure comparison
    // -----------------------------------------------------------------------

    /**
     * {@inheritDoc}
     *
     * <p>This is the 1st step of secure comparison and runs on client side.
     */
    @Override
    public List<BigInteger> encryptComparisonInput(long value, int bitLength) {
        validateComparisonInput(BigInteger.valueOf(value), bitLength);
        List<BigInteger> bits = new ArrayList<>(bitLength);
        for (int i = 0; i < bitLength; i++) {
            bits.add(encryptValue(BigInteger.valueOf((value >> i) & 1)));
        }
        return List.copyOf(bits);
    }

    /**
     * {@inheritDoc}
     *
     * <p>This is the 2nd step of secure comparison and runs on server side. Private key is not
     * required, and server learns nothing about x.
     */
    @Override
    public List<BigInteger> evaluateComparison(List<BigInteger> encryptedInput, long value) {
        return blindComparison(encryptedInput, BigInteger.valueOf(value), 0);
    }

    /**
     * {@inheritDoc}
     *
     * <p>This is the 3rd step of secure comparison and runs on client side. Client learns only
     * whether {@code x <= y}, but not y.
     */
    @Override
    public boolean decryptComparison(List<BigInteger> encryptedResult) {
        for (BigInteger ciphertext : encryptedResult) {
            if (isZero(ciphertext)) {
                return true;
            }
        }
        return false;
    }

    // -----------------------------------------------------------------------
    // Private decision tree evaluation
    // -----------------------------------------------------------------------

    /**
     * {@inheritDoc}
     *
     * <p>This is the 1st step of private decision tree evaluation and runs on client side.
     */
    @Override
    public List<List<BigInteger>> encryptDecisionTreeFeatures(List<Long> features, int bitLength) {
        List<List<BigInteger>> encrypted = new ArrayList<>(features.size());
        for (Long feature : features) {
            encrypted.add(encryptComparisonInput(feature, bitLength));
        }
        return List.copyOf(encrypted);
    }

    /**
     * {@inheritDoc}
     *
     * <p>This is the 2nd step of private decision tree evaluation and runs on server side. Each
     * comparison is randomly flipped, so client cannot learn the path.
     */
    @Override
    public NumericDecisionTree.Comparisons evaluateDecisionTreeComparisons(
            NumericDecisionTree tree, List<List<BigInteger>> encryptedFeatures) {
        List<NumericDecisionTree.Node> nodes = new ArrayList<>();
        collectNodes(tree, nodes);

        List<Integer> flips = new ArrayList<>(nodes.size());
        for (int i = 0; i < nodes.size(); i++) {
            flips.add(MathUtils.random().nextInt(2));
        }

        List<List<BigInteger>> encryptedComparisons = new ArrayList<>(nodes.size());
        for (int i = 0; i < nodes.size(); i++) {
            NumericDecisionTree.Node node = nodes.get(i);
            int featureIndex = node.featureIndex();
            if (featureIndex < 0 || featureIndex >= encryptedFeatures.size()) {
                throw new IllegalArgumentException(
                        "Feature index " + featureIndex + " does not exist");
            }
            encryptedComparisons.add(
                    blindComparison(
                            encryptedFeatures.get(featureIndex),
                            BigInteger.valueOf(node.threshold()),
                            flips.get(i)));
        }

        return new NumericDecisionTree.Comparisons(
                encryptedComparisons, new NumericDecisionTree.ServerState(tree, flips));
    }

    /**
     * {@inheritDoc}
     *
     * <p>This is the 3rd step of private decision tree evaluation and runs on client side.
     */
    @Override
    public List<BigInteger> answerDecisionTreeComparisons(
            List<List<BigInteger>> encryptedComparisons) {
        List<BigInteger> answers = new ArrayList<>(encryptedComparisons.size());
        for (List<BigInteger> comparison : encryptedComparisons) {
            answers.add(
                    encryptValue(decryptComparison(comparison) ? BigInteger.ONE : BigInteger.ZERO));
        }
        return List.copyOf(answers);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Path cost of a leaf is the number of wrong decisions on its path, so only the reached leaf
     * has cost 0. This is the 4th step of private decision tree evaluation and runs on server side.
     */
    @Override
    public List<NumericDecisionTree.EncryptedLeaf> evaluateDecisionTreeLeaves(
            NumericDecisionTree.ServerState serverState, List<BigInteger> encryptedAnswers) {
        BigInteger u = plaintextModulo;
        List<Integer> flips = serverState.flips();

        // path cost is at most the depth of the tree, so it must not wrap around u
        if (BigInteger.valueOf(flips.size()).compareTo(u) >= 0) {
            throw new IllegalArgumentException(
                    "Decision tree must have less than " + u + " decision nodes");
        }

        if (encryptedAnswers.size() != flips.size()) {
            throw new IllegalArgumentException(
                    "Expected " + flips.size() + " answers but got " + encryptedAnswers.size());
        }

        // remove the random flip, so b = 1 if feature <= threshold
        List<BigInteger> encryptedDecisions = new ArrayList<>(flips.size());
        for (int i = 0; i < flips.size(); i++) {
            BigInteger answer = encryptedAnswers.get(i);
            encryptedDecisions.add(flips.get(i) == 0 ? answer : negateBit(answer));
        }

        // path cost of each leaf. going left is wrong if b = 0, going right is wrong if b = 1
        List<BigInteger[]> leaves = new ArrayList<>();
        traverse(
                serverState.tree(),
                encryptValue(BigInteger.ZERO),
                encryptedDecisions,
                new int[1],
                leaves);

        // for each leaf, client receives (r1 * cost, r2 * cost + label). only the reached
        // leaf has cost 0, others look random to the client.
        List<NumericDecisionTree.EncryptedLeaf> encryptedLeaves = new ArrayList<>(leaves.size());
        BigInteger upper = u.subtract(BigInteger.ONE);
        for (BigInteger[] leaf : leaves) {
            BigInteger cost = leaf[0];
            BigInteger r1 = MathUtils.randomInt(BigInteger.ONE, upper);
            BigInteger r2 = MathUtils.randomInt(BigInteger.ONE, upper);
            BigInteger maskedCost = reencryptValue(multiplyValue(cost, r1));
            BigInteger maskedLabel = addValues(multiplyValue(cost, r2), encryptValue(leaf[1]));
            encryptedLeaves.add(new NumericDecisionTree.EncryptedLeaf(maskedCost, maskedLabel));
        }

        Collections.shuffle(encryptedLeaves, MathUtils.random());
        return List.copyOf(encryptedLeaves);
    }

    private void traverse(
            NumericDecisionTree subtree,
            BigInteger cost,
            List<BigInteger> encryptedDecisions,
            int[] nodeIndex,
            List<BigInteger[]> leaves) {
        if (subtree instanceof NumericDecisionTree.Leaf leaf) {
            BigInteger label = BigInteger.valueOf(leaf.label());
            if (label.signum() < 0 || label.compareTo(plaintextModulo) >= 0) {
                throw new IllegalArgumentException(
                        "Leaf labels must be in [0, " + plaintextModulo + ") but got " + label);
            }
            leaves.add(new BigInteger[] {cost, label});
            return;
        }
        NumericDecisionTree.Node node = (NumericDecisionTree.Node) subtree;
        BigInteger b = encryptedDecisions.get(nodeIndex[0]);
        nodeIndex[0]++;
        traverse(
                node.ifLessOrEqual(),
                addValues(cost, negateBit(b)),
                encryptedDecisions,
                nodeIndex,
                leaves);
        traverse(node.ifGreater(), addValues(cost, b), encryptedDecisions, nodeIndex, leaves);
    }

    /**
     * {@inheritDoc}
     *
     * <p>This is the last step of private decision tree evaluation and runs on client side.
     */
    @Override
    public long decryptDecisionTreeOutput(List<NumericDecisionTree.EncryptedLeaf> encryptedLeaves) {
        for (NumericDecisionTree.EncryptedLeaf leaf : encryptedLeaves) {
            if (isZero(leaf.maskedCost())) {
                return decryptValue(leaf.maskedLabel()).longValueExact();
            }
        }
        throw new IllegalArgumentException("None of the leaves is reached");
    }

    // -----------------------------------------------------------------------
    // Encrypted argmax
    // -----------------------------------------------------------------------

    /**
     * {@inheritDoc}
     *
     * <p>Runs on server side and interacts with the client (private key owner) through the client
     * callable. Client learns neither the values nor the comparison results, and server learns
     * nothing. Index of the first maximum is returned on ties.
     */
    @Override
    public BigInteger evaluateArgmax(
            List<BigInteger> encryptedValues,
            int bitLength,
            Function<ArgmaxMessage, List<BigInteger>> client) {
        BigInteger u = plaintextModulo;

        if (encryptedValues.isEmpty()) {
            throw new IllegalArgumentException("Argmax requires at least one value");
        }

        // z = b - a + 2^bit_length must be in the plaintext space without wrapping around
        if (BigInteger.TWO.pow(bitLength + 1).compareTo(u) >= 0) {
            throw new IllegalArgumentException(
                    "Plaintext space "
                            + u
                            + " is too small for argmax of "
                            + bitLength
                            + "-bit values. Use a larger key size or a smaller bit length.");
        }

        // client's masked values are compared bit by bit, so u's bit length must fit
        validateComparisonInput(u.subtract(BigInteger.ONE), u.bitLength());

        BigInteger maxValue = encryptedValues.get(0);
        BigInteger maxIndex = encryptValue(BigInteger.ZERO);
        for (int index = 1; index < encryptedValues.size(); index++) {
            BigInteger candidate = encryptedValues.get(index);
            BigInteger isGreater = greaterThan(candidate, maxValue, bitLength, client);

            // max_value += is_greater * (candidate - max_value)
            // max_index += is_greater * (index - max_index)
            BigInteger valueDiff = addValues(candidate, negate(maxValue));
            BigInteger indexDiff =
                    addValues(encryptValue(BigInteger.valueOf(index)), negate(maxIndex));
            List<BigInteger> updates = multiply(isGreater, List.of(valueDiff, indexDiff), client);
            maxValue = addValues(maxValue, updates.get(0));
            maxIndex = addValues(maxIndex, updates.get(1));
        }

        return reencryptValue(maxIndex);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Runs on client side. Every value the client decrypts here is masked with a uniformly
     * random value, so client learns nothing.
     */
    @Override
    public List<BigInteger> answerArgmax(ArgmaxMessage message) {
        BigInteger u = plaintextModulo;

        if (message instanceof ArgmaxMessage.MaskedDifference masked) {
            BigInteger value = decryptValue(masked.ciphertext());
            return encryptComparisonInput(value.longValueExact(), u.bitLength());
        }

        if (message instanceof ArgmaxMessage.Comparisons comparisons) {
            List<BigInteger> bits = new ArrayList<>(2);
            for (List<BigInteger> comparison : comparisons.comparisons()) {
                bits.add(decryptComparison(comparison) ? BigInteger.ONE : BigInteger.ZERO);
            }
            return List.of(
                    encryptValue(bits.get(0)),
                    encryptValue(bits.get(1)),
                    encryptValue(bits.get(0).multiply(bits.get(1))));
        }

        ArgmaxMessage.Products products = (ArgmaxMessage.Products) message;
        BigInteger maskedBit = decryptValue(products.maskedBit());
        List<BigInteger> answer = new ArrayList<>(products.maskedFactors().size());
        for (BigInteger factor : products.maskedFactors()) {
            answer.add(encryptValue(maskedBit.multiply(decryptValue(factor)).mod(u)));
        }
        return List.copyOf(answer);
    }

    /**
     * Computes {@code E(a > b)} for encrypted a and b in {@code [0, 2^bitLength)} with the client.
     */
    private BigInteger greaterThan(
            BigInteger encryptedA,
            BigInteger encryptedB,
            int bitLength,
            Function<ArgmaxMessage, List<BigInteger>> client) {
        BigInteger u = plaintextModulo;
        BigInteger offset = BigInteger.TWO.pow(bitLength);

        // z = a - b + 2^bit_length is in [1, 2^(bit_length + 1)), and a > b iff z > 2^bit_length.
        // client receives d = z + r mod u for a uniformly random r, which reveals nothing.
        BigInteger r = MathUtils.randomInt(BigInteger.ZERO, u.subtract(BigInteger.ONE));
        BigInteger maskedDifference =
                addValues(
                        addValues(encryptedA, negate(encryptedB)),
                        encryptValue(offset.add(r).mod(u)));
        List<BigInteger> encryptedDBits =
                client.apply(new ArgmaxMessage.MaskedDifference(reencryptValue(maskedDifference)));

        // a > b iff d is in the arc [start, end] of Z_u. if the arc does not wrap around u,
        // it is (d >= start) and (d <= end). otherwise, it is (d >= start) or (d <= end).
        BigInteger start = r.add(offset).add(BigInteger.ONE).mod(u);
        BigInteger end = r.add(offset.shiftLeft(1)).subtract(BigInteger.ONE).mod(u);
        boolean wraps = start.compareTo(end) > 0;

        // each comparison gives client a bit x_i, while server keeps a bit k_i such that
        // c_i = x_i xor k_i. random flips make x_i uniformly random for the client.
        // d >= start is the negation of d <= start - 1, and always true if start = 0.
        int[] flips = {MathUtils.random().nextInt(2), MathUtils.random().nextInt(2)};
        BigInteger firstThreshold;
        int firstNegated;
        if (start.signum() == 0) {
            firstThreshold = u.subtract(BigInteger.ONE);
            firstNegated = 0;
        } else {
            firstThreshold = start.subtract(BigInteger.ONE);
            firstNegated = 1;
        }

        List<List<BigInteger>> comparisons =
                List.of(
                        blindComparison(encryptedDBits, firstThreshold, flips[0]),
                        blindComparison(encryptedDBits, end, flips[1]));
        List<BigInteger> answer = client.apply(new ArgmaxMessage.Comparisons(comparisons));
        BigInteger x1 = answer.get(0);
        BigInteger x2 = answer.get(1);
        BigInteger x1x2 = answer.get(2);

        long k1 = flips[0] ^ firstNegated;
        long k2 = flips[1];

        // c_i = k_i + (1 - 2 k_i) x_i is linear in x_i, and so is c_1 * c_2 in x_1, x_2, x_1 x_2
        BigInteger c1 = linear(List.of(new Term(x1, 1 - 2 * k1)), BigInteger.valueOf(k1));
        BigInteger c2 = linear(List.of(new Term(x2, 1 - 2 * k2)), BigInteger.valueOf(k2));
        BigInteger c1c2 =
                linear(
                        List.of(
                                new Term(x1, k2 * (1 - 2 * k1)),
                                new Term(x2, k1 * (1 - 2 * k2)),
                                new Term(x1x2, (1 - 2 * k1) * (1 - 2 * k2))),
                        BigInteger.valueOf(k1 * k2));

        if (wraps) {
            // c1 or c2 = c1 + c2 - c1 * c2
            return addValues(addValues(c1, c2), negate(c1c2));
        }
        return c1c2;
    }

    /**
     * Computes {@code E(b * f)} for an encrypted b and each encrypted f with the client's help.
     * Client multiplies {@code B = b + rho} and {@code F = f + sigma}, both uniformly random, and
     * server restores {@code b * f = B * F - sigma * b - rho * f - rho * sigma}.
     */
    private List<BigInteger> multiply(
            BigInteger encryptedBit,
            List<BigInteger> encryptedFactors,
            Function<ArgmaxMessage, List<BigInteger>> client) {
        BigInteger upper = plaintextModulo.subtract(BigInteger.ONE);
        BigInteger rho = MathUtils.randomInt(BigInteger.ZERO, upper);
        List<BigInteger> sigmas = new ArrayList<>(encryptedFactors.size());
        for (int i = 0; i < encryptedFactors.size(); i++) {
            sigmas.add(MathUtils.randomInt(BigInteger.ZERO, upper));
        }

        BigInteger maskedBit = addValues(encryptedBit, encryptValue(rho));
        List<BigInteger> maskedFactors = new ArrayList<>(encryptedFactors.size());
        for (int i = 0; i < encryptedFactors.size(); i++) {
            maskedFactors.add(addValues(encryptedFactors.get(i), encryptValue(sigmas.get(i))));
        }
        List<BigInteger> maskedProducts =
                client.apply(new ArgmaxMessage.Products(maskedBit, maskedFactors));

        List<BigInteger> products = new ArrayList<>(encryptedFactors.size());
        for (int i = 0; i < encryptedFactors.size(); i++) {
            BigInteger sigma = sigmas.get(i);
            products.add(
                    linear(
                            List.of(
                                    new Term(maskedProducts.get(i), BigInteger.ONE),
                                    new Term(encryptedBit, sigma.negate()),
                                    new Term(encryptedFactors.get(i), rho.negate())),
                            rho.negate().multiply(sigma)));
        }
        return products;
    }

    /**
     * Computes {@code E(sum(coefficient * m) + constant)} for {@code (E(m), coefficient)} terms.
     */
    private BigInteger linear(List<Term> terms, BigInteger constant) {
        BigInteger u = plaintextModulo;
        BigInteger result = encryptValue(constant.mod(u));
        for (Term term : terms) {
            BigInteger coefficient = term.coefficient().mod(u);
            if (coefficient.signum() != 0) {
                result = addValues(result, multiplyValue(term.ciphertext(), coefficient));
            }
        }
        return result;
    }

    /** Computes {@code E(-m)} from {@code E(m)}. */
    private BigInteger negate(BigInteger ciphertext) {
        return multiplyValue(ciphertext, plaintextModulo.subtract(BigInteger.ONE));
    }

    /** Computes {@code E(1 - b)} from {@code E(b)} for a bit b. */
    private BigInteger negateBit(BigInteger ciphertext) {
        return addValues(
                encryptValue(BigInteger.ONE),
                multiplyValue(ciphertext, plaintextModulo.subtract(BigInteger.ONE)));
    }

    /**
     * Checks that a compared value fits into bitLength bits, and the comparison fits into the
     * plaintext space.
     */
    private void validateComparisonInput(BigInteger value, int bitLength) {
        if (value.signum() < 0 || value.bitLength() > bitLength) {
            throw new IllegalArgumentException(
                    "Compared values must be integers in [0, 2^"
                            + bitLength
                            + ") but got "
                            + value);
        }

        // values are extended by one bit to break ties. intermediate values of the
        // comparison are in [-2, 3 * (bit_length + 1) - 1] and must not wrap around u.
        if (BigInteger.valueOf(3L * (bitLength + 1) - 1).compareTo(plaintextModulo) >= 0) {
            throw new IllegalArgumentException(
                    "Plaintext space "
                            + plaintextModulo
                            + " is too small to compare "
                            + bitLength
                            + "-bit values. Use a larger key size or a smaller bit length.");
        }
    }

    /**
     * DGK comparison of the client's encrypted x and the server's plain y. Client finds a zero
     * among the returned ciphertexts if and only if {@code x <= y} (flip = 0) or {@code x > y}
     * (flip = 1).
     *
     * @param encryptedBits encrypted bits of x, least significant bit first
     * @param value y
     * @param flip 0 or 1. server keeps it secret to hide the result from the client
     * @return blinded ciphertexts, shuffled and re-randomized
     */
    private List<BigInteger> blindComparison(
            List<BigInteger> encryptedBits, BigInteger value, int flip) {
        BigInteger u = plaintextModulo;
        int bitLength = encryptedBits.size();
        validateComparisonInput(value, bitLength);

        // compare 2x with 2y + 1 instead, so that x <= y if and only if 2x < 2y + 1.
        // this way, x and y are never equal and flipping the direction is consistent.
        List<BigInteger> xBits = new ArrayList<>(bitLength + 1);
        xBits.add(encryptValue(BigInteger.ZERO));
        xBits.addAll(encryptedBits);
        BigInteger y = value.shiftLeft(1).add(BigInteger.ONE);

        // s = 1 looks for x < y, s = -1 looks for x > y
        BigInteger s = flip == 0 ? BigInteger.ONE : u.subtract(BigInteger.ONE);

        // c_i = s + x_i - y_i + 3 * sum_{j > i} (x_j xor y_j)
        // c_i = 0 only at the most significant differing bit, and only if x_i - y_i = -s
        List<BigInteger> blinded = new ArrayList<>(bitLength + 1);
        BigInteger xorSum = encryptValue(BigInteger.ZERO);
        BigInteger upper = u.subtract(BigInteger.ONE);
        for (int i = bitLength; i >= 0; i--) {
            boolean yBit = y.testBit(i);
            BigInteger c =
                    addValues(
                            encryptValue(
                                    s.subtract(yBit ? BigInteger.ONE : BigInteger.ZERO).mod(u)),
                            xBits.get(i));
            c = addValues(c, multiplyValue(xorSum, THREE));

            BigInteger r = MathUtils.randomInt(BigInteger.ONE, upper);
            blinded.add(reencryptValue(multiplyValue(c, r)));

            BigInteger xXorY = yBit ? negateBit(xBits.get(i)) : xBits.get(i);
            xorSum = addValues(xorSum, xXorY);
        }

        Collections.shuffle(blinded, MathUtils.random());
        return List.copyOf(blinded);
    }

    /** Collects the decision nodes in pre-order. */
    private static void collectNodes(
            NumericDecisionTree tree, List<NumericDecisionTree.Node> nodes) {
        if (tree instanceof NumericDecisionTree.Node node) {
            nodes.add(node);
            collectNodes(node.ifLessOrEqual(), nodes);
            collectNodes(node.ifGreater(), nodes);
        }
    }

    // -----------------------------------------------------------------------
    // Arithmetic on bare ciphertext integers
    // -----------------------------------------------------------------------

    private BigInteger encryptValue(BigInteger plaintext) {
        return ((IntValue) encrypt(plaintext, generateRandomKey())).value();
    }

    private BigInteger decryptValue(BigInteger ciphertext) {
        BigInteger p = keys.privateNumber("p");
        BigInteger vp = keys.privateNumber("v_p");
        BigInteger g = keys.publicNumber("g");
        BigInteger u = keys.publicNumber("u");

        // c^v_p = (g^v_p)^m mod p because h^v_p = 1 mod p. g^v_p has order u in Z_p*
        // so m is the discrete logarithm of c^v_p in a small subgroup of order u.
        BigInteger z = ciphertext.modPow(vp, p);
        BigInteger base = g.modPow(vp, p);

        // baby-step giant-step
        int step = u.sqrt().intValueExact() + 1;
        Map<BigInteger, Integer> table = babySteps;
        if (table == null) {
            table = new HashMap<>();
            BigInteger value = BigInteger.ONE;
            for (int j = 0; j < step; j++) {
                table.putIfAbsent(value, j);
                value = value.multiply(base).mod(p);
            }
            babySteps = table;
        }

        BigInteger giant = base.modPow(BigInteger.valueOf(step), p).modInverse(p);
        for (long i = 0; i < step; i++) {
            Integer j = table.get(z);
            if (j != null) {
                return BigInteger.valueOf(i * step + j).mod(u);
            }
            z = z.multiply(giant).mod(p);
        }

        throw new IllegalArgumentException(
                "Damgard-Geisler-Kroigaard ciphertext cannot be decrypted");
    }

    private BigInteger addValues(BigInteger ciphertext1, BigInteger ciphertext2) {
        return ciphertext1.multiply(ciphertext2).mod(keys.publicNumber("n"));
    }

    private BigInteger multiplyValue(BigInteger ciphertext, BigInteger constant) {
        BigInteger n = keys.publicNumber("n");
        BigInteger scalar = constant;
        if (scalar.compareTo(plaintextModulo) >= 0) {
            scalar = scalar.mod(plaintextModulo);
            BigInteger normalized = scalar;
            logger.debug(
                    () ->
                            "Damgard-Geisler-Kroigaard can encrypt messages [0, "
                                    + plaintextModulo
                                    + "). Seems constant exceeded this limit. New constant is "
                                    + normalized);
        }
        return ciphertext.modPow(scalar, n);
    }

    private BigInteger reencryptValue(BigInteger ciphertext) {
        return addValues(ciphertext, encryptValue(BigInteger.ZERO));
    }

    // -----------------------------------------------------------------------
    // Key generation helpers
    // -----------------------------------------------------------------------

    private static BigInteger randomPrimeOfBits(int bits) {
        return MathUtils.randomPrime(BigInteger.TWO.pow(bits - 1), BigInteger.TWO.pow(bits));
    }

    /** Finds a prime p in the form of {@code 2 * u * v * r + 1}. */
    private static BigInteger findPrime(BigInteger u, BigInteger v, int rSize, int maxTries) {
        BigInteger low = BigInteger.TWO.pow(rSize - 1);
        BigInteger high = BigInteger.TWO.pow(rSize).subtract(BigInteger.ONE);
        BigInteger factor = BigInteger.TWO.multiply(u).multiply(v);
        for (int attempt = 0; attempt < maxTries; attempt++) {
            BigInteger r = MathUtils.randomInt(low, high);
            BigInteger p = factor.multiply(r).add(BigInteger.ONE);
            if (MathUtils.isPrime(p)) {
                return p;
            }
        }
        throw new IllegalArgumentException(
                "Failed to find prime p = 1 mod 2*" + u + "*" + v + " in " + maxTries + " tries");
    }

    /** Finds an element of {@code Z_p*} whose order is exactly the product of the given primes. */
    private static BigInteger findElementOfOrder(
            BigInteger p, List<BigInteger> factors, int maxTries) {
        BigInteger order = BigInteger.ONE;
        for (BigInteger factor : factors) {
            order = order.multiply(factor);
        }
        BigInteger cofactor = p.subtract(BigInteger.ONE).divide(order);
        for (int attempt = 0; attempt < maxTries; attempt++) {
            BigInteger x = MathUtils.randomInt(BigInteger.TWO, p.subtract(BigInteger.TWO));
            BigInteger y = x.modPow(cofactor, p);
            // order of y divides prod(factors). it is exactly that if
            // removing any prime factor does not send y to 1
            boolean exact = true;
            for (BigInteger factor : factors) {
                if (y.modPow(order.divide(factor), p).equals(BigInteger.ONE)) {
                    exact = false;
                    break;
                }
            }
            if (exact) {
                return y;
            }
        }
        throw new IllegalArgumentException(
                "Failed to find an element of order " + order + " in " + maxTries + " tries");
    }

    /** Finds x such that {@code x = ap mod p} and {@code x = aq mod q}. */
    private static BigInteger crt(BigInteger ap, BigInteger aq, BigInteger p, BigInteger q) {
        return ap.add(p.multiply(aq.subtract(ap).multiply(p.modInverse(q)).mod(q)))
                .mod(p.multiply(q));
    }
}
