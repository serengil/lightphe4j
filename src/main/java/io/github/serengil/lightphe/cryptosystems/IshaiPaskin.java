package io.github.serengil.lightphe.cryptosystems;

import io.github.serengil.lightphe.model.Algorithm;
import io.github.serengil.lightphe.model.DecisionTree;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.IntValue;
import io.github.serengil.lightphe.model.value.TupleValue;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;

/**
 * Ishai-Paskin evaluates a decision tree on encrypted data.
 *
 * <p>A client encrypts its input bits, a server holding a private decision tree evaluates it on the
 * encrypted input and returns an encryption of the output. Ciphertext size depends on the depth of
 * the tree, not on its size. The paper calls these branching programs. Decision trees are their
 * most common form, and trees sharing sub trees (DAGs) are supported as well.
 *
 * <p>It is built on length flexible Damgard-Jurik: level s encrypts messages in {@code Z_(n^s)}
 * into ciphertexts in {@code Z_(n^(s+1))}, so a level s ciphertext fits into the plaintext space of
 * level s+1. Each level of the tree wraps one more encryption layer around the result. It is also
 * homomorphic with respect to the addition as Damgard-Jurik.
 *
 * <p>Ref: Ishai, Y., Paskin, A. (2007). <a
 * href="https://doi.org/10.1007/978-3-540-70936-7_31">Evaluating Branching Programs on Encrypted
 * Data</a>. TCC 2007.
 */
public final class IshaiPaskin extends DamgardJurik {

    /** Message raised when a homomorphic operation is applied on the output of a decision tree. */
    public static final String DECISION_TREE_OUTPUT_NOT_SUPPORTED_MSG =
            "Output of a decision tree can only be decrypted."
                    + " Homomorphic operations are not supported on it.";

    /**
     * An evaluated node: level 0 is a plain leaf value, level l a ciphertext wrapped in l layers.
     *
     * @param level the number of encryption layers
     * @param value the plain value or ciphertext
     */
    private record Leveled(int level, BigInteger value) {}

    /**
     * Builds an Ishai-Paskin cryptosystem.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param keySize key size in bits; {@code null} defaults to 1024
     */
    public IshaiPaskin(Keys keys, Integer keySize) {
        super(Algorithm.ISHAI_PASKIN, DEFAULT_S, keys, keySize);
    }

    /**
     * Builds an Ishai-Paskin cryptosystem around an existing key pair.
     *
     * @param keys the private-public key pair
     */
    public IshaiPaskin(Keys keys) {
        this(keys, null);
    }

    /**
     * Encrypts a plaintext with Damgard-Jurik at the given level.
     *
     * @param plaintext the message to encrypt in {@code Z_(n^level)}
     * @param level encryption level s; the ciphertext will be in {@code Z_(n^(s+1))}
     * @return the ciphertext
     */
    public BigInteger encryptAtLevel(BigInteger plaintext, int level) {
        return encryptAtLevel(plaintext, level, generateRandomKey());
    }

    /**
     * Encrypts a plaintext with Damgard-Jurik at the given level with an explicit random key.
     *
     * @param plaintext the message to encrypt in {@code Z_(n^level)}
     * @param level encryption level s; the ciphertext will be in {@code Z_(n^(s+1))}
     * @param randomKey a random key co-prime to {@code n}
     * @return the ciphertext
     */
    public BigInteger encryptAtLevel(BigInteger plaintext, int level, BigInteger randomKey) {
        BigInteger n = keys.publicNumber("n");
        BigInteger g = keys.publicNumber("g");
        BigInteger modulo = n.pow(level + 1);
        return g.modPow(plaintext, modulo)
                .multiply(randomKey.modPow(n.pow(level), modulo))
                .mod(modulo);
    }

    /**
     * Decrypts a ciphertext with Damgard-Jurik at the given level.
     *
     * @param ciphertext the ciphertext in {@code Z_(n^(level+1))}
     * @param level encryption level s
     * @return the message in {@code Z_(n^level)}
     */
    public BigInteger decryptAtLevel(BigInteger ciphertext, int level) {
        BigInteger phi = keys.privateNumber("phi");
        BigInteger n = keys.publicNumber("n");
        BigInteger plaintextSpace = n.pow(level);

        // randomness vanishes because the order of Z*_{n^(s+1)} is phi * n^s.
        // what remains is (1 + n)^(m * phi)
        BigInteger a = ciphertext.modPow(phi, n.pow(level + 1));
        BigInteger mPhi = dlog(a, level);
        return mPhi.multiply(phi.modInverse(plaintextSpace)).mod(plaintextSpace);
    }

    /** Finds i such that {@code a = (1 + n)^i mod n^(s+1)} with Damgard-Jurik's algorithm. */
    private BigInteger dlog(BigInteger a, int level) {
        BigInteger n = keys.publicNumber("n");
        BigInteger i = BigInteger.ZERO;
        for (int j = 1; j <= level; j++) {
            BigInteger nj = n.pow(j);
            BigInteger t1 = a.mod(n.pow(j + 1)).subtract(BigInteger.ONE).divide(n);
            BigInteger t2 = i;
            BigInteger factorial = BigInteger.ONE;
            for (int k = 2; k <= j; k++) {
                i = i.subtract(BigInteger.ONE);
                t2 = t2.multiply(i).mod(nj);
                factorial = factorial.multiply(BigInteger.valueOf(k));
                t1 =
                        t1.subtract(t2.multiply(n.pow(k - 1)).multiply(factorial.modInverse(nj)))
                                .mod(nj);
            }
            i = t1;
        }
        return i;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Each bit is encrypted at every level from 1 to depth because the server decides which
     * level it needs.
     */
    @Override
    public List<List<BigInteger>> encryptDecisionTreeInput(List<Integer> bits, int depth) {
        if (depth < 1) {
            throw new IllegalArgumentException(
                    "depth must be a positive integer but it is " + depth);
        }
        List<List<BigInteger>> encryptedInput = new ArrayList<>(bits.size());
        for (Integer bit : bits) {
            if (bit == null || (bit != 0 && bit != 1)) {
                throw new IllegalArgumentException(
                        "Input must consist of bits (0 or 1) but got " + bit);
            }
            List<BigInteger> levels = new ArrayList<>(depth);
            for (int level = 1; level <= depth; level++) {
                levels.add(encryptAtLevel(BigInteger.valueOf(bit), level));
            }
            encryptedInput.add(List.copyOf(levels));
        }
        return List.copyOf(encryptedInput);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Private key is not required. The output is the tuple {@code (level, ciphertext)} where
     * ciphertext wraps level layers of encryption around the output of the tree.
     */
    @Override
    public CipherValue evaluateDecisionTree(
            DecisionTree tree, List<List<BigInteger>> encryptedInput) {
        int depth = encryptedInput.isEmpty() ? 0 : encryptedInput.get(0).size();
        Map<DecisionTree, Leveled> memo = new IdentityHashMap<>();
        Leveled result = evaluateNode(tree, encryptedInput, depth, memo);

        if (result.level() == 0) {
            // tree is a constant, still return an encrypted output
            result = new Leveled(1, encryptAtLevel(result.value(), 1));
        }

        return TupleValue.of(
                IntValue.of(BigInteger.valueOf(result.level())), IntValue.of(result.value()));
    }

    /** Evaluates a node of a decision tree bottom up. */
    private Leveled evaluateNode(
            DecisionTree tree,
            List<List<BigInteger>> encryptedInput,
            int depth,
            Map<DecisionTree, Leveled> memo) {
        BigInteger n = keys.publicNumber("n");

        if (tree instanceof DecisionTree.Leaf leaf) {
            return new Leveled(0, leaf.value().mod(n));
        }

        Leveled cached = memo.get(tree);
        if (cached != null) {
            return cached;
        }

        DecisionTree.Node node = (DecisionTree.Node) tree;
        if (node.variable() < 0 || node.variable() >= encryptedInput.size()) {
            throw new IllegalArgumentException(
                    "Variable index "
                            + node.variable()
                            + " is out of input range [0, "
                            + encryptedInput.size()
                            + ")");
        }

        Leveled evaluated0 = evaluateNode(node.ifZero(), encryptedInput, depth, memo);
        Leveled evaluated1 = evaluateNode(node.ifOne(), encryptedInput, depth, memo);

        // bring both branches to the same level by wrapping fresh encryption layers
        int level = Math.max(evaluated0.level(), evaluated1.level());
        BigInteger value0 = lift(evaluated0, level);
        BigInteger value1 = lift(evaluated1, level);

        // values at level l are in Z_{n^(l+1)}, which is plaintext space of level l+1.
        // E(x)^(v1 - v0) * E(v0) = E(v0 + x * (v1 - v0)) = E(v_x)
        level += 1;
        if (level > depth) {
            throw new IllegalArgumentException(
                    "Decision tree is deeper than " + depth + " levels of encrypted input");
        }

        BigInteger plaintextSpace = n.pow(level);
        BigInteger ciphertextSpace = n.pow(level + 1);

        BigInteger encryptedBit = encryptedInput.get(node.variable()).get(level - 1);
        BigInteger difference = value1.subtract(value0).mod(plaintextSpace);
        BigInteger ciphertext =
                encryptedBit
                        .modPow(difference, ciphertextSpace)
                        .multiply(encryptAtLevel(value0, level))
                        .mod(ciphertextSpace);

        Leveled result = new Leveled(level, ciphertext);
        memo.put(tree, result);
        return result;
    }

    /** Wraps encryption layers around a value with fresh randomness. */
    private BigInteger lift(Leveled evaluated, int toLevel) {
        BigInteger value = evaluated.value();
        for (int level = evaluated.level() + 1; level <= toLevel; level++) {
            value = encryptAtLevel(value, level);
        }
        return value;
    }

    @Override
    public CipherValue add(CipherValue ciphertext1, CipherValue ciphertext2) {
        if (!(ciphertext1 instanceof IntValue) || !(ciphertext2 instanceof IntValue)) {
            throw new IllegalArgumentException(DECISION_TREE_OUTPUT_NOT_SUPPORTED_MSG);
        }
        return super.add(ciphertext1, ciphertext2);
    }

    @Override
    public CipherValue multiplyByConstant(CipherValue ciphertext, BigInteger constant) {
        if (!(ciphertext instanceof IntValue)) {
            throw new IllegalArgumentException(DECISION_TREE_OUTPUT_NOT_SUPPORTED_MSG);
        }
        return super.multiplyByConstant(ciphertext, constant);
    }

    @Override
    public CipherValue reencrypt(CipherValue ciphertext) {
        if (!(ciphertext instanceof IntValue)) {
            throw new IllegalArgumentException(DECISION_TREE_OUTPUT_NOT_SUPPORTED_MSG);
        }
        return super.reencrypt(ciphertext);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Accepts a ciphertext created by {@link #encrypt}, or the {@code (level, ciphertext)}
     * output of a decision tree evaluation.
     */
    @Override
    public BigInteger decrypt(CipherValue ciphertext) {
        if (ciphertext instanceof IntValue) {
            return super.decrypt(ciphertext);
        }

        TupleValue output = asTuple(ciphertext);
        if (output.size() != 2) {
            throw new IllegalArgumentException(
                    "expected a (level, ciphertext) pair, got " + output.size() + " components");
        }
        int level = asInt(output.get(0)).intValueExact();
        BigInteger value = asInt(output.get(1));

        // peel encryption layers from outer to inner
        for (int current = level; current > 0; current--) {
            value = decryptAtLevel(value, current);
        }
        return value;
    }
}
