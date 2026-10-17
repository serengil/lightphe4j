package io.github.serengil.lightphe.model;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * A decision tree with numeric thresholds, evaluated privately by Damgard-Geisler-Kroigaard.
 *
 * <p>A tree is either a {@link Leaf} carrying an integer label, or a {@link Node} that continues
 * with {@code ifLessOrEqual} when the feature at {@code featureIndex} is less than or equal to
 * {@code threshold}, and with {@code ifGreater} otherwise. This is the Java counterpart of the
 * {@code (feature_index, threshold, tree_if_less_or_equal, tree_if_greater)} tuples of the Python
 * library.
 */
public sealed interface NumericDecisionTree {

    /**
     * A leaf that outputs a label.
     *
     * @param label the output
     */
    record Leaf(long label) implements NumericDecisionTree {

        @Override
        public String toString() {
            return Long.toString(label);
        }
    }

    /**
     * A decision node that compares one feature with a threshold.
     *
     * @param featureIndex the index of the compared feature
     * @param threshold the threshold
     * @param ifLessOrEqual the sub tree to continue with when the feature is at most the threshold
     * @param ifGreater the sub tree to continue with otherwise
     */
    record Node(
            int featureIndex,
            long threshold,
            NumericDecisionTree ifLessOrEqual,
            NumericDecisionTree ifGreater)
            implements NumericDecisionTree {

        /** Creates a decision node, rejecting missing sub trees. */
        public Node {
            Objects.requireNonNull(ifLessOrEqual, "ifLessOrEqual");
            Objects.requireNonNull(ifGreater, "ifGreater");
        }

        @Override
        public String toString() {
            return "("
                    + featureIndex
                    + ", "
                    + threshold
                    + ", "
                    + ifLessOrEqual
                    + ", "
                    + ifGreater
                    + ")";
        }
    }

    /**
     * Output of the server's comparison step: the comparisons sent to the client, and the state the
     * server keeps secret for the last step.
     *
     * @param encryptedComparisons the blinded comparisons, to be sent to the client
     * @param serverState the state the server must keep secret
     */
    record Comparisons(List<List<BigInteger>> encryptedComparisons, ServerState serverState) {

        /** Creates the comparison step output, copying the comparisons defensively. */
        public Comparisons {
            encryptedComparisons = encryptedComparisons.stream().map(List::copyOf).toList();
            Objects.requireNonNull(serverState, "serverState");
        }
    }

    /**
     * What the server remembers between its comparison and leaf steps.
     *
     * @param tree the evaluated tree
     * @param flips the random flip of every decision node, in pre-order
     */
    record ServerState(NumericDecisionTree tree, List<Integer> flips) {

        /** Creates the server state, copying the flips defensively. */
        public ServerState {
            Objects.requireNonNull(tree, "tree");
            flips = List.copyOf(flips);
        }
    }

    /**
     * An encrypted leaf sent to the client: {@code E(r1 * cost)} and {@code E(r2 * cost + label)}.
     * Only the reached leaf has cost 0.
     *
     * @param maskedCost the masked path cost
     * @param maskedLabel the masked label
     */
    record EncryptedLeaf(BigInteger maskedCost, BigInteger maskedLabel) {

        /** Creates an encrypted leaf, rejecting {@code null} components. */
        public EncryptedLeaf {
            Objects.requireNonNull(maskedCost, "maskedCost");
            Objects.requireNonNull(maskedLabel, "maskedLabel");
        }
    }

    /**
     * Builds a leaf.
     *
     * @param label the output
     * @return the leaf
     */
    static NumericDecisionTree leaf(long label) {
        return new Leaf(label);
    }

    /**
     * Builds a decision node.
     *
     * @param featureIndex the index of the compared feature
     * @param threshold the threshold
     * @param ifLessOrEqual the sub tree to continue with when the feature is at most the threshold
     * @param ifGreater the sub tree to continue with otherwise
     * @return the node
     */
    static NumericDecisionTree node(
            int featureIndex,
            long threshold,
            NumericDecisionTree ifLessOrEqual,
            NumericDecisionTree ifGreater) {
        return new Node(featureIndex, threshold, ifLessOrEqual, ifGreater);
    }

    /**
     * Runs the tree on plain features.
     *
     * @param features the features
     * @return the label of the reached leaf
     */
    default long evaluate(List<Long> features) {
        NumericDecisionTree current = this;
        while (current instanceof Node node) {
            current =
                    features.get(node.featureIndex()) <= node.threshold()
                            ? node.ifLessOrEqual()
                            : node.ifGreater();
        }
        return ((Leaf) current).label();
    }
}
