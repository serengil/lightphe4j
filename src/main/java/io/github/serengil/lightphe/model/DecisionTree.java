package io.github.serengil.lightphe.model;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * A decision tree evaluated on encrypted input by Ishai-Paskin.
 *
 * <p>A tree is either a {@link Leaf} carrying an integer output, or a {@link Node} that continues
 * with {@code ifZero} when the input bit at {@code variable} is 0, and with {@code ifOne} when it
 * is 1. Sub trees may be shared between several parents, which turns the tree into a DAG; shared
 * sub trees are evaluated once.
 */
public sealed interface DecisionTree {

    /**
     * A leaf that outputs an integer.
     *
     * @param value the output
     */
    record Leaf(BigInteger value) implements DecisionTree {

        /** Creates a leaf, rejecting a {@code null} value. */
        public Leaf {
            Objects.requireNonNull(value, "value");
        }

        @Override
        public String toString() {
            return value.toString();
        }
    }

    /**
     * A decision node that checks one input bit.
     *
     * @param variable the index of the input bit
     * @param ifZero the sub tree to continue with when the bit is 0
     * @param ifOne the sub tree to continue with when the bit is 1
     */
    record Node(int variable, DecisionTree ifZero, DecisionTree ifOne) implements DecisionTree {

        /** Creates a decision node, rejecting missing sub trees. */
        public Node {
            Objects.requireNonNull(ifZero, "ifZero");
            Objects.requireNonNull(ifOne, "ifOne");
        }

        @Override
        public String toString() {
            return "(" + variable + ", " + ifZero + ", " + ifOne + ")";
        }
    }

    /**
     * Builds a leaf.
     *
     * @param value the output
     * @return the leaf
     */
    static DecisionTree leaf(long value) {
        return new Leaf(BigInteger.valueOf(value));
    }

    /**
     * Builds a decision node.
     *
     * @param variable the index of the input bit
     * @param ifZero the sub tree to continue with when the bit is 0
     * @param ifOne the sub tree to continue with when the bit is 1
     * @return the node
     */
    static DecisionTree node(int variable, DecisionTree ifZero, DecisionTree ifOne) {
        return new Node(variable, ifZero, ifOne);
    }

    /**
     * Returns the maximum number of decisions on a path of the tree.
     *
     * @return the depth
     */
    default int depth() {
        if (this instanceof Node node) {
            return 1 + Math.max(node.ifZero().depth(), node.ifOne().depth());
        }
        return 0;
    }

    /**
     * Runs the tree on plain input bits.
     *
     * @param bits the input bits
     * @return the output of the tree
     */
    default BigInteger evaluate(List<Integer> bits) {
        DecisionTree current = this;
        while (current instanceof Node node) {
            current = bits.get(node.variable()) == 1 ? node.ifOne() : node.ifZero();
        }
        return ((Leaf) current).value();
    }
}
