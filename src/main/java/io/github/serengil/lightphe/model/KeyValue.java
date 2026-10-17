package io.github.serengil.lightphe.model;

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * A single entry inside a key section.
 *
 * <p>Key material in the Python library is a nested dictionary whose leaves are integers, curve
 * points written as two-element tuples, or - for Boneh-Goh-Nissim - a further dictionary. This
 * sealed hierarchy is the type-safe rendering of that structure, and it serialises back to exactly
 * the same JSON.
 */
public sealed interface KeyValue {

    /**
     * An integer key component, e.g. an RSA modulus or a Paillier generator.
     *
     * @param value the integer
     */
    record Num(BigInteger value) implements KeyValue {

        /** Creates an integer key component, rejecting a {@code null} value. */
        public Num {
            Objects.requireNonNull(value, "value");
        }

        @Override
        public String toString() {
            return value.toString();
        }
    }

    /**
     * A curve point key component, e.g. the elliptic curve ElGamal public key {@code Qa}.
     *
     * @param x the x coordinate
     * @param y the y coordinate
     */
    record Point(BigInteger x, BigInteger y) implements KeyValue {

        /** Creates a curve point key component, rejecting {@code null} coordinates. */
        public Point {
            Objects.requireNonNull(x, "x");
            Objects.requireNonNull(y, "y");
        }

        @Override
        public String toString() {
            return "(" + x + ", " + y + ")";
        }
    }

    /**
     * A list of integers other than a two-element curve point, e.g. a Castagnos-Laguillaumie binary
     * quadratic form {@code [a, b, c]}.
     *
     * @param values the integers
     */
    record Numbers(List<BigInteger> values) implements KeyValue {

        /** Creates an integer list key component, copying the values defensively. */
        public Numbers {
            values = List.copyOf(values);
        }

        @Override
        public String toString() {
            return values.toString();
        }
    }

    /**
     * A list of integer lists, e.g. a Gentry-Halevi-Vaikuntanathan matrix or the vector of curve
     * points of Freeman-Boneh-Goh-Nissim.
     *
     * @param rows the rows
     */
    record Matrix(List<List<BigInteger>> rows) implements KeyValue {

        /** Creates a matrix key component, copying the rows defensively. */
        public Matrix {
            rows = rows.stream().map(List::copyOf).toList();
        }

        @Override
        public String toString() {
            return rows.toString();
        }
    }

    /** A nested dictionary key component, used by Boneh-Goh-Nissim to carry its generated curve. */
    final class Nested implements KeyValue {

        private final Map<String, KeyValue> entries;

        /**
         * Creates a nested key component.
         *
         * @param entries the nested entries; copied defensively
         */
        public Nested(Map<String, KeyValue> entries) {
            this.entries = new LinkedHashMap<>(entries);
        }

        /**
         * Returns the nested entries.
         *
         * @return a live view of the entries
         */
        public Map<String, KeyValue> entries() {
            return entries;
        }

        /**
         * Returns the integer stored under the given field.
         *
         * @param field the field name
         * @return the integer
         * @throws IllegalArgumentException when the field is absent or is not an integer
         */
        public BigInteger number(String field) {
            KeyValue value = entries.get(field);
            if (!(value instanceof Num num)) {
                throw new IllegalArgumentException(
                        "nested field '" + field + "' is not an integer");
            }
            return num.value();
        }

        /**
         * Returns the curve point stored under the given field.
         *
         * @param field the field name
         * @return the point
         * @throws IllegalArgumentException when the field is absent or is not a point
         */
        public Point point(String field) {
            KeyValue value = entries.get(field);
            if (!(value instanceof Point point)) {
                throw new IllegalArgumentException("nested field '" + field + "' is not a point");
            }
            return point;
        }

        /**
         * Returns a deep copy of this nested component.
         *
         * @return the copy
         */
        public Nested copy() {
            Map<String, KeyValue> copied = new LinkedHashMap<>();
            entries.forEach(
                    (key, value) ->
                            copied.put(
                                    key, value instanceof Nested nested ? nested.copy() : value));
            return new Nested(copied);
        }

        @Override
        public boolean equals(Object obj) {
            return obj instanceof Nested other && entries.equals(other.entries);
        }

        @Override
        public int hashCode() {
            return entries.hashCode();
        }

        @Override
        public String toString() {
            return entries.entrySet().stream()
                    .map(entry -> entry.getKey() + ": " + entry.getValue())
                    .collect(Collectors.joining(", ", "{", "}"));
        }
    }

    /**
     * Wraps an integer.
     *
     * @param value the integer
     * @return the key component
     */
    static KeyValue of(BigInteger value) {
        return new Num(value);
    }

    /**
     * Wraps a {@code long}.
     *
     * @param value the integer
     * @return the key component
     */
    static KeyValue of(long value) {
        return new Num(BigInteger.valueOf(value));
    }

    /**
     * Wraps a list of integers.
     *
     * @param values the integers
     * @return the key component
     */
    static KeyValue numbers(List<BigInteger> values) {
        return new Numbers(values);
    }

    /**
     * Wraps a list of integer lists.
     *
     * @param rows the rows
     * @return the key component
     */
    static KeyValue matrix(List<List<BigInteger>> rows) {
        return new Matrix(rows);
    }

    /**
     * Wraps a curve point.
     *
     * @param x the x coordinate
     * @param y the y coordinate
     * @return the key component
     */
    static KeyValue point(BigInteger x, BigInteger y) {
        return new Point(x, y);
    }
}
