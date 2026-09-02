package io.github.serengil.lightphe.model.value;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * An ordered collection of ciphertext values.
 *
 * <p>This models the {@code (c1, c2)} pairs of ElGamal and elliptic curve ElGamal, the per-bit
 * ciphertext lists of Goldwasser-Micali, and the per-bit vectors of Sander-Young-Yung, which nest
 * one tuple inside another.
 */
public final class TupleValue implements CipherValue {

    private final List<CipherValue> items;

    private TupleValue(List<CipherValue> items) {
        this.items = List.copyOf(items);
    }

    /**
     * Builds a tuple from the given items.
     *
     * @param items the tuple components
     * @return the tuple
     */
    public static TupleValue of(CipherValue... items) {
        return new TupleValue(List.of(items));
    }

    /**
     * Builds a tuple from the given items.
     *
     * @param items the tuple components
     * @return the tuple
     */
    public static TupleValue of(List<? extends CipherValue> items) {
        return new TupleValue(new ArrayList<>(items));
    }

    /**
     * Builds a tuple of integer ciphertexts.
     *
     * @param values the integers
     * @return the tuple
     */
    public static TupleValue ofIntegers(List<BigInteger> values) {
        return new TupleValue(values.stream().map(v -> (CipherValue) new IntValue(v)).toList());
    }

    /**
     * Returns the tuple components.
     *
     * @return an unmodifiable view of the items
     */
    public List<CipherValue> items() {
        return items;
    }

    /**
     * Returns the number of components.
     *
     * @return the tuple length
     */
    public int size() {
        return items.size();
    }

    /**
     * Returns the component at the given index.
     *
     * @param index zero-based position
     * @return the component
     */
    public CipherValue get(int index) {
        return items.get(index);
    }

    /**
     * Returns the components as integers.
     *
     * @return the integers carried by this tuple
     * @throws IllegalArgumentException when any component is not an integer
     */
    public List<BigInteger> asIntegers() {
        List<BigInteger> out = new ArrayList<>(items.size());
        for (int i = 0; i < items.size(); i++) {
            if (!(items.get(i) instanceof IntValue value)) {
                throw new IllegalArgumentException(
                        "tuple item " + i + " is not an integer ciphertext");
            }
            out.add(value.value());
        }
        return out;
    }

    /**
     * Returns the components as nested tuples.
     *
     * @return the tuples carried by this tuple
     * @throws IllegalArgumentException when any component is not a tuple
     */
    public List<TupleValue> asTuples() {
        List<TupleValue> out = new ArrayList<>(items.size());
        for (int i = 0; i < items.size(); i++) {
            if (!(items.get(i) instanceof TupleValue value)) {
                throw new IllegalArgumentException("tuple item " + i + " is not a tuple");
            }
            out.add(value);
        }
        return out;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return obj instanceof TupleValue other && items.equals(other.items);
    }

    @Override
    public int hashCode() {
        return Objects.hash(items);
    }

    @Override
    public String toString() {
        return items.stream().map(Object::toString).collect(Collectors.joining(", ", "(", ")"));
    }
}
