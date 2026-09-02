package io.github.serengil.lightphe.cryptosystems;

import io.github.serengil.lightphe.model.Algorithm;
import io.github.serengil.lightphe.model.Homomorphic;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.IntValue;
import io.github.serengil.lightphe.model.value.TupleValue;
import java.math.BigInteger;

/**
 * Shared plumbing for the cryptosystems: key material, the two moduli, and the small helpers that
 * unwrap a {@link CipherValue} into the shape a scheme expects.
 *
 * <p>Subclasses assign {@code plaintextModulo} and {@code ciphertextModulo} in their constructor
 * and never touch them again.
 */
public abstract class AbstractHomomorphic implements Homomorphic {

    /** The private-public key pair. */
    protected final Keys keys;

    /** The algorithm this cryptosystem implements. */
    private final Algorithm algorithm;

    /** Size of the message space. */
    protected BigInteger plaintextModulo;

    /** Modulus the ciphertext arithmetic is carried out in. */
    protected BigInteger ciphertextModulo;

    /**
     * Creates the cryptosystem.
     *
     * @param algorithm the algorithm being implemented
     * @param keys the key material
     */
    protected AbstractHomomorphic(Algorithm algorithm, Keys keys) {
        this.algorithm = algorithm;
        this.keys = keys;
    }

    @Override
    public Algorithm algorithm() {
        return algorithm;
    }

    @Override
    public Keys keys() {
        return keys;
    }

    @Override
    public BigInteger plaintextModulo() {
        return plaintextModulo;
    }

    @Override
    public BigInteger ciphertextModulo() {
        return ciphertextModulo;
    }

    /**
     * Unwraps a ciphertext expected to be a single integer.
     *
     * @param value the ciphertext
     * @return the integer it carries
     * @throws IllegalArgumentException when the ciphertext has another shape
     */
    protected static BigInteger asInt(CipherValue value) {
        if (!(value instanceof IntValue intValue)) {
            throw new IllegalArgumentException(
                    "expected an integer ciphertext, got " + value.getClass().getSimpleName());
        }
        return intValue.value();
    }

    /**
     * Unwraps a ciphertext expected to be a tuple.
     *
     * @param value the ciphertext
     * @return the tuple it carries
     * @throws IllegalArgumentException when the ciphertext has another shape
     */
    protected static TupleValue asTuple(CipherValue value) {
        if (!(value instanceof TupleValue tuple)) {
            throw new IllegalArgumentException(
                    "expected a tuple ciphertext, got " + value.getClass().getSimpleName());
        }
        return tuple;
    }

    /**
     * Unwraps a ciphertext expected to be a pair of integers, such as an ElGamal {@code (c1, c2)}.
     *
     * @param value the ciphertext
     * @return the two integers
     * @throws IllegalArgumentException when the ciphertext is not a pair of integers
     */
    protected static BigInteger[] asIntPair(CipherValue value) {
        TupleValue tuple = asTuple(value);
        if (tuple.size() != 2) {
            throw new IllegalArgumentException(
                    "expected a ciphertext pair, got " + tuple.size() + " components");
        }
        return new BigInteger[] {asInt(tuple.get(0)), asInt(tuple.get(1))};
    }
}
