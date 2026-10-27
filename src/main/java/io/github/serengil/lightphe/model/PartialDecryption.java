package io.github.serengil.lightphe.model;

import io.github.serengil.lightphe.model.value.CipherValue;
import java.util.Objects;

/**
 * A ciphertext decrypted partially with the share of a shareholder in threshold decryption. It
 * reveals nothing about the plaintext alone, and threshold many of them restore the plaintext.
 *
 * <p>Java counterpart of the {@code {"index": i, "value": v, "proof": ...}} dictionaries of the
 * Python library.
 *
 * @param index the index of the shareholder in {@code [1, parties]}
 * @param value the partial decryption, an integer or an elliptic curve point
 * @param proof the zero-knowledge proof that the partial decryption is computed with the share of
 *     the shareholder, or {@code null} when it is not proven
 */
public record PartialDecryption(int index, CipherValue value, Proof proof) {

    /** Creates the partial decryption, rejecting a {@code null} value. */
    public PartialDecryption {
        Objects.requireNonNull(value, "value");
    }

    /**
     * Creates an unproven partial decryption.
     *
     * @param index the index of the shareholder
     * @param value the partial decryption
     */
    public PartialDecryption(int index, CipherValue value) {
        this(index, value, null);
    }

    /**
     * Returns a copy of this partial decryption with another value, keeping its index and proof.
     *
     * @param newValue the new value
     * @return the copy
     */
    public PartialDecryption withValue(CipherValue newValue) {
        return new PartialDecryption(index, newValue, proof);
    }

    /**
     * Returns a copy of this partial decryption under another index, keeping its value and proof.
     *
     * @param newIndex the new index
     * @return the copy
     */
    public PartialDecryption withIndex(int newIndex) {
        return new PartialDecryption(newIndex, value, proof);
    }

    /**
     * Returns a copy of this partial decryption with another proof, keeping its index and value.
     *
     * @param newProof the new proof, or {@code null} to drop it
     * @return the copy
     */
    public PartialDecryption withProof(Proof newProof) {
        return new PartialDecryption(index, value, newProof);
    }
}
