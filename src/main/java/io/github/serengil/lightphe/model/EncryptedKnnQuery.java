package io.github.serengil.lightphe.model;

import java.util.List;
import java.util.Objects;

/**
 * An encrypted query vector of encrypted k nearest neighbor search, the Java counterpart of the
 * {@code {"query": ..., "norm": ...}} dictionaries of the Python library.
 *
 * @param query the encrypted entries of the query vector
 * @param norm the encrypted squared norm of the query vector
 */
public record EncryptedKnnQuery(List<Ciphertext> query, Ciphertext norm) {

    /** Creates the encrypted query, copying the entries defensively. */
    public EncryptedKnnQuery {
        query = List.copyOf(query);
        Objects.requireNonNull(norm, "norm");
    }
}
