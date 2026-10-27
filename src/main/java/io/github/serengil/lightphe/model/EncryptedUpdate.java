package io.github.serengil.lightphe.model;

import java.util.List;
import java.util.Objects;

/**
 * An encrypted model update, or an encrypted sum of model updates, in secure aggregation. Java
 * counterpart of the {@code {"chunks": ..., "layout": ..., "count": ...}} dictionaries of the
 * Python library.
 *
 * @param chunks the ciphertexts, each packing many values of the update
 * @param layout the packing layout
 * @param count the number of updates it contains
 */
public record EncryptedUpdate(List<Ciphertext> chunks, AggregationLayout layout, int count) {

    /** Creates the encrypted update, copying the chunks defensively. */
    public EncryptedUpdate {
        chunks = List.copyOf(chunks);
        Objects.requireNonNull(layout, "layout");
    }
}
