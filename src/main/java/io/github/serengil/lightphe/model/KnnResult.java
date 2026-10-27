package io.github.serengil.lightphe.model;

import java.util.List;

/**
 * The result of encrypted k nearest neighbor search, to be decrypted by the client. Java
 * counterpart of the {@code {"indices": ..., "labels": ...}} dictionaries of the Python library.
 *
 * @param indices the encrypted indices of the k nearest vectors from the nearest one
 * @param labels the encrypted labels of the k nearest vectors, or an empty list when the database
 *     has no labels
 */
public record KnnResult(List<Ciphertext> indices, List<Ciphertext> labels) {

    /** Creates the result, copying the lists defensively. */
    public KnnResult {
        indices = List.copyOf(indices);
        labels = labels == null ? List.of() : List.copyOf(labels);
    }
}
