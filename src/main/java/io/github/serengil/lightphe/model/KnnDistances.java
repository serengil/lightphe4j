package io.github.serengil.lightphe.model;

import java.math.BigInteger;
import java.util.List;

/**
 * The k nearest vectors found from encrypted distances, the Java counterpart of the {@code
 * {"indices": ..., "distances": ...}} dictionaries of the Python library.
 *
 * @param indices the indices of the k nearest vectors from the nearest one. Earlier index is
 *     returned on ties.
 * @param distances the squared euclidean distances of the k nearest vectors
 */
public record KnnDistances(List<Integer> indices, List<BigInteger> distances) {

    /** Creates the result, copying the lists defensively. */
    public KnnDistances {
        indices = List.copyOf(indices);
        distances = List.copyOf(distances);
    }
}
