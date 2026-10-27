package io.github.serengil.lightphe.model;

import java.util.List;

/**
 * The decrypted sum and mean of model updates in secure aggregation, the Java counterpart of the
 * {@code {"sum": ..., "mean": ..., "count": ...}} dictionaries of the Python library.
 *
 * @param sum the sum of updates
 * @param mean the mean of updates
 * @param count the number of updates
 */
public record Aggregate(List<Double> sum, List<Double> mean, int count) {

    /** Creates the aggregate, copying the values defensively. */
    public Aggregate {
        sum = List.copyOf(sum);
        mean = List.copyOf(mean);
    }
}
