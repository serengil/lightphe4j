package io.github.serengil.lightphe.model;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Packing layout of model updates in secure aggregation, the Java counterpart of the {@code layout}
 * dictionary of the Python library. Updates can be aggregated only if they have the same layout.
 *
 * @param length number of values in an update
 * @param precision number of decimal digits kept after quantization
 * @param bound the maximum value scaled by {@code 10^precision}
 * @param maxClients maximum number of updates to be summed
 * @param slotBits number of bits of a slot
 * @param slots number of slots packed into a plaintext
 */
public record AggregationLayout(
        int length, int precision, BigInteger bound, int maxClients, int slotBits, int slots) {

    /** Creates the layout, rejecting a {@code null} bound. */
    public AggregationLayout {
        Objects.requireNonNull(bound, "bound");
    }
}
