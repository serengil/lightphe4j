package io.github.serengil.lightphe.model;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * A message the server sends to the client during encrypted argmax.
 *
 * <p>Java counterpart of the {@code {"type": ..., "payload": ...}} dictionaries of the Python
 * library. The protocol needs a few round trips per value, so the server talks to the client
 * through a callable that sends one of these messages and returns the client's answer. Each message
 * reports its Python {@link #type()} name, which is handy when it has to be serialised for a
 * network call.
 */
public sealed interface ArgmaxMessage {

    /**
     * Returns the message type as named by the Python library.
     *
     * @return the type name
     */
    String type();

    /**
     * Asks the client to encrypt the bits of a masked difference.
     *
     * @param ciphertext the masked difference
     */
    record MaskedDifference(BigInteger ciphertext) implements ArgmaxMessage {

        /** Creates the message, rejecting a {@code null} ciphertext. */
        public MaskedDifference {
            Objects.requireNonNull(ciphertext, "ciphertext");
        }

        @Override
        public String type() {
            return "masked_difference";
        }
    }

    /**
     * Asks the client to answer two blinded comparisons.
     *
     * @param comparisons the blinded comparisons
     */
    record Comparisons(List<List<BigInteger>> comparisons) implements ArgmaxMessage {

        /** Creates the message, copying the comparisons defensively. */
        public Comparisons {
            comparisons = comparisons.stream().map(List::copyOf).toList();
        }

        @Override
        public String type() {
            return "comparisons";
        }
    }

    /**
     * Asks the client to multiply a masked bit with masked factors.
     *
     * @param maskedBit the masked bit
     * @param maskedFactors the masked factors
     */
    record Products(BigInteger maskedBit, List<BigInteger> maskedFactors) implements ArgmaxMessage {

        /** Creates the message, copying the factors defensively. */
        public Products {
            Objects.requireNonNull(maskedBit, "maskedBit");
            maskedFactors = List.copyOf(maskedFactors);
        }

        @Override
        public String type() {
            return "products";
        }
    }
}
