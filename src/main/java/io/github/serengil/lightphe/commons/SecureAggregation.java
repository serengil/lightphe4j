package io.github.serengil.lightphe.commons;

import io.github.serengil.lightphe.model.AggregationLayout;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Secure aggregation of model updates for federated learning, the counterpart of {@code
 * lightphe.commons.secure_aggregation}.
 *
 * <p>Each client quantizes its update to integers and packs many of them into a single plaintext,
 * so it encrypts one ciphertext per chunk of values instead of one ciphertext per value. Server
 * sums the encrypted updates of clients chunk by chunk, and only the sum is decrypted, e.g. by a
 * committee holding shares of the private key with threshold decryption.
 *
 * <ul>
 *   <li>quantization: x is scaled by {@code 10^precision} and rounded, so it is an integer in
 *       {@code [-B, B]} where B is the maximum value scaled the same way
 *   <li>packing: values are shifted by B to be non-negative, and placed into slots of {@code
 *       slotBits} bits, i.e. {@code plaintext = sum of (x_i + B) * 2^(slotBits * i)}
 *   <li>headroom: a slot of the sum of c updates is at most {@code c * 2B}, so {@code slotBits} is
 *       the bit length of {@code maxClients * 2B}, and slots never overflow into each other
 *   <li>unpacking: slot of the sum minus {@code c * B} is the sum of values of c clients
 * </ul>
 *
 * <p>Ref: Bonawitz, K. et al. (2017). Practical Secure Aggregation for Privacy-Preserving Machine
 * Learning. ACM CCS 2017.
 *
 * <p>Ref: Zhang, C. et al. (2020). BatchCrypt: Efficient Homomorphic Encryption for Cross-Silo
 * Federated Learning. USENIX ATC 2020.
 */
public final class SecureAggregation {

    private SecureAggregation() {
        throw new AssertionError("no instances");
    }

    /**
     * Builds the packing layout of updates.
     *
     * @param length number of values in an update
     * @param precision number of decimal digits kept after quantization
     * @param maxValue absolute values of updates must be at most this
     * @param maxClients maximum number of updates to be summed
     * @param modulo plaintext modulo of the cryptosystem
     * @return the layout
     * @throws IllegalArgumentException when the arguments are invalid or slots do not fit
     */
    public static AggregationLayout buildLayout(
            int length, int precision, Number maxValue, int maxClients, BigInteger modulo) {
        if (length < 1) {
            throw new IllegalArgumentException("Update must have at least one value");
        }
        if (maxClients < 1) {
            throw new IllegalArgumentException(
                    "Maximum number of clients must be a positive integer");
        }
        if (maxValue == null || maxValue.doubleValue() <= 0) {
            throw new IllegalArgumentException("Maximum value must be a positive number");
        }
        if (precision < 0) {
            throw new IllegalArgumentException("Precision must be a non-negative integer");
        }

        BigInteger bound = quantize(maxValue, precision);
        if (bound.signum() < 1) {
            throw new IllegalArgumentException(
                    "Maximum value " + maxValue + " is zero after quantization");
        }

        int slotBits =
                BigInteger.valueOf(maxClients).multiply(BigInteger.TWO).multiply(bound).bitLength();
        // packed plaintexts must be less than the plaintext modulo
        int slots = (modulo.bitLength() - 1) / slotBits;
        if (slots < 1) {
            throw new IllegalArgumentException(
                    "Plaintext space is too small for "
                            + slotBits
                            + "-bit slots. Use a larger key size, a smaller precision, a smaller"
                            + " maximum value or fewer clients.");
        }
        return new AggregationLayout(length, precision, bound, maxClients, slotBits, slots);
    }

    /**
     * Quantizes an update and packs its values into plaintexts.
     *
     * @param update the model update of a client
     * @param layout output of {@link #buildLayout}
     * @return one plaintext for each chunk of values
     * @throws IllegalArgumentException when a value exceeds the maximum value
     */
    public static List<BigInteger> pack(List<? extends Number> update, AggregationLayout layout) {
        BigInteger bound = layout.bound();
        List<BigInteger> shifted = new ArrayList<>(update.size());
        for (Number x : update) {
            if (x == null) {
                throw new IllegalArgumentException("Update must be a list of numbers");
            }
            BigInteger quantized = quantize(x, layout.precision());
            if (quantized.abs().compareTo(bound) > 0) {
                throw new IllegalArgumentException(
                        "Value " + x + " of the update exceeds the maximum value");
            }
            shifted.add(quantized.add(bound));
        }

        List<BigInteger> plaintexts = new ArrayList<>();
        for (int start = 0; start < shifted.size(); start += layout.slots()) {
            BigInteger plaintext = BigInteger.ZERO;
            int end = Math.min(start + layout.slots(), shifted.size());
            for (int i = start; i < end; i++) {
                plaintext = plaintext.or(shifted.get(i).shiftLeft(layout.slotBits() * (i - start)));
            }
            plaintexts.add(plaintext);
        }
        return plaintexts;
    }

    /**
     * Unpacks the sum of count updates from decrypted plaintexts.
     *
     * @param plaintexts decrypted chunks of the sum
     * @param layout output of {@link #buildLayout}
     * @param count number of summed updates
     * @return the sum of updates
     */
    public static List<Double> unpack(
            List<BigInteger> plaintexts, AggregationLayout layout, int count) {
        BigInteger offset = BigInteger.valueOf(count).multiply(layout.bound());
        BigInteger mask = BigInteger.ONE.shiftLeft(layout.slotBits()).subtract(BigInteger.ONE);

        List<Double> values = new ArrayList<>(layout.length());
        for (BigInteger plaintext : plaintexts) {
            for (int i = 0; i < layout.slots() && values.size() < layout.length(); i++) {
                BigInteger slot = plaintext.shiftRight(layout.slotBits() * i).and(mask);
                values.add(
                        new BigDecimal(slot.subtract(offset))
                                .movePointLeft(layout.precision())
                                .doubleValue());
            }
        }
        return values;
    }

    /**
     * Returns the number of chunks of an update.
     *
     * @param layout output of {@link #buildLayout}
     * @return the number of ciphertexts an update is packed into
     */
    public static int chunksOf(AggregationLayout layout) {
        return (layout.length() + layout.slots() - 1) / layout.slots();
    }

    /** Scales a value by {@code 10^precision} and rounds it half to even as Python's round does. */
    private static BigInteger quantize(Number value, int precision) {
        if (value instanceof BigInteger
                || value instanceof Long
                || value instanceof Integer
                || value instanceof Short
                || value instanceof Byte) {
            BigInteger integral =
                    value instanceof BigInteger big ? big : BigInteger.valueOf(value.longValue());
            return integral.multiply(BigInteger.TEN.pow(precision));
        }
        double scaled = value.doubleValue() * Math.pow(10, precision);
        if (Double.isNaN(scaled) || Double.isInfinite(scaled)) {
            throw new IllegalArgumentException("Update must be a list of finite numbers");
        }
        return new BigDecimal(Math.rint(scaled)).toBigInteger();
    }
}
