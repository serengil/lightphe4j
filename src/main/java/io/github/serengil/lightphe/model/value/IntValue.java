package io.github.serengil.lightphe.model.value;

import java.math.BigInteger;
import java.util.Objects;

/**
 * A single integer ciphertext.
 *
 * <p>Used by RSA, Paillier, Damgard-Jurik, Okamoto-Uchiyama, Benaloh and Naccache-Stern.
 *
 * @param value the ciphertext integer
 */
public record IntValue(BigInteger value) implements CipherValue {

    /**
     * Creates an integer ciphertext.
     *
     * @param value the ciphertext integer; must not be {@code null}
     */
    public IntValue {
        Objects.requireNonNull(value, "value");
    }

    /**
     * Wraps a {@code long} as an integer ciphertext.
     *
     * @param value the ciphertext integer
     * @return the wrapped value
     */
    public static IntValue of(long value) {
        return new IntValue(BigInteger.valueOf(value));
    }

    /**
     * Wraps a {@link BigInteger} as an integer ciphertext.
     *
     * @param value the ciphertext integer
     * @return the wrapped value
     */
    public static IntValue of(BigInteger value) {
        return new IntValue(value);
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
