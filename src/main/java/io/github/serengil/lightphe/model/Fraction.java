package io.github.serengil.lightphe.model;

import io.github.serengil.lightphe.model.value.CipherValue;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.experimental.Accessors;

/**
 * One element of an encrypted tensor, stored as a signed fraction.
 *
 * <p>Real numbers are encrypted as an integer dividend over a power-of-ten divisor, both encrypted
 * under the same key, plus a sign kept in the clear. The absolute dividend is carried separately
 * because element-wise multiplication has to work on magnitudes: partially homomorphic schemes
 * cannot compare a ciphertext against zero.
 *
 * <p>Java counterpart of {@code lightphe.models.Tensor.Fraction}.
 */
@Getter
@Builder
@AllArgsConstructor
@Accessors(fluent = true)
public final class Fraction {

    /** The signed, scaled numerator. */
    private final CipherValue dividend;

    /** The magnitude of the numerator, used by element-wise multiplication. */
    private final CipherValue absDividend;

    /** The scaling factor, a power of ten. */
    private final CipherValue divisor;

    /** The sign of the value, either {@code 1} or {@code -1}. */
    @Builder.Default private final int sign = 1;

    @Override
    public String toString() {
        return "Fraction(" + (sign == -1 ? "-" : "+") + absDividend + " / " + divisor + ")";
    }
}
