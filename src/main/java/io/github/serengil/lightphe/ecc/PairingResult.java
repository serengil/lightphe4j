package io.github.serengil.lightphe.ecc;

import java.math.BigInteger;

/**
 * The outcome of a pairing computation.
 *
 * <p>Supersingular curves with embedding degree two land in the quadratic extension {@code F_{p^2}}
 * and report {@link #extended()}; every other curve returns a base field element. This mirrors the
 * Python API, where {@code weil_pairing} returns either an {@code int} or a {@code (a, b)} tuple.
 */
public final class PairingResult {

    private final BigInteger base;
    private final Fp2 value;

    private PairingResult(BigInteger base, Fp2 value) {
        this.base = base;
        this.value = value;
    }

    /**
     * Wraps an {@code r}-th root of unity in the base field {@code F_p}.
     *
     * @param base the field element
     * @return the pairing result
     */
    public static PairingResult ofBase(BigInteger base) {
        return new PairingResult(base, null);
    }

    /**
     * Wraps an {@code r}-th root of unity in the quadratic extension {@code F_{p^2}}.
     *
     * @param value the extension field element
     * @return the pairing result
     */
    public static PairingResult ofExtended(Fp2 value) {
        return new PairingResult(null, value);
    }

    /**
     * Reports whether the result lives in {@code F_{p^2}} rather than in {@code F_p}.
     *
     * @return {@code true} for an extension field element
     */
    public boolean extended() {
        return value != null;
    }

    /**
     * Returns the base field element.
     *
     * @return the element, or {@code null} when the result is extended
     */
    public BigInteger base() {
        return base;
    }

    /**
     * Returns the extension field element.
     *
     * @return the element, or {@code null} when the result lives in the base field
     */
    public Fp2 value() {
        return value;
    }

    @Override
    public String toString() {
        return extended() ? value.toString() : String.valueOf(base);
    }
}
