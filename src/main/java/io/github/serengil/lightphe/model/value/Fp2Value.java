package io.github.serengil.lightphe.model.value;

import io.github.serengil.lightphe.ecc.Fp2;
import java.math.BigInteger;
import java.util.Objects;

/**
 * An element {@code a + b*i} of the quadratic extension field {@code F_{p^2}}.
 *
 * <p>{@code F_{p^2}} is the target group of the Boneh-Goh-Nissim pairing, so a BGN ciphertext turns
 * into an {@code Fp2Value} after its single permitted homomorphic multiplication.
 *
 * @param a the real coordinate
 * @param b the imaginary coordinate
 */
public record Fp2Value(BigInteger a, BigInteger b) implements CipherValue {

    /**
     * Creates an extension field ciphertext.
     *
     * @param a the real coordinate; must not be {@code null}
     * @param b the imaginary coordinate; must not be {@code null}
     */
    public Fp2Value {
        Objects.requireNonNull(a, "a");
        Objects.requireNonNull(b, "b");
    }

    /**
     * Captures an {@link Fp2} element as a ciphertext value.
     *
     * @param element the field element
     * @return the ciphertext value
     */
    public static Fp2Value from(Fp2 element) {
        return new Fp2Value(element.a(), element.b());
    }

    /**
     * Converts this value back into an {@link Fp2} element.
     *
     * @return the field element
     */
    public Fp2 toFp2() {
        return Fp2.of(a, b);
    }

    @Override
    public String toString() {
        return "(" + a + ", " + b + ")";
    }
}
