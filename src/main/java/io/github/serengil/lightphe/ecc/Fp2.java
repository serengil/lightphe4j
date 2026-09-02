package io.github.serengil.lightphe.ecc;

import java.math.BigInteger;
import java.util.Objects;

/**
 * An element {@code a + b*i} of the quadratic extension field {@code F_{p^2}}, where {@code i^2 =
 * -1}.
 *
 * <p>The representation is only valid for {@code p = 3 (mod 4)}, which is exactly the case the
 * supersingular curves used by Boneh-Goh-Nissim satisfy. {@code F_{p^2}} is the target group {@code
 * G_T} of the modified Tate pairing, so a BGN ciphertext becomes an {@code Fp2} after its single
 * permitted homomorphic multiplication.
 *
 * <p>Instances are immutable; every operation allocates its result.
 */
public final class Fp2 {

    /** The real coordinate. */
    private final BigInteger a;

    /** The imaginary coordinate. */
    private final BigInteger b;

    private Fp2(BigInteger a, BigInteger b) {
        this.a = a;
        this.b = b;
    }

    /**
     * Builds the element {@code a + b*i}.
     *
     * @param a real coordinate
     * @param b imaginary coordinate
     * @return the field element
     */
    public static Fp2 of(BigInteger a, BigInteger b) {
        return new Fp2(Objects.requireNonNull(a, "a"), Objects.requireNonNull(b, "b"));
    }

    /**
     * Embeds an element of {@code F_p} into {@code F_{p^2}}.
     *
     * @param a the base field element
     * @return {@code a + 0*i}
     */
    public static Fp2 fromBase(BigInteger a) {
        return new Fp2(a, BigInteger.ZERO);
    }

    /**
     * Returns the multiplicative identity {@code 1 + 0*i}.
     *
     * @return one
     */
    public static Fp2 one() {
        return new Fp2(BigInteger.ONE, BigInteger.ZERO);
    }

    /**
     * Returns the additive identity {@code 0 + 0*i}.
     *
     * @return zero
     */
    public static Fp2 zero() {
        return new Fp2(BigInteger.ZERO, BigInteger.ZERO);
    }

    /**
     * Returns the real coordinate.
     *
     * @return {@code a} in {@code a + b*i}
     */
    public BigInteger a() {
        return a;
    }

    /**
     * Returns the imaginary coordinate.
     *
     * @return {@code b} in {@code a + b*i}
     */
    public BigInteger b() {
        return b;
    }

    /**
     * Reports whether this is the additive identity.
     *
     * @return {@code true} when both coordinates are zero
     */
    public boolean isZero() {
        return a.signum() == 0 && b.signum() == 0;
    }

    /**
     * Reports whether this is the multiplicative identity.
     *
     * @return {@code true} when the element is {@code 1 + 0*i}
     */
    public boolean isOne() {
        return a.equals(BigInteger.ONE) && b.signum() == 0;
    }

    /**
     * Adds two {@code F_{p^2}} elements.
     *
     * @param other the addend
     * @param p the field modulus
     * @return {@code this + other mod p}
     */
    public Fp2 add(Fp2 other, BigInteger p) {
        return new Fp2(a.add(other.a).mod(p), b.add(other.b).mod(p));
    }

    /**
     * Subtracts two {@code F_{p^2}} elements.
     *
     * @param other the subtrahend
     * @param p the field modulus
     * @return {@code this - other mod p}
     */
    public Fp2 subtract(Fp2 other, BigInteger p) {
        return new Fp2(a.subtract(other.a).mod(p), b.subtract(other.b).mod(p));
    }

    /**
     * Multiplies two {@code F_{p^2}} elements: {@code (a+bi)(c+di) = (ac-bd) + (ad+bc)i}.
     *
     * @param other the multiplier
     * @param p the field modulus
     * @return {@code this * other mod p}
     */
    public Fp2 multiply(Fp2 other, BigInteger p) {
        BigInteger real = a.multiply(other.a).subtract(b.multiply(other.b)).mod(p);
        BigInteger imaginary = a.multiply(other.b).add(b.multiply(other.a)).mod(p);
        return new Fp2(real, imaginary);
    }

    /**
     * Inverts this element: {@code (a+bi)^-1 = (a-bi) / (a^2+b^2)}.
     *
     * @param p the field modulus
     * @return the multiplicative inverse
     * @throws ArithmeticException when this element is zero and therefore not invertible
     */
    public Fp2 inverse(BigInteger p) {
        BigInteger norm = a.multiply(a).add(b.multiply(b)).mod(p);
        if (norm.signum() == 0) {
            throw new ArithmeticException("Cannot invert zero in F_{p^2}");
        }
        BigInteger normInverse = norm.modInverse(p);
        return new Fp2(a.multiply(normInverse).mod(p), b.negate().multiply(normInverse).mod(p));
    }

    /**
     * Raises this element to the power {@code n} by square-and-multiply. Negative exponents invert
     * the base first.
     *
     * @param n the exponent
     * @param p the field modulus
     * @return {@code this^n mod p}
     */
    public Fp2 pow(BigInteger n, BigInteger p) {
        if (n.signum() == 0) {
            return one();
        }
        Fp2 base = this;
        BigInteger exponent = n;
        if (exponent.signum() < 0) {
            base = inverse(p);
            exponent = exponent.negate();
        }

        Fp2 result = one();
        for (int i = 0; i < exponent.bitLength(); i++) {
            if (exponent.testBit(i)) {
                result = result.multiply(base, p);
            }
            base = base.multiply(base, p);
        }
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Fp2 other)) {
            return false;
        }
        return a.equals(other.a) && b.equals(other.b);
    }

    @Override
    public int hashCode() {
        return Objects.hash(a, b);
    }

    @Override
    public String toString() {
        return "(" + a + " + " + b + "*i)";
    }
}
