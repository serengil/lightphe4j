package io.github.serengil.lightphe.model;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * A ciphertext of the {@link CatalanoFiore} transform. It is either non-multiplied as {@code (a,
 * beta)}, or multiplied as {@code (alpha, pairs)}.
 *
 * <p>The Python operators {@code +}, {@code -} and {@code *} become {@link #add}, {@link #subtract}
 * and {@link #multiply}, each accepting another ciphertext or a plain integer.
 */
public final class CatalanoFioreCiphertext {

    private final Homomorphic cs;
    private final BigInteger a;
    private final Ciphertext beta;
    private final Ciphertext alpha;
    private final List<Ciphertext[]> pairs;

    private CatalanoFioreCiphertext(
            Homomorphic cs,
            BigInteger a,
            Ciphertext beta,
            Ciphertext alpha,
            List<Ciphertext[]> pairs) {
        this.cs = cs;
        this.a = a;
        this.beta = beta;
        this.alpha = alpha;
        this.pairs = List.copyOf(pairs);
    }

    static CatalanoFioreCiphertext nonMultiplied(Homomorphic cs, BigInteger a, Ciphertext beta) {
        return new CatalanoFioreCiphertext(cs, a, beta, null, List.of());
    }

    private static CatalanoFioreCiphertext multiplied(
            Homomorphic cs, Ciphertext alpha, List<Ciphertext[]> pairs) {
        return new CatalanoFioreCiphertext(cs, null, null, alpha, pairs);
    }

    /**
     * Reports whether this ciphertext is the result of a multiplication of ciphertexts.
     *
     * @return {@code true} for a multiplied ciphertext
     */
    public boolean isMultiplied() {
        return alpha != null;
    }

    /**
     * Returns the clear part {@code a = m - b} of a non-multiplied ciphertext.
     *
     * @return a, or {@code null} for a multiplied ciphertext
     */
    public BigInteger a() {
        return a;
    }

    /**
     * Returns {@code Enc(b)} of a non-multiplied ciphertext.
     *
     * @return beta, or {@code null} for a multiplied ciphertext
     */
    public Ciphertext beta() {
        return beta;
    }

    /**
     * Returns alpha of a multiplied ciphertext, which encrypts the product minus the sum of {@code
     * b1 b2} of its pairs.
     *
     * @return alpha, or {@code null} for a non-multiplied ciphertext
     */
    public Ciphertext alpha() {
        return alpha;
    }

    /**
     * Returns the {@code (Enc(b1), Enc(b2))} pairs of a multiplied ciphertext.
     *
     * @return the pairs; empty for a non-multiplied ciphertext
     */
    public List<Ciphertext[]> pairs() {
        return pairs;
    }

    private BigInteger modulo() {
        return cs.plaintextModulo();
    }

    private Ciphertext encrypt(BigInteger plaintext) {
        return Ciphertext.of(cs, cs.encrypt(plaintext));
    }

    /**
     * Performs homomorphic addition with another ciphertext.
     *
     * @param other some other ciphertext
     * @return the ciphertext of the sum
     * @throws IllegalArgumentException when the ciphertexts belong to different cryptosystems
     */
    public CatalanoFioreCiphertext add(CatalanoFioreCiphertext other) {
        checkSameSystem(other);

        if (!isMultiplied() && !other.isMultiplied()) {
            return nonMultiplied(cs, a.add(other.a).mod(modulo()), beta.add(other.beta));
        }

        CatalanoFioreCiphertext first = toMultiplied();
        CatalanoFioreCiphertext second = other.toMultiplied();
        List<Ciphertext[]> merged = new ArrayList<>(first.pairs);
        merged.addAll(second.pairs);
        return multiplied(cs, first.alpha.add(second.alpha), merged);
    }

    /**
     * Adds a plain constant.
     *
     * @param constant the constant
     * @return the ciphertext of the sum
     */
    public CatalanoFioreCiphertext add(BigInteger constant) {
        // adding a plain constant requires no homomorphic operation for a non-multiplied one
        if (!isMultiplied()) {
            return nonMultiplied(cs, a.add(constant).mod(modulo()), beta);
        }
        return multiplied(cs, alpha.add(encrypt(constant.mod(modulo()))), pairs);
    }

    /**
     * Adds a plain constant.
     *
     * @param constant the constant
     * @return the ciphertext of the sum
     */
    public CatalanoFioreCiphertext add(long constant) {
        return add(BigInteger.valueOf(constant));
    }

    /**
     * Negates the encrypted value.
     *
     * @return the ciphertext of the negation
     */
    public CatalanoFioreCiphertext negate() {
        return multiply(-1);
    }

    /**
     * Performs homomorphic subtraction of another ciphertext.
     *
     * @param other some other ciphertext
     * @return the ciphertext of the difference
     */
    public CatalanoFioreCiphertext subtract(CatalanoFioreCiphertext other) {
        return add(other.negate());
    }

    /**
     * Subtracts a plain constant.
     *
     * @param constant the constant
     * @return the ciphertext of the difference
     */
    public CatalanoFioreCiphertext subtract(long constant) {
        return add(BigInteger.valueOf(constant).negate());
    }

    /**
     * Multiplies with a plain constant.
     *
     * @param constant the constant
     * @return the ciphertext of the product
     */
    public CatalanoFioreCiphertext multiply(BigInteger constant) {
        BigInteger scalar = constant.mod(modulo());
        if (!isMultiplied()) {
            return nonMultiplied(cs, a.multiply(scalar).mod(modulo()), beta.multiply(scalar));
        }
        // scaling the first ciphertext of each pair scales the product b1 b2
        List<Ciphertext[]> scaled = new ArrayList<>(pairs.size());
        for (Ciphertext[] pair : pairs) {
            scaled.add(new Ciphertext[] {pair[0].multiply(scalar), pair[1]});
        }
        return multiplied(cs, alpha.multiply(scalar), scaled);
    }

    /**
     * Multiplies with a plain constant.
     *
     * @param constant the constant
     * @return the ciphertext of the product
     */
    public CatalanoFioreCiphertext multiply(long constant) {
        return multiply(BigInteger.valueOf(constant));
    }

    /**
     * Performs homomorphic multiplication with another ciphertext. Only non-multiplied ciphertexts
     * can be multiplied.
     *
     * @param other some other ciphertext
     * @return the multiplied ciphertext
     * @throws IllegalArgumentException when either ciphertext is already multiplied, or they belong
     *     to different cryptosystems
     */
    public CatalanoFioreCiphertext multiply(CatalanoFioreCiphertext other) {
        checkSameSystem(other);

        if (isMultiplied() || other.isMultiplied()) {
            throw new IllegalArgumentException(
                    "Catalano-Fiore transform supports only one multiplication. "
                            + "Multiplied ciphertexts cannot be multiplied with"
                            + " ciphertexts again.");
        }

        // Enc(a1 a2) + a1 Enc(b2) + a2 Enc(b1) encrypts m1 m2 - b1 b2
        Ciphertext product =
                encrypt(a.multiply(other.a).mod(modulo()))
                        .add(other.beta.multiply(a))
                        .add(beta.multiply(other.a));
        List<Ciphertext[]> productPairs = new ArrayList<>(1);
        productPairs.add(new Ciphertext[] {beta, other.beta});
        return multiplied(cs, product, productPairs);
    }

    /**
     * Represents a non-multiplied ciphertext {@code (a, Enc(b))} as a multiplied one with {@code
     * alpha = Enc(a) + Enc(b)} and no pairs.
     *
     * @return the multiplied representation
     */
    public CatalanoFioreCiphertext toMultiplied() {
        if (isMultiplied()) {
            return this;
        }
        return multiplied(cs, encrypt(a).add(beta), List.of());
    }

    private void checkSameSystem(CatalanoFioreCiphertext other) {
        if (!other.modulo().equals(modulo())) {
            throw new IllegalArgumentException("Ciphertexts belong to different cryptosystems");
        }
    }

    @Override
    public String toString() {
        if (isMultiplied()) {
            return "CatalanoFioreCiphertext(multiplied, " + pairs.size() + " pairs)";
        }
        return "CatalanoFioreCiphertext(non-multiplied)";
    }
}
