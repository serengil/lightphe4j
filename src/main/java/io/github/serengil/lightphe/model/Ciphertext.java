package io.github.serengil.lightphe.model;

import io.github.serengil.lightphe.commons.PheUtils;
import io.github.serengil.lightphe.cryptosystems.CryptosystemFactory;
import io.github.serengil.lightphe.model.value.CipherValue;
import java.math.BigInteger;
import java.util.Objects;

/**
 * An encrypted message together with the public key material needed to keep computing on it.
 *
 * <p>A ciphertext carries its own cryptosystem, built from the public key alone, so homomorphic
 * operations can be evaluated by a party that never sees the private key. Java counterpart of
 * {@code lightphe.models.Ciphertext.Ciphertext}, where the Python operators {@code +}, {@code *},
 * {@code ^} and {@code &} become {@link #add}, {@link #multiply}, {@link #xor} and {@link #and}.
 *
 * <h2>Example</h2>
 *
 * <pre>{@code
 * Ciphertext c1 = cs.encrypt(17);
 * Ciphertext c2 = cs.encrypt(21);
 * BigInteger sum = cs.decrypt(c1.add(c2));   // 38
 * }</pre>
 */
public final class Ciphertext {

    private final Algorithm algorithmName;
    private final Keys keys;
    private final CipherValue value;
    private final Homomorphic cs;

    /**
     * Builds a ciphertext, constructing the cryptosystem that backs it from the given keys.
     *
     * @param algorithmName the algorithm the ciphertext was produced with
     * @param keys the key material; a public key is enough to keep computing
     * @param value the encrypted payload
     * @param form elliptic curve form, only used by elliptic curve ElGamal
     * @param curve elliptic curve name, only used by elliptic curve ElGamal
     */
    public Ciphertext(
            Algorithm algorithmName, Keys keys, CipherValue value, String form, String curve) {
        this.algorithmName = Objects.requireNonNull(algorithmName, "algorithmName");
        this.keys = Objects.requireNonNull(keys, "keys");
        this.value = Objects.requireNonNull(value, "value");
        this.cs =
                CryptosystemFactory.build(
                        algorithmName, CryptosystemFactory.Options.ofKeys(keys, form, curve));
    }

    /**
     * Builds a ciphertext, constructing the cryptosystem that backs it from the given keys.
     *
     * @param algorithmName the algorithm the ciphertext was produced with
     * @param keys the key material
     * @param value the encrypted payload
     */
    public Ciphertext(Algorithm algorithmName, Keys keys, CipherValue value) {
        this(algorithmName, keys, value, null, null);
    }

    private Ciphertext(Homomorphic cs, CipherValue value) {
        this.algorithmName = cs.algorithm();
        this.keys = cs.keys();
        this.value = Objects.requireNonNull(value, "value");
        this.cs = cs;
    }

    /**
     * Wraps a payload in a ciphertext that reuses an already built cryptosystem.
     *
     * <p>Equivalent to the public constructor but without rebuilding the cryptosystem, which
     * matters when a whole tensor is being evaluated.
     *
     * @param cs the cryptosystem the payload belongs to
     * @param value the encrypted payload
     * @return the ciphertext
     */
    public static Ciphertext of(Homomorphic cs, CipherValue value) {
        return new Ciphertext(cs, value);
    }

    /**
     * Returns the algorithm this ciphertext was produced with.
     *
     * @return the algorithm
     */
    public Algorithm algorithmName() {
        return algorithmName;
    }

    /**
     * Returns the key material carried alongside the payload.
     *
     * @return the keys
     */
    public Keys keys() {
        return keys;
    }

    /**
     * Returns the encrypted payload.
     *
     * @return the ciphertext value
     */
    public CipherValue value() {
        return value;
    }

    /**
     * Returns the cryptosystem backing this ciphertext.
     *
     * @return the cryptosystem
     */
    public Homomorphic cs() {
        return cs;
    }

    /**
     * Performs homomorphic addition.
     *
     * @param other some other ciphertext
     * @return the homomorphic addition of the two ciphertexts
     * @throws IllegalArgumentException when no public key is available, or when the scheme is not
     *     additively homomorphic
     */
    public Ciphertext add(Ciphertext other) {
        requirePublicKey("homomorphic addition");
        return new Ciphertext(cs, cs.add(value, other.value));
    }

    /**
     * Performs homomorphic multiplication.
     *
     * @param other some other ciphertext
     * @return the homomorphic multiplication of the two ciphertexts
     * @throws IllegalArgumentException when no public key is available, or when the scheme is not
     *     multiplicatively homomorphic
     */
    public Ciphertext multiply(Ciphertext other) {
        requirePublicKey("homomorphic multiplication");
        return new Ciphertext(cs, cs.multiply(value, other.value));
    }

    /**
     * Multiplies this ciphertext by a known plain constant.
     *
     * @param constant a known plain constant
     * @return the scalar multiplication of the ciphertext
     * @throws IllegalArgumentException when the scheme does not support scalar multiplication
     */
    public Ciphertext multiply(BigInteger constant) {
        requirePublicKey("homomorphic multiplication");
        return new Ciphertext(cs, cs.multiplyByConstant(value, constant));
    }

    /**
     * Multiplies this ciphertext by a known plain constant.
     *
     * @param constant a known plain constant
     * @return the scalar multiplication of the ciphertext
     */
    public Ciphertext multiply(long constant) {
        return multiply(BigInteger.valueOf(constant));
    }

    /**
     * Multiplies this ciphertext by a known real constant, which is first normalised into the
     * message space.
     *
     * @param constant a known plain constant
     * @return the scalar multiplication of the ciphertext
     */
    public Ciphertext multiply(double constant) {
        requirePublicKey("homomorphic multiplication");
        BigInteger normalized = PheUtils.normalizeInput(constant, cs.plaintextModulo());
        return new Ciphertext(cs, cs.multiplyByConstant(value, normalized));
    }

    /**
     * Performs homomorphic exclusive or.
     *
     * @param other some other ciphertext
     * @return the homomorphic exclusive or of the two ciphertexts
     * @throws IllegalArgumentException when the scheme is not homomorphic with respect to xor
     */
    public Ciphertext xor(Ciphertext other) {
        requirePublicKey("homomorphic xor");
        return new Ciphertext(cs, cs.xor(value, other.value));
    }

    /**
     * Performs homomorphic bitwise and.
     *
     * @param other some other ciphertext
     * @return the homomorphic bitwise and of the two ciphertexts
     * @throws IllegalArgumentException when the scheme is not homomorphic with respect to and
     */
    public Ciphertext and(Ciphertext other) {
        requirePublicKey("homomorphic and");
        return new Ciphertext(cs, cs.homomorphicAnd(value, other.value));
    }

    private void requirePublicKey(String operation) {
        if (cs.keys().publicKey() == null || cs.keys().publicKey().isEmpty()) {
            throw new IllegalArgumentException("You must have public key to perform " + operation);
        }
    }

    @Override
    public String toString() {
        return "Ciphertext(" + value + ")";
    }
}
