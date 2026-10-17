package io.github.serengil.lightphe.model;

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The private-public key pair of a cryptosystem.
 *
 * <p>Java counterpart of the {@code keys} dictionary of the Python library: a {@code public_key}
 * section, an optional {@code private_key} section, and - for elliptic curve ElGamal - the curve
 * form and name the keys were generated for.
 *
 * <p>A cryptosystem that carries only a public key can encrypt and evaluate homomorphic operations
 * but cannot decrypt.
 */
public final class Keys {

    /** Name of the public key section, as it appears in exported JSON. */
    public static final String PUBLIC_KEY = "public_key";

    /** Name of the private key section, as it appears in exported JSON. */
    public static final String PRIVATE_KEY = "private_key";

    /** Name of the optional curve form entry. */
    public static final String FORM = "form";

    /** Name of the optional curve name entry. */
    public static final String CURVE = "curve";

    private Map<String, KeyValue> publicKey;
    private Map<String, KeyValue> privateKey;
    private String form;
    private String curve;

    private Keys(
            Map<String, KeyValue> publicKey,
            Map<String, KeyValue> privateKey,
            String form,
            String curve) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.form = form;
        this.curve = curve;
    }

    /**
     * Creates an empty key pair, ready to be filled in by a key generator.
     *
     * @return an empty key pair
     */
    public static Keys empty() {
        return new Keys(new LinkedHashMap<>(), new LinkedHashMap<>(), null, null);
    }

    /**
     * Creates a key pair from its two sections.
     *
     * <p>A {@code null} section means the section is absent, which the key validator reports
     * differently from a section that is present but incomplete.
     *
     * @param publicKey the public key section, or {@code null} when there is none
     * @param privateKey the private key section, or {@code null} for an encryption-only key pair
     * @return the key pair
     */
    public static Keys of(Map<String, KeyValue> publicKey, Map<String, KeyValue> privateKey) {
        return new Keys(
                publicKey == null ? null : new LinkedHashMap<>(publicKey),
                privateKey == null ? null : new LinkedHashMap<>(privateKey),
                null,
                null);
    }

    /**
     * Returns the public key section.
     *
     * @return a live view of the public key entries, or {@code null} when the section is absent
     */
    public Map<String, KeyValue> publicKey() {
        return publicKey;
    }

    /**
     * Returns the private key section.
     *
     * @return a live view of the private key entries, or {@code null} when absent
     */
    public Map<String, KeyValue> privateKey() {
        return privateKey;
    }

    /**
     * Reports whether a private key is present, and therefore whether decryption is possible.
     *
     * @return {@code true} when the private key section exists and is non-empty
     */
    public boolean hasPrivateKey() {
        return privateKey != null && !privateKey.isEmpty();
    }

    /** Drops the public key section, marking it absent rather than empty. */
    public void removePublicKey() {
        publicKey = null;
    }

    /**
     * Drops the private key section.
     *
     * @return the removed private key section, or {@code null} when there was none
     */
    public Map<String, KeyValue> removePrivateKey() {
        Map<String, KeyValue> removed = privateKey;
        privateKey = null;
        return removed;
    }

    /**
     * Restores a previously removed private key section.
     *
     * @param restored the section to put back
     */
    public void restorePrivateKey(Map<String, KeyValue> restored) {
        this.privateKey = restored;
    }

    /**
     * Returns the elliptic curve form the keys belong to, when one was recorded.
     *
     * @return the form name
     */
    public Optional<String> form() {
        return Optional.ofNullable(form);
    }

    /**
     * Returns the elliptic curve name the keys belong to, when one was recorded.
     *
     * @return the curve name
     */
    public Optional<String> curve() {
        return Optional.ofNullable(curve);
    }

    /**
     * Records the elliptic curve form the keys belong to.
     *
     * @param form the form name
     */
    public void setForm(String form) {
        this.form = form;
    }

    /**
     * Records the elliptic curve name the keys belong to.
     *
     * @param curve the curve name
     */
    public void setCurve(String curve) {
        this.curve = curve;
    }

    /**
     * Returns a public key field as an integer.
     *
     * @param field the field name
     * @return the integer
     * @throws IllegalArgumentException when the field is absent or is not an integer
     */
    public BigInteger publicNumber(String field) {
        if (publicKey == null) {
            throw new IllegalArgumentException("public_key is not available");
        }
        return number(publicKey, PUBLIC_KEY, field);
    }

    /**
     * Returns a private key field as an integer.
     *
     * @param field the field name
     * @return the integer
     * @throws IllegalArgumentException when the field is absent or is not an integer
     */
    public BigInteger privateNumber(String field) {
        if (privateKey == null) {
            throw new IllegalArgumentException("private_key is not available");
        }
        return number(privateKey, PRIVATE_KEY, field);
    }

    /**
     * Returns a public key field as a list of integers.
     *
     * @param field the field name
     * @return the integers
     * @throws IllegalArgumentException when the field is absent or is not a list of integers
     */
    public List<BigInteger> publicNumbers(String field) {
        return numbers(publicKey, PUBLIC_KEY, field);
    }

    /**
     * Returns a private key field as a list of integers.
     *
     * @param field the field name
     * @return the integers
     * @throws IllegalArgumentException when the field is absent or is not a list of integers
     */
    public List<BigInteger> privateNumbers(String field) {
        return numbers(privateKey, PRIVATE_KEY, field);
    }

    /**
     * Returns a public key field as a list of integer lists.
     *
     * @param field the field name
     * @return the rows
     * @throws IllegalArgumentException when the field is absent or is not a matrix
     */
    public List<List<BigInteger>> publicMatrix(String field) {
        return matrix(publicKey, PUBLIC_KEY, field);
    }

    /**
     * Returns a private key field as a list of integer lists.
     *
     * @param field the field name
     * @return the rows
     * @throws IllegalArgumentException when the field is absent or is not a matrix
     */
    public List<List<BigInteger>> privateMatrix(String field) {
        return matrix(privateKey, PRIVATE_KEY, field);
    }

    /**
     * Returns a public key field as a curve point.
     *
     * @param field the field name
     * @return the point
     * @throws IllegalArgumentException when the field is absent or is not a point
     */
    public KeyValue.Point publicPoint(String field) {
        KeyValue value = publicKey == null ? null : publicKey.get(field);
        if (!(value instanceof KeyValue.Point point)) {
            throw new IllegalArgumentException(PUBLIC_KEY + "." + field + " is not a curve point");
        }
        return point;
    }

    /**
     * Returns a public key field as a nested dictionary.
     *
     * @param field the field name
     * @return the nested entries
     * @throws IllegalArgumentException when the field is absent or is not nested
     */
    public KeyValue.Nested publicNested(String field) {
        KeyValue value = publicKey == null ? null : publicKey.get(field);
        if (!(value instanceof KeyValue.Nested nested)) {
            throw new IllegalArgumentException(
                    PUBLIC_KEY + "." + field + " is not a nested dictionary");
        }
        return nested;
    }

    private static List<BigInteger> numbers(
            Map<String, KeyValue> section, String name, String field) {
        KeyValue value = section == null ? null : section.get(field);
        if (value instanceof KeyValue.Numbers numbers) {
            return numbers.values();
        }
        // a two-element list cannot be told apart from a curve point in exported JSON
        if (value instanceof KeyValue.Point point) {
            return List.of(point.x(), point.y());
        }
        throw new IllegalArgumentException(name + "." + field + " is not an integer list");
    }

    private static List<List<BigInteger>> matrix(
            Map<String, KeyValue> section, String name, String field) {
        KeyValue value = section == null ? null : section.get(field);
        if (!(value instanceof KeyValue.Matrix matrix)) {
            throw new IllegalArgumentException(name + "." + field + " is not a matrix");
        }
        return matrix.rows();
    }

    private static BigInteger number(Map<String, KeyValue> section, String name, String field) {
        KeyValue value = section.get(field);
        if (!(value instanceof KeyValue.Num num)) {
            throw new IllegalArgumentException(name + "." + field + " is not an integer");
        }
        return num.value();
    }

    /**
     * Returns a deep copy of this key pair, so that callers may mutate one without disturbing the
     * other.
     *
     * @return the copy
     */
    public Keys deepCopy() {
        Map<String, KeyValue> copiedPublic = publicKey == null ? null : copySection(publicKey);
        Map<String, KeyValue> copiedPrivate = privateKey == null ? null : copySection(privateKey);
        return new Keys(copiedPublic, copiedPrivate, form, curve);
    }

    /**
     * Returns a copy of this key pair with the private key section stripped, suitable for handing
     * to a party that should be able to encrypt and evaluate but not decrypt.
     *
     * @return the public-only copy
     */
    public Keys publicOnly() {
        Keys copy = deepCopy();
        copy.removePrivateKey();
        return copy;
    }

    private static Map<String, KeyValue> copySection(Map<String, KeyValue> section) {
        Map<String, KeyValue> copied = new LinkedHashMap<>();
        section.forEach(
                (key, value) ->
                        copied.put(
                                key,
                                value instanceof KeyValue.Nested nested ? nested.copy() : value));
        return copied;
    }

    @Override
    public String toString() {
        return KeysCodec.toJson(this);
    }
}
