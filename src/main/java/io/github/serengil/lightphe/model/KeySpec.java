package io.github.serengil.lightphe.model;

import java.util.List;
import java.util.Map;

/**
 * The key fields a cryptosystem requires.
 *
 * <p>Java counterpart of the {@code REQUIRED_KEYS} class attribute each Python cryptosystem
 * declares.
 *
 * @param publicKey required sub-fields of the {@code public_key} section
 * @param privateKey required sub-fields of the {@code private_key} section
 * @param nested maps a {@code public_key} sub-field that itself holds a dictionary to that
 *     dictionary's required sub-fields
 * @param alternativePrivateKey sub-fields accepted in the {@code private_key} section instead of
 *     the required ones, or an empty list when there is no alternative
 */
public record KeySpec(
        List<String> publicKey,
        List<String> privateKey,
        Map<String, List<String>> nested,
        List<String> alternativePrivateKey) {

    /**
     * Creates a key specification, copying the supplied collections.
     *
     * @param publicKey required public key fields
     * @param privateKey required private key fields
     * @param nested required nested fields
     * @param alternativePrivateKey private key fields accepted instead of the required ones
     */
    public KeySpec {
        publicKey = List.copyOf(publicKey);
        privateKey = List.copyOf(privateKey);
        nested = Map.copyOf(nested);
        alternativePrivateKey = List.copyOf(alternativePrivateKey);
    }

    /**
     * Creates a key specification without nested requirements.
     *
     * @param publicKey required public key fields
     * @param privateKey required private key fields
     * @return the specification
     */
    public static KeySpec of(List<String> publicKey, List<String> privateKey) {
        return new KeySpec(publicKey, privateKey, Map.of(), List.of());
    }

    /**
     * Creates a key specification with nested requirements.
     *
     * @param publicKey required public key fields
     * @param privateKey required private key fields
     * @param nested required nested fields, keyed by the owning public key field
     * @return the specification
     */
    public static KeySpec of(
            List<String> publicKey, List<String> privateKey, Map<String, List<String>> nested) {
        return new KeySpec(publicKey, privateKey, nested, List.of());
    }

    /**
     * Creates a key specification whose private key may alternatively carry another set of fields.
     *
     * @param publicKey required public key fields
     * @param privateKey required private key fields
     * @param alternativePrivateKey private key fields accepted instead of the required ones
     * @return the specification
     */
    public static KeySpec withAlternativePrivateKey(
            List<String> publicKey, List<String> privateKey, List<String> alternativePrivateKey) {
        return new KeySpec(publicKey, privateKey, Map.of(), alternativePrivateKey);
    }
}
