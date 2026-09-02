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
 */
public record KeySpec(
        List<String> publicKey, List<String> privateKey, Map<String, List<String>> nested) {

    /**
     * Creates a key specification, copying the supplied collections.
     *
     * @param publicKey required public key fields
     * @param privateKey required private key fields
     * @param nested required nested fields
     */
    public KeySpec {
        publicKey = List.copyOf(publicKey);
        privateKey = List.copyOf(privateKey);
        nested = Map.copyOf(nested);
    }

    /**
     * Creates a key specification without nested requirements.
     *
     * @param publicKey required public key fields
     * @param privateKey required private key fields
     * @return the specification
     */
    public static KeySpec of(List<String> publicKey, List<String> privateKey) {
        return new KeySpec(publicKey, privateKey, Map.of());
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
        return new KeySpec(publicKey, privateKey, nested);
    }
}
