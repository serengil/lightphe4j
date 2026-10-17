package io.github.serengil.lightphe.commons;

import io.github.serengil.lightphe.cryptosystems.CryptosystemFactory;
import io.github.serengil.lightphe.model.Algorithm;
import io.github.serengil.lightphe.model.KeySpec;
import io.github.serengil.lightphe.model.KeyValue;
import io.github.serengil.lightphe.model.Keys;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Validates user-supplied key material against the requirements of a cryptosystem.
 *
 * <p>Java counterpart of {@code lightphe.commons.key_validator}.
 */
public final class KeyValidator {

    private KeyValidator() {
        throw new AssertionError("no instances");
    }

    /**
     * Validates that user-supplied keys carry the required sub-fields for the given cryptosystem.
     *
     * <p>{@code public_key} is always required, because every cryptosystem needs it for encryption;
     * {@code private_key} is optional, being absent in encryption-only setups. Whichever is present
     * must contain all its required sub-fields.
     *
     * <p>The required-field specification is read from the cryptosystem's {@link
     * io.github.serengil.lightphe.model.Homomorphic#requiredKeys()}, which carries the public and
     * private field lists plus an optional nested entry for dictionary-valued {@code public_key}
     * sub-fields. An optional alternative private key lists another set of fields that is accepted
     * instead of the required {@code private_key} fields.
     *
     * @param algorithm the algorithm the keys are meant for
     * @param keys the user-supplied key pair
     * @throws IllegalArgumentException when required fields are missing or the structure is wrong
     */
    public static void validateKeys(Algorithm algorithm, Keys keys) {
        KeySpec spec = CryptosystemFactory.requiredKeys(algorithm);
        if (spec == null) {
            return;
        }

        if (keys == null) {
            throw new IllegalArgumentException(algorithm + " keys must be a dict, got null");
        }

        if (keys.publicKey() == null) {
            throw new IllegalArgumentException(algorithm + " keys must contain 'public_key'");
        }

        requireFields(algorithm, Keys.PUBLIC_KEY, keys.publicKey(), spec.publicKey());
        if (keys.privateKey() != null) {
            requirePrivateFields(algorithm, keys.privateKey(), spec);
        }

        for (Map.Entry<String, List<String>> entry : spec.nested().entrySet()) {
            String parent = entry.getKey();
            KeyValue value = keys.publicKey().get(parent);
            if (value == null) {
                continue;
            }
            if (!(value instanceof KeyValue.Nested nested)) {
                throw new IllegalArgumentException(
                        algorithm + " 'public_key." + parent + "' must be a dict");
            }
            List<String> missing = missingFields(nested.entries().keySet(), entry.getValue());
            if (!missing.isEmpty()) {
                throw new IllegalArgumentException(
                        algorithm
                                + " 'public_key."
                                + parent
                                + "' is missing required fields: "
                                + missing);
            }
        }
    }

    private static void requireFields(
            Algorithm algorithm,
            String section,
            Map<String, KeyValue> present,
            List<String> required) {
        List<String> missing = missingFields(present.keySet(), required);
        if (!missing.isEmpty()) {
            throw new IllegalArgumentException(
                    algorithm + " '" + section + "' is missing required fields: " + missing);
        }
    }

    private static void requirePrivateFields(
            Algorithm algorithm, Map<String, KeyValue> present, KeySpec spec) {
        List<String> missing = missingFields(present.keySet(), spec.privateKey());
        List<String> alternative = spec.alternativePrivateKey();
        if (!missing.isEmpty() && !alternative.isEmpty()) {
            if (missingFields(present.keySet(), alternative).isEmpty()) {
                return;
            }
            throw new IllegalArgumentException(
                    algorithm
                            + " '"
                            + Keys.PRIVATE_KEY
                            + "' is missing required fields: "
                            + missing
                            + " (or alternatively "
                            + alternative
                            + ")");
        }
        requireFields(algorithm, Keys.PRIVATE_KEY, present, spec.privateKey());
    }

    private static List<String> missingFields(
            java.util.Set<String> present, List<String> required) {
        List<String> missing = new ArrayList<>();
        for (String field : required) {
            if (!present.contains(field)) {
                missing.add(field);
            }
        }
        return missing;
    }
}
