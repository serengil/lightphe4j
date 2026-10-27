package io.github.serengil.lightphe.model;

import java.util.Objects;

/**
 * Partial decryptions of an item of an encrypted tensor, the Java counterpart of the {@code
 * {"abs_dividend": ..., "divisor": ...}} dictionaries of the Python library.
 *
 * @param absDividend the partial decryption of the absolute dividend
 * @param divisor the partial decryption of the divisor
 */
public record FractionPartialDecryption(PartialDecryption absDividend, PartialDecryption divisor) {

    /** Creates the partial decryptions, rejecting {@code null} components. */
    public FractionPartialDecryption {
        Objects.requireNonNull(absDividend, "absDividend");
        Objects.requireNonNull(divisor, "divisor");
    }
}
