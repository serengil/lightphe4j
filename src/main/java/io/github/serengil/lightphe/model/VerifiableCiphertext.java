package io.github.serengil.lightphe.model;

import java.math.BigInteger;
import java.util.Objects;

/**
 * A Camenisch-Shoup ciphertext of a discrete logarithm together with the proof that it really
 * contains it.
 *
 * <p>Java counterpart of the {@code {"ciphertext": (u, e, v), "commitment": l, "proof": {...}}}
 * dictionary of the Python library.
 *
 * @param u first component of the ciphertext
 * @param e second component of the ciphertext
 * @param v validity tag bound to the label
 * @param commitment commitment to the secret in the auxiliary group
 * @param proof the proof
 */
public record VerifiableCiphertext(
        BigInteger u, BigInteger e, BigInteger v, BigInteger commitment, Proof proof) {

    /** Creates a verifiable ciphertext, rejecting {@code null} components. */
    public VerifiableCiphertext {
        Objects.requireNonNull(u, "u");
        Objects.requireNonNull(e, "e");
        Objects.requireNonNull(v, "v");
        Objects.requireNonNull(commitment, "commitment");
        Objects.requireNonNull(proof, "proof");
    }

    /**
     * The Fiat-Shamir proof of a verifiable ciphertext.
     *
     * @param challenge the challenge
     * @param r response for the random key
     * @param s response for the randomness of the commitment
     * @param m response for the secret
     */
    public record Proof(BigInteger challenge, BigInteger r, BigInteger s, BigInteger m) {

        /** Creates a proof, rejecting {@code null} components. */
        public Proof {
            Objects.requireNonNull(challenge, "challenge");
            Objects.requireNonNull(r, "r");
            Objects.requireNonNull(s, "s");
            Objects.requireNonNull(m, "m");
        }
    }
}
