package io.github.serengil.lightphe.model;

import io.github.serengil.lightphe.model.value.CipherValue;
import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * A non-interactive zero-knowledge proof, or the evidence of a correct decryption.
 *
 * <p>Java counterpart of the proof dictionaries of the Python library. Each record names the
 * dictionary keys it mirrors, so a proof can be serialised for a network call in the same shape.
 * Proofs are made non-interactive with the Fiat-Shamir heuristic, see {@link
 * io.github.serengil.lightphe.commons.Zkp}.
 */
public sealed interface Proof {

    /**
     * A Chaum-Pedersen or Schnorr proof: {@code {"challenge": e, "response": z}}. Used by proofs of
     * correct decryption and partial decryption, and by proofs of knowledge of ElGamal variants.
     *
     * @param challenge the Fiat-Shamir challenge e
     * @param response the response z
     */
    record ChallengeResponse(BigInteger challenge, BigInteger response) implements Proof {

        /** Creates the proof, rejecting {@code null} components. */
        public ChallengeResponse {
            Objects.requireNonNull(challenge, "challenge");
            Objects.requireNonNull(response, "response");
        }
    }

    /**
     * A disjunctive proof that a ciphertext encrypts one of given values: {@code {"challenges":
     * [...], "responses": [...]}}. Proofs of all values but the true one are simulated.
     *
     * @param challenges the challenge of each value
     * @param responses the response of each value
     */
    record Disjunctive(List<BigInteger> challenges, List<BigInteger> responses) implements Proof {

        /** Creates the proof, copying the lists defensively. */
        public Disjunctive {
            challenges = List.copyOf(challenges);
            responses = List.copyOf(responses);
        }
    }

    /**
     * Proof of correct decryption of Paillier and Damgard-Jurik: {@code {"randomness": r}}. A
     * ciphertext is one to one with its plaintext and randomness, so revealing r proves m.
     *
     * @param randomness the randomness r of the ciphertext in {@code Z*_n}
     */
    record Randomness(BigInteger randomness) implements Proof {

        /** Creates the proof, rejecting a {@code null} randomness. */
        public Randomness {
            Objects.requireNonNull(randomness, "randomness");
        }
    }

    /**
     * Proof of knowledge of the plaintext and randomness of a Paillier or Damgard-Jurik ciphertext:
     * {@code {"challenge": e, "plaintext_response": z_m, "randomness_response": z_r}}.
     *
     * @param challenge the Fiat-Shamir challenge e
     * @param plaintextResponse the response z_m of the plaintext
     * @param randomnessResponse the response z_r of the randomness
     */
    record PaillierKnowledge(
            BigInteger challenge, BigInteger plaintextResponse, BigInteger randomnessResponse)
            implements Proof {

        /** Creates the proof, rejecting {@code null} components. */
        public PaillierKnowledge {
            Objects.requireNonNull(challenge, "challenge");
            Objects.requireNonNull(plaintextResponse, "plaintextResponse");
            Objects.requireNonNull(randomnessResponse, "randomnessResponse");
        }
    }

    /**
     * A range proof: {@code {"ciphertexts": [...], "proofs": [...]}}. The first ciphertext encrypts
     * the lower bound and the others encrypt bits, each with a proof of membership. The ciphertext
     * of the plaintext is restored from them homomorphically.
     *
     * @param ciphertexts the encryption of the lower bound and encryptions of bits
     * @param proofs the proof of membership of each ciphertext
     */
    record Range(List<CipherValue> ciphertexts, List<Proof> proofs) implements Proof {

        /** Creates the proof, copying the lists defensively. */
        public Range {
            ciphertexts = List.copyOf(ciphertexts);
            proofs = List.copyOf(proofs);
        }
    }

    /**
     * A one-hot proof: {@code {"slots": [...], "sum": ...}}. Each slot is proven to be 0 or 1, and
     * the homomorphic sum of slots is proven to be 1.
     *
     * @param slots the proof of membership of each slot
     * @param sum the proof that slots sum to 1
     */
    record OneHot(List<Proof> slots, Proof sum) implements Proof {

        /** Creates the proof, copying the slot proofs defensively. */
        public OneHot {
            slots = List.copyOf(slots);
            Objects.requireNonNull(sum, "sum");
        }
    }
}
