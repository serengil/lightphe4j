package io.github.serengil.lightphe.model;

/**
 * A value together with the proof about it, the Java counterpart of the {@code (value, proof)}
 * tuples of the Python library. For instance, a ciphertext with the proof that it encrypts one of
 * the allowed values, or a plaintext with the proof that it is the correct decryption.
 *
 * @param value the proven value, e.g. a ciphertext or a plaintext
 * @param proof the proof, to be shared with the verifier
 * @param <T> type of the proven value
 */
public record Proven<T>(T value, Proof proof) {}
