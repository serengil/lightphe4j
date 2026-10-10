package io.github.serengil.lightphe.model;

import io.github.serengil.lightphe.model.value.CipherValue;
import java.math.BigInteger;
import java.util.List;

/**
 * The contract every cryptosystem in this library fulfils.
 *
 * <p>Java counterpart of the abstract {@code Homomorphic} class of the Python library. The optional
 * operations - {@link #add}, {@link #multiply}, {@link #multiplyByConstant}, {@link #xor}, {@link
 * #homomorphicAnd} and {@link #reencrypt} - default to reporting that the scheme is not homomorphic
 * with respect to them, and each cryptosystem overrides the ones it supports.
 *
 * <p>Implementations are immutable after construction: key material is never written to again and
 * every operation returns a freshly allocated value, so a single instance may be shared by any
 * number of threads.
 */
public interface Homomorphic {

    /**
     * Reports which cryptosystem this is.
     *
     * @return the algorithm
     */
    Algorithm algorithm();

    /**
     * Returns the key material backing this cryptosystem.
     *
     * @return the private-public key pair
     */
    Keys keys();

    /**
     * Returns the size of the message space. Plaintexts are normalised into {@code [0,
     * plaintextModulo)} before encryption.
     *
     * @return the plaintext modulus
     */
    BigInteger plaintextModulo();

    /**
     * Returns the modulus ciphertext arithmetic is carried out in.
     *
     * @return the ciphertext modulus
     */
    BigInteger ciphertextModulo();

    /**
     * Returns the key fields this cryptosystem requires.
     *
     * @return the key specification
     */
    KeySpec requiredKeys();

    /**
     * Generates a one-time random key for encryption.
     *
     * @return the random key
     */
    BigInteger generateRandomKey();

    /**
     * Encrypts a plaintext that has already been reduced modulo {@link #plaintextModulo()}.
     *
     * @param plaintext the message to encrypt
     * @return the ciphertext
     */
    CipherValue encrypt(BigInteger plaintext);

    /**
     * Recovers the plaintext behind a ciphertext. Requires the private key.
     *
     * @param ciphertext the encrypted message
     * @return the restored message
     */
    BigInteger decrypt(CipherValue ciphertext);

    /**
     * Performs homomorphic addition: evaluates {@code E(m1 + m2)} from {@code E(m1)} and {@code
     * E(m2)}.
     *
     * @param ciphertext1 first ciphertext
     * @param ciphertext2 second ciphertext
     * @return the ciphertext of the sum
     * @throws IllegalArgumentException when the scheme is not additively homomorphic
     */
    default CipherValue add(CipherValue ciphertext1, CipherValue ciphertext2) {
        throw new IllegalArgumentException(
                algorithm() + " is not homomorphic with respect to the addition");
    }

    /**
     * Performs homomorphic multiplication: evaluates {@code E(m1 * m2)} from {@code E(m1)} and
     * {@code E(m2)}.
     *
     * @param ciphertext1 first ciphertext
     * @param ciphertext2 second ciphertext
     * @return the ciphertext of the product
     * @throws IllegalArgumentException when the scheme is not multiplicatively homomorphic
     */
    default CipherValue multiply(CipherValue ciphertext1, CipherValue ciphertext2) {
        throw new IllegalArgumentException(
                algorithm() + " is not homomorphic with respect to the multiplication");
    }

    /**
     * Performs homomorphic exclusive or: evaluates {@code E(m1 ^ m2)} from {@code E(m1)} and {@code
     * E(m2)}.
     *
     * @param ciphertext1 first ciphertext
     * @param ciphertext2 second ciphertext
     * @return the ciphertext of the exclusive or
     * @throws IllegalArgumentException when the scheme is not homomorphic with respect to xor
     */
    default CipherValue xor(CipherValue ciphertext1, CipherValue ciphertext2) {
        throw new IllegalArgumentException(
                algorithm() + " is not homomorphic with respect to the exclusive or");
    }

    /**
     * Performs homomorphic bitwise and: evaluates {@code E(m1 & m2)} from {@code E(m1)} and {@code
     * E(m2)}.
     *
     * @param ciphertext1 first ciphertext
     * @param ciphertext2 second ciphertext
     * @return the ciphertext of the bitwise and
     * @throws IllegalArgumentException when the scheme is not homomorphic with respect to and
     */
    default CipherValue homomorphicAnd(CipherValue ciphertext1, CipherValue ciphertext2) {
        throw new IllegalArgumentException(
                algorithm() + " is not homomorphic with respect to the bitwise and");
    }

    /**
     * Multiplies a ciphertext by a known plain constant: evaluates {@code E(m * k)} from {@code
     * E(m)} and {@code k}.
     *
     * @param ciphertext the ciphertext
     * @param constant the known plain constant
     * @return the scaled ciphertext
     * @throws IllegalArgumentException when the scheme does not support scalar multiplication
     */
    default CipherValue multiplyByConstant(CipherValue ciphertext, BigInteger constant) {
        throw new IllegalArgumentException(
                algorithm() + " is not supporting multiplying ciphertext by a known constant");
    }

    /**
     * Re-generates a ciphertext so that many ciphertexts decrypt to the same plaintext.
     *
     * @param ciphertext the ciphertext to re-randomise
     * @return a different ciphertext of the same plaintext
     * @throws IllegalArgumentException when the scheme does not support re-encryption
     */
    default CipherValue reencrypt(CipherValue ciphertext) {
        throw new IllegalArgumentException(algorithm() + " does not support re-encryption");
    }

    /**
     * Encrypts the input bits of a decision tree, for trees up to the given depth.
     *
     * @param bits the input bits, each 0 or 1
     * @param depth the maximum number of decisions on a path of the tree
     * @return item {@code [i][s - 1]} is the encryption of bit {@code i} at level {@code s}
     * @throws IllegalArgumentException when the scheme does not support decision trees
     */
    default List<List<BigInteger>> encryptDecisionTreeInput(List<Integer> bits, int depth) {
        throw new IllegalArgumentException(
                algorithm() + " does not support evaluating decision trees");
    }

    /**
     * Evaluates a decision tree on encrypted input bits.
     *
     * @param tree the decision tree
     * @param encryptedInput the output of {@link #encryptDecisionTreeInput}
     * @return the encrypted output of the tree
     * @throws IllegalArgumentException when the scheme does not support decision trees
     */
    default CipherValue evaluateDecisionTree(
            DecisionTree tree, List<List<BigInteger>> encryptedInput) {
        throw new IllegalArgumentException(
                algorithm() + " does not support evaluating decision trees");
    }

    /**
     * Reports whether decryption is possible.
     *
     * @return {@code true} when a private key is available
     */
    default boolean hasPrivateKey() {
        return keys().hasPrivateKey();
    }
}
