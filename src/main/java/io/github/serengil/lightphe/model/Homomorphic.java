package io.github.serengil.lightphe.model;

import io.github.serengil.lightphe.ecc.CurvePoint;
import io.github.serengil.lightphe.model.value.CipherValue;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * The contract every cryptosystem in this library fulfils.
 *
 * <p>Java counterpart of the abstract {@code Homomorphic} class of the Python library. The optional
 * operations - {@link #add}, {@link #multiply}, {@link #multiplyByConstant}, {@link #xor}, {@link
 * #homomorphicAnd} and {@link #reencrypt} - default to reporting that the scheme is not homomorphic
 * with respect to them, and each cryptosystem overrides the ones it supports. Every cryptosystem
 * implements a subset of the protocol operations below the same way.
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
                algorithm() + " does not support evaluating decision trees with bits and depth");
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

    // -----------------------------------------------------------------------
    // Secure comparison
    // -----------------------------------------------------------------------

    /**
     * Encrypts the bits of the client's value to compare it with a value of the server.
     *
     * @param value the client's value in {@code [0, 2^bitLength)}
     * @param bitLength the number of bits of compared values
     * @return the encrypted bits, least significant bit first
     * @throws IllegalArgumentException when the scheme does not support secure comparison
     */
    default List<BigInteger> encryptComparisonInput(long value, int bitLength) {
        throw new IllegalArgumentException(algorithm() + " does not support secure comparison");
    }

    /**
     * Compares the client's encrypted value with the server's value.
     *
     * @param encryptedInput the output of {@link #encryptComparisonInput}
     * @param value the server's value in {@code [0, 2^bitLength)}
     * @return the encrypted result, to be sent back to the client
     * @throws IllegalArgumentException when the scheme does not support secure comparison
     */
    default List<BigInteger> evaluateComparison(List<BigInteger> encryptedInput, long value) {
        throw new IllegalArgumentException(algorithm() + " does not support secure comparison");
    }

    /**
     * Restores the result of a secure comparison.
     *
     * @param encryptedResult the output of {@link #evaluateComparison}
     * @return {@code true} when the client's value is at most the server's value
     * @throws IllegalArgumentException when the scheme does not support secure comparison
     */
    default boolean decryptComparison(List<BigInteger> encryptedResult) {
        throw new IllegalArgumentException(algorithm() + " does not support secure comparison");
    }

    // -----------------------------------------------------------------------
    // Private decision tree evaluation with numeric features
    // -----------------------------------------------------------------------

    /**
     * Encrypts the client's features to be evaluated in the server's decision tree.
     *
     * @param features the features, each in {@code [0, 2^bitLength)}
     * @param bitLength the number of bits of features and thresholds
     * @return the encrypted features
     * @throws IllegalArgumentException when the scheme does not support it
     */
    default List<List<BigInteger>> encryptDecisionTreeFeatures(List<Long> features, int bitLength) {
        throw new IllegalArgumentException(
                algorithm()
                        + " does not support private decision tree evaluation"
                        + " with features and bit_length");
    }

    /**
     * Compares the encrypted features with the thresholds of all decision nodes.
     *
     * @param tree the decision tree
     * @param encryptedFeatures the output of {@link #encryptDecisionTreeFeatures}
     * @return the comparisons for the client and the state the server keeps secret
     * @throws IllegalArgumentException when the scheme does not support it
     */
    default NumericDecisionTree.Comparisons evaluateDecisionTreeComparisons(
            NumericDecisionTree tree, List<List<BigInteger>> encryptedFeatures) {
        throw new IllegalArgumentException(
                algorithm() + " does not support private decision tree evaluation");
    }

    /**
     * Answers the server's comparisons in encrypted form.
     *
     * @param encryptedComparisons the comparisons of {@link #evaluateDecisionTreeComparisons}
     * @return the encrypted answers
     * @throws IllegalArgumentException when the scheme does not support it
     */
    default List<BigInteger> answerDecisionTreeComparisons(
            List<List<BigInteger>> encryptedComparisons) {
        throw new IllegalArgumentException(
                algorithm() + " does not support private decision tree evaluation");
    }

    /**
     * Finds the reached leaf in encrypted form.
     *
     * @param serverState the state of {@link #evaluateDecisionTreeComparisons}
     * @param encryptedAnswers the output of {@link #answerDecisionTreeComparisons}
     * @return the encrypted leaves
     * @throws IllegalArgumentException when the scheme does not support it
     */
    default List<NumericDecisionTree.EncryptedLeaf> evaluateDecisionTreeLeaves(
            NumericDecisionTree.ServerState serverState, List<BigInteger> encryptedAnswers) {
        throw new IllegalArgumentException(
                algorithm() + " does not support private decision tree evaluation");
    }

    /**
     * Restores the label of the reached leaf.
     *
     * @param encryptedLeaves the output of {@link #evaluateDecisionTreeLeaves}
     * @return the label of the reached leaf
     * @throws IllegalArgumentException when the scheme does not support it
     */
    default long decryptDecisionTreeOutput(
            List<NumericDecisionTree.EncryptedLeaf> encryptedLeaves) {
        throw new IllegalArgumentException(
                algorithm() + " does not support private decision tree evaluation");
    }

    // -----------------------------------------------------------------------
    // Encrypted argmax
    // -----------------------------------------------------------------------

    /**
     * Finds the index of the maximum of encrypted values without decrypting them.
     *
     * @param encryptedValues the encrypted values in {@code [0, 2^bitLength)}
     * @param bitLength the number of bits of the values
     * @param client sends a message to the client and returns its answer
     * @return the encrypted index
     * @throws IllegalArgumentException when the scheme does not support encrypted argmax
     */
    default BigInteger evaluateArgmax(
            List<BigInteger> encryptedValues,
            int bitLength,
            Function<ArgmaxMessage, List<BigInteger>> client) {
        throw new IllegalArgumentException(algorithm() + " does not support encrypted argmax");
    }

    /**
     * Answers a message of the server during encrypted argmax.
     *
     * @param message the message of the server
     * @return the answer, to be sent back to the server
     * @throws IllegalArgumentException when the scheme does not support encrypted argmax
     */
    default List<BigInteger> answerArgmax(ArgmaxMessage message) {
        throw new IllegalArgumentException(algorithm() + " does not support encrypted argmax");
    }

    // -----------------------------------------------------------------------
    // Master key decryption
    // -----------------------------------------------------------------------

    /**
     * Decrypts a ciphertext with the master key instead of the private key of its owner.
     *
     * @param ciphertext the encrypted message of any user
     * @param publicKey the public key of the user the ciphertext was encrypted for, or {@code null}
     *     to use the public key of this cryptosystem
     * @return the restored message
     * @throws IllegalArgumentException when the scheme does not support master key decryption
     */
    default BigInteger decryptWithMasterKey(
            CipherValue ciphertext, Map<String, KeyValue> publicKey) {
        throw new IllegalArgumentException(algorithm() + " does not support master key decryption");
    }

    /**
     * Generates a key pair for a new user sharing a master key.
     *
     * @return the private-public key pair of the new user
     * @throws IllegalArgumentException when the scheme does not support it
     */
    default Keys generateUserKeys() {
        throw new IllegalArgumentException(
                algorithm() + " does not support generating user keys sharing a master key");
    }

    // -----------------------------------------------------------------------
    // Verifiable encryption
    // -----------------------------------------------------------------------

    /**
     * Encrypts the discrete logarithm of an elliptic curve point and proves that the ciphertext
     * contains it.
     *
     * @param secret the discrete logarithm of the public point
     * @param label public data bound to the ciphertext
     * @return the verifiable ciphertext
     * @throws IllegalArgumentException when the scheme does not support verifiable encryption
     */
    default VerifiableCiphertext encryptVerifiably(BigInteger secret, String label) {
        throw new IllegalArgumentException(algorithm() + " does not support verifiable encryption");
    }

    /**
     * Verifies that a verifiable ciphertext contains the discrete logarithm of a public point.
     *
     * @param verifiableCiphertext the output of {@link #encryptVerifiably}
     * @param publicPoint the public point known by the verifier
     * @param label the label the ciphertext is expected to be bound to
     * @return {@code true} when the ciphertext contains the secret of the public point
     * @throws IllegalArgumentException when the scheme does not support verifiable encryption
     */
    default boolean verifyEncryption(
            VerifiableCiphertext verifiableCiphertext, CurvePoint publicPoint, String label) {
        throw new IllegalArgumentException(algorithm() + " does not support verifiable encryption");
    }

    /**
     * Restores the secret from a verifiable ciphertext.
     *
     * @param verifiableCiphertext the output of {@link #encryptVerifiably}
     * @param label the label used in encryption
     * @return the discrete logarithm of the public point
     * @throws IllegalArgumentException when the scheme does not support verifiable encryption
     */
    default BigInteger decryptVerifiableCiphertext(
            VerifiableCiphertext verifiableCiphertext, String label) {
        throw new IllegalArgumentException(algorithm() + " does not support verifiable encryption");
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
