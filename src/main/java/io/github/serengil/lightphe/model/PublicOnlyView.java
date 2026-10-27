package io.github.serengil.lightphe.model;

import io.github.serengil.lightphe.ecc.CurvePoint;
import io.github.serengil.lightphe.model.value.CipherValue;
import java.math.BigInteger;
import java.util.List;
import java.util.function.Function;

/**
 * A read-only view of a cryptosystem with its private key stripped.
 *
 * <p>Handed to an untrusted party - or stored inside an {@link EncryptedTensor} - it can encrypt
 * and evaluate homomorphic operations but refuses to decrypt. The moduli of the original
 * cryptosystem are preserved, which matters for schemes such as Boneh-Goh-Nissim whose plaintext
 * modulus is derived from private key material and could not be recomputed from the public key
 * alone.
 */
public final class PublicOnlyView implements Homomorphic {

    private final Homomorphic delegate;
    private final Keys publicKeys;

    private PublicOnlyView(Homomorphic delegate) {
        this.delegate = delegate;
        this.publicKeys = delegate.keys().publicOnly();
    }

    /**
     * Wraps a cryptosystem so that its private key is no longer reachable.
     *
     * @param delegate the cryptosystem to wrap
     * @return the public-only view, or the argument itself when it already has no private key
     */
    public static Homomorphic of(Homomorphic delegate) {
        if (!delegate.keys().hasPrivateKey()) {
            return delegate;
        }
        return new PublicOnlyView(delegate);
    }

    @Override
    public Algorithm algorithm() {
        return delegate.algorithm();
    }

    @Override
    public Keys keys() {
        return publicKeys;
    }

    @Override
    public BigInteger plaintextModulo() {
        return delegate.plaintextModulo();
    }

    @Override
    public BigInteger ciphertextModulo() {
        return delegate.ciphertextModulo();
    }

    @Override
    public KeySpec requiredKeys() {
        return delegate.requiredKeys();
    }

    @Override
    public BigInteger generateRandomKey() {
        return delegate.generateRandomKey();
    }

    @Override
    public CipherValue encrypt(BigInteger plaintext) {
        return delegate.encrypt(plaintext);
    }

    /**
     * {@inheritDoc}
     *
     * @throws IllegalArgumentException always: this view holds no private key
     */
    @Override
    public BigInteger decrypt(CipherValue ciphertext) {
        throw new IllegalArgumentException("You must have private key to perform decryption");
    }

    @Override
    public CipherValue add(CipherValue ciphertext1, CipherValue ciphertext2) {
        return delegate.add(ciphertext1, ciphertext2);
    }

    @Override
    public CipherValue multiply(CipherValue ciphertext1, CipherValue ciphertext2) {
        return delegate.multiply(ciphertext1, ciphertext2);
    }

    @Override
    public CipherValue xor(CipherValue ciphertext1, CipherValue ciphertext2) {
        return delegate.xor(ciphertext1, ciphertext2);
    }

    @Override
    public CipherValue homomorphicAnd(CipherValue ciphertext1, CipherValue ciphertext2) {
        return delegate.homomorphicAnd(ciphertext1, ciphertext2);
    }

    @Override
    public CipherValue multiplyByConstant(CipherValue ciphertext, BigInteger constant) {
        return delegate.multiplyByConstant(ciphertext, constant);
    }

    @Override
    public CipherValue reencrypt(CipherValue ciphertext) {
        return delegate.reencrypt(ciphertext);
    }

    @Override
    public List<List<BigInteger>> encryptDecisionTreeInput(List<Integer> bits, int depth) {
        return delegate.encryptDecisionTreeInput(bits, depth);
    }

    @Override
    public CipherValue evaluateDecisionTree(
            DecisionTree tree, List<List<BigInteger>> encryptedInput) {
        return delegate.evaluateDecisionTree(tree, encryptedInput);
    }

    @Override
    public List<BigInteger> encryptComparisonInput(long value, int bitLength) {
        return delegate.encryptComparisonInput(value, bitLength);
    }

    @Override
    public List<BigInteger> evaluateComparison(List<BigInteger> encryptedInput, long value) {
        return delegate.evaluateComparison(encryptedInput, value);
    }

    @Override
    public List<List<BigInteger>> encryptDecisionTreeFeatures(List<Long> features, int bitLength) {
        return delegate.encryptDecisionTreeFeatures(features, bitLength);
    }

    @Override
    public NumericDecisionTree.Comparisons evaluateDecisionTreeComparisons(
            NumericDecisionTree tree, List<List<BigInteger>> encryptedFeatures) {
        return delegate.evaluateDecisionTreeComparisons(tree, encryptedFeatures);
    }

    @Override
    public List<NumericDecisionTree.EncryptedLeaf> evaluateDecisionTreeLeaves(
            NumericDecisionTree.ServerState serverState, List<BigInteger> encryptedAnswers) {
        return delegate.evaluateDecisionTreeLeaves(serverState, encryptedAnswers);
    }

    @Override
    public BigInteger evaluateArgmax(
            List<BigInteger> encryptedValues,
            int bitLength,
            Function<ArgmaxMessage, List<BigInteger>> client) {
        return delegate.evaluateArgmax(encryptedValues, bitLength, client);
    }

    @Override
    public Keys generateUserKeys() {
        return delegate.generateUserKeys();
    }

    @Override
    public VerifiableCiphertext encryptVerifiably(BigInteger secret, String label) {
        return delegate.encryptVerifiably(secret, label);
    }

    @Override
    public boolean verifyEncryption(
            VerifiableCiphertext verifiableCiphertext, CurvePoint publicPoint, String label) {
        return delegate.verifyEncryption(verifiableCiphertext, publicPoint, label);
    }

    @Override
    public CipherValue encrypt(BigInteger plaintext, BigInteger randomKey) {
        return delegate.encrypt(plaintext, randomKey);
    }

    @Override
    public BigInteger combinePartialDecryptions(
            CipherValue ciphertext, List<PartialDecryption> partialDecryptions, boolean verify) {
        return delegate.combinePartialDecryptions(ciphertext, partialDecryptions, verify);
    }

    @Override
    public boolean verifyPartialDecryption(
            CipherValue ciphertext, PartialDecryption partialDecryption) {
        return delegate.verifyPartialDecryption(ciphertext, partialDecryption);
    }

    @Override
    public boolean verifyDecryption(CipherValue ciphertext, BigInteger plaintext, Proof proof) {
        return delegate.verifyDecryption(ciphertext, plaintext, proof);
    }

    @Override
    public boolean supportsMembershipProofs() {
        return delegate.supportsMembershipProofs();
    }

    @Override
    public Proven<CipherValue> encryptWithProof(
            BigInteger plaintext, List<BigInteger> values, Object context) {
        return delegate.encryptWithProof(plaintext, values, context);
    }

    @Override
    public boolean verifyCiphertext(
            CipherValue ciphertext, Proof proof, List<BigInteger> values, Object context) {
        return delegate.verifyCiphertext(ciphertext, proof, values, context);
    }

    @Override
    public Proof proveMembership(
            CipherValue ciphertext,
            BigInteger plaintext,
            BigInteger randomKey,
            List<BigInteger> values,
            Object context) {
        return delegate.proveMembership(ciphertext, plaintext, randomKey, values, context);
    }

    @Override
    public BigInteger combineRandomKeys(List<BigInteger> randomKeys) {
        return delegate.combineRandomKeys(randomKeys);
    }

    @Override
    public Proven<CipherValue> encryptWithProofOfKnowledge(BigInteger plaintext, Object context) {
        return delegate.encryptWithProofOfKnowledge(plaintext, context);
    }

    @Override
    public boolean verifyKnowledge(CipherValue ciphertext, Proof proof, Object context) {
        return delegate.verifyKnowledge(ciphertext, proof, context);
    }

    @Override
    public boolean hasPrivateKey() {
        return false;
    }
}
