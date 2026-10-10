package io.github.serengil.lightphe.model;

import io.github.serengil.lightphe.model.value.CipherValue;
import java.math.BigInteger;
import java.util.List;

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
    public boolean hasPrivateKey() {
        return false;
    }
}
