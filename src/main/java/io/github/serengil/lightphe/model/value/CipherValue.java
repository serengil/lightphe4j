package io.github.serengil.lightphe.model.value;

/**
 * A ciphertext payload.
 *
 * <p>The hierarchy is deliberately closed: only the four types permitted below implement it, which
 * lets every cryptosystem switch over the complete set of shapes a ciphertext can take without a
 * fallback branch that would silently accept nonsense.
 *
 * <p>Values are immutable. Homomorphic operations always return a new value instead of mutating
 * their operands, so a value may be shared freely between threads.
 */
public sealed interface CipherValue permits IntValue, TupleValue, PointValue, Fp2Value {

    /**
     * Renders the value the way the Python library prints it.
     *
     * @return a human readable representation
     */
    @Override
    String toString();
}
