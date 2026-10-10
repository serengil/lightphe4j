package io.github.serengil.lightphe.model;

/**
 * Identifies a cryptosystem.
 *
 * <p>The wire names match the algorithm names used by the Python reference implementation, so keys
 * exported by one library can be consumed by the other.
 */
public enum Algorithm {

    /** Partially homomorphic with respect to the multiplication. */
    RSA("RSA"),

    /** Multiplicatively homomorphic ElGamal. */
    EL_GAMAL("ElGamal"),

    /** Additively homomorphic ElGamal, encrypting {@code g^m} instead of {@code m}. */
    EXPONENTIAL_EL_GAMAL("Exponential-ElGamal"),

    /** Additively homomorphic ElGamal over an elliptic curve. */
    ELLIPTIC_CURVE_EL_GAMAL("EllipticCurve-ElGamal"),

    /** Additively homomorphic; also supports scalar multiplication. */
    PAILLIER("Paillier"),

    /** Generalisation of Paillier with modulus {@code n^(s+1)}. */
    DAMGARD_JURIK("Damgard-Jurik"),

    /** Additively homomorphic over {@code n = p^2 * q}. */
    OKAMOTO_UCHIYAMA("Okamoto-Uchiyama"),

    /** Additively homomorphic over a small message space. */
    BENALOH("Benaloh"),

    /** Generalisation of Benaloh, additively homomorphic. */
    NACCACHE_STERN("Naccache-Stern"),

    /** Homomorphic with respect to the exclusive or, bit by bit. */
    GOLDWASSER_MICALI("Goldwasser-Micali"),

    /** Homomorphic with respect to the bitwise and. */
    SANDER_YOUNG_YUNG("Sander-Young-Yung"),

    /** Additively homomorphic and, once per ciphertext, multiplicatively homomorphic. */
    BONEH_GOH_NISSIM("Boneh-Goh-Nissim"),

    /** Additively homomorphic over {@code Z_(2^k)}, generalising Goldwasser-Micali to k bits. */
    JOYE_LIBERT("Joye-Libert"),

    /** Additively homomorphic ElGamal-like scheme in class groups of quadratic fields. */
    CASTAGNOS_LAGUILLAUMIE("Castagnos-Laguillaumie"),

    /** Evaluates decision trees on encrypted input; additively homomorphic as Damgard-Jurik. */
    ISHAI_PASKIN("Ishai-Paskin");

    private final String algorithmName;

    Algorithm(String algorithmName) {
        this.algorithmName = algorithmName;
    }

    /**
     * Returns the user-facing algorithm name, e.g. {@code "Damgard-Jurik"}.
     *
     * @return the algorithm name
     */
    public String algorithmName() {
        return algorithmName;
    }

    /**
     * Resolves an algorithm from its user-facing name.
     *
     * @param name the algorithm name, e.g. {@code "Exponential-ElGamal"}
     * @return the matching algorithm
     * @throws IllegalArgumentException when no algorithm carries that name
     */
    public static Algorithm of(String name) {
        for (Algorithm algorithm : values()) {
            if (algorithm.algorithmName.equalsIgnoreCase(name)) {
                return algorithm;
            }
        }
        throw new IllegalArgumentException("unimplemented algorithm - " + name);
    }

    @Override
    public String toString() {
        return algorithmName;
    }
}
