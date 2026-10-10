package io.github.serengil.lightphe.cryptosystems;

import io.github.serengil.lightphe.model.Algorithm;
import io.github.serengil.lightphe.model.Homomorphic;
import io.github.serengil.lightphe.model.KeySpec;
import io.github.serengil.lightphe.model.Keys;
import java.math.BigInteger;

/**
 * Builds cryptosystems from an {@link Algorithm} and the parameters that algorithm understands.
 *
 * <p>This is the single place that knows which constructor belongs to which algorithm, so the
 * facade, the ciphertext model and the key validator all agree on the mapping. Exponential ElGamal
 * reuses ElGamal's key structure, which is why both map onto the same class.
 */
public final class CryptosystemFactory {

    /** Default key size in bits when the caller does not name one. */
    public static final int DEFAULT_KEY_SIZE = 1024;

    /** Default number of key generation attempts. */
    public static final int DEFAULT_MAX_TRIES = 10000;

    private CryptosystemFactory() {
        throw new AssertionError("no instances");
    }

    /**
     * Options a cryptosystem may be built with. Every field is optional; the defaults reproduce the
     * behaviour of the Python library.
     *
     * @param keys an existing private-public key pair, or {@code null} to generate one
     * @param keySize key size in bits, or {@code null} for the algorithm's default
     * @param form elliptic curve form, only used by elliptic curve ElGamal
     * @param curve elliptic curve name, only used by elliptic curve ElGamal
     * @param plaintextLimit upper bound for plaintext values, only used by Benaloh and
     *     Sander-Young-Yung
     * @param maxTries maximum attempts to generate keys; RSA, Benaloh, Naccache-Stern,
     *     Goldwasser-Micali, Boneh-Goh-Nissim, Joye-Libert and Castagnos-Laguillaumie need multiple
     *     attempts, and the other algorithms ignore it
     */
    public record Options(
            Keys keys,
            Integer keySize,
            String form,
            String curve,
            BigInteger plaintextLimit,
            int maxTries) {

        /**
         * Returns options carrying nothing but an existing key pair.
         *
         * @param keys the key pair
         * @return the options
         */
        public static Options ofKeys(Keys keys) {
            return new Options(keys, null, null, null, null, DEFAULT_MAX_TRIES);
        }

        /**
         * Returns options carrying an existing key pair together with the curve it belongs to.
         *
         * @param keys the key pair
         * @param form elliptic curve form
         * @param curve elliptic curve name
         * @return the options
         */
        public static Options ofKeys(Keys keys, String form, String curve) {
            return new Options(keys, null, form, curve, null, DEFAULT_MAX_TRIES);
        }
    }

    /**
     * Builds a cryptosystem among the partially and somewhat homomorphic algorithms.
     *
     * @param algorithm the algorithm to build
     * @param options the construction parameters
     * @return the cryptosystem
     * @throws IllegalArgumentException when the algorithm is not implemented
     */
    public static Homomorphic build(Algorithm algorithm, Options options) {
        Keys keys = options.keys();
        Integer keySize = options.keySize();
        int maxTries = options.maxTries();

        return switch (algorithm) {
            case RSA -> new RSA(keys, keySize, maxTries);
            case EL_GAMAL -> new ElGamal(keys, false, keySize);
            case EXPONENTIAL_EL_GAMAL -> new ElGamal(keys, true, keySize);
            case ELLIPTIC_CURVE_EL_GAMAL ->
                    new EllipticCurveElGamal(keys, keySize, options.form(), options.curve());
            case PAILLIER -> new Paillier(keys, keySize);
            case DAMGARD_JURIK -> new DamgardJurik(keys, keySize);
            case OKAMOTO_UCHIYAMA -> new OkamotoUchiyama(keys, keySize);
            case BENALOH -> new Benaloh(keys, keySize, options.plaintextLimit(), maxTries);
            case NACCACHE_STERN -> new NaccacheStern(keys, keySize, false, maxTries);
            case GOLDWASSER_MICALI -> new GoldwasserMicali(keys, keySize, maxTries);
            case SANDER_YOUNG_YUNG ->
                    new SanderYoungYung(keys, keySize, toIntOrNull(options.plaintextLimit()));
            case BONEH_GOH_NISSIM -> new BonehGohNissim(keys, keySize, maxTries);
            case JOYE_LIBERT -> new JoyeLibert(keys, keySize, maxTries);
            case CASTAGNOS_LAGUILLAUMIE -> new CastagnosLaguillaumie(keys, keySize, maxTries);
            case ISHAI_PASKIN -> new IshaiPaskin(keys, keySize);
        };
    }

    /**
     * Returns the key fields the given algorithm requires.
     *
     * <p>Exponential ElGamal reuses ElGamal's key structure.
     *
     * @param algorithm the algorithm
     * @return the key specification
     */
    public static KeySpec requiredKeys(Algorithm algorithm) {
        return switch (algorithm) {
            case RSA -> RSA.REQUIRED_KEYS;
            case EL_GAMAL, EXPONENTIAL_EL_GAMAL -> ElGamal.REQUIRED_KEYS;
            case ELLIPTIC_CURVE_EL_GAMAL -> EllipticCurveElGamal.REQUIRED_KEYS;
            case PAILLIER -> Paillier.REQUIRED_KEYS;
            case DAMGARD_JURIK -> DamgardJurik.REQUIRED_KEYS;
            case OKAMOTO_UCHIYAMA -> OkamotoUchiyama.REQUIRED_KEYS;
            case BENALOH -> Benaloh.REQUIRED_KEYS;
            case NACCACHE_STERN -> NaccacheStern.REQUIRED_KEYS;
            case GOLDWASSER_MICALI -> GoldwasserMicali.REQUIRED_KEYS;
            case SANDER_YOUNG_YUNG -> SanderYoungYung.REQUIRED_KEYS;
            case BONEH_GOH_NISSIM -> BonehGohNissim.REQUIRED_KEYS;
            case JOYE_LIBERT -> JoyeLibert.REQUIRED_KEYS;
            case CASTAGNOS_LAGUILLAUMIE -> CastagnosLaguillaumie.REQUIRED_KEYS;
            case ISHAI_PASKIN -> DamgardJurik.REQUIRED_KEYS;
        };
    }

    private static Integer toIntOrNull(BigInteger value) {
        return value == null ? null : value.intValueExact();
    }
}
