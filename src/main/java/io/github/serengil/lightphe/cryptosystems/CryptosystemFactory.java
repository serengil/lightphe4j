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
     * @param form elliptic curve form, only used by elliptic curve ElGamal and Camenisch-Shoup
     * @param curve elliptic curve name, only used by elliptic curve ElGamal and Camenisch-Shoup
     * @param plaintextLimit upper bound for plaintext values, only used by Benaloh,
     *     Sander-Young-Yung, Regev, Brakerski-Vaikuntanathan, Freeman-Boneh-Goh-Nissim,
     *     Gentry-Halevi-Vaikuntanathan and Lyubashevsky-Peikert-Regev
     * @param maxTries maximum attempts to generate keys; RSA, Benaloh, Naccache-Stern,
     *     Goldwasser-Micali, Boneh-Goh-Nissim, Joye-Libert, Castagnos-Laguillaumie,
     *     Damgard-Geisler-Kroigaard, Bresson-Catalano-Pointcheval and Camenisch-Shoup need multiple
     *     attempts, and the other algorithms ignore it
     * @param primeOrder picks the generator of a known prime order while generating keys of ElGamal
     *     or exponential ElGamal, which threshold decryption and zero-knowledge proofs require
     */
    public record Options(
            Keys keys,
            Integer keySize,
            String form,
            String curve,
            BigInteger plaintextLimit,
            int maxTries,
            boolean primeOrder) {

        /**
         * Returns options generating ElGamal keys with a generator of an unknown order.
         *
         * @param keys an existing private-public key pair, or {@code null} to generate one
         * @param keySize key size in bits, or {@code null} for the algorithm's default
         * @param form elliptic curve form
         * @param curve elliptic curve name
         * @param plaintextLimit upper bound for plaintext values
         * @param maxTries maximum attempts to generate keys
         */
        public Options(
                Keys keys,
                Integer keySize,
                String form,
                String curve,
                BigInteger plaintextLimit,
                int maxTries) {
            this(keys, keySize, form, curve, plaintextLimit, maxTries, false);
        }

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
            case EL_GAMAL -> new ElGamal(keys, false, keySize, options.primeOrder());
            case EXPONENTIAL_EL_GAMAL -> new ElGamal(keys, true, keySize, options.primeOrder());
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
            case DAMGARD_GEISLER_KROIGAARD -> new DamgardGeislerKroigaard(keys, keySize, maxTries);
            case BRESSON_CATALANO_POINTCHEVAL ->
                    new BressonCatalanoPointcheval(keys, keySize, maxTries);
            case CAMENISCH_SHOUP ->
                    new CamenischShoup(keys, keySize, maxTries, options.form(), options.curve());
            case ELLIPTIC_CURVE_PAILLIER -> new EllipticCurvePaillier(keys, keySize);
            case REGEV -> new Regev(keys, keySize, options.plaintextLimit());
            case BRAKERSKI_VAIKUNTANATHAN ->
                    new BrakerskiVaikuntanathan(keys, keySize, options.plaintextLimit());
            case FREEMAN_BONEH_GOH_NISSIM ->
                    new FreemanBonehGohNissim(keys, keySize, options.plaintextLimit());
            case GENTRY_HALEVI_VAIKUNTANATHAN ->
                    new GentryHaleviVaikuntanathan(keys, keySize, options.plaintextLimit());
            case LYUBASHEVSKY_PEIKERT_REGEV ->
                    new LyubashevskyPeikertRegev(keys, keySize, options.plaintextLimit());
            case ML_KEM -> new MLKEM(keys, keySize);
            case GENTRY_SAHAI_WATERS -> new GentrySahaiWaters(keys, keySize);
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
            case DAMGARD_GEISLER_KROIGAARD -> DamgardGeislerKroigaard.REQUIRED_KEYS;
            case BRESSON_CATALANO_POINTCHEVAL -> BressonCatalanoPointcheval.REQUIRED_KEYS;
            case CAMENISCH_SHOUP -> CamenischShoup.REQUIRED_KEYS;
            case ELLIPTIC_CURVE_PAILLIER -> EllipticCurvePaillier.REQUIRED_KEYS;
            case REGEV -> Regev.REQUIRED_KEYS;
            case BRAKERSKI_VAIKUNTANATHAN -> BrakerskiVaikuntanathan.REQUIRED_KEYS;
            case FREEMAN_BONEH_GOH_NISSIM -> FreemanBonehGohNissim.REQUIRED_KEYS;
            case GENTRY_HALEVI_VAIKUNTANATHAN -> GentryHaleviVaikuntanathan.REQUIRED_KEYS;
            case LYUBASHEVSKY_PEIKERT_REGEV -> LyubashevskyPeikertRegev.REQUIRED_KEYS;
            case ML_KEM -> MLKEM.REQUIRED_KEYS;
            case GENTRY_SAHAI_WATERS -> GentrySahaiWaters.REQUIRED_KEYS;
        };
    }

    /**
     * Rejects real numbers for the algorithms that support integers only.
     *
     * <p>Joye-Libert cannot invert powers of 10 in its plaintext space, the lattice and discrete
     * logarithm based schemes cannot fit values scaled by powers of 10 into their small plaintext
     * space or noise budget, and ML-KEM and Gentry-Sahai-Waters are homomorphic with respect to
     * boolean operations only.
     *
     * @param algorithm the algorithm
     * @throws IllegalArgumentException when the algorithm does not support floats
     */
    public static void requireFloatSupport(Algorithm algorithm) {
        if (algorithm == Algorithm.JOYE_LIBERT) {
            throw new IllegalArgumentException(JoyeLibert.FLOAT_NOT_SUPPORTED_MSG);
        }
        requireTensorSupport(algorithm);
    }

    /**
     * Rejects tensors for the algorithms whose plaintext space or noise budget cannot hold values
     * scaled by powers of 10, even when the tensor items are integers.
     *
     * @param algorithm the algorithm
     * @throws IllegalArgumentException when the algorithm does not support tensors
     */
    public static void requireTensorSupport(Algorithm algorithm) {
        String message =
                switch (algorithm) {
                    case REGEV -> Regev.FLOAT_NOT_SUPPORTED_MSG;
                    case BRAKERSKI_VAIKUNTANATHAN ->
                            BrakerskiVaikuntanathan.FLOAT_NOT_SUPPORTED_MSG;
                    case FREEMAN_BONEH_GOH_NISSIM -> FreemanBonehGohNissim.FLOAT_NOT_SUPPORTED_MSG;
                    case GENTRY_HALEVI_VAIKUNTANATHAN ->
                            GentryHaleviVaikuntanathan.FLOAT_NOT_SUPPORTED_MSG;
                    case LYUBASHEVSKY_PEIKERT_REGEV ->
                            LyubashevskyPeikertRegev.FLOAT_NOT_SUPPORTED_MSG;
                    case ML_KEM -> MLKEM.FLOAT_NOT_SUPPORTED_MSG;
                    case GENTRY_SAHAI_WATERS -> GentrySahaiWaters.FLOAT_NOT_SUPPORTED_MSG;
                    default -> null;
                };
        if (message != null) {
            throw new IllegalArgumentException(message);
        }
    }

    private static Integer toIntOrNull(BigInteger value) {
        return value == null ? null : value.intValueExact();
    }
}
