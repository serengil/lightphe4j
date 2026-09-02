package io.github.serengil.lightphe;

import io.github.serengil.lightphe.commons.KeyValidator;
import io.github.serengil.lightphe.commons.Logger;
import io.github.serengil.lightphe.commons.PheUtils;
import io.github.serengil.lightphe.cryptosystems.CryptosystemFactory;
import io.github.serengil.lightphe.model.Algorithm;
import io.github.serengil.lightphe.model.Ciphertext;
import io.github.serengil.lightphe.model.EncryptedTensor;
import io.github.serengil.lightphe.model.Fraction;
import io.github.serengil.lightphe.model.Homomorphic;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.KeysCodec;
import io.github.serengil.lightphe.model.PublicOnlyView;
import io.github.serengil.lightphe.model.value.CipherValue;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.IntStream;
import lombok.Builder;

/**
 * The entry point of the library: a partially or somewhat homomorphic cryptosystem you can encrypt
 * with, compute on, and decrypt with.
 *
 * <p>Java counterpart of the Python {@code LightPHE} class. Because Java dispatches on static types
 * rather than runtime ones, the single Python {@code encrypt}/{@code decrypt} pair is split into
 * {@link #encrypt(BigInteger)} / {@link #decrypt(Ciphertext)} for scalars and {@link
 * #encryptTensor(List)} / {@link #decryptTensor(EncryptedTensor)} for vectors.
 *
 * <h2>Example</h2>
 *
 * <pre>{@code
 * LightPHE cs = LightPHE.builder()
 *         .algorithmName("Paillier")
 *         .keySize(1024)
 *         .build();
 *
 * Ciphertext salary = cs.encrypt(10_000);
 * Ciphertext raise = cs.encrypt(1_000);
 * BigInteger total = cs.decrypt(salary.add(raise));   // 11000
 * }</pre>
 */
public final class LightPHE {

    /** Library version, tracking the Python release this port is based on. */
    public static final String VERSION = "0.0.25";

    /** Default number of digits kept after the decimal point in tensor operations. */
    public static final int DEFAULT_PRECISION = 5;

    private static final Logger logger = Logger.forModule(LightPHE.class);

    private static final MathContext DIVISION_CONTEXT = new MathContext(50);

    private final Algorithm algorithmName;
    private final int precision;
    private final String form;
    private final String curve;
    private final Homomorphic cs;

    /**
     * Builds a LightPHE cryptosystem.
     *
     * @param algorithmName one of {@code RSA}, {@code ElGamal}, {@code Exponential-ElGamal}, {@code
     *     EllipticCurve-ElGamal}, {@code Paillier}, {@code Damgard-Jurik}, {@code
     *     Okamoto-Uchiyama}, {@code Benaloh}, {@code Naccache-Stern}, {@code Goldwasser-Micali},
     *     {@code Sander-Young-Yung} or {@code Boneh-Goh-Nissim}
     * @param keys optional private-public key pair
     * @param keyFile if keys were exported already, the file to load them from
     * @param keySize key size in bits
     * @param precision precision for homomorphic operations on tensors; zero or less selects the
     *     default of {@value #DEFAULT_PRECISION}
     * @param form the form of the elliptic curve: {@code weierstrass} (default), {@code edwards} or
     *     {@code koblitz}. Only used when {@code algorithmName} is {@code EllipticCurve-ElGamal}.
     * @param curve the elliptic curve to use, for example {@code ed25519} or {@code ed448} for the
     *     Edwards form, {@code secp256k1} for the Weierstrass form and {@code k-409} for the
     *     Koblitz form. The full list of available curves is at <a
     *     href="https://github.com/serengil/LightECC?tab=readme-ov-file#supported-curves">
     *     LightECC</a>. Only used when {@code algorithmName} is {@code EllipticCurve-ElGamal}.
     * @param plaintextLimit upper bound for plaintext values. Only used when {@code algorithmName}
     *     is {@code Benaloh} or {@code Sander-Young-Yung}.
     * @param maxTries maximum attempts to generate keys; zero or less selects the default of 10000.
     *     RSA, Benaloh, Naccache-Stern, Goldwasser-Micali and Boneh-Goh-Nissim need multiple
     *     attempts to generate valid keys, and the other algorithms discard it.
     */
    @Builder
    public LightPHE(
            String algorithmName,
            Keys keys,
            Path keyFile,
            Integer keySize,
            int precision,
            String form,
            String curve,
            BigInteger plaintextLimit,
            int maxTries) {
        this.algorithmName = Algorithm.of(algorithmName);
        this.precision = precision > 0 ? precision : DEFAULT_PRECISION;
        this.form = form;
        this.curve = curve;

        Keys resolved = keys;
        if (keyFile != null) {
            resolved = restoreKeys(keyFile);
        }

        if (resolved != null) {
            KeyValidator.validateKeys(this.algorithmName, resolved);
        }

        this.cs =
                CryptosystemFactory.build(
                        this.algorithmName,
                        new CryptosystemFactory.Options(
                                resolved,
                                keySize,
                                form,
                                curve,
                                plaintextLimit,
                                maxTries > 0 ? maxTries : CryptosystemFactory.DEFAULT_MAX_TRIES));
    }

    /**
     * Returns the algorithm this cryptosystem implements.
     *
     * @return the algorithm
     */
    public Algorithm algorithmName() {
        return algorithmName;
    }

    /**
     * Returns the underlying cryptosystem.
     *
     * @return the cryptosystem
     */
    public Homomorphic cs() {
        return cs;
    }

    /**
     * Returns the precision used for tensor operations.
     *
     * @return the number of digits kept after the decimal point
     */
    public int precision() {
        return precision;
    }

    // -----------------------------------------------------------------------
    // Encryption and decryption
    // -----------------------------------------------------------------------

    /**
     * Encrypts a plaintext with the built cryptosystem.
     *
     * @param plaintext the message
     * @return the encrypted message
     * @throws IllegalArgumentException when no public key is available
     */
    public Ciphertext encrypt(BigInteger plaintext) {
        requirePublicKey("encryption");
        CipherValue ciphertext =
                cs.encrypt(PheUtils.normalizeInput(plaintext, cs.plaintextModulo()));
        return buildCiphertext(ciphertext);
    }

    /**
     * Encrypts a plaintext with the built cryptosystem.
     *
     * @param plaintext the message
     * @return the encrypted message
     */
    public Ciphertext encrypt(long plaintext) {
        return encrypt(BigInteger.valueOf(plaintext));
    }

    /**
     * Encrypts a real plaintext, which is first normalised into the message space.
     *
     * @param plaintext the message
     * @return the encrypted message
     * @throws IllegalArgumentException when no public key is available, or when the value is
     *     negative - a case the reference implementation leaves unimplemented
     */
    public Ciphertext encrypt(double plaintext) {
        requirePublicKey("encryption");
        CipherValue ciphertext =
                cs.encrypt(PheUtils.normalizeInput(plaintext, cs.plaintextModulo()));
        return buildCiphertext(ciphertext);
    }

    /**
     * Decrypts a ciphertext with the built cryptosystem.
     *
     * @param ciphertext the encrypted message
     * @return the restored message
     * @throws IllegalArgumentException when the private key is missing
     */
    public BigInteger decrypt(Ciphertext ciphertext) {
        requireKeysForDecryption();
        return cs.decrypt(ciphertext.value());
    }

    /**
     * Encrypts a tensor of real or integer values.
     *
     * <p>Every item is stored as an encrypted dividend over a shared encrypted divisor, so the
     * result supports element-wise multiplication, addition and dot products.
     *
     * @param tensor the values to encrypt
     * @return the encrypted tensor
     * @throws IllegalArgumentException when no public key is available
     */
    public EncryptedTensor encryptTensor(List<? extends Number> tensor) {
        requirePublicKey("encryption");

        CipherValue encryptedZero = cs.encrypt(BigInteger.ZERO);
        CipherValue encryptedDivisor = cs.encrypt(BigInteger.TEN.pow(precision));

        List<Fraction> fractions =
                IntStream.range(0, tensor.size())
                        .parallel()
                        .mapToObj(
                                index ->
                                        encryptFloat(
                                                tensor.get(index),
                                                encryptedDivisor,
                                                cs,
                                                precision,
                                                encryptedZero))
                        .toList();

        return new EncryptedTensor(fractions, PublicOnlyView.of(cs), precision);
    }

    /**
     * Decrypts an encrypted tensor.
     *
     * @param encryptedTensor the encrypted tensor
     * @return the restored values
     * @throws IllegalArgumentException when the private key is missing
     */
    public List<Double> decryptTensor(EncryptedTensor encryptedTensor) {
        requireKeysForDecryption();

        List<Double> plainTensor = new ArrayList<>(encryptedTensor.fractions().size());
        for (Fraction fraction : encryptedTensor.fractions()) {
            int sign = fraction.sign();
            BigInteger absDividend = cs.decrypt(fraction.absDividend());
            // TODO: do I really need an encrypted divisor? Could the current precision be stored
            // instead?
            BigInteger divisor = cs.decrypt(fraction.divisor());

            BigDecimal restored =
                    new BigDecimal(absDividend)
                            .divide(new BigDecimal(divisor), DIVISION_CONTEXT)
                            .multiply(BigDecimal.valueOf(sign));
            plainTensor.add(restored.doubleValue());
        }
        return plainTensor;
    }

    // -----------------------------------------------------------------------
    // Ciphertext utilities
    // -----------------------------------------------------------------------

    /**
     * Generates a different ciphertext belonging to the same plaintext.
     *
     * @param ciphertext the encrypted message
     * @return a re-randomised encryption of the same message
     * @throws IllegalArgumentException when no public key is available, or when the scheme does not
     *     support re-encryption
     */
    public Ciphertext regenerateCiphertext(Ciphertext ciphertext) {
        requirePublicKey("decryption");
        CipherValue regenerated = cs.reencrypt(ciphertext.value());
        return new Ciphertext(algorithmName, cs.keys(), regenerated, form, curve);
    }

    /**
     * Wraps a bare ciphertext payload in a {@link Ciphertext}, which carries the keys needed to
     * perform homomorphic operations on it.
     *
     * @param ciphertext the ciphertext content
     * @return the wrapped ciphertext
     */
    public Ciphertext createCiphertextObj(CipherValue ciphertext) {
        return new Ciphertext(algorithmName, cs.keys(), ciphertext, form, curve);
    }

    // -----------------------------------------------------------------------
    // Key management
    // -----------------------------------------------------------------------

    /**
     * Exports the keys to a file.
     *
     * @param targetFile the target file
     * @param publicOnly set this to {@code true} when the file will be published; the private key
     *     is then left out
     * @throws UncheckedIOException when the file cannot be written
     */
    public void exportKeys(Path targetFile, boolean publicOnly) {
        Keys exported = publicOnly ? cs.keys().publicOnly() : cs.keys();

        if (!publicOnly) {
            logger.warn(
                    "You did not set public arg to True. So, exported key has private key "
                            + "information.Do not share this to anyone");
        }

        try {
            Files.writeString(targetFile, KeysCodec.toJson(exported), StandardCharsets.UTF_8);
        } catch (IOException err) {
            throw new UncheckedIOException("Failed to export keys to " + targetFile, err);
        }
    }

    /**
     * Exports the private and public keys to a file.
     *
     * @param targetFile the target file
     */
    public void exportKeys(Path targetFile) {
        exportKeys(targetFile, false);
    }

    /**
     * Restores keys from a file.
     *
     * @param targetFile the file to read
     * @return the restored private-public key pair
     * @throws IllegalArgumentException when the file carries neither a public nor a private key
     * @throws UncheckedIOException when the file cannot be read
     */
    public static Keys restoreKeys(Path targetFile) {
        String content;
        try {
            content = Files.readString(targetFile, StandardCharsets.UTF_8);
        } catch (IOException err) {
            throw new UncheckedIOException("Failed to restore keys from " + targetFile, err);
        }

        Keys keys = KeysCodec.fromJson(content);

        if (keys.hasPrivateKey()) {
            logger.info("private-public key pair is restored from " + targetFile);
        } else if (keys.publicKey() != null && !keys.publicKey().isEmpty()) {
            logger.info("public key is restored from " + targetFile);
        } else {
            throw new IllegalArgumentException("File " + targetFile + " must have public_key key");
        }
        return keys;
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    private Ciphertext buildCiphertext(CipherValue value) {
        return new Ciphertext(algorithmName, cs.keys().publicOnly(), value, form, curve);
    }

    private void requirePublicKey(String operation) {
        if (cs.keys().publicKey() == null || cs.keys().publicKey().isEmpty()) {
            throw new IllegalArgumentException("You must have public key to perform " + operation);
        }
    }

    private void requireKeysForDecryption() {
        if (!cs.keys().hasPrivateKey()) {
            throw new IllegalArgumentException("You must have private key to perform decryption");
        }
        if (cs.keys().publicKey() == null || cs.keys().publicKey().isEmpty()) {
            throw new IllegalArgumentException("You must have public key to perform decryption");
        }
    }

    /**
     * Encrypts a single tensor item.
     *
     * <p>Integral and real values take different routes: an integer is scaled by {@code
     * 10^precision} after being reduced into the message space, while a real number is fractionised
     * first. Zero gets its own branch because it is very common in embeddings, and re-using the
     * pre-computed encryption of zero saves a modular exponentiation per occurrence.
     *
     * @param value the item to encrypt
     * @param encryptedDivisor the pre-computed encrypted divisor
     * @param cs the cryptosystem itself
     * @param precision how many digits after the decimal point to keep
     * @param encryptedZero the pre-computed encryption of zero
     * @return the encrypted item
     */
    static Fraction encryptFloat(
            Number value,
            CipherValue encryptedDivisor,
            Homomorphic cs,
            int precision,
            CipherValue encryptedZero) {

        BigInteger modulo = cs.plaintextModulo();

        if (value.doubleValue() == 0.0) {
            // this is very common in VGG-Face embeddings
            return Fraction.builder()
                    .dividend(encryptedZero)
                    .divisor(encryptedDivisor)
                    .absDividend(encryptedZero)
                    .sign(1)
                    .build();
        }

        if (isIntegral(value)) {
            BigInteger integral = toBigInteger(value);
            BigInteger scale = BigInteger.TEN.pow(precision);

            CipherValue dividend = cs.encrypt(integral.mod(modulo).multiply(scale));
            CipherValue absDividend =
                    integral.signum() > 0
                            ? dividend
                            : cs.encrypt(integral.abs().mod(modulo).multiply(scale));

            return Fraction.builder()
                    .dividend(dividend)
                    .divisor(encryptedDivisor)
                    .absDividend(absDividend)
                    .sign(integral.signum() >= 0 ? 1 : -1)
                    .build();
        }

        double real = value.doubleValue();
        // reducing the value first avoids "int too large to convert to float" when the security
        // level is high and the modulus no longer fits a double
        double reduced = exceedsModulo(real, modulo) ? real % modulo.doubleValue() : real;
        BigInteger dividendValue = PheUtils.fractionize(reduced, modulo, precision).dividend();

        CipherValue dividend = cs.encrypt(dividendValue);
        CipherValue absDividend;
        if (real > 0) {
            absDividend = dividend;
        } else {
            double magnitude = Math.abs(real);
            double reducedMagnitude =
                    exceedsModulo(magnitude, modulo) ? magnitude % modulo.doubleValue() : magnitude;
            absDividend =
                    cs.encrypt(
                            PheUtils.fractionize(reducedMagnitude, modulo, precision).dividend());
        }

        return Fraction.builder()
                .dividend(dividend)
                .divisor(encryptedDivisor)
                .absDividend(absDividend)
                .sign(real >= 0 ? 1 : -1)
                .build();
    }

    private static boolean exceedsModulo(double value, BigInteger modulo) {
        return new BigDecimal(value).compareTo(new BigDecimal(modulo)) > 0;
    }

    private static boolean isIntegral(Number value) {
        return value instanceof Integer
                || value instanceof Long
                || value instanceof Short
                || value instanceof Byte
                || value instanceof BigInteger;
    }

    private static BigInteger toBigInteger(Number value) {
        return value instanceof BigInteger big ? big : BigInteger.valueOf(value.longValue());
    }
}
