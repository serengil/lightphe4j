package io.github.serengil.lightphe.cryptosystems;

import io.github.serengil.lightphe.commons.Logger;
import io.github.serengil.lightphe.commons.MathUtils;
import io.github.serengil.lightphe.ecc.CurvePoint;
import io.github.serengil.lightphe.ecc.Fp2;
import io.github.serengil.lightphe.ecc.InvalidCurveOrderException;
import io.github.serengil.lightphe.ecc.LightECC;
import io.github.serengil.lightphe.ecc.PairingResult;
import io.github.serengil.lightphe.ecc.PointNotOnCurveException;
import io.github.serengil.lightphe.model.Algorithm;
import io.github.serengil.lightphe.model.KeySpec;
import io.github.serengil.lightphe.model.KeyValue;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.Fp2Value;
import io.github.serengil.lightphe.model.value.PointValue;
import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Boneh-Goh-Nissim, homomorphic with respect to the addition and, once per ciphertext, with respect
 * to the multiplication - which makes it somewhat rather than partially homomorphic.
 *
 * <p>A fresh ciphertext is a point on a supersingular curve of embedding degree two. The single
 * permitted multiplication runs the bilinear pairing and lands the result in the target group
 * {@code G_T = F_{p^2}}, where further additions are still possible but no further multiplication
 * is.
 *
 * <p>Ref: <a
 * href="https://sefiks.com/2026/04/02/a-step-by-step-somewhat-homomorphic-encryption-example-with-boneh-goh-nissim-in-python/">
 * A step by step somewhat homomorphic encryption example with Boneh-Goh-Nissim</a>
 */
public final class BonehGohNissim extends AbstractHomomorphic {

    /** The key fields Boneh-Goh-Nissim requires. */
    public static final KeySpec REQUIRED_KEYS =
            KeySpec.of(
                    List.of("curve", "G", "u", "h", "l"),
                    List.of("q1", "q2"),
                    Map.of("curve", List.of("a", "b", "p", "G", "n")));

    private static final Logger logger = Logger.forModule(BonehGohNissim.class);

    private final LightECC ec;

    /**
     * Builds a Boneh-Goh-Nissim cryptosystem.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param keySize size of the keys to generate in bits; {@code null} defaults to 1024
     * @param maxTries maximum attempts to generate keys
     */
    public BonehGohNissim(Keys keys, Integer keySize, int maxTries) {
        super(
                Algorithm.BONEH_GOH_NISSIM,
                keys != null ? keys : generateKeys(keySize == null ? 1024 : keySize, maxTries));

        KeyValue.Nested curve = this.keys.publicNested("curve");
        KeyValue.Point generator = curve.point("G");
        this.ec =
                LightECC.customWeierstrass(
                        curve.number("a"),
                        curve.number("b"),
                        curve.number("p"),
                        generator.x(),
                        generator.y(),
                        curve.number("n"));

        this.plaintextModulo = hasPrivateKey() ? this.keys.privateNumber("q2") : curve.number("n");
        this.ciphertextModulo = ec.modulo();
    }

    /**
     * Builds a Boneh-Goh-Nissim cryptosystem around an existing key pair.
     *
     * @param keys the private-public key pair
     */
    public BonehGohNissim(Keys keys) {
        this(keys, null, 10000);
    }

    /**
     * Returns the elliptic curve this cryptosystem operates on.
     *
     * @return the generated supersingular curve
     */
    public LightECC ec() {
        return ec;
    }

    /**
     * Generates the public and private keys of the Boneh-Goh-Nissim cryptosystem.
     *
     * @param keySize size of the keys to generate in bits
     * @param maxTries maximum attempts to generate keys
     * @return the generated key pair
     * @throws IllegalStateException when no valid key pair is found within {@code maxTries}
     */
    public static Keys generateKeys(int keySize, int maxTries) {
        BigInteger q1 = null;
        BigInteger q2 = null;
        BigInteger n = null;
        BigInteger p = null;
        BigInteger a = BigInteger.ONE;
        BigInteger b = BigInteger.ZERO;
        BigInteger l = null;
        BigInteger[] generator = null;
        LightECC ec = null;

        BigInteger lowerBound = BigInteger.TWO.pow(keySize / 2);
        BigInteger upperBound = BigInteger.TWO.pow(keySize / 2 + 1);

        for (int attempt = 0; attempt < maxTries; attempt++) {
            // choose large odd distinct primes q1 and q2
            q1 = MathUtils.randomPrime(lowerBound, upperBound);
            q2 = MathUtils.randomPrime(lowerBound, upperBound);
            while (q1.equals(q2)) {
                q2 = MathUtils.randomPrime(lowerBound, upperBound);
            }

            n = q1.multiply(q2);

            // Find l such that p = n*l - 1 is prime and p = 3 (mod 4). Supersingularity of
            // y^2 = x^3 + x requires p = 3 (mod 4). Since n is odd (a product of two odd primes),
            // n*l = 0 (mod 4) iff l = 0 (mod 4), so we iterate multiples of 4 systematically.
            l = null;
            for (long candidate = 4; candidate < (long) maxTries * 4 + 4; candidate += 4) {
                BigInteger pCandidate =
                        n.multiply(BigInteger.valueOf(candidate)).subtract(BigInteger.ONE);
                if (MathUtils.isPrime(pCandidate)) {
                    l = BigInteger.valueOf(candidate);
                    break;
                }
            }

            if (l == null) {
                int attempts = attempt + 1;
                logger.debug(() -> "No valid l found for attempt " + attempts + ", retrying");
                continue;
            }

            p = n.multiply(l).subtract(BigInteger.ONE);
            generator = findGenerator(p, maxTries);

            try {
                ec = LightECC.customWeierstrass(a, b, p, generator[0], generator[1], n);
            } catch (InvalidCurveOrderException | PointNotOnCurveException err) {
                int attempts = attempt + 1;
                logger.debug(
                        () ->
                                "Curve order validation failed for attempt "
                                        + attempts
                                        + ", retrying");
                continue;
            }

            logger.debug("Curve order validated by LightECC.");
            BigInteger finalQ1 = q1;
            BigInteger finalQ2 = q2;
            BigInteger finalN = n;
            BigInteger finalP = p;
            BigInteger finalL = l;
            logger.debug(
                    () ->
                            "q1 = " + finalQ1 + ", q2 = " + finalQ2 + ", n = " + finalN + ", p = "
                                    + finalP + ", l = " + finalL);
            break;
        }

        if (ec == null) {
            throw new IllegalStateException(
                    "Failed to generate keys after " + maxTries + " attempts");
        }

        BigInteger r;
        while (true) {
            r = MathUtils.randomInt(BigInteger.TWO, n.subtract(BigInteger.ONE));
            if (r.gcd(n).equals(BigInteger.ONE)) {
                break;
            }
        }

        CurvePoint u = ec.g().multiply(r);
        CurvePoint h = u.multiply(q2);

        Map<String, KeyValue> curve = new LinkedHashMap<>();
        curve.put("a", KeyValue.of(a));
        curve.put("b", KeyValue.of(b));
        curve.put("p", KeyValue.of(p));
        curve.put("G", KeyValue.point(generator[0], generator[1]));
        curve.put("n", KeyValue.of(n));

        Keys keys = Keys.empty();
        keys.publicKey().put("curve", new KeyValue.Nested(curve));
        keys.privateKey().put("q1", KeyValue.of(q1));
        keys.privateKey().put("q2", KeyValue.of(q2));
        keys.publicKey().put("G", KeyValue.point(generator[0], generator[1]));
        keys.publicKey().put("u", KeyValue.point(u.x(), u.y()));
        keys.publicKey().put("h", KeyValue.point(h.x(), h.y()));
        keys.publicKey().put("l", KeyValue.of(l));
        return keys;
    }

    /**
     * Picks a point on the supersingular curve {@code y^2 = x^3 + x} over {@code F_p} to serve as
     * the generator.
     *
     * @param p the field modulus, which must be prime
     * @param maxTries maximum attempts before giving up
     * @return the coordinates of the generator
     * @throws IllegalArgumentException when {@code p} is not prime
     * @throws IllegalStateException when no generator is found within {@code maxTries}
     */
    private static BigInteger[] findGenerator(BigInteger p, int maxTries) {
        if (!MathUtils.isPrime(p)) {
            throw new IllegalArgumentException("p must be prime");
        }

        for (int attempt = 0; attempt < maxTries; attempt++) {
            BigInteger x = MathUtils.randomInt(BigInteger.ZERO, p.subtract(BigInteger.ONE));
            BigInteger rhs = x.modPow(BigInteger.valueOf(3), p).add(x).mod(p);
            List<BigInteger> roots = MathUtils.sqrtMod(rhs, p); // get all square roots
            if (!roots.isEmpty()) {
                return new BigInteger[] {x, roots.get(0)}; // just return the first one
            }
        }

        throw new IllegalStateException(
                "Failed to find a generator after " + maxTries + " attempts");
    }

    @Override
    public KeySpec requiredKeys() {
        return REQUIRED_KEYS;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Boneh-Goh-Nissim requires a one-time random key per encryption.
     */
    @Override
    public BigInteger generateRandomKey() {
        if (hasPrivateKey()) {
            BigInteger q2 = keys.privateNumber("q2");
            return MathUtils.randomInt(BigInteger.ONE, q2.subtract(BigInteger.ONE));
        }

        BigInteger n = keys.publicNested("curve").number("n");
        logger.warn(
                "Private key is not available. Random key will be bounded by n"
                        + " instead of q2. Encryption will work for small plaintexts,"
                        + " but negative number encoding via plaintext_modulo will not"
                        + " round-trip correctly because plaintext_modulo is set to n"
                        + " (public) instead of q2 (private).");
        return MathUtils.randomInt(BigInteger.ONE, n.subtract(BigInteger.ONE));
    }

    @Override
    public CipherValue encrypt(BigInteger plaintext) {
        return encrypt(plaintext, generateRandomKey());
    }

    /**
     * Encrypts a plaintext with an explicit random key.
     *
     * @param plaintext the message to encrypt
     * @param randomKey the one-time random key
     * @return the ciphertext, a point on the elliptic curve
     */
    public CipherValue encrypt(BigInteger plaintext, BigInteger randomKey) {
        CurvePoint g = ec.g();
        CurvePoint h = publicPoint("h");
        return PointValue.from(g.multiply(plaintext).add(h.multiply(randomKey)));
    }

    /**
     * {@inheritDoc}
     *
     * <p>Handles both {@code G1} ciphertexts, produced by encryption and addition, and {@code G_T}
     * ciphertexts in {@code F_{p^2}}, produced by homomorphic multiplication.
     */
    @Override
    public BigInteger decrypt(CipherValue ciphertext) {
        BigInteger q1 = keys.privateNumber("q1");
        BigInteger q2 = keys.privateNumber("q2");

        if (ciphertext instanceof Fp2Value fp2Value) {
            return decryptGt(fp2Value.toFp2(), q1, q2);
        }

        CurvePoint g = ec.g();
        CurvePoint mp = toCurvePoint(ciphertext).multiply(q1);
        CurvePoint p = g.multiply(q1);

        // P has order q2, so the discrete logarithm result is in [0, q2)
        if (mp.equals(ec.o())) {
            return BigInteger.ZERO;
        }

        CurvePoint accumulator = p;
        for (BigInteger i = BigInteger.ONE; i.compareTo(q2) < 0; i = i.add(BigInteger.ONE)) {
            if (accumulator.equals(mp)) {
                return i;
            }
            accumulator = accumulator.add(p);
        }

        throw new IllegalStateException("Decryption failed");
    }

    /**
     * Decrypts a {@code G_T} ciphertext, the result of a homomorphic multiplication.
     *
     * <p>{@code e(C1, C2)^q1 = e(G, G)^(q1 * m1 * m2)}, so the plaintext product is recovered by
     * solving the discrete logarithm {@code base^m == target} with {@code base = e(G, G)^q1} and
     * {@code target = e(C1, C2)^q1}.
     *
     * @param ciphertext the pairing value in {@code F_{p^2}}
     * @param q1 private key component
     * @param q2 private key component bounding the search
     * @return the plaintext product {@code m1 * m2}
     */
    private BigInteger decryptGt(Fp2 ciphertext, BigInteger q1, BigInteger q2) {
        BigInteger p = ec.modulo();
        CurvePoint g = ec.g();

        // e(G, G) - pairing of the generator with itself via the distortion map
        PairingResult egg = ec.pairing(g, g);
        if (!egg.extended()) {
            throw new IllegalArgumentException(
                    "Boneh-Goh-Nissim requires a supersingular curve with embedding degree 2. "
                            + "The pairing returned an F_p element instead of an F_{p^2} element.");
        }

        // base = e(G, G)^q1, target = e(C1, C2)^q1
        Fp2 base = egg.value().pow(q1, p);
        Fp2 target = ciphertext.pow(q1, p);

        // brute-force the discrete logarithm in G_T - the result is in [0, q2)
        if (target.isOne()) {
            return BigInteger.ZERO;
        }

        Fp2 accumulator = Fp2.one();
        for (BigInteger i = BigInteger.ONE; i.compareTo(q2) < 0; i = i.add(BigInteger.ONE)) {
            accumulator = accumulator.multiply(base, p);
            if (accumulator.equals(target)) {
                return i;
            }
        }

        throw new IllegalStateException("Decryption of G_T ciphertext failed");
    }

    /**
     * {@inheritDoc}
     *
     * <p>Both operands must live in the same group: two curve points add as points, two {@code
     * F_{p^2}} elements add by multiplication in the target group.
     */
    @Override
    public CipherValue add(CipherValue ciphertext1, CipherValue ciphertext2) {
        if (ciphertext1 instanceof PointValue && ciphertext2 instanceof PointValue) {
            return PointValue.from(toCurvePoint(ciphertext1).add(toCurvePoint(ciphertext2)));
        }

        if (ciphertext1 instanceof Fp2Value first && ciphertext2 instanceof Fp2Value second) {
            return Fp2Value.from(first.toFp2().multiply(second.toFp2(), ec.modulo()));
        }

        throw new IllegalArgumentException(
                "Both ciphertexts must be of the same type for addition.");
    }

    /**
     * {@inheritDoc}
     *
     * <p>Homomorphic multiplication uses the bilinear pairing. The result is an element of {@code
     * F_{p^2}} - the pairing target group {@code G_T} - and not a point on the elliptic curve, so
     * it cannot be multiplied again.
     */
    @Override
    public CipherValue multiply(CipherValue ciphertext1, CipherValue ciphertext2) {
        // The pair (a, b) represents a + b*i where i^2 = -1 mod p
        if (ciphertext1 instanceof Fp2Value || ciphertext2 instanceof Fp2Value) {
            throw new IllegalArgumentException(
                    "Boneh-Goh-Nissim only supports multiplication ciphertexts once!");
        }

        PairingResult result = ec.pairing(toCurvePoint(ciphertext1), toCurvePoint(ciphertext2));
        if (!result.extended()) {
            throw new IllegalArgumentException(
                    "Boneh-Goh-Nissim requires a supersingular curve with embedding degree 2. "
                            + "The pairing returned an F_p element instead of an F_{p^2} element.");
        }

        // The pairing result is an element of F_{p^2}, not a point on the curve. In BGN the pairing
        // maps two curve points to a field element in the multiplicative group G_T, so homomorphic
        // multiplication works in the target group rather than back on the curve.
        return Fp2Value.from(result.value());
    }

    @Override
    public CipherValue multiplyByConstant(CipherValue ciphertext, BigInteger constant) {
        if (ciphertext instanceof PointValue) {
            return PointValue.from(toCurvePoint(ciphertext).multiply(constant));
        }
        if (ciphertext instanceof Fp2Value value) {
            // For G_T elements, exponentiation achieves scalar multiplication: repeating the
            // multiplication `constant` times is exactly raising the base to that power.
            return Fp2Value.from(value.toFp2().pow(constant, ec.modulo()));
        }

        throw new IllegalArgumentException(
                "Ciphertext must be either an EllipticCurvePoint or a tuple "
                        + "representing an F_{p^2} element for multiplication by constant.");
    }

    @Override
    public CipherValue reencrypt(CipherValue ciphertext) {
        CurvePoint h = publicPoint("h");
        BigInteger r = generateRandomKey();
        return PointValue.from(toCurvePoint(ciphertext).add(h.multiply(r)));
    }

    private CurvePoint publicPoint(String field) {
        KeyValue.Point point = keys.publicPoint(field);
        return ec.point(point.x(), point.y());
    }

    private CurvePoint toCurvePoint(CipherValue value) {
        if (!(value instanceof PointValue point)) {
            throw new IllegalArgumentException(
                    "expected an elliptic curve point, got " + value.getClass().getSimpleName());
        }
        return point.infinity() ? ec.o() : ec.point(point.x(), point.y());
    }
}
