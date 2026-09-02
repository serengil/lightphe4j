package io.github.serengil.lightphe.cryptosystems;

import io.github.serengil.lightphe.commons.Logger;
import io.github.serengil.lightphe.commons.MathUtils;
import io.github.serengil.lightphe.ecc.CurvePoint;
import io.github.serengil.lightphe.ecc.LightECC;
import io.github.serengil.lightphe.model.Algorithm;
import io.github.serengil.lightphe.model.KeySpec;
import io.github.serengil.lightphe.model.KeyValue;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.PointValue;
import io.github.serengil.lightphe.model.value.TupleValue;
import java.math.BigInteger;
import java.util.List;

/**
 * Elliptic curve ElGamal, an additively homomorphic cryptosystem.
 *
 * <p>Decryption has to solve the elliptic curve discrete logarithm problem, but that stays easy as
 * long as plaintexts are not very large - unlike Benaloh or Naccache-Stern, whose message space is
 * bounded by the key itself.
 *
 * <p>Ref: <a href="https://sefiks.com/2018/08/21/elliptic-curve-elgamal-encryption/">Elliptic curve
 * ElGamal encryption</a>
 */
public final class EllipticCurveElGamal extends AbstractHomomorphic {

    /** The key fields elliptic curve ElGamal requires. */
    public static final KeySpec REQUIRED_KEYS = KeySpec.of(List.of("Qa"), List.of("ka"));

    private static final Logger logger = Logger.forModule(EllipticCurveElGamal.class);

    private final LightECC ecc;

    /**
     * Builds an elliptic curve ElGamal cryptosystem.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param keySize key size in bits; {@code null} defaults to the bit length of the curve order,
     *     which for the default curve is equivalent to 1024-bit RSA
     * @param form the elliptic curve form: {@code "weierstrass"} (default), {@code "edwards"} or
     *     {@code "koblitz"}
     * @param curve the elliptic curve to use, e.g. {@code ed25519} or {@code ed448} for the Edwards
     *     form and {@code secp256k1} for the Weierstrass form
     */
    public EllipticCurveElGamal(Keys keys, Integer keySize, String form, String curve) {
        super(Algorithm.ELLIPTIC_CURVE_EL_GAMAL, resolveKeys(keys, keySize, form, curve));
        this.ecc = LightECC.of(form, curve);

        if (curve != null) {
            this.keys.setCurve(curve);
        }
        if (form != null) {
            this.keys.setForm(form);
        }

        this.plaintextModulo = ecc.modulo();
        this.ciphertextModulo = ecc.modulo();
    }

    /**
     * Builds an elliptic curve ElGamal cryptosystem around an existing key pair.
     *
     * @param keys the private-public key pair
     * @param form the elliptic curve form
     * @param curve the elliptic curve to use
     */
    public EllipticCurveElGamal(Keys keys, String form, String curve) {
        this(keys, null, form, curve);
    }

    private static Keys resolveKeys(Keys keys, Integer keySize, String form, String curve) {
        if (keys != null) {
            return keys;
        }
        LightECC ecc = LightECC.of(form, curve);
        return generateKeys(ecc, keySize == null ? ecc.n().bitLength() : keySize);
    }

    /**
     * Returns the underlying elliptic curve.
     *
     * @return the curve this cryptosystem operates on
     */
    public LightECC ecc() {
        return ecc;
    }

    /**
     * Generates the public and private keys of the elliptic curve ElGamal cryptosystem.
     *
     * @param ecc the curve to generate keys on
     * @param keySize key size in bits
     * @return the generated key pair
     */
    public static Keys generateKeys(LightECC ecc, int keySize) {
        Keys keys = Keys.empty();

        // private key
        BigInteger ka = MathUtils.getRandomBits(keySize);
        logger.debug(() -> keySize + " bit private key generated for Elliptic Curve ElGamal.");

        // public key
        CurvePoint qa = ecc.g().multiply(ka);

        keys.publicKey().put("Qa", KeyValue.point(qa.x(), qa.y()));
        keys.privateKey().put("ka", KeyValue.of(ka));
        return keys;
    }

    @Override
    public KeySpec requiredKeys() {
        return REQUIRED_KEYS;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Elliptic curve ElGamal requires a one-time random key per encryption.
     */
    @Override
    public BigInteger generateRandomKey() {
        return MathUtils.getRandomBits(ecc.n().bitLength());
    }

    @Override
    public CipherValue encrypt(BigInteger plaintext) {
        return encrypt(plaintext, generateRandomKey());
    }

    /**
     * Encrypts a plaintext with an explicit random key.
     *
     * @param plaintext the message to encrypt
     * @param randomKey the random key; do not set this to a static value
     * @return the ciphertext pair {@code (c1, c2)}
     */
    public CipherValue encrypt(BigInteger plaintext, BigInteger randomKey) {
        CurvePoint qa = publicPoint();

        CurvePoint s = ecc.g().multiply(plaintext);
        CurvePoint c1 = ecc.g().multiply(randomKey);
        CurvePoint c2 = qa.multiply(randomKey).add(s);

        return TupleValue.of(PointValue.from(c1), PointValue.from(c2));
    }

    @Override
    public BigInteger decrypt(CipherValue ciphertext) {
        // private key
        BigInteger ka = keys.privateNumber("ka");

        CurvePoint[] pair = asPointPair(ciphertext);
        CurvePoint sPrime = pair[0].negate().multiply(ka).add(pair[1]);

        // s_prime is a point on the elliptic curve with s_prime = k x G; we need to find k from the
        // known s_prime and G, which requires solving the elliptic curve discrete logarithm problem
        return sPrime.divide(ecc.g());
    }

    /**
     * {@inheritDoc}
     *
     * <p>The result equals {@code E(m1 + m2)}.
     */
    @Override
    public CipherValue add(CipherValue ciphertext1, CipherValue ciphertext2) {
        CurvePoint[] first = asPointPair(ciphertext1);
        CurvePoint[] second = asPointPair(ciphertext2);

        CurvePoint a = first[0].add(second[0]);
        CurvePoint b = first[1].add(second[1]);
        return TupleValue.of(PointValue.from(a), PointValue.from(b));
    }

    /**
     * {@inheritDoc}
     *
     * <p>The result equals {@code k x E(m) = E(m * k)}.
     */
    @Override
    public CipherValue multiplyByConstant(CipherValue ciphertext, BigInteger constant) {
        CurvePoint[] pair = asPointPair(ciphertext);
        return TupleValue.of(
                PointValue.from(pair[0].multiply(constant)),
                PointValue.from(pair[1].multiply(constant)));
    }

    @Override
    public CipherValue reencrypt(CipherValue ciphertext) {
        BigInteger rPrime = generateRandomKey();
        CurvePoint qa = publicPoint();

        CurvePoint[] pair = asPointPair(ciphertext);
        CurvePoint c1Prime = pair[0].add(ecc.g().multiply(rPrime));
        CurvePoint c2Prime = pair[1].add(qa.multiply(rPrime));
        return TupleValue.of(PointValue.from(c1Prime), PointValue.from(c2Prime));
    }

    private CurvePoint publicPoint() {
        KeyValue.Point qa = keys.publicPoint("Qa");
        return ecc.point(qa.x(), qa.y());
    }

    private CurvePoint[] asPointPair(CipherValue value) {
        TupleValue tuple = asTuple(value);
        if (tuple.size() != 2) {
            throw new IllegalArgumentException(
                    "expected a ciphertext pair, got " + tuple.size() + " components");
        }
        return new CurvePoint[] {toCurvePoint(tuple.get(0)), toCurvePoint(tuple.get(1))};
    }

    private CurvePoint toCurvePoint(CipherValue value) {
        if (!(value instanceof PointValue point)) {
            throw new IllegalArgumentException(
                    "expected an elliptic curve point, got " + value.getClass().getSimpleName());
        }
        return point.infinity() ? ecc.o() : ecc.point(point.x(), point.y());
    }
}
