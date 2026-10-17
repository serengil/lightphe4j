package io.github.serengil.lightphe.cryptosystems;

import io.github.serengil.lightphe.commons.Logger;
import io.github.serengil.lightphe.commons.MathUtils;
import io.github.serengil.lightphe.model.Algorithm;
import io.github.serengil.lightphe.model.KeySpec;
import io.github.serengil.lightphe.model.KeyValue;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.IntValue;
import io.github.serengil.lightphe.model.value.TupleValue;
import java.math.BigInteger;
import java.util.List;

/**
 * Elliptic Curve Paillier, homomorphic with respect to the addition. It also supports raising a
 * ciphertext base to a plaintext exponent, which yields scalar multiplication.
 *
 * <p>It is the elliptic curve analogue of Paillier. Paillier works in the multiplicative group
 * {@code Z_(n^2)*}, whereas this works in the group of points on an elliptic curve {@code y^2 = x^3
 * + b} over the ring {@code Z_(n^2)} where {@code n = pq}.
 *
 * <p>Points reducing to the point at infinity modulo n form a subgroup of order n, in which
 * discrete logarithm is easy, similar to {@code 1 + n} in Paillier. A ciphertext is {@code m * (n :
 * 1 : 0) + r * g}, where g is a point whose order is a secret factor of the group order.
 * Multiplying a ciphertext by that order clears {@code r * g} and leaves m.
 *
 * <p>p and q are 2 mod 3, so the curve has {@code p + 1} points modulo p and {@code q + 1} points
 * modulo q as in KMOV cryptosystem, and the group order is known by the private key owner only.
 * Points are in projective coordinates as division is not always possible in {@code Z_(n^2)}.
 * Additions use complete formulas, which work for all points including doubling and the point at
 * infinity, as the order of g is odd and so it has no point of order 2. Ciphertexts are 3 times
 * larger than Paillier's, and operations are slower.
 *
 * <p>Point arithmetic is implemented here instead of the {@code ecc} package, which works with
 * affine points and divides in its addition formulas. That suits curves over prime fields, but
 * {@code Z_(n^2)} is not a field, and messages live in points reducing to the point at infinity
 * modulo n, such as {@code (mn : 1 : 0)}, which cannot be written as affine points. Projective
 * coordinates with complete formulas never divide and keep those points distinct.
 *
 * <p>Ref: Galbraith, S. D. (2002). Elliptic Curve Paillier Schemes. Journal of Cryptology, 15(2),
 * 129-138.
 *
 * <p>Ref: Renes, J., Costello, C., Batina, L. (2016). Complete Addition Formulas for Prime Order
 * Elliptic Curves. EUROCRYPT 2016.
 */
public final class EllipticCurvePaillier extends AbstractHomomorphic {

    /** The key fields Elliptic Curve Paillier requires. */
    public static final KeySpec REQUIRED_KEYS =
            KeySpec.of(List.of("n", "b", "g"), List.of("order"));

    /** Extra bits of the random key, so that it is statistically uniform modulo the order of g. */
    private static final int RANDOM_KEY_EXTRA_BITS = 128;

    private static final Logger logger = Logger.forModule(EllipticCurvePaillier.class);

    private static final BigInteger THREE = BigInteger.valueOf(3);

    /** A projective point {@code (X : Y : Z)}. */
    private record Point(BigInteger x, BigInteger y, BigInteger z) {}

    private static final Point INFINITY =
            new Point(BigInteger.ZERO, BigInteger.ONE, BigInteger.ZERO);

    /** Precomputed {@code 2^i * g} points, built on first encryption. */
    private volatile Point[] gPowers;

    /**
     * Builds an Elliptic Curve Paillier cryptosystem.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param keySize key size in bits; {@code null} defaults to 1024
     */
    public EllipticCurvePaillier(Keys keys, Integer keySize) {
        super(
                Algorithm.ELLIPTIC_CURVE_PAILLIER,
                keys != null ? keys : generateKeys(keySize == null ? 1024 : keySize));
        BigInteger n = this.keys.publicNumber("n");
        this.plaintextModulo = n;
        this.ciphertextModulo = n.multiply(n);
    }

    /**
     * Builds an Elliptic Curve Paillier cryptosystem around an existing key pair.
     *
     * @param keys the private-public key pair
     */
    public EllipticCurvePaillier(Keys keys) {
        this(keys, null);
    }

    /**
     * Generates the public and private keys of the Elliptic Curve Paillier cryptosystem.
     *
     * @param keySize key size in bits
     * @return the generated key pair
     * @throws IllegalArgumentException when the key size is too small
     */
    public static Keys generateKeys(int keySize) {
        if (keySize < 16) {
            throw new IllegalArgumentException(
                    "Key size " + keySize + " is too small for Elliptic Curve Paillier");
        }

        while (true) {
            BigInteger p = findPrime(keySize / 2);
            BigInteger q = findPrime(keySize / 2);
            if (p.equals(q)) {
                continue;
            }
            BigInteger n = p.multiply(q);
            BigInteger nSquare = n.multiply(n);

            // exponent of the group modulo n, and its odd part
            BigInteger pPlusOne = p.add(BigInteger.ONE);
            BigInteger qPlusOne = q.add(BigInteger.ONE);
            BigInteger exponent = pPlusOne.multiply(qPlusOne).divide(pPlusOne.gcd(qPlusOne));
            BigInteger order = exponent.shiftRight(exponent.getLowestSetBit());
            if (!order.gcd(n).equals(BigInteger.ONE)) {
                continue;
            }

            // random point P, and the curve passing through it
            BigInteger x = MathUtils.randomInt(BigInteger.ZERO, nSquare.subtract(BigInteger.ONE));
            BigInteger y = MathUtils.randomInt(BigInteger.ZERO, nSquare.subtract(BigInteger.ONE));
            BigInteger b = y.multiply(y).subtract(x.pow(3)).mod(nSquare);
            if (!b.gcd(n).equals(BigInteger.ONE)) {
                continue;
            }

            // g has odd order dividing the secret order
            Point g =
                    multiply(
                            new Point(x, y, BigInteger.ONE),
                            n.multiply(exponent.divide(order)),
                            b,
                            nSquare);
            if (!g.z().gcd(n).equals(BigInteger.ONE)) {
                continue;
            }
            BigInteger zInverse = g.z().modInverse(nSquare);

            Keys keys = Keys.empty();
            keys.publicKey().put("n", KeyValue.of(n));
            keys.publicKey().put("b", KeyValue.of(b));
            keys.publicKey()
                    .put(
                            "g",
                            KeyValue.point(
                                    g.x().multiply(zInverse).mod(nSquare),
                                    g.y().multiply(zInverse).mod(nSquare)));

            keys.privateKey().put("order", KeyValue.of(order));
            keys.privateKey().put("p", KeyValue.of(p));
            keys.privateKey().put("q", KeyValue.of(q));
            return keys;
        }
    }

    @Override
    public KeySpec requiredKeys() {
        return REQUIRED_KEYS;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Elliptic Curve Paillier requires a one-time random key per encryption.
     */
    @Override
    public BigInteger generateRandomKey() {
        BigInteger n = keys.publicNumber("n");
        return MathUtils.randomInt(BigInteger.ONE, n.shiftLeft(RANDOM_KEY_EXTRA_BITS));
    }

    @Override
    public CipherValue encrypt(BigInteger plaintext) {
        return encrypt(plaintext, generateRandomKey());
    }

    /**
     * Encrypts a plaintext with an explicit random key.
     *
     * @param plaintext the message to encrypt in {@code [0, n)}
     * @param randomKey the random key
     * @return the ciphertext, the projective point {@code m * (n : 1 : 0) + r * g}
     */
    public CipherValue encrypt(BigInteger plaintext, BigInteger randomKey) {
        BigInteger n = keys.publicNumber("n");
        BigInteger b = keys.publicNumber("b");
        BigInteger nSquare = n.multiply(n);

        BigInteger message = plaintext;
        if (message.compareTo(n) >= 0) {
            message = message.mod(n);
            BigInteger normalized = message;
            logger.debug(
                    () ->
                            "Elliptic Curve Paillier can encrypt messages [0, "
                                    + n
                                    + "). Seems plaintext exceeded this limit. New plaintext is "
                                    + normalized);
        }

        // m * (n : 1 : 0) = (mn : 1 : 0), similar to (1 + n)^m = 1 + mn in Paillier
        Point messagePoint =
                new Point(message.multiply(n).mod(nSquare), BigInteger.ONE, BigInteger.ZERO);
        return toValue(add(messagePoint, multiplyG(randomKey), b, nSquare));
    }

    @Override
    public BigInteger decrypt(CipherValue ciphertext) {
        BigInteger n = keys.publicNumber("n");
        BigInteger b = keys.publicNumber("b");
        BigInteger order = keys.privateNumber("order");
        BigInteger nSquare = n.multiply(n);

        // order * C = (order * m) * (n : 1 : 0) as order * r * g is the point at infinity
        Point restored = multiply(toPoint(ciphertext), order, b, nSquare);
        if (restored.x().mod(n).signum() != 0
                || restored.z().mod(n).signum() != 0
                || !restored.y().gcd(n).equals(BigInteger.ONE)) {
            throw new IllegalArgumentException("Ciphertext is invalid");
        }

        // (kn : 1 : 0) -> k
        BigInteger scaledMessage =
                restored.x().multiply(restored.y().modInverse(nSquare)).mod(nSquare).divide(n);
        return scaledMessage.multiply(order.modInverse(n)).mod(n);
    }

    /**
     * {@inheritDoc}
     *
     * <p>The result equals {@code E(m1 + m2)}.
     */
    @Override
    public CipherValue add(CipherValue ciphertext1, CipherValue ciphertext2) {
        BigInteger n = keys.publicNumber("n");
        BigInteger b = keys.publicNumber("b");
        return toValue(add(toPoint(ciphertext1), toPoint(ciphertext2), b, n.multiply(n)));
    }

    /**
     * {@inheritDoc}
     *
     * <p>The result equals {@code E(m * constant)}.
     */
    @Override
    public CipherValue multiplyByConstant(CipherValue ciphertext, BigInteger constant) {
        BigInteger n = keys.publicNumber("n");
        BigInteger b = keys.publicNumber("b");
        BigInteger scalar = constant;

        if (scalar.compareTo(plaintextModulo) >= 0) {
            scalar = scalar.mod(plaintextModulo);
            BigInteger normalized = scalar;
            logger.debug(
                    () ->
                            "Elliptic Curve Paillier can encrypt messages [0, "
                                    + n
                                    + "). Seems constant exceeded this limit. New constant is "
                                    + normalized);
        }

        return toValue(multiply(toPoint(ciphertext), scalar, b, n.multiply(n)));
    }

    @Override
    public CipherValue reencrypt(CipherValue ciphertext) {
        return add(ciphertext, encrypt(BigInteger.ZERO));
    }

    /**
     * Adds two projective points on {@code y^2 = x^3 + b} over {@code Z_(n^2)} with complete
     * formulas (Algorithm 7 of Renes-Costello-Batina for {@code a = 0}).
     */
    private static Point add(Point point1, Point point2, BigInteger b, BigInteger mod) {
        BigInteger b3 = b.multiply(THREE);
        BigInteger x1 = point1.x();
        BigInteger y1 = point1.y();
        BigInteger z1 = point1.z();
        BigInteger x2 = point2.x();
        BigInteger y2 = point2.y();
        BigInteger z2 = point2.z();

        BigInteger t0 = x1.multiply(x2).mod(mod);
        BigInteger t1 = y1.multiply(y2).mod(mod);
        BigInteger t2 = z1.multiply(z2).mod(mod);
        BigInteger t3 = x1.add(y1).multiply(x2.add(y2)).subtract(t0).subtract(t1).mod(mod);
        BigInteger t4 = y1.add(z1).multiply(y2.add(z2)).subtract(t1).subtract(t2).mod(mod);
        BigInteger y3 = x1.add(z1).multiply(x2.add(z2)).subtract(t0).subtract(t2).mod(mod);
        t0 = t0.multiply(THREE).mod(mod);
        t2 = b3.multiply(t2).mod(mod);
        BigInteger z3 = t1.add(t2).mod(mod);
        t1 = t1.subtract(t2).mod(mod);
        y3 = b3.multiply(y3).mod(mod);
        BigInteger x3 = t3.multiply(t1).subtract(t4.multiply(y3)).mod(mod);
        y3 = t1.multiply(z3).add(y3.multiply(t0)).mod(mod);
        z3 = z3.multiply(t4).add(t0.multiply(t3)).mod(mod);
        return new Point(x3, y3, z3);
    }

    /** Multiplies a projective point with a non-negative scalar with double and add method. */
    private static Point multiply(Point point, BigInteger scalar, BigInteger b, BigInteger mod) {
        Point result = INFINITY;
        for (int i = scalar.bitLength() - 1; i >= 0; i--) {
            result = add(result, result, b, mod);
            if (scalar.testBit(i)) {
                result = add(result, point, b, mod);
            }
        }
        return result;
    }

    /** Multiplies g with a scalar using precomputed {@code 2^i * g} points, avoiding doublings. */
    private Point multiplyG(BigInteger scalar) {
        BigInteger n = keys.publicNumber("n");
        BigInteger b = keys.publicNumber("b");
        BigInteger nSquare = n.multiply(n);

        int bits = Math.max(scalar.bitLength(), n.shiftLeft(RANDOM_KEY_EXTRA_BITS).bitLength());
        Point[] powers = gPowers;
        if (powers == null || powers.length < bits) {
            KeyValue.Point g = keys.publicPoint("g");
            powers = new Point[bits];
            powers[0] = new Point(g.x(), g.y(), BigInteger.ONE);
            for (int i = 1; i < bits; i++) {
                powers[i] = add(powers[i - 1], powers[i - 1], b, nSquare);
            }
            gPowers = powers;
        }

        Point result = INFINITY;
        for (int i = 0; i < scalar.bitLength(); i++) {
            if (scalar.testBit(i)) {
                result = add(result, powers[i], b, nSquare);
            }
        }
        return result;
    }

    /**
     * Finds a prime {@code p = 2 mod 3}, so that {@code y^2 = x^3 + b} has {@code p + 1} points.
     */
    private static BigInteger findPrime(int bits) {
        while (true) {
            BigInteger candidate = MathUtils.getRandomBits(bits).setBit(bits - 1).setBit(0);
            if (candidate.mod(THREE).intValue() == 2 && MathUtils.isPrime(candidate)) {
                return candidate;
            }
        }
    }

    private static CipherValue toValue(Point point) {
        return TupleValue.of(
                IntValue.of(point.x()), IntValue.of(point.y()), IntValue.of(point.z()));
    }

    private static Point toPoint(CipherValue value) {
        TupleValue tuple = asTuple(value);
        if (tuple.size() != 3) {
            throw new IllegalArgumentException(
                    "expected a projective point (X : Y : Z), got " + tuple.size() + " components");
        }
        return new Point(asInt(tuple.get(0)), asInt(tuple.get(1)), asInt(tuple.get(2)));
    }
}
