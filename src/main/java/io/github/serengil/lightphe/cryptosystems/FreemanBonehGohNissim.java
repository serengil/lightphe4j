package io.github.serengil.lightphe.cryptosystems;

import io.github.serengil.lightphe.commons.MathUtils;
import io.github.serengil.lightphe.ecc.CurvePoint;
import io.github.serengil.lightphe.ecc.Fp2;
import io.github.serengil.lightphe.ecc.LightECC;
import io.github.serengil.lightphe.ecc.PairingResult;
import io.github.serengil.lightphe.model.Algorithm;
import io.github.serengil.lightphe.model.KeySpec;
import io.github.serengil.lightphe.model.KeyValue;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.Fp2Value;
import io.github.serengil.lightphe.model.value.PointValue;
import io.github.serengil.lightphe.model.value.TupleValue;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Freeman-Boneh-Goh-Nissim, the prime-order version of Boneh-Goh-Nissim. It is homomorphic with
 * respect to the addition, and supports one multiplication of ciphertexts. Boneh-Goh-Nissim works
 * in a group of composite order {@code n = q1 q2}, and its security relies on hardness of factoring
 * n, which requires a large group. This works in a group of prime order r, and its security relies
 * on decision linear assumption.
 *
 * <p>Groups are vectors of 3 points on the supersingular curve {@code y^2 = x^3 + x} over {@code
 * F_p}, whose points of order r have a symmetric pairing into {@code F_{p^2}}.
 *
 * <ul>
 *   <li>private key: secret vector v in {@code Z_r^3}
 *   <li>public key: h1 and h2 spanning the subgroup H of vectors orthogonal to v, and g out of H.
 *       Vectors are multiplied with the generator point P.
 *   <li>encryption: {@code C = m g + a1 h1 + a2 h2} for random a1 and a2
 *   <li>decryption: projection {@code pi(C) = v1 C1 + v2 C2 + v3 C3 = m pi(g)} as {@code pi(H) =
 *       0}, then discrete logarithm of it with base {@code pi(g)}
 *   <li>multiplication: {@code 3 x 3} pairings {@code e(C_i, C'_j)}. Its projection, product of
 *       {@code e(C_i, C'_j)^(v_i v_j)}, is {@code e(pi(C), pi(C')) = e(pi(g), pi(g))^(m m')}.
 * </ul>
 *
 * <p>Freeman's symmetric instantiation needs vectors of 3 points, because decisional Diffie-Hellman
 * is easy in groups having a symmetric pairing.
 *
 * <p>Notice that decryption solves discrete logarithm as in Boneh-Goh-Nissim, so decrypted values
 * must be small: in {@code [-limit, limit]} where limit is {@code 2^20} by default, and can be set
 * with the plaintext limit. Floats and tensors are not supported. Ciphertexts are 3 points, and
 * multiplied ciphertexts are 9 elements of {@code F_{p^2}}. Multiplied ciphertexts can be added
 * with each other and multiplied with constants. Adding a fresh ciphertext to a multiplied one
 * pairs it with g first, which costs 9 pairings.
 *
 * <p>Key size is the bit length of the field size p. Default is 1024. The group order r is 256
 * bits, and security is bounded by discrete logarithm in {@code F_{p^2}}: about 112 bits for p of
 * 1024 bits, and 128 bits for p of 1536 bits. It is not quantum resistant.
 *
 * <p>Ref: Freeman, D. M. (2010). Converting Pairing-Based Cryptosystems from Composite-Order Groups
 * to Prime-Order Groups. EUROCRYPT 2010.
 *
 * <p>Ref: Boneh, D., Goh, E.-J., Nissim, K. (2005). Evaluating 2-DNF Formulas on Ciphertexts. TCC
 * 2005.
 */
public final class FreemanBonehGohNissim extends AbstractHomomorphic {

    /** The key fields Freeman-Boneh-Goh-Nissim requires. */
    public static final KeySpec REQUIRED_KEYS =
            KeySpec.of(List.of("p", "r", "P", "g", "h1", "h2", "limit"), List.of("v"));

    /** Floats are scaled by powers of 10, which exceeds the range of discrete logarithm. */
    public static final String FLOAT_NOT_SUPPORTED_MSG =
            "Freeman-Boneh-Goh-Nissim does not support float values or tensors, because they are"
                    + " scaled by powers of 10, which exceed the range that decryption can restore."
                    + " Use integers instead.";

    /**
     * Decrypted values must be in {@code [-limit, limit]} by default, as decryption solves discrete
     * logarithm with baby-step giant-step.
     */
    private static final BigInteger DEFAULT_PLAINTEXT_LIMIT = BigInteger.ONE.shiftLeft(20);

    /** Bit length of the prime group order r. */
    private static final int MAX_ORDER_BITS = 256;

    /** A ciphertext is a vector of DIMENSION points, a multiplied one DIMENSION^2 elements. */
    public static final int DIMENSION = 3;

    private static final BigInteger FOUR = BigInteger.valueOf(4);

    private final LightECC ec;

    /** Baby-step giant-step table on the curve, built when needed. */
    private volatile DiscreteLogTable<CurvePoint> curveTable;

    /** Baby-step giant-step table in the target group, built when needed. */
    private volatile DiscreteLogTable<Fp2> gtTable;

    /** A baby-step giant-step table: base, step size, baby steps and the giant step. */
    private record DiscreteLogTable<T>(T base, long size, Map<T, Long> babySteps, T giantStep) {}

    /**
     * Builds a Freeman-Boneh-Goh-Nissim cryptosystem.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param keySize bit length of the field size p; {@code null} defaults to 1024
     * @param plaintextLimit decrypted values must be in {@code [-limit, limit]}; {@code null}
     *     defaults to {@code 2^20}. Decryption takes about {@code sqrt(limit)} steps.
     */
    public FreemanBonehGohNissim(Keys keys, Integer keySize, BigInteger plaintextLimit) {
        super(
                Algorithm.FREEMAN_BONEH_GOH_NISSIM,
                keys != null
                        ? keys
                        : generateKeys(keySize == null ? 1024 : keySize, plaintextLimit));
        KeyValue.Point generator = this.keys.publicPoint("P");
        this.ec =
                buildCurve(
                        this.keys.publicNumber("p"),
                        this.keys.publicNumber("r"),
                        generator.x(),
                        generator.y());
        this.plaintextModulo = this.keys.publicNumber("r");
        this.ciphertextModulo = this.keys.publicNumber("p");
    }

    /**
     * Builds a Freeman-Boneh-Goh-Nissim cryptosystem around an existing key pair.
     *
     * @param keys the private-public key pair
     */
    public FreemanBonehGohNissim(Keys keys) {
        this(keys, null, null);
    }

    /**
     * Returns the elliptic curve this cryptosystem operates on.
     *
     * @return the supersingular curve whose generator has prime order r
     */
    public LightECC ec() {
        return ec;
    }

    /**
     * Generates the public and private keys of the Freeman-Boneh-Goh-Nissim cryptosystem.
     *
     * @param keySize bit length of the field size p
     * @param plaintextLimit decrypted values must be in {@code [-limit, limit]}, or {@code null}
     *     for the default
     * @return the generated key pair
     * @throws IllegalArgumentException when the key size is too small or the limit too large
     */
    public static Keys generateKeys(int keySize, BigInteger plaintextLimit) {
        if (keySize < 32) {
            throw new IllegalArgumentException(
                    "Key size " + keySize + " is too small for Freeman-Boneh-Goh-Nissim");
        }

        BigInteger limit = plaintextLimit == null ? DEFAULT_PLAINTEXT_LIMIT : plaintextLimit;
        int rBits = Math.min(MAX_ORDER_BITS, keySize / 2);
        BigInteger r =
                MathUtils.randomPrime(BigInteger.TWO.pow(rBits - 1), BigInteger.TWO.pow(rBits));
        if (limit.shiftLeft(1).add(BigInteger.ONE).compareTo(r) >= 0) {
            throw new IllegalArgumentException(
                    "Plaintext limit "
                            + limit
                            + " is too large for the group order of key size "
                            + keySize);
        }

        // p = r l - 1 with 4 | l, so that p = 3 mod 4 and y^2 = x^3 + x has p + 1 = r l points
        BigInteger l =
                BigInteger.ONE.shiftLeft(keySize - rBits).divide(FOUR).multiply(FOUR).max(FOUR);
        while (!MathUtils.isPrime(r.multiply(l).subtract(BigInteger.ONE))) {
            l = l.add(FOUR);
        }
        BigInteger p = r.multiply(l).subtract(BigInteger.ONE);

        // generator P of the subgroup of order r
        CurvePoint point;
        while (true) {
            BigInteger x = MathUtils.randomInt(BigInteger.ZERO, p.subtract(BigInteger.ONE));
            List<BigInteger> roots =
                    MathUtils.sqrtMod(x.modPow(BigInteger.valueOf(3), p).add(x).mod(p), p);
            if (roots.isEmpty()) {
                continue;
            }
            LightECC unordered =
                    LightECC.customWeierstrass(
                            BigInteger.ONE, BigInteger.ZERO, p, x, roots.get(0), null);
            point = unordered.g().multiply(l);
            if (!point.equals(unordered.o())) {
                break;
            }
        }
        LightECC ec = buildCurve(p, r, point.x(), point.y());

        // secret projection v, and H = vectors orthogonal to v
        List<BigInteger> v = new ArrayList<>(DIMENSION);
        for (int i = 0; i < DIMENSION; i++) {
            v.add(MathUtils.randomInt(BigInteger.ONE, r.subtract(BigInteger.ONE)));
        }
        BigInteger[] h1;
        BigInteger[] h2;
        while (true) {
            h1 = randomOrthogonal(v, r);
            h2 = randomOrthogonal(v, r);
            // h1 and h2 must be linearly independent
            if (independent(h1, h2, r)) {
                break;
            }
        }
        BigInteger[] g = new BigInteger[DIMENSION];
        while (true) {
            BigInteger dot = BigInteger.ZERO;
            for (int i = 0; i < DIMENSION; i++) {
                g[i] = MathUtils.randomInt(BigInteger.ZERO, r.subtract(BigInteger.ONE));
                dot = dot.add(v.get(i).multiply(g[i]));
            }
            if (dot.mod(r).signum() != 0) {
                break;
            }
        }

        Keys keys = Keys.empty();
        keys.publicKey().put("p", KeyValue.of(p));
        keys.publicKey().put("r", KeyValue.of(r));
        keys.publicKey().put("P", KeyValue.point(ec.g().x(), ec.g().y()));
        keys.publicKey().put("g", KeyValue.matrix(scaledGenerators(ec, g)));
        keys.publicKey().put("h1", KeyValue.matrix(scaledGenerators(ec, h1)));
        keys.publicKey().put("h2", KeyValue.matrix(scaledGenerators(ec, h2)));
        keys.publicKey().put("limit", KeyValue.of(limit));

        keys.privateKey().put("v", KeyValue.numbers(v));
        return keys;
    }

    @Override
    public KeySpec requiredKeys() {
        return REQUIRED_KEYS;
    }

    /**
     * {@inheritDoc}
     *
     * @throws UnsupportedOperationException always: the random key of Freeman-Boneh-Goh-Nissim is a
     *     pair of scalars, see {@link #generateRandomPair()}
     */
    @Override
    public BigInteger generateRandomKey() {
        throw new UnsupportedOperationException(
                "Freeman-Boneh-Goh-Nissim requires a pair of random scalars per encryption."
                        + " Use generateRandomPair.");
    }

    /**
     * Generates the pair of random scalars required per encryption.
     *
     * @return a1 and a2 in {@code [0, r)}
     */
    public BigInteger[] generateRandomPair() {
        BigInteger upper = plaintextModulo.subtract(BigInteger.ONE);
        return new BigInteger[] {
            MathUtils.randomInt(BigInteger.ZERO, upper), MathUtils.randomInt(BigInteger.ZERO, upper)
        };
    }

    @Override
    public CipherValue encrypt(BigInteger plaintext) {
        return encrypt(plaintext, generateRandomPair());
    }

    /**
     * Encrypts a plaintext with an explicit pair of random scalars.
     *
     * @param plaintext the message to encrypt
     * @param randomPair the random scalars a1 and a2
     * @return the ciphertext: 3 points of {@code m g + a1 h1 + a2 h2}
     */
    public CipherValue encrypt(BigInteger plaintext, BigInteger[] randomPair) {
        BigInteger message = plaintext.mod(plaintextModulo);
        List<CurvePoint> g = publicPoints("g");
        List<CurvePoint> h1 = publicPoints("h1");
        List<CurvePoint> h2 = publicPoints("h2");

        List<CipherValue> points = new ArrayList<>(DIMENSION);
        for (int i = 0; i < DIMENSION; i++) {
            CurvePoint point =
                    g.get(i)
                            .multiply(message)
                            .add(h1.get(i).multiply(randomPair[0]))
                            .add(h2.get(i).multiply(randomPair[1]));
            points.add(PointValue.from(point));
        }
        return TupleValue.of(points);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Accepts 3 points, or 9 elements of {@code F_{p^2}} for a multiplied ciphertext. The
     * restored message is in {@code [0, r)}.
     */
    @Override
    public BigInteger decrypt(CipherValue ciphertext) {
        BigInteger r = plaintextModulo;
        BigInteger p = ciphertextModulo;
        List<BigInteger> v = keys.privateNumbers("v");
        List<CipherValue> items = asTuple(ciphertext).items();

        if (isMultiplied(ciphertext)) {
            // product of e(C_i, C'_j)^(v_i v_j) = e(pi(C), pi(C'))
            Fp2 projected = Fp2.one();
            for (int index = 0; index < items.size(); index++) {
                int i = index / DIMENSION;
                int j = index % DIMENSION;
                Fp2 element = toFp2(items.get(index));
                projected =
                        projected.multiply(element.pow(v.get(i).multiply(v.get(j)).mod(r), p), p);
            }
            return discreteLogGt(projected).mod(r);
        }

        return discreteLogCurve(project(toPoints(ciphertext))).mod(r);
    }

    /**
     * {@inheritDoc}
     *
     * <p>A fresh ciphertext is paired with g before it is added to a multiplied one.
     */
    @Override
    public CipherValue add(CipherValue ciphertext1, CipherValue ciphertext2) {
        BigInteger p = ciphertextModulo;
        boolean multiplied1 = isMultiplied(ciphertext1);
        boolean multiplied2 = isMultiplied(ciphertext2);

        if (!multiplied1 && !multiplied2) {
            List<CurvePoint> points1 = toPoints(ciphertext1);
            List<CurvePoint> points2 = toPoints(ciphertext2);
            List<CipherValue> sum = new ArrayList<>(DIMENSION);
            for (int i = 0; i < DIMENSION; i++) {
                sum.add(PointValue.from(points1.get(i).add(points2.get(i))));
            }
            return TupleValue.of(sum);
        }

        // E(m g + h, g) is an encryption of m as a multiplied ciphertext
        List<CurvePoint> g = publicPoints("g");
        List<Fp2> elements1 =
                multiplied1 ? toElements(ciphertext1) : pair(toPoints(ciphertext1), g);
        List<Fp2> elements2 =
                multiplied2 ? toElements(ciphertext2) : pair(toPoints(ciphertext2), g);
        List<CipherValue> sum = new ArrayList<>(elements1.size());
        for (int i = 0; i < elements1.size(); i++) {
            sum.add(Fp2Value.from(elements1.get(i).multiply(elements2.get(i), p)));
        }
        return TupleValue.of(sum);
    }

    /**
     * {@inheritDoc}
     *
     * <p>It costs 9 pairings, and the result is 9 elements of {@code F_{p^2}}.
     */
    @Override
    public CipherValue multiply(CipherValue ciphertext1, CipherValue ciphertext2) {
        if (isMultiplied(ciphertext1) || isMultiplied(ciphertext2)) {
            throw new IllegalArgumentException(
                    "Freeman-Boneh-Goh-Nissim supports only one multiplication. "
                            + "Multiplied ciphertexts cannot be multiplied with"
                            + " ciphertexts again.");
        }
        List<CipherValue> elements = new ArrayList<>(DIMENSION * DIMENSION);
        for (Fp2 element : pair(toPoints(ciphertext1), toPoints(ciphertext2))) {
            elements.add(Fp2Value.from(element));
        }
        return TupleValue.of(elements);
    }

    @Override
    public CipherValue multiplyByConstant(CipherValue ciphertext, BigInteger constant) {
        BigInteger scalar = constant.mod(plaintextModulo);
        List<CipherValue> scaled = new ArrayList<>();

        if (isMultiplied(ciphertext)) {
            for (Fp2 element : toElements(ciphertext)) {
                scaled.add(Fp2Value.from(element.pow(scalar, ciphertextModulo)));
            }
            return TupleValue.of(scaled);
        }
        for (CurvePoint point : toPoints(ciphertext)) {
            scaled.add(PointValue.from(point.multiply(scalar)));
        }
        return TupleValue.of(scaled);
    }

    /**
     * {@inheritDoc}
     *
     * @throws IllegalArgumentException when the ciphertext is multiplied
     */
    @Override
    public CipherValue reencrypt(CipherValue ciphertext) {
        if (isMultiplied(ciphertext)) {
            throw new IllegalArgumentException(
                    "Freeman-Boneh-Goh-Nissim can re-encrypt non-multiplied ciphertexts only");
        }
        return add(ciphertext, encrypt(BigInteger.ZERO));
    }

    /** Tensor product of two vectors of points with the pairing: {@code e(C_i, C'_j)}. */
    private List<Fp2> pair(List<CurvePoint> points1, List<CurvePoint> points2) {
        List<Fp2> result = new ArrayList<>(DIMENSION * DIMENSION);
        for (CurvePoint x : points1) {
            for (CurvePoint y : points2) {
                result.add(pairing(x, y));
            }
        }
        return result;
    }

    private Fp2 pairing(CurvePoint x, CurvePoint y) {
        if (x.equals(ec.o()) || y.equals(ec.o())) {
            return Fp2.one();
        }
        PairingResult result = ec.pairing(x, y);
        return result.extended() ? result.value() : Fp2.fromBase(result.base());
    }

    /** Secret projection {@code pi(C) = v1 C1 + v2 C2 + v3 C3}, which vanishes on H. */
    private CurvePoint project(List<CurvePoint> points) {
        List<BigInteger> v = keys.privateNumbers("v");
        CurvePoint result = ec.o();
        for (int i = 0; i < DIMENSION; i++) {
            result = result.add(points.get(i).multiply(v.get(i)));
        }
        return result;
    }

    /** Finds m in {@code [-limit, limit]} such that {@code target = m pi(g)}. */
    private BigInteger discreteLogCurve(CurvePoint target) {
        DiscreteLogTable<CurvePoint> table = curveTable;
        if (table == null) {
            CurvePoint base = project(publicPoints("g"));
            long size = tableSize();
            Map<CurvePoint, Long> babySteps = new HashMap<>();
            CurvePoint current = ec.o();
            for (long j = 0; j < size; j++) {
                babySteps.putIfAbsent(current, j);
                current = current.add(base);
            }
            // giant step is -size * base, and the search starts from target + limit * base
            table =
                    new DiscreteLogTable<>(
                            base,
                            size,
                            babySteps,
                            base.multiply(BigInteger.valueOf(size).negate()));
            curveTable = table;
        }

        BigInteger limit = keys.publicNumber("limit");
        CurvePoint current = target.add(table.base().multiply(limit));
        for (long i = 0; i <= table.size(); i++) {
            Long j = table.babySteps().get(current);
            if (j != null) {
                BigInteger candidate = BigInteger.valueOf(i * table.size() + j).subtract(limit);
                if (candidate.abs().compareTo(limit) <= 0) {
                    return candidate;
                }
            }
            current = current.add(table.giantStep());
        }
        throw outOfRange(limit);
    }

    /** Finds m in {@code [-limit, limit]} such that {@code target = e(pi(g), pi(g))^m}. */
    private BigInteger discreteLogGt(Fp2 target) {
        BigInteger p = ciphertextModulo;
        DiscreteLogTable<Fp2> table = gtTable;
        if (table == null) {
            CurvePoint projectedG = project(publicPoints("g"));
            Fp2 base = pairing(projectedG, projectedG);
            long size = tableSize();
            Map<Fp2, Long> babySteps = new HashMap<>();
            Fp2 current = Fp2.one();
            for (long j = 0; j < size; j++) {
                babySteps.putIfAbsent(current, j);
                current = current.multiply(base, p);
            }
            table =
                    new DiscreteLogTable<>(
                            base,
                            size,
                            babySteps,
                            base.pow(BigInteger.valueOf(size), p).inverse(p));
            gtTable = table;
        }

        BigInteger limit = keys.publicNumber("limit");
        Fp2 current = target.multiply(table.base().pow(limit, p), p);
        for (long i = 0; i <= table.size(); i++) {
            Long j = table.babySteps().get(current);
            if (j != null) {
                BigInteger candidate = BigInteger.valueOf(i * table.size() + j).subtract(limit);
                if (candidate.abs().compareTo(limit) <= 0) {
                    return candidate;
                }
            }
            current = current.multiply(table.giantStep(), p);
        }
        throw outOfRange(limit);
    }

    private long tableSize() {
        return keys.publicNumber("limit").shiftLeft(1).sqrt().longValueExact() + 1;
    }

    private static IllegalArgumentException outOfRange(BigInteger limit) {
        return new IllegalArgumentException(
                "Decryption failed, because result is out of [-"
                        + limit
                        + ", "
                        + limit
                        + "]. Set a greater plaintext_limit while building the cryptosystem.");
    }

    private List<CurvePoint> publicPoints(String field) {
        List<CurvePoint> points = new ArrayList<>(DIMENSION);
        for (List<BigInteger> coordinates : keys.publicMatrix(field)) {
            points.add(ec.point(coordinates.get(0), coordinates.get(1)));
        }
        return points;
    }

    private List<CurvePoint> toPoints(CipherValue ciphertext) {
        List<CurvePoint> points = new ArrayList<>(DIMENSION);
        for (CipherValue item : asTuple(ciphertext).items()) {
            if (!(item instanceof PointValue point)) {
                throw new IllegalArgumentException(
                        "expected an elliptic curve point, got " + item.getClass().getSimpleName());
            }
            points.add(point.infinity() ? ec.o() : ec.point(point.x(), point.y()));
        }
        return points;
    }

    private static List<Fp2> toElements(CipherValue ciphertext) {
        List<Fp2> elements = new ArrayList<>(DIMENSION * DIMENSION);
        for (CipherValue item : asTuple(ciphertext).items()) {
            elements.add(toFp2(item));
        }
        return elements;
    }

    private static Fp2 toFp2(CipherValue item) {
        if (!(item instanceof Fp2Value value)) {
            throw new IllegalArgumentException(
                    "expected an F_{p^2} element, got " + item.getClass().getSimpleName());
        }
        return value.toFp2();
    }

    private static boolean isMultiplied(CipherValue ciphertext) {
        return asTuple(ciphertext).size() == DIMENSION * DIMENSION;
    }

    /** Random vector x in {@code Z_r^3} such that {@code v . x = 0 mod r}. */
    private static BigInteger[] randomOrthogonal(List<BigInteger> v, BigInteger r) {
        BigInteger upper = r.subtract(BigInteger.ONE);
        BigInteger x1 = MathUtils.randomInt(BigInteger.ZERO, upper);
        BigInteger x2 = MathUtils.randomInt(BigInteger.ZERO, upper);
        BigInteger x3 =
                v.get(0)
                        .multiply(x1)
                        .add(v.get(1).multiply(x2))
                        .negate()
                        .multiply(v.get(2).modInverse(r))
                        .mod(r);
        return new BigInteger[] {x1, x2, x3};
    }

    private static boolean independent(BigInteger[] h1, BigInteger[] h2, BigInteger r) {
        for (int i = 0; i < DIMENSION; i++) {
            for (int j = i + 1; j < DIMENSION; j++) {
                if (h1[i].multiply(h2[j]).subtract(h1[j].multiply(h2[i])).mod(r).signum() != 0) {
                    return true;
                }
            }
        }
        return false;
    }

    private static List<List<BigInteger>> scaledGenerators(LightECC ec, BigInteger[] scalars) {
        List<List<BigInteger>> points = new ArrayList<>(DIMENSION);
        for (BigInteger scalar : scalars) {
            CurvePoint point = ec.g().multiply(scalar);
            points.add(List.of(point.x(), point.y()));
        }
        return points;
    }

    /** Supersingular curve {@code y^2 = x^3 + x} over {@code F_p} whose generator has order r. */
    private static LightECC buildCurve(BigInteger p, BigInteger r, BigInteger x, BigInteger y) {
        return LightECC.customWeierstrass(BigInteger.ONE, BigInteger.ZERO, p, x, y, r);
    }
}
