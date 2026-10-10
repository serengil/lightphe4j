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
 * Castagnos-Laguillaumie, homomorphic with respect to the addition. It also supports multiplying a
 * ciphertext by a known plain constant.
 *
 * <p>It is an ElGamal-like scheme in the class group of an imaginary quadratic order of
 * discriminant {@code Δp = -p^3 q}, which has a subgroup F of order p with an easy discrete
 * logarithm. So, decryption does not require brute force.
 *
 * <p>Ref: Castagnos, G., Laguillaumie, F. (2015). <a
 * href="https://eprint.iacr.org/2015/047">Linearly Homomorphic Encryption from DDH</a>. CT-RSA
 * 2015.
 */
public final class CastagnosLaguillaumie extends AbstractHomomorphic {

    /** The key fields Castagnos-Laguillaumie requires. */
    public static final KeySpec REQUIRED_KEYS =
            KeySpec.of(List.of("p", "q", "g", "h"), List.of("x"));

    private static final Logger logger = Logger.forModule(CastagnosLaguillaumie.class);

    private static final BigInteger FOUR = BigInteger.valueOf(4);
    private static final BigInteger THREE = BigInteger.valueOf(3);

    private final BigInteger deltaK;
    private final BigInteger deltaP;
    private final BigInteger bound;

    /**
     * A binary quadratic form {@code ax^2 + bxy + cy^2}.
     *
     * @param a the first coefficient
     * @param b the second coefficient
     * @param c the third coefficient
     */
    record Form(BigInteger a, BigInteger b, BigInteger c) {

        static Form of(List<BigInteger> values) {
            return new Form(values.get(0), values.get(1), values.get(2));
        }

        List<BigInteger> values() {
            return List.of(a, b, c);
        }
    }

    /**
     * Builds a Castagnos-Laguillaumie cryptosystem.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param keySize bit length of the fundamental discriminant {@code Δk = -pq}; {@code null}
     *     defaults to 1024
     * @param maxTries maximum attempts to generate keys
     */
    public CastagnosLaguillaumie(Keys keys, Integer keySize, int maxTries) {
        super(
                Algorithm.CASTAGNOS_LAGUILLAUMIE,
                keys != null ? keys : generateKeys(keySize == null ? 1024 : keySize, maxTries));
        BigInteger p = this.keys.publicNumber("p");
        BigInteger q = this.keys.publicNumber("q");

        this.deltaK = p.multiply(q).negate();
        this.deltaP = p.multiply(p).multiply(deltaK);
        this.bound = findBound(deltaK);

        this.plaintextModulo = p;
        this.ciphertextModulo = deltaP.negate();
    }

    /**
     * Builds a Castagnos-Laguillaumie cryptosystem around an existing key pair.
     *
     * @param keys the private-public key pair
     */
    public CastagnosLaguillaumie(Keys keys) {
        this(keys, null, CryptosystemFactory.DEFAULT_MAX_TRIES);
    }

    /**
     * Generates the public and private keys of the Castagnos-Laguillaumie cryptosystem.
     *
     * @param keySize bit length of the fundamental discriminant {@code Δk = -pq}
     * @param maxTries maximum number of tries to generate keys
     * @return the generated key pair
     */
    public static Keys generateKeys(int keySize, int maxTries) {
        // p defines the message space Z_p. q must be greater than 4p to keep the forms of the
        // subgroup F reduced.
        int pSize = Math.max(4, keySize / 4);
        int qSize = keySize - pSize;

        for (int attempt = 0; attempt < maxTries; attempt++) {
            BigInteger p =
                    MathUtils.randomPrime(
                            BigInteger.TWO.pow(pSize - 1),
                            BigInteger.TWO.pow(pSize).subtract(BigInteger.ONE));
            BigInteger q =
                    MathUtils.randomPrime(
                            BigInteger.TWO.pow(qSize - 1),
                            BigInteger.TWO.pow(qSize).subtract(BigInteger.ONE));

            // pq = 3 mod 4 makes Δk = -pq a fundamental discriminant
            if (!p.multiply(q).mod(FOUR).equals(THREE) || MathUtils.jacobiSymbol(p, q) != -1) {
                continue;
            }

            BigInteger deltaK = p.multiply(q).negate();
            BigInteger deltaP = p.multiply(p).multiply(deltaK);

            Form g = findGenerator(p, q, deltaK, deltaP);
            if (g == null) {
                continue;
            }

            BigInteger x = MathUtils.randomInt(BigInteger.ONE, findBound(deltaK));
            Form h = pow(g, x, deltaP);

            Keys keys = Keys.empty();
            keys.privateKey().put("x", KeyValue.of(x));
            keys.publicKey().put("p", KeyValue.of(p));
            keys.publicKey().put("q", KeyValue.of(q));
            keys.publicKey().put("g", KeyValue.numbers(g.values()));
            keys.publicKey().put("h", KeyValue.numbers(h.values()));
            return keys;
        }
        throw new IllegalStateException("Failed to generate keys after " + maxTries + " attempts");
    }

    @Override
    public KeySpec requiredKeys() {
        return REQUIRED_KEYS;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Castagnos-Laguillaumie draws a fresh random exponent per encryption.
     */
    @Override
    public BigInteger generateRandomKey() {
        return MathUtils.randomInt(BigInteger.ONE, bound);
    }

    @Override
    public CipherValue encrypt(BigInteger plaintext) {
        return encrypt(plaintext, generateRandomKey());
    }

    /**
     * Encrypts a plaintext with an explicit random exponent.
     *
     * @param plaintext the message to encrypt in {@code [0, p)}
     * @param randomKey the random exponent
     * @return the ciphertext, the pair of forms {@code (g^r, f^m h^r)}
     */
    public CipherValue encrypt(BigInteger plaintext, BigInteger randomKey) {
        Form g = Form.of(keys.publicNumbers("g"));
        Form h = Form.of(keys.publicNumbers("h"));

        Form c1 = pow(g, randomKey, deltaP);
        Form c2 = compose(fPow(plaintext), pow(h, randomKey, deltaP), deltaP);
        return pairValue(c1, c2);
    }

    @Override
    public BigInteger decrypt(CipherValue ciphertext) {
        BigInteger p = keys.publicNumber("p");
        BigInteger x = keys.privateNumber("x");
        Form[] pair = asPair(ciphertext);

        // f^m = c2 / c1^x
        Form fm = compose(pair[1], inverse(pow(pair[0], x, deltaP)), deltaP);
        if (fm.equals(identity(deltaP))) {
            return BigInteger.ZERO;
        }

        // discrete logarithm in F is easy: f^m = (p^2, L(m) p, *)
        // where L(m) is congruent to m^-1 modulo p
        if (!fm.a().equals(p.multiply(p)) || fm.b().mod(p).signum() != 0) {
            throw new IllegalArgumentException(
                    "Decryption failed. Ciphertext does not belong to keys.");
        }
        return fm.b().divide(p).mod(p).modInverse(p);
    }

    /**
     * {@inheritDoc}
     *
     * <p>The result equals {@code E(m1 + m2)}.
     */
    @Override
    public CipherValue add(CipherValue ciphertext1, CipherValue ciphertext2) {
        Form[] first = asPair(ciphertext1);
        Form[] second = asPair(ciphertext2);
        return pairValue(
                compose(first[0], second[0], deltaP), compose(first[1], second[1], deltaP));
    }

    /**
     * {@inheritDoc}
     *
     * <p>The result equals {@code E(m * constant)}.
     */
    @Override
    public CipherValue multiplyByConstant(CipherValue ciphertext, BigInteger constant) {
        BigInteger scalar = constant;
        if (scalar.compareTo(plaintextModulo) >= 0) {
            scalar = scalar.mod(plaintextModulo);
            BigInteger normalized = scalar;
            logger.debug(
                    () ->
                            "Castagnos-Laguillaumie can encrypt messages [0, "
                                    + plaintextModulo
                                    + "). Seems constant exceeded this limit. New constant is "
                                    + normalized);
        }
        Form[] pair = asPair(ciphertext);
        return pairValue(pow(pair[0], scalar, deltaP), pow(pair[1], scalar, deltaP));
    }

    @Override
    public CipherValue reencrypt(CipherValue ciphertext) {
        CipherValue neutralEncrypted = encrypt(BigInteger.ZERO);
        return add(ciphertext, neutralEncrypted);
    }

    /**
     * Computes {@code f^m} in closed form, where {@code f = (p^2, p, *)} generates the subgroup F
     * of order p.
     */
    private Form fPow(BigInteger m) {
        BigInteger p = keys.publicNumber("p");
        BigInteger reduced = m.mod(p);
        if (reduced.signum() == 0) {
            return identity(deltaP);
        }

        // L(m) is the odd integer in [-p, p] congruent to m^-1 modulo p
        BigInteger l = reduced.modInverse(p);
        if (!l.testBit(0)) {
            l = l.subtract(p);
        }

        BigInteger a = p.multiply(p);
        BigInteger b = l.multiply(p);
        return reduce(new Form(a, b, formC(a, b, deltaP)));
    }

    /**
     * Upper bound for exponents. Class number of {@code Δk} is about {@code sqrt(|Δk|) log(|Δk|)},
     * and an additional 40 bits makes exponents statistically close to uniform.
     */
    private static BigInteger findBound(BigInteger deltaK) {
        BigInteger magnitude = deltaK.negate();
        return magnitude.sqrt().multiply(BigInteger.valueOf(magnitude.bitLength())).shiftLeft(40);
    }

    /**
     * Finds {@code g = [φp^-1(r^2)]^p} where r is an ideal above a small split prime. Then g
     * belongs to the subgroup of p-th powers in {@code Cl(Δp)}.
     */
    private static Form findGenerator(
            BigInteger p, BigInteger q, BigInteger deltaK, BigInteger deltaP) {
        for (int candidate = 3; candidate < 10000; candidate += 2) {
            BigInteger r = BigInteger.valueOf(candidate);
            if (!MathUtils.isPrime(r) || r.equals(p) || r.equals(q)) {
                continue;
            }
            if (MathUtils.jacobiSymbol(deltaK, r) != 1) {
                continue;
            }

            // prime form above r in Cl(Δk). b must be odd and b^2 = Δk mod 4r
            List<BigInteger> roots = MathUtils.sqrtMod(deltaK, r);
            if (roots.isEmpty()) {
                continue;
            }
            BigInteger b = roots.get(0);
            if (!b.testBit(0)) {
                b = r.subtract(b);
            }
            Form rForm = new Form(r, b, formC(r, b, deltaK));

            // squaring prevents being in 2-torsion of the class group
            Form r2 = compose(rForm, rForm, deltaK);
            if (r2.a().mod(p).signum() == 0) {
                continue;
            }

            // lift from Cl(Δk) to Cl(Δp) via φp^-1(a, b, c) = (a, bp, cp^2)
            Form lifted =
                    reduce(new Form(r2.a(), r2.b().multiply(p), r2.c().multiply(p).multiply(p)));
            Form g = pow(lifted, p, deltaP);

            if (!g.equals(identity(deltaP))) {
                return g;
            }
        }
        return null;
    }

    // -----------------------------------------------------------------------
    // Binary quadratic form arithmetic
    // Ref: Cohen, H. (1993). A Course in Computational Algebraic Number Theory.
    // -----------------------------------------------------------------------

    /** Principal form of the class group for a discriminant {@code delta = 1 mod 4}. */
    private static Form identity(BigInteger delta) {
        return new Form(
                BigInteger.ONE, BigInteger.ONE, BigInteger.ONE.subtract(delta).divide(FOUR));
    }

    /** Inverse of a reduced form in the class group. */
    private static Form inverse(Form f) {
        return reduce(new Form(f.a(), f.b().negate(), f.c()));
    }

    /** Completes a form of discriminant delta: {@code c = (b^2 - delta) / 4a}. */
    private static BigInteger formC(BigInteger a, BigInteger b, BigInteger delta) {
        return b.multiply(b).subtract(delta).divide(FOUR.multiply(a));
    }

    /** Finds the equivalent form with {@code -a < b <= a}. */
    private static Form normalize(Form f) {
        BigInteger twoA = f.a().shiftLeft(1);
        BigInteger r = floorDiv(f.a().subtract(f.b()), twoA);
        BigInteger b = f.b().add(twoA.multiply(r));
        BigInteger c = f.a().multiply(r).multiply(r).add(f.b().multiply(r)).add(f.c());
        return new Form(f.a(), b, c);
    }

    /**
     * Finds the unique reduced form equivalent to f, i.e. {@code |b| <= a <= c}, and {@code b >= 0}
     * if {@code a = |b|} or {@code a = c} (Cohen Algorithm 5.4.2).
     */
    private static Form reduce(Form f) {
        Form current = f;
        if (!(current.a().negate().compareTo(current.b()) < 0
                && current.b().compareTo(current.a()) <= 0)) {
            current = normalize(current);
        }

        while (current.a().compareTo(current.c()) > 0) {
            current = normalize(new Form(current.c(), current.b().negate(), current.a()));
        }

        if (current.a().equals(current.c()) && current.b().signum() < 0) {
            current = new Form(current.a(), current.b().negate(), current.c());
        }
        return current;
    }

    /** Composition of two forms with discriminant delta (Cohen Algorithm 5.4.7). */
    private static Form compose(Form f1, Form f2, BigInteger delta) {
        Form first = f1;
        Form second = f2;
        if (first.a().compareTo(second.a()) > 0) {
            first = f2;
            second = f1;
        }
        BigInteger a1 = first.a();
        BigInteger b1 = first.b();
        BigInteger a2 = second.a();
        BigInteger b2 = second.b();
        BigInteger c2 = second.c();

        BigInteger s = b1.add(b2).divide(BigInteger.TWO);
        BigInteger n = b2.subtract(s);

        BigInteger y1;
        BigInteger d;
        if (a2.mod(a1).signum() == 0) {
            y1 = BigInteger.ZERO;
            d = a1;
        } else {
            BigInteger[] gcd = xgcd(a2, a1);
            d = gcd[0];
            y1 = gcd[1];
        }

        BigInteger x2;
        BigInteger y2;
        BigInteger d1;
        if (s.mod(d).signum() == 0) {
            y2 = BigInteger.ONE.negate();
            x2 = BigInteger.ZERO;
            d1 = d;
        } else {
            BigInteger[] gcd = xgcd(s, d);
            d1 = gcd[0];
            x2 = gcd[1];
            y2 = gcd[2].negate();
        }

        BigInteger v1 = a1.divide(d1);
        BigInteger v2 = a2.divide(d1);
        BigInteger r = y1.multiply(y2).multiply(n).subtract(x2.multiply(c2)).mod(v1);
        BigInteger b3 = b2.add(BigInteger.TWO.multiply(v2).multiply(r));
        BigInteger a3 = v1.multiply(v2);
        return reduce(new Form(a3, b3, formC(a3, b3, delta)));
    }

    /** Exponentiation in the class group with square and multiply. */
    private static Form pow(Form f, BigInteger exponent, BigInteger delta) {
        Form result = identity(delta);
        Form base = f;
        BigInteger e = exponent;
        while (e.signum() > 0) {
            if (e.testBit(0)) {
                result = compose(result, base, delta);
            }
            base = compose(base, base, delta);
            e = e.shiftRight(1);
        }
        return result;
    }

    /**
     * Extended euclidean algorithm with floor division, matching the Python reference.
     *
     * @return {@code [d, u, v]} such that {@code u a + v b = d = gcd(a, b)}
     */
    private static BigInteger[] xgcd(BigInteger a, BigInteger b) {
        BigInteger x = a;
        BigInteger y = b;
        BigInteger u0 = BigInteger.ONE;
        BigInteger u1 = BigInteger.ZERO;
        BigInteger v0 = BigInteger.ZERO;
        BigInteger v1 = BigInteger.ONE;
        while (y.signum() != 0) {
            BigInteger quotient = floorDiv(x, y);
            BigInteger nextY = x.subtract(quotient.multiply(y));
            x = y;
            y = nextY;
            BigInteger nextU = u0.subtract(quotient.multiply(u1));
            u0 = u1;
            u1 = nextU;
            BigInteger nextV = v0.subtract(quotient.multiply(v1));
            v0 = v1;
            v1 = nextV;
        }
        return new BigInteger[] {x, u0, v0};
    }

    /** Division rounding towards negative infinity, like Python's {@code //}. */
    private static BigInteger floorDiv(BigInteger a, BigInteger b) {
        BigInteger[] division = a.divideAndRemainder(b);
        if (division[1].signum() != 0 && (division[1].signum() < 0) != (b.signum() < 0)) {
            return division[0].subtract(BigInteger.ONE);
        }
        return division[0];
    }

    private static CipherValue formValue(Form f) {
        return TupleValue.of(IntValue.of(f.a()), IntValue.of(f.b()), IntValue.of(f.c()));
    }

    private static CipherValue pairValue(Form c1, Form c2) {
        return TupleValue.of(formValue(c1), formValue(c2));
    }

    private static Form[] asPair(CipherValue value) {
        TupleValue pair = asTuple(value);
        if (pair.size() != 2) {
            throw new IllegalArgumentException(
                    "expected a ciphertext pair, got " + pair.size() + " components");
        }
        return new Form[] {asForm(pair.get(0)), asForm(pair.get(1))};
    }

    private static Form asForm(CipherValue value) {
        TupleValue form = asTuple(value);
        if (form.size() != 3) {
            throw new IllegalArgumentException(
                    "a form needs 3 integers, got " + form.size() + " components");
        }
        return new Form(asInt(form.get(0)), asInt(form.get(1)), asInt(form.get(2)));
    }
}
