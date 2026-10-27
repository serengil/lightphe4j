package io.github.serengil.lightphe.commons;

import io.github.serengil.lightphe.ecc.CurvePoint;
import io.github.serengil.lightphe.ecc.LightECC;
import io.github.serengil.lightphe.model.Homomorphic;
import io.github.serengil.lightphe.model.KeyValue;
import io.github.serengil.lightphe.model.Proof;
import io.github.serengil.lightphe.model.Proven;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.IntValue;
import io.github.serengil.lightphe.model.value.PointValue;
import io.github.serengil.lightphe.model.value.TupleValue;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Zero-knowledge proofs, the counterpart of {@code lightphe.commons.zkp}.
 *
 * <p>Proofs are made non-interactive with the Fiat-Shamir heuristic. Challenge is the hash of
 * everything the verifier sees, so the prover cannot pick it. The transcript is serialised exactly
 * as {@code json.dumps} of the Python library does, so a proof created by one library is verified
 * by the other.
 *
 * <p>Context of a proof is public data bound to it, e.g. id of a voter. It may be {@code null}, a
 * string, a number, a boolean, a list or a map of them.
 *
 * <p>Ref: Fiat &amp; Shamir, "How to prove yourself", 1986
 *
 * <p>Ref: Chaum &amp; Pedersen, "Wallet databases with observers", 1992
 */
public final class Zkp {

    /** Challenge length of proofs in groups of unknown order in bits. */
    public static final int CHALLENGE_BITS = 128;

    /** Statistical hiding of responses in groups of unknown order, in bits. */
    public static final int STATISTICAL_BITS = 80;

    private Zkp() {
        throw new AssertionError("no instances");
    }

    // -----------------------------------------------------------------------
    // Fiat-Shamir challenge
    // -----------------------------------------------------------------------

    /**
     * Fiat-Shamir challenge as the hash of a domain and all public items of a proof.
     *
     * @param domain separates challenges of different proofs
     * @param modulo challenge is reduced in this modulo, e.g. order of the group
     * @param items public items of the proof
     * @return the challenge
     */
    public static BigInteger challenge(String domain, BigInteger modulo, Object... items) {
        StringBuilder transcript = new StringBuilder();
        writeJson(transcript, Arrays.asList(domain, Arrays.asList(items)));
        try {
            byte[] digest =
                    MessageDigest.getInstance("SHA-512")
                            .digest(transcript.toString().getBytes(StandardCharsets.UTF_8));
            return new BigInteger(1, digest).mod(modulo);
        } catch (NoSuchAlgorithmException err) {
            throw new IllegalStateException("SHA-512 is not available", err);
        }
    }

    /**
     * Writes an item as compact json, the same as {@code json.dumps(canonicalize(item),
     * separators=(",", ":"))} of the Python library. Tuples, lists and points are written as lists.
     */
    private static void writeJson(StringBuilder out, Object item) {
        if (item == null) {
            out.append("null");
        } else if (item instanceof Boolean bool) {
            out.append(bool ? "true" : "false");
        } else if (item instanceof BigInteger
                || item instanceof Long
                || item instanceof Integer
                || item instanceof Short
                || item instanceof Byte) {
            out.append(item);
        } else if (item instanceof Double || item instanceof Float) {
            // floats are canonicalized into strings
            writeString(out, item.toString());
        } else if (item instanceof CharSequence text) {
            writeString(out, text.toString());
        } else if (item instanceof IntValue value) {
            out.append(value.value());
        } else if (item instanceof PointValue point) {
            if (point.infinity()) {
                writeJson(out, List.of("inf", "inf"));
            } else {
                writeJson(out, List.of(point.x(), point.y()));
            }
        } else if (item instanceof TupleValue tuple) {
            writeJson(out, tuple.items());
        } else if (item instanceof CurvePoint point) {
            writeJson(out, PointValue.from(point));
        } else if (item instanceof KeyValue.Point point) {
            writeJson(out, List.of(point.x(), point.y()));
        } else if (item instanceof Map<?, ?> map) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                writeString(out, String.valueOf(entry.getKey()));
                out.append(':');
                writeJson(out, entry.getValue());
            }
            out.append('}');
        } else if (item instanceof Iterable<?> iterable) {
            out.append('[');
            boolean first = true;
            for (Object element : iterable) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                writeJson(out, element);
            }
            out.append(']');
        } else if (item instanceof Object[] array) {
            writeJson(out, Arrays.asList(array));
        } else {
            throw new IllegalArgumentException(
                    "Context of a proof must be json serializable, got "
                            + item.getClass().getSimpleName());
        }
    }

    /** Writes a json string escaping non-ascii characters as json.dumps does by default. */
    private static void writeString(StringBuilder out, String text) {
        out.append('"');
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                default -> {
                    if (c < 0x20 || c > 0x7f) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    // -----------------------------------------------------------------------
    // Groups of a known prime order
    // -----------------------------------------------------------------------

    /**
     * A cyclic group of a known prime order q used in proofs.
     *
     * @param <E> type of the group elements
     */
    public interface PrimeOrderGroup<E> {

        /**
         * Returns the prime order of the group.
         *
         * @return q
         */
        BigInteger q();

        /**
         * Raises an element to a power.
         *
         * @param base the element
         * @param k the exponent, reduced modulo q
         * @return {@code base^k}
         */
        E exp(E base, BigInteger k);

        /**
         * Applies the group operation.
         *
         * @param a first element
         * @param b second element
         * @return {@code a * b}
         */
        E mul(E a, E b);

        /**
         * Reports whether an element belongs to the group of prime order.
         *
         * @param a the element
         * @return {@code true} for a member
         */
        boolean isMember(E a);
    }

    /**
     * Subgroup of prime order q in the multiplicative group of integers modulo prime p.
     *
     * @param p the prime modulus
     * @param q the prime order of the subgroup
     */
    public record ModularGroup(BigInteger p, BigInteger q) implements PrimeOrderGroup<BigInteger> {

        @Override
        public BigInteger exp(BigInteger base, BigInteger k) {
            return base.modPow(k.mod(q), p);
        }

        @Override
        public BigInteger mul(BigInteger a, BigInteger b) {
            return a.multiply(b).mod(p);
        }

        @Override
        public boolean isMember(BigInteger a) {
            return a != null
                    && a.signum() > 0
                    && a.compareTo(p) < 0
                    && a.modPow(q, p).equals(BigInteger.ONE);
        }
    }

    /**
     * Subgroup generated by the base point of an elliptic curve. Group operation is written
     * multiplicatively here, i.e. exp is scalar multiplication and mul is addition.
     *
     * @param ecc the elliptic curve
     */
    public record EllipticCurveGroup(LightECC ecc) implements PrimeOrderGroup<CurvePoint> {

        @Override
        public BigInteger q() {
            return ecc.n();
        }

        @Override
        public CurvePoint exp(CurvePoint base, BigInteger k) {
            return base.multiply(k.mod(ecc.n()));
        }

        @Override
        public CurvePoint mul(CurvePoint a, CurvePoint b) {
            return a.add(b);
        }

        @Override
        public boolean isMember(CurvePoint a) {
            if (a == null) {
                return false;
            }
            // scalar multiplication reduces the scalar modulo n, so n a is computed as (n - 1) a +
            // a
            BigInteger n = ecc.n();
            return a.multiply(n.subtract(BigInteger.ONE)).add(a).isIdentity();
        }
    }

    // -----------------------------------------------------------------------
    // Chaum-Pedersen proofs of equality of discrete logarithms
    // -----------------------------------------------------------------------

    /**
     * Chaum-Pedersen proof that {@code log_g1(h1) = log_g2(h2) = x} without revealing x.
     *
     * @param group group of the elements
     * @param g1 first base
     * @param h1 {@code g1^x}
     * @param g2 second base
     * @param h2 {@code g2^x}
     * @param x the common discrete logarithm known by the prover
     * @param domain name of the statement being proven
     * @param context extra public data bound to the proof
     * @param <E> type of the group elements
     * @return the challenge and response
     */
    public static <E> Proof proveDleq(
            PrimeOrderGroup<E> group,
            E g1,
            E h1,
            E g2,
            E h2,
            BigInteger x,
            String domain,
            Object context) {
        BigInteger q = group.q();
        BigInteger w = MathUtils.randomInt(BigInteger.ONE, q.subtract(BigInteger.ONE));
        E a1 = group.exp(g1, w);
        E a2 = group.exp(g2, w);
        BigInteger e = challenge(domain, q, context, g1, h1, g2, h2, a1, a2);
        BigInteger z = w.add(e.multiply(x)).mod(q);
        return new Proof.ChallengeResponse(e, z);
    }

    /**
     * Verifies a Chaum-Pedersen proof that {@code log_g1(h1) = log_g2(h2)}.
     *
     * @param group group of the elements
     * @param g1 first base
     * @param h1 first power
     * @param g2 second base
     * @param h2 second power
     * @param proof output of {@link #proveDleq}
     * @param domain name of the statement being proven
     * @param context extra public data bound to the proof
     * @param <E> type of the group elements
     * @return {@code true} when the proof is valid
     */
    public static <E> boolean verifyDleq(
            PrimeOrderGroup<E> group,
            E g1,
            E h1,
            E g2,
            E h2,
            Proof proof,
            String domain,
            Object context) {
        if (!(proof instanceof Proof.ChallengeResponse response)) {
            return false;
        }
        BigInteger q = group.q();
        BigInteger e = response.challenge();
        BigInteger z = response.response();
        if (!inRange(e, q) || !inRange(z, q)) {
            return false;
        }

        // soundness requires all elements to be in the group of prime order
        for (E element : List.of(g1, h1, g2, h2)) {
            if (!group.isMember(element)) {
                return false;
            }
        }

        // a = g^z * h^(-e) is the commitment of an honest prover
        E a1 = group.mul(group.exp(g1, z), group.exp(h1, e.negate()));
        E a2 = group.mul(group.exp(g2, z), group.exp(h2, e.negate()));
        return e.equals(challenge(domain, q, context, g1, h1, g2, h2, a1, a2));
    }

    /**
     * Disjunctive Chaum-Pedersen proof that {@code log_g1(h1) = log_g2(h2)} for at least one h2 in
     * h2s, without revealing which one. Proofs of other items are simulated.
     *
     * @param group group of the elements
     * @param g1 first base
     * @param h1 {@code g1^x}
     * @param g2 second base
     * @param h2s candidates, {@code h2s[index] = g2^x}
     * @param x the common discrete logarithm known by the prover
     * @param index index of the true statement
     * @param domain name of the statement being proven
     * @param context extra public data bound to the proof
     * @param <E> type of the group elements
     * @return the challenges and responses of all statements
     */
    public static <E> Proof proveDleqOr(
            PrimeOrderGroup<E> group,
            E g1,
            E h1,
            E g2,
            List<E> h2s,
            BigInteger x,
            int index,
            String domain,
            Object context) {
        BigInteger q = group.q();
        List<BigInteger> challenges = new ArrayList<>();
        List<BigInteger> responses = new ArrayList<>();
        List<E> commitments = new ArrayList<>();
        BigInteger w = MathUtils.randomInt(BigInteger.ONE, q.subtract(BigInteger.ONE));
        for (int i = 0; i < h2s.size(); i++) {
            if (i == index) {
                challenges.add(BigInteger.ZERO);
                responses.add(BigInteger.ZERO);
                commitments.add(group.exp(g1, w));
                commitments.add(group.exp(g2, w));
                continue;
            }
            // simulated proof for a false statement
            BigInteger ei = MathUtils.randomInt(BigInteger.ZERO, q.subtract(BigInteger.ONE));
            BigInteger zi = MathUtils.randomInt(BigInteger.ZERO, q.subtract(BigInteger.ONE));
            challenges.add(ei);
            responses.add(zi);
            commitments.add(group.mul(group.exp(g1, zi), group.exp(h1, ei.negate())));
            commitments.add(group.mul(group.exp(g2, zi), group.exp(h2s.get(i), ei.negate())));
        }

        BigInteger e = challenge(domain, q, orItems(context, g1, h1, g2, h2s, commitments));
        // challenge of the true statement completes the sum
        BigInteger sum = challenges.stream().reduce(BigInteger.ZERO, BigInteger::add);
        BigInteger own = e.subtract(sum).mod(q);
        challenges.set(index, own);
        responses.set(index, w.add(own.multiply(x)).mod(q));
        return new Proof.Disjunctive(challenges, responses);
    }

    /**
     * Verifies a disjunctive Chaum-Pedersen proof.
     *
     * @param group group of the elements
     * @param g1 first base
     * @param h1 first power
     * @param g2 second base
     * @param h2s candidates, one of them is claimed to be {@code g2^log_g1(h1)}
     * @param proof output of {@link #proveDleqOr}
     * @param domain name of the statement being proven
     * @param context extra public data bound to the proof
     * @param <E> type of the group elements
     * @return {@code true} when the proof is valid
     */
    public static <E> boolean verifyDleqOr(
            PrimeOrderGroup<E> group,
            E g1,
            E h1,
            E g2,
            List<E> h2s,
            Proof proof,
            String domain,
            Object context) {
        if (!(proof instanceof Proof.Disjunctive disjunctive)) {
            return false;
        }
        List<BigInteger> challenges = disjunctive.challenges();
        List<BigInteger> responses = disjunctive.responses();
        if (challenges.size() != h2s.size() || responses.size() != h2s.size()) {
            return false;
        }
        BigInteger q = group.q();
        for (BigInteger value : challenges) {
            if (!inRange(value, q)) {
                return false;
            }
        }
        for (BigInteger value : responses) {
            if (!inRange(value, q)) {
                return false;
            }
        }

        // soundness requires all elements to be in the group of prime order
        List<E> elements = new ArrayList<>(Arrays.asList(g1, h1, g2));
        elements.addAll(h2s);
        for (E element : elements) {
            if (!group.isMember(element)) {
                return false;
            }
        }

        List<E> commitments = new ArrayList<>();
        for (int i = 0; i < h2s.size(); i++) {
            BigInteger ei = challenges.get(i);
            BigInteger zi = responses.get(i);
            commitments.add(group.mul(group.exp(g1, zi), group.exp(h1, ei.negate())));
            commitments.add(group.mul(group.exp(g2, zi), group.exp(h2s.get(i), ei.negate())));
        }

        BigInteger e = challenge(domain, q, orItems(context, g1, h1, g2, h2s, commitments));
        return challenges.stream().reduce(BigInteger.ZERO, BigInteger::add).mod(q).equals(e);
    }

    /** Items of a disjunctive challenge: context, g1, h1, g2, h2s and commitments, flattened. */
    private static <E> Object[] orItems(
            Object context, E g1, E h1, E g2, List<E> h2s, List<E> commitments) {
        List<Object> items = new ArrayList<>(Arrays.asList(context, g1, h1, g2));
        items.addAll(h2s);
        items.addAll(commitments);
        return items.toArray();
    }

    // -----------------------------------------------------------------------
    // Schnorr proofs of knowledge of a discrete logarithm
    // -----------------------------------------------------------------------

    /**
     * Schnorr proof of knowledge of {@code x = log_g(h)} without revealing x.
     *
     * @param group group of the elements
     * @param g the base
     * @param h {@code g^x}
     * @param x discrete logarithm known by the prover
     * @param domain name of the statement being proven
     * @param context extra public data bound to the proof
     * @param <E> type of the group elements
     * @return the challenge and response
     */
    public static <E> Proof proveDlog(
            PrimeOrderGroup<E> group, E g, E h, BigInteger x, String domain, Object context) {
        BigInteger q = group.q();
        BigInteger w = MathUtils.randomInt(BigInteger.ONE, q.subtract(BigInteger.ONE));
        E a = group.exp(g, w);
        BigInteger e = challenge(domain, q, context, g, h, a);
        return new Proof.ChallengeResponse(e, w.add(e.multiply(x)).mod(q));
    }

    /**
     * Verifies a Schnorr proof of knowledge of {@code log_g(h)}.
     *
     * @param group group of the elements
     * @param g the base
     * @param h the power
     * @param proof output of {@link #proveDlog}
     * @param domain name of the statement being proven
     * @param context extra public data bound to the proof
     * @param <E> type of the group elements
     * @return {@code true} when the proof is valid
     */
    public static <E> boolean verifyDlog(
            PrimeOrderGroup<E> group, E g, E h, Proof proof, String domain, Object context) {
        if (!(proof instanceof Proof.ChallengeResponse response)) {
            return false;
        }
        BigInteger q = group.q();
        BigInteger e = response.challenge();
        BigInteger z = response.response();
        if (!inRange(e, q) || !inRange(z, q)) {
            return false;
        }
        if (!group.isMember(g) || !group.isMember(h)) {
            return false;
        }

        // a = g^z * h^(-e) is the commitment of an honest prover
        E a = group.mul(group.exp(g, z), group.exp(h, e.negate()));
        return e.equals(challenge(domain, q, context, g, h, a));
    }

    // -----------------------------------------------------------------------
    // Paillier and Damgard-Jurik
    // -----------------------------------------------------------------------

    /**
     * Proof of correct decryption for Paillier and Damgard-Jurik. A ciphertext is {@code g^m * r^n
     * mod n^2}, and this is one to one for m in {@code Z_n} and r in {@code Z*_n}. So, revealing r
     * proves m without a zero-knowledge proof. Only the private key owner can recover r. It reveals
     * nothing about other ciphertexts.
     *
     * @param ciphertext the encrypted message
     * @param plaintext the restored message in modulo n
     * @param n the public modulus
     * @param phi euler's totient of n
     * @return the randomness r of the ciphertext in {@code Z*_n}
     * @throws IllegalArgumentException when the randomness cannot be recovered
     */
    public static Proof provePaillierDecryption(
            BigInteger ciphertext, BigInteger plaintext, BigInteger n, BigInteger phi) {
        BigInteger n2 = n.multiply(n);
        if (!n.gcd(phi).equals(BigInteger.ONE)) {
            throw new IllegalArgumentException(
                    "Randomness cannot be recovered because gcd(n, phi) != 1");
        }
        // c * g^-m = r^n mod n^2, and r^n mod n is enough to find r mod n
        BigInteger rn =
                ciphertext.multiply(BigInteger.ONE.add(n).modPow(plaintext.negate(), n2)).mod(n);
        return new Proof.Randomness(rn.modPow(n.modInverse(phi), n));
    }

    /**
     * Verifies a proof of correct decryption for Paillier and Damgard-Jurik.
     *
     * @param ciphertext the encrypted message
     * @param plaintext the claimed message in modulo n
     * @param proof output of {@link #provePaillierDecryption}
     * @param n the public modulus
     * @return {@code true} when the proof is valid
     */
    public static boolean verifyPaillierDecryption(
            BigInteger ciphertext, BigInteger plaintext, Proof proof, BigInteger n) {
        if (!(proof instanceof Proof.Randomness randomness)
                || plaintext == null
                || ciphertext == null) {
            return false;
        }
        BigInteger r = randomness.randomness();
        if (r.signum() <= 0
                || r.compareTo(n) >= 0
                || !r.gcd(n).equals(BigInteger.ONE)
                || !ciphertext.gcd(n).equals(BigInteger.ONE)) {
            return false;
        }
        if (plaintext.signum() < 0 || plaintext.compareTo(n) >= 0) {
            return false;
        }
        BigInteger n2 = n.multiply(n);
        return ciphertext
                .mod(n2)
                .equals(
                        BigInteger.ONE
                                .add(n)
                                .modPow(plaintext, n2)
                                .multiply(r.modPow(n, n2))
                                .mod(n2));
    }

    /**
     * Challenge length of proofs of n-th powers. Challenges must be smaller than the smallest prime
     * factor of n for soundness.
     *
     * @param n the public modulus
     * @return the number of bits
     */
    public static int nthPowerChallengeBits(BigInteger n) {
        return Math.max(1, Math.min(CHALLENGE_BITS, n.bitLength() / 2 - 2));
    }

    /**
     * Draws a random element of the multiplicative group of the modulo.
     *
     * @param n the public modulus, units are co-prime to it
     * @param modulo a power of n
     * @return the unit
     */
    public static BigInteger randomUnit(BigInteger n, BigInteger modulo) {
        while (true) {
            BigInteger r = MathUtils.randomInt(BigInteger.ONE, modulo.subtract(BigInteger.ONE));
            if (r.gcd(n).equals(BigInteger.ONE)) {
                return r;
            }
        }
    }

    /**
     * Proves that at least one of us is an n-th power in modulo, without revealing which. This is
     * the 1-out-of-k proof of Damgard &amp; Jurik, showing that a ciphertext c encrypts one of k
     * values v, where us are {@code c * g^-v}.
     *
     * @param n the public modulus
     * @param modulo {@code n^(s+1)}
     * @param us candidates, {@code us[index] = r^n mod modulo}
     * @param r the n-th root of {@code us[index]} known by the prover
     * @param index index of the true statement
     * @param domain name of the statement being proven
     * @param context extra public data bound to the proof
     * @return the challenges and responses of all statements
     */
    public static Proof proveNthPowerOr(
            BigInteger n,
            BigInteger modulo,
            List<BigInteger> us,
            BigInteger r,
            int index,
            String domain,
            Object context) {
        BigInteger bound = BigInteger.ONE.shiftLeft(nthPowerChallengeBits(n));
        List<BigInteger> challenges = new ArrayList<>();
        List<BigInteger> responses = new ArrayList<>();
        List<BigInteger> commitments = new ArrayList<>();
        BigInteger rho = randomUnit(n, modulo);
        for (int i = 0; i < us.size(); i++) {
            if (i == index) {
                challenges.add(BigInteger.ZERO);
                responses.add(BigInteger.ZERO);
                commitments.add(rho.modPow(n, modulo));
                continue;
            }
            // simulated proof for a false statement
            BigInteger ei = MathUtils.randomInt(BigInteger.ZERO, bound.subtract(BigInteger.ONE));
            BigInteger zi = randomUnit(n, modulo);
            challenges.add(ei);
            responses.add(zi);
            commitments.add(
                    zi.modPow(n, modulo)
                            .multiply(us.get(i).modPow(ei.negate(), modulo))
                            .mod(modulo));
        }

        BigInteger e = challenge(domain, bound, context, n, modulo, us, commitments);
        // challenge of the true statement completes the sum
        BigInteger sum = challenges.stream().reduce(BigInteger.ZERO, BigInteger::add);
        BigInteger own = e.subtract(sum).mod(bound);
        challenges.set(index, own);
        responses.set(index, rho.multiply(r.modPow(own, modulo)).mod(modulo));
        return new Proof.Disjunctive(challenges, responses);
    }

    /**
     * Verifies a proof that at least one of us is an n-th power in modulo.
     *
     * @param n the public modulus
     * @param modulo {@code n^(s+1)}
     * @param us the candidates
     * @param proof output of {@link #proveNthPowerOr}
     * @param domain name of the statement being proven
     * @param context extra public data bound to the proof
     * @return {@code true} when the proof is valid
     */
    public static boolean verifyNthPowerOr(
            BigInteger n,
            BigInteger modulo,
            List<BigInteger> us,
            Proof proof,
            String domain,
            Object context) {
        if (!(proof instanceof Proof.Disjunctive disjunctive)) {
            return false;
        }
        List<BigInteger> challenges = disjunctive.challenges();
        List<BigInteger> responses = disjunctive.responses();
        if (challenges.size() != us.size() || responses.size() != us.size()) {
            return false;
        }
        BigInteger bound = BigInteger.ONE.shiftLeft(nthPowerChallengeBits(n));
        for (BigInteger ei : challenges) {
            if (!inRange(ei, bound)) {
                return false;
            }
        }
        List<BigInteger> units = new ArrayList<>(responses);
        units.addAll(us);
        for (BigInteger value : units) {
            if (!isUnit(value, n, modulo)) {
                return false;
            }
        }

        List<BigInteger> commitments = new ArrayList<>();
        for (int i = 0; i < us.size(); i++) {
            commitments.add(
                    responses
                            .get(i)
                            .modPow(n, modulo)
                            .multiply(us.get(i).modPow(challenges.get(i).negate(), modulo))
                            .mod(modulo));
        }
        BigInteger e = challenge(domain, bound, context, n, modulo, us, commitments);
        return challenges.stream().reduce(BigInteger.ZERO, BigInteger::add).mod(bound).equals(e);
    }

    /**
     * Candidates {@code c * g^-v} for each value v. Ciphertext encrypts v if and only if its
     * candidate is an n-th power, i.e. an encryption of 0.
     *
     * @param ciphertext the encrypted message
     * @param values the allowed values
     * @param n the public modulus
     * @param modulo the ciphertext modulo {@code n^(s+1)}
     * @return the candidates
     */
    public static List<BigInteger> paillierMembershipCandidates(
            BigInteger ciphertext, List<BigInteger> values, BigInteger n, BigInteger modulo) {
        BigInteger g = BigInteger.ONE.add(n);
        List<BigInteger> candidates = new ArrayList<>(values.size());
        for (BigInteger value : values) {
            candidates.add(ciphertext.multiply(g.modPow(value.negate(), modulo)).mod(modulo));
        }
        return candidates;
    }

    /**
     * Proof of knowledge of plaintext m and randomness r of a Paillier or Damgard-Jurik ciphertext
     * {@code c = g^m * r^n mod n^(s+1)}, without revealing them.
     *
     * @param ciphertext the encrypted message
     * @param plaintext m known by the prover
     * @param r the randomness known by the prover
     * @param n the public modulus
     * @param modulo the ciphertext modulo {@code n^(s+1)}
     * @param domain name of the statement being proven
     * @param context extra public data bound to the proof
     * @return the challenge and responses
     */
    public static Proof provePaillierKnowledge(
            BigInteger ciphertext,
            BigInteger plaintext,
            BigInteger r,
            BigInteger n,
            BigInteger modulo,
            String domain,
            Object context) {
        BigInteger g = BigInteger.ONE.add(n);
        BigInteger bound = BigInteger.ONE.shiftLeft(nthPowerChallengeBits(n));
        BigInteger a = MathUtils.randomInt(BigInteger.ZERO, n.subtract(BigInteger.ONE));
        BigInteger b = randomUnit(n, modulo);
        BigInteger t = g.modPow(a, modulo).multiply(b.modPow(n, modulo)).mod(modulo);
        BigInteger e = challenge(domain, bound, context, n, modulo, ciphertext, t);

        // a + e * m = z_m + carry * n, and g^(carry * n) is moved into the n-th power
        BigInteger[] division = a.add(e.multiply(plaintext)).divideAndRemainder(n);
        BigInteger carry = division[0];
        BigInteger zm = division[1];
        BigInteger zr =
                b.multiply(r.modPow(e, modulo)).multiply(g.modPow(carry, modulo)).mod(modulo);
        return new Proof.PaillierKnowledge(e, zm, zr);
    }

    /**
     * Verifies a proof of knowledge of plaintext and randomness of a Paillier or Damgard-Jurik
     * ciphertext.
     *
     * @param ciphertext the encrypted message
     * @param proof output of {@link #provePaillierKnowledge}
     * @param n the public modulus
     * @param modulo the ciphertext modulo {@code n^(s+1)}
     * @param domain name of the statement being proven
     * @param context extra public data bound to the proof
     * @return {@code true} when the proof is valid
     */
    public static boolean verifyPaillierKnowledge(
            BigInteger ciphertext,
            Proof proof,
            BigInteger n,
            BigInteger modulo,
            String domain,
            Object context) {
        if (!(proof instanceof Proof.PaillierKnowledge knowledge) || ciphertext == null) {
            return false;
        }
        BigInteger e = knowledge.challenge();
        BigInteger zm = knowledge.plaintextResponse();
        BigInteger zr = knowledge.randomnessResponse();
        BigInteger bound = BigInteger.ONE.shiftLeft(nthPowerChallengeBits(n));
        if (!inRange(e, bound) || !inRange(zm, n)) {
            return false;
        }
        if (!isUnit(ciphertext, n, modulo) || !isUnit(zr, n, modulo)) {
            return false;
        }

        // t = g^z_m * z_r^n * c^-e is the commitment of an honest prover
        BigInteger g = BigInteger.ONE.add(n);
        BigInteger t =
                g.modPow(zm, modulo)
                        .multiply(zr.modPow(n, modulo))
                        .multiply(ciphertext.modPow(e.negate(), modulo))
                        .mod(modulo);
        return e.equals(challenge(domain, bound, context, n, modulo, ciphertext, t));
    }

    /**
     * Bit length of random values of proofs in groups of unknown order, so that responses hide the
     * secret statistically.
     *
     * @param n the public modulus
     * @param modulo {@code n^(s+1)}
     * @param xBits upper bound of the bit length of the secret
     * @return the number of bits
     */
    public static int dleqUnknownOrderBits(BigInteger n, BigInteger modulo, int xBits) {
        return Math.max(modulo.bitLength(), xBits) + nthPowerChallengeBits(n) + STATISTICAL_BITS;
    }

    /**
     * Proof that {@code log_g1(h1) = log_g2(h2) = x} in the group of squares modulo {@code
     * n^(s+1)}, whose order is secret. Response is computed over the integers and hides x
     * statistically. This is the proof of correct partial decryption of Shoup and Damgard-Jurik.
     *
     * @param n the public modulus, product of two safe primes
     * @param modulo {@code n^(s+1)}
     * @param g1 first base, a square
     * @param h1 {@code g1^x}
     * @param g2 second base, a square
     * @param h2 {@code g2^x}
     * @param x the common discrete logarithm known by the prover
     * @param xBits upper bound of the bit length of x
     * @param domain name of the statement being proven
     * @param context extra public data bound to the proof
     * @return the challenge and response
     */
    public static Proof proveDleqUnknownOrder(
            BigInteger n,
            BigInteger modulo,
            BigInteger g1,
            BigInteger h1,
            BigInteger g2,
            BigInteger h2,
            BigInteger x,
            int xBits,
            String domain,
            Object context) {
        BigInteger w = MathUtils.getRandomBits(dleqUnknownOrderBits(n, modulo, xBits));
        BigInteger a1 = g1.modPow(w, modulo);
        BigInteger a2 = g2.modPow(w, modulo);
        BigInteger bound = BigInteger.ONE.shiftLeft(nthPowerChallengeBits(n));
        BigInteger e = challenge(domain, bound, context, modulo, g1, h1, g2, h2, a1, a2);
        return new Proof.ChallengeResponse(e, w.add(e.multiply(x)));
    }

    /**
     * Verifies a proof that {@code log_g1(h1) = log_g2(h2)} in the group of squares modulo {@code
     * n^(s+1)}.
     *
     * @param n the public modulus, product of two safe primes
     * @param modulo {@code n^(s+1)}
     * @param g1 first base
     * @param h1 first power
     * @param g2 second base
     * @param h2 second power
     * @param proof output of {@link #proveDleqUnknownOrder}
     * @param xBits upper bound of the bit length of the secret
     * @param domain name of the statement being proven
     * @param context extra public data bound to the proof
     * @return {@code true} when the proof is valid
     */
    public static boolean verifyDleqUnknownOrder(
            BigInteger n,
            BigInteger modulo,
            BigInteger g1,
            BigInteger h1,
            BigInteger g2,
            BigInteger h2,
            Proof proof,
            int xBits,
            String domain,
            Object context) {
        if (!(proof instanceof Proof.ChallengeResponse response)) {
            return false;
        }
        BigInteger e = response.challenge();
        BigInteger z = response.response();
        BigInteger bound = BigInteger.ONE.shiftLeft(nthPowerChallengeBits(n));
        if (!inRange(e, bound)) {
            return false;
        }
        if (!inRange(z, BigInteger.ONE.shiftLeft(dleqUnknownOrderBits(n, modulo, xBits) + 1))) {
            return false;
        }
        for (BigInteger element : Arrays.asList(g1, h1, g2, h2)) {
            if (!isUnit(element, n, modulo)) {
                return false;
            }
        }

        // a = g^z * h^(-e) is the commitment of an honest prover
        BigInteger a1 = g1.modPow(z, modulo).multiply(h1.modPow(e.negate(), modulo)).mod(modulo);
        BigInteger a2 = g2.modPow(z, modulo).multiply(h2.modPow(e.negate(), modulo)).mod(modulo);
        return e.equals(challenge(domain, bound, context, modulo, g1, h1, g2, h2, a1, a2));
    }

    // -----------------------------------------------------------------------
    // Range proofs
    // -----------------------------------------------------------------------

    /**
     * Weights of bits to represent every integer in {@code [0, width]} exactly, i.e. {@code 1, 2,
     * 4, ..., 2^(k-2)} and {@code width - (2^(k-1) - 1)} where k is the bit length of width. Sums
     * of 0/1 bits with these weights cover {@code [0, width]}, and nothing out of it.
     *
     * @param width high - low of the range
     * @return the weights
     */
    public static List<BigInteger> rangeWeights(BigInteger width) {
        int k = width.bitLength();
        List<BigInteger> weights = new ArrayList<>(k);
        if (k == 0) {
            return weights;
        }
        for (int i = 0; i < k - 1; i++) {
            weights.add(BigInteger.ONE.shiftLeft(i));
        }
        weights.add(width.subtract(BigInteger.ONE.shiftLeft(k - 1).subtract(BigInteger.ONE)));
        return weights;
    }

    /**
     * Finds 0/1 bits of a value in {@code [0, sum of weights]} for weights of {@link
     * #rangeWeights}.
     *
     * @param value the value to decompose
     * @param weights output of {@link #rangeWeights}
     * @return the bits
     */
    public static List<Integer> decompose(BigInteger value, List<BigInteger> weights) {
        List<Integer> bits = new ArrayList<>(weights.size());
        if (weights.isEmpty()) {
            return bits;
        }
        BigInteger lastWeight = weights.get(weights.size() - 1);
        int last = value.compareTo(lastWeight) >= 0 ? 1 : 0;
        BigInteger rest = last == 1 ? value.subtract(lastWeight) : value;
        for (int i = 0; i < weights.size() - 1; i++) {
            bits.add(rest.testBit(i) ? 1 : 0);
        }
        bits.add(last);
        return bits;
    }

    /**
     * Context of a part of a range proof. It binds every part to its position and range, so parts
     * cannot be reordered or moved into another proof.
     *
     * @param context public data bound to the proof
     * @param low lower bound
     * @param high upper bound
     * @param index position of the part
     * @return the context of the part
     */
    public static List<Object> rangeContext(
            Object context, BigInteger low, BigInteger high, int index) {
        return Arrays.asList("range", low, high, index, context);
    }

    /**
     * Restores the ciphertext of a range proof homomorphically as {@code c_low + sum of w_i * c_i}.
     *
     * @param cs additively homomorphic cryptosystem
     * @param ciphertexts encryption of low and encryptions of bits
     * @param weights weights of bits
     * @return the ciphertext
     */
    public static CipherValue combineRangeCiphertexts(
            Homomorphic cs, List<CipherValue> ciphertexts, List<BigInteger> weights) {
        CipherValue combined = ciphertexts.get(0);
        for (int i = 0; i < weights.size(); i++) {
            combined =
                    cs.add(combined, cs.multiplyByConstant(ciphertexts.get(i + 1), weights.get(i)));
        }
        return combined;
    }

    /**
     * Encrypts a plaintext in {@code [low, high]} and proves that it is in this range without
     * revealing it. It is decomposed into bits, each bit is encrypted with a proof that it is 0 or
     * 1, and low is encrypted with a proof that it is low. Ciphertext is {@code c_low + sum of w_i
     * * c_i}, so anyone can restore it from the parts.
     *
     * @param cs additively homomorphic cryptosystem supporting proofs of membership
     * @param plaintext message in {@code [low, high]}
     * @param low lower bound
     * @param high upper bound
     * @param values normalized {@code [low, 0, 1]} in plaintext modulo
     * @param context public data bound to the proof
     * @return the encrypted plaintext and the proof
     */
    public static Proven<CipherValue> proveRange(
            Homomorphic cs,
            BigInteger plaintext,
            BigInteger low,
            BigInteger high,
            List<BigInteger> values,
            Object context) {
        BigInteger normalizedLow = values.get(0);
        BigInteger zero = values.get(1);
        BigInteger one = values.get(2);
        List<BigInteger> weights = rangeWeights(high.subtract(low));
        List<Integer> bits = decompose(plaintext.subtract(low), weights);

        List<CipherValue> ciphertexts = new ArrayList<>();
        List<Proof> proofs = new ArrayList<>();
        for (int index = 0; index <= bits.size(); index++) {
            BigInteger value;
            List<BigInteger> allowed;
            if (index == 0) {
                value = normalizedLow;
                allowed = List.of(normalizedLow);
            } else {
                value = bits.get(index - 1) == 1 ? one : zero;
                allowed = List.of(zero, one);
            }
            Proven<CipherValue> part =
                    cs.encryptWithProof(value, allowed, rangeContext(context, low, high, index));
            ciphertexts.add(part.value());
            proofs.add(part.proof());
        }

        CipherValue ciphertext = combineRangeCiphertexts(cs, ciphertexts, weights);
        return new Proven<>(ciphertext, new Proof.Range(ciphertexts, proofs));
    }

    /**
     * Verifies that a ciphertext encrypts a value in {@code [low, high]} with public key only.
     *
     * @param cs additively homomorphic cryptosystem supporting proofs of membership
     * @param ciphertext the encrypted message
     * @param proof output of {@link #proveRange}
     * @param low lower bound
     * @param high upper bound
     * @param values normalized {@code [low, 0, 1]} in plaintext modulo
     * @param context public data that the proof is expected to be bound to
     * @return {@code true} when the proof is valid
     */
    public static boolean verifyRange(
            Homomorphic cs,
            CipherValue ciphertext,
            Proof proof,
            BigInteger low,
            BigInteger high,
            List<BigInteger> values,
            Object context) {
        if (!(proof instanceof Proof.Range range)) {
            return false;
        }
        List<CipherValue> ciphertexts = range.ciphertexts();
        List<Proof> proofs = range.proofs();
        List<BigInteger> weights = rangeWeights(high.subtract(low));
        if (ciphertexts.size() != weights.size() + 1 || proofs.size() != weights.size() + 1) {
            return false;
        }

        BigInteger normalizedLow = values.get(0);
        BigInteger zero = values.get(1);
        BigInteger one = values.get(2);
        for (int index = 0; index < ciphertexts.size(); index++) {
            List<BigInteger> allowed = index == 0 ? List.of(normalizedLow) : List.of(zero, one);
            if (!cs.verifyCiphertext(
                    ciphertexts.get(index),
                    proofs.get(index),
                    allowed,
                    rangeContext(context, low, high, index))) {
                return false;
            }
        }

        CipherValue combined;
        try {
            combined = combineRangeCiphertexts(cs, ciphertexts, weights);
        } catch (RuntimeException err) {
            // malformed parts raise errors of the cryptosystem
            return false;
        }
        return combined.equals(ciphertext);
    }

    // -----------------------------------------------------------------------
    // One-hot proofs
    // -----------------------------------------------------------------------

    /**
     * Context of a part of a one-hot proof. It binds every slot to its position and the number of
     * options, so slots cannot be reordered or moved into another ballot.
     *
     * @param context public data bound to the proof
     * @param options number of options
     * @param slot index of the slot, or {@code "sum"}
     * @return the context of the part
     */
    public static List<Object> oneHotContext(Object context, int options, Object slot) {
        return Arrays.asList("one-hot", options, slot, context);
    }

    /**
     * Encrypts a one-hot vector, i.e. 1 for the chosen option and 0 for others, and proves that
     * each slot is 0 or 1 and that slots sum to 1 without revealing the choice.
     *
     * @param cs additively homomorphic cryptosystem supporting proofs of membership
     * @param choice index of the chosen option
     * @param options number of options
     * @param values normalized {@code [0, 1]} in plaintext modulo
     * @param context public data bound to the proof
     * @return the encrypted slots and the proof of slots and their sum
     */
    public static Proven<List<CipherValue>> proveOneHot(
            Homomorphic cs, int choice, int options, List<BigInteger> values, Object context) {
        BigInteger zero = values.get(0);
        BigInteger one = values.get(1);
        List<CipherValue> ciphertexts = new ArrayList<>(options);
        List<BigInteger> randomKeys = new ArrayList<>(options);
        List<Proof> slotProofs = new ArrayList<>(options);
        for (int slot = 0; slot < options; slot++) {
            BigInteger plaintext = slot == choice ? one : zero;
            BigInteger randomKey = cs.generateRandomKey();
            CipherValue ciphertext = cs.encrypt(plaintext, randomKey);
            slotProofs.add(
                    cs.proveMembership(
                            ciphertext,
                            plaintext,
                            randomKey,
                            List.of(zero, one),
                            oneHotContext(context, options, slot)));
            ciphertexts.add(ciphertext);
            randomKeys.add(randomKey);
        }

        // sum of slots encrypts 1, and its random key is combined from random keys of slots
        CipherValue total = ciphertexts.get(0);
        for (int i = 1; i < ciphertexts.size(); i++) {
            total = cs.add(total, ciphertexts.get(i));
        }
        Proof sumProof =
                cs.proveMembership(
                        total,
                        one,
                        cs.combineRandomKeys(randomKeys),
                        List.of(one),
                        oneHotContext(context, options, "sum"));
        return new Proven<>(ciphertexts, new Proof.OneHot(slotProofs, sumProof));
    }

    /**
     * Verifies that encrypted slots are a one-hot vector with public key only.
     *
     * @param cs additively homomorphic cryptosystem supporting proofs of membership
     * @param ciphertexts the encrypted slots
     * @param proof output of {@link #proveOneHot}
     * @param values normalized {@code [0, 1]} in plaintext modulo
     * @param context public data that the proof is expected to be bound to
     * @return {@code true} when the proof is valid
     */
    public static boolean verifyOneHot(
            Homomorphic cs,
            List<CipherValue> ciphertexts,
            Proof proof,
            List<BigInteger> values,
            Object context) {
        if (!(proof instanceof Proof.OneHot oneHot)
                || ciphertexts == null
                || ciphertexts.isEmpty()) {
            return false;
        }
        List<Proof> slotProofs = oneHot.slots();
        if (slotProofs.size() != ciphertexts.size()) {
            return false;
        }
        int options = ciphertexts.size();
        BigInteger zero = values.get(0);
        BigInteger one = values.get(1);

        for (int slot = 0; slot < options; slot++) {
            if (!cs.verifyCiphertext(
                    ciphertexts.get(slot),
                    slotProofs.get(slot),
                    List.of(zero, one),
                    oneHotContext(context, options, slot))) {
                return false;
            }
        }

        CipherValue total;
        try {
            total = ciphertexts.get(0);
            for (int i = 1; i < ciphertexts.size(); i++) {
                total = cs.add(total, ciphertexts.get(i));
            }
        } catch (RuntimeException err) {
            // malformed slots raise errors of the cryptosystem
            return false;
        }
        return cs.verifyCiphertext(
                total, oneHot.sum(), List.of(one), oneHotContext(context, options, "sum"));
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static boolean inRange(BigInteger value, BigInteger bound) {
        return value != null && value.signum() >= 0 && value.compareTo(bound) < 0;
    }

    private static boolean isUnit(BigInteger value, BigInteger n, BigInteger modulo) {
        return value != null
                && value.signum() > 0
                && value.compareTo(modulo) < 0
                && value.gcd(n).equals(BigInteger.ONE);
    }
}
