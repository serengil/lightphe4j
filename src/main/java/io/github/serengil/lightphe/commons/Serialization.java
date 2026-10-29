package io.github.serengil.lightphe.commons;

import io.github.serengil.lightphe.model.Aggregate;
import io.github.serengil.lightphe.model.AggregationLayout;
import io.github.serengil.lightphe.model.Algorithm;
import io.github.serengil.lightphe.model.ArgmaxMessage;
import io.github.serengil.lightphe.model.CatalanoFioreCiphertext;
import io.github.serengil.lightphe.model.Ciphertext;
import io.github.serengil.lightphe.model.EncryptedKnnQuery;
import io.github.serengil.lightphe.model.EncryptedTensor;
import io.github.serengil.lightphe.model.EncryptedUpdate;
import io.github.serengil.lightphe.model.Fraction;
import io.github.serengil.lightphe.model.FractionPartialDecryption;
import io.github.serengil.lightphe.model.KnnDistances;
import io.github.serengil.lightphe.model.KnnResult;
import io.github.serengil.lightphe.model.PartialDecryption;
import io.github.serengil.lightphe.model.Proof;
import io.github.serengil.lightphe.model.Proven;
import io.github.serengil.lightphe.model.VerifiableCiphertext;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.Fp2Value;
import io.github.serengil.lightphe.model.value.IntValue;
import io.github.serengil.lightphe.model.value.PointValue;
import io.github.serengil.lightphe.model.value.TupleValue;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.UnaryOperator;

/**
 * Converts ciphertexts, proofs and messages of interactive protocols into a json serializable form
 * and back, to send them to another party. Keys of the cryptosystem are never encoded, the receiver
 * restores ciphertexts with its own keys.
 *
 * <p>Java counterpart of {@code lightphe.commons.serialization}, producing the same wire format, so
 * serialized items can be exchanged between the two implementations. Python tuples are encoded as
 * tagged objects; Java has no tuples, so they are decoded as lists. Records of the Java library are
 * encoded as the dictionaries they mirror in the Python library, and restored from decoded items
 * with {@link #convert}.
 */
public final class Serialization {

    /** Key marking an encoded object that json cannot represent natively. */
    public static final String TAG = "__lightphe__";

    /** Version of the encoding, increased if it changes in a backward incompatible way. */
    public static final int VERSION = 1;

    /** Kind of an encoded ciphertext. */
    public static final String CIPHERTEXT = "ciphertext";

    /** Kind of an encoded Catalano-Fiore ciphertext. */
    public static final String CATALANO_FIORE = "catalano-fiore";

    /** Kind of an encoded encrypted tensor. */
    public static final String TENSOR = "tensor";

    /** Kind of an encoded elliptic curve point. */
    public static final String POINT = "point";

    /** Kind of an encoded tuple. */
    public static final String TUPLE = "tuple";

    /** Kind of an encoded dict having keys other than strings. */
    public static final String DICT = "dict";

    /** Kind of an encoded float that json cannot represent, e.g. infinity. */
    public static final String FLOAT = "float";

    /** Kind of an encoded item of an encrypted tensor. */
    public static final String FRACTION = "fraction";

    private static final double INFINITY = Double.POSITIVE_INFINITY;

    private Serialization() {
        throw new AssertionError("no instances");
    }

    /**
     * Builds ciphertexts, tensors and elliptic curve points with the cryptosystem of the receiver.
     */
    @FunctionalInterface
    public interface Restorer {

        /**
         * Builds a deserialized object.
         *
         * @param kind kind of the object, one of {@link #CIPHERTEXT}, {@link #CATALANO_FIORE},
         *     {@link #TENSOR} or {@link #POINT}
         * @param fields decoded fields of the object
         * @return restored object
         */
        Object restore(String kind, Map<String, Object> fields);
    }

    // -----------------------------------------------------------------------
    // Encoding
    // -----------------------------------------------------------------------

    /**
     * Converts an item into a json serializable form.
     *
     * @param item Ciphertext, CatalanoFioreCiphertext, EncryptedTensor, a proof or a message of an
     *     interactive protocol, or null, Boolean, Number, String, List and Map of them
     * @return json serializable form of the item
     * @throws IllegalArgumentException when the item cannot be serialized
     */
    public static Object encode(Object item) {
        if (item == null || item instanceof Boolean || item instanceof String) {
            return item;
        }
        if (item instanceof Double || item instanceof Float) {
            double value = ((Number) item).doubleValue();
            // identity element of some elliptic curve forms is (inf, inf)
            if (Double.isFinite(value)) {
                return value;
            }
            return tagged(FLOAT, "value", pythonFloat(value));
        }
        if (item instanceof BigInteger
                || item instanceof Long
                || item instanceof Integer
                || item instanceof Short
                || item instanceof Byte) {
            return item;
        }
        if (item instanceof List<?> list) {
            List<Object> out = new ArrayList<>(list.size());
            for (Object element : list) {
                out.add(encode(element));
            }
            return out;
        }
        if (item instanceof Map<?, ?> map) {
            return encodeMap(map);
        }
        if (item instanceof Ciphertext ciphertext) {
            Map<String, Object> out = versioned(CIPHERTEXT, ciphertext.algorithmName());
            out.put("value", encodeValue(ciphertext.value(), ciphertext.algorithmName()));
            return out;
        }
        if (item instanceof CatalanoFioreCiphertext ciphertext) {
            return encodeCatalanoFiore(ciphertext);
        }
        if (item instanceof EncryptedTensor tensor) {
            Algorithm algorithm = tensor.cs().algorithm();
            Map<String, Object> out = new LinkedHashMap<>();
            out.put(TAG, TENSOR);
            out.put("version", VERSION);
            out.put("algorithm_name", tensorAlgorithmName(algorithm));
            out.put("precision", tensor.precision());
            List<Object> fractions = new ArrayList<>(tensor.fractions().size());
            for (Fraction fraction : tensor.fractions()) {
                fractions.add(encodeFraction(fraction, algorithm));
            }
            out.put("fractions", fractions);
            return out;
        }
        if (item instanceof Fraction fraction) {
            return encodeFraction(fraction, null);
        }
        if (item instanceof CipherValue value) {
            return encodeValue(value, null);
        }
        if (item instanceof Proof proof) {
            return encodeProof(proof);
        }
        if (item instanceof Proven<?> proven) {
            return tuple(encode(proven.value()), encodeProof(proven.proof()));
        }
        if (item instanceof PartialDecryption partial) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("index", partial.index());
            out.put("value", encodeValue(partial.value(), null));
            if (partial.proof() != null) {
                out.put("proof", encodeProof(partial.proof()));
            }
            return out;
        }
        if (item instanceof FractionPartialDecryption partial) {
            return dict(
                    "abs_dividend",
                    encode(partial.absDividend()),
                    "divisor",
                    encode(partial.divisor()));
        }
        if (item instanceof VerifiableCiphertext verifiable) {
            VerifiableCiphertext.Proof proof = verifiable.proof();
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("ciphertext", tuple(verifiable.u(), verifiable.e(), verifiable.v()));
            out.put("commitment", verifiable.commitment());
            Map<String, Object> encodedProof = new LinkedHashMap<>();
            encodedProof.put("challenge", proof.challenge());
            encodedProof.put("r", proof.r());
            encodedProof.put("s", proof.s());
            encodedProof.put("m", proof.m());
            out.put("proof", encodedProof);
            return out;
        }
        if (item instanceof EncryptedKnnQuery query) {
            return dict("query", encode(query.query()), "norm", encode(query.norm()));
        }
        if (item instanceof KnnResult result) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("indices", encode(result.indices()));
            if (!result.labels().isEmpty()) {
                out.put("labels", encode(result.labels()));
            }
            return out;
        }
        if (item instanceof KnnDistances distances) {
            return dict(
                    "indices",
                    encode(distances.indices()),
                    "distances",
                    encode(distances.distances()));
        }
        if (item instanceof EncryptedUpdate update) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("chunks", encode(update.chunks()));
            out.put("layout", encode(update.layout()));
            out.put("count", update.count());
            return out;
        }
        if (item instanceof AggregationLayout layout) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("length", layout.length());
            out.put("precision", layout.precision());
            out.put("bound", layout.bound());
            out.put("max_clients", layout.maxClients());
            out.put("slot_bits", layout.slotBits());
            out.put("slots", layout.slots());
            return out;
        }
        if (item instanceof Aggregate aggregate) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("sum", encode(aggregate.sum()));
            out.put("mean", encode(aggregate.mean()));
            out.put("count", aggregate.count());
            return out;
        }
        if (item instanceof ArgmaxMessage message) {
            return dict("type", message.type(), "payload", encode(argmaxPayload(message)));
        }
        throw new IllegalArgumentException(
                "Object of type " + item.getClass().getSimpleName() + " cannot be serialized");
    }

    /**
     * Converts an item into a json serializable dict.
     *
     * @param item Ciphertext, CatalanoFioreCiphertext or EncryptedTensor
     * @return serialized item
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> toDict(Object item) {
        return (Map<String, Object>) encode(item);
    }

    private static Object encodeMap(Map<?, ?> map) {
        boolean plain = !map.containsKey(TAG);
        for (Object key : map.keySet()) {
            plain &= key instanceof String;
        }
        if (plain) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                out.put((String) entry.getKey(), encode(entry.getValue()));
            }
            return out;
        }
        List<Object> items = new ArrayList<>(map.size());
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            items.add(Arrays.asList(encode(entry.getKey()), encode(entry.getValue())));
        }
        return tagged(DICT, "items", items);
    }

    private static Map<String, Object> encodeCatalanoFiore(CatalanoFioreCiphertext ciphertext) {
        Ciphertext any = ciphertext.isMultiplied() ? ciphertext.alpha() : ciphertext.beta();
        Map<String, Object> out = versioned(CATALANO_FIORE, any.algorithmName());
        out.put("a", ciphertext.a());
        out.put("beta", encode(ciphertext.beta()));
        out.put("alpha", encode(ciphertext.alpha()));
        List<Object> pairs = new ArrayList<>(ciphertext.pairs().size());
        for (Ciphertext[] pair : ciphertext.pairs()) {
            pairs.add(List.of(encode(pair[0]), encode(pair[1])));
        }
        out.put("pairs", pairs);
        return out;
    }

    private static Map<String, Object> encodeFraction(Fraction fraction, Algorithm algorithm) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put(TAG, FRACTION);
        out.put("dividend", encodeValue(fraction.dividend(), algorithm));
        out.put("abs_dividend", encodeValue(fraction.absDividend(), algorithm));
        out.put("divisor", encodeValue(fraction.divisor(), algorithm));
        out.put("sign", fraction.sign());
        return out;
    }

    /**
     * Encodes a ciphertext content in the shape the Python library keeps it: points of
     * Boneh-Goh-Nissim are elliptic curve points, other points and elements of {@code F_{p^2}} are
     * tuples, and Goldwasser-Micali and Sander-Young-Yung keep their bits in lists.
     */
    private static Object encodeValue(CipherValue value, Algorithm algorithm) {
        if (value instanceof IntValue integer) {
            return integer.value();
        }
        if (value instanceof PointValue point) {
            Object x = point.infinity() ? encode(INFINITY) : point.x();
            Object y = point.infinity() ? encode(INFINITY) : point.y();
            if (algorithm == Algorithm.BONEH_GOH_NISSIM) {
                Map<String, Object> out = new LinkedHashMap<>();
                out.put(TAG, POINT);
                out.put("x", x);
                out.put("y", y);
                return out;
            }
            return tuple(x, y);
        }
        if (value instanceof Fp2Value element) {
            return tuple(element.a(), element.b());
        }
        TupleValue tuple = (TupleValue) value;
        List<Object> items = new ArrayList<>(tuple.size());
        for (CipherValue item : tuple.items()) {
            items.add(encodeValue(item, algorithm));
        }
        if (algorithm == Algorithm.GOLDWASSER_MICALI || algorithm == Algorithm.SANDER_YOUNG_YUNG) {
            return items;
        }
        return tagged(TUPLE, "items", items);
    }

    private static Map<String, Object> encodeProof(Proof proof) {
        if (proof instanceof Proof.ChallengeResponse p) {
            return dict("challenge", p.challenge(), "response", p.response());
        }
        if (proof instanceof Proof.Disjunctive p) {
            return dict("challenges", p.challenges(), "responses", p.responses());
        }
        if (proof instanceof Proof.Randomness p) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("randomness", p.randomness());
            return out;
        }
        if (proof instanceof Proof.PaillierKnowledge p) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("challenge", p.challenge());
            out.put("plaintext_response", p.plaintextResponse());
            out.put("randomness_response", p.randomnessResponse());
            return out;
        }
        if (proof instanceof Proof.Range p) {
            List<Object> ciphertexts = new ArrayList<>(p.ciphertexts().size());
            for (CipherValue ciphertext : p.ciphertexts()) {
                ciphertexts.add(encodeValue(ciphertext, null));
            }
            return dict("ciphertexts", ciphertexts, "proofs", encode(p.proofs()));
        }
        Proof.OneHot p = (Proof.OneHot) proof;
        return dict("slots", encode(p.slots()), "sum", encodeProof(p.sum()));
    }

    private static List<?> argmaxPayload(ArgmaxMessage message) {
        if (message instanceof ArgmaxMessage.MaskedDifference m) {
            return List.of(m.ciphertext());
        }
        if (message instanceof ArgmaxMessage.Comparisons m) {
            return m.comparisons();
        }
        if (message instanceof ArgmaxMessage.Products m) {
            List<BigInteger> payload = new ArrayList<>(m.maskedFactors().size() + 1);
            payload.add(m.maskedBit());
            payload.addAll(m.maskedFactors());
            return payload;
        }
        return ((ArgmaxMessage.Equality) message).payload();
    }

    /**
     * Name of the algorithm of a tensor, the name of the class of the cryptosystem in the Python
     * library. Exponential ElGamal is built by the ElGamal class.
     *
     * @param algorithm the algorithm
     * @return the name
     */
    public static String tensorAlgorithmName(Algorithm algorithm) {
        return algorithm == Algorithm.EXPONENTIAL_EL_GAMAL
                ? Algorithm.EL_GAMAL.algorithmName()
                : algorithm.algorithmName();
    }

    private static Map<String, Object> versioned(String kind, Algorithm algorithm) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put(TAG, kind);
        out.put("version", VERSION);
        out.put("algorithm_name", algorithm.algorithmName());
        return out;
    }

    private static Map<String, Object> tagged(String kind, String field, Object value) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put(TAG, kind);
        out.put(field, value);
        return out;
    }

    private static Map<String, Object> tuple(Object... items) {
        return tagged(TUPLE, "items", new ArrayList<>(List.of(items)));
    }

    private static Map<String, Object> dict(
            String key1, Object value1, String key2, Object value2) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put(key1, value1);
        out.put(key2, value2);
        return out;
    }

    private static String pythonFloat(double value) {
        if (Double.isNaN(value)) {
            return "nan";
        }
        return value > 0 ? "inf" : "-inf";
    }

    // -----------------------------------------------------------------------
    // Decoding
    // -----------------------------------------------------------------------

    /**
     * Restores an item from its json serializable form created by {@link #encode}.
     *
     * @param item json serializable form of the item
     * @param restore builds ciphertexts, tensors and elliptic curve points with the cryptosystem of
     *     the receiver
     * @return restored item. Integers are restored as BigInteger, and tuples as lists.
     * @throws IllegalArgumentException when the item is malformed
     */
    public static Object decode(Object item, Restorer restore) {
        if (item == null
                || item instanceof Boolean
                || item instanceof Number
                || item instanceof String) {
            return item instanceof Number number ? normalizeNumber(number) : item;
        }
        // already restored, e.g. an output of deserialize passed to fromDict
        if (item instanceof Ciphertext
                || item instanceof CatalanoFioreCiphertext
                || item instanceof EncryptedTensor
                || item instanceof Fraction
                || item instanceof CipherValue) {
            return item;
        }
        if (item instanceof List<?> list) {
            List<Object> out = new ArrayList<>(list.size());
            for (Object element : list) {
                out.add(decode(element, restore));
            }
            return out;
        }
        if (!(item instanceof Map<?, ?> map)) {
            throw new IllegalArgumentException(
                    "Object of type "
                            + item.getClass().getSimpleName()
                            + " cannot be deserialized");
        }
        if (!map.containsKey(TAG)) {
            Map<Object, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                out.put(entry.getKey(), decode(entry.getValue(), restore));
            }
            return out;
        }

        Object kind = map.get(TAG);
        if (TUPLE.equals(kind)) {
            return decode(field(map, "items", List.class), restore);
        }
        if (DICT.equals(kind)) {
            Map<Object, Object> out = new LinkedHashMap<>();
            for (Object pair : field(map, "items", List.class)) {
                if (!(pair instanceof List<?> keyValue) || keyValue.size() != 2) {
                    throw new IllegalArgumentException(
                            "Items of an encoded dict must be key value pairs");
                }
                out.put(decode(keyValue.get(0), restore), decode(keyValue.get(1), restore));
            }
            return out;
        }
        if (FLOAT.equals(kind)) {
            String value = field(map, "value", String.class);
            return switch (value) {
                case "inf" -> Double.POSITIVE_INFINITY;
                case "-inf" -> Double.NEGATIVE_INFINITY;
                case "nan" -> Double.NaN;
                default -> throw new IllegalArgumentException("Invalid encoded float " + value);
            };
        }
        if (FRACTION.equals(kind)) {
            BigInteger sign = field(map, "sign", BigInteger.class);
            if (!sign.equals(BigInteger.ONE) && !sign.equals(BigInteger.ONE.negate())) {
                throw new IllegalArgumentException("Sign of a fraction must be 1 or -1");
            }
            return Fraction.builder()
                    .dividend(decodeCiphertextValue(map.get("dividend"), restore))
                    .absDividend(decodeCiphertextValue(map.get("abs_dividend"), restore))
                    .divisor(decodeCiphertextValue(map.get("divisor"), restore))
                    .sign(sign.intValue())
                    .build();
        }
        if (CIPHERTEXT.equals(kind) || CATALANO_FIORE.equals(kind) || TENSOR.equals(kind)) {
            Object version = normalizeNumber(map.get("version"));
            if (!BigInteger.valueOf(VERSION).equals(version)) {
                throw new IllegalArgumentException(
                        "Unsupported serialization version "
                                + map.get("version")
                                + ", expected "
                                + VERSION);
            }
            field(map, "algorithm_name", String.class);
        }
        Map<String, Object> fields = new LinkedHashMap<>();
        if (CIPHERTEXT.equals(kind)) {
            fields.put("algorithm_name", map.get("algorithm_name"));
            fields.put("value", decodeCiphertextValue(map.get("value"), restore));
            return restore.restore(CIPHERTEXT, fields);
        }
        if (CATALANO_FIORE.equals(kind)) {
            fields.put("algorithm_name", map.get("algorithm_name"));
            fields.put("a", normalizeNumber(map.get("a")));
            fields.put("beta", decode(map.get("beta"), restore));
            fields.put("alpha", decode(map.get("alpha"), restore));
            List<Object> pairs = new ArrayList<>();
            for (Object pair : field(map, "pairs", List.class)) {
                if (!(pair instanceof List<?> items) || items.size() != 2) {
                    throw new IllegalArgumentException(
                            "Pairs of a Catalano-Fiore ciphertext must have 2 ciphertexts");
                }
                pairs.add(
                        Arrays.asList(
                                decode(items.get(0), restore), decode(items.get(1), restore)));
            }
            fields.put("pairs", pairs);
            return restore.restore(CATALANO_FIORE, fields);
        }
        if (TENSOR.equals(kind)) {
            List<Fraction> fractions = new ArrayList<>();
            for (Object fraction : field(map, "fractions", List.class)) {
                if (!(decode(fraction, restore) instanceof Fraction decoded)) {
                    throw new IllegalArgumentException(
                            "Items of an encrypted tensor must be fractions");
                }
                fractions.add(decoded);
            }
            fields.put("algorithm_name", map.get("algorithm_name"));
            fields.put("precision", field(map, "precision", BigInteger.class));
            fields.put("fractions", fractions);
            return restore.restore(TENSOR, fields);
        }
        if (POINT.equals(kind)) {
            fields.put("x", decode(map.get("x"), restore));
            fields.put("y", decode(map.get("y"), restore));
            return restore.restore(POINT, fields);
        }
        throw new IllegalArgumentException("Unknown serialized object " + kind);
    }

    /**
     * Decodes the content of a ciphertext, which must consist of integers, tuples and lists of
     * them, or elliptic curve points.
     *
     * @param item json serializable form of the ciphertext content
     * @param restore builds elliptic curve points with the cryptosystem of the receiver
     * @return ciphertext content
     * @throws IllegalArgumentException when the content is malformed
     */
    public static CipherValue decodeCiphertextValue(Object item, Restorer restore) {
        return toCipherValue(decode(item, restore));
    }

    /**
     * Converts a decoded ciphertext content into a {@link CipherValue}: integers become {@link
     * IntValue}, and tuples and lists become {@link TupleValue}. Algorithm specific shapes, e.g.
     * points kept as tuples, are left to the receiver.
     *
     * @param value decoded ciphertext content
     * @return the ciphertext value
     * @throws IllegalArgumentException when the content is malformed
     */
    public static CipherValue toCipherValue(Object value) {
        if (value instanceof PointValue point) {
            return point;
        }
        if (value instanceof BigInteger integer) {
            return new IntValue(integer);
        }
        if (value instanceof List<?> list) {
            List<CipherValue> items = new ArrayList<>(list.size());
            for (Object item : list) {
                items.add(toCipherValue(item));
            }
            return TupleValue.of(items);
        }
        throw new IllegalArgumentException(
                "Ciphertext must consist of integers, or tuples and lists of them");
    }

    private static Object normalizeNumber(Object item) {
        if (item instanceof Double || item instanceof Float || item instanceof BigInteger) {
            return item instanceof Float f ? (Object) f.doubleValue() : item;
        }
        if (item instanceof Number number) {
            return BigInteger.valueOf(number.longValue());
        }
        return item;
    }

    /** Gets a field of an encoded object, and checks its type. */
    private static <T> T field(Map<?, ?> item, String name, Class<T> expectedType) {
        Object value = normalizeNumber(item.get(name));
        if (!expectedType.isInstance(value)) {
            throw new IllegalArgumentException(
                    "Field "
                            + name
                            + " of serialized "
                            + item.get(TAG)
                            + " must be "
                            + pythonTypeName(expectedType));
        }
        return expectedType.cast(value);
    }

    private static String pythonTypeName(Class<?> type) {
        if (type == BigInteger.class) {
            return "int";
        }
        if (type == String.class) {
            return "str";
        }
        return type.getSimpleName().toLowerCase(Locale.ROOT);
    }

    // -----------------------------------------------------------------------
    // Typed conversion
    // -----------------------------------------------------------------------

    /**
     * Converts a decoded item into a record of the Java library, e.g. the dict of a proof into a
     * {@link Proof}, or a tuple of a ciphertext and its proof into a {@link Proven}.
     *
     * @param item decoded item, an output of {@link #decode}
     * @param type expected type: Ciphertext, CatalanoFioreCiphertext, EncryptedTensor, Proof,
     *     Proven, PartialDecryption, FractionPartialDecryption, VerifiableCiphertext,
     *     EncryptedKnnQuery, KnnResult, KnnDistances, EncryptedUpdate, AggregationLayout,
     *     Aggregate, ArgmaxMessage, or a type the item already has
     * @param normalize converts ciphertext contents into the shapes the cryptosystem of the
     *     receiver expects
     * @param <T> expected type
     * @return converted item
     * @throws IllegalArgumentException when the item cannot be converted
     */
    public static <T> T convert(Object item, Class<T> type, UnaryOperator<CipherValue> normalize) {
        if (type.isInstance(item)) {
            return type.cast(item);
        }
        Object result;
        if (type == Proof.class) {
            result = toProof(item, normalize);
        } else if (type == Proven.class) {
            List<?> items = list(item, "proven value");
            if (items.size() != 2) {
                throw new IllegalArgumentException("Proven value must be a value and a proof");
            }
            result = new Proven<>(items.get(0), toProof(items.get(1), normalize));
        } else if (type == PartialDecryption.class) {
            Map<?, ?> map = map(item, "partial decryption");
            Object proof = map.get("proof");
            result =
                    new PartialDecryption(
                            intOf(map.get("index"), "index"),
                            normalize.apply(toCipherValue(map.get("value"))),
                            proof == null ? null : toProof(proof, normalize));
        } else if (type == FractionPartialDecryption.class) {
            Map<?, ?> map = map(item, "fraction partial decryption");
            result =
                    new FractionPartialDecryption(
                            convert(map.get("abs_dividend"), PartialDecryption.class, normalize),
                            convert(map.get("divisor"), PartialDecryption.class, normalize));
        } else if (type == VerifiableCiphertext.class) {
            Map<?, ?> map = map(item, "verifiable ciphertext");
            List<BigInteger> ciphertext = integers(map.get("ciphertext"), "ciphertext");
            if (ciphertext.size() != 3) {
                throw new IllegalArgumentException("Verifiable ciphertext must have u, e and v");
            }
            Map<?, ?> proof = map(map.get("proof"), "proof");
            result =
                    new VerifiableCiphertext(
                            ciphertext.get(0),
                            ciphertext.get(1),
                            ciphertext.get(2),
                            integer(map.get("commitment"), "commitment"),
                            new VerifiableCiphertext.Proof(
                                    integer(proof.get("challenge"), "challenge"),
                                    integer(proof.get("r"), "r"),
                                    integer(proof.get("s"), "s"),
                                    integer(proof.get("m"), "m")));
        } else if (type == EncryptedKnnQuery.class) {
            Map<?, ?> map = map(item, "encrypted query");
            result =
                    new EncryptedKnnQuery(
                            convertList(map.get("query"), Ciphertext.class, normalize),
                            convert(map.get("norm"), Ciphertext.class, normalize));
        } else if (type == KnnResult.class) {
            Map<?, ?> map = map(item, "nearest neighbor result");
            Object labels = map.get("labels");
            result =
                    new KnnResult(
                            convertList(map.get("indices"), Ciphertext.class, normalize),
                            labels == null
                                    ? List.of()
                                    : convertList(labels, Ciphertext.class, normalize));
        } else if (type == KnnDistances.class) {
            Map<?, ?> map = map(item, "nearest neighbors");
            List<Integer> indices = new ArrayList<>();
            for (BigInteger index : integers(map.get("indices"), "indices")) {
                indices.add(intOf(index, "indices"));
            }
            result = new KnnDistances(indices, integers(map.get("distances"), "distances"));
        } else if (type == EncryptedUpdate.class) {
            Map<?, ?> map = map(item, "encrypted update");
            result =
                    new EncryptedUpdate(
                            convertList(map.get("chunks"), Ciphertext.class, normalize),
                            convert(map.get("layout"), AggregationLayout.class, normalize),
                            intOf(map.get("count"), "count"));
        } else if (type == AggregationLayout.class) {
            Map<?, ?> map = map(item, "layout");
            result =
                    new AggregationLayout(
                            intOf(map.get("length"), "length"),
                            intOf(map.get("precision"), "precision"),
                            integer(map.get("bound"), "bound"),
                            intOf(map.get("max_clients"), "max_clients"),
                            intOf(map.get("slot_bits"), "slot_bits"),
                            intOf(map.get("slots"), "slots"));
        } else if (type == Aggregate.class) {
            Map<?, ?> map = map(item, "aggregate");
            result =
                    new Aggregate(
                            doubles(map.get("sum"), "sum"),
                            doubles(map.get("mean"), "mean"),
                            intOf(map.get("count"), "count"));
        } else if (type == ArgmaxMessage.class) {
            result = toArgmaxMessage(item);
        } else {
            throw new IllegalArgumentException(
                    "Serialized item cannot be restored as " + type.getSimpleName());
        }
        return type.cast(result);
    }

    /**
     * Converts a decoded list into a list of records of the Java library.
     *
     * @param item decoded list
     * @param type expected type of items, see {@link #convert}
     * @param normalize converts ciphertext contents into the shapes the cryptosystem of the
     *     receiver expects
     * @param <T> expected type of items
     * @return converted list
     * @throws IllegalArgumentException when the item is not a list, or an item cannot be converted
     */
    public static <T> List<T> convertList(
            Object item, Class<T> type, UnaryOperator<CipherValue> normalize) {
        List<?> items = list(item, "list of " + type.getSimpleName());
        List<T> out = new ArrayList<>(items.size());
        for (Object element : items) {
            out.add(convert(element, type, normalize));
        }
        return out;
    }

    private static Proof toProof(Object item, UnaryOperator<CipherValue> normalize) {
        Map<?, ?> map = map(item, "proof");
        if (map.containsKey("ciphertexts") && map.containsKey("proofs")) {
            List<CipherValue> ciphertexts = new ArrayList<>();
            for (Object ciphertext : list(map.get("ciphertexts"), "ciphertexts")) {
                ciphertexts.add(normalize.apply(toCipherValue(ciphertext)));
            }
            return new Proof.Range(
                    ciphertexts, convertList(map.get("proofs"), Proof.class, normalize));
        }
        if (map.containsKey("slots") && map.containsKey("sum")) {
            return new Proof.OneHot(
                    convertList(map.get("slots"), Proof.class, normalize),
                    toProof(map.get("sum"), normalize));
        }
        if (map.containsKey("challenges") && map.containsKey("responses")) {
            return new Proof.Disjunctive(
                    integers(map.get("challenges"), "challenges"),
                    integers(map.get("responses"), "responses"));
        }
        if (map.containsKey("plaintext_response")) {
            return new Proof.PaillierKnowledge(
                    integer(map.get("challenge"), "challenge"),
                    integer(map.get("plaintext_response"), "plaintext_response"),
                    integer(map.get("randomness_response"), "randomness_response"));
        }
        if (map.containsKey("randomness")) {
            return new Proof.Randomness(integer(map.get("randomness"), "randomness"));
        }
        if (map.containsKey("challenge") && map.containsKey("response")) {
            return new Proof.ChallengeResponse(
                    integer(map.get("challenge"), "challenge"),
                    integer(map.get("response"), "response"));
        }
        throw new IllegalArgumentException("Unknown proof with keys " + map.keySet());
    }

    private static ArgmaxMessage toArgmaxMessage(Object item) {
        Map<?, ?> map = map(item, "message");
        Object type = map.get("type");
        if ("comparisons".equals(type)) {
            List<List<BigInteger>> comparisons = new ArrayList<>();
            for (Object comparison : list(map.get("payload"), "payload")) {
                comparisons.add(integers(comparison, "comparison"));
            }
            return new ArgmaxMessage.Comparisons(comparisons);
        }
        List<BigInteger> payload = integers(map.get("payload"), "payload");
        if ("masked_difference".equals(type)) {
            if (payload.size() != 1) {
                throw new IllegalArgumentException("Payload must have a masked difference");
            }
            return new ArgmaxMessage.MaskedDifference(payload.get(0));
        }
        if ("products".equals(type)) {
            if (payload.isEmpty()) {
                throw new IllegalArgumentException("Payload must have a masked bit");
            }
            return new ArgmaxMessage.Products(payload.get(0), payload.subList(1, payload.size()));
        }
        if ("equality".equals(type)) {
            return new ArgmaxMessage.Equality(payload);
        }
        throw new IllegalArgumentException("Unknown argmax message type " + type);
    }

    private static Map<?, ?> map(Object item, String name) {
        if (!(item instanceof Map<?, ?> map)) {
            throw new IllegalArgumentException("Serialized " + name + " must be a dict");
        }
        return map;
    }

    private static List<?> list(Object item, String name) {
        if (!(item instanceof List<?> list)) {
            throw new IllegalArgumentException("Serialized " + name + " must be a list");
        }
        return list;
    }

    private static BigInteger integer(Object item, String name) {
        Object value = normalizeNumber(item);
        if (!(value instanceof BigInteger integer)) {
            throw new IllegalArgumentException("Serialized " + name + " must be an integer");
        }
        return integer;
    }

    private static int intOf(Object item, String name) {
        try {
            return integer(item, name).intValueExact();
        } catch (ArithmeticException err) {
            throw new IllegalArgumentException("Serialized " + name + " is out of range", err);
        }
    }

    private static List<BigInteger> integers(Object item, String name) {
        List<BigInteger> out = new ArrayList<>();
        for (Object element : list(item, name)) {
            out.add(integer(element, name));
        }
        return out;
    }

    private static List<Double> doubles(Object item, String name) {
        List<Double> out = new ArrayList<>();
        for (Object element : list(item, name)) {
            if (!(element instanceof Number number)) {
                throw new IllegalArgumentException("Serialized " + name + " must be numbers");
            }
            out.add(number.doubleValue());
        }
        return out;
    }
}
