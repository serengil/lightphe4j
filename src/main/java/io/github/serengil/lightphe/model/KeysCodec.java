package io.github.serengil.lightphe.model;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Serialises {@link Keys} to JSON and back.
 *
 * <p>The wire format is byte-for-byte the one {@code json.dumps(keys)} produces in the Python
 * library, so key files can be exchanged between the two implementations: integers are written as
 * bare JSON numbers of arbitrary length, curve points as two-element arrays, and the
 * Boneh-Goh-Nissim curve as a nested object.
 *
 * <p>A hand-rolled parser keeps the library free of a JSON dependency; it accepts exactly the shape
 * this codec emits.
 */
public final class KeysCodec {

    private KeysCodec() {
        throw new AssertionError("no instances");
    }

    // -----------------------------------------------------------------------
    // Serialisation
    // -----------------------------------------------------------------------

    /**
     * Serialises a key pair to JSON.
     *
     * @param keys the key pair
     * @return the JSON document
     */
    public static String toJson(Keys keys) {
        StringBuilder out = new StringBuilder();
        out.append('{');
        boolean first = true;

        if (keys.privateKey() != null) {
            out.append('"').append(Keys.PRIVATE_KEY).append("\": ");
            writeSection(out, keys.privateKey());
            first = false;
        }

        if (keys.publicKey() != null) {
            if (!first) {
                out.append(", ");
            }
            out.append('"').append(Keys.PUBLIC_KEY).append("\": ");
            writeSection(out, keys.publicKey());
            first = false;
        }

        if (keys.form().isPresent()) {
            if (!first) {
                out.append(", ");
            }
            out.append('"')
                    .append(Keys.FORM)
                    .append("\": \"")
                    .append(keys.form().get())
                    .append('"');
            first = false;
        }

        if (keys.curve().isPresent()) {
            if (!first) {
                out.append(", ");
            }
            out.append('"')
                    .append(Keys.CURVE)
                    .append("\": \"")
                    .append(keys.curve().get())
                    .append('"');
        }

        out.append('}');
        return out.toString();
    }

    private static void writeSection(StringBuilder out, Map<String, KeyValue> section) {
        out.append('{');
        boolean first = true;
        for (Map.Entry<String, KeyValue> entry : section.entrySet()) {
            if (!first) {
                out.append(", ");
            }
            first = false;
            out.append('"').append(entry.getKey()).append("\": ");
            writeValue(out, entry.getValue());
        }
        out.append('}');
    }

    private static void writeValue(StringBuilder out, KeyValue value) {
        if (value instanceof KeyValue.Num num) {
            out.append(num.value());
        } else if (value instanceof KeyValue.Point point) {
            out.append('[').append(point.x()).append(", ").append(point.y()).append(']');
        } else if (value instanceof KeyValue.Nested nested) {
            writeSection(out, nested.entries());
        } else {
            throw new IllegalStateException("unsupported key value - " + value);
        }
    }

    // -----------------------------------------------------------------------
    // Deserialisation
    // -----------------------------------------------------------------------

    /**
     * Parses a key pair from JSON.
     *
     * @param json the JSON document
     * @return the key pair
     * @throws IllegalArgumentException when the document is malformed or carries no key sections
     */
    public static Keys fromJson(String json) {
        Parser parser = new Parser(json);
        Object parsed = parser.parseValue();
        parser.skipWhitespace();
        if (!parser.atEnd()) {
            throw new IllegalArgumentException("trailing content in key document");
        }
        if (!(parsed instanceof Map<?, ?> root)) {
            throw new IllegalArgumentException(
                    "The content of the key file does not represent a valid dictionary.");
        }

        Keys keys = Keys.empty();
        Object publicSection = root.get(Keys.PUBLIC_KEY);
        Object privateSection = root.get(Keys.PRIVATE_KEY);

        if (publicSection == null) {
            keys.removePublicKey();
        } else {
            keys.publicKey().putAll(toSection(publicSection, Keys.PUBLIC_KEY));
        }
        if (privateSection == null) {
            keys.removePrivateKey();
        } else {
            keys.privateKey().putAll(toSection(privateSection, Keys.PRIVATE_KEY));
        }

        if (root.get(Keys.FORM) instanceof String form) {
            keys.setForm(form);
        }
        if (root.get(Keys.CURVE) instanceof String curve) {
            keys.setCurve(curve);
        }
        return keys;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, KeyValue> toSection(Object raw, String name) {
        if (!(raw instanceof Map<?, ?> map)) {
            throw new IllegalArgumentException("'" + name + "' must be a dict");
        }
        Map<String, KeyValue> section = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            section.put((String) entry.getKey(), toKeyValue(entry.getValue()));
        }
        return section;
    }

    private static KeyValue toKeyValue(Object raw) {
        if (raw instanceof BigInteger number) {
            return new KeyValue.Num(number);
        }
        if (raw instanceof List<?> list) {
            if (list.size() != 2
                    || !(list.get(0) instanceof BigInteger x)
                    || !(list.get(1) instanceof BigInteger y)) {
                throw new IllegalArgumentException("a curve point needs exactly 2 coordinates");
            }
            return new KeyValue.Point(x, y);
        }
        if (raw instanceof Map<?, ?> map) {
            Map<String, KeyValue> nested = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                nested.put((String) entry.getKey(), toKeyValue(entry.getValue()));
            }
            return new KeyValue.Nested(nested);
        }
        throw new IllegalArgumentException("unsupported key material - " + raw);
    }

    /** Minimal recursive-descent JSON reader covering the shapes this codec emits. */
    private static final class Parser {

        private final String source;
        private int position;

        Parser(String source) {
            this.source = source;
        }

        boolean atEnd() {
            return position >= source.length();
        }

        void skipWhitespace() {
            while (position < source.length() && Character.isWhitespace(source.charAt(position))) {
                position++;
            }
        }

        Object parseValue() {
            skipWhitespace();
            if (atEnd()) {
                throw new IllegalArgumentException("unexpected end of key document");
            }
            char current = source.charAt(position);
            return switch (current) {
                case '{' -> parseObject();
                case '[' -> parseArray();
                case '"' -> parseString();
                case 't', 'f', 'n' -> parseLiteral();
                default -> parseNumber();
            };
        }

        private Map<String, Object> parseObject() {
            Map<String, Object> map = new LinkedHashMap<>();
            expect('{');
            skipWhitespace();
            if (peek() == '}') {
                position++;
                return map;
            }
            while (true) {
                skipWhitespace();
                String key = parseString();
                skipWhitespace();
                expect(':');
                map.put(key, parseValue());
                skipWhitespace();
                char next = peek();
                position++;
                if (next == '}') {
                    return map;
                }
                if (next != ',') {
                    throw new IllegalArgumentException("expected ',' or '}' at offset " + position);
                }
            }
        }

        private List<Object> parseArray() {
            List<Object> list = new ArrayList<>();
            expect('[');
            skipWhitespace();
            if (peek() == ']') {
                position++;
                return list;
            }
            while (true) {
                list.add(parseValue());
                skipWhitespace();
                char next = peek();
                position++;
                if (next == ']') {
                    return list;
                }
                if (next != ',') {
                    throw new IllegalArgumentException("expected ',' or ']' at offset " + position);
                }
            }
        }

        private String parseString() {
            expect('"');
            StringBuilder out = new StringBuilder();
            while (true) {
                char current = source.charAt(position++);
                if (current == '"') {
                    return out.toString();
                }
                if (current == '\\') {
                    char escaped = source.charAt(position++);
                    switch (escaped) {
                        case 'n' -> out.append('\n');
                        case 't' -> out.append('\t');
                        case 'r' -> out.append('\r');
                        case 'b' -> out.append('\b');
                        case 'f' -> out.append('\f');
                        case 'u' -> {
                            out.append(
                                    (char)
                                            Integer.parseInt(
                                                    source.substring(position, position + 4), 16));
                            position += 4;
                        }
                        default -> out.append(escaped);
                    }
                } else {
                    out.append(current);
                }
            }
        }

        private Object parseLiteral() {
            if (source.startsWith("true", position)) {
                position += 4;
                return Boolean.TRUE;
            }
            if (source.startsWith("false", position)) {
                position += 5;
                return Boolean.FALSE;
            }
            if (source.startsWith("null", position)) {
                position += 4;
                return null;
            }
            throw new IllegalArgumentException("unexpected literal at offset " + position);
        }

        private BigInteger parseNumber() {
            int start = position;
            if (peek() == '-' || peek() == '+') {
                position++;
            }
            while (position < source.length() && Character.isDigit(source.charAt(position))) {
                position++;
            }
            if (position == start) {
                throw new IllegalArgumentException("expected a number at offset " + position);
            }
            return new BigInteger(source.substring(start, position));
        }

        private char peek() {
            if (atEnd()) {
                throw new IllegalArgumentException("unexpected end of key document");
            }
            return source.charAt(position);
        }

        private void expect(char expected) {
            skipWhitespace();
            if (peek() != expected) {
                throw new IllegalArgumentException(
                        "expected '" + expected + "' at offset " + position);
            }
            position++;
        }
    }
}
