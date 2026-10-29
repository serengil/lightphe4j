package io.github.serengil.lightphe.commons;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A minimal json reader and writer, keeping the library free of a json dependency.
 *
 * <p>Integers are read as {@link BigInteger} of arbitrary length and numbers with a fraction or an
 * exponent as {@link Double}, objects as {@link LinkedHashMap} and arrays as {@link ArrayList}.
 * Output uses the separators and ascii escaping of Python's {@code json.dumps}.
 */
public final class Json {

    private Json() {
        throw new AssertionError("no instances");
    }

    /**
     * Writes a json serializable item.
     *
     * @param item null, Boolean, Number, String, List or Map with string keys of them
     * @return the json document
     * @throws IllegalArgumentException when the item is not json serializable
     */
    public static String write(Object item) {
        StringBuilder out = new StringBuilder();
        write(out, item);
        return out.toString();
    }

    /**
     * Parses a json document.
     *
     * @param json the json document
     * @return the parsed item
     * @throws IllegalArgumentException when the document is not a valid json
     */
    public static Object read(String json) {
        Parser parser = new Parser(json);
        Object item = parser.parseValue();
        parser.skipWhitespace();
        if (!parser.atEnd()) {
            throw new IllegalArgumentException("trailing content at offset " + parser.position);
        }
        return item;
    }

    private static void write(StringBuilder out, Object item) {
        if (item == null) {
            out.append("null");
        } else if (item instanceof Boolean bool) {
            out.append(bool ? "true" : "false");
        } else if (item instanceof Double || item instanceof Float) {
            double value = ((Number) item).doubleValue();
            if (!Double.isFinite(value)) {
                throw new IllegalArgumentException("json cannot represent " + value);
            }
            out.append(value);
        } else if (item instanceof Number number) {
            out.append(number);
        } else if (item instanceof CharSequence text) {
            writeString(out, text.toString());
        } else if (item instanceof Map<?, ?> map) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!(entry.getKey() instanceof String key)) {
                    throw new IllegalArgumentException("json keys must be strings");
                }
                if (!first) {
                    out.append(", ");
                }
                first = false;
                writeString(out, key);
                out.append(": ");
                write(out, entry.getValue());
            }
            out.append('}');
        } else if (item instanceof List<?> list) {
            out.append('[');
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) {
                    out.append(", ");
                }
                write(out, list.get(i));
            }
            out.append(']');
        } else {
            throw new IllegalArgumentException(
                    "Object of type " + item.getClass().getSimpleName() + " is not json");
        }
    }

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
                    if (c < 0x20 || c > 0x7e) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    /** Recursive-descent json reader. */
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
            while (!atEnd() && " \t\n\r".indexOf(source.charAt(position)) >= 0) {
                position++;
            }
        }

        Object parseValue() {
            skipWhitespace();
            char current = peek();
            return switch (current) {
                case '{' -> parseObject();
                case '[' -> parseArray();
                case '"' -> parseString();
                case 't' -> parseLiteral("true", Boolean.TRUE);
                case 'f' -> parseLiteral("false", Boolean.FALSE);
                case 'n' -> parseLiteral("null", null);
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
                char next = next();
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
                char next = next();
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
                char current = next();
                if (current == '"') {
                    return out.toString();
                }
                if (current < 0x20) {
                    throw new IllegalArgumentException(
                            "control character in string at offset " + position);
                }
                if (current != '\\') {
                    out.append(current);
                    continue;
                }
                char escaped = next();
                switch (escaped) {
                    case '"', '\\', '/' -> out.append(escaped);
                    case 'n' -> out.append('\n');
                    case 't' -> out.append('\t');
                    case 'r' -> out.append('\r');
                    case 'b' -> out.append('\b');
                    case 'f' -> out.append('\f');
                    case 'u' -> {
                        if (position + 4 > source.length()) {
                            throw new IllegalArgumentException("unexpected end of json");
                        }
                        try {
                            out.append(
                                    (char)
                                            Integer.parseInt(
                                                    source.substring(position, position + 4), 16));
                        } catch (NumberFormatException err) {
                            throw new IllegalArgumentException(
                                    "invalid unicode escape at offset " + position, err);
                        }
                        position += 4;
                    }
                    default ->
                            throw new IllegalArgumentException(
                                    "invalid escape at offset " + position);
                }
            }
        }

        private Object parseLiteral(String literal, Object value) {
            if (!source.startsWith(literal, position)) {
                throw new IllegalArgumentException("unexpected literal at offset " + position);
            }
            position += literal.length();
            return value;
        }

        private Object parseNumber() {
            int start = position;
            if (peek() == '-') {
                position++;
            }
            int digits = skipDigits();
            if (digits == 0) {
                throw new IllegalArgumentException("expected a value at offset " + start);
            }
            if (digits > 1 && source.charAt(position - digits) == '0') {
                throw new IllegalArgumentException("leading zero at offset " + start);
            }
            boolean integral = true;
            if (!atEnd() && source.charAt(position) == '.') {
                integral = false;
                position++;
                if (skipDigits() == 0) {
                    throw new IllegalArgumentException("expected a digit at offset " + position);
                }
            }
            if (!atEnd() && (source.charAt(position) == 'e' || source.charAt(position) == 'E')) {
                integral = false;
                position++;
                if (!atEnd()
                        && (source.charAt(position) == '+' || source.charAt(position) == '-')) {
                    position++;
                }
                if (skipDigits() == 0) {
                    throw new IllegalArgumentException("expected a digit at offset " + position);
                }
            }
            String number = source.substring(start, position);
            return integral ? new BigInteger(number) : (Object) Double.parseDouble(number);
        }

        private int skipDigits() {
            int start = position;
            while (!atEnd() && source.charAt(position) >= '0' && source.charAt(position) <= '9') {
                position++;
            }
            return position - start;
        }

        private char peek() {
            if (atEnd()) {
                throw new IllegalArgumentException("unexpected end of json");
            }
            return source.charAt(position);
        }

        private char next() {
            char current = peek();
            position++;
            return current;
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
