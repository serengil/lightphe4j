package io.github.serengil.lightphe.commons;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;

/**
 * Conversions between the plain values callers work with and the integers cryptosystems encrypt.
 *
 * <p>Java counterpart of {@code lightphe.commons.phe_utils}.
 */
public final class PheUtils {

    /** Working precision of the decimal arithmetic, matching {@code getcontext().prec = 50}. */
    private static final MathContext CONTEXT = new MathContext(50);

    private static final BigInteger TEN = BigInteger.TEN;

    private static final Logger logger = Logger.forModule(PheUtils.class);

    private PheUtils() {
        throw new AssertionError("no instances");
    }

    /**
     * Result of splitting a real number into an integer dividend over a power-of-ten divisor.
     *
     * @param dividend the scaled numerator, already reduced modulo the plaintext modulus
     * @param divisor the scaling factor, a power of ten
     */
    public record Fractionized(BigInteger dividend, BigInteger divisor) {}

    /**
     * Normalises an integer value into the range of the modulus.
     *
     * @param value the value to normalise
     * @param modulo the modulus
     * @return {@code value mod modulo}
     */
    public static BigInteger normalizeInput(BigInteger value, BigInteger modulo) {
        if (value.compareTo(modulo) > 0) {
            logger.warn(
                    "Value "
                            + value
                            + " is greater than modulo "
                            + modulo
                            + ". Normalizing it to be in the range of modulo.");
        }
        return value.mod(modulo);
    }

    /**
     * Normalises a real value into the range of the modulus.
     *
     * <p>A non-negative float {@code v} is written as {@code dividend / divisor} and mapped to
     * {@code dividend * divisor^-1 mod modulo}. Negative floats are rejected, exactly as the Python
     * implementation does.
     *
     * @param value the value to normalise
     * @param modulo the modulus
     * @return the normalised value
     * @throws IllegalArgumentException when {@code value} is negative
     */
    public static BigInteger normalizeInput(double value, BigInteger modulo) {
        if (value < 0) {
            // TODO: think and implement this later
            throw new IllegalArgumentException(
                    "Case constant float and negative not implemented yet");
        }
        Fractionized fraction = fractionize(value, modulo);
        logger.debug(() -> fraction.dividend() + "*" + fraction.divisor() + "^-1 mod " + modulo);
        return fraction.dividend().multiply(fraction.divisor().modInverse(modulo)).mod(modulo);
    }

    /**
     * Splits a real value into an integer dividend over a power-of-ten divisor, deriving the number
     * of decimal places from the value itself.
     *
     * @param value the value to split
     * @param modulo the modulus the dividend is reduced by
     * @return the dividend and divisor
     */
    public static Fractionized fractionize(double value, BigInteger modulo) {
        return fractionize(value, modulo, null);
    }

    /**
     * Splits a real value into an integer dividend over a power-of-ten divisor.
     *
     * @param value the value to split
     * @param modulo the modulus the dividend is reduced by
     * @param precision how many digits after the decimal point to keep; {@code null} derives the
     *     count from the value's own representation
     * @return the dividend and divisor
     */
    public static Fractionized fractionize(double value, BigInteger modulo, Integer precision) {
        BigInteger scalingFactor;
        if (precision == null) {
            scalingFactor = TEN.pow(decimalPlaces(value));
        } else {
            scalingFactor = TEN.pow(precision);
        }

        // The reference implementation wraps this in a rescaling loop. With an explicit precision
        // the scaling factor is exactly 10^precision, so neither rescaling branch can fire and the
        // loop always terminates on its first pass; the same holds when the precision is derived.
        BigInteger integerValue =
                new BigDecimal(value, CONTEXT)
                        .multiply(new BigDecimal(scalingFactor), CONTEXT)
                        .toBigInteger()
                        .mod(modulo);

        BigInteger factor = scalingFactor;
        logger.debug(() -> integerValue + "*" + factor + "^-1 mod " + modulo);
        return new Fractionized(integerValue, scalingFactor);
    }

    /**
     * Counts the digits after the decimal point in the shortest representation of a double, the
     * Java equivalent of {@code len(str(value).split(".")[1])}.
     *
     * @param value the value to inspect
     * @return the number of decimal places, at least one
     */
    static int decimalPlaces(double value) {
        String repr = Double.toString(Math.abs(value));
        int exponentIndex = repr.indexOf('E');
        int exponent = 0;
        if (exponentIndex >= 0) {
            exponent = Integer.parseInt(repr.substring(exponentIndex + 1));
            repr = repr.substring(0, exponentIndex);
        }
        int dotIndex = repr.indexOf('.');
        int places = dotIndex < 0 ? 0 : repr.length() - dotIndex - 1;
        places -= exponent;
        return Math.max(places, 1);
    }
}
