package io.github.serengil.lightphe.model;

import io.github.serengil.lightphe.commons.Logger;
import io.github.serengil.lightphe.commons.PheUtils;
import io.github.serengil.lightphe.model.value.CipherValue;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import lombok.Getter;
import lombok.experimental.Accessors;

/**
 * A vector of encrypted real numbers.
 *
 * <p>Java counterpart of {@code lightphe.models.Tensor.EncryptedTensor}, where the Python operators
 * {@code @}, {@code *} and {@code +} become {@link #matmul}, {@link #multiply} and {@link #add}.
 *
 * <p>Sign handling is the one place where partial homomorphism shows through: a scheme cannot
 * compare a ciphertext against zero, so signs are tracked in the clear alongside the encrypted
 * magnitudes. When two operands of a homomorphic addition disagree in sign the result's sign cannot
 * be determined, and the tensor reports it as positive.
 *
 * <h2>Example</h2>
 *
 * <pre>{@code
 * EncryptedTensor encrypted = cs.encryptTensor(List.of(1.005, 2.05, 3.6));
 * List<Double> restored = cs.decryptTensor(encrypted.multiply(2));
 * }</pre>
 */
@Getter
@Accessors(fluent = true)
public final class EncryptedTensor {

    private static final Logger logger = Logger.forModule(EncryptedTensor.class);

    /** Above this many elements the dot product sums its terms in parallel. */
    private static final int PARALLEL_SUM_THRESHOLD = 10000;

    /** The individual encrypted tensor items. */
    private final List<Fraction> fractions;

    /** The cryptosystem the fractions were produced with. */
    private final Homomorphic cs;

    /** How many digits after the decimal point the fractions preserve. */
    private final int precision;

    /**
     * Creates an encrypted tensor.
     *
     * @param fractions the fractions storing the individual encrypted tensor items
     * @param cs the built cryptosystem
     * @param precision the precision of the tensor
     */
    public EncryptedTensor(List<Fraction> fractions, Homomorphic cs, int precision) {
        this.fractions = List.copyOf(fractions);
        this.cs = cs;
        this.precision = precision;
    }

    /**
     * Creates an encrypted tensor with the default precision of five digits.
     *
     * @param fractions the fractions storing the individual encrypted tensor items
     * @param cs the built cryptosystem
     */
    public EncryptedTensor(List<Fraction> fractions, Homomorphic cs) {
        this(fractions, cs, 5);
    }

    /**
     * Computes the dot product of this encrypted tensor with a plain one.
     *
     * <p>The result is a single-element tensor holding the encrypted sum of the element-wise
     * products.
     *
     * @param other the plain tensor
     * @return a one-element encrypted tensor carrying the dot product
     * @throws IllegalArgumentException when either tensor is empty or the sizes differ
     */
    public EncryptedTensor matmul(List<? extends Number> other) {
        EncryptedTensor products = multiply(other);

        if (products.fractions.isEmpty()) {
            throw new IllegalArgumentException("Dot product cannot be calculated for empty tensor");
        }

        CipherValue divisor = products.fractions.get(0).divisor();
        List<Fraction> terms = products.fractions;

        CipherValue total;
        if (terms.size() > PARALLEL_SUM_THRESHOLD) {
            // Homomorphic addition is associative, so the terms can be folded in any grouping.
            total =
                    IntStream.range(0, terms.size())
                            .parallel()
                            .mapToObj(index -> terms.get(index).absDividend())
                            .reduce(cs::add)
                            .orElseThrow();
        } else {
            total = terms.get(0).absDividend();
            for (int i = 1; i < terms.size(); i++) {
                total = cs.add(total, terms.get(i).absDividend());
            }
        }

        Fraction fraction =
                Fraction.builder()
                        .dividend(total)
                        .absDividend(total)
                        .divisor(divisor)
                        .sign(1)
                        .build();

        return new EncryptedTensor(List.of(fraction), cs, precision);
    }

    /**
     * Performs homomorphic element-wise multiplication with another encrypted tensor.
     *
     * @param other the other encrypted tensor
     * @return the element-wise product
     * @throws IllegalArgumentException when the tensor sizes differ
     */
    public EncryptedTensor multiply(EncryptedTensor other) {
        if (fractions.size() != other.fractions.size()) {
            throw new IllegalArgumentException(
                    "Tensor sizes must be equal in homomorphic multiplication");
        }

        List<Fraction> products = new ArrayList<>(fractions.size());
        for (int i = 0; i < fractions.size(); i++) {
            Fraction alpha = fractions.get(i);
            Fraction beta = other.fractions.get(i);

            products.add(
                    Fraction.builder()
                            .dividend(cs.multiply(alpha.dividend(), beta.dividend()))
                            .absDividend(cs.multiply(alpha.absDividend(), beta.absDividend()))
                            .divisor(cs.multiply(alpha.divisor(), beta.divisor()))
                            .sign(alpha.sign() * beta.sign())
                            .build());
        }
        return new EncryptedTensor(products, cs, precision);
    }

    /**
     * Performs element-wise multiplication of this encrypted tensor with a plain one.
     *
     * @param other the plain tensor
     * @return the element-wise product
     * @throws IllegalArgumentException when the sizes differ, or when either tensor holds a
     *     negative item
     */
    public EncryptedTensor multiply(List<? extends Number> other) {
        if (fractions.size() != other.size()) {
            throw new IllegalArgumentException(
                    "Tensor sizes must be equal in homomorphic multiplication");
        }

        boolean anyNegative =
                other.stream().anyMatch(value -> value.doubleValue() < 0)
                        || fractions.stream().anyMatch(fraction -> fraction.sign() < 0);
        if (anyNegative) {
            throw new IllegalArgumentException(
                    "all items in the plain and encrypted tensor must be positive"
                            + " to perform element wise multiplication");
        }

        BigInteger modulo = cs.plaintextModulo();
        List<Fraction> products = new ArrayList<>(fractions.size());
        CipherValue divisor = null;

        for (int i = 0; i < fractions.size(); i++) {
            Fraction alpha = fractions.get(i);
            double beta = Math.abs(other.get(i).doubleValue());
            double reduced =
                    new BigDecimal(beta).compareTo(new BigDecimal(modulo)) > 0
                            ? beta % modulo.doubleValue()
                            : beta;

            PheUtils.Fractionized fractionized = PheUtils.fractionize(reduced, modulo, precision);

            CipherValue dividend =
                    cs.multiplyByConstant(alpha.absDividend(), fractionized.dividend());

            if (divisor == null) {
                divisor = cs.multiplyByConstant(alpha.divisor(), fractionized.divisor());
            }

            products.add(
                    Fraction.builder()
                            .dividend(dividend)
                            .absDividend(dividend)
                            .divisor(divisor)
                            .sign(1)
                            .build());
        }

        return new EncryptedTensor(products, cs, precision);
    }

    /**
     * Multiplies every item of this tensor by a known plain constant.
     *
     * @param constant the constant
     * @return the scaled tensor
     */
    public EncryptedTensor multiply(BigInteger constant) {
        int constantSign = constant.signum() >= 0 ? 1 : -1;
        return scale(constant.abs(), constantSign);
    }

    /**
     * Multiplies every item of this tensor by a known plain constant.
     *
     * @param constant the constant
     * @return the scaled tensor
     */
    public EncryptedTensor multiply(long constant) {
        return multiply(BigInteger.valueOf(constant));
    }

    /**
     * Multiplies every item of this tensor by a known real constant, which is first normalised into
     * the message space.
     *
     * @param constant the constant
     * @return the scaled tensor
     */
    public EncryptedTensor multiply(double constant) {
        int constantSign = constant >= 0 ? 1 : -1;
        BigInteger normalized = PheUtils.normalizeInput(Math.abs(constant), cs.plaintextModulo());
        return scale(normalized, constantSign);
    }

    private EncryptedTensor scale(BigInteger constant, int constantSign) {
        List<Fraction> scaled = new ArrayList<>(fractions.size());
        for (Fraction alpha : fractions) {
            // notice that the divisor is alpha's own divisor rather than a product
            scaled.add(
                    Fraction.builder()
                            .dividend(cs.multiplyByConstant(alpha.dividend(), constant))
                            .absDividend(cs.multiplyByConstant(alpha.absDividend(), constant))
                            .divisor(alpha.divisor())
                            .sign(constantSign * alpha.sign())
                            .build());
        }
        return new EncryptedTensor(scaled, cs, precision);
    }

    /**
     * Performs homomorphic addition with another encrypted tensor.
     *
     * @param other the other encrypted tensor
     * @return the element-wise sum
     * @throws IllegalArgumentException when the tensor sizes differ
     */
    public EncryptedTensor add(EncryptedTensor other) {
        if (fractions.size() != other.fractions.size()) {
            throw new IllegalArgumentException("Fraction sizes must be equal");
        }

        List<Fraction> sums = new ArrayList<>(fractions.size());
        for (int i = 0; i < fractions.size(); i++) {
            Fraction alpha = fractions.get(i);
            Fraction beta = other.fractions.get(i);

            CipherValue dividend = cs.add(alpha.dividend(), beta.dividend());
            CipherValue absDividend = cs.add(alpha.absDividend(), beta.absDividend());

            // notice that the divisor is alpha's own divisor rather than a sum
            if (alpha.sign() == -1 && beta.sign() == -1) {
                sums.add(
                        Fraction.builder()
                                .dividend(dividend)
                                .absDividend(absDividend)
                                .divisor(alpha.divisor())
                                .sign(-1)
                                .build());
            } else {
                // if one is positive and one is negative then the result's sign cannot be known;
                // trust the modular arithmetic instead.
                if (alpha.sign() != beta.sign()) {
                    int index = i;
                    logger.warn(
                            index
                                    + "-th items of the vectors have different signs, and "
                                    + "result's sign cannot be determined in PHE. Result will "
                                    + "be shown for positive for this anyway.");
                }

                sums.add(
                        Fraction.builder()
                                .dividend(dividend)
                                .absDividend(dividend)
                                .divisor(alpha.divisor())
                                .sign(1)
                                .build());
            }
        }

        return new EncryptedTensor(sums, cs, precision);
    }

    @Override
    public String toString() {
        return fractions.stream().map(Fraction::toString).collect(Collectors.joining(", "));
    }
}
