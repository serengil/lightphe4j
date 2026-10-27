package io.github.serengil.lightphe.commons;

import io.github.serengil.lightphe.model.ArgmaxMessage;
import io.github.serengil.lightphe.model.Homomorphic;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.IntValue;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

/**
 * Classification over encrypted data, the counterpart of {@code lightphe.commons.classifiers}.
 *
 * <p>Client (private key owner) encrypts its features, and server evaluates its private model on
 * them, so client learns only the predicted class, and server learns nothing about the features.
 *
 * <ul>
 *   <li>hyperplane: class scores {@code <w_i, x> + b_i} are linear in the encrypted features. They
 *       are shifted by {@code 2^bitLength} to be non-negative, which keeps the argmax.
 *   <li>naive bayes: client encrypts each categorical feature as a one-hot vector, so the score
 *       {@code log P(c) + sum of log P(x_j | c)} is linear in it. Log probabilities are quantized,
 *       and the log probabilities of each feature are shifted by their minimum, which adds the same
 *       constant to scores of all classes, so it keeps the argmax.
 *   <li>argmax: interactive argmax of Damgard-Geisler-Kroigaard on encrypted scores.
 * </ul>
 *
 * <p>Ref: Bost, R., Popa, R. A., Tu, S., Goldwasser, S. (2015). Machine Learning Classification
 * over Encrypted Data. NDSS 2015.
 */
public final class Classifiers {

    private Classifiers() {
        throw new AssertionError("no instances");
    }

    /**
     * Quantized log probabilities of a naive bayes model.
     *
     * @param priors quantized log priors of classes
     * @param likelihoods quantized log likelihoods, {@code likelihoods[c][j][v]}
     * @param bitLength scores are less than {@code 2^bitLength}
     */
    public record QuantizedNaiveBayes(
            List<BigInteger> priors, List<List<List<BigInteger>>> likelihoods, int bitLength) {}

    /**
     * Finds the class of the greatest score {@code <w_i, x> + b_i} for encrypted features x.
     *
     * @param cs Damgard-Geisler-Kroigaard cryptosystem having the public key
     * @param encryptedFeatures features encrypted by the client
     * @param weights weights of each class
     * @param biases bias of each class
     * @param bitLength absolute values of scores must be less than {@code 2^bitLength}
     * @param client sends a message to the client and returns its response
     * @return the encrypted index of the predicted class
     */
    public static CipherValue evaluateHyperplane(
            Homomorphic cs,
            List<CipherValue> encryptedFeatures,
            List<List<BigInteger>> weights,
            List<BigInteger> biases,
            int bitLength,
            Function<ArgmaxMessage, List<BigInteger>> client) {
        BigInteger u = cs.plaintextModulo();
        BigInteger offset = BigInteger.ONE.shiftLeft(bitLength);
        List<BigInteger> scores = new ArrayList<>(weights.size());
        for (int c = 0; c < weights.size(); c++) {
            CipherValue score = cs.encrypt(biases.get(c).add(offset).mod(u));
            List<BigInteger> classWeights = weights.get(c);
            for (int j = 0; j < classWeights.size(); j++) {
                BigInteger weight = classWeights.get(j).mod(u);
                if (weight.signum() != 0) {
                    score = cs.add(score, cs.multiplyByConstant(encryptedFeatures.get(j), weight));
                }
            }
            scores.add(asInteger(score));
        }
        // scores are in [0, 2^(bitLength + 1)) after the shift
        return IntValue.of(cs.evaluateArgmax(scores, bitLength + 1, client));
    }

    /**
     * Quantizes log probabilities of a naive bayes model to non-negative integers.
     *
     * @param priors {@code P(c)} of each class
     * @param likelihoods {@code P(x_j = v | c)} for class c, feature j and value v, i.e. {@code
     *     likelihoods[c][j][v]}
     * @param precision number of decimal digits kept from log probabilities
     * @return the quantized model
     * @throws IllegalArgumentException when a probability is not in {@code (0, 1]}
     */
    public static QuantizedNaiveBayes quantizeNaiveBayes(
            List<? extends Number> priors,
            List<? extends List<? extends List<? extends Number>>> likelihoods,
            int precision) {
        double scale = Math.pow(10, precision);

        List<Double> logPriors = new ArrayList<>(priors.size());
        for (Number prior : priors) {
            logPriors.add(log(prior));
        }
        double lowestPrior = logPriors.stream().mapToDouble(Double::doubleValue).min().orElse(0);
        List<BigInteger> quantizedPriors = new ArrayList<>(priors.size());
        for (double logPrior : logPriors) {
            quantizedPriors.add(round((logPrior - lowestPrior) * scale));
        }

        int features = likelihoods.get(0).size();
        List<List<List<BigInteger>>> quantizedLikelihoods = new ArrayList<>();
        for (int c = 0; c < likelihoods.size(); c++) {
            quantizedLikelihoods.add(new ArrayList<>());
        }
        for (int j = 0; j < features; j++) {
            List<List<Double>> logs = new ArrayList<>();
            double lowest = Double.POSITIVE_INFINITY;
            for (List<? extends List<? extends Number>> classLikelihoods : likelihoods) {
                List<Double> values = new ArrayList<>();
                for (Number probability : classLikelihoods.get(j)) {
                    double value = log(probability);
                    values.add(value);
                    lowest = Math.min(lowest, value);
                }
                logs.add(values);
            }
            for (int c = 0; c < logs.size(); c++) {
                List<BigInteger> quantized = new ArrayList<>();
                for (double value : logs.get(c)) {
                    quantized.add(round((value - lowest) * scale));
                }
                quantizedLikelihoods.get(c).add(quantized);
            }
        }

        BigInteger largest = BigInteger.ZERO;
        for (int c = 0; c < quantizedPriors.size(); c++) {
            BigInteger score = quantizedPriors.get(c);
            for (List<BigInteger> values : quantizedLikelihoods.get(c)) {
                score = score.add(values.stream().reduce(BigInteger.ZERO, BigInteger::max));
            }
            largest = largest.max(score);
        }
        return new QuantizedNaiveBayes(
                quantizedPriors, quantizedLikelihoods, Math.max(1, largest.bitLength()));
    }

    /**
     * Encrypts categorical features as one-hot vectors. Runs on client side.
     *
     * @param cs additively homomorphic cryptosystem
     * @param features value of each feature in {@code [0, domain size)}
     * @param domainSizes number of values of each feature
     * @return {@code E(1)} at the value, and {@code E(0)} elsewhere, for each feature
     */
    public static List<List<CipherValue>> encryptNaiveBayesInput(
            Homomorphic cs, List<Integer> features, List<Integer> domainSizes) {
        List<List<CipherValue>> encrypted = new ArrayList<>(features.size());
        for (int j = 0; j < features.size(); j++) {
            List<CipherValue> oneHot = new ArrayList<>(domainSizes.get(j));
            for (int value = 0; value < domainSizes.get(j); value++) {
                oneHot.add(cs.encrypt(value == features.get(j) ? BigInteger.ONE : BigInteger.ZERO));
            }
            encrypted.add(oneHot);
        }
        return encrypted;
    }

    /**
     * Finds the most probable class of a naive bayes model for encrypted one-hot features.
     *
     * @param cs Damgard-Geisler-Kroigaard cryptosystem having the public key
     * @param encryptedInput output of {@link #encryptNaiveBayesInput}
     * @param model the quantized model
     * @param client sends a message to the client and returns its response
     * @return the encrypted index of the predicted class
     */
    public static CipherValue evaluateNaiveBayes(
            Homomorphic cs,
            List<List<CipherValue>> encryptedInput,
            QuantizedNaiveBayes model,
            Function<ArgmaxMessage, List<BigInteger>> client) {
        BigInteger u = cs.plaintextModulo();
        List<BigInteger> scores = new ArrayList<>(model.priors().size());
        for (int c = 0; c < model.priors().size(); c++) {
            CipherValue score = cs.encrypt(model.priors().get(c).mod(u));
            List<List<BigInteger>> classLikelihoods = model.likelihoods().get(c);
            for (int j = 0; j < encryptedInput.size(); j++) {
                List<CipherValue> oneHot = encryptedInput.get(j);
                List<BigInteger> values = classLikelihoods.get(j);
                for (int v = 0; v < oneHot.size(); v++) {
                    BigInteger value = values.get(v).mod(u);
                    if (value.signum() != 0) {
                        score = cs.add(score, cs.multiplyByConstant(oneHot.get(v), value));
                    }
                }
            }
            scores.add(asInteger(score));
        }
        return IntValue.of(cs.evaluateArgmax(scores, model.bitLength(), client));
    }

    /**
     * Checks that every class of a linear model has the same number of weights.
     *
     * @param weights weights of each class
     * @throws IllegalArgumentException when classes have different shapes
     */
    public static void validateWeightsShape(List<? extends List<?>> weights) {
        if (weights == null || weights.isEmpty()) {
            throw new IllegalArgumentException("Weights must be a non-empty list of class weights");
        }
        for (List<?> classWeights : weights) {
            if (classWeights == null || classWeights.size() != weights.get(0).size()) {
                throw new IllegalArgumentException(
                        "Every class must have the same number of weights");
            }
        }
    }

    /**
     * Checks that every class of a naive bayes model has likelihoods of the same features and
     * values.
     *
     * @param likelihoods likelihoods of each class
     * @throws IllegalArgumentException when classes have different shapes
     */
    public static void validateLikelihoodsShape(
            List<? extends List<? extends List<?>>> likelihoods) {
        if (likelihoods == null || likelihoods.isEmpty()) {
            throw new IllegalArgumentException(
                    "Likelihoods must be a non-empty list of class likelihoods");
        }
        List<Integer> shape = shapeOf(likelihoods.get(0));
        for (List<? extends List<?>> classLikelihoods : likelihoods) {
            if (!shapeOf(classLikelihoods).equals(shape)) {
                throw new IllegalArgumentException(
                        "Every class must have likelihoods of the same features and values");
            }
        }
    }

    private static List<Integer> shapeOf(List<? extends List<?>> classLikelihoods) {
        return classLikelihoods.stream().map(List::size).toList();
    }

    private static double log(Number probability) {
        double value = probability == null ? Double.NaN : probability.doubleValue();
        if (!(value > 0 && value <= 1)) {
            throw new IllegalArgumentException(
                    "Probabilities must be in (0, 1], got "
                            + probability
                            + ". Smooth zero probabilities, e.g. with Laplace smoothing.");
        }
        return Math.log(value);
    }

    /** Rounds half to even as Python's round does. */
    private static BigInteger round(double value) {
        return new BigDecimal(Math.rint(value)).toBigInteger();
    }

    private static BigInteger asInteger(CipherValue value) {
        if (!(value instanceof IntValue integer)) {
            throw new IllegalArgumentException("expected an integer ciphertext");
        }
        return integer.value();
    }
}
