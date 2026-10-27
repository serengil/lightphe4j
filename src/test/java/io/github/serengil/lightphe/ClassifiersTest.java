package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.serengil.lightphe.commons.Classifiers;
import io.github.serengil.lightphe.model.Ciphertext;
import io.github.serengil.lightphe.model.Keys;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Port of {@code tests/test_classifiers.py}. */
class ClassifiersTest {

    // 512-bit keys have the same 32-bit plaintext space as 1024-bit keys, but are faster.
    // they are not secure, and are for testing only.
    private static final LightPHE clientCs =
            LightPHE.builder().algorithmName("Damgard-Geisler-Kroigaard").keySize(512).build();

    private static final LightPHE serverCs =
            LightPHE.builder()
                    .algorithmName("Damgard-Geisler-Kroigaard")
                    .keys(Keys.of(clientCs.cs().keys().publicKey(), null))
                    .build();

    private static int classifyHyperplane(
            List<Long> features, List<List<Long>> weights, int bitLength, List<Long> biases) {
        List<Ciphertext> encryptedFeatures = features.stream().map(clientCs::encrypt).toList();
        Ciphertext encryptedClass =
                serverCs.evaluateHyperplane(
                        encryptedFeatures, weights, bitLength, clientCs::answerArgmax, biases);
        return clientCs.decrypt(encryptedClass).intValueExact();
    }

    private static int classifyNaiveBayes(
            List<Integer> features, List<Double> priors, List<List<List<Double>>> likelihoods) {
        List<Integer> domainSizes = likelihoods.get(0).stream().map(List::size).toList();
        List<List<Ciphertext>> encryptedInput =
                clientCs.encryptNaiveBayesInput(features, domainSizes);
        Ciphertext encryptedClass =
                serverCs.evaluateNaiveBayes(
                        encryptedInput, priors, likelihoods, clientCs::answerArgmax);
        return clientCs.decrypt(encryptedClass).intValueExact();
    }

    private static int argmax(List<Double> scores) {
        int best = 0;
        for (int i = 1; i < scores.size(); i++) {
            if (scores.get(i) > scores.get(best)) {
                best = i;
            }
        }
        return best;
    }

    private static long randomInt(Random random, int low, int high) {
        return low + random.nextInt(high - low + 1);
    }

    @Test
    @DisplayName("Encrypted hyperplane classification matches plain argmax")
    void testHyperplaneMatchesPlainArgmax() {
        Random random = new Random(1);
        for (int round = 0; round < 8; round++) {
            List<List<Long>> weights = new ArrayList<>();
            List<Long> biases = new ArrayList<>();
            for (int c = 0; c < 4; c++) {
                List<Long> classWeights = new ArrayList<>();
                for (int j = 0; j < 6; j++) {
                    classWeights.add(randomInt(random, -20, 20));
                }
                weights.add(classWeights);
                biases.add(randomInt(random, -100, 100));
            }
            List<Long> features = new ArrayList<>();
            for (int j = 0; j < 6; j++) {
                features.add(randomInt(random, -30, 30));
            }
            List<Double> scores = new ArrayList<>();
            for (int c = 0; c < 4; c++) {
                long score = biases.get(c);
                for (int j = 0; j < 6; j++) {
                    score += weights.get(c).get(j) * features.get(j);
                }
                scores.add((double) score);
            }
            // scores are in (-2^13, 2^13)
            assertThat(classifyHyperplane(features, weights, 13, biases)).isEqualTo(argmax(scores));
        }
    }

    @Test
    @DisplayName("Ties return the earlier class, and binary classifiers work")
    void testHyperplaneTiesAndBinaryClassification() {
        // earlier class on ties
        assertThat(
                        classifyHyperplane(
                                List.of(1L, 1L),
                                List.of(List.of(2L, 0L), List.of(0L, 2L), List.of(1L, 1L)),
                                4,
                                null))
                .isZero();

        // a binary linear classifier is a hyperplane of two classes: 0 and w
        List<Long> weights = List.of(3L, -2L, 5L);
        for (List<Long> features : List.of(List.of(1L, 4L, 0L), List.of(2L, 1L, 1L))) {
            long score = -4;
            for (int j = 0; j < 3; j++) {
                score += weights.get(j) * features.get(j);
            }
            assertThat(
                            classifyHyperplane(
                                    features,
                                    List.of(List.of(0L, 0L, 0L), weights),
                                    8,
                                    List.of(0L, -4L)))
                    .isEqualTo(score > 0 ? 1 : 0);
        }
    }

    @Test
    @DisplayName("A customer learns only whether the loan is approved")
    void testCreditApprovalWithLogisticRegression() {
        // features: income in thousands, debt in thousands, years of employment, late payments
        double[] floatWeights = {0.042, -0.065, 0.31, -0.9};
        double floatBias = -1.2;
        List<Long> quantized = new ArrayList<>();
        for (double w : floatWeights) {
            quantized.add(Math.round(w * 1000));
        }
        List<List<Long>> weights = List.of(List.of(0L, 0L, 0L, 0L), quantized);
        List<Long> biases = List.of(0L, Math.round(floatBias * 1000));

        for (List<Long> features :
                List.of(
                        List.of(85L, 20L, 6L, 0L),
                        List.of(30L, 45L, 1L, 3L),
                        List.of(55L, 10L, 3L, 1L))) {
            double logit = floatBias;
            for (int j = 0; j < 4; j++) {
                logit += floatWeights[j] * features.get(j);
            }
            assertThat(classifyHyperplane(features, weights, 16, biases))
                    .isEqualTo(logit > 0 ? 1 : 0);
        }
    }

    @Test
    @DisplayName("Encrypted naive bayes matches plain prediction")
    void testNaiveBayesMatchesPlainPrediction() {
        Random random = new Random(2);
        List<Integer> domainSizes = List.of(2, 3, 2);
        List<Double> priors = List.of(0.5, 0.3, 0.2);
        List<List<List<Double>>> likelihoods = new ArrayList<>();
        for (int c = 0; c < priors.size(); c++) {
            List<List<Double>> classLikelihoods = new ArrayList<>();
            for (int size : domainSizes) {
                double[] values = new double[size];
                double total = 0;
                for (int v = 0; v < size; v++) {
                    values[v] = 0.05 + random.nextDouble() * 0.95;
                    total += values[v];
                }
                List<Double> normalized = new ArrayList<>();
                for (double value : values) {
                    normalized.add(value / total);
                }
                classLikelihoods.add(normalized);
            }
            likelihoods.add(classLikelihoods);
        }

        for (int a = 0; a < 2; a++) {
            for (int b = 0; b < 3; b++) {
                for (int d = 0; d < 2; d++) {
                    List<Integer> features = List.of(a, b, d);
                    List<Double> scores = new ArrayList<>();
                    for (int c = 0; c < priors.size(); c++) {
                        double score = Math.log(priors.get(c));
                        for (int j = 0; j < features.size(); j++) {
                            score += Math.log(likelihoods.get(c).get(j).get(features.get(j)));
                        }
                        scores.add(score);
                    }
                    List<Double> ranked =
                            scores.stream().sorted((x, y) -> Double.compare(y, x)).toList();
                    // quantization with precision 3 cannot separate scores closer than 10^-2
                    if (ranked.get(0) - ranked.get(1) < 1e-2) {
                        continue;
                    }
                    assertThat(classifyNaiveBayes(features, priors, likelihoods))
                            .isEqualTo(argmax(scores));
                }
            }
        }
    }

    @Test
    @DisplayName("A patient learns only the most likely diagnosis")
    void testMedicalDiagnosisWithNaiveBayes() {
        // symptoms: fever (no, yes), cough (none, dry, wet), fatigue (no, yes)
        // diagnoses: cold, flu, allergy
        List<List<int[]>> records =
                List.of(
                        List.of(
                                new int[] {0, 2, 0},
                                new int[] {0, 2, 1},
                                new int[] {1, 2, 0},
                                new int[] {0, 1, 0},
                                new int[] {0, 2, 0}),
                        List.of(
                                new int[] {1, 1, 1},
                                new int[] {1, 2, 1},
                                new int[] {1, 1, 1},
                                new int[] {1, 1, 0},
                                new int[] {0, 1, 1}),
                        List.of(
                                new int[] {0, 0, 0},
                                new int[] {0, 1, 0},
                                new int[] {0, 0, 1},
                                new int[] {0, 0, 0}));
        int[] domainSizes = {2, 3, 2};
        int total = records.stream().mapToInt(List::size).sum();
        List<Double> priors = records.stream().map(rows -> (double) rows.size() / total).toList();

        // laplace smoothing keeps probabilities positive
        List<List<List<Double>>> likelihoods = new ArrayList<>();
        for (List<int[]> rows : records) {
            List<List<Double>> classLikelihoods = new ArrayList<>();
            for (int j = 0; j < domainSizes.length; j++) {
                List<Double> values = new ArrayList<>();
                for (int v = 0; v < domainSizes[j]; v++) {
                    int feature = j;
                    int value = v;
                    long matches = rows.stream().filter(row -> row[feature] == value).count();
                    values.add((double) (matches + 1) / (rows.size() + domainSizes[j]));
                }
                classLikelihoods.add(values);
            }
            likelihoods.add(classLikelihoods);
        }

        assertThat(classifyNaiveBayes(List.of(1, 1, 1), priors, likelihoods)).isEqualTo(1);
        assertThat(classifyNaiveBayes(List.of(0, 2, 0), priors, likelihoods)).isZero();
        assertThat(classifyNaiveBayes(List.of(0, 0, 0), priors, likelihoods)).isEqualTo(2);
    }

    @Test
    @DisplayName("Naive bayes log probabilities are quantized to non-negative integers")
    void testQuantizationOfNaiveBayes() {
        Classifiers.QuantizedNaiveBayes model =
                Classifiers.quantizeNaiveBayes(
                        List.of(0.25, 0.75),
                        List.of(List.of(List.of(0.5, 0.5)), List.of(List.of(0.1, 0.9))),
                        3);
        // log probabilities are shifted by their minimum, so the smallest one is 0
        assertThat(model.priors()).contains(BigInteger.ZERO);
        List<BigInteger> all =
                model.likelihoods().stream().flatMap(List::stream).flatMap(List::stream).toList();
        assertThat(all).contains(BigInteger.ZERO).allMatch(x -> x.signum() >= 0);

        BigInteger largest = BigInteger.ZERO;
        for (int c = 0; c < model.priors().size(); c++) {
            BigInteger score = model.priors().get(c);
            for (List<BigInteger> values : model.likelihoods().get(c)) {
                score = score.add(values.stream().reduce(BigInteger.ZERO, BigInteger::max));
            }
            largest = largest.max(score);
        }
        assertThat(largest).isLessThan(BigInteger.ONE.shiftLeft(model.bitLength()));
    }

    @Test
    @DisplayName("Invalid inputs of encrypted classification are rejected")
    void testInvalidInputs() {
        List<Ciphertext> encryptedFeatures = List.of(clientCs.encrypt(1), clientCs.encrypt(2));

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                serverCs.evaluateHyperplane(
                                        encryptedFeatures,
                                        List.of(List.of(1, 2), List.of(3)),
                                        8,
                                        clientCs::answerArgmax))
                .withMessageContaining("same number of weights");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                serverCs.evaluateHyperplane(
                                        encryptedFeatures,
                                        List.of(List.of(1, 0.5)),
                                        8,
                                        clientCs::answerArgmax))
                .withMessageContaining("must be integers");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                serverCs.evaluateHyperplane(
                                        encryptedFeatures,
                                        List.of(List.of(1, 2, 3)),
                                        8,
                                        clientCs::answerArgmax))
                .withMessageContaining("list of 3 ciphertexts");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                serverCs.evaluateHyperplane(
                                        encryptedFeatures,
                                        List.of(List.of(1, 2)),
                                        8,
                                        clientCs::answerArgmax,
                                        List.of(1, 2)))
                .withMessageContaining("bias for each class");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                serverCs.evaluateHyperplane(
                                        encryptedFeatures,
                                        List.of(List.of(1, 2)),
                                        40,
                                        clientCs::answerArgmax))
                .withMessageContaining("too small for argmax");

        List<List<List<Double>>> likelihoods =
                List.of(List.of(List.of(0.5, 0.5)), List.of(List.of(0.2, 0.8)));
        List<List<Ciphertext>> encryptedInput =
                clientCs.encryptNaiveBayesInput(List.of(1), List.of(2));
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                serverCs.evaluateNaiveBayes(
                                        encryptedInput,
                                        List.of(0.5, 0.5),
                                        List.of(
                                                List.of(List.of(1.0, 0.0)),
                                                List.of(List.of(0.2, 0.8))),
                                        clientCs::answerArgmax))
                .withMessageContaining("Smooth zero probabilities");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                serverCs.evaluateNaiveBayes(
                                        encryptedInput,
                                        List.of(1.0),
                                        likelihoods,
                                        clientCs::answerArgmax))
                .withMessageContaining("prior for each class");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                serverCs.evaluateNaiveBayes(
                                        clientCs.encryptNaiveBayesInput(List.of(1), List.of(3)),
                                        List.of(0.5, 0.5),
                                        likelihoods,
                                        clientCs::answerArgmax))
                .withMessageContaining("domain sizes");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> clientCs.encryptNaiveBayesInput(List.of(2), List.of(2)))
                .withMessageContaining("must be an integer in");

        LightPHE paillier = LightPHE.builder().algorithmName("Paillier").keySize(64).build();
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> paillier.encryptNaiveBayesInput(List.of(0), List.of(2)))
                .withMessageContaining("does not support encrypted classification");
    }
}
