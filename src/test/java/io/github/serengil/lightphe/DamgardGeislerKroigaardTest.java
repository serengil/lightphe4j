package io.github.serengil.lightphe;

import static io.github.serengil.lightphe.model.NumericDecisionTree.leaf;
import static io.github.serengil.lightphe.model.NumericDecisionTree.node;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.within;

import io.github.serengil.lightphe.model.ArgmaxMessage;
import io.github.serengil.lightphe.model.Ciphertext;
import io.github.serengil.lightphe.model.EncryptedTensor;
import io.github.serengil.lightphe.model.NumericDecisionTree;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Function;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Port of {@code tests/test_damgardgeislerkroigaard.py}. */
class DamgardGeislerKroigaardTest {

    private static final String ALGORITHM = "Damgard-Geisler-Kroigaard";

    private static final LightPHE cs =
            LightPHE.builder().algorithmName(ALGORITHM).keySize(50).build();

    // secure comparison and private decision trees

    private static final LightPHE protocolCs =
            LightPHE.builder().algorithmName(ALGORITHM).keySize(256).build();

    private static final LightPHE serverCs =
            LightPHE.builder()
                    .algorithmName(ALGORITHM)
                    .keys(protocolCs.cs().keys().publicOnly())
                    .build();

    // examples in the readme

    private static final LightPHE readmeCustomerCs =
            LightPHE.builder().algorithmName(ALGORITHM).build();

    @Test
    @DisplayName(
            "Damgard-Geisler-Kroigaard supports homomorphic addition and scalar multiplication")
    void testApi() {
        BigInteger modulo = cs.cs().plaintextModulo();

        long m1 = 3;
        long m2 = 4;

        Ciphertext c1 = cs.encrypt(m1);
        Ciphertext c2 = cs.encrypt(m2);

        // proof of decryption
        assertThat(cs.decrypt(c1)).isEqualTo(BigInteger.valueOf(m1));
        assertThat(cs.decrypt(c2)).isEqualTo(BigInteger.valueOf(m2));

        // homomorphic addition
        assertThat(cs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(m1 + m2).mod(modulo));

        // homomorphic scalar multiplication
        assertThat(cs.decrypt(c1.multiply(m2))).isEqualTo(BigInteger.valueOf(m1 * m2).mod(modulo));

        // negative plaintexts and addition wrapping around the plaintext modulo
        Ciphertext c3 = cs.encrypt(-2L);
        assertThat(cs.decrypt(c3)).isEqualTo(modulo.subtract(BigInteger.TWO));
        assertThat(cs.decrypt(c1.add(c3))).isEqualTo(BigInteger.valueOf(m1 - 2));
        assertThat(cs.decrypt(cs.encrypt(modulo.subtract(BigInteger.ONE)).add(c1)))
                .isEqualTo(BigInteger.valueOf(m1 - 1));

        // re-randomization
        Ciphertext c1Prime = cs.regenerateCiphertext(c1);
        assertThat(c1Prime.value()).isNotEqualTo(c1.value());
        assertThat(cs.decrypt(c1Prime)).isEqualTo(BigInteger.valueOf(m1));

        // unsupported homomorphic operations
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.multiply(c2));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.xor(c2));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.and(c2));
    }

    @Test
    @DisplayName("Damgard-Geisler-Kroigaard restores every plaintext of a small space")
    void testAllPlaintextsInSmallSpace() {
        LightPHE smallCs = LightPHE.builder().algorithmName(ALGORITHM).keySize(32).build();
        long modulo = smallCs.cs().plaintextModulo().longValueExact();
        for (long m = 0; m < modulo; m++) {
            assertThat(smallCs.decrypt(smallCs.encrypt(m))).isEqualTo(BigInteger.valueOf(m));
        }
    }

    @Test
    @DisplayName("Damgard-Geisler-Kroigaard works with predefined keys")
    void testApiWithPredefinedKeys() {
        LightPHE restoredCs =
                LightPHE.builder().algorithmName(ALGORITHM).keys(cs.cs().keys()).build();
        long m1 = 2;
        long m2 = 5;
        Ciphertext c1 = cs.encrypt(m1);
        Ciphertext c2 = restoredCs.encrypt(m2);
        assertThat(restoredCs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(m1 + m2));
        assertThat(cs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(m1 + m2));
    }

    @Test
    @DisplayName("Damgard-Geisler-Kroigaard encrypts with the public key only")
    void testEncryptionWithPublicKeyOnly() {
        LightPHE publicCs =
                LightPHE.builder()
                        .algorithmName(ALGORITHM)
                        .keys(cs.cs().keys().publicOnly())
                        .build();
        long m1 = 6;
        Ciphertext c1 = publicCs.encrypt(m1);
        assertThat(cs.decrypt(c1)).isEqualTo(BigInteger.valueOf(m1));

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> publicCs.decrypt(c1));
    }

    @Test
    @DisplayName("Damgard-Geisler-Kroigaard works with 1024-bit keys, floats and tensors")
    void testLargeKeys() {
        LightPHE largeCs = LightPHE.builder().algorithmName(ALGORITHM).keySize(1024).build();
        long m1 = 123456789;
        long m2 = 987654321;
        Ciphertext c1 = largeCs.encrypt(m1);
        Ciphertext c2 = largeCs.encrypt(m2);
        assertThat(largeCs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(m1 + m2));
        assertThat(largeCs.decrypt(c1.multiply(10L))).isEqualTo(BigInteger.valueOf(m1 * 10));

        // floats and tensors
        Ciphertext c3 = largeCs.encrypt(1.5);
        assertThat(largeCs.decrypt(c3.multiply(4L))).isEqualTo(BigInteger.valueOf(6));
        EncryptedTensor encTensor = largeCs.encryptTensor(List.of(1.5, 2.25, 3.5));
        assertTensor(largeCs.decryptTensor(encTensor), 1.5, 2.25, 3.5);
        assertTensor(largeCs.decryptTensor(encTensor.add(encTensor)), 3.0, 4.5, 7.0);
        assertTensor(largeCs.decryptTensor(encTensor.multiply(2L)), 3.0, 4.5, 7.0);
    }

    private static void assertTensor(List<Double> actual, double... expected) {
        assertThat(actual).hasSize(expected.length);
        for (int i = 0; i < expected.length; i++) {
            assertThat(actual.get(i)).isCloseTo(expected[i], within(1e-9));
        }
    }

    private static long runPrivateDecisionTree(
            NumericDecisionTree tree, List<Long> features, int bitLength) {
        // client
        List<List<BigInteger>> encryptedFeatures =
                protocolCs.encryptDecisionTreeFeatures(features, bitLength);
        // server
        NumericDecisionTree.Comparisons comparisons =
                serverCs.evaluateDecisionTreeComparisons(tree, encryptedFeatures);
        // client
        List<BigInteger> encryptedAnswers =
                protocolCs.answerDecisionTreeComparisons(comparisons.encryptedComparisons());
        // server
        List<NumericDecisionTree.EncryptedLeaf> encryptedLeaves =
                serverCs.evaluateDecisionTreeLeaves(comparisons.serverState(), encryptedAnswers);
        // client
        return protocolCs.decryptDecisionTreeOutput(encryptedLeaves);
    }

    @Test
    @DisplayName("Secure comparison is correct for all pairs of 4-bit values")
    void testSecureComparisonAllPairs() {
        int bitLength = 4;
        for (long x = 0; x < (1 << bitLength); x++) {
            List<BigInteger> encryptedX = protocolCs.encryptComparisonInput(x, bitLength);
            assertThat(encryptedX).hasSize(bitLength);
            for (long y = 0; y < (1 << bitLength); y++) {
                List<BigInteger> encryptedResult = serverCs.evaluateComparison(encryptedX, y);
                assertThat(encryptedResult).hasSize(bitLength + 1);
                assertThat(protocolCs.decryptComparison(encryptedResult))
                        .as("%d <= %d", x, y)
                        .isEqualTo(x <= y);
            }
        }
    }

    @Test
    @DisplayName("Secure comparison is correct for edge values")
    void testSecureComparisonEdgeValues() {
        int bitLength = 16;
        long maxValue = (1L << bitLength) - 1;
        long[][] pairs = {
            {0, 0},
            {0, maxValue},
            {maxValue, 0},
            {maxValue, maxValue},
            {12345, 12345},
            {12345, 12346},
            {12346, 12345}
        };
        for (long[] pair : pairs) {
            List<BigInteger> encryptedX = protocolCs.encryptComparisonInput(pair[0], bitLength);
            List<BigInteger> encryptedResult = serverCs.evaluateComparison(encryptedX, pair[1]);
            assertThat(protocolCs.decryptComparison(encryptedResult)).isEqualTo(pair[0] <= pair[1]);
        }
    }

    @Test
    @DisplayName("Secure comparison rejects invalid inputs")
    void testSecureComparisonInvalidInputs() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> protocolCs.encryptComparisonInput(16, 4))
                .withMessageContaining("must be integers");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> protocolCs.encryptComparisonInput(-1, 4))
                .withMessageContaining("must be integers");

        List<BigInteger> encryptedX = protocolCs.encryptComparisonInput(3, 4);
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> serverCs.evaluateComparison(encryptedX, 16))
                .withMessageContaining("must be integers");

        // 4-bit plaintext space cannot hold the comparison of 8-bit values
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.encryptComparisonInput(3, 8))
                .withMessageContaining("too small to compare");

        // client side requires private key
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                serverCs.decryptComparison(
                                        serverCs.evaluateComparison(encryptedX, 5)))
                .withMessageContaining("You must have private key");
    }

    @Test
    @DisplayName("Private decision tree evaluation follows the plain tree")
    void testPrivateDecisionTree() {
        // loan approval: features are 0 (age), 1 (income in thousand dollars) and
        // 2 (number of open loans), and leaves are credit limits in thousand dollars.
        //
        //                         F1: income <= 40?
        //                       /yes                 \no
        //           F0: age <= 25?               F2: open loans <= 2?
        //            /yes      \no                 /yes             \no
        //           0    F2: open loans <= 1?   F1: income <= 100?   10
        //                  /yes       \no         /yes       \no
        //                 5            0         20           50
        NumericDecisionTree tree =
                node(
                        1,
                        40,
                        node(0, 25, leaf(0), node(2, 1, leaf(5), leaf(0))),
                        node(2, 2, node(1, 100, leaf(20), leaf(50)), leaf(10)));
        int bitLength = 8;

        List<List<Long>> samples =
                List.of(
                        List.of(22L, 30L, 0L),
                        List.of(30L, 30L, 1L),
                        List.of(30L, 30L, 3L),
                        List.of(40L, 41L, 0L),
                        List.of(40L, 100L, 2L),
                        List.of(40L, 101L, 2L),
                        List.of(50L, 200L, 3L),
                        List.of(25L, 40L, 1L));
        for (List<Long> features : samples) {
            long expected = tree.evaluate(features);
            // comparisons are flipped randomly, so run each sample several times
            for (int i = 0; i < 3; i++) {
                assertThat(runPrivateDecisionTree(tree, features, bitLength))
                        .as("features %s", features)
                        .isEqualTo(expected);
            }
        }
    }

    @Test
    @DisplayName("Private decision tree evaluation is correct for all 2-bit inputs")
    void testPrivateDecisionTreeAllInputs() {
        NumericDecisionTree tree =
                node(
                        0,
                        1,
                        node(1, 2, leaf(1), leaf(2)),
                        node(1, 0, leaf(3), node(0, 2, leaf(4), leaf(5))));
        int bitLength = 2;
        for (long a = 0; a < 4; a++) {
            for (long b = 0; b < 4; b++) {
                List<Long> features = List.of(a, b);
                assertThat(runPrivateDecisionTree(tree, features, bitLength))
                        .isEqualTo(tree.evaluate(features));
            }
        }
    }

    @Test
    @DisplayName("Private decision tree evaluation supports a single leaf")
    void testPrivateDecisionTreeSingleLeaf() {
        assertThat(runPrivateDecisionTree(leaf(7), List.of(1L, 2L), 4)).isEqualTo(7);
    }

    @Test
    @DisplayName("Private decision tree evaluation rejects invalid inputs")
    void testPrivateDecisionTreeInvalidInputs() {
        List<List<BigInteger>> encryptedFeatures =
                protocolCs.encryptDecisionTreeFeatures(List.of(1L, 2L), 4);

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                serverCs.evaluateDecisionTreeComparisons(
                                        node(2, 1, leaf(0), leaf(1)), encryptedFeatures))
                .withMessageContaining("Feature index 2 does not exist");

        // malformed decision nodes cannot be built in Java, as the tree is typed

        NumericDecisionTree.Comparisons negativeLeaf =
                serverCs.evaluateDecisionTreeComparisons(
                        node(0, 1, leaf(0), leaf(-1)), encryptedFeatures);
        List<BigInteger> oneAnswer = List.of(protocolCs.encryptComparisonInput(0, 1).get(0));
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                serverCs.evaluateDecisionTreeLeaves(
                                        negativeLeaf.serverState(), oneAnswer))
                .withMessageContaining("Leaf labels must be");

        NumericDecisionTree.Comparisons comparisons =
                serverCs.evaluateDecisionTreeComparisons(
                        node(0, 1, leaf(0), leaf(1)), encryptedFeatures);
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                serverCs.evaluateDecisionTreeLeaves(
                                        comparisons.serverState(), List.of()))
                .withMessageContaining("Expected 1 answers but got 0");
    }

    @Test
    @DisplayName("Other algorithms do not support secure comparison or private decision trees")
    void testUnsupportedAlgorithms() {
        LightPHE paillierCs = LightPHE.builder().algorithmName("Paillier").keySize(50).build();
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> paillierCs.encryptComparisonInput(1, 4))
                .withMessageContaining("does not support secure comparison");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> paillierCs.evaluateComparison(List.of(BigInteger.ONE), 1))
                .withMessageContaining("does not support secure comparison");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> paillierCs.encryptDecisionTreeFeatures(List.of(1L), 4))
                .withMessageContaining("does not support private decision tree");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                paillierCs.evaluateDecisionTreeComparisons(
                                        node(0, 1, leaf(0), leaf(1)),
                                        List.of(List.of(BigInteger.ONE))))
                .withMessageContaining("does not support private decision tree");
    }

    private static long runArgmax(List<Long> values, int bitLength) {
        List<Ciphertext> encryptedValues = new ArrayList<>();
        for (long value : values) {
            encryptedValues.add(protocolCs.encrypt(value));
        }
        Ciphertext encryptedIndex =
                serverCs.evaluateArgmax(encryptedValues, bitLength, protocolCs::answerArgmax);
        return protocolCs.decrypt(encryptedIndex).longValueExact();
    }

    /** Index of the first maximum on ties, like {@code list.index(max(...))}. */
    private static long indexOfMax(List<Long> values) {
        return values.indexOf(Collections.max(values));
    }

    @Test
    @DisplayName("Encrypted argmax finds the index of the first maximum")
    void testArgmax() {
        List<List<Long>> cases =
                List.of(
                        List.of(5L),
                        List.of(3L, 9L),
                        List.of(9L, 3L),
                        List.of(7L, 7L),
                        List.of(1L, 7L, 3L, 7L),
                        List.of(0L, 0L, 0L, 0L),
                        List.of(255L, 0L, 254L),
                        List.of(10L, 20L, 30L, 40L, 50L),
                        List.of(50L, 40L, 30L, 20L, 10L),
                        List.of(12L, 200L, 3L, 199L, 255L, 17L));
        for (List<Long> values : cases) {
            assertThat(runArgmax(values, 8))
                    .as("argmax of %s", values)
                    .isEqualTo(indexOfMax(values));
        }
    }

    @Test
    @DisplayName("Encrypted argmax is correct for random values")
    void testArgmaxRandomValues() {
        Random rng = new Random(42);
        int[] bitLengths = {1, 4, 8, 12};
        // masks are random, so the comparison arc wraps around u in some rounds
        for (int round = 0; round < 30; round++) {
            int bitLength = bitLengths[rng.nextInt(bitLengths.length)];
            int size = 1 + rng.nextInt(6);
            List<Long> values = new ArrayList<>(size);
            for (int i = 0; i < size; i++) {
                values.add((long) rng.nextInt(1 << bitLength));
            }
            assertThat(runArgmax(values, bitLength))
                    .as("argmax of %s", values)
                    .isEqualTo(indexOfMax(values));
        }
    }

    private static List<Ciphertext> linearClassifierScores(
            List<Ciphertext> encryptedFeatures, long[][] weights) {
        List<Ciphertext> encryptedScores = new ArrayList<>();
        for (long[] classWeights : weights) {
            Ciphertext score = encryptedFeatures.get(0).multiply(classWeights[0]);
            for (int i = 1; i < classWeights.length; i++) {
                score = score.add(encryptedFeatures.get(i).multiply(classWeights[i]));
            }
            encryptedScores.add(score);
        }
        return encryptedScores;
    }

    @Test
    @DisplayName("Encrypted argmax predicts the class of a linear classifier")
    void testArgmaxOfLinearClassifier() {
        // client's encrypted features, server's private linear model with 3 classes
        long[] features = {3, 1, 4};
        long[][] weights = {{1, 2, 0}, {0, 1, 3}, {2, 0, 1}};

        List<Ciphertext> encryptedFeatures = new ArrayList<>();
        for (long feature : features) {
            encryptedFeatures.add(protocolCs.encrypt(feature));
        }

        // server computes encrypted class scores homomorphically
        List<Ciphertext> encryptedScores = linearClassifierScores(encryptedFeatures, weights);

        Ciphertext encryptedClass =
                serverCs.evaluateArgmax(encryptedScores, 8, protocolCs::answerArgmax);

        List<Long> scores = new ArrayList<>();
        for (long[] classWeights : weights) {
            long score = 0;
            for (int i = 0; i < features.length; i++) {
                score += classWeights[i] * features[i];
            }
            scores.add(score);
        }
        assertThat(indexOfMax(scores)).isEqualTo(1);
        assertThat(protocolCs.decrypt(encryptedClass)).isEqualTo(BigInteger.ONE);
    }

    @Test
    @DisplayName("Encrypted argmax talks to the client in three round trips per value")
    void testArgmaxClientSeesOnlyMaskedValues() {
        List<Long> values = List.of(10L, 200L, 30L);
        List<String> seen = new ArrayList<>();

        Function<ArgmaxMessage, List<BigInteger>> client =
                message -> {
                    seen.add(message.type());
                    return protocolCs.answerArgmax(message);
                };

        List<Ciphertext> encryptedValues = new ArrayList<>();
        for (long value : values) {
            encryptedValues.add(protocolCs.encrypt(value));
        }
        Ciphertext encryptedIndex = serverCs.evaluateArgmax(encryptedValues, 8, client);
        assertThat(protocolCs.decrypt(encryptedIndex)).isEqualTo(BigInteger.ONE);

        // 3 round trips for each of the remaining 2 values
        assertThat(seen)
                .containsExactly(
                        "masked_difference",
                        "comparisons",
                        "products",
                        "masked_difference",
                        "comparisons",
                        "products");
    }

    @Test
    @DisplayName("Encrypted argmax works with 1024-bit keys")
    void testArgmaxLargeKeys() {
        LightPHE largeCs = LightPHE.builder().algorithmName(ALGORITHM).keySize(1024).build();
        List<Ciphertext> encryptedValues = new ArrayList<>();
        for (long value : List.of(40000L, 65535L, 3L, 65534L)) {
            encryptedValues.add(largeCs.encrypt(value));
        }
        Ciphertext encryptedIndex =
                largeCs.evaluateArgmax(encryptedValues, 16, largeCs::answerArgmax);
        assertThat(largeCs.decrypt(encryptedIndex)).isEqualTo(BigInteger.ONE);
    }

    @Test
    @DisplayName("Encrypted argmax rejects invalid inputs")
    void testArgmaxInvalidInputs() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> serverCs.evaluateArgmax(List.of(), 8, protocolCs::answerArgmax))
                .withMessageContaining("at least one value");

        Ciphertext one = protocolCs.encrypt(1);
        int tooManyBits = protocolCs.cs().plaintextModulo().bitLength();
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                serverCs.evaluateArgmax(
                                        List.of(one, one), tooManyBits, protocolCs::answerArgmax))
                .withMessageContaining("too small for argmax");

        // unknown message types cannot be built in Java, as messages are a sealed hierarchy

        // client side requires private key
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                serverCs.answerArgmax(
                                        new ArgmaxMessage.Products(BigInteger.ONE, List.of())))
                .withMessageContaining("You must have private key");

        LightPHE paillierCs = LightPHE.builder().algorithmName("Paillier").keySize(50).build();
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                paillierCs.evaluateArgmax(
                                        List.of(paillierCs.encrypt(1)),
                                        4,
                                        paillierCs::answerArgmax))
                .withMessageContaining("does not support encrypted argmax");
    }

    @Test
    @DisplayName("Decision tree inputs go to the method of the right cryptosystem")
    void testDecisionTreeInputArguments() {
        // Damgard-Geisler-Kroigaard expects features and bit length, not bits and depth
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> protocolCs.encryptDecisionTreeInput(List.of(1, 0), 2))
                .withMessageContaining("with bits and depth");

        // Ishai-Paskin expects bits and depth, not features and bit length
        LightPHE ishaiPaskinCs =
                LightPHE.builder().algorithmName("Ishai-Paskin").keySize(50).build();
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> ishaiPaskinCs.encryptDecisionTreeFeatures(List.of(1L), 4))
                .withMessageContaining("with features and bit_length");
    }

    private static LightPHE buildReadmeServerCs(Path tempDir) {
        // customer shares only the public key with the server
        Path publicKeyFile = tempDir.resolve("public.txt");
        readmeCustomerCs.exportKeys(publicKeyFile, true);
        LightPHE server =
                LightPHE.builder().algorithmName(ALGORITHM).keyFile(publicKeyFile).build();
        assertThat(server.cs().keys().hasPrivateKey()).isFalse();
        return server;
    }

    @Test
    @DisplayName("Damgard-Geisler-Kroigaard runs the decision tree example in the readme")
    void testReadmeDecisionTree(@TempDir Path tempDir) {
        LightPHE customerCs = readmeCustomerCs;
        LightPHE bankCs = buildReadmeServerCs(tempDir);

        // features are 0 (age), 1 (income in thousand dollars) and 2 (number of open loans),
        // and leaves are credit limits in thousand dollars.
        //
        //                   F1: income <= 40?
        //                  /yes                \no
        //        F0: age <= 25?          F2: open loans <= 2?
        //         /yes      \no            /yes           \no
        //        0           5            20              10
        NumericDecisionTree creditLimitTree =
                node(1, 40, node(0, 25, leaf(0), leaf(5)), node(2, 2, leaf(20), leaf(10)));

        // the customer in the readme first, then every path of the tree drawn in the readme
        Map<List<Long>, Long> expectedLimits = new LinkedHashMap<>();
        expectedLimits.put(List.of(30L, 75L, 1L), 20L);
        expectedLimits.put(List.of(25L, 40L, 0L), 0L);
        expectedLimits.put(List.of(26L, 40L, 0L), 5L);
        expectedLimits.put(List.of(30L, 41L, 2L), 20L);
        expectedLimits.put(List.of(30L, 41L, 3L), 10L);

        List<List<List<BigInteger>>> lastComparisons = new ArrayList<>();
        List<List<NumericDecisionTree.EncryptedLeaf>> lastLeaves = new ArrayList<>();
        expectedLimits.forEach(
                (features, expectedLimit) -> {
                    List<List<BigInteger>> encryptedFeatures =
                            customerCs.encryptDecisionTreeFeatures(features, 8);
                    NumericDecisionTree.Comparisons comparisons =
                            bankCs.evaluateDecisionTreeComparisons(
                                    creditLimitTree, encryptedFeatures);
                    List<BigInteger> encryptedAnswers =
                            customerCs.answerDecisionTreeComparisons(
                                    comparisons.encryptedComparisons());
                    List<NumericDecisionTree.EncryptedLeaf> encryptedLeaves =
                            bankCs.evaluateDecisionTreeLeaves(
                                    comparisons.serverState(), encryptedAnswers);
                    assertThat(customerCs.decryptDecisionTreeOutput(encryptedLeaves))
                            .as("features %s", features)
                            .isEqualTo(expectedLimit);
                    lastComparisons.add(comparisons.encryptedComparisons());
                    lastLeaves.add(encryptedLeaves);
                });

        // bank cannot run the customer's steps
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> bankCs.answerDecisionTreeComparisons(lastComparisons.get(0)))
                .withMessageContaining("private key");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> bankCs.decryptDecisionTreeOutput(lastLeaves.get(0)))
                .withMessageContaining("private key");
    }

    @Test
    @DisplayName("Damgard-Geisler-Kroigaard runs the secure comparison example in the readme")
    void testReadmeSecureComparison(@TempDir Path tempDir) {
        LightPHE clientCs = readmeCustomerCs;
        LightPHE auctionCs = buildReadmeServerCs(tempDir);

        List<BigInteger> encryptedBid = clientCs.encryptComparisonInput(120, 16);
        List<BigInteger> encryptedResult = auctionCs.evaluateComparison(encryptedBid, 150);
        assertThat(clientCs.decryptComparison(encryptedResult)).isTrue();

        // bid above the reserve price
        List<BigInteger> aboveReserve = auctionCs.evaluateComparison(encryptedBid, 100);
        assertThat(clientCs.decryptComparison(aboveReserve)).isFalse();

        // server cannot learn the result
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> auctionCs.decryptComparison(aboveReserve))
                .withMessageContaining("private key");
    }

    @Test
    @DisplayName("Damgard-Geisler-Kroigaard runs the argmax example in the readme")
    void testReadmeArgmax(@TempDir Path tempDir) {
        LightPHE clientCs = readmeCustomerCs;
        LightPHE modelCs = buildReadmeServerCs(tempDir);

        List<Ciphertext> encryptedFeatures = new ArrayList<>();
        for (long feature : new long[] {3, 1, 4}) {
            encryptedFeatures.add(clientCs.encrypt(feature));
        }

        long[][] weights = {{1, 2, 0}, {0, 1, 3}, {2, 0, 1}};
        List<Ciphertext> encryptedScores = linearClassifierScores(encryptedFeatures, weights);

        Ciphertext encryptedClass =
                modelCs.evaluateArgmax(encryptedScores, 8, clientCs::answerArgmax);
        assertThat(encryptedClass.keys().hasPrivateKey()).isFalse();
        assertThat(clientCs.decrypt(encryptedClass)).isEqualTo(BigInteger.ONE);

        // server cannot decrypt the predicted class
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> modelCs.decrypt(encryptedClass))
                .withMessageContaining("private key");
    }
}
