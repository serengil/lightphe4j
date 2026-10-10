package io.github.serengil.lightphe;

import static io.github.serengil.lightphe.model.DecisionTree.leaf;
import static io.github.serengil.lightphe.model.DecisionTree.node;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.serengil.lightphe.cryptosystems.IshaiPaskin;
import io.github.serengil.lightphe.model.Ciphertext;
import io.github.serengil.lightphe.model.DecisionTree;
import io.github.serengil.lightphe.model.value.TupleValue;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Port of {@code tests/test_ishaipaskin.py}. */
class IshaiPaskinTest {

    private static final LightPHE cs =
            LightPHE.builder().algorithmName("Ishai-Paskin").keySize(50).build();

    private static List<List<Integer>> allBits(int width) {
        List<List<Integer>> result = new ArrayList<>();
        for (int i = 0; i < (1 << width); i++) {
            List<Integer> bits = new ArrayList<>(width);
            for (int j = width - 1; j >= 0; j--) {
                bits.add((i >> j) & 1);
            }
            result.add(bits);
        }
        return result;
    }

    private static void assertTree(DecisionTree tree, int width, int depth) {
        int levels = depth > 0 ? depth : Math.max(1, tree.depth());
        for (List<Integer> bits : allBits(width)) {
            List<List<BigInteger>> encryptedInput = cs.encryptDecisionTreeInput(bits, levels);
            Ciphertext output = cs.evaluateDecisionTree(tree, encryptedInput);
            assertThat(cs.decrypt(output))
                    .as("%s on %s", tree, bits)
                    .isEqualTo(tree.evaluate(bits));
        }
    }

    @Test
    @DisplayName("Ishai-Paskin is additively homomorphic as Damgard-Jurik")
    void testApi() {
        long m1 = 17;
        long m2 = 21;

        Ciphertext c1 = cs.encrypt(m1);
        Ciphertext c2 = cs.encrypt(m2);

        assertThat(cs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(m1 + m2));
        assertThat(cs.decrypt(c1.multiply(m2))).isEqualTo(BigInteger.valueOf(m1 * m2));

        Ciphertext c1Prime = cs.regenerateCiphertext(c1);
        assertThat(c1Prime.value()).isNotEqualTo(c1.value());
        assertThat(cs.decrypt(c1Prime)).isEqualTo(BigInteger.valueOf(m1));

        // unsupported homomorphic operations
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.multiply(c2));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.xor(c2));
    }

    @Test
    @DisplayName("Ishai-Paskin encrypts and decrypts at every level")
    void testEncryptionLevels() {
        IshaiPaskin ip = (IshaiPaskin) cs.cs();
        BigInteger n = ip.keys().publicNumber("n");
        for (int level = 1; level <= 4; level++) {
            BigInteger space = n.pow(level);
            // plaintext space of level s is Z_{n^s}
            for (BigInteger raw :
                    List.of(
                            BigInteger.ZERO,
                            BigInteger.ONE,
                            BigInteger.valueOf(12345),
                            n.add(BigInteger.valueOf(7)),
                            space.subtract(BigInteger.ONE))) {
                BigInteger m = raw.mod(space);
                BigInteger c = ip.encryptAtLevel(m, level);
                assertThat(c).isLessThan(n.pow(level + 1));
                assertThat(ip.decryptAtLevel(c, level)).isEqualTo(m);
            }

            // level s is additively homomorphic in Z_{n^s}
            BigInteger c1 = ip.encryptAtLevel(space.subtract(BigInteger.valueOf(3)), level);
            BigInteger c2 = ip.encryptAtLevel(BigInteger.TEN, level);
            BigInteger product = c1.multiply(c2).mod(n.pow(level + 1));
            assertThat(ip.decryptAtLevel(product, level)).isEqualTo(BigInteger.valueOf(7));
        }
    }

    @Test
    @DisplayName("Ishai-Paskin evaluates boolean decision trees")
    void testBooleanTrees() {
        assertTree(node(0, node(1, leaf(0), leaf(1)), leaf(1)), 2, 0); // x0 OR x1
        assertTree(node(0, leaf(0), node(1, leaf(0), leaf(1))), 2, 0); // x0 AND x1
        assertTree(node(1, leaf(1), leaf(0)), 2, 0); // NOT x1

        // shared sub trees (DAG) are evaluated once
        DecisionTree x2Is0 = node(2, leaf(1), leaf(0));
        DecisionTree x2Is1 = node(2, leaf(0), leaf(1));
        DecisionTree x1XorX2 = node(1, x2Is1, x2Is0);
        DecisionTree x1XnorX2 = node(1, x2Is0, x2Is1);
        assertTree(node(0, x1XorX2, x1XnorX2), 3, 0);

        DecisionTree majority =
                node(
                        0,
                        node(1, leaf(0), node(2, leaf(0), leaf(1))),
                        node(1, node(2, leaf(0), leaf(1)), leaf(1)));
        assertTree(majority, 3, 0);
    }

    @Test
    @DisplayName("Ishai-Paskin evaluates decision trees with non-binary leaves")
    void testDecisionTreeWithNonBinaryLeaves() {
        // leaves at different depths returning class labels
        DecisionTree decisionTree =
                node(0, node(1, leaf(10), node(2, leaf(20), leaf(30))), leaf(40));
        assertTree(decisionTree, 3, 0);

        // encrypted input can be prepared for deeper trees than evaluated one
        assertTree(decisionTree, 3, 5);

        // constant tree
        assertTree(leaf(99), 1, 0);
    }

    @Test
    @DisplayName("Ishai-Paskin re-randomizes the output")
    void testOutputIsRerandomized() {
        DecisionTree tree = node(0, node(1, leaf(0), leaf(1)), leaf(1));
        List<List<BigInteger>> encryptedInput = cs.encryptDecisionTreeInput(List.of(1, 0), 2);
        Ciphertext output1 = cs.evaluateDecisionTree(tree, encryptedInput);
        Ciphertext output2 = cs.evaluateDecisionTree(tree, encryptedInput);

        // output always wraps as many layers as the tree depth
        TupleValue value1 = (TupleValue) output1.value();
        TupleValue value2 = (TupleValue) output2.value();
        assertThat(value1.get(0)).isEqualTo(value2.get(0));
        assertThat(value1.get(0).toString()).isEqualTo("2");
        assertThat(value1.get(1)).isNotEqualTo(value2.get(1));
        assertThat(cs.decrypt(output1)).isEqualTo(BigInteger.ONE);
        assertThat(cs.decrypt(output2)).isEqualTo(BigInteger.ONE);
    }

    @Test
    @DisplayName("Ishai-Paskin runs the credit limit example in the readme")
    void testCreditLimitExampleInReadme(@TempDir Path tempDir) {
        // bank's secret tree: Q0 = has stable income?, Q1 = has existing debt?,
        // Q2 = owns a house?, leaves are credit limits in thousand dollars
        DecisionTree creditLimitTree =
                node(0, node(2, leaf(0), leaf(5)), node(1, leaf(20), node(2, leaf(5), leaf(10))));

        // customer builds the cryptosystem and keeps the private key
        LightPHE customerCs = LightPHE.builder().algorithmName("Ishai-Paskin").keySize(50).build();

        // customer shares only the public key with the bank
        Path publicKeyFile = tempDir.resolve("public.txt");
        customerCs.exportKeys(publicKeyFile, true);

        // bank builds its own cryptosystem with the customer's public key
        LightPHE bankCs =
                LightPHE.builder().algorithmName("Ishai-Paskin").keyFile(publicKeyFile).build();
        assertThat(bankCs.cs().keys().hasPrivateKey()).isFalse();

        // every path of the tree drawn in the readme
        Map<List<Integer>, Long> expectedLimits = new LinkedHashMap<>();
        expectedLimits.put(List.of(0, 0, 0), 0L);
        expectedLimits.put(List.of(0, 1, 0), 0L);
        expectedLimits.put(List.of(0, 0, 1), 5L);
        expectedLimits.put(List.of(0, 1, 1), 5L);
        expectedLimits.put(List.of(1, 0, 0), 20L);
        expectedLimits.put(List.of(1, 0, 1), 20L);
        expectedLimits.put(List.of(1, 1, 0), 5L);
        expectedLimits.put(List.of(1, 1, 1), 10L);

        List<Ciphertext> encryptedLimits = new ArrayList<>();
        expectedLimits.forEach(
                (answers, expectedLimit) -> {
                    // customer encrypts the answers and sends them to the bank
                    List<List<BigInteger>> encryptedAnswers =
                            customerCs.encryptDecisionTreeInput(answers, 3);

                    // bank runs its tree on encrypted answers
                    Ciphertext encryptedLimit =
                            bankCs.evaluateDecisionTree(creditLimitTree, encryptedAnswers);
                    assertThat(encryptedLimit.keys().hasPrivateKey()).isFalse();

                    // customer decrypts the result
                    assertThat(customerCs.decrypt(encryptedLimit))
                            .as("answers %s", answers)
                            .isEqualTo(BigInteger.valueOf(expectedLimit));
                    encryptedLimits.add(encryptedLimit);
                });
        Ciphertext encryptedLimit = encryptedLimits.get(encryptedLimits.size() - 1);

        // bank cannot decrypt the result
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> bankCs.decrypt(encryptedLimit))
                .withMessageContaining("private key");

        // output can only be decrypted, homomorphic operations are not supported
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> encryptedLimit.add(encryptedLimit))
                .withMessageContaining("can only be decrypted");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> encryptedLimit.multiply(2L))
                .withMessageContaining("can only be decrypted");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> customerCs.regenerateCiphertext(encryptedLimit))
                .withMessageContaining("can only be decrypted");
    }

    @Test
    @DisplayName("Ishai-Paskin rejects invalid inputs")
    void testInvalidInputs() {
        List<List<BigInteger>> encryptedInput = cs.encryptDecisionTreeInput(List.of(1, 0), 1);

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                cs.evaluateDecisionTree(
                                        node(0, node(1, leaf(0), leaf(1)), leaf(1)),
                                        encryptedInput))
                .withMessageContaining("deeper than");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () -> cs.evaluateDecisionTree(node(2, leaf(0), leaf(1)), encryptedInput))
                .withMessageContaining("out of input range");
        assertThatExceptionOfType(NullPointerException.class)
                .isThrownBy(() -> node(0, leaf(1), null));
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.encryptDecisionTreeInput(List.of(2), 1))
                .withMessageContaining("bits");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.encryptDecisionTreeInput(List.of(1), 0))
                .withMessageContaining("depth");
    }

    @Test
    @DisplayName("Ishai-Paskin works with 1024-bit keys")
    void testLargeKeys() {
        LightPHE largeCs = LightPHE.builder().algorithmName("Ishai-Paskin").keySize(1024).build();
        DecisionTree majority =
                node(
                        0,
                        node(1, leaf(0), node(2, leaf(0), leaf(1))),
                        node(1, node(2, leaf(0), leaf(1)), leaf(1)));
        for (List<Integer> bits : List.of(List.of(1, 0, 1), List.of(0, 1, 0))) {
            List<List<BigInteger>> encryptedInput = largeCs.encryptDecisionTreeInput(bits, 3);
            Ciphertext output = largeCs.evaluateDecisionTree(majority, encryptedInput);
            assertThat(largeCs.decrypt(output)).isEqualTo(majority.evaluate(bits));
        }
    }
}
