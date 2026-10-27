package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

import io.github.serengil.lightphe.ecc.curves.CurveForm;
import io.github.serengil.lightphe.ecc.curves.CurveRegistry;
import io.github.serengil.lightphe.model.Aggregate;
import io.github.serengil.lightphe.model.CatalanoFioreCiphertext;
import io.github.serengil.lightphe.model.Ciphertext;
import io.github.serengil.lightphe.model.DecisionTree;
import io.github.serengil.lightphe.model.EncryptedKnnQuery;
import io.github.serengil.lightphe.model.EncryptedTensor;
import io.github.serengil.lightphe.model.EncryptedUpdate;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.KnnResult;
import io.github.serengil.lightphe.model.PartialDecryption;
import io.github.serengil.lightphe.model.Proven;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.DoubleBinaryOperator;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Every snippet in the README, kept honest by compiling and running it. Key sizes are reduced so
 * the suite stays fast; the code is otherwise what the documentation shows.
 */
class ReadmeExamplesTest {

    @Test
    @DisplayName("README: additively homomorphic workflow")
    void additiveWorkflow() {
        // build an additively homomorphic cryptosystem
        LightPHE cs = LightPHE.builder().algorithmName("Paillier").keySize(50).build();

        // define plaintexts
        long m1 = 10000; // base salary in usd
        long m2 = 500; // wage increase in usd

        // encrypt plaintexts - the private key is not required
        Ciphertext c1 = cs.encrypt(m1);
        Ciphertext c2 = cs.encrypt(m2);

        // homomorphic addition - the private key is not required
        Ciphertext c3 = c1.add(c2);

        // homomorphic scalar multiplication - the private key is not required
        double k = 1.05; // increase something by 5%
        Ciphertext c4 = c1.multiply(k);

        // decryption - the private key is required
        assertThat(cs.decrypt(c3)).isEqualTo(BigInteger.valueOf(m1 + m2));
        assertThat(cs.decrypt(c4)).isEqualTo(BigInteger.valueOf(10500));
    }

    @Test
    @DisplayName("README: multiplicatively homomorphic workflow and ciphertext regeneration")
    void multiplicativeWorkflow() {
        LightPHE cs = LightPHE.builder().algorithmName("ElGamal").keySize(50).build();

        long m1 = 17;
        long m2 = 21;

        Ciphertext c1 = cs.encrypt(m1);
        Ciphertext c2 = cs.encrypt(m2);

        // homomorphic multiplication
        Ciphertext c3 = c1.multiply(c2);
        assertThat(cs.decrypt(c3)).isEqualTo(BigInteger.valueOf(m1 * m2));

        // ciphertext regeneration
        Ciphertext c1Prime = cs.regenerateCiphertext(c1);
        assertThat(c1Prime.value()).isNotEqualTo(c1.value());
        assertThat(cs.decrypt(c1Prime)).isEqualTo(BigInteger.valueOf(m1));
        assertThat(cs.decrypt(c1)).isEqualTo(BigInteger.valueOf(m1));
    }

    @Test
    @DisplayName("README: elliptic curve cryptosystem and curve inventory")
    void ellipticCurveWorkflow() {
        LightPHE phe =
                LightPHE.builder().algorithmName("EllipticCurve-ElGamal").form("edwards").build();

        assertThat(phe.decrypt(phe.encrypt(10))).isEqualTo(BigInteger.TEN);

        List<String> edwardsCurves = CurveRegistry.listCurves(CurveForm.EDWARDS);
        assertThat(edwardsCurves).contains("ed25519", "ed448");

        // the README claims 141 standard curve configurations across the three forms
        int total =
                CurveRegistry.listCurves(CurveForm.WEIERSTRASS).size()
                        + CurveRegistry.listCurves(CurveForm.EDWARDS).size()
                        + CurveRegistry.listCurves(CurveForm.KOBLITZ).size();
        assertThat(total).isEqualTo(141);
    }

    @Test
    @DisplayName("README: vector embeddings")
    void vectorEmbeddings() {
        // build an additively homomorphic cryptosystem
        LightPHE cs = LightPHE.builder().algorithmName("Paillier").keySize(50).build();

        // define plain embeddings
        List<Number> t1 = List.of(1.005, 2.05, 3.6, 4, 4.02, 3.5);
        List<Number> t2 = List.of(5, 6.2, 7.5, 8.02, 8.02, 4.5);
        List<Number> t3 = List.of(1.03, 2.04, 3.05, 7.02, 2.01, 1.06);

        // encrypt embeddings
        EncryptedTensor c1 = cs.encryptTensor(t1);
        EncryptedTensor c2 = cs.encryptTensor(t2);

        // addition of two encrypted embeddings
        EncryptedTensor c4 = c1.add(c2);

        // scalar multiplication of an embedding
        EncryptedTensor c5 = c1.multiply(3);

        // element-wise multiplication of an encrypted embedding with a plain one
        EncryptedTensor c6 = c1.multiply(t3);

        // encrypted dot product, and likewise cosine similarity
        EncryptedTensor c7 = c1.matmul(t3);

        assertThat(cs.decryptTensor(c4)).hasSize(t1.size());
        assertClose(cs.decryptTensor(c4), elementWise(t1, t2, Double::sum));
        assertClose(cs.decryptTensor(c5), scale(t1, 3));
        assertClose(cs.decryptTensor(c6), elementWise(t1, t3, (a, b) -> a * b));

        double expectedDot = 0;
        for (int i = 0; i < t1.size(); i++) {
            expectedDot += t1.get(i).doubleValue() * t3.get(i).doubleValue();
        }
        assertThat(cs.decryptTensor(c7).get(0)).isCloseTo(expectedDot, within(0.1));
    }

    @Test
    @DisplayName("README: decision trees")
    void decisionTrees(@TempDir Path tempDir) {
        DecisionTree creditLimitTree =
                DecisionTree.node(
                        0,
                        DecisionTree.node(2, DecisionTree.leaf(0), DecisionTree.leaf(5)),
                        DecisionTree.node(
                                1,
                                DecisionTree.leaf(20),
                                DecisionTree.node(2, DecisionTree.leaf(5), DecisionTree.leaf(10))));

        LightPHE customerCs = LightPHE.builder().algorithmName("Ishai-Paskin").keySize(50).build();

        Path publicKeyFile = tempDir.resolve("public.txt");
        customerCs.exportKeys(publicKeyFile, true);

        List<Integer> answers = List.of(1, 1, 0);
        List<List<BigInteger>> encryptedAnswers = customerCs.encryptDecisionTreeInput(answers, 3);

        LightPHE bankCs =
                LightPHE.builder().algorithmName("Ishai-Paskin").keyFile(publicKeyFile).build();

        Ciphertext encryptedLimit = bankCs.evaluateDecisionTree(creditLimitTree, encryptedAnswers);

        assertThat(customerCs.decrypt(encryptedLimit)).isEqualTo(BigInteger.valueOf(5));
    }

    @Test
    @DisplayName("README: key management")
    void keyManagement(@TempDir Path tempDir) {
        Path secret = tempDir.resolve("secret.json");
        Path publicKey = tempDir.resolve("public.json");

        LightPHE onPrem = LightPHE.builder().algorithmName("Paillier").keySize(50).build();

        // export the full key pair, and a public-only copy safe to publish
        onPrem.exportKeys(secret);
        onPrem.exportKeys(publicKey, true);

        // a party holding only the public key can encrypt and evaluate, but not decrypt
        LightPHE cloud = LightPHE.builder().algorithmName("Paillier").keyFile(publicKey).build();

        Ciphertext sum = cloud.encrypt(17).add(cloud.encrypt(21));
        assertThat(cloud.cs().keys().hasPrivateKey()).isFalse();
        assertThat(onPrem.decrypt(sum)).isEqualTo(BigInteger.valueOf(38));
    }

    @Test
    @DisplayName("README: hyperplane and naive Bayes classifiers")
    void classifiers() {
        LightPHE clientCs =
                LightPHE.builder().algorithmName("Damgard-Geisler-Kroigaard").keySize(512).build();
        List<Ciphertext> encryptedFeatures =
                Stream.of(85L, 20L, 6L, 0L).map(clientCs::encrypt).toList();

        LightPHE serverCs =
                LightPHE.builder()
                        .algorithmName("Damgard-Geisler-Kroigaard")
                        .keys(Keys.of(clientCs.cs().keys().publicKey(), null))
                        .build();
        List<List<Long>> weights =
                List.of(List.of(0L, 0L, 0L, 0L), List.of(42L, -65L, 310L, -900L));
        List<Long> biases = List.of(0L, -1200L);
        Ciphertext encryptedClass =
                serverCs.evaluateHyperplane(
                        encryptedFeatures, weights, 16, clientCs::answerArgmax, biases);
        assertThat(clientCs.decrypt(encryptedClass)).isEqualTo(BigInteger.ONE);

        List<List<Ciphertext>> encryptedSymptoms =
                clientCs.encryptNaiveBayesInput(List.of(1, 1, 1), List.of(2, 3, 2));
        List<Double> priors = List.of(0.36, 0.36, 0.28);
        List<List<List<Double>>> likelihoods =
                List.of(
                        List.of(
                                List.of(0.71, 0.29),
                                List.of(0.12, 0.25, 0.63),
                                List.of(0.71, 0.29)),
                        List.of(
                                List.of(0.29, 0.71),
                                List.of(0.12, 0.63, 0.25),
                                List.of(0.29, 0.71)),
                        List.of(
                                List.of(0.83, 0.17),
                                List.of(0.57, 0.29, 0.14),
                                List.of(0.67, 0.33)));
        Ciphertext diagnosis =
                serverCs.evaluateNaiveBayes(
                        encryptedSymptoms, priors, likelihoods, clientCs::answerArgmax);
        assertThat(clientCs.decrypt(diagnosis)).isEqualTo(BigInteger.ONE);
    }

    @Test
    @DisplayName("README: encrypted nearest neighbor search")
    void nearestNeighbors() {
        LightPHE clientCs =
                LightPHE.builder().algorithmName("Damgard-Geisler-Kroigaard").keySize(512).build();
        EncryptedKnnQuery encryptedQuery = clientCs.encryptKnnQuery(List.of(12L, -7L, 33L, 5L));
        LightPHE serverCs =
                LightPHE.builder()
                        .algorithmName("Damgard-Geisler-Kroigaard")
                        .keys(Keys.of(clientCs.cs().keys().publicKey(), null))
                        .build();
        List<List<Long>> gallery =
                List.of(
                        List.of(10L, -5L, 30L, 4L),
                        List.of(-40L, 22L, 1L, 9L),
                        List.of(13L, -8L, 35L, 6L));
        List<Long> people = List.of(101L, 102L, 103L);
        KnnResult result =
                serverCs.evaluateKnn(encryptedQuery, gallery, 2, 16, clientCs::answerKnn, people);
        assertThat(result.labels().stream().map(clientCs::decrypt).toList())
                .containsExactly(BigInteger.valueOf(103), BigInteger.valueOf(101));

        LightPHE ownerCs =
                LightPHE.builder()
                        .algorithmName("Paillier")
                        .keySize(256)
                        .boost("Catalano-Fiore")
                        .build();
        List<List<CatalanoFioreCiphertext>> encryptedGallery =
                gallery.stream()
                        .map(vector -> vector.stream().map(ownerCs::encryptBoosted).toList())
                        .toList();
        List<CatalanoFioreCiphertext> query =
                Stream.of(12L, -7L, 33L, 5L).map(ownerCs::encryptBoosted).toList();
        LightPHE cloudCs =
                LightPHE.builder()
                        .algorithmName("Paillier")
                        .keys(Keys.of(ownerCs.cs().keys().publicKey(), null))
                        .boost("Catalano-Fiore")
                        .build();
        List<CatalanoFioreCiphertext> encryptedDistances =
                cloudCs.evaluateKnnDistances(query, encryptedGallery);
        assertThat(ownerCs.decryptKnn(encryptedDistances, 2).indices()).containsExactly(2, 0);
    }

    @Test
    @DisplayName("README: threshold decryption and secure aggregation")
    void thresholdDecryption(@TempDir Path tmp) {
        LightPHE dealerCs = LightPHE.builder().algorithmName("Paillier").keySize(128).build();
        List<Keys> shareKeys = dealerCs.generateThresholdKeys(3, 5);
        Path publicFile = tmp.resolve("public.txt");
        dealerCs.exportKeys(publicFile, true);
        List<LightPHE> shareholders =
                shareKeys.stream()
                        .map(
                                keys ->
                                        LightPHE.builder()
                                                .algorithmName("Paillier")
                                                .keys(keys)
                                                .build())
                        .toList();
        LightPHE publicCs =
                LightPHE.builder().algorithmName("Paillier").keyFile(publicFile).build();
        Ciphertext c = publicCs.encrypt(100).add(publicCs.encrypt(50));
        List<PartialDecryption> partials =
                Stream.of(0, 2, 4).map(i -> shareholders.get(i).partialDecrypt(c)).toList();
        assertThat(publicCs.combinePartialDecryptions(c, partials))
                .isEqualTo(BigInteger.valueOf(150));

        LightPHE committeeDealer =
                LightPHE.builder().algorithmName("Paillier").keySize(256).safePrimes(true).build();
        List<LightPHE> committee =
                committeeDealer.generateThresholdKeys(3, 5).stream()
                        .map(
                                keys ->
                                        LightPHE.builder()
                                                .algorithmName("Paillier")
                                                .keys(keys)
                                                .build())
                        .toList();
        Keys publicKey = Keys.of(committeeDealer.cs().keys().publicKey(), null);
        LightPHE clientCs = LightPHE.builder().algorithmName("Paillier").keys(publicKey).build();
        List<List<Double>> updates =
                List.of(
                        List.of(0.12, -0.53, 0.98),
                        List.of(0.33, 0.21, -0.47),
                        List.of(-0.25, 0.08, 0.61));
        List<EncryptedUpdate> encryptedUpdates =
                updates.stream().map(update -> clientCs.encryptUpdate(update, 1, 100)).toList();
        LightPHE serverCs = LightPHE.builder().algorithmName("Paillier").keys(publicKey).build();
        EncryptedUpdate encryptedSum = serverCs.aggregateUpdates(encryptedUpdates);
        List<List<PartialDecryption>> aggregatePartials =
                committee.subList(0, 3).stream()
                        .map(member -> member.partialDecryptAggregate(encryptedSum, true))
                        .toList();
        Aggregate result = serverCs.combineAggregate(encryptedSum, aggregatePartials, true);
        assertThat(result.mean().get(1)).isCloseTo(-0.08, within(1e-9));
    }

    @Test
    @DisplayName("README: zero-knowledge proofs and e-voting")
    void zeroKnowledgeProofs() {
        LightPHE cs =
                LightPHE.builder()
                        .algorithmName("Exponential-ElGamal")
                        .keySize(128)
                        .primeOrder(true)
                        .build();
        Ciphertext c = cs.encrypt(17).add(cs.encrypt(25));
        Proven<BigInteger> decryption = cs.decryptWithProof(c);
        assertThat(cs.verifyDecryption(c, decryption.value(), decryption.proof())).isTrue();
        assertThat(
                        cs.verifyDecryption(
                                c, decryption.value().add(BigInteger.ONE), decryption.proof()))
                .isFalse();

        LightPHE paillier = LightPHE.builder().algorithmName("Paillier").keySize(128).build();
        Proven<Ciphertext> alice = paillier.encryptWithProofOfKnowledge(950, "alice");
        assertThat(paillier.verifyKnowledge(alice.value(), alice.proof(), "alice")).isTrue();
        Ciphertext malloryBid = alice.value().add(paillier.encrypt(1));
        assertThat(paillier.verifyKnowledge(malloryBid, alice.proof(), "mallory")).isFalse();

        List<Integer> stars = List.of(1, 2, 3, 4, 5);
        Proven<Ciphertext> rating = paillier.encryptWithProof(4, stars, "customer-42");
        assertThat(paillier.verifyCiphertext(rating.value(), rating.proof(), stars, "customer-42"))
                .isTrue();

        Proven<Ciphertext> salary = paillier.encryptWithRangeProof(85000, 0, 500000, "alice");
        assertThat(paillier.verifyRange(salary.value(), salary.proof(), 0, 500000, "alice"))
                .isTrue();
        assertThat(paillier.verifyRange(salary.value(), salary.proof(), 0, 50000, "alice"))
                .isFalse();

        List<Long> values = List.of(1L, 100L, 10000L);
        Proven<Ciphertext> red1 = paillier.encryptWithProof(values.get(0), values, "alice");
        Proven<Ciphertext> blue = paillier.encryptWithProof(values.get(2), values, "bob");
        Proven<Ciphertext> red2 = paillier.encryptWithProof(values.get(0), values, "carol");
        Ciphertext tally = red1.value().add(blue.value()).add(red2.value());
        assertThat(paillier.decryptWithProof(tally).value()).isEqualTo(BigInteger.valueOf(10002));

        Proven<List<Ciphertext>> aliceBallot = cs.encryptOneHot(0, 4, "alice");
        Proven<List<Ciphertext>> bobBallot = cs.encryptOneHot(2, 4, "bob");
        assertThat(cs.verifyOneHot(aliceBallot.value(), aliceBallot.proof(), "alice")).isTrue();
        List<BigInteger> votes = new ArrayList<>();
        for (int k = 0; k < 4; k++) {
            Ciphertext count = aliceBallot.value().get(k).add(bobBallot.value().get(k));
            votes.add(cs.decryptWithProof(count).value());
        }
        assertThat(votes)
                .containsExactly(BigInteger.ONE, BigInteger.ZERO, BigInteger.ONE, BigInteger.ZERO);
    }

    @Test
    @DisplayName("README: new post-quantum algorithms")
    void postQuantum() {
        LightPHE lpr =
                LightPHE.builder().algorithmName("Lyubashevsky-Peikert-Regev").keySize(64).build();
        assertThat(lpr.decrypt(lpr.encrypt(1500).add(lpr.encrypt(2500))))
                .isEqualTo(BigInteger.valueOf(4000));

        LightPHE mlKem = LightPHE.builder().algorithmName("ML-KEM").build();
        BigInteger m1 =
                new BigInteger(
                        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 16);
        BigInteger m2 =
                new BigInteger(
                        "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321", 16);
        assertThat(mlKem.decrypt(mlKem.encrypt(m1).xor(mlKem.encrypt(m2)))).isEqualTo(m1.xor(m2));

        LightPHE gsw = LightPHE.builder().algorithmName("Gentry-Sahai-Waters").keySize(64).build();
        Ciphertext a = gsw.encrypt(1);
        Ciphertext b = gsw.encrypt(1);
        Ciphertext c = gsw.encrypt(0);
        Ciphertext d = gsw.encrypt(1);
        assertThat(gsw.decrypt(a.and(b).xor(a.and(c)).xor(b.and(c)))).isEqualTo(BigInteger.ONE);
        assertThat(gsw.decrypt(a.and(b).and(c.and(d)))).isEqualTo(BigInteger.ZERO);
    }

    private static List<Double> elementWise(
            List<Number> a, List<Number> b, DoubleBinaryOperator operator) {
        return IntStream.range(0, a.size())
                .mapToObj(
                        i -> operator.applyAsDouble(a.get(i).doubleValue(), b.get(i).doubleValue()))
                .toList();
    }

    private static List<Double> scale(List<Number> a, double factor) {
        return a.stream().map(value -> value.doubleValue() * factor).toList();
    }

    private static void assertClose(List<Double> actual, List<Double> expected) {
        assertThat(actual).hasSameSizeAs(expected);
        for (int i = 0; i < actual.size(); i++) {
            assertThat(actual.get(i)).as("item %d", i).isCloseTo(expected.get(i), within(0.1));
        }
    }
}
