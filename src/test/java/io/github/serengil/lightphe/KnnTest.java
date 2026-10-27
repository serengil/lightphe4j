package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.serengil.lightphe.cryptosystems.DamgardGeislerKroigaard;
import io.github.serengil.lightphe.model.ArgmaxMessage;
import io.github.serengil.lightphe.model.CatalanoFioreCiphertext;
import io.github.serengil.lightphe.model.EncryptedKnnQuery;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.KnnDistances;
import io.github.serengil.lightphe.model.KnnResult;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Random;
import java.util.function.Function;
import java.util.stream.IntStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Port of {@code tests/test_knn.py}. */
class KnnTest {

    // 512-bit keys have the same 32-bit plaintext space as 1024-bit keys, but are faster.
    // they are not secure, and are for testing only.
    private static final LightPHE clientCs =
            LightPHE.builder().algorithmName("Damgard-Geisler-Kroigaard").keySize(512).build();

    private static final LightPHE serverCs =
            LightPHE.builder()
                    .algorithmName("Damgard-Geisler-Kroigaard")
                    .keys(Keys.of(clientCs.cs().keys().publicKey(), null))
                    .build();

    private static long squaredDistance(List<Long> a, List<Long> b) {
        long total = 0;
        for (int i = 0; i < a.size(); i++) {
            long difference = a.get(i) - b.get(i);
            total += difference * difference;
        }
        return total;
    }

    private static List<Long> plainKnn(List<Long> query, List<List<Long>> database, int k) {
        // earlier index first on ties
        return IntStream.range(0, database.size())
                .boxed()
                .sorted(Comparator.comparingLong(i -> squaredDistance(query, database.get(i))))
                .limit(k)
                .map(Integer::longValue)
                .toList();
    }

    record Found(List<Long> indices, List<Long> labels) {}

    private static Found search(
            List<Long> query,
            List<List<Long>> database,
            int k,
            int bitLength,
            List<Long> labels,
            Function<ArgmaxMessage, List<BigInteger>> client) {
        EncryptedKnnQuery encryptedQuery = clientCs.encryptKnnQuery(query);
        KnnResult result =
                serverCs.evaluateKnn(
                        encryptedQuery,
                        database,
                        k,
                        bitLength,
                        client != null ? client : clientCs::answerKnn,
                        labels);
        return new Found(
                result.indices().stream().map(c -> clientCs.decrypt(c).longValueExact()).toList(),
                result.labels().stream().map(c -> clientCs.decrypt(c).longValueExact()).toList());
    }

    private static List<Long> randomVector(Random random, int size, int low, int high) {
        List<Long> vector = new ArrayList<>(size);
        for (int i = 0; i < size; i++) {
            vector.add((long) (low + random.nextInt(high - low + 1)));
        }
        return vector;
    }

    @Test
    @DisplayName("Encrypted k-NN matches plain k-NN")
    void testMatchesPlainKnn() {
        Random random = new Random(7);
        for (int round = 0; round < 2; round++) {
            List<List<Long>> database = new ArrayList<>();
            for (int i = 0; i < 10; i++) {
                database.add(randomVector(random, 8, -50, 50));
            }
            List<Long> labels = randomVector(random, database.size(), 1, 1_000_000);
            List<Long> query = randomVector(random, 8, -50, 50);

            Found found = search(query, database, 3, 17, labels, null);
            List<Long> expected = plainKnn(query, database, 3);
            assertThat(found.indices()).isEqualTo(expected);
            assertThat(found.labels())
                    .isEqualTo(expected.stream().map(i -> labels.get(i.intValue())).toList());
        }
    }

    @Test
    @DisplayName("k of one and a full ranking match plain k-NN")
    void testKOfOneAndFullRanking() {
        Random random = new Random(11);
        List<List<Long>> database = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            database.add(randomVector(random, 4, 0, 20));
        }
        List<Long> query = randomVector(random, 4, 0, 20);

        Found found = search(query, database, 1, 12, null, null);
        assertThat(found.indices()).isEqualTo(plainKnn(query, database, 1));
        assertThat(found.labels()).isEmpty();

        assertThat(search(query, database, 5, 12, null, null).indices())
                .isEqualTo(plainKnn(query, database, 5));
    }

    @Test
    @DisplayName("Earlier index is returned first on ties")
    void testTiesReturnEarlierIndexFirst() {
        List<List<Long>> database =
                List.of(
                        List.of(3L, 4L),
                        List.of(0L, 0L),
                        List.of(3L, 4L),
                        List.of(0L, 0L),
                        List.of(9L, 9L));
        assertThat(search(List.of(0L, 0L), database, 4, 8, null, null).indices())
                .containsExactly(1L, 3L, 0L, 2L);
    }

    @Test
    @DisplayName("Client sees a single zero in shuffled positions")
    void testClientSeesOneZeroInShuffledPositions() {
        List<List<Long>> database = new ArrayList<>();
        for (long i = 0; i < 6; i++) {
            database.add(List.of(i, 2 * i));
        }
        DamgardGeislerKroigaard dgk = (DamgardGeislerKroigaard) clientCs.cs();
        List<List<Boolean>> seen = new ArrayList<>();

        Function<ArgmaxMessage, List<BigInteger>> recordingClient =
                message -> {
                    if (message instanceof ArgmaxMessage.Equality equality) {
                        seen.add(equality.payload().stream().map(dgk::isZero).toList());
                    }
                    return clientCs.answerKnn(message);
                };

        assertThat(search(List.of(0L, 0L), database, 3, 8, null, recordingClient).indices())
                .containsExactly(0L, 1L, 2L);

        // one equality round per found vector except the last one, each having a single zero
        assertThat(seen).hasSize(2);
        for (List<Boolean> round : seen) {
            assertThat(round).hasSize(database.size());
            assertThat(round.stream().filter(zero -> zero).count()).isEqualTo(1);
        }
    }

    @Test
    @DisplayName("A noisy face embedding is found in the gallery")
    void testFaceSearchWithQuantizedEmbeddings() {
        // gallery of 8 people with 32-dimensional embeddings in [-1, 1]
        Random random = new Random(5);
        List<double[]> gallery = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            double[] embedding = new double[32];
            for (int j = 0; j < embedding.length; j++) {
                embedding[j] = random.nextDouble() * 2 - 1;
            }
            gallery.add(embedding);
        }
        List<Long> people = List.of(101L, 102L, 103L, 104L, 105L, 106L, 107L, 108L);

        // query is a noisy capture of person 105
        double[] query = new double[32];
        for (int j = 0; j < query.length; j++) {
            query[j] = gallery.get(4)[j] + random.nextGaussian() * 0.05;
        }

        // embeddings are quantized to 8-bit integers, so squared distances are less than 2^21
        Function<double[], List<Long>> quantize =
                vector -> {
                    List<Long> quantized = new ArrayList<>(vector.length);
                    for (double x : vector) {
                        quantized.add(Math.max(-127, Math.min(127, Math.round(x * 127))));
                    }
                    return quantized;
                };

        Found found =
                search(
                        quantize.apply(query),
                        gallery.stream().map(quantize).toList(),
                        1,
                        21,
                        people,
                        null);
        assertThat(found.labels()).containsExactly(105L);
    }

    @Test
    @DisplayName("Invalid inputs of encrypted k-NN are rejected")
    void testInvalidInputs() {
        EncryptedKnnQuery encryptedQuery = clientCs.encryptKnnQuery(List.of(1L, 2L));
        List<List<Long>> database = List.of(List.of(1L, 2L), List.of(3L, 4L));
        Function<ArgmaxMessage, List<BigInteger>> client = clientCs::answerKnn;

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                serverCs.evaluateKnn(
                                        encryptedQuery, List.of(List.of(1L, 2L, 3L)), 1, 8, client))
                .withMessageContaining("list of 2 integers");
        for (int k : new int[] {0, 3}) {
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> serverCs.evaluateKnn(encryptedQuery, database, k, 8, client))
                    .withMessageContaining("k must be in");
        }
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                serverCs.evaluateKnn(
                                        encryptedQuery, database, 1, 8, client, List.of(1L)))
                .withMessageContaining("one for each vector");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> serverCs.evaluateKnn(encryptedQuery, database, 1, 4, client))
                .withMessageContaining("does not fit");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> serverCs.evaluateKnn(encryptedQuery, database, 1, 40, client))
                .withMessageContaining("too small for argmax");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> serverCs.evaluateKnn(null, database, 1, 8, client))
                .withMessageContaining("output of encryptKnnQuery");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> clientCs.encryptKnnQuery(List.of()))
                .withMessageContaining("non-empty list of integers");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> serverCs.answerKnn(new ArgmaxMessage.Equality(List.of())))
                .withMessageContaining("private key");

        LightPHE paillier = LightPHE.builder().algorithmName("Paillier").keySize(64).build();
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> paillier.encryptKnnQuery(List.of(1L, 2L)))
                .withMessageContaining("does not support encrypted nearest neighbor search");
    }

    // scenario b: owner stores its encrypted database in an untrusted cloud
    private static final LightPHE ownerCs =
            LightPHE.builder()
                    .algorithmName("Paillier")
                    .keySize(256)
                    .boost("Catalano-Fiore")
                    .build();

    private static final LightPHE cloudCs =
            LightPHE.builder()
                    .algorithmName("Paillier")
                    .keys(Keys.of(ownerCs.cs().keys().publicKey(), null))
                    .boost("Catalano-Fiore")
                    .build();

    private static List<CatalanoFioreCiphertext> encryptVector(List<Long> vector) {
        return vector.stream().map(ownerCs::encryptBoosted).toList();
    }

    @Test
    @DisplayName("Cloud computes encrypted distances of an encrypted database")
    void testEncryptedDatabaseInCloud() {
        Random random = new Random(13);
        List<List<Long>> database = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            database.add(randomVector(random, 6, -100, 100));
        }
        List<Long> query = randomVector(random, 6, -100, 100);

        // owner encrypts its database once and uploads it, then encrypts queries
        List<List<CatalanoFioreCiphertext>> encryptedDatabase =
                database.stream().map(KnnTest::encryptVector).toList();
        List<CatalanoFioreCiphertext> encryptedQuery = encryptVector(query);

        // cloud computes encrypted distances with the public key only
        List<CatalanoFioreCiphertext> encryptedDistances =
                cloudCs.evaluateKnnDistances(encryptedQuery, encryptedDatabase);
        assertThat(encryptedDistances).hasSize(database.size());
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cloudCs.decryptKnn(encryptedDistances, 3))
                .withMessageContaining("private key");

        // owner decrypts them and finds the nearest vectors locally
        KnnDistances result = ownerCs.decryptKnn(encryptedDistances, 3);
        List<Long> expected = plainKnn(query, database, 3);
        assertThat(result.indices().stream().map(Integer::longValue).toList()).isEqualTo(expected);
        assertThat(result.distances())
                .isEqualTo(
                        expected.stream()
                                .map(
                                        i ->
                                                BigInteger.valueOf(
                                                        squaredDistance(
                                                                query, database.get(i.intValue()))))
                                .toList());
    }

    @Test
    @DisplayName("Invalid inputs of encrypted distances are rejected")
    void testEncryptedDatabaseInCloudInvalidInputs() {
        List<CatalanoFioreCiphertext> encryptedQuery = encryptVector(List.of(1L, 2L));
        List<List<CatalanoFioreCiphertext>> encryptedDatabase =
                List.of(encryptVector(List.of(3L, 4L)));

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                cloudCs.evaluateKnnDistances(
                                        encryptedQuery, List.of(encryptVector(List.of(1L)))))
                .withMessageContaining("list of 2 encrypted integers");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cloudCs.evaluateKnnDistances(List.of(), encryptedDatabase))
                .withMessageContaining("non-empty list of encrypted integers");

        // products cannot be multiplied again
        CatalanoFioreCiphertext product = encryptedQuery.get(0).multiply(encryptedQuery.get(1));
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                cloudCs.evaluateKnnDistances(
                                        List.of(product, encryptedQuery.get(1)), encryptedDatabase))
                .withMessageContaining("non-empty list of encrypted integers");

        List<CatalanoFioreCiphertext> distances =
                cloudCs.evaluateKnnDistances(encryptedQuery, encryptedDatabase);
        for (int k : new int[] {0, 2}) {
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> ownerCs.decryptKnn(distances, k))
                    .withMessageContaining("k must be in");
        }

        LightPHE plain = LightPHE.builder().algorithmName("Paillier").keySize(64).build();
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> plain.evaluateKnnDistances(encryptedQuery, encryptedDatabase))
                .withMessageContaining("boost = \"Catalano-Fiore\"");
    }
}
