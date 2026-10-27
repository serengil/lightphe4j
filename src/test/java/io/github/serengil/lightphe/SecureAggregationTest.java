package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.within;

import io.github.serengil.lightphe.commons.SecureAggregation;
import io.github.serengil.lightphe.model.Aggregate;
import io.github.serengil.lightphe.model.AggregationLayout;
import io.github.serengil.lightphe.model.EncryptedUpdate;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.PartialDecryption;
import io.github.serengil.lightphe.model.value.IntValue;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Port of {@code tests/test_secure_aggregation.py}. */
class SecureAggregationTest {

    /** Quantization error of a value is at most half of {@code 10^-precision}. */
    private static final double TOLERANCE = 1e-5;

    /** The server, which has the public key only, and a committee holding shares of the key. */
    record Setup(LightPHE server, List<LightPHE> committee) {}

    private static Setup buildCommittee(int threshold, int parties) {
        LightPHE dealer =
                LightPHE.builder().algorithmName("Paillier").keySize(256).safePrimes(true).build();
        List<Keys> shareKeys = dealer.generateThresholdKeys(threshold, parties);
        List<LightPHE> committee =
                shareKeys.stream()
                        .map(
                                keys ->
                                        LightPHE.builder()
                                                .algorithmName("Paillier")
                                                .keys(keys)
                                                .build())
                        .toList();
        LightPHE server =
                LightPHE.builder()
                        .algorithmName("Paillier")
                        .keys(Keys.of(dealer.cs().keys().publicKey(), null))
                        .build();
        return new Setup(server, committee);
    }

    private static List<Double> randomUpdate(Random random, int length, double bound) {
        List<Double> update = new ArrayList<>(length);
        for (int i = 0; i < length; i++) {
            update.add((random.nextDouble() * 2 - 1) * bound);
        }
        return update;
    }

    private static List<Double> sumOf(List<List<Double>> updates) {
        List<Double> total = new ArrayList<>();
        for (int i = 0; i < updates.get(0).size(); i++) {
            double sum = 0;
            for (List<Double> update : updates) {
                sum += update.get(i);
            }
            total.add(sum);
        }
        return total;
    }

    private static void assertClose(List<Double> actual, List<Double> expected, double tolerance) {
        assertThat(actual).hasSameSizeAs(expected);
        for (int i = 0; i < expected.size(); i++) {
            assertThat(actual.get(i)).isCloseTo(expected.get(i), within(tolerance));
        }
    }

    @Test
    @DisplayName("Sum of packed plaintexts unpacks to the sum of updates")
    void testPackingRoundTrip() {
        BigInteger modulo = BigInteger.ONE.shiftLeft(1024);
        AggregationLayout layout = SecureAggregation.buildLayout(100, 3, 2.5, 7, modulo);
        assertThat(layout.bound()).isEqualTo(BigInteger.valueOf(2500));
        assertThat(layout.slotBits()).isEqualTo(BigInteger.valueOf(7 * 2 * 2500).bitLength());
        assertThat(layout.slots()).isEqualTo((modulo.bitLength() - 1) / layout.slotBits());

        Random random = new Random(0);
        List<List<Double>> updates = new ArrayList<>();
        for (int c = 0; c < 7; c++) {
            List<Double> update = new ArrayList<>();
            for (int i = 0; i < 100; i++) {
                update.add(Math.round((random.nextDouble() * 5 - 2.5) * 1000) / 1000.0);
            }
            updates.add(update);
        }
        updates.get(0).set(0, 2.5);
        updates.get(0).set(1, -2.5);
        updates.get(0).set(2, 0.0);

        // sum of packed plaintexts unpacks to the sum of updates, as slots never overflow
        List<BigInteger> total = new ArrayList<>();
        for (int i = 0; i < SecureAggregation.chunksOf(layout); i++) {
            total.add(BigInteger.ZERO);
        }
        for (List<Double> update : updates) {
            List<BigInteger> plaintexts = SecureAggregation.pack(update, layout);
            for (int i = 0; i < plaintexts.size(); i++) {
                assertThat(plaintexts.get(i)).isLessThan(modulo);
                total.set(i, total.get(i).add(plaintexts.get(i)));
            }
        }
        assertClose(SecureAggregation.unpack(total, layout, 7), sumOf(updates), 1e-9);
    }

    @Test
    @DisplayName("Any threshold many committee members decrypt the sum only")
    void testThresholdAggregation() {
        Random random = new Random(1);
        Setup setup = buildCommittee(3, 5);
        LightPHE server = setup.server();
        int length = 120;
        List<List<Double>> updates = new ArrayList<>();
        for (int c = 0; c < 6; c++) {
            updates.add(randomUpdate(random, length, 1));
        }

        List<EncryptedUpdate> encrypted =
                updates.stream().map(update -> server.encryptUpdate(update, 1, 50)).toList();
        AggregationLayout layout = encrypted.get(0).layout();
        assertThat(encrypted.get(0).chunks()).hasSize(SecureAggregation.chunksOf(layout));
        assertThat(SecureAggregation.chunksOf(layout)).isLessThan(length);

        EncryptedUpdate encryptedSum = server.aggregateUpdates(encrypted);
        assertThat(encryptedSum.count()).isEqualTo(6);

        // any 3 of 5 members decrypt the sum, e.g. if 2 members drop out
        List<List<PartialDecryption>> partials =
                setup.committee().stream()
                        .map(member -> member.partialDecryptAggregate(encryptedSum, true))
                        .toList();
        List<Double> expectedSum = sumOf(updates);
        for (List<List<PartialDecryption>> subset :
                List.of(partials.subList(0, 3), partials.subList(2, 5))) {
            Aggregate result = server.combineAggregate(encryptedSum, subset, true);
            assertThat(result.count()).isEqualTo(6);
            assertClose(result.sum(), expectedSum, 6 * TOLERANCE);
            assertClose(result.mean(), expectedSum.stream().map(x -> x / 6).toList(), TOLERANCE);
        }

        // 2 members cannot decrypt the sum
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () -> server.combineAggregate(encryptedSum, partials.subList(0, 2), false))
                .withMessageContaining("At least 3");
    }

    @Test
    @DisplayName("A cheating committee member is discarded with verification")
    void testCheatingCommitteeMemberIsDiscarded() {
        Random random = new Random(2);
        Setup setup = buildCommittee(3, 5);
        LightPHE server = setup.server();
        List<List<Double>> updates = new ArrayList<>();
        List<EncryptedUpdate> encrypted = new ArrayList<>();
        for (int c = 0; c < 3; c++) {
            List<Double> update = randomUpdate(random, 10, 1);
            updates.add(update);
            encrypted.add(server.encryptUpdate(update, 1, 10));
        }
        EncryptedUpdate encryptedSum = server.aggregateUpdates(encrypted);
        List<List<PartialDecryption>> partials = new ArrayList<>();
        for (LightPHE member : setup.committee().subList(0, 4)) {
            partials.add(member.partialDecryptAggregate(encryptedSum, true));
        }

        // member 1 shifts its partial decryption of the first chunk to bias the sum
        BigInteger n = server.cs().keys().publicNumber("n");
        BigInteger modulo = server.cs().ciphertextModulo();
        PartialDecryption honest = partials.get(0).get(0);
        PartialDecryption forged =
                honest.withValue(
                        IntValue.of(
                                ((IntValue) honest.value())
                                        .value()
                                        .multiply(n.add(BigInteger.ONE))
                                        .mod(modulo)));
        List<PartialDecryption> forgedMember = new ArrayList<>(partials.get(0));
        forgedMember.set(0, forged);
        partials.set(0, forgedMember);

        // without verification, the sum is wrong
        List<Double> expectedSum = sumOf(updates);
        Aggregate biased = server.combineAggregate(encryptedSum, partials.subList(0, 3), false);
        boolean differs = false;
        for (int i = 0; i < expectedSum.size(); i++) {
            differs |= Math.abs(biased.sum().get(i) - expectedSum.get(i)) > 3 * TOLERANCE;
        }
        assertThat(differs).isTrue();

        // with verification, the forged partial decryption is discarded
        Aggregate result = server.combineAggregate(encryptedSum, partials, true);
        assertClose(result.sum(), expectedSum, 3 * TOLERANCE);
    }

    @Test
    @DisplayName("Federated averaging trains a linear model on encrypted updates")
    void testFederatedAveraging() {
        Random random = new Random(3);
        Setup setup = buildCommittee(2, 3);
        LightPHE server = setup.server();

        double trueW = 2.0;
        double trueB = -1.0;
        List<double[][]> clients = new ArrayList<>();
        for (int c = 0; c < 4; c++) {
            double[] xs = new double[30];
            double[] ys = new double[30];
            for (int i = 0; i < xs.length; i++) {
                xs[i] = random.nextDouble() * 2 - 1;
                ys[i] = trueW * xs[i] + trueB + random.nextGaussian() * 0.01;
            }
            clients.add(new double[][] {xs, ys});
        }

        List<Double> weights = List.of(0.0, 0.0);
        for (int round = 0; round < 30; round++) {
            List<EncryptedUpdate> encrypted = new ArrayList<>();
            for (double[][] data : clients) {
                // one local step of gradient descent on mean squared error
                double w = weights.get(0);
                double b = weights.get(1);
                double gradW = 0;
                double gradB = 0;
                for (int i = 0; i < data[0].length; i++) {
                    double error = w * data[0][i] + b - data[1][i];
                    gradW += 2 * error * data[0][i];
                    gradB += 2 * error;
                }
                gradW /= data[0].length;
                gradB /= data[0].length;
                encrypted.add(
                        server.encryptUpdate(List.of(w - 0.5 * gradW, b - 0.5 * gradB), 10, 4));
            }
            EncryptedUpdate encryptedSum = server.aggregateUpdates(encrypted);
            List<List<PartialDecryption>> partials =
                    setup.committee().subList(0, 2).stream()
                            .map(member -> member.partialDecryptAggregate(encryptedSum, false))
                            .toList();
            weights = server.combineAggregate(encryptedSum, partials, false).mean();
        }

        assertClose(weights, List.of(trueW, trueB), 0.05);
    }

    @Test
    @DisplayName("A single key owner decrypts the aggregate of Paillier and Damgard-Jurik")
    void testSingleKeyOwnerAndDamgardJurik() {
        for (String algorithmName : List.of("Paillier", "Damgard-Jurik")) {
            LightPHE cs = LightPHE.builder().algorithmName(algorithmName).keySize(256).build();
            EncryptedUpdate encryptedSum =
                    cs.aggregateUpdates(
                            List.of(
                                    cs.encryptUpdate(List.of(0.5, -0.25, 1.0), 1, 2),
                                    cs.encryptUpdate(List.of(-1.0, 0.75, 0.0), 1, 2)));
            Aggregate result = cs.decryptAggregate(encryptedSum);
            assertClose(result.sum(), List.of(-0.5, 0.5, 1.0), 1e-9);
            assertClose(result.mean(), List.of(-0.25, 0.25, 0.5), 1e-9);
        }
    }

    @Test
    @DisplayName("Invalid inputs of secure aggregation are rejected")
    void testInvalidInputs() {
        LightPHE cs = LightPHE.builder().algorithmName("Paillier").keySize(256).build();

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.encryptUpdate(List.of(0.5, 1.5), 1, 2))
                .withMessageContaining("exceeds the maximum value");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.encryptUpdate(List.of(), 1, 2))
                .withMessageContaining("at least one value");
        // a single slot needs more bits than the plaintext space of a 256-bit key has
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.encryptUpdate(List.of(0.5), BigInteger.TEN.pow(80), 2))
                .withMessageContaining("too small");

        EncryptedUpdate a = cs.encryptUpdate(List.of(0.5, 0.5), 1, 2);
        EncryptedUpdate b = cs.encryptUpdate(List.of(0.5), 1, 2);
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.aggregateUpdates(List.of(a, b)))
                .withMessageContaining("same layout");

        // summing more updates than the slots are packed for would overflow
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.aggregateUpdates(List.of(a, a, a)))
                .withMessageContaining("overflow");

        LightPHE elGamal =
                LightPHE.builder().algorithmName("Exponential-ElGamal").keySize(50).build();
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> elGamal.encryptUpdate(List.of(0.5), 1, 2))
                .withMessageContaining("does not support secure aggregation");
    }
}
