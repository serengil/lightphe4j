package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.within;

import io.github.serengil.lightphe.commons.Json;
import io.github.serengil.lightphe.commons.Serialization;
import io.github.serengil.lightphe.model.Aggregate;
import io.github.serengil.lightphe.model.ArgmaxMessage;
import io.github.serengil.lightphe.model.CatalanoFioreCiphertext;
import io.github.serengil.lightphe.model.Ciphertext;
import io.github.serengil.lightphe.model.EncryptedKnnQuery;
import io.github.serengil.lightphe.model.EncryptedTensor;
import io.github.serengil.lightphe.model.EncryptedUpdate;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.KnnDistances;
import io.github.serengil.lightphe.model.KnnResult;
import io.github.serengil.lightphe.model.PartialDecryption;
import io.github.serengil.lightphe.model.Proof;
import io.github.serengil.lightphe.model.Proven;
import io.github.serengil.lightphe.model.value.Fp2Value;
import io.github.serengil.lightphe.model.value.PointValue;
import io.github.serengil.lightphe.model.value.TupleValue;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Function;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** Port of {@code tests/test_serialization.py}. */
class SerializationTest {

    private static LightPHE build(String algorithmName, Integer keySize) {
        return LightPHE.builder().algorithmName(algorithmName).keySize(keySize).build();
    }

    private static LightPHE publicParty(LightPHE cs) {
        return LightPHE.builder()
                .algorithmName(cs.algorithmName().algorithmName())
                .keys(cs.cs().keys().publicOnly())
                .build();
    }

    // small keys are not secure, and are for testing only
    @ParameterizedTest(name = "{0}")
    @CsvSource(
            nullValues = "null",
            value = {
                "RSA, 128, mul",
                "ElGamal, 128, mul",
                "Exponential-ElGamal, 128, add",
                "EllipticCurve-ElGamal, null, add",
                "Paillier, 128, add",
                "Damgard-Jurik, 128, add",
                "Okamoto-Uchiyama, 128, add",
                "Benaloh, 64, add",
                "Naccache-Stern, 64, add",
                "Goldwasser-Micali, 64, xor",
                "Sander-Young-Yung, 64, and",
                "Boneh-Goh-Nissim, 64, add",
                "Joye-Libert, 128, add",
                "Castagnos-Laguillaumie, 128, add",
                "Ishai-Paskin, 128, add",
                "Damgard-Geisler-Kroigaard, 128, add",
                "Bresson-Catalano-Pointcheval, 128, add",
                "Camenisch-Shoup, 128, add",
                "EllipticCurve-Paillier, 128, add",
                "Regev, null, add",
                "Brakerski-Vaikuntanathan, 64, add",
                "Freeman-Boneh-Goh-Nissim, null, add",
                "Gentry-Halevi-Vaikuntanathan, null, add",
                "Lyubashevsky-Peikert-Regev, 64, add",
                "ML-KEM, 512, xor",
                "Gentry-Sahai-Waters, 64, xor",
            })
    @DisplayName("Ciphertexts survive a round trip through an untrusted party")
    void testRoundTripThroughUntrustedParty(
            String algorithmName, Integer keySize, String operation) {
        LightPHE owner = build(algorithmName, keySize);
        LightPHE cloud = publicParty(owner);

        Ciphertext c1 = owner.encrypt(1);
        Ciphertext c2 = owner.encrypt(1);

        // owner sends ciphertexts, and cloud computes on them with the public key only
        String data = owner.serialize(c1);
        assertThat(data).doesNotContain("private_key");
        Ciphertext restored1 = cloud.deserialize(data, Ciphertext.class);
        Ciphertext restored2 = cloud.fromDict(Json.read(Json.write(c2.toDict())), Ciphertext.class);
        assertThat(restored1.value()).isEqualTo(c1.value());
        assertThat(restored1.keys().hasPrivateKey()).isFalse();

        Ciphertext result =
                switch (operation) {
                    case "mul" -> restored1.multiply(restored2);
                    case "xor" -> restored1.xor(restored2);
                    case "and" -> restored1.and(restored2);
                    default -> restored1.add(restored2);
                };
        BigInteger expected = BigInteger.valueOf("add".equals(operation) ? 2 : 1);
        if ("xor".equals(operation)) {
            expected = BigInteger.ZERO;
        }

        // cloud sends the result back to the owner
        Ciphertext received = owner.deserialize(cloud.serialize(result), Ciphertext.class);
        assertThat(owner.decrypt(received)).isEqualTo(expected);
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(
            nullValues = "null",
            value = {
                "Boneh-Goh-Nissim, 64",
                "Freeman-Boneh-Goh-Nissim, null",
                "Brakerski-Vaikuntanathan, 64"
            })
    @DisplayName("Multiplied ciphertexts are told apart by their shapes")
    void testMultipliedCiphertexts(String algorithmName, Integer keySize) {
        // a point on the curve for Boneh-Goh-Nissim becomes an element of F_p^2
        LightPHE owner = build(algorithmName, keySize);
        LightPHE cloud = publicParty(owner);

        Ciphertext c1 = cloud.deserialize(owner.serialize(owner.encrypt(3)), Ciphertext.class);
        Ciphertext c2 = owner.encrypt(4);
        Ciphertext product = c1.multiply(cloud.fromDict(c2.toDict(), Ciphertext.class));
        Ciphertext restored = owner.deserialize(cloud.serialize(product), Ciphertext.class);
        assertThat(restored.value()).isEqualTo(product.value());
        assertThat(owner.decrypt(restored)).isEqualTo(12);
    }

    @Test
    @DisplayName("Values of Boneh-Goh-Nissim and elliptic curve ElGamal keep their Python shapes")
    void testValueShapes() {
        LightPHE bgn = build("Boneh-Goh-Nissim", 64);
        Map<String, Object> point = bgn.encrypt(1).toDict();
        assertThat(((Map<?, ?>) point.get("value")).get(Serialization.TAG))
                .isEqualTo(Serialization.POINT);
        Ciphertext product = bgn.encrypt(2).multiply(bgn.encrypt(3));
        assertThat(product.value()).isInstanceOf(Fp2Value.class);
        assertThat(((Map<?, ?>) product.toDict().get("value")).get(Serialization.TAG))
                .isEqualTo(Serialization.TUPLE);

        LightPHE ec = build("EllipticCurve-ElGamal", null);
        Ciphertext restored = ec.fromDict(ec.encrypt(5).toDict(), Ciphertext.class);
        assertThat(((TupleValue) restored.value()).get(0)).isInstanceOf(PointValue.class);
        assertThat(ec.decrypt(restored)).isEqualTo(5);

        LightPHE gm = build("Goldwasser-Micali", 64);
        assertThat(gm.encrypt(1).toDict().get("value")).isInstanceOf(List.class);
    }

    @Test
    @DisplayName("Serialization preserves nested structures, dict keys and floats")
    void testStructuresArePreserved() {
        LightPHE cs = build("Paillier", 128);
        Ciphertext c = cs.encrypt(5);
        Map<Object, Object> intKeys = new LinkedHashMap<>();
        intKeys.put(1, c);
        intKeys.put(2, List.of(c, c));
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("list", Arrays.asList(c, null, true, "text", 1.5));
        item.put("int_keys", intKeys);
        item.put("inf", List.of(Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY));
        item.put(Serialization.TAG, "not an encoded object");

        Map<?, ?> restored = (Map<?, ?>) cs.deserialize(cs.serialize(item));

        List<?> list = (List<?>) restored.get("list");
        assertThat(list.subList(1, 5)).isEqualTo(Arrays.asList(null, true, "text", 1.5));
        assertThat(cs.decrypt((Ciphertext) list.get(0))).isEqualTo(5);
        Map<?, ?> restoredKeys = (Map<?, ?>) restored.get("int_keys");
        assertThat(new ArrayList<Object>(restoredKeys.keySet()))
                .containsExactly(BigInteger.ONE, BigInteger.TWO);
        assertThat(cs.decrypt((Ciphertext) ((List<?>) restoredKeys.get(BigInteger.TWO)).get(1)))
                .isEqualTo(5);
        assertThat(restored.get("inf"))
                .isEqualTo(List.of(Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY));
        assertThat(restored.get(Serialization.TAG)).isEqualTo("not an encoded object");
    }

    @Test
    @DisplayName("Encrypted tensors survive a round trip")
    void testTensors() {
        LightPHE cs =
                LightPHE.builder().algorithmName("Paillier").keySize(128).precision(3).build();
        LightPHE cloud = publicParty(cs);
        EncryptedTensor signed =
                cs.deserialize(
                        cs.serialize(cs.encryptTensor(List.of(1.5, -2.25, 3))),
                        EncryptedTensor.class);
        assertThat(cs.decryptTensor(signed))
                .satisfiesExactly(
                        v -> assertThat(v).isCloseTo(1.5, within(1e-6)),
                        v -> assertThat(v).isCloseTo(-2.25, within(1e-6)),
                        v -> assertThat(v).isCloseTo(3, within(1e-6)));

        EncryptedTensor restored =
                cloud.deserialize(
                        cs.serialize(cs.encryptTensor(List.of(1.5, 2.25, 3))),
                        EncryptedTensor.class);
        assertThat(restored.cs().keys().hasPrivateKey()).isFalse();

        // cloud multiplies the encrypted tensor with a plain tensor and sends it back
        EncryptedTensor result =
                cs.deserialize(
                        cloud.serialize(restored.multiply(List.of(2, 2, 2))),
                        EncryptedTensor.class);
        assertThat(cs.decryptTensor(result))
                .satisfiesExactly(
                        v -> assertThat(v).isCloseTo(3, within(1e-6)),
                        v -> assertThat(v).isCloseTo(4.5, within(1e-6)),
                        v -> assertThat(v).isCloseTo(6, within(1e-6)));
    }

    @Test
    @DisplayName("Proofs survive a round trip")
    void testProofs() {
        LightPHE prover = build("Paillier", 128);
        LightPHE verifier = publicParty(prover);

        Proven<Ciphertext> range = prover.encryptWithRangeProof(17, 0, 100, null);
        Proven<?> receivedRange = verifier.deserialize(prover.serialize(range), Proven.class);
        assertThat(
                        verifier.verifyRange(
                                (Ciphertext) receivedRange.value(),
                                receivedRange.proof(),
                                0,
                                100,
                                null))
                .isTrue();

        Proven<List<Ciphertext>> oneHot = prover.encryptOneHot(1, 3, null);
        Proven<?> receivedOneHot = verifier.deserialize(prover.serialize(oneHot), Proven.class);
        List<Ciphertext> slots =
                ((List<?>) receivedOneHot.value()).stream().map(Ciphertext.class::cast).toList();
        assertThat(verifier.verifyOneHot(slots, receivedOneHot.proof(), null)).isTrue();

        Proven<BigInteger> decryption = prover.decryptWithProof(range.value());
        Map<String, Object> message = new LinkedHashMap<>();
        message.put("ciphertext", range.value());
        message.put("plaintext", decryption.value());
        message.put("proof", decryption.proof());
        Map<?, ?> received = (Map<?, ?>) verifier.deserialize(prover.serialize(message));
        assertThat(
                        verifier.verifyDecryption(
                                (Ciphertext) received.get("ciphertext"),
                                (BigInteger) received.get("plaintext"),
                                verifier.fromDict(received.get("proof"), Proof.class)))
                .isTrue();
    }

    @Test
    @DisplayName("Elliptic curve proofs survive a round trip")
    void testEllipticCurveProofs() {
        LightPHE prover = build("EllipticCurve-ElGamal", null);
        LightPHE verifier = publicParty(prover);

        Ciphertext ciphertext = prover.encrypt(7);
        Proven<BigInteger> decryption = prover.decryptWithProof(ciphertext);
        List<?> message =
                (List<?>)
                        verifier.deserialize(
                                prover.serialize(
                                        List.of(
                                                ciphertext,
                                                decryption.value(),
                                                decryption.proof())));
        assertThat(
                        verifier.verifyDecryption(
                                (Ciphertext) message.get(0),
                                (BigInteger) message.get(1),
                                verifier.fromDict(message.get(2), Proof.class)))
                .isTrue();
    }

    @Test
    @DisplayName("Threshold decryption works over network")
    void testThresholdDecryptionOverNetwork() {
        LightPHE dealer =
                LightPHE.builder().algorithmName("Paillier").keySize(256).safePrimes(true).build();
        List<Keys> shareKeys = dealer.generateThresholdKeys(2, 3);
        List<LightPHE> shareholders = new ArrayList<>();
        for (Keys keys : shareKeys) {
            shareholders.add(LightPHE.builder().algorithmName("Paillier").keys(keys).build());
        }
        LightPHE combiner = publicParty(dealer);

        Ciphertext ciphertext = combiner.encrypt(42);
        String data = combiner.serialize(ciphertext);

        // every shareholder receives the ciphertext, and sends its partial decryption back
        List<PartialDecryption> partials = new ArrayList<>();
        for (LightPHE shareholder : shareholders.subList(0, 2)) {
            PartialDecryption partial =
                    shareholder.partialDecrypt(
                            shareholder.deserialize(data, Ciphertext.class), true);
            partials.add(
                    combiner.deserialize(shareholder.serialize(partial), PartialDecryption.class));
        }
        assertThat(partials.get(0).proof()).isNotNull();
        assertThat(combiner.combinePartialDecryptions(ciphertext, partials, true)).isEqualTo(42);
    }

    @Test
    @DisplayName("Secure aggregation works over network")
    void testSecureAggregationOverNetwork() {
        Random random = new Random(3);
        LightPHE owner = build("Paillier", 256);
        LightPHE server = publicParty(owner);
        List<List<Double>> updates = new ArrayList<>();
        List<String> messages = new ArrayList<>();
        for (int c = 0; c < 3; c++) {
            List<Double> update = new ArrayList<>();
            for (int i = 0; i < 20; i++) {
                update.add(random.nextDouble() * 2 - 1);
            }
            updates.add(update);
            LightPHE client = publicParty(owner);
            messages.add(client.serialize(client.encryptUpdate(update, 1, 10)));
        }

        List<EncryptedUpdate> received = new ArrayList<>();
        for (String message : messages) {
            received.add(server.deserialize(message, EncryptedUpdate.class));
        }
        EncryptedUpdate encryptedSum = server.aggregateUpdates(received);
        Aggregate result =
                owner.decryptAggregate(
                        owner.deserialize(server.serialize(encryptedSum), EncryptedUpdate.class));

        assertThat(result.count()).isEqualTo(3);
        for (int i = 0; i < 20; i++) {
            double expected = 0;
            for (List<Double> update : updates) {
                expected += update.get(i);
            }
            assertThat(result.sum().get(i)).isCloseTo(expected, within(1e-4));
        }
        assertThat(owner.deserialize(owner.serialize(result), Aggregate.class)).isEqualTo(result);
    }

    @Test
    @DisplayName("k-NN works over network")
    void testKnnOverNetwork() {
        LightPHE client = build("Damgard-Geisler-Kroigaard", 512);
        LightPHE server = publicParty(client);

        Function<ArgmaxMessage, List<BigInteger>> network =
                message -> {
                    // server serializes its message, client answers it, and server restores it
                    ArgmaxMessage received =
                            client.deserialize(server.serialize(message), ArgmaxMessage.class);
                    assertThat(received).isEqualTo(message);
                    List<BigInteger> answer = client.answerKnn(received);
                    return server.deserializeList(client.serialize(answer), BigInteger.class);
                };

        List<List<Long>> database =
                List.of(List.of(1L, 2L), List.of(5L, 5L), List.of(0L, 0L), List.of(9L, 1L));
        EncryptedKnnQuery query =
                server.deserialize(
                        client.serialize(client.encryptKnnQuery(List.of(1L, 1L))),
                        EncryptedKnnQuery.class);
        KnnResult result = server.evaluateKnn(query, database, 2, 8, network);
        KnnResult received = client.deserialize(server.serialize(result), KnnResult.class);

        assertThat(received.indices().stream().map(client::decrypt).toList())
                .containsExactly(BigInteger.ZERO, BigInteger.TWO);
    }

    @Test
    @DisplayName("Catalano-Fiore ciphertexts survive a round trip")
    void testCatalanoFiore() {
        LightPHE owner =
                LightPHE.builder()
                        .algorithmName("Paillier")
                        .keySize(128)
                        .boost("Catalano-Fiore")
                        .build();
        LightPHE cloud =
                LightPHE.builder()
                        .algorithmName("Paillier")
                        .keys(owner.cs().keys().publicOnly())
                        .boost("Catalano-Fiore")
                        .build();

        List<List<Long>> database =
                List.of(List.of(1L, 2L, 3L), List.of(4L, 4L, 4L), List.of(0L, 1L, 2L));
        List<List<CatalanoFioreCiphertext>> encryptedDatabase = new ArrayList<>();
        for (Object vector :
                (List<?>)
                        cloud.deserialize(
                                owner.serialize(
                                        database.stream()
                                                .map(
                                                        v ->
                                                                v.stream()
                                                                        .map(owner::encryptBoosted)
                                                                        .toList())
                                                .toList()))) {
            encryptedDatabase.add(
                    ((List<?>) vector).stream().map(CatalanoFioreCiphertext.class::cast).toList());
        }
        List<CatalanoFioreCiphertext> encryptedQuery =
                cloud.deserializeList(
                        owner.serialize(
                                List.of(
                                        owner.encryptBoosted(1),
                                        owner.encryptBoosted(1),
                                        owner.encryptBoosted(1))),
                        CatalanoFioreCiphertext.class);

        List<CatalanoFioreCiphertext> distances =
                cloud.evaluateKnnDistances(encryptedQuery, encryptedDatabase);
        List<CatalanoFioreCiphertext> received =
                owner.deserializeList(cloud.serialize(distances), CatalanoFioreCiphertext.class);
        assertThat(received).allMatch(CatalanoFioreCiphertext::isMultiplied);
        KnnDistances nearest = owner.decryptKnn(received, 2);
        assertThat(nearest.indices()).containsExactly(2, 0);
        assertThat(nearest.distances()).containsExactly(BigInteger.TWO, BigInteger.valueOf(5));
        assertThat(owner.deserialize(owner.serialize(nearest), KnnDistances.class))
                .isEqualTo(nearest);

        // a party without the boost restores Catalano-Fiore ciphertexts as well
        CatalanoFioreCiphertext product =
                publicParty(owner)
                        .fromDict(
                                owner.encryptBoosted(6).multiply(owner.encryptBoosted(7)).toDict(),
                                CatalanoFioreCiphertext.class);
        assertThat(product.isMultiplied()).isTrue();
        assertThat(owner.decrypt(product)).isEqualTo(42);
    }

    @Test
    @SuppressWarnings("unchecked")
    @DisplayName("Invalid serialized inputs are rejected")
    void testInvalidInputs() {
        LightPHE cs = build("Paillier", 128);
        Map<String, Object> data = cs.encrypt(5).toDict();

        LightPHE other = build("Damgard-Jurik", 128);
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> other.fromDict(data))
                .withMessageContaining("belongs to Paillier");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.deserialize("{not json"))
                .withMessageContaining("not a valid json");

        for (Object value :
                Arrays.asList("123", true, null, Map.of("x", 1), List.of(1, "2"), 1.5)) {
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> cs.fromDict(with(data, "value", value)))
                    .withMessageContaining("must consist of integers");
        }

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.fromDict(with(data, "version", 999)))
                .withMessageContaining("version");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.fromDict(Map.of(Serialization.TAG, "something")))
                .withMessageContaining("Unknown serialized object");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.fromDict(Map.of(Serialization.TAG, "float", "value", "1e3")))
                .withMessageContaining("Invalid encoded float");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.serialize(new Object()))
                .withMessageContaining("cannot be serialized");

        // points must be on the curve
        LightPHE bgn = build("Boneh-Goh-Nissim", 64);
        Map<String, Object> pointData = bgn.encrypt(1).toDict();
        Map<String, Object> point =
                new LinkedHashMap<>((Map<String, Object>) pointData.get("value"));
        point.put("y", ((BigInteger) point.get("y")).add(BigInteger.ONE));
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> bgn.fromDict(with(pointData, "value", point)))
                .withMessageContaining("not on the curve");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.fromDict(with(data, "value", pointData.get("value"))))
                .withMessageContaining("not elliptic curve points");

        // Catalano-Fiore ciphertexts must be well formed
        LightPHE cf =
                LightPHE.builder()
                        .algorithmName("Paillier")
                        .keys(cs.cs().keys())
                        .boost("Catalano-Fiore")
                        .build();
        Map<String, Object> cfData = cf.encryptBoosted(5).toDict();
        BigInteger modulo = cs.cs().plaintextModulo();
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.fromDict(with(cfData, "a", modulo)))
                .withMessageContaining("must be in");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.fromDict(with(cfData, "pairs", List.of(List.of(data, data)))))
                .withMessageContaining("a and beta only");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.fromDict(with(cfData, "alpha", data)))
                .withMessageContaining("alpha and pairs only");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> other.fromDict(cfData))
                .withMessageContaining("belongs to Paillier");
    }

    private static Map<String, Object> with(Map<String, Object> data, String key, Object value) {
        Map<String, Object> copy = new LinkedHashMap<>(data);
        copy.put(key, value);
        return copy;
    }
}
