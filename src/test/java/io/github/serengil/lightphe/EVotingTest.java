package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.serengil.lightphe.commons.Threshold;
import io.github.serengil.lightphe.commons.Zkp;
import io.github.serengil.lightphe.model.Ciphertext;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.PartialDecryption;
import io.github.serengil.lightphe.model.Proof;
import io.github.serengil.lightphe.model.Proven;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.IntValue;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** Port of {@code tests/test_evoting.py}. */
class EVotingTest {

    private static LightPHE publicCopy(LightPHE cs, String algorithmName) {
        return LightPHE.builder()
                .algorithmName(algorithmName)
                .keys(Keys.of(cs.cs().keys().publicKey(), null))
                .build();
    }

    private static <T> T sum(List<T> items, java.util.function.BinaryOperator<T> add) {
        T total = items.get(0);
        for (T item : items.subList(1, items.size())) {
            total = add.apply(total, item);
        }
        return total;
    }

    @Test
    @DisplayName("Voters cast proven 0/1 ballots, and trustees decrypt the tally with proofs")
    void testEncryptedVoting() {
        ThresholdTest.Committee committee = ThresholdTest.build("Exponential-ElGamal", 128, 2, 3);
        LightPHE authority = committee.dealer();

        Map<String, Long> votes = new LinkedHashMap<>();
        votes.put("alice", 1L);
        votes.put("bob", 0L);
        votes.put("carol", 1L);
        votes.put("dave", 1L);
        Map<String, Proven<Ciphertext>> ballots = new LinkedHashMap<>();
        votes.forEach(
                (voter, vote) -> ballots.put(voter, authority.encryptWithProof(vote, null, voter)));

        // mallory copies alice's ballot
        ballots.put("mallory", ballots.get("alice"));

        List<Ciphertext> valid = new ArrayList<>();
        ballots.forEach(
                (voter, ballot) -> {
                    if (authority.verifyCiphertext(ballot.value(), ballot.proof(), null, voter)) {
                        valid.add(ballot.value());
                    }
                });
        assertThat(valid).hasSize(votes.size());

        Ciphertext tally = sum(valid, Ciphertext::add);
        List<PartialDecryption> partials =
                committee.shareholders().subList(0, 2).stream()
                        .map(trustee -> trustee.partialDecrypt(tally, true))
                        .toList();
        assertThat(authority.combinePartialDecryptions(tally, partials, true))
                .isEqualTo(BigInteger.valueOf(3));
    }

    @Test
    @DisplayName("A vote for party k is base^k, so the tally keeps each count in a digit")
    void testEncryptedElectionOfParties() {
        LightPHE authority = LightPHE.builder().algorithmName("Paillier").keySize(128).build();
        LightPHE publicCs = publicCopy(authority, "Paillier");

        // a vote for party k is encrypted as base^k, so each party's count is kept in its own
        // digit in base 100. a party can get at most 99 votes in base 100.
        List<String> parties = List.of("red", "green", "blue");
        long base = 100;
        List<Long> values = List.of(1L, base, base * base);

        Map<String, String> votes = new LinkedHashMap<>();
        votes.put("alice", "red");
        votes.put("bob", "blue");
        votes.put("carol", "red");
        votes.put("dave", "red");
        votes.put("erin", "blue");
        Map<String, Proven<Ciphertext>> ballots = new LinkedHashMap<>();
        votes.forEach(
                (voter, party) ->
                        ballots.put(
                                voter,
                                publicCs.encryptWithProof(
                                        values.get(parties.indexOf(party)), values, voter)));

        // mallory copies alice's ballot
        ballots.put("mallory", ballots.get("alice"));

        // oscar cannot vote twice for a party, as 2 * base^k is not an allowed value
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> publicCs.encryptWithProof(2 * values.get(1), values, "oscar"))
                .withMessageContaining("one of the allowed values");

        // oscar cannot reuse a proof of a single vote for a doubled ballot
        Proven<Ciphertext> oscar = publicCs.encryptWithProof(values.get(1), values, "oscar");
        ballots.put("oscar", new Proven<>(oscar.value().add(oscar.value()), oscar.proof()));

        List<Ciphertext> valid = new ArrayList<>();
        ballots.forEach(
                (voter, ballot) -> {
                    if (publicCs.verifyCiphertext(ballot.value(), ballot.proof(), values, voter)) {
                        valid.add(ballot.value());
                    }
                });
        assertThat(valid).hasSize(votes.size());

        Ciphertext tally = sum(valid, Ciphertext::add);

        // authority decrypts the tally with a proof, and anyone verifies it
        Proven<BigInteger> result = authority.decryptWithProof(tally);
        assertThat(publicCs.verifyDecryption(tally, result.value(), result.proof())).isTrue();

        // 3 x 1 + 0 x 100 + 2 x 10000 = 20003, i.e. 2 | 00 | 03 for blue | green | red
        assertThat(count(result.value(), parties, base))
                .containsExactly(
                        Map.entry("red", 3L), Map.entry("green", 0L), Map.entry("blue", 2L));
    }

    private static Map<String, Long> count(BigInteger result, List<String> parties, long base) {
        Map<String, Long> counts = new LinkedHashMap<>();
        for (int k = 0; k < parties.size(); k++) {
            counts.put(
                    parties.get(k),
                    result.divide(BigInteger.valueOf(base).pow(k))
                            .mod(BigInteger.valueOf(base))
                            .longValueExact());
        }
        return counts;
    }

    @Test
    @DisplayName("Proofs of partial decryption stop a trustee adding votes to its own party")
    void testTrusteesTallyElectionOfParties() {
        LightPHE authority =
                LightPHE.builder().algorithmName("Paillier").keySize(128).safePrimes(true).build();
        List<Keys> shareKeys = authority.generateThresholdKeys(2, 3);
        List<LightPHE> trustees =
                shareKeys.stream()
                        .map(
                                keys ->
                                        LightPHE.builder()
                                                .algorithmName("Paillier")
                                                .keys(keys)
                                                .build())
                        .toList();

        List<String> parties = List.of("red", "green", "blue");
        long base = 100;
        List<Long> values = List.of(1L, base, base * base);

        Map<String, String> votes = new LinkedHashMap<>();
        votes.put("alice", "red");
        votes.put("bob", "blue");
        votes.put("carol", "red");
        votes.put("dave", "green");
        votes.put("erin", "red");
        List<Ciphertext> valid = new ArrayList<>();
        votes.forEach(
                (voter, party) -> {
                    Proven<Ciphertext> ballot =
                            authority.encryptWithProof(
                                    values.get(parties.indexOf(party)), values, voter);
                    if (authority.verifyCiphertext(ballot.value(), ballot.proof(), values, voter)) {
                        valid.add(ballot.value());
                    }
                });
        Ciphertext tally = sum(valid, Ciphertext::add);

        List<PartialDecryption> partials =
                trustees.stream().map(trustee -> trustee.partialDecrypt(tally, true)).toList();
        assertThat(
                        count(
                                authority.combinePartialDecryptions(
                                        tally, partials.subList(0, 2), true),
                                parties,
                                base))
                .containsExactly(
                        Map.entry("red", 3L), Map.entry("green", 1L), Map.entry("blue", 1L));

        // trustee 1 of blue party knows that trustee 2 joins the decryption, so it finds the
        // shift adding 50 votes to blue from public lagrange coefficients
        BigInteger n = authority.cs().keys().publicNumber("n");
        BigInteger modulo = authority.cs().ciphertextModulo();
        BigInteger delta = BigInteger.valueOf(6);
        BigInteger coefficient = Threshold.scaledLagrangeCoefficient(1, List.of(1, 2), delta);
        BigInteger target = BigInteger.valueOf(50 * values.get(parties.indexOf("blue")));
        BigInteger shift =
                target.multiply(BigInteger.valueOf(4))
                        .multiply(delta)
                        .multiply(delta)
                        .multiply(coefficient.shiftLeft(1).modInverse(n))
                        .mod(n);
        PartialDecryption forged =
                partials.get(0)
                        .withValue(
                                IntValue.of(
                                        ((IntValue) partials.get(0).value())
                                                .value()
                                                .multiply(
                                                        n.add(BigInteger.ONE).modPow(shift, modulo))
                                                .mod(modulo)));

        // without proofs, blue gets 50 more votes silently
        BigInteger forgedResult =
                authority.combinePartialDecryptions(tally, List.of(forged, partials.get(1)));
        assertThat(count(forgedResult, parties, base))
                .containsExactly(
                        Map.entry("red", 3L), Map.entry("green", 1L), Map.entry("blue", 51L));

        // with proofs, the forged partial decryption is discarded and the honest trustees decrypt
        List<PartialDecryption> withForged = new ArrayList<>();
        withForged.add(forged);
        withForged.addAll(partials.subList(1, 3));
        assertThat(
                        count(
                                authority.combinePartialDecryptions(tally, withForged, true),
                                parties,
                                base))
                .containsExactly(
                        Map.entry("red", 3L), Map.entry("green", 1L), Map.entry("blue", 1L));
    }

    @Test
    @DisplayName("One-hot ballots count each party separately")
    void testOneHotElection() {
        ThresholdTest.Committee committee = ThresholdTest.build("Exponential-ElGamal", 128, 2, 3);
        LightPHE authority = committee.dealer();

        List<String> parties =
                List.of("red", "green", "blue", "yellow", "purple", "orange", "black", "white");
        Map<String, String> votes = new LinkedHashMap<>();
        votes.put("alice", "red");
        votes.put("bob", "blue");
        votes.put("carol", "red");
        votes.put("dave", "white");
        votes.put("erin", "blue");
        votes.put("frank", "red");
        Map<String, Proven<List<Ciphertext>>> ballots = new LinkedHashMap<>();
        votes.forEach(
                (voter, party) ->
                        ballots.put(
                                voter,
                                authority.encryptOneHot(
                                        parties.indexOf(party), parties.size(), voter)));

        // mallory copies alice's ballot, and oscar reorders bob's slots to vote for another party
        ballots.put("mallory", ballots.get("alice"));
        List<Ciphertext> bobSlots = ballots.get("bob").value();
        List<Ciphertext> reordered = new ArrayList<>(bobSlots.subList(1, bobSlots.size()));
        reordered.add(bobSlots.get(0));
        ballots.put("oscar", new Proven<>(reordered, ballots.get("bob").proof()));

        List<List<Ciphertext>> valid = new ArrayList<>();
        ballots.forEach(
                (voter, ballot) -> {
                    if (authority.verifyOneHot(ballot.value(), ballot.proof(), voter)) {
                        valid.add(ballot.value());
                    }
                });
        assertThat(valid).hasSize(votes.size());

        // sum each slot over all ballots
        List<Ciphertext> tally = new ArrayList<>(valid.get(0));
        for (List<Ciphertext> ballot : valid.subList(1, valid.size())) {
            for (int i = 0; i < tally.size(); i++) {
                tally.set(i, tally.get(i).add(ballot.get(i)));
            }
        }

        Map<String, BigInteger> counts = new LinkedHashMap<>();
        for (int i = 0; i < parties.size(); i++) {
            Ciphertext encryptedCount = tally.get(i);
            List<PartialDecryption> partials =
                    committee.shareholders().subList(0, 2).stream()
                            .map(trustee -> trustee.partialDecrypt(encryptedCount, true))
                            .toList();
            counts.put(
                    parties.get(i),
                    authority.combinePartialDecryptions(encryptedCount, partials, true));
        }

        Map<String, BigInteger> expected = new LinkedHashMap<>();
        for (String party : parties) {
            expected.put(party, BigInteger.ZERO);
        }
        expected.put("red", BigInteger.valueOf(3));
        expected.put("blue", BigInteger.TWO);
        expected.put("white", BigInteger.ONE);
        assertThat(counts).isEqualTo(expected);
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(
            value = {
                "Exponential-ElGamal, 128, true",
                "EllipticCurve-ElGamal, null, false",
                "Paillier, 128, false",
                "Damgard-Jurik, 128, false"
            },
            nullValues = "null")
    @DisplayName("Cheating one-hot ballots built slot by slot are rejected")
    void testCheatingOneHotBallotsAreRejected(
            String algorithmName, Integer keySize, boolean primeOrder) {
        LightPHE cs = ZkpTest.build(algorithmName, keySize, primeOrder);
        int options = 3;

        // an honest ballot built in the same way is valid
        Proven<List<Ciphertext>> honest = cheat(cs, List.of(0, 1, 0), options);
        assertThat(cs.verifyOneHot(honest.value(), honest.proof(), null)).isTrue();

        // voting for two parties, voting twice for a party, or abstaining is rejected
        for (List<Integer> slots : List.of(List.of(1, 1, 0), List.of(2, 0, 0), List.of(0, 0, 0))) {
            Proven<List<Ciphertext>> ballot = cheat(cs, slots, options);
            assertThat(cs.verifyOneHot(ballot.value(), ballot.proof(), null))
                    .as("slots %s", slots)
                    .isFalse();
        }
    }

    /** A cheating voter builds its ballot slot by slot, proving whatever it can. */
    private static Proven<List<Ciphertext>> cheat(LightPHE cs, List<Integer> slots, int options) {
        List<CipherValue> ciphertexts = new ArrayList<>();
        List<BigInteger> randomKeys = new ArrayList<>();
        List<Proof> slotProofs = new ArrayList<>();
        List<BigInteger> bits = List.of(BigInteger.ZERO, BigInteger.ONE);
        for (int slot = 0; slot < slots.size(); slot++) {
            BigInteger plaintext = BigInteger.valueOf(slots.get(slot));
            BigInteger randomKey = cs.cs().generateRandomKey();
            CipherValue ciphertext = cs.cs().encrypt(plaintext, randomKey);
            // a slot of 2 cannot be proven to be 0 or 1, so prove it as 1
            slotProofs.add(
                    cs.cs()
                            .proveMembership(
                                    ciphertext,
                                    plaintext.min(BigInteger.ONE),
                                    randomKey,
                                    bits,
                                    Zkp.oneHotContext(null, options, slot)));
            ciphertexts.add(ciphertext);
            randomKeys.add(randomKey);
        }
        CipherValue total = sum(ciphertexts, cs.cs()::add);
        // claim that the sum is 1 although it may not be
        Proof sumProof =
                cs.cs()
                        .proveMembership(
                                total,
                                BigInteger.ONE,
                                cs.cs().combineRandomKeys(randomKeys),
                                List.of(BigInteger.ONE),
                                Zkp.oneHotContext(null, options, "sum"));
        return new Proven<>(
                ciphertexts.stream().map(cs::createCiphertextObj).toList(),
                new Proof.OneHot(slotProofs, sumProof));
    }

    @Test
    @DisplayName("One-hot ballots report invalid inputs")
    void testOneHotInvalidInputs() {
        LightPHE cs = LightPHE.builder().algorithmName("Paillier").keySize(128).build();
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.encryptOneHot(3, 3, null))
                .withMessageContaining("Choice must be in");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.encryptOneHot(0, 0, null))
                .withMessageContaining("at least 1");

        Proven<List<Ciphertext>> ballot = cs.encryptOneHot(0, 1, null);
        assertThat(cs.verifyOneHot(ballot.value(), ballot.proof(), null)).isTrue();
        assertThat(cs.verifyOneHot(List.of(), ballot.proof(), null)).isFalse();
        assertThat(cs.verifyOneHot(ballot.value(), null, null)).isFalse();

        LightPHE rsa = LightPHE.builder().algorithmName("RSA").keySize(50).build();
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> rsa.encryptOneHot(0, 2, null))
                .withMessageContaining("does not support proving");
    }
}
