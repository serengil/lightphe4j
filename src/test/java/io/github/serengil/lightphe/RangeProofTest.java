package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.serengil.lightphe.commons.Zkp;
import io.github.serengil.lightphe.model.Ciphertext;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.Proof;
import io.github.serengil.lightphe.model.Proven;
import io.github.serengil.lightphe.model.value.CipherValue;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** Port of {@code tests/test_range_proof.py}. */
class RangeProofTest {

    @ParameterizedTest(name = "{0}")
    @CsvSource(
            value = {
                "Exponential-ElGamal, 128, true",
                "EllipticCurve-ElGamal, null, false",
                "Paillier, 128, false",
                "Damgard-Jurik, 128, false"
            },
            nullValues = "null")
    @DisplayName("Range proofs are bound to their range, context and ciphertext")
    void testRangeProof(
            String algorithmName, Integer keySize, boolean primeOrder, @TempDir Path tmp) {
        LightPHE cs = ZkpTest.build(algorithmName, keySize, primeOrder);

        // prover and verifier have the public key only
        LightPHE publicCs = ZkpTest.publicCopy(cs, algorithmName, tmp);

        long low = 10;
        long high = 200;
        Proven<Ciphertext> proven = null;
        for (long plaintext : new long[] {low, 137, high}) {
            proven = publicCs.encryptWithRangeProof(plaintext, low, high, "alice");
            assertThat(cs.decrypt(proven.value())).isEqualTo(BigInteger.valueOf(plaintext));
            assertThat(publicCs.verifyRange(proven.value(), proven.proof(), low, high, "alice"))
                    .isTrue();
        }
        Ciphertext c = proven.value();
        Proof proof = proven.proof();

        // proof is bound to its context, range and ciphertext
        assertThat(publicCs.verifyRange(c, proof, low, high, "bob")).isFalse();
        assertThat(publicCs.verifyRange(c, proof, low, high, null)).isFalse();
        assertThat(publicCs.verifyRange(c, proof, low - 1, high, "alice")).isFalse();
        assertThat(publicCs.verifyRange(c, proof, low, high + 1, "alice")).isFalse();
        assertThat(publicCs.verifyRange(c.add(c), proof, low, high, "alice")).isFalse();
        Ciphertext otherC = publicCs.encryptWithRangeProof(high, low, high, "alice").value();
        assertThat(publicCs.verifyRange(otherC, proof, low, high, "alice")).isFalse();

        // tampered, reordered, truncated and malformed proofs are rejected
        Proof.Range range = (Proof.Range) proof;
        List<CipherValue> ciphertexts = new ArrayList<>(range.ciphertexts());
        List<Proof> proofs = new ArrayList<>(range.proofs());
        Collections.swap(ciphertexts, 1, 2);
        Collections.swap(proofs, 1, 2);
        assertThat(
                        publicCs.verifyRange(
                                c, new Proof.Range(ciphertexts, proofs), low, high, "alice"))
                .isFalse();

        Proof truncated =
                new Proof.Range(
                        range.ciphertexts().subList(0, range.ciphertexts().size() - 1),
                        range.proofs().subList(0, range.proofs().size() - 1));
        assertThat(publicCs.verifyRange(c, truncated, low, high, "alice")).isFalse();

        List<Proof> tamperedProofs = new ArrayList<>(range.proofs());
        tamperedProofs.set(1, ZkpTest.tamper(tamperedProofs.get(1)));
        assertThat(
                        publicCs.verifyRange(
                                c,
                                new Proof.Range(range.ciphertexts(), tamperedProofs),
                                low,
                                high,
                                "alice"))
                .isFalse();

        assertThat(publicCs.verifyRange(c, null, low, high, "alice")).isFalse();
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
    @DisplayName("Out of range ciphertexts are rejected")
    void testOutOfRangeCiphertextIsRejected(
            String algorithmName, Integer keySize, boolean primeOrder) {
        LightPHE cs = ZkpTest.build(algorithmName, keySize, primeOrder);
        BigInteger low = BigInteger.ZERO;
        BigInteger high = BigInteger.valueOf(100);
        List<BigInteger> values = List.of(BigInteger.ZERO, BigInteger.ZERO, BigInteger.ONE);

        // decomposition cannot represent 150 with bits of [0, 100], so restored ciphertext
        // does not encrypt 150, and the ciphertext of 150 does not match it
        Ciphertext outOfRange = cs.encrypt(150);
        Proof proof =
                Zkp.proveRange(cs.cs(), BigInteger.valueOf(150), low, high, values, null).proof();
        assertThat(cs.verifyRange(outOfRange, proof, low, high, null)).isFalse();

        Proof other = cs.encryptWithRangeProof(50, 0, 100, null).proof();
        assertThat(cs.verifyRange(outOfRange, other, low, high, null)).isFalse();
    }

    @Test
    @DisplayName("Single value, negative and power of two ranges work")
    void testEdgeRanges() {
        LightPHE cs = LightPHE.builder().algorithmName("Paillier").keySize(128).build();
        BigInteger modulo = cs.cs().plaintextModulo();

        // single value range
        Proven<Ciphertext> single = cs.encryptWithRangeProof(7, 7, 7, null);
        assertThat(cs.verifyRange(single.value(), single.proof(), 7, 7, null)).isTrue();
        assertThat(cs.decrypt(single.value())).isEqualTo(BigInteger.valueOf(7));

        // ranges with negative values decrypt to modulo - x as encrypt does
        Proven<Ciphertext> negative = cs.encryptWithRangeProof(-30, -100, 100, null);
        assertThat(cs.verifyRange(negative.value(), negative.proof(), -100, 100, null)).isTrue();
        assertThat(cs.decrypt(negative.value())).isEqualTo(modulo.subtract(BigInteger.valueOf(30)));

        // power of two widths
        for (long high : new long[] {1, 2, 255, 256}) {
            Proven<Ciphertext> proven = cs.encryptWithRangeProof(high, 0, high, null);
            assertThat(cs.verifyRange(proven.value(), proven.proof(), 0, high, null)).isTrue();
        }

        // invalid inputs
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.encryptWithRangeProof(101, 0, 100, null))
                .withMessageContaining("must be in");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.encryptWithRangeProof(-1, 0, 100, null))
                .withMessageContaining("must be in");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.encryptWithRangeProof(5, 10, 0, null))
                .withMessageContaining("must not be greater");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                cs.encryptWithRangeProof(
                                        BigInteger.valueOf(5), BigInteger.ZERO, modulo, null))
                .withMessageContaining("narrower");
    }

    @Test
    @DisplayName("Range proofs report unsupported algorithms")
    void testUnsupportedAlgorithms() {
        LightPHE elGamal = ZkpTest.build("ElGamal", 128, true);
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> elGamal.encryptWithRangeProof(5, 1, 10, null))
                .withMessageContaining("Use Exponential-ElGamal instead");

        LightPHE exponential = ZkpTest.build("Exponential-ElGamal", 50, false);
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> exponential.encryptWithRangeProof(5, 0, 10, null))
                .withMessageContaining("primeOrder = true");

        for (String algorithmName : List.of("RSA", "Okamoto-Uchiyama")) {
            LightPHE cs = ZkpTest.build(algorithmName, 50, false);
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> cs.encryptWithRangeProof(5, 0, 10, null))
                    .withMessageContaining("does not support proving");
        }
    }

    @Test
    @DisplayName("Employees prove that encrypted salaries are in a sensible range")
    void testSalarySurvey() {
        LightPHE authority = LightPHE.builder().algorithmName("Paillier").keySize(128).build();
        LightPHE publicCs =
                LightPHE.builder()
                        .algorithmName("Paillier")
                        .keys(Keys.of(authority.cs().keys().publicKey(), null))
                        .build();
        long low = 0;
        long high = 500000;

        Map<String, Long> salaries = new LinkedHashMap<>();
        salaries.put("alice", 85000L);
        salaries.put("bob", 62000L);
        salaries.put("carol", 120000L);
        salaries.put("dave", 47000L);
        Map<String, Proven<Ciphertext>> submissions = new LinkedHashMap<>();
        salaries.forEach(
                (employee, salary) ->
                        submissions.put(
                                employee,
                                publicCs.encryptWithRangeProof(salary, low, high, employee)));

        // mallory copies alice's submission
        submissions.put("mallory", submissions.get("alice"));

        // oscar cannot prove a huge salary, and cannot reuse a proof of a valid salary
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () -> publicCs.encryptWithRangeProof(1_000_000_000L, low, high, "oscar"))
                .withMessageContaining("must be in");
        Proof oscarProof = publicCs.encryptWithRangeProof(50000, low, high, "oscar").proof();
        submissions.put("oscar", new Proven<>(publicCs.encrypt(1_000_000_000L), oscarProof));

        // trent cannot submit a negative salary either
        Proof trentProof = publicCs.encryptWithRangeProof(0, low, high, "trent").proof();
        submissions.put("trent", new Proven<>(publicCs.encrypt(-1_000_000L), trentProof));

        List<Ciphertext> valid = new ArrayList<>();
        submissions.forEach(
                (employee, submission) -> {
                    if (publicCs.verifyRange(
                            submission.value(), submission.proof(), low, high, employee)) {
                        valid.add(submission.value());
                    }
                });
        assertThat(valid).hasSize(salaries.size());

        Ciphertext total = valid.get(0);
        for (Ciphertext c : valid.subList(1, valid.size())) {
            total = total.add(c);
        }

        // authority decrypts the total only with a proof, and anyone verifies it
        Proven<BigInteger> result = authority.decryptWithProof(total);
        assertThat(publicCs.verifyDecryption(total, result.value(), result.proof())).isTrue();
        assertThat(result.value()).isEqualTo(BigInteger.valueOf(314000));
        assertThat(result.value().longValueExact() / valid.size()).isEqualTo(78500);
    }
}
