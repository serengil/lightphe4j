package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.serengil.lightphe.commons.Zkp;
import io.github.serengil.lightphe.cryptosystems.EllipticCurveElGamal;
import io.github.serengil.lightphe.ecc.CurvePoint;
import io.github.serengil.lightphe.ecc.LightECC;
import io.github.serengil.lightphe.model.Ciphertext;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.PartialDecryption;
import io.github.serengil.lightphe.model.Proof;
import io.github.serengil.lightphe.model.Proven;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.IntValue;
import io.github.serengil.lightphe.model.value.PointValue;
import io.github.serengil.lightphe.model.value.TupleValue;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/** Port of {@code tests/test_zkp.py}. */
class ZkpTest {

    static LightPHE build(String algorithmName, Integer keySize, boolean primeOrder) {
        return LightPHE.builder()
                .algorithmName(algorithmName)
                .keySize(keySize)
                .primeOrder(primeOrder)
                .build();
    }

    static LightPHE publicCopy(LightPHE cs, String algorithmName, Path tmp) {
        Path publicFile = tmp.resolve("public.json");
        cs.exportKeys(publicFile, true);
        return LightPHE.builder().algorithmName(algorithmName).keyFile(publicFile).build();
    }

    /** Combines two encrypted values homomorphically, and returns the expected plaintext. */
    record Computed(Ciphertext ciphertext, BigInteger expected) {}

    static Computed compute(LightPHE cs, String algorithmName, long m1, long m2) {
        if ("ElGamal".equals(algorithmName)) {
            return new Computed(
                    cs.encrypt(m1).multiply(cs.encrypt(m2)), BigInteger.valueOf(m1 * m2));
        }
        return new Computed(cs.encrypt(m1).add(cs.encrypt(m2)), BigInteger.valueOf(m1 + m2));
    }

    /** Increments the first component of a proof. */
    static Proof tamper(Proof proof) {
        if (proof instanceof Proof.ChallengeResponse p) {
            return new Proof.ChallengeResponse(p.challenge().add(BigInteger.ONE), p.response());
        }
        if (proof instanceof Proof.Disjunctive p) {
            List<BigInteger> challenges = new ArrayList<>(p.challenges());
            challenges.set(0, challenges.get(0).add(BigInteger.ONE));
            return new Proof.Disjunctive(challenges, p.responses());
        }
        if (proof instanceof Proof.Randomness p) {
            return new Proof.Randomness(p.randomness().add(BigInteger.ONE));
        }
        if (proof instanceof Proof.PaillierKnowledge p) {
            return new Proof.PaillierKnowledge(
                    p.challenge().add(BigInteger.ONE),
                    p.plaintextResponse(),
                    p.randomnessResponse());
        }
        throw new IllegalArgumentException("unexpected proof " + proof);
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(
            value = {
                "ElGamal, 128, true",
                "Exponential-ElGamal, 128, true",
                "EllipticCurve-ElGamal, null, false",
                "Paillier, 128, false",
                "Damgard-Jurik, 128, false"
            },
            nullValues = "null")
    @DisplayName("Proof of correct decryption is verified with the public key only")
    void testProofOfCorrectDecryption(
            String algorithmName, Integer keySize, boolean primeOrder, @TempDir Path tmp) {
        LightPHE cs = build(algorithmName, keySize, primeOrder);
        Computed computed = compute(cs, algorithmName, 17, 3);
        Ciphertext c = computed.ciphertext();

        Proven<BigInteger> decryption = cs.decryptWithProof(c);
        BigInteger plaintext = decryption.value();
        Proof proof = decryption.proof();
        assertThat(plaintext).isEqualTo(computed.expected()).isEqualTo(cs.decrypt(c));
        assertThat(cs.verifyDecryption(c, plaintext, proof)).isTrue();

        // verifier has the public key only
        LightPHE verifier = publicCopy(cs, algorithmName, tmp);
        assertThat(verifier.verifyDecryption(c, plaintext, proof)).isTrue();

        // wrong plaintext, tampered proof and malformed proof are rejected
        assertThat(verifier.verifyDecryption(c, plaintext.add(BigInteger.ONE), proof)).isFalse();
        assertThat(verifier.verifyDecryption(c, plaintext, tamper(proof))).isFalse();
        assertThat(verifier.verifyDecryption(c, plaintext, null)).isFalse();
        assertThat(verifier.verifyDecryption(c, null, proof)).isFalse();

        // proof of a ciphertext does not prove another ciphertext of same plaintext
        Ciphertext cPrime = cs.regenerateCiphertext(c);
        assertThat(verifier.verifyDecryption(cPrime, plaintext, proof)).isFalse();
        Proven<BigInteger> other = cs.decryptWithProof(cPrime);
        assertThat(other.value()).isEqualTo(plaintext);
        assertThat(verifier.verifyDecryption(cPrime, plaintext, other.proof())).isTrue();
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"ElGamal", "Exponential-ElGamal"})
    @DisplayName("ElGamal proofs require a generator of a prime order")
    void testElGamalProofsRequirePrimeOrder(String algorithmName) {
        LightPHE cs = build(algorithmName, 50, false);
        Ciphertext c = cs.encrypt(5);
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.decryptWithProof(c))
                .withMessageContaining("primeOrder = true");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                cs.verifyDecryption(
                                        c,
                                        5,
                                        new Proof.ChallengeResponse(
                                                BigInteger.ONE, BigInteger.ONE)))
                .withMessageContaining("primeOrder = true");
    }

    @Test
    @DisplayName("Ciphertexts out of the group of prime order are rejected")
    void testCiphertextOutOfGroupIsRejected() {
        LightPHE cs = build("Exponential-ElGamal", 128, true);
        Ciphertext c = cs.encrypt(5);
        Proven<BigInteger> decryption = cs.decryptWithProof(c);

        // -c1 is not in the subgroup of prime order q
        BigInteger p = cs.cs().keys().publicNumber("p");
        List<BigInteger> pair = ((TupleValue) c.value()).asIntegers();
        Ciphertext forged =
                cs.createCiphertextObj(
                        TupleValue.of(
                                IntValue.of(p.subtract(pair.get(0))), IntValue.of(pair.get(1))));
        assertThat(cs.verifyDecryption(forged, decryption.value(), decryption.proof())).isFalse();
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"RSA", "Okamoto-Uchiyama"})
    @DisplayName("Algorithms without proofs of correct decryption report it")
    void testUnsupportedAlgorithms(String algorithmName) {
        LightPHE cs = build(algorithmName, 50, false);
        Ciphertext c = cs.encrypt(5);
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.decryptWithProof(c))
                .withMessageContaining("does not support proofs of correct decryption");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.verifyDecryption(c, 5, null))
                .withMessageContaining("does not support proofs of correct decryption");
    }

    private static ThresholdTest.Committee committee(
            String algorithmName, int threshold, int parties) {
        return ThresholdTest.build(
                algorithmName,
                "EllipticCurve-ElGamal".equals(algorithmName) ? null : 128,
                threshold,
                parties);
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"ElGamal", "Exponential-ElGamal", "EllipticCurve-ElGamal"})
    @DisplayName("Proofs of partial decryption catch a cheating shareholder")
    void testVerifiablePartialDecryptions(String algorithmName) {
        int parties = 5;
        ThresholdTest.Committee committee = committee(algorithmName, 3, parties);
        LightPHE dealer = committee.dealer();
        List<LightPHE> shareholders = committee.shareholders();

        Computed computed = compute(dealer, algorithmName, 17, 3);
        Ciphertext c = computed.ciphertext();
        List<PartialDecryption> partials =
                shareholders.stream().map(s -> s.partialDecrypt(c, true)).toList();

        for (PartialDecryption partial : partials) {
            assertThat(dealer.verifyPartialDecryption(c, partial)).isTrue();
        }

        // a cheating shareholder sends a wrong value with its old proof
        PartialDecryption honest = partials.get(0);
        CipherValue forgedValue;
        if ("EllipticCurve-ElGamal".equals(algorithmName)) {
            forgedValue = shareholders.get(1).partialDecrypt(c, true).value();
        } else {
            Keys keys = dealer.cs().keys();
            BigInteger p = keys.publicNumber("p");
            forgedValue =
                    IntValue.of(
                            ((IntValue) honest.value())
                                    .value()
                                    .multiply(keys.publicNumber("g"))
                                    .mod(p));
        }
        PartialDecryption forged = honest.withValue(forgedValue);
        assertThat(dealer.verifyPartialDecryption(c, forged)).isFalse();

        // a proof cannot be reused under another index or for another ciphertext
        assertThat(dealer.verifyPartialDecryption(c, honest.withIndex(2))).isFalse();
        assertThat(dealer.verifyPartialDecryption(c, honest.withIndex(parties + 1))).isFalse();
        Ciphertext otherC = dealer.regenerateCiphertext(c);
        assertThat(dealer.verifyPartialDecryption(otherC, honest)).isFalse();
        assertThat(dealer.verifyPartialDecryption(c, honest.withProof(null))).isFalse();

        // invalid partial decryptions are discarded if enough valid ones remain
        List<PartialDecryption> withForged = new ArrayList<>();
        withForged.add(forged);
        withForged.addAll(partials.subList(1, 4));
        assertThat(dealer.combinePartialDecryptions(c, withForged, true))
                .isEqualTo(computed.expected());

        // otherwise combination fails instead of returning a wrong plaintext
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () -> dealer.combinePartialDecryptions(c, withForged.subList(0, 3), true))
                .withMessageContaining("valid partial decryptions");

        // partial decryptions without proofs are discarded if verification is on
        List<PartialDecryption> unproven =
                shareholders.stream().map(s -> s.partialDecrypt(c)).toList();
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> dealer.combinePartialDecryptions(c, unproven, true))
                .withMessageContaining("valid partial decryptions");
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"ElGamal", "Exponential-ElGamal", "EllipticCurve-ElGamal"})
    @DisplayName("Proofs of partial decryption are opt-in")
    void testPartialDecryptionProofsAreOptIn(String algorithmName) {
        ThresholdTest.Committee committee = committee(algorithmName, 2, 3);
        LightPHE dealer = committee.dealer();
        Computed computed = compute(dealer, algorithmName, 17, 3);
        Ciphertext c = computed.ciphertext();

        // no proofs by default, and combination does not check them by default
        List<PartialDecryption> partials =
                committee.shareholders().stream().map(s -> s.partialDecrypt(c)).toList();
        assertThat(partials).allMatch(partial -> partial.proof() == null);
        assertThat(dealer.combinePartialDecryptions(c, partials)).isEqualTo(computed.expected());

        // proven partial decryptions are combined with or without verification
        List<PartialDecryption> proven =
                committee.shareholders().stream().map(s -> s.partialDecrypt(c, true)).toList();
        assertThat(dealer.combinePartialDecryptions(c, proven)).isEqualTo(computed.expected());
        assertThat(dealer.combinePartialDecryptions(c, proven, true))
                .isEqualTo(computed.expected());

        // without verification, a cheating shareholder causes a wrong plaintext silently.
        // additive variants would brute force a huge discrete logarithm, so check ElGamal only.
        if ("ElGamal".equals(algorithmName)) {
            BigInteger p = dealer.cs().keys().publicNumber("p");
            PartialDecryption forged =
                    partials.get(0)
                            .withValue(
                                    IntValue.of(
                                            ((IntValue) partials.get(0).value())
                                                    .value()
                                                    .shiftLeft(1)
                                                    .mod(p)));
            assertThat(dealer.combinePartialDecryptions(c, List.of(forged, partials.get(1))))
                    .isNotEqualTo(computed.expected());
        }
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"Paillier", "Damgard-Jurik"})
    @DisplayName("Proofs of Paillier partial decryptions require safe primes")
    void testPaillierPartialDecryptionProofsRequireSafePrimes(String algorithmName) {
        ThresholdTest.Committee committee = ThresholdTest.build(algorithmName, 50, 2, 3);
        LightPHE dealer = committee.dealer();
        LightPHE shareholder = committee.shareholders().get(0);
        Ciphertext c = dealer.encrypt(5);

        // regular keys still decrypt without proofs
        List<PartialDecryption> partials =
                committee.shareholders().stream().map(s -> s.partialDecrypt(c)).toList();
        assertThat(dealer.combinePartialDecryptions(c, partials)).isEqualTo(BigInteger.valueOf(5));

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> shareholder.partialDecrypt(c, true))
                .withMessageContaining("safePrimes = true");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> dealer.verifyPartialDecryption(c, shareholder.partialDecrypt(c)))
                .withMessageContaining("safePrimes = true");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> dealer.combinePartialDecryptions(c, partials, true))
                .withMessageContaining("safePrimes = true");
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"Paillier", "Damgard-Jurik"})
    @DisplayName("Proofs of Paillier partial decryptions catch a cheating shareholder")
    void testVerifiablePaillierPartialDecryptions(String algorithmName, @TempDir Path tmp) {
        int parties = 5;
        LightPHE dealer =
                LightPHE.builder()
                        .algorithmName(algorithmName)
                        .keySize(128)
                        .safePrimes(true)
                        .build();

        // safe prime keys work as regular keys
        Ciphertext c = dealer.encrypt(100).add(dealer.encrypt(50));
        assertThat(dealer.decrypt(c)).isEqualTo(BigInteger.valueOf(150));
        assertThat(dealer.decrypt(c.multiply(3))).isEqualTo(BigInteger.valueOf(450));

        List<Keys> shareKeys = dealer.generateThresholdKeys(3, parties);

        // keys of shareholders survive exporting and restoring
        List<LightPHE> shareholders = new ArrayList<>();
        for (int k = 0; k < shareKeys.size(); k++) {
            Path keyFile = tmp.resolve("share_" + k + ".json");
            LightPHE.builder()
                    .algorithmName(algorithmName)
                    .keys(shareKeys.get(k))
                    .build()
                    .exportKeys(keyFile);
            shareholders.add(
                    LightPHE.builder().algorithmName(algorithmName).keyFile(keyFile).build());
        }

        List<PartialDecryption> partials =
                shareholders.stream().map(s -> s.partialDecrypt(c, true)).toList();
        for (PartialDecryption partial : partials) {
            assertThat(dealer.verifyPartialDecryption(c, partial)).isTrue();
        }
        assertThat(dealer.combinePartialDecryptions(c, partials, true))
                .isEqualTo(BigInteger.valueOf(150));

        // partial decryptions without proofs are combined if verification is off
        List<PartialDecryption> unproven =
                shareholders.stream().map(s -> s.partialDecrypt(c)).toList();
        assertThat(unproven).allMatch(partial -> partial.proof() == null);
        assertThat(dealer.combinePartialDecryptions(c, unproven))
                .isEqualTo(BigInteger.valueOf(150));
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> dealer.combinePartialDecryptions(c, unproven, true))
                .withMessageContaining("valid partial decryptions");

        // a cheating shareholder multiplies its partial decryption with (1 + n)
        BigInteger n = dealer.cs().keys().publicNumber("n");
        BigInteger modulo = dealer.cs().ciphertextModulo();
        PartialDecryption honest = partials.get(0);
        PartialDecryption forged =
                honest.withValue(
                        IntValue.of(
                                ((IntValue) honest.value())
                                        .value()
                                        .multiply(n.add(BigInteger.ONE))
                                        .mod(modulo)));
        assertThat(dealer.verifyPartialDecryption(c, forged)).isFalse();

        // a proof cannot be reused under another index or for another ciphertext
        assertThat(dealer.verifyPartialDecryption(c, honest.withIndex(2))).isFalse();
        assertThat(dealer.verifyPartialDecryption(c, honest.withIndex(parties + 1))).isFalse();
        assertThat(dealer.verifyPartialDecryption(dealer.regenerateCiphertext(c), honest))
                .isFalse();
        assertThat(dealer.verifyPartialDecryption(c, honest.withProof(null))).isFalse();
        assertThat(dealer.verifyPartialDecryption(c, honest.withProof(tamper(honest.proof()))))
                .isFalse();

        // invalid partial decryptions are discarded if enough valid ones remain
        List<PartialDecryption> withForged = new ArrayList<>();
        withForged.add(forged);
        withForged.addAll(partials.subList(1, 4));
        assertThat(dealer.combinePartialDecryptions(c, withForged, true))
                .isEqualTo(BigInteger.valueOf(150));
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () -> dealer.combinePartialDecryptions(c, withForged.subList(0, 3), true))
                .withMessageContaining("valid partial decryptions");
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
    @DisplayName("Proofs of membership bind ballots to their values and context")
    void testProofOfMembership(
            String algorithmName, Integer keySize, boolean primeOrder, @TempDir Path tmp) {
        LightPHE cs = build(algorithmName, keySize, primeOrder);

        // voter has the public key only
        LightPHE voter = publicCopy(cs, algorithmName, tmp);

        for (long vote : new long[] {0, 1}) {
            Proven<Ciphertext> ballot = voter.encryptWithProof(vote, null, "voter-42");
            Ciphertext c = ballot.value();
            Proof proof = ballot.proof();
            assertThat(cs.decrypt(c)).isEqualTo(BigInteger.valueOf(vote));
            assertThat(voter.verifyCiphertext(c, proof, null, "voter-42")).isTrue();
            assertThat(voter.verifyCiphertext(c, proof, List.of(0, 1), "voter-42")).isTrue();

            // proof is bound to its context, values and ciphertext
            assertThat(voter.verifyCiphertext(c, proof, null, "voter-43")).isFalse();
            assertThat(voter.verifyCiphertext(c, proof)).isFalse();
            assertThat(voter.verifyCiphertext(c, proof, List.of(1, 0), "voter-42")).isFalse();
            assertThat(voter.verifyCiphertext(c.add(c), proof, null, "voter-42")).isFalse();
            assertThat(voter.verifyCiphertext(c, tamper(proof), null, "voter-42")).isFalse();
            assertThat(voter.verifyCiphertext(c, null, null, "voter-42")).isFalse();
        }

        // larger sets of values, e.g. a rating in [1, 5]
        Proven<Ciphertext> rating = voter.encryptWithProof(4, List.of(1, 2, 3, 4, 5), null);
        assertThat(
                        voter.verifyCiphertext(
                                rating.value(), rating.proof(), List.of(1, 2, 3, 4, 5), null))
                .isTrue();
        assertThat(
                        voter.verifyCiphertext(
                                rating.value(), rating.proof(), List.of(1, 2, 3, 5, 6), null))
                .isFalse();
        assertThat(cs.decrypt(rating.value())).isEqualTo(BigInteger.valueOf(4));

        // single allowed value
        Proven<Ciphertext> single = voter.encryptWithProof(7, List.of(7), null);
        assertThat(voter.verifyCiphertext(single.value(), single.proof(), List.of(7), null))
                .isTrue();

        // invalid inputs
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> voter.encryptWithProof(2))
                .withMessageContaining("one of the allowed values");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> voter.encryptWithProof(1, List.of(0, 1, 1), null))
                .withMessageContaining("distinct");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> voter.encryptWithProof(1, List.of(), null))
                .withMessageContaining("non-empty");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> voter.encryptWithProof(1, List.of(0, 1.5), null))
                .withMessageContaining("non-empty");
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
    @DisplayName("A voter encrypting 2 cannot prove that it encrypts 1")
    void testCheatingVoterIsRejected(String algorithmName, Integer keySize, boolean primeOrder) {
        LightPHE cs = build(algorithmName, keySize, primeOrder);
        Keys keys = cs.cs().keys();
        List<BigInteger> values = List.of(BigInteger.ZERO, BigInteger.ONE);
        BigInteger r = cs.cs().generateRandomKey();
        CipherValue value = cs.cs().encrypt(BigInteger.TWO, r);

        Proof proof;
        if ("Paillier".equals(algorithmName) || "Damgard-Jurik".equals(algorithmName)) {
            BigInteger n = keys.publicNumber("n");
            BigInteger modulo = cs.cs().ciphertextModulo();
            String domain =
                    "Paillier".equals(algorithmName)
                            ? "lightphe/paillier/membership"
                            : "lightphe/damgard-jurik/membership";
            proof =
                    Zkp.proveNthPowerOr(
                            n,
                            modulo,
                            Zkp.paillierMembershipCandidates(
                                    ((IntValue) value).value(), values, n, modulo),
                            r,
                            1,
                            domain,
                            Arrays.asList(values, null));
        } else if ("Exponential-ElGamal".equals(algorithmName)) {
            BigInteger p = keys.publicNumber("p");
            BigInteger g = keys.publicNumber("g");
            List<BigInteger> pair = ((TupleValue) value).asIntegers();
            List<BigInteger> h2s = new ArrayList<>();
            for (BigInteger v : values) {
                h2s.add(pair.get(1).multiply(g.modPow(v.negate(), p)).mod(p));
            }
            proof =
                    Zkp.proveDleqOr(
                            new Zkp.ModularGroup(p, keys.publicNumber("q")),
                            g,
                            pair.get(0),
                            keys.publicNumber("y"),
                            h2s,
                            r,
                            1,
                            "lightphe/exponential-elgamal/membership",
                            Arrays.asList(p, pair.get(1), values, null));
        } else {
            LightECC ecc = ((EllipticCurveElGamal) cs.cs()).ecc();
            TupleValue pair = (TupleValue) value;
            PointValue c1 = (PointValue) pair.get(0);
            PointValue c2Value = (PointValue) pair.get(1);
            CurvePoint c2 = ecc.point(c2Value.x(), c2Value.y());
            List<CurvePoint> h2s = new ArrayList<>();
            for (BigInteger v : values) {
                h2s.add(v.signum() == 0 ? c2 : c2.subtract(ecc.g().multiply(v)));
            }
            proof =
                    Zkp.proveDleqOr(
                            new Zkp.EllipticCurveGroup(ecc),
                            ecc.g(),
                            ecc.point(c1.x(), c1.y()),
                            ecc.point(keys.publicPoint("Qa").x(), keys.publicPoint("Qa").y()),
                            h2s,
                            r,
                            1,
                            "lightphe/elliptic-curve-elgamal/membership",
                            Arrays.asList(ecc.n(), c2Value, values, null));
        }

        Ciphertext ballot = cs.createCiphertextObj(value);
        assertThat(cs.decrypt(ballot)).isEqualTo(BigInteger.TWO);
        assertThat(cs.verifyCiphertext(ballot, proof)).isFalse();
    }

    @Test
    @DisplayName("Membership proofs report unsupported algorithms")
    void testMembershipProofsUnsupported() {
        LightPHE elGamal = build("ElGamal", 128, true);
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> elGamal.encryptWithProof(1, List.of(1, 2), null))
                .withMessageContaining("Use Exponential-ElGamal instead");

        LightPHE exponential = build("Exponential-ElGamal", 50, false);
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> exponential.encryptWithProof(1))
                .withMessageContaining("primeOrder = true");

        for (String algorithmName : List.of("RSA", "Okamoto-Uchiyama")) {
            LightPHE cs = build(algorithmName, 50, false);
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> cs.encryptWithProof(1))
                    .withMessageContaining("does not support proving");
        }
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(
            value = {
                "ElGamal, 128, true",
                "Exponential-ElGamal, 128, true",
                "EllipticCurve-ElGamal, null, false",
                "Paillier, 128, false",
                "Damgard-Jurik, 128, false"
            },
            nullValues = "null")
    @DisplayName("Proofs of knowledge cannot be reused for copied or modified ciphertexts")
    void testProofOfKnowledge(
            String algorithmName, Integer keySize, boolean primeOrder, @TempDir Path tmp) {
        LightPHE cs = build(algorithmName, keySize, primeOrder);

        // prover and verifier have the public key only
        LightPHE publicCs = publicCopy(cs, algorithmName, tmp);

        Proven<Ciphertext> proven = publicCs.encryptWithProofOfKnowledge(17, "alice");
        Ciphertext c = proven.value();
        Proof proof = proven.proof();
        assertThat(cs.decrypt(c)).isEqualTo(BigInteger.valueOf(17));
        assertThat(publicCs.verifyKnowledge(c, proof, "alice")).isTrue();

        // proof is bound to its context and ciphertext
        assertThat(publicCs.verifyKnowledge(c, proof, "bob")).isFalse();
        assertThat(publicCs.verifyKnowledge(c, proof)).isFalse();

        // a copied ciphertext cannot be re-randomized or modified with the same proof
        assertThat(publicCs.verifyKnowledge(publicCs.regenerateCiphertext(c), proof, "alice"))
                .isFalse();
        Ciphertext modified =
                "ElGamal".equals(algorithmName)
                        ? c.multiply(publicCs.encrypt(2))
                        : c.add(publicCs.encrypt(1));
        assertThat(publicCs.verifyKnowledge(modified, proof, "alice")).isFalse();
        if (!"ElGamal".equals(algorithmName)) {
            assertThat(publicCs.verifyKnowledge(c.multiply(3), proof, "alice")).isFalse();
        }

        // tampered and malformed proofs are rejected
        assertThat(publicCs.verifyKnowledge(c, tamper(proof), "alice")).isFalse();
        assertThat(publicCs.verifyKnowledge(c, null, "alice")).isFalse();
        assertThat(publicCs.verifyKnowledge(c, new Proof.Randomness(BigInteger.ONE), "alice"))
                .isFalse();

        // a proof of another ciphertext does not prove this one
        Proven<Ciphertext> other = publicCs.encryptWithProofOfKnowledge(17, "alice");
        assertThat(publicCs.verifyKnowledge(c, other.proof(), "alice")).isFalse();
        assertThat(publicCs.verifyKnowledge(other.value(), other.proof(), "alice")).isTrue();
    }

    @Test
    @DisplayName("Proofs of knowledge report unsupported algorithms")
    void testProofOfKnowledgeUnsupported() {
        for (String algorithmName : List.of("ElGamal", "Exponential-ElGamal")) {
            LightPHE cs = build(algorithmName, 50, false);
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> cs.encryptWithProofOfKnowledge(5))
                    .withMessageContaining("primeOrder = true");
        }

        for (String algorithmName : List.of("RSA", "Okamoto-Uchiyama")) {
            LightPHE cs = build(algorithmName, 50, false);
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> cs.encryptWithProofOfKnowledge(5))
                    .withMessageContaining("does not support proofs of knowledge");
        }
    }

    @Test
    @DisplayName("Fiat-Shamir transcripts are serialised as json.dumps of the Python library")
    void testChallengeTranscript() {
        // hashlib.sha512(b'["d",[null,"\\u00e9",[1,2],{"k":true}]]') of the Python library
        BigInteger modulo = BigInteger.ONE.shiftLeft(512);
        BigInteger expected =
                new BigInteger(
                        1,
                        sha512(
                                "[\"d\",[null,\"\\u00e9\",[1,2],{\"k\":true}]]"
                                        .getBytes(StandardCharsets.UTF_8)));
        assertThat(
                        Zkp.challenge(
                                "d",
                                modulo,
                                null,
                                "é",
                                TupleValue.of(IntValue.of(1), IntValue.of(2)),
                                Map.of("k", true)))
                .isEqualTo(expected);
    }

    private static byte[] sha512(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-512").digest(input);
        } catch (NoSuchAlgorithmException err) {
            throw new IllegalStateException(err);
        }
    }
}
