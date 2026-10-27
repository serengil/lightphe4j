package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.within;

import io.github.serengil.lightphe.model.Ciphertext;
import io.github.serengil.lightphe.model.EncryptedTensor;
import io.github.serengil.lightphe.model.FractionPartialDecryption;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.PartialDecryption;
import io.github.serengil.lightphe.model.value.IntValue;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/** Port of {@code tests/test_threshold.py}. */
class ThresholdTest {

    private static final int THRESHOLD = 3;
    private static final int PARTIES = 5;

    /** A dealer, which keeps the public key only, and its shareholders. */
    record Committee(LightPHE dealer, List<LightPHE> shareholders) {}

    static Committee build(String algorithmName, Integer keySize, int threshold, int parties) {
        LightPHE dealer =
                LightPHE.builder()
                        .algorithmName(algorithmName)
                        .keySize(keySize)
                        .primeOrder(
                                "ElGamal".equals(algorithmName)
                                        || "Exponential-ElGamal".equals(algorithmName))
                        .build();
        List<Keys> shareKeys = dealer.generateThresholdKeys(threshold, parties);
        List<LightPHE> shareholders = new ArrayList<>();
        for (Keys keys : shareKeys) {
            shareholders.add(LightPHE.builder().algorithmName(algorithmName).keys(keys).build());
        }
        return new Committee(dealer, shareholders);
    }

    static Committee build(String algorithmName, Integer keySize) {
        return build(algorithmName, keySize, THRESHOLD, PARTIES);
    }

    static List<PartialDecryption> partials(List<LightPHE> shareholders, Ciphertext c) {
        return shareholders.stream().map(shareholder -> shareholder.partialDecrypt(c)).toList();
    }

    /** Every subset of the given size of the items, in order. */
    static <T> List<List<T>> combinations(List<T> items, int size) {
        List<List<T>> result = new ArrayList<>();
        combine(items, size, 0, new ArrayList<>(), result);
        return result;
    }

    private static <T> void combine(
            List<T> items, int size, int start, List<T> current, List<List<T>> result) {
        if (current.size() == size) {
            result.add(List.copyOf(current));
            return;
        }
        for (int i = start; i < items.size(); i++) {
            current.add(items.get(i));
            combine(items, size, i + 1, current, result);
            current.remove(current.size() - 1);
        }
    }

    @ParameterizedTest(name = "{0}")
    @CsvSource(
            value = {
                "Exponential-ElGamal, 50",
                "EllipticCurve-ElGamal, null",
                "Paillier, 50",
                "Damgard-Jurik, 50"
            },
            nullValues = "null")
    @DisplayName("Any threshold many shareholders decrypt sums and scalar products")
    void testAdditiveThresholdDecryption(String algorithmName, Integer keySize) {
        Committee committee = build(algorithmName, keySize);
        LightPHE dealer = committee.dealer();

        long m1 = 17;
        long m2 = 21;
        long k = 3;
        Ciphertext c1 = dealer.encrypt(m1);
        Ciphertext c2 = dealer.encrypt(m2);

        // homomorphic operations before threshold decryption
        List<Ciphertext> ciphertexts = List.of(c1, c1.add(c2), c1.multiply(k));
        List<Long> expectations = List.of(m1, m1 + m2, m1 * k);
        for (int i = 0; i < ciphertexts.size(); i++) {
            Ciphertext c = ciphertexts.get(i);
            BigInteger expected = BigInteger.valueOf(expectations.get(i));
            List<PartialDecryption> partials = partials(committee.shareholders(), c);

            // any threshold many shareholders can decrypt
            for (List<PartialDecryption> subset : combinations(partials, THRESHOLD)) {
                assertThat(dealer.combinePartialDecryptions(c, subset)).isEqualTo(expected);
            }

            // more than threshold many partial decryptions are fine as well
            assertThat(dealer.combinePartialDecryptions(c, partials)).isEqualTo(expected);

            // less than threshold many partial decryptions are rejected
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(
                            () ->
                                    dealer.combinePartialDecryptions(
                                            c, partials.subList(0, THRESHOLD - 1)))
                    .withMessageContaining("At least");
        }

        // regenerated ciphertexts are decrypted as well
        Ciphertext c3 = dealer.regenerateCiphertext(c1);
        List<PartialDecryption> partials =
                partials(committee.shareholders().subList(0, THRESHOLD), c3);
        assertThat(dealer.combinePartialDecryptions(c3, partials))
                .isEqualTo(BigInteger.valueOf(m1));
    }

    @Test
    @DisplayName("Threshold decryption of multiplicative ElGamal restores products")
    void testMultiplicativeElGamalThresholdDecryption() {
        Committee committee = build("ElGamal", 50);
        LightPHE dealer = committee.dealer();
        Ciphertext c = dealer.encrypt(17).multiply(dealer.encrypt(21));

        List<PartialDecryption> partials = partials(committee.shareholders(), c);
        for (List<PartialDecryption> subset : combinations(partials, THRESHOLD)) {
            assertThat(dealer.combinePartialDecryptions(c, subset))
                    .isEqualTo(BigInteger.valueOf(17 * 21));
        }
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"Paillier", "Damgard-Jurik"})
    @DisplayName("Negative and float values are restored as decrypt does")
    void testNegativeAndFloatValues(String algorithmName) {
        Committee committee = build(algorithmName, 50);
        LightPHE dealer = committee.dealer();
        BigInteger modulo = dealer.cs().plaintextModulo();
        List<LightPHE> shareholders = committee.shareholders().subList(0, THRESHOLD);

        Ciphertext c = dealer.encrypt(-5L);
        assertThat(dealer.combinePartialDecryptions(c, partials(shareholders, c)))
                .isEqualTo(modulo.subtract(BigInteger.valueOf(5)));

        // float is restored as dividend * divisor^-1 mod modulo, same as decrypt
        Ciphertext f = dealer.encrypt(1.5);
        assertThat(dealer.combinePartialDecryptions(f, partials(shareholders, f)))
                .isEqualTo(
                        BigInteger.valueOf(15)
                                .multiply(BigInteger.TEN.modInverse(modulo))
                                .mod(modulo));
    }

    @Test
    @DisplayName("Encrypted tensors are restored from partial decryptions")
    void testTensors() {
        Committee committee = build("Paillier", 128);
        LightPHE dealer = committee.dealer();

        List<Number> tensor = List.of(1.005, 2.05, -3.5, 4, 0);
        EncryptedTensor encrypted = dealer.encryptTensor(tensor);

        List<List<FractionPartialDecryption>> partials = new ArrayList<>();
        for (LightPHE shareholder : committee.shareholders().subList(1, 4)) {
            partials.add(shareholder.partialDecryptTensor(encrypted, false));
        }
        List<Double> restored = dealer.combineTensorPartialDecryptions(encrypted, partials, false);
        for (int i = 0; i < tensor.size(); i++) {
            assertThat(restored.get(i)).isCloseTo(tensor.get(i).doubleValue(), within(1e-3));
        }
    }

    @Test
    @DisplayName("Dealer drops the private key, and anyone combines with the public key")
    void testPrivateKeyIsDroppedAndPublicKeyIsShared(@TempDir Path tmp) {
        Committee committee = build("Paillier", 50);
        LightPHE dealer = committee.dealer();

        // dealer forgets the private key
        assertThat(dealer.cs().keys().hasPrivateKey()).isFalse();
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> dealer.decrypt(dealer.encrypt(1)))
                .withMessageContaining("private key");

        // shareholders cannot decrypt alone, and do not have the private key
        Ciphertext c = dealer.encrypt(42);
        for (LightPHE shareholder : committee.shareholders()) {
            assertThat(shareholder.cs().keys().hasPrivateKey()).isFalse();
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> shareholder.decrypt(c))
                    .withMessageContaining("private key");
        }

        // dealer cannot generate threshold keys again
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> dealer.generateThresholdKeys(THRESHOLD, PARTIES))
                .withMessageContaining("private key");

        // anyone having the exported public key can combine partial decryptions
        Path publicFile = tmp.resolve("public.json");
        dealer.exportKeys(publicFile, true);
        LightPHE publicCs =
                LightPHE.builder().algorithmName("Paillier").keyFile(publicFile).build();
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> publicCs.partialDecrypt(c))
                .withMessageContaining("threshold key");

        // keys of shareholders survive exporting and restoring
        Path shareFile = tmp.resolve("share.json");
        committee.shareholders().get(0).exportKeys(shareFile);
        LightPHE restored = LightPHE.builder().algorithmName("Paillier").keyFile(shareFile).build();
        List<PartialDecryption> partials = new ArrayList<>();
        partials.add(restored.partialDecrypt(c));
        partials.addAll(partials(committee.shareholders().subList(1, THRESHOLD), c));
        assertThat(publicCs.combinePartialDecryptions(c, partials))
                .isEqualTo(BigInteger.valueOf(42));
    }

    @Test
    @DisplayName("Duplicate, conflicting and unknown partial decryptions are rejected")
    void testInvalidInputs() {
        Committee committee = build("Paillier", 50);
        LightPHE dealer = committee.dealer();
        Ciphertext c = dealer.encrypt(7);
        List<PartialDecryption> partials = partials(committee.shareholders(), c);

        // same party counted once
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                dealer.combinePartialDecryptions(
                                        c,
                                        List.of(partials.get(0), partials.get(0), partials.get(0))))
                .withMessageContaining("distinct");

        // conflicting partial decryptions of same party
        PartialDecryption forged =
                partials.get(0)
                        .withValue(
                                IntValue.of(
                                        ((IntValue) partials.get(0).value())
                                                .value()
                                                .add(BigInteger.ONE)));
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                dealer.combinePartialDecryptions(
                                        c, List.of(partials.get(0), forged, partials.get(1))))
                .withMessageContaining("Conflicting");

        // unknown party
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                dealer.combinePartialDecryptions(
                                        c,
                                        List.of(
                                                partials.get(0),
                                                partials.get(1),
                                                new PartialDecryption(
                                                        PARTIES + 1, IntValue.of(1)))))
                .withMessageContaining("Index");

        for (int[] scheme : new int[][] {{0, 5}, {6, 5}}) {
            LightPHE cs = LightPHE.builder().algorithmName("Paillier").keySize(50).build();
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> cs.generateThresholdKeys(scheme[0], scheme[1]));
        }
    }

    @Test
    @DisplayName("Threshold of one and threshold of all parties work")
    void testThresholdOfOneAndAllParties() {
        for (int[] scheme : new int[][] {{1, 3}, {3, 3}}) {
            Committee committee = build("Exponential-ElGamal", 50, scheme[0], scheme[1]);
            Ciphertext c = committee.dealer().encrypt(10);
            List<PartialDecryption> partials = partials(committee.shareholders(), c);
            assertThat(
                            committee
                                    .dealer()
                                    .combinePartialDecryptions(c, partials.subList(0, scheme[0])))
                    .isEqualTo(BigInteger.TEN);
        }
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"ElGamal", "Exponential-ElGamal"})
    @DisplayName("ElGamal keys without a prime order generator are rejected")
    void testElGamalKeysWithoutPrimeOrderAreRejected(String algorithmName) {
        // default key generation is unchanged and does not have q
        LightPHE cs = LightPHE.builder().algorithmName(algorithmName).keySize(50).build();
        assertThat(cs.cs().keys().publicKey()).doesNotContainKey("q");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.generateThresholdKeys(THRESHOLD, PARTIES))
                .withMessageContaining("primeOrder = true");

        // private key is kept if threshold keys cannot be generated
        assertThat(cs.decrypt(cs.encrypt(2))).isEqualTo(BigInteger.TWO);
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"ElGamal", "Exponential-ElGamal"})
    @DisplayName("Prime order ElGamal keys have a generator of order q")
    void testPrimeOrderElGamalKeys(String algorithmName) {
        LightPHE cs =
                LightPHE.builder()
                        .algorithmName(algorithmName)
                        .keySize(50)
                        .primeOrder(true)
                        .build();
        Keys keys = cs.cs().keys();
        BigInteger p = keys.publicNumber("p");
        BigInteger g = keys.publicNumber("g");
        BigInteger q = keys.publicNumber("q");
        assertThat(p.subtract(BigInteger.ONE).mod(q)).isZero();
        assertThat(g).isNotEqualTo(BigInteger.ONE);
        assertThat(g.modPow(q, p)).isEqualTo(BigInteger.ONE);

        // classic usage works with prime order keys as well
        Ciphertext c1 = cs.encrypt(17);
        Ciphertext c2 = cs.encrypt(21);
        if ("ElGamal".equals(algorithmName)) {
            assertThat(cs.decrypt(c1.multiply(c2))).isEqualTo(BigInteger.valueOf(17 * 21));
        } else {
            assertThat(cs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(17 + 21));
            assertThat(cs.decrypt(c1.multiply(3))).isEqualTo(BigInteger.valueOf(17 * 3));
        }
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"RSA", "Okamoto-Uchiyama", "Goldwasser-Micali"})
    @DisplayName("Algorithms without threshold decryption report it")
    void testUnsupportedAlgorithms(String algorithmName) {
        LightPHE cs = LightPHE.builder().algorithmName(algorithmName).keySize(50).build();
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.generateThresholdKeys(THRESHOLD, PARTIES))
                .withMessageContaining("does not support threshold decryption");
    }
}
