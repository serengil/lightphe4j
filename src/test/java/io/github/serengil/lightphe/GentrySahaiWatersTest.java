package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.serengil.lightphe.model.Ciphertext;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Port of {@code tests/test_gentrysahaiwaters.py}. Structure of keys, the gadget decomposition and
 * the noise of large keys are tested in {@code cryptosystems.LatticeInternalsTest}.
 */
class GentrySahaiWatersTest {

    private static final String ALGORITHM = "Gentry-Sahai-Waters";

    private static final LightPHE cs =
            LightPHE.builder().algorithmName(ALGORITHM).keySize(64).build();

    private static int decrypt(Ciphertext c) {
        return cs.decrypt(c).intValueExact();
    }

    @Test
    @DisplayName("Truth tables of and, multiplication and exclusive or")
    void testTruthTables() {
        for (int a = 0; a < 2; a++) {
            for (int b = 0; b < 2; b++) {
                Ciphertext ca = cs.encrypt(a);
                Ciphertext cb = cs.encrypt(b);
                assertThat(decrypt(ca)).isEqualTo(a);
                assertThat(decrypt(ca.and(cb))).isEqualTo(a & b);
                assertThat(decrypt(ca.multiply(cb))).isEqualTo(a * b);
                assertThat(decrypt(ca.xor(cb))).isEqualTo(a ^ b);
            }
        }

        // not is exclusive or with 1
        Ciphertext one = cs.encrypt(1);
        assertThat(decrypt(cs.encrypt(0).xor(one))).isEqualTo(1);
        assertThat(decrypt(cs.encrypt(1).xor(one))).isZero();

        // re-randomization
        Ciphertext c = cs.encrypt(1);
        Ciphertext cPrime = cs.regenerateCiphertext(c);
        assertThat(cPrime.value()).isNotEqualTo(c.value());
        assertThat(decrypt(cPrime)).isEqualTo(1);

        // unsupported homomorphic operations
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c.add(cPrime));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c.multiply(3));
    }

    @Test
    @DisplayName("Circuits of multiplicative depth 2 work")
    void testCircuitsOfDepthTwo() {
        for (int bits = 0; bits < 16; bits++) {
            int a = bits & 1;
            int b = (bits >> 1) & 1;
            int c = (bits >> 2) & 1;
            int d = (bits >> 3) & 1;
            Ciphertext ca = cs.encrypt(a);
            Ciphertext cb = cs.encrypt(b);
            Ciphertext cc = cs.encrypt(c);
            Ciphertext cd = cs.encrypt(d);
            // product of products
            assertThat(decrypt(ca.and(cb).and(cc.and(cd)))).isEqualTo(a & b & c & d);
            // majority of three
            Ciphertext majority = ca.and(cb).xor(ca.and(cc)).xor(cb.and(cc));
            assertThat(decrypt(majority)).isEqualTo(a + b + c >= 2 ? 1 : 0);
            // exclusive or of products, and product of exclusive ors
            assertThat(decrypt(ca.and(cb).xor(cc.and(cd)))).isEqualTo((a & b) ^ (c & d));
            assertThat(decrypt(ca.xor(cb).and(cc.xor(cd)))).isEqualTo((a ^ b) & (c ^ d));
        }
    }

    @Test
    @DisplayName("Long chains of ands with fresh ciphertexts work")
    void testLongChainOfAnds() {
        List<Integer> ones = new ArrayList<>();
        for (int i = 0; i < 40; i++) {
            ones.add(1);
        }
        List<Integer> withZero = new ArrayList<>(ones);
        withZero.set(20, 0);

        // acc = acc & fresh adds a fixed noise each time
        for (List<Integer> bits : List.of(ones, withZero)) {
            Ciphertext acc = cs.encrypt(bits.get(0));
            for (int bit : bits.subList(1, bits.size())) {
                acc = acc.and(cs.encrypt(bit));
            }
            assertThat(decrypt(acc)).isEqualTo(bits.stream().mapToInt(x -> x).min().getAsInt());
        }
    }

    @Test
    @DisplayName("A ripple carry adder adds two encrypted 8-bit integers")
    void testRippleCarryAdder() {
        Random random = new Random(0);
        for (int round = 0; round < 3; round++) {
            int x = random.nextInt(256);
            int y = random.nextInt(256);
            List<Ciphertext> xBits = new ArrayList<>();
            List<Ciphertext> yBits = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                xBits.add(cs.encrypt((x >> i) & 1));
                yBits.add(cs.encrypt((y >> i) & 1));
            }

            Ciphertext carry = cs.encrypt(0);
            List<Ciphertext> resultBits = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                Ciphertext a = xBits.get(i);
                Ciphertext b = yBits.get(i);
                Ciphertext half = a.xor(b);
                resultBits.add(half.xor(carry));
                // carry = a & b ^ carry & (a ^ b)
                carry = a.and(b).xor(carry.and(half));
            }
            resultBits.add(carry);

            int result = 0;
            for (int i = 0; i < resultBits.size(); i++) {
                result |= decrypt(resultBits.get(i)) << i;
            }
            assertThat(result).isEqualTo(x + y);
        }
    }

    @Test
    @DisplayName("Integers other than bits, floats and tensors are rejected")
    void testInvalidInputs() {
        for (long plaintext : new long[] {2, -1}) {
            assertThatExceptionOfType(IllegalArgumentException.class)
                    .isThrownBy(() -> cs.encrypt(plaintext))
                    .withMessageContaining("encrypts bits");
        }
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.encrypt(1.5))
                .withMessageContaining("encrypts bits");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.encryptTensor(List.of(0, 1)))
                .withMessageContaining("encrypts bits");
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.encrypt(1).multiply(1.5))
                .withMessageContaining("encrypts bits");
    }

    @ParameterizedTest
    @ValueSource(ints = {4, 48, 100})
    @DisplayName("Ring degree must be a power of 2")
    void testRingDegreeMustBePowerOfTwo(int keySize) {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () -> LightPHE.builder().algorithmName(ALGORITHM).keySize(keySize).build())
                .withMessageContaining("must be a power of 2");
    }

    @Test
    @DisplayName("Exported public key evaluates ands but cannot decrypt")
    void testExportedKeys(@TempDir Path tmp) {
        Path publicFile = tmp.resolve("public.txt");
        cs.exportKeys(publicFile, true);

        LightPHE publicCs = LightPHE.builder().algorithmName(ALGORITHM).keyFile(publicFile).build();
        Ciphertext c = publicCs.encrypt(1).and(publicCs.encrypt(1));
        assertThat(cs.decrypt(c)).isEqualTo(BigInteger.ONE);

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> publicCs.decrypt(c))
                .withMessageContaining("private key");
    }
}
