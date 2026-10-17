package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.serengil.lightphe.cryptosystems.FreemanBonehGohNissim;
import io.github.serengil.lightphe.ecc.CurvePoint;
import io.github.serengil.lightphe.ecc.LightECC;
import io.github.serengil.lightphe.model.Ciphertext;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Port of {@code tests/test_freemanbonehgohnissim.py}. */
class FreemanBonehGohNissimTest {

    private static final String ALGORITHM = "Freeman-Boneh-Goh-Nissim";

    private static final LightPHE cs =
            LightPHE.builder().algorithmName(ALGORITHM).keySize(64).build();

    private static LightPHE build(int keySize, BigInteger plaintextLimit) {
        return LightPHE.builder()
                .algorithmName(ALGORITHM)
                .keySize(keySize)
                .plaintextLimit(plaintextLimit)
                .build();
    }

    @Test
    @DisplayName("Freeman-Boneh-Goh-Nissim supports addition, one multiplication and constants")
    void testApi() {
        BigInteger modulo = cs.cs().plaintextModulo();

        long m1 = 17;
        long m2 = 21;

        Ciphertext c1 = cs.encrypt(m1);
        Ciphertext c2 = cs.encrypt(m2);

        // proof of decryption
        assertThat(cs.decrypt(c1)).isEqualTo(BigInteger.valueOf(m1));
        assertThat(cs.decrypt(c2)).isEqualTo(BigInteger.valueOf(m2));

        // homomorphic addition
        assertThat(cs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(m1 + m2));

        // homomorphic multiplication
        assertThat(cs.decrypt(c1.multiply(c2))).isEqualTo(BigInteger.valueOf(m1 * m2));

        // homomorphic scalar multiplication
        assertThat(cs.decrypt(c1.multiply(m2))).isEqualTo(BigInteger.valueOf(m1 * m2));

        // negative plaintexts
        Ciphertext c3 = cs.encrypt(-5L);
        assertThat(cs.decrypt(c3)).isEqualTo(modulo.subtract(BigInteger.valueOf(5)));
        assertThat(cs.decrypt(c1.add(c3))).isEqualTo(BigInteger.valueOf(m1 - 5));
        assertThat(cs.decrypt(c1.multiply(c3)))
                .isEqualTo(modulo.subtract(BigInteger.valueOf(5 * m1)));

        // re-randomization
        Ciphertext c1Prime = cs.regenerateCiphertext(c1);
        assertThat(c1Prime.value()).isNotEqualTo(c1.value());
        assertThat(cs.decrypt(c1Prime)).isEqualTo(BigInteger.valueOf(m1));

        // unsupported homomorphic operations
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.xor(c2));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.and(c2));
    }

    @Test
    @DisplayName("Freeman-Boneh-Goh-Nissim keys are well formed")
    void testKeysAreWellFormed() {
        FreemanBonehGohNissim scheme = (FreemanBonehGohNissim) cs.cs();
        BigInteger p = scheme.keys().publicNumber("p");
        BigInteger r = scheme.keys().publicNumber("r");
        List<BigInteger> v = scheme.keys().privateNumbers("v");
        LightECC ec = scheme.ec();

        // p + 1 points on y^2 = x^3 + x, and the generator has prime order r
        assertThat(p.mod(BigInteger.valueOf(4))).isEqualTo(BigInteger.valueOf(3));
        assertThat(p.add(BigInteger.ONE).mod(r)).isEqualTo(BigInteger.ZERO);
        assertThat(ec.g().multiply(r.subtract(BigInteger.ONE)).add(ec.g())).isEqualTo(ec.o());

        // projection v vanishes on h1 and h2, but not on g
        assertThat(project(ec, scheme.keys().publicMatrix("h1"), v)).isEqualTo(ec.o());
        assertThat(project(ec, scheme.keys().publicMatrix("h2"), v)).isEqualTo(ec.o());
        assertThat(project(ec, scheme.keys().publicMatrix("g"), v)).isNotEqualTo(ec.o());
    }

    private static CurvePoint project(
            LightECC ec, List<List<BigInteger>> points, List<BigInteger> v) {
        CurvePoint result = ec.o();
        for (int i = 0; i < points.size(); i++) {
            CurvePoint point = ec.point(points.get(i).get(0), points.get(i).get(1));
            result = result.add(point.multiply(v.get(i)));
        }
        return result;
    }

    @Test
    @DisplayName("Freeman-Boneh-Goh-Nissim evaluates degree-2 functions")
    void testDegree2Functions() {
        BigInteger modulo = cs.cs().plaintextModulo();
        Random random = new Random();
        for (int round = 0; round < 20; round++) {
            long x = random.nextInt(201) - 100;
            long y = random.nextInt(201) - 100;
            long z = random.nextInt(201) - 100;
            long k = random.nextInt(41) - 20;
            Ciphertext cx = cs.encrypt(x);
            Ciphertext cy = cs.encrypt(y);
            Ciphertext cz = cs.encrypt(z);

            assertThat(cs.decrypt(cx.multiply(cx))).isEqualTo(mod(x * x, modulo));
            assertThat(cs.decrypt(cx.add(cy).multiply(cz))).isEqualTo(mod((x + y) * z, modulo));

            // multiplied ciphertexts can be added with each other and with fresh ciphertexts
            assertThat(cs.decrypt(cx.multiply(cy).add(cz.multiply(cz))))
                    .isEqualTo(mod(x * y + z * z, modulo));
            assertThat(cs.decrypt(cx.multiply(cy).add(cz))).isEqualTo(mod(x * y + z, modulo));
            assertThat(cs.decrypt(cz.add(cx.multiply(cy)))).isEqualTo(mod(z + x * y, modulo));

            // constants before and after multiplication, including zero
            assertThat(cs.decrypt(cx.multiply(k).multiply(cy))).isEqualTo(mod(k * x * y, modulo));
            assertThat(cs.decrypt(cx.multiply(cy).multiply(k))).isEqualTo(mod(k * x * y, modulo));
            assertThat(cs.decrypt(cx.multiply(0L))).isEqualTo(BigInteger.ZERO);
        }
    }

    private static BigInteger mod(long value, BigInteger modulo) {
        return BigInteger.valueOf(value).mod(modulo);
    }

    @Test
    @DisplayName("Freeman-Boneh-Goh-Nissim supports only one multiplication")
    void testOnlyOneMultiplication() {
        Ciphertext c1 = cs.encrypt(2);
        Ciphertext c2 = cs.encrypt(3);
        Ciphertext c3 = cs.encrypt(4);
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> c1.multiply(c2).multiply(c3))
                .withMessageContaining("only one multiplication");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> c1.multiply(c2.multiply(c3)))
                .withMessageContaining("only one multiplication");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.regenerateCiphertext(c1.multiply(c2)))
                .withMessageContaining("non-multiplied ciphertexts only");
    }

    @Test
    @DisplayName("Freeman-Boneh-Goh-Nissim restores results within the plaintext limit only")
    void testPlaintextLimit() {
        assertThat(cs.cs().keys().publicNumber("limit")).isEqualTo(BigInteger.TWO.pow(20));

        LightPHE smallCs = build(64, BigInteger.valueOf(100));
        assertThat(smallCs.decrypt(smallCs.encrypt(100))).isEqualTo(BigInteger.valueOf(100));
        assertThat(smallCs.decrypt(smallCs.encrypt(-100)))
                .isEqualTo(smallCs.cs().plaintextModulo().subtract(BigInteger.valueOf(100)));
        assertThat(smallCs.decrypt(smallCs.encrypt(10).multiply(smallCs.encrypt(10))))
                .isEqualTo(BigInteger.valueOf(100));

        // results out of the limit cannot be restored
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> smallCs.decrypt(smallCs.encrypt(101)))
                .withMessageContaining("out of");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () -> smallCs.decrypt(smallCs.encrypt(11).multiply(smallCs.encrypt(10))))
                .withMessageContaining("out of");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> build(64, BigInteger.TWO.pow(40)))
                .withMessageContaining("too large");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> build(16, null))
                .withMessageContaining("too small");
    }

    @Test
    @DisplayName("Freeman-Boneh-Goh-Nissim does not support floats and tensors")
    void testFloatsAndTensorsAreNotSupported() {
        Ciphertext c = cs.encrypt(5);
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.encrypt(1.5))
                .withMessageContaining("Freeman-Boneh-Goh-Nissim does not support float");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.encryptTensor(List.of(1, 2, 3)))
                .withMessageContaining("Freeman-Boneh-Goh-Nissim does not support float");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> c.multiply(1.5))
                .withMessageContaining("Freeman-Boneh-Goh-Nissim does not support float");
    }

    @Test
    @DisplayName("Freeman-Boneh-Goh-Nissim does not need the Catalano-Fiore transform")
    void testCatalanoFioreIsNotNeeded() {
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(
                        () ->
                                LightPHE.builder()
                                        .algorithmName(ALGORITHM)
                                        .keys(cs.cs().keys())
                                        .boost("Catalano-Fiore")
                                        .build())
                .withMessageContaining("already supports one multiplication");
    }

    @Test
    @DisplayName("Freeman-Boneh-Goh-Nissim works with predefined keys")
    void testApiWithPredefinedKeys() {
        LightPHE restoredCs =
                LightPHE.builder().algorithmName(ALGORITHM).keys(cs.cs().keys()).build();
        Ciphertext c1 = cs.encrypt(11);
        Ciphertext c2 = restoredCs.encrypt(7);
        assertThat(restoredCs.decrypt(c1.multiply(c2))).isEqualTo(BigInteger.valueOf(77));
        assertThat(cs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(18));
    }

    @Test
    @DisplayName("Freeman-Boneh-Goh-Nissim multiplies with the public key only")
    void testExportedKeys(@TempDir Path tempDir) {
        Path publicKeyFile = tempDir.resolve("public.txt");
        cs.exportKeys(publicKeyFile, true);

        // multiplication requires the public key only
        LightPHE publicCs =
                LightPHE.builder().algorithmName(ALGORITHM).keyFile(publicKeyFile).build();
        Ciphertext c = publicCs.encrypt(42).multiply(publicCs.encrypt(2)).add(publicCs.encrypt(1));
        assertThat(cs.decrypt(c)).isEqualTo(BigInteger.valueOf(85));

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> publicCs.decrypt(c))
                .withMessageContaining("private key");
    }

    @Test
    @DisplayName("Freeman-Boneh-Goh-Nissim works with 1024-bit keys")
    void testLargeKeys() {
        LightPHE largeCs = build(1024, null);
        assertThat(largeCs.cs().keys().publicNumber("r").bitLength()).isEqualTo(256);

        BigInteger modulo = largeCs.cs().plaintextModulo();
        Ciphertext c1 = largeCs.encrypt(123);
        Ciphertext c2 = largeCs.encrypt(-456L);
        assertThat(largeCs.decrypt(c1.add(c2))).isEqualTo(modulo.subtract(BigInteger.valueOf(333)));
        assertThat(largeCs.decrypt(c1.multiply(c2).add(c1)))
                .isEqualTo(
                        modulo.subtract(BigInteger.valueOf(123 * 456))
                                .add(BigInteger.valueOf(123)));
    }
}
