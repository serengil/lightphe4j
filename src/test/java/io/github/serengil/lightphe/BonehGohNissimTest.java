package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.serengil.lightphe.model.Ciphertext;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.KeysCodec;
import io.github.serengil.lightphe.model.value.CipherValue;
import java.math.BigInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Port of {@code tests/test_bonehgohnissim.py}. */
class BonehGohNissimTest {

    private static final LightPHE cs =
            LightPHE.builder()
                    .algorithmName("Boneh-Goh-Nissim")
                    .keySize(50)
                    .maxTries(10000)
                    .build();

    private static BigInteger big(long value) {
        return BigInteger.valueOf(value);
    }

    @Test
    @DisplayName("Boneh-Goh-Nissim adds freely and multiplies once")
    void testApi() {
        long m1 = 83;
        long m2 = 31;

        Ciphertext c1 = cs.encrypt(m1);
        Ciphertext c2 = cs.encrypt(m2);

        // proof of decryption
        assertThat(cs.decrypt(c1)).isEqualTo(big(m1));
        assertThat(cs.decrypt(c2)).isEqualTo(big(m2));

        BigInteger modulo = cs.cs().plaintextModulo();

        // homomorphic addition
        assertThat(cs.decrypt(c1.add(c2))).isEqualTo(big(m1 + m2).mod(modulo));

        // homomorphic multiplication, once
        Ciphertext product = c1.multiply(c2);
        assertThat(cs.decrypt(product)).isEqualTo(big(m1 * m2).mod(modulo));

        // scalar multiplication
        long k = 2;
        assertThat(cs.decrypt(c1.multiply(k))).isEqualTo(big(m1 * k).mod(modulo));

        // unsupported homomorphic operations
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> product.multiply(c2))
                .withMessageContaining(
                        "Boneh-Goh-Nissim only supports multiplication ciphertexts once!");

        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.and(c2));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.xor(c2));

        // re-randomization
        CipherValue c1Prime = cs.cs().reencrypt(c1.value());
        CipherValue c2Prime = cs.cs().reencrypt(c2.value());
        assertThat(cs.cs().decrypt(c1Prime)).isEqualTo(big(m1));
        assertThat(cs.cs().decrypt(c2Prime)).isEqualTo(big(m2));
    }

    @Test
    @DisplayName("Boneh-Goh-Nissim evaluates a linear regression on ciphertexts")
    void testLinearRegression() {
        long x1 = 5;
        long w1 = 7;
        long x2 = 3;
        long w2 = 4;

        Ciphertext x1Enc = cs.encrypt(x1);
        Ciphertext w1Enc = cs.encrypt(w1);
        Ciphertext x2Enc = cs.encrypt(x2);
        Ciphertext w2Enc = cs.encrypt(w2);

        Ciphertext x1w1Enc = x1Enc.multiply(w1Enc);
        Ciphertext x2w2Enc = x2Enc.multiply(w2Enc);

        Ciphertext sumEnc = x1w1Enc.add(x2w2Enc);
        assertThat(cs.decrypt(sumEnc)).isEqualTo(big(x1 * w1 + x2 * w2));

        // multiplication by a constant
        assertThat(cs.decrypt(x1w1Enc.multiply(5L))).isEqualTo(big(5 * x1 * w1));

        // unsupported homomorphic operations
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> x1w1Enc.multiply(w2Enc))
                .withMessageContaining(
                        "Boneh-Goh-Nissim only supports multiplication ciphertexts once!");
    }

    @Test
    @DisplayName("Boneh-Goh-Nissim computes a cosine similarity numerator on ciphertexts")
    void testCosineSimilarity() {
        long i1 = 5;
        long i2 = 2;
        long i3 = 8;

        // v2 = [1, 1, 2]
        long j1 = 1;
        long j2 = 1;
        long j3 = 2;

        Ciphertext i1Enc = cs.encrypt(i1);
        Ciphertext i2Enc = cs.encrypt(i2);
        Ciphertext i3Enc = cs.encrypt(i3);

        Ciphertext j1Enc = cs.encrypt(j1);
        Ciphertext j2Enc = cs.encrypt(j2);
        Ciphertext j3Enc = cs.encrypt(j3);

        // homomorphic operation
        Ciphertext cosineSimEnc =
                i1Enc.multiply(j1Enc).add(i2Enc.multiply(j2Enc)).add(i3Enc.multiply(j3Enc));

        // proof of work
        assertThat(cs.decrypt(cosineSimEnc)).isEqualTo(big(i1 * j1 + i2 * j2 + i3 * j3));
    }

    @Test
    @DisplayName("Boneh-Goh-Nissim computes a squared euclidean distance on ciphertexts")
    void testEuclideanDistance() {
        // v1 = [5, 2, 8]
        long i1 = 5;
        long i2 = 2;
        long i3 = 8;

        // v2 = [1, 1, 2]
        long j1 = 1;
        long j2 = 1;
        long j3 = 2;

        Ciphertext i1Enc = cs.encrypt(i1);
        Ciphertext i2Enc = cs.encrypt(i2);
        Ciphertext i3Enc = cs.encrypt(i3);

        Ciphertext j1Enc = cs.encrypt(-j1);
        Ciphertext j2Enc = cs.encrypt(-j2);
        Ciphertext j3Enc = cs.encrypt(-j3);

        Ciphertext d1 = i1Enc.add(j1Enc);
        Ciphertext d2 = i2Enc.add(j2Enc);
        Ciphertext d3 = i3Enc.add(j3Enc);

        Ciphertext euclideanSquaredEnc = d1.multiply(d1).add(d2.multiply(d2)).add(d3.multiply(d3));

        long expected = (i1 - j1) * (i1 - j1) + (i2 - j2) * (i2 - j2) + (i3 - j3) * (i3 - j3);
        assertThat(cs.decrypt(euclideanSquaredEnc)).isEqualTo(big(expected));
    }

    @Test
    @DisplayName("Boneh-Goh-Nissim works with pre-defined keys")
    void testApiWithPredefinedKeys() {
        String json =
                """
                {
                  "private_key": {"q1": 1260048562698661, "q2": 1495813357973021},
                  "public_key": {
                    "curve": {
                      "a": 1,
                      "b": 0,
                      "p": 1477681217875020437035023206706703,
                      "G": [404050258967758769169929337984186, 548422986186523785500578682099939],
                      "n": 1884797471779362802340590824881
                    },
                    "G": [404050258967758769169929337984186, 548422986186523785500578682099939],
                    "u": [496699107331579016081758964967239, 1209427529257066171815901459972102],
                    "h": [557434130026147587760748115479880, 109859910481881270030204038710204],
                    "l": 784
                  }
                }
                """;

        Keys keys = KeysCodec.fromJson(json);
        LightPHE bgn = LightPHE.builder().algorithmName("Boneh-Goh-Nissim").keys(keys).build();

        long m1 = 3;
        long m2 = 2;

        Ciphertext c1 = bgn.encrypt(m1);
        Ciphertext c2 = bgn.encrypt(m2);

        // proof of decryption
        assertThat(bgn.decrypt(c1)).isEqualTo(big(m1));
        assertThat(bgn.decrypt(c2)).isEqualTo(big(m2));

        BigInteger modulo = bgn.cs().plaintextModulo();

        // homomorphic addition
        assertThat(bgn.decrypt(c1.add(c2))).isEqualTo(big(m1 + m2).mod(modulo));

        // homomorphic multiplication
        Ciphertext product = c1.multiply(c2);
        assertThat(bgn.decrypt(product)).isEqualTo(big(m1 * m2).mod(modulo));

        // scalar multiplication
        long k = 2;
        assertThat(bgn.decrypt(c1.multiply(k))).isEqualTo(big(m1 * k).mod(modulo));

        // unsupported homomorphic operations
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.and(c2));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.xor(c2));

        // re-randomization
        CipherValue c1Prime = bgn.cs().reencrypt(c1.value());
        CipherValue c2Prime = bgn.cs().reencrypt(c2.value());
        assertThat(bgn.cs().decrypt(c1Prime)).isEqualTo(big(m1));
        assertThat(bgn.cs().decrypt(c2Prime)).isEqualTo(big(m2));
    }
}
