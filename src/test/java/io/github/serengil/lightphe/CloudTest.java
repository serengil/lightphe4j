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

/** Port of {@code tests/test_cloud.py}. */
class CloudTest {

    /** Pre-generated 20-bit RSA keys. */
    private static final String PRIVATE =
            "{\"private_key\": {\"d\": 30365}, \"public_key\": {\"n\": 175501, \"e\": 101753}}";

    private static final String PUBLIC = "{\"public_key\": {\"n\": 175501, \"e\": 101753}}";

    @Test
    @DisplayName("A cloud holding only the public key can still evaluate a product")
    void testEncryption() {
        Keys publicKeys = KeysCodec.fromJson(PUBLIC);
        Keys privateKeys = KeysCodec.fromJson(PRIVATE);

        // we actually have both the private and the public key here, but one can encrypt messages
        // with the public key alone
        LightPHE cs = LightPHE.builder().algorithmName("RSA").keys(publicKeys).build();
        LightPHE secretCs = LightPHE.builder().algorithmName("RSA").keys(privateKeys).build();

        long m1 = 10000;
        Ciphertext c1 = cs.encrypt(m1);

        double m2 = 1.05;
        Ciphertext c2 = cs.encrypt(m2);

        assertThat(secretCs.decrypt(c1)).isEqualTo(BigInteger.valueOf(m1));

        CipherValue c3Value = homomorphicOperations(c1.value(), c2.value());
        Ciphertext c3 = cs.createCiphertextObj(c3Value);

        assertThat(secretCs.decrypt(c3)).isEqualTo(BigInteger.valueOf(10500));
    }

    /** One can perform homomorphic operations while not holding the private key. */
    private CipherValue homomorphicOperations(CipherValue c1, CipherValue c2) {
        LightPHE cs =
                LightPHE.builder().algorithmName("RSA").keys(KeysCodec.fromJson(PUBLIC)).build();

        Ciphertext c1Obj = cs.createCiphertextObj(c1);
        Ciphertext c2Obj = cs.createCiphertextObj(c2);

        // one cannot perform decryption without the private key
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.decrypt(c1Obj));
        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> cs.decrypt(c2Obj));

        // no private key needed
        return c1Obj.multiply(c2Obj).value();
    }
}
