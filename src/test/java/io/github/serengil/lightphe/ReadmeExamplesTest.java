package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

import io.github.serengil.lightphe.ecc.curves.CurveForm;
import io.github.serengil.lightphe.ecc.curves.CurveRegistry;
import io.github.serengil.lightphe.model.Ciphertext;
import io.github.serengil.lightphe.model.EncryptedTensor;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.List;
import java.util.function.DoubleBinaryOperator;
import java.util.stream.IntStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Every snippet in the README, kept honest by compiling and running it. Key sizes are reduced so
 * the suite stays fast; the code is otherwise what the documentation shows.
 */
class ReadmeExamplesTest {

    @Test
    @DisplayName("README: additively homomorphic workflow")
    void additiveWorkflow() {
        // build an additively homomorphic cryptosystem
        LightPHE cs = LightPHE.builder().algorithmName("Paillier").keySize(50).build();

        // define plaintexts
        long m1 = 10000; // base salary in usd
        long m2 = 500; // wage increase in usd

        // encrypt plaintexts - the private key is not required
        Ciphertext c1 = cs.encrypt(m1);
        Ciphertext c2 = cs.encrypt(m2);

        // homomorphic addition - the private key is not required
        Ciphertext c3 = c1.add(c2);

        // homomorphic scalar multiplication - the private key is not required
        double k = 1.05; // increase something by 5%
        Ciphertext c4 = c1.multiply(k);

        // decryption - the private key is required
        assertThat(cs.decrypt(c3)).isEqualTo(BigInteger.valueOf(m1 + m2));
        assertThat(cs.decrypt(c4)).isEqualTo(BigInteger.valueOf(10500));
    }

    @Test
    @DisplayName("README: multiplicatively homomorphic workflow and ciphertext regeneration")
    void multiplicativeWorkflow() {
        LightPHE cs = LightPHE.builder().algorithmName("ElGamal").keySize(50).build();

        long m1 = 17;
        long m2 = 21;

        Ciphertext c1 = cs.encrypt(m1);
        Ciphertext c2 = cs.encrypt(m2);

        // homomorphic multiplication
        Ciphertext c3 = c1.multiply(c2);
        assertThat(cs.decrypt(c3)).isEqualTo(BigInteger.valueOf(m1 * m2));

        // ciphertext regeneration
        Ciphertext c1Prime = cs.regenerateCiphertext(c1);
        assertThat(c1Prime.value()).isNotEqualTo(c1.value());
        assertThat(cs.decrypt(c1Prime)).isEqualTo(BigInteger.valueOf(m1));
        assertThat(cs.decrypt(c1)).isEqualTo(BigInteger.valueOf(m1));
    }

    @Test
    @DisplayName("README: elliptic curve cryptosystem and curve inventory")
    void ellipticCurveWorkflow() {
        LightPHE phe =
                LightPHE.builder().algorithmName("EllipticCurve-ElGamal").form("edwards").build();

        assertThat(phe.decrypt(phe.encrypt(10))).isEqualTo(BigInteger.TEN);

        List<String> edwardsCurves = CurveRegistry.listCurves(CurveForm.EDWARDS);
        assertThat(edwardsCurves).contains("ed25519", "ed448");

        // the README claims 141 standard curve configurations across the three forms
        int total =
                CurveRegistry.listCurves(CurveForm.WEIERSTRASS).size()
                        + CurveRegistry.listCurves(CurveForm.EDWARDS).size()
                        + CurveRegistry.listCurves(CurveForm.KOBLITZ).size();
        assertThat(total).isEqualTo(141);
    }

    @Test
    @DisplayName("README: vector embeddings")
    void vectorEmbeddings() {
        // build an additively homomorphic cryptosystem
        LightPHE cs = LightPHE.builder().algorithmName("Paillier").keySize(50).build();

        // define plain embeddings
        List<Number> t1 = List.of(1.005, 2.05, 3.6, 4, 4.02, 3.5);
        List<Number> t2 = List.of(5, 6.2, 7.5, 8.02, 8.02, 4.5);
        List<Number> t3 = List.of(1.03, 2.04, 3.05, 7.02, 2.01, 1.06);

        // encrypt embeddings
        EncryptedTensor c1 = cs.encryptTensor(t1);
        EncryptedTensor c2 = cs.encryptTensor(t2);

        // addition of two encrypted embeddings
        EncryptedTensor c4 = c1.add(c2);

        // scalar multiplication of an embedding
        EncryptedTensor c5 = c1.multiply(3);

        // element-wise multiplication of an encrypted embedding with a plain one
        EncryptedTensor c6 = c1.multiply(t3);

        // encrypted dot product, and likewise cosine similarity
        EncryptedTensor c7 = c1.matmul(t3);

        assertThat(cs.decryptTensor(c4)).hasSize(t1.size());
        assertClose(cs.decryptTensor(c4), elementWise(t1, t2, Double::sum));
        assertClose(cs.decryptTensor(c5), scale(t1, 3));
        assertClose(cs.decryptTensor(c6), elementWise(t1, t3, (a, b) -> a * b));

        double expectedDot = 0;
        for (int i = 0; i < t1.size(); i++) {
            expectedDot += t1.get(i).doubleValue() * t3.get(i).doubleValue();
        }
        assertThat(cs.decryptTensor(c7).get(0)).isCloseTo(expectedDot, within(0.1));
    }

    @Test
    @DisplayName("README: key management")
    void keyManagement(@TempDir Path tempDir) {
        Path secret = tempDir.resolve("secret.json");
        Path publicKey = tempDir.resolve("public.json");

        LightPHE onPrem = LightPHE.builder().algorithmName("Paillier").keySize(50).build();

        // export the full key pair, and a public-only copy safe to publish
        onPrem.exportKeys(secret);
        onPrem.exportKeys(publicKey, true);

        // a party holding only the public key can encrypt and evaluate, but not decrypt
        LightPHE cloud = LightPHE.builder().algorithmName("Paillier").keyFile(publicKey).build();

        Ciphertext sum = cloud.encrypt(17).add(cloud.encrypt(21));
        assertThat(cloud.cs().keys().hasPrivateKey()).isFalse();
        assertThat(onPrem.decrypt(sum)).isEqualTo(BigInteger.valueOf(38));
    }

    private static List<Double> elementWise(
            List<Number> a, List<Number> b, DoubleBinaryOperator operator) {
        return IntStream.range(0, a.size())
                .mapToObj(
                        i -> operator.applyAsDouble(a.get(i).doubleValue(), b.get(i).doubleValue()))
                .toList();
    }

    private static List<Double> scale(List<Number> a, double factor) {
        return a.stream().map(value -> value.doubleValue() * factor).toList();
    }

    private static void assertClose(List<Double> actual, List<Double> expected) {
        assertThat(actual).hasSameSizeAs(expected);
        for (int i = 0; i < actual.size(); i++) {
            assertThat(actual.get(i)).as("item %d", i).isCloseTo(expected.get(i), within(0.1));
        }
    }
}
