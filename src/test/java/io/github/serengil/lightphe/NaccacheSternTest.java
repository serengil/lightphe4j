package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import io.github.serengil.lightphe.model.Ciphertext;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.KeysCodec;
import java.math.BigInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Port of {@code tests/test_naccache.py}. */
class NaccacheSternTest {

    /**
     * Key generation for Naccache-Stern is probabilistic, may take time and may not always succeed.
     * These are the pre-generated keys the Python suite uses so that encryption, decryption and the
     * homomorphic operations can be exercised deterministically.
     */
    private static final String PREDEFINED_KEYS =
            """
            {
              "public_key": {
                "n": 75275183223356977395233015128636801841182684353869611205877871399639096259927846711964449336873721703958210179653876541687516247046310691985977881277598653839478670263258301833023097636036737220721033604997817044724812266620826468829212603338614968953684914579782761554925497589591101127424868060977977362624693729,
                "g": 2322858651861384064537514431822509724460178869240342120700966005387085547272373554253264326744794826709642720143603083090045603237528622393527254537059946505389885957837759097286992580665451178640443489482838164247603492906332153298019557819758033383394570549848334276102748452532710144646257390863266986629778942,
                "sigma": 255255
              },
              "private_key": {
                "a": 11597041531885171702428009785553891872754255798746286340205448513302430749967682685453809973100036260110796582178813477436613205882229456042479325870287379,
                "b": 6357265649357031680615244845679689252112451833267362870520093680285536565908774220658104716644696735431871010152670595233003071273441498122136618828384989,
                "p": 2435378721695886057509882054966317293278393717736720131443144187793510457493213363945300094351007614623267282257550830261688773235268185768920658432760349591,
                "q": 30909025587173888031151320439694649143770740813345918276468695473548278783448460260839705132326515527669756851362284434022860932531472563869828240743607816519,
                "phi": 75275183223356977395233015128636801841182684353869611205877871399639096259927846711964449336873721703958210179653876541687516247046310691985977881277598653806134265954388527744361895141375770783671899073915178636812972605279037227887538978553609742276161772286758627935090233305041395360684118422229078186256527620
              }
            }
            """;

    @Test
    @DisplayName("Naccache-Stern works with pre-defined keys")
    void testPredefinedKeys() {
        Keys keys = KeysCodec.fromJson(PREDEFINED_KEYS);
        LightPHE cs = LightPHE.builder().algorithmName("Naccache-Stern").keys(keys).build();

        int securityLevel = cs.cs().keys().publicNumber("n").bitLength();
        assertThat(securityLevel).isGreaterThan(768);

        long m1 = 17;
        long m2 = 21;

        Ciphertext c1 = cs.encrypt(m1);
        Ciphertext c2 = cs.encrypt(m2);

        // homomorphic addition
        assertThat(cs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(m1 + m2));

        // homomorphic scalar multiplication
        assertThat(cs.decrypt(c1.multiply(m2))).isEqualTo(BigInteger.valueOf(m1 * m2));
        assertThat(cs.decrypt(c2.multiply(m1))).isEqualTo(BigInteger.valueOf(m1 * m2));

        // unsupported homomorphic operations
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.multiply(c2));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.xor(c2));
    }

    @Test
    @DisplayName("Naccache-Stern supports homomorphic addition and scalar multiplication")
    void testApi() {
        LightPHE cs = LightPHE.builder().algorithmName("Naccache-Stern").keySize(37).build();

        long m1 = 17;
        long m2 = 21;

        Ciphertext c1 = cs.encrypt(m1);
        Ciphertext c2 = cs.encrypt(m2);

        // homomorphic addition
        assertThat(cs.decrypt(c1.add(c2))).isEqualTo(BigInteger.valueOf(m1 + m2));

        // homomorphic scalar multiplication
        assertThat(cs.decrypt(c1.multiply(m2))).isEqualTo(BigInteger.valueOf(m1 * m2));
        assertThat(cs.decrypt(c2.multiply(m1))).isEqualTo(BigInteger.valueOf(m1 * m2));

        // unsupported homomorphic operations
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.multiply(c2));
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> c1.xor(c2));
    }
}
