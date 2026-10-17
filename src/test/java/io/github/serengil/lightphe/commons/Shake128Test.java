package io.github.serengil.lightphe.commons;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Checks SHAKE-128 against vectors produced by Python's {@code hashlib.shake_128}. */
class Shake128Test {

    private static String hex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }

    @Test
    @DisplayName("SHAKE-128 of the empty message")
    void testEmptyMessage() {
        assertThat(hex(Shake128.digest(new byte[0], 32)))
                .isEqualTo("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
    }

    @Test
    @DisplayName("SHAKE-128 squeezes more than one block of output")
    void testLongOutput() {
        assertThat(hex(Shake128.digest("abc".getBytes(StandardCharsets.US_ASCII), 200)))
                .isEqualTo(
                        "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"
                                + "44c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca578378"
                                + "9a41f8611214ce612394df286a62d1a2252aa94db9c538956c717dc2bed4f232"
                                + "a0294c857c730aa16067ac1062f1201fb0d377cfb9cde4c63599b27f3462bba4"
                                + "a0ed296c801f9ff7f57302bb3076ee145f97a32ae68e76ab66c48d51675bd49a"
                                + "cc29082f5647584e6aa01b3f5af057805f973ff8ecb8b226ac32ada6f01c1fcd"
                                + "4818cb006aa5b4cd");
    }

    @Test
    @DisplayName("SHAKE-128 absorbs messages longer than one block")
    void testLongInput() {
        byte[] input = new byte[200];
        for (int i = 0; i < input.length; i++) {
            input[i] = (byte) i;
        }
        assertThat(hex(Shake128.digest(input, 40)))
                .isEqualTo(
                        "0c4234ca1e31801ae606f8b8d8e0665c66f42a21d601c2681858a92c79ad5d69"
                                + "e143c3b1393dd894");
    }

    @Test
    @DisplayName("SHAKE-128 squeezed in chunks equals the output squeezed at once")
    void testIncrementalSqueeze() {
        // the seed shape Regev and Brakerski-Vaikuntanathan expand their public keys from
        byte[] seed = new byte[32];
        byte[] raw = BigInteger.TWO.pow(255).add(BigInteger.valueOf(12345)).toByteArray();
        System.arraycopy(raw, raw.length - 32, seed, 0, 32);

        byte[] atOnce = Shake128.digest(seed, 400);
        assertThat(hex(Arrays.copyOfRange(atOnce, 368, 400)))
                .isEqualTo("d41c4724b64a3d73e826ff03cddc8f7c19d669d9a4c835b7a3cdc409d1b2be7c");

        Shake128 stream = new Shake128(seed);
        byte[] inChunks = new byte[400];
        for (int start = 0; start < inChunks.length; start += 9) {
            stream.squeeze(inChunks, start, Math.min(9, inChunks.length - start));
        }
        assertThat(inChunks).isEqualTo(atOnce);
    }
}
