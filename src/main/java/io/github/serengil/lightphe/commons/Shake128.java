package io.github.serengil.lightphe.commons;

/**
 * SHAKE-128 extendable output function of FIPS 202, the counterpart of Python's {@code
 * hashlib.shake_128}.
 *
 * <p>Regev and Brakerski-Vaikuntanathan expand their public matrix and polynomial from a seed with
 * it, so key pairs exported by the Python library expand to exactly the same values here. The JDK
 * does not expose SHAKE through {@code MessageDigest} before Java 25, hence this small
 * implementation of Keccak-f[1600].
 *
 * <p>Output is squeezed incrementally, so arbitrarily long streams can be consumed without holding
 * them in memory at once. Instances are not thread-safe.
 */
public final class Shake128 {

    /** Rate of SHAKE-128 in bytes. */
    private static final int RATE = 168;

    private static final long[] ROUND_CONSTANTS = {
        0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL, 0x8000000080008000L,
        0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
        0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
        0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L,
        0x8000000000008002L, 0x8000000000000080L, 0x000000000000800aL, 0x800000008000000aL,
        0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    private static final int[] ROTATIONS = {
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
    };

    private static final int[] PI_LANES = {
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
    };

    private final long[] state = new long[25];
    private final byte[] block = new byte[RATE];
    private int offset;

    /**
     * Absorbs the whole input, after which output can be squeezed.
     *
     * @param input the message
     */
    public Shake128(byte[] input) {
        int position = 0;
        while (input.length - position >= RATE) {
            xorBlock(input, position, RATE);
            permute();
            position += RATE;
        }
        byte[] last = new byte[RATE];
        System.arraycopy(input, position, last, 0, input.length - position);
        // SHAKE domain separation and pad10*1
        last[input.length - position] ^= 0x1F;
        last[RATE - 1] ^= (byte) 0x80;
        xorBlock(last, 0, RATE);
        permute();
        extractBlock();
    }

    /**
     * Computes {@code length} bytes of SHAKE-128 output at once.
     *
     * @param input the message
     * @param length number of output bytes
     * @return the output
     */
    public static byte[] digest(byte[] input, int length) {
        byte[] out = new byte[length];
        new Shake128(input).squeeze(out, 0, length);
        return out;
    }

    /**
     * Squeezes the next bytes of output.
     *
     * @param out the buffer to fill
     * @param start first index of the buffer to fill
     * @param length number of bytes to fill
     */
    public void squeeze(byte[] out, int start, int length) {
        int position = start;
        int remaining = length;
        while (remaining > 0) {
            if (offset == RATE) {
                permute();
                extractBlock();
            }
            int chunk = Math.min(remaining, RATE - offset);
            System.arraycopy(block, offset, out, position, chunk);
            offset += chunk;
            position += chunk;
            remaining -= chunk;
        }
    }

    private void xorBlock(byte[] data, int start, int length) {
        for (int i = 0; i < length; i++) {
            state[i >>> 3] ^= (data[start + i] & 0xFFL) << (8 * (i & 7));
        }
    }

    private void extractBlock() {
        for (int i = 0; i < RATE; i++) {
            block[i] = (byte) (state[i >>> 3] >>> (8 * (i & 7)));
        }
        offset = 0;
    }

    private void permute() {
        long[] bc = new long[5];
        for (long roundConstant : ROUND_CONSTANTS) {
            // theta
            for (int i = 0; i < 5; i++) {
                bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
            }
            for (int i = 0; i < 5; i++) {
                long t = bc[(i + 4) % 5] ^ Long.rotateLeft(bc[(i + 1) % 5], 1);
                for (int j = 0; j < 25; j += 5) {
                    state[j + i] ^= t;
                }
            }

            // rho and pi
            long t = state[1];
            for (int i = 0; i < 24; i++) {
                int lane = PI_LANES[i];
                long saved = state[lane];
                state[lane] = Long.rotateLeft(t, ROTATIONS[i]);
                t = saved;
            }

            // chi
            for (int j = 0; j < 25; j += 5) {
                for (int i = 0; i < 5; i++) {
                    bc[i] = state[j + i];
                }
                for (int i = 0; i < 5; i++) {
                    state[j + i] ^= ~bc[(i + 1) % 5] & bc[(i + 2) % 5];
                }
            }

            // iota
            state[0] ^= roundConstant;
        }
    }
}
