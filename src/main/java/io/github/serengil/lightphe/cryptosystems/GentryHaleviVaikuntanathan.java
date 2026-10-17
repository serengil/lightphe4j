package io.github.serengil.lightphe.cryptosystems;

import io.github.serengil.lightphe.commons.Logger;
import io.github.serengil.lightphe.commons.MathUtils;
import io.github.serengil.lightphe.model.Algorithm;
import io.github.serengil.lightphe.model.KeySpec;
import io.github.serengil.lightphe.model.KeyValue;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.IntValue;
import io.github.serengil.lightphe.model.value.TupleValue;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Gentry-Halevi-Vaikuntanathan, homomorphic with respect to the addition, and supports one
 * multiplication of ciphertexts like Boneh-Goh-Nissim, without pairings. Its security relies on
 * learning with errors (LWE) problem.
 *
 * <p>THIS IS FOR LEARNING PURPOSES ONLY, AND IT IS NOT SECURE. Ciphertexts are {@code m x m}
 * matrices where m grows with {@code n log q}, so secure parameters would need ciphertexts of
 * terabytes. Here, the lattice dimension n is between 2 and 8, which offers no security at all. Use
 * Brakerski-Vaikuntanathan for a practical and quantum resistant alternative.
 *
 * <p>Matrices are over {@code Z_q} where q is a power of 2, and plaintexts are in {@code Z_p} for
 * an odd prime p.
 *
 * <ul>
 *   <li>private key: short {@code m x m} matrix T, which is full rank and satisfies {@code T A = 0
 *       mod q}. It is generated with the gadget trapdoor of Micciancio-Peikert: {@code A^T = [A_bar
 *       | G - A_bar R]} where G is the gadget matrix of powers of 2.
 *   <li>public key: {@code m x n} matrix A
 *   <li>encryption of m: {@code C = A S + p X + m I mod q} for uniformly random S and small X
 *   <li>decryption: {@code T C T^T mod q = T (p X + m I) T^T}, as {@code T A = 0}. When its entries
 *       are small enough, it equals {@code T (p X + m I) T^T} over integers, so reducing it modulo
 *       p and multiplying with {@code T^-1} and {@code T^-T} modulo p restores {@code m I}.
 *   <li>multiplication: {@code C1 C2^T}, which is decrypted in the same way to {@code m1 m2 I}, as
 *       {@code T (A S1 + Z1)(A S2 + Z2)^T T^T = T Z1 Z2^T T^T}
 * </ul>
 *
 * <p>The original scheme encrypts {@code m x m} matrices of plaintexts. Here, a single plaintext is
 * encrypted as the scalar matrix {@code m I}.
 *
 * <p>Noise grows with homomorphic operations, and decryption returns a wrong result without any
 * error when it exceeds {@code q / 2}. q is chosen to leave room for multiplying a product with
 * constants up to a few thousands, or for adding thousands of products.
 *
 * <p>Ref: Gentry, C., Halevi, S., Vaikuntanathan, V. (2010). A Simple BGN-Type Cryptosystem from
 * LWE. EUROCRYPT 2010.
 *
 * <p>Ref: Micciancio, D., Peikert, C. (2012). Trapdoors for Lattices: Simpler, Tighter, Faster,
 * Smaller. EUROCRYPT 2012.
 */
public final class GentryHaleviVaikuntanathan extends AbstractHomomorphic {

    /** The key fields Gentry-Halevi-Vaikuntanathan requires. */
    public static final KeySpec REQUIRED_KEYS = KeySpec.of(List.of("A", "q", "p"), List.of("T"));

    /** Floats are scaled by powers of 10, which exceeds the small plaintext space. */
    public static final String FLOAT_NOT_SUPPORTED_MSG =
            "Gentry-Halevi-Vaikuntanathan does not support float values or tensors, because they"
                    + " are scaled by powers of 10, which exceed its small plaintext space."
                    + " Use integers instead.";

    /** Shown whenever the cryptosystem is built. */
    public static final String INSECURE_WARNING_MSG =
            "Gentry-Halevi-Vaikuntanathan is for learning purposes only. Its ciphertexts are huge"
                    + " matrices for secure parameters, so it supports tiny key sizes that are not"
                    + " secure. Use Brakerski-Vaikuntanathan for a practical alternative.";

    /** Smallest supported lattice dimension. */
    public static final int MIN_KEY_SIZE = 2;

    /** Greatest supported lattice dimension, as ciphertexts grow with {@code n log q}. */
    public static final int MAX_KEY_SIZE = 8;

    /** Default lattice dimension. */
    public static final int DEFAULT_KEY_SIZE = 4;

    /** Default plaintext modulus p. */
    private static final int DEFAULT_PLAINTEXT_MODULO = 101;

    /** Room for noise growth after a multiplication in bits, i.e. for additions and constants. */
    private static final int NOISE_MARGIN_BITS = 12;

    /** Errors are sampled from centered binomial distribution with this parameter. */
    private static final int ETA = 2;

    private static final int FRESH = 1;
    private static final int MULTIPLIED = 2;

    /** Matrix products modulo q run on wrapping longs up to this many bits of q. */
    private static final int LONG_ARITHMETIC_BITS = 62;

    private static final Logger logger = Logger.forModule(GentryHaleviVaikuntanathan.class);

    /** First row of {@code T^-1 mod p}, built on first decryption when the keys do not carry it. */
    private volatile BigInteger[] inverseRow;

    /**
     * Builds a Gentry-Halevi-Vaikuntanathan cryptosystem.
     *
     * @param keys the private-public key pair; {@code null} generates a random pair
     * @param keySize lattice dimension n in {@code [2, 8]}; {@code null} defaults to 4
     * @param plaintextLimit upper bound for plaintext values. Plaintext modulus p is the smallest
     *     prime greater than or equal to it; {@code null} defaults to 101.
     */
    public GentryHaleviVaikuntanathan(Keys keys, Integer keySize, BigInteger plaintextLimit) {
        super(Algorithm.GENTRY_HALEVI_VAIKUNTANATHAN, buildKeys(keys, keySize, plaintextLimit));
        this.plaintextModulo = this.keys.publicNumber("p");
        this.ciphertextModulo = this.keys.publicNumber("q");
    }

    /**
     * Builds a Gentry-Halevi-Vaikuntanathan cryptosystem around an existing key pair.
     *
     * @param keys the private-public key pair
     */
    public GentryHaleviVaikuntanathan(Keys keys) {
        this(keys, null, null);
    }

    private static Keys buildKeys(Keys keys, Integer keySize, BigInteger plaintextLimit) {
        logger.warn(INSECURE_WARNING_MSG);
        return keys != null
                ? keys
                : generateKeys(keySize == null ? DEFAULT_KEY_SIZE : keySize, plaintextLimit);
    }

    /**
     * Generates the public and private keys of the Gentry-Halevi-Vaikuntanathan cryptosystem.
     *
     * @param keySize lattice dimension n
     * @param plaintextLimit upper bound for plaintext values, or {@code null} for the default
     * @return the generated key pair
     * @throws IllegalArgumentException when the key size is out of the supported range
     */
    public static Keys generateKeys(int keySize, BigInteger plaintextLimit) {
        int n = keySize;
        if (n < MIN_KEY_SIZE || n > MAX_KEY_SIZE) {
            throw new IllegalArgumentException(
                    "Key size "
                            + n
                            + " is not supported. Gentry-Halevi-Vaikuntanathan is for learning"
                            + " purposes only, and its key size must be in ["
                            + MIN_KEY_SIZE
                            + ", "
                            + MAX_KEY_SIZE
                            + "].");
        }

        // T must be invertible modulo p, and det(T) is a power of 2
        BigInteger p = BigInteger.valueOf(DEFAULT_PLAINTEXT_MODULO);
        if (plaintextLimit != null) {
            p =
                    MathUtils.nextPrime(
                            plaintextLimit.max(BigInteger.valueOf(3)).subtract(BigInteger.ONE));
        }

        int mBar = 2 * n;
        int k = modulusBits(n, mBar, p);
        BigInteger q = BigInteger.ONE.shiftLeft(k);
        int nk = n * k;
        BigInteger finalP = p;
        logger.debug(
                () -> "n = " + n + ", log q = " + k + ", m = " + (mBar + nk) + ", p = " + finalP);

        // A^T = [A_bar | G - A_bar R], where G = I_n (x) (1, 2, ..., 2^(k-1))
        BigInteger[][] aBar = new BigInteger[n][mBar];
        for (BigInteger[] row : aBar) {
            for (int j = 0; j < mBar; j++) {
                row[j] = MathUtils.getRandomBits(k);
            }
        }
        long[][] r = new long[mBar][nk];
        for (long[] row : r) {
            for (int c = 0; c < nk; c++) {
                row[c] = MathUtils.random().nextInt(3) - 1L;
            }
        }
        BigInteger[][] aTransposed = new BigInteger[n][mBar + nk];
        for (int i = 0; i < n; i++) {
            System.arraycopy(aBar[i], 0, aTransposed[i], 0, mBar);
            for (int c = 0; c < nk; c++) {
                BigInteger aBarR = BigInteger.ZERO;
                for (int j = 0; j < mBar; j++) {
                    if (r[j][c] != 0) {
                        aBarR = aBarR.add(aBar[i][j].multiply(BigInteger.valueOf(r[j][c])));
                    }
                }
                BigInteger gadget = c / k == i ? BigInteger.ONE.shiftLeft(c % k) : BigInteger.ZERO;
                aTransposed[i][mBar + c] = gadget.subtract(aBarR).mod(q);
            }
        }

        // W is the bit decomposition of -A_bar, so that G W = -A_bar mod q
        long[][] w = new long[nk][mBar];
        for (int j = 0; j < mBar; j++) {
            for (int i = 0; i < n; i++) {
                BigInteger value = aBar[i][j].negate().mod(q);
                for (int bit = 0; bit < k; bit++) {
                    w[i * k + bit][j] = value.testBit(bit) ? 1 : 0;
                }
            }
        }

        // S_G = I_n (x) S_k, whose columns 2 e_i - e_(i+1) and 2 e_k are orthogonal to the gadget
        long[][] sG = new long[nk][nk];
        for (int block = 0; block < n; block++) {
            for (int i = 0; i < k; i++) {
                sG[block * k + i][block * k + i] = 2;
                if (i + 1 < k) {
                    sG[block * k + i + 1][block * k + i] = -1;
                }
            }
        }

        // S = [[I + R W, R S_G], [W, S_G]] is a short basis with A^T S = 0 mod q
        long[][] rw = multiplyExact(r, w);
        long[][] rsG = multiplyExact(r, sG);
        int m = mBar + nk;
        long[][] s = new long[m][m];
        for (int i = 0; i < mBar; i++) {
            for (int j = 0; j < mBar; j++) {
                s[i][j] = (i == j ? 1 : 0) + rw[i][j];
            }
            System.arraycopy(rsG[i], 0, s[i], mBar, nk);
        }
        for (int i = 0; i < nk; i++) {
            System.arraycopy(w[i], 0, s[mBar + i], 0, mBar);
            System.arraycopy(sG[i], 0, s[mBar + i], mBar, nk);
        }

        // T = S^T and A = (A^T)^T
        List<List<BigInteger>> t = new ArrayList<>(m);
        for (int i = 0; i < m; i++) {
            List<BigInteger> row = new ArrayList<>(m);
            for (int j = 0; j < m; j++) {
                row.add(BigInteger.valueOf(s[j][i]));
            }
            t.add(row);
        }
        List<List<BigInteger>> a = new ArrayList<>(m);
        for (int i = 0; i < m; i++) {
            List<BigInteger> row = new ArrayList<>(n);
            for (int j = 0; j < n; j++) {
                row.add(aTransposed[j][i]);
            }
            a.add(row);
        }

        Keys keys = Keys.empty();
        keys.publicKey().put("A", KeyValue.matrix(a));
        keys.publicKey().put("q", KeyValue.of(q));
        keys.publicKey().put("p", KeyValue.of(p));

        keys.privateKey().put("T", KeyValue.matrix(t));
        // first row of T^-1 mod p is enough to restore scalar matrices m I
        keys.privateKey()
                .put("u", KeyValue.numbers(Arrays.asList(firstRowOfInverse(toArray(t), p))));
        return keys;
    }

    @Override
    public KeySpec requiredKeys() {
        return REQUIRED_KEYS;
    }

    /**
     * {@inheritDoc}
     *
     * @throws UnsupportedOperationException always: the random key of Gentry-Halevi-Vaikuntanathan
     *     is a matrix, see {@link #generateRandomMatrix()}
     */
    @Override
    public BigInteger generateRandomKey() {
        throw new UnsupportedOperationException(
                "Gentry-Halevi-Vaikuntanathan requires a uniformly random matrix per encryption."
                        + " Use generateRandomMatrix.");
    }

    /**
     * Generates the uniformly random {@code n x m} matrix S required per encryption.
     *
     * @return the matrix S
     */
    public BigInteger[][] generateRandomMatrix() {
        List<List<BigInteger>> a = keys.publicMatrix("A");
        int k = ciphertextModulo.bitLength() - 1;
        BigInteger[][] s = new BigInteger[a.get(0).size()][a.size()];
        for (BigInteger[] row : s) {
            for (int j = 0; j < row.length; j++) {
                row[j] = MathUtils.getRandomBits(k);
            }
        }
        return s;
    }

    @Override
    public CipherValue encrypt(BigInteger plaintext) {
        return encrypt(plaintext, generateRandomMatrix());
    }

    /**
     * Encrypts a plaintext with an explicit random matrix.
     *
     * @param plaintext the message to encrypt in {@code [0, p)}
     * @param randomMatrix the uniformly random {@code n x m} matrix S
     * @return the ciphertext: the level and the {@code m x m} matrix {@code C = A S + p X + m I mod
     *     q}
     */
    public CipherValue encrypt(BigInteger plaintext, BigInteger[][] randomMatrix) {
        BigInteger q = ciphertextModulo;
        BigInteger p = plaintextModulo;
        BigInteger[][] a = toArray(keys.publicMatrix("A"));
        int m = a.length;

        BigInteger message = plaintext;
        if (message.compareTo(p) >= 0) {
            message = message.mod(p);
            BigInteger normalized = message;
            logger.debug(
                    () ->
                            "Gentry-Halevi-Vaikuntanathan can encrypt messages [0, "
                                    + p
                                    + "). Seems plaintext exceeded this limit. New plaintext is "
                                    + normalized);
        }

        BigInteger[][] matrix = multiplyTransposedModQ(a, transpose(randomMatrix));
        for (int i = 0; i < m; i++) {
            for (int j = 0; j < m; j++) {
                BigInteger entry = matrix[i][j].add(p.multiply(BigInteger.valueOf(sampleSmall())));
                if (i == j) {
                    entry = entry.add(message);
                }
                matrix[i][j] = entry.mod(q);
            }
        }
        return toValue(FRESH, matrix);
    }

    @Override
    public BigInteger decrypt(CipherValue ciphertext) {
        BigInteger q = ciphertextModulo;
        BigInteger p = plaintextModulo;
        BigInteger[][] t = toArray(keys.privateMatrix("T"));
        BigInteger[] u = inverseRow(t);
        BigInteger[][] matrix = matrixOf(ciphertext);
        int m = t.length;

        // E = T C T^T mod q, centered, equals T (p X + B) T^T over integers
        BigInteger[][] tc = multiplyTransposedModQ(t, transpose(matrix));
        BigInteger[][] e = multiplyTransposedModQ(tc, t);
        BigInteger halfQ = q.shiftRight(1);

        // B = T^-1 E T^-T mod p, and its first diagonal entry is the message
        BigInteger result = BigInteger.ZERO;
        for (int j = 0; j < m; j++) {
            BigInteger column = BigInteger.ZERO;
            for (int i = 0; i < m; i++) {
                BigInteger entry = e[i][j];
                if (entry.compareTo(halfQ) > 0) {
                    entry = entry.subtract(q);
                }
                column = column.add(u[i].multiply(entry));
            }
            result = result.add(column.multiply(u[j]));
        }
        return result.mod(p);
    }

    /**
     * {@inheritDoc}
     *
     * <p>Fresh and multiplied ciphertexts can be added, as they are decrypted in the same way.
     */
    @Override
    public CipherValue add(CipherValue ciphertext1, CipherValue ciphertext2) {
        BigInteger q = ciphertextModulo;
        BigInteger[][] matrix1 = matrixOf(ciphertext1);
        BigInteger[][] matrix2 = matrixOf(ciphertext2);
        for (int i = 0; i < matrix1.length; i++) {
            for (int j = 0; j < matrix1[i].length; j++) {
                matrix1[i][j] = matrix1[i][j].add(matrix2[i][j]).mod(q);
            }
        }
        return toValue(Math.max(levelOf(ciphertext1), levelOf(ciphertext2)), matrix1);
    }

    /**
     * {@inheritDoc}
     *
     * <p>The result is the matrix product {@code C1 C2^T}.
     */
    @Override
    public CipherValue multiply(CipherValue ciphertext1, CipherValue ciphertext2) {
        if (levelOf(ciphertext1) != FRESH || levelOf(ciphertext2) != FRESH) {
            throw new IllegalArgumentException(
                    "Gentry-Halevi-Vaikuntanathan supports only one multiplication. "
                            + "Multiplied ciphertexts cannot be multiplied with"
                            + " ciphertexts again.");
        }
        return toValue(
                MULTIPLIED, multiplyTransposedModQ(matrixOf(ciphertext1), matrixOf(ciphertext2)));
    }

    /**
     * {@inheritDoc}
     *
     * <p>Noise of the result is the noise of the ciphertext times {@code |constant|}.
     */
    @Override
    public CipherValue multiplyByConstant(CipherValue ciphertext, BigInteger constant) {
        BigInteger q = ciphertextModulo;
        BigInteger p = plaintextModulo;

        // centered representative keeps the noise small for negative constants
        BigInteger scalar = constant.mod(p);
        if (scalar.compareTo(p.shiftRight(1)) > 0) {
            scalar = scalar.subtract(p);
        }

        BigInteger[][] matrix = matrixOf(ciphertext);
        for (BigInteger[] row : matrix) {
            for (int j = 0; j < row.length; j++) {
                row[j] = row[j].multiply(scalar).mod(q);
            }
        }
        return toValue(levelOf(ciphertext), matrix);
    }

    @Override
    public CipherValue reencrypt(CipherValue ciphertext) {
        return add(ciphertext, encrypt(BigInteger.ZERO));
    }

    private BigInteger[] inverseRow(BigInteger[][] t) {
        BigInteger[] row = inverseRow;
        if (row == null) {
            row =
                    keys.privateKey().containsKey("u")
                            ? keys.privateNumbers("u").toArray(new BigInteger[0])
                            : firstRowOfInverse(t, plaintextModulo);
            inverseRow = row;
        }
        return row;
    }

    /**
     * Bits of q, so that the noise of a product stays below {@code q / 2} with a margin. Noise of a
     * product is about {@code p^2 m^2} times a small factor, and {@code m = m_bar + n log q}, so it
     * is found iteratively.
     */
    private static int modulusBits(int n, int mBar, BigInteger p) {
        double log2P = log2(p);
        int k = 32;
        while (true) {
            int m = mBar + n * k;
            int required =
                    (int)
                            Math.ceil(
                                    2 * log2P
                                            + 2 * (Math.log(m) / Math.log(2))
                                            + 2
                                            + NOISE_MARGIN_BITS);
            if (required <= k) {
                return k;
            }
            k = required;
        }
    }

    private static double log2(BigInteger value) {
        int shift = Math.max(0, value.bitLength() - 53);
        return Math.log(value.shiftRight(shift).doubleValue()) / Math.log(2) + shift;
    }

    /** Samples from centered binomial distribution with cryptographically secure randomness. */
    private static int sampleSmall() {
        int bits = MathUtils.random().nextInt(1 << (2 * ETA));
        int mask = (1 << ETA) - 1;
        return Integer.bitCount(bits & mask) - Integer.bitCount(bits >>> ETA);
    }

    /** Computes {@code left x right^T mod q}. */
    private BigInteger[][] multiplyTransposedModQ(BigInteger[][] left, BigInteger[][] right) {
        BigInteger q = ciphertextModulo;
        int rows = left.length;
        int columns = right.length;
        int inner = left[0].length;
        BigInteger[][] product = new BigInteger[rows][columns];

        if (q.bitLength() - 1 <= LONG_ARITHMETIC_BITS) {
            // q divides 2^64, so wrapping arithmetic is exact modulo q
            long mask = q.longValueExact() - 1;
            long[][] l = toLongs(left);
            long[][] r = toLongs(right);
            for (int i = 0; i < rows; i++) {
                for (int j = 0; j < columns; j++) {
                    long sum = 0;
                    long[] li = l[i];
                    long[] rj = r[j];
                    for (int x = 0; x < inner; x++) {
                        sum += li[x] * rj[x];
                    }
                    product[i][j] = BigInteger.valueOf(sum & mask);
                }
            }
            return product;
        }

        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < columns; j++) {
                BigInteger sum = BigInteger.ZERO;
                for (int x = 0; x < inner; x++) {
                    sum = sum.add(left[i][x].multiply(right[j][x]));
                }
                product[i][j] = sum.mod(q);
            }
        }
        return product;
    }

    /** Exact product of two small integer matrices. */
    private static long[][] multiplyExact(long[][] left, long[][] right) {
        int rows = left.length;
        int columns = right[0].length;
        long[][] product = new long[rows][columns];
        for (int i = 0; i < rows; i++) {
            for (int x = 0; x < right.length; x++) {
                long factor = left[i][x];
                if (factor == 0) {
                    continue;
                }
                for (int j = 0; j < columns; j++) {
                    product[i][j] += factor * right[x][j];
                }
            }
        }
        return product;
    }

    /** First row of the inverse of a matrix modulo prime p with Gauss-Jordan elimination. */
    private static BigInteger[] firstRowOfInverse(BigInteger[][] matrix, BigInteger p) {
        int size = matrix.length;
        BigInteger[][] augmented = new BigInteger[size][2 * size];
        for (int i = 0; i < size; i++) {
            for (int j = 0; j < size; j++) {
                augmented[i][j] = matrix[i][j].mod(p);
                augmented[i][size + j] = i == j ? BigInteger.ONE : BigInteger.ZERO;
            }
        }
        for (int column = 0; column < size; column++) {
            int pivot = column;
            while (augmented[pivot][column].signum() == 0) {
                pivot++;
            }
            BigInteger[] swap = augmented[column];
            augmented[column] = augmented[pivot];
            augmented[pivot] = swap;

            BigInteger inverse = augmented[column][column].modInverse(p);
            for (int j = 0; j < 2 * size; j++) {
                augmented[column][j] = augmented[column][j].multiply(inverse).mod(p);
            }
            for (int row = 0; row < size; row++) {
                BigInteger factor = augmented[row][column];
                if (row != column && factor.signum() != 0) {
                    for (int j = 0; j < 2 * size; j++) {
                        augmented[row][j] =
                                augmented[row][j]
                                        .subtract(factor.multiply(augmented[column][j]))
                                        .mod(p);
                    }
                }
            }
        }
        return Arrays.copyOfRange(augmented[0], size, 2 * size);
    }

    private static long[][] toLongs(BigInteger[][] matrix) {
        long[][] out = new long[matrix.length][];
        for (int i = 0; i < matrix.length; i++) {
            out[i] = new long[matrix[i].length];
            for (int j = 0; j < matrix[i].length; j++) {
                // the low 64 bits are all that matter modulo q
                out[i][j] = matrix[i][j].longValue();
            }
        }
        return out;
    }

    private static BigInteger[][] transpose(BigInteger[][] matrix) {
        BigInteger[][] out = new BigInteger[matrix[0].length][matrix.length];
        for (int i = 0; i < matrix.length; i++) {
            for (int j = 0; j < matrix[i].length; j++) {
                out[j][i] = matrix[i][j];
            }
        }
        return out;
    }

    private static BigInteger[][] toArray(List<List<BigInteger>> rows) {
        BigInteger[][] out = new BigInteger[rows.size()][];
        for (int i = 0; i < rows.size(); i++) {
            out[i] = rows.get(i).toArray(new BigInteger[0]);
        }
        return out;
    }

    private static CipherValue toValue(int level, BigInteger[][] matrix) {
        List<CipherValue> rows = new ArrayList<>(matrix.length);
        for (BigInteger[] row : matrix) {
            rows.add(TupleValue.ofIntegers(Arrays.asList(row)));
        }
        return TupleValue.of(IntValue.of(level), TupleValue.of(rows));
    }

    private static int levelOf(CipherValue ciphertext) {
        return asInt(asTuple(ciphertext).get(0)).intValueExact();
    }

    private static BigInteger[][] matrixOf(CipherValue ciphertext) {
        TupleValue pair = asTuple(ciphertext);
        if (pair.size() != 2) {
            throw new IllegalArgumentException(
                    "expected a (level, matrix) pair, got " + pair.size() + " components");
        }
        List<TupleValue> rows = asTuple(pair.get(1)).asTuples();
        BigInteger[][] matrix = new BigInteger[rows.size()][];
        for (int i = 0; i < rows.size(); i++) {
            matrix[i] = rows.get(i).asIntegers().toArray(new BigInteger[0]);
        }
        return matrix;
    }
}
