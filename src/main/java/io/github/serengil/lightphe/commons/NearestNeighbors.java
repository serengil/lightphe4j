package io.github.serengil.lightphe.commons;

import io.github.serengil.lightphe.cryptosystems.DamgardGeislerKroigaard;
import io.github.serengil.lightphe.model.ArgmaxMessage;
import io.github.serengil.lightphe.model.Homomorphic;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.IntValue;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;

/**
 * Encrypted k nearest neighbor search, the counterpart of {@code
 * lightphe.commons.nearest_neighbors}.
 *
 * <p>Client (private key owner) encrypts a query vector, and server finds the k nearest vectors of
 * its database by squared euclidean distance without learning the query, the distances or the
 * result. Client learns only the indices, or the labels, of the k nearest vectors in order.
 *
 * <ul>
 *   <li>distance: {@code ||q - x||^2 = ||q||^2 - 2 dot(q, x) + ||x||^2} is linear in the encrypted
 *       q when client sends {@code E(||q||^2)} as well, so server computes it with additions and
 *       multiplications with constants only.
 *   <li>argmin: argmax of {@code 2^bitLength - 1 - distance} with the interactive argmax of
 *       Damgard-Geisler-Kroigaard, which reveals nothing to both parties.
 *   <li>exclusion: server turns the encrypted index of the nearest vector into an encrypted one-hot
 *       vector with the client's help, and lifts every other value by {@code 2^bitLength}, so the
 *       next argmax finds the next nearest vector.
 * </ul>
 *
 * <p>Ref: Erkin, Z. et al. (2009). Privacy-Preserving Face Recognition. PETS 2009.
 */
public final class NearestNeighbors {

    private NearestNeighbors() {
        throw new AssertionError("no instances");
    }

    /**
     * An encrypted query vector and its encrypted squared norm.
     *
     * @param query ciphertexts of entries
     * @param norm ciphertext of the squared norm
     */
    public record Query(List<CipherValue> query, CipherValue norm) {}

    /**
     * Encrypted indices, and encrypted labels if labels are set, of the k nearest vectors from the
     * nearest one.
     *
     * @param indices encrypted indices
     * @param labels encrypted labels, or {@code null} when the database has no labels
     */
    public record Result(List<CipherValue> indices, List<CipherValue> labels) {}

    /**
     * Encrypts a query vector and its squared norm. Runs on client side.
     *
     * @param cs additively homomorphic cryptosystem
     * @param query the query vector
     * @return the encrypted query
     */
    public static Query encryptQuery(Homomorphic cs, List<Long> query) {
        BigInteger u = cs.plaintextModulo();
        List<CipherValue> encrypted = new ArrayList<>(query.size());
        BigInteger norm = BigInteger.ZERO;
        for (long x : query) {
            BigInteger value = BigInteger.valueOf(x);
            encrypted.add(cs.encrypt(value.mod(u)));
            norm = norm.add(value.multiply(value));
        }
        return new Query(encrypted, cs.encrypt(norm.mod(u)));
    }

    /**
     * Finds the k nearest vectors of a database to an encrypted query. Runs on server side and
     * interacts with the client through the client callable.
     *
     * @param cs Damgard-Geisler-Kroigaard cryptosystem having the public key
     * @param encryptedQuery output of {@link #encryptQuery}
     * @param database vectors of the server
     * @param k number of nearest vectors to find
     * @param bitLength squared distances must be less than {@code 2^bitLength}
     * @param client sends a message to the client and returns its response
     * @param labels optional labels of vectors, or {@code null}. If set, encrypted labels of the
     *     nearest vectors are returned as well.
     * @return the encrypted indices, and labels if set, of the k nearest vectors
     */
    public static Result evaluateKnn(
            Homomorphic cs,
            Query encryptedQuery,
            List<List<Long>> database,
            int k,
            int bitLength,
            Function<ArgmaxMessage, List<BigInteger>> client,
            List<Long> labels) {
        BigInteger u = cs.plaintextModulo();
        int size = database.size();
        BigInteger offset = BigInteger.ONE.shiftLeft(bitLength);
        List<CipherValue> query = encryptedQuery.query();

        // values = 2^bitLength - 1 - distance, so the nearest vector has the greatest value
        List<CipherValue> values = new ArrayList<>(size);
        for (List<Long> vector : database) {
            BigInteger squaredNorm = BigInteger.ZERO;
            for (long x : vector) {
                squaredNorm = squaredNorm.add(BigInteger.valueOf(x).pow(2));
            }
            CipherValue value =
                    cs.add(
                            cs.encrypt(
                                    offset.subtract(BigInteger.ONE).subtract(squaredNorm).mod(u)),
                            cs.multiplyByConstant(
                                    encryptedQuery.norm(), u.subtract(BigInteger.ONE)));
            for (int i = 0; i < vector.size(); i++) {
                BigInteger x = BigInteger.valueOf(vector.get(i));
                if (x.mod(u).signum() != 0) {
                    value =
                            cs.add(
                                    value,
                                    cs.multiplyByConstant(query.get(i), x.shiftLeft(1).mod(u)));
                }
            }
            values.add(value);
        }

        // values are lifted by 2^bitLength in each round, so they need more bits
        int argmaxBitLength = bitLength + Integer.toBinaryString(k).length();

        List<CipherValue> indices = new ArrayList<>(k);
        List<CipherValue> foundLabels = new ArrayList<>(k);
        for (int round = 0; round < k; round++) {
            CipherValue index =
                    IntValue.of(cs.evaluateArgmax(asIntegers(values), argmaxBitLength, client));
            indices.add(index);

            boolean lastRound = round == k - 1;
            if (lastRound && labels == null) {
                break;
            }

            List<CipherValue> oneHot = oneHotIndex(cs, index, size, client);

            if (labels != null) {
                CipherValue label = cs.encrypt(BigInteger.ZERO);
                for (int i = 0; i < size; i++) {
                    BigInteger plainLabel = BigInteger.valueOf(labels.get(i)).mod(u);
                    if (plainLabel.signum() != 0) {
                        label = cs.add(label, cs.multiplyByConstant(oneHot.get(i), plainLabel));
                    }
                }
                foundLabels.add(cs.reencrypt(label));
            }

            if (!lastRound) {
                // every value except the found one is lifted by 2^bitLength: value + offset (1 -
                // bit)
                CipherValue lift = cs.encrypt(offset.mod(u));
                BigInteger negativeOffset = u.subtract(offset).mod(u);
                List<CipherValue> lifted = new ArrayList<>(size);
                for (int i = 0; i < size; i++) {
                    lifted.add(
                            cs.add(
                                    cs.add(values.get(i), lift),
                                    cs.multiplyByConstant(oneHot.get(i), negativeOffset)));
                }
                values = lifted;
            }
        }

        return new Result(indices, labels == null ? null : foundLabels);
    }

    /**
     * Turns an encrypted index into an encrypted one-hot vector with the client's help. Client
     * receives {@code E(r_i (index - i))} for random non-zero {@code r_i} in a random order, so it
     * learns only that one of them is zero, but not its position.
     *
     * @param cs Damgard-Geisler-Kroigaard cryptosystem having the public key
     * @param encryptedIndex encrypted index in {@code [0, size)}
     * @param size length of the one-hot vector
     * @param client sends a message to the client and returns its response
     * @return {@code E(1)} at the index, and {@code E(0)} elsewhere
     */
    public static List<CipherValue> oneHotIndex(
            Homomorphic cs,
            CipherValue encryptedIndex,
            int size,
            Function<ArgmaxMessage, List<BigInteger>> client) {
        BigInteger u = cs.plaintextModulo();
        List<Integer> order = new ArrayList<>(size);
        for (int i = 0; i < size; i++) {
            order.add(i);
        }
        Collections.shuffle(order, MathUtils.random());

        List<BigInteger> blinded = new ArrayList<>(size);
        for (int i : order) {
            CipherValue difference =
                    cs.add(encryptedIndex, cs.encrypt(BigInteger.valueOf(-i).mod(u)));
            BigInteger blinding = MathUtils.randomInt(BigInteger.ONE, u.subtract(BigInteger.ONE));
            blinded.add(asInteger(cs.reencrypt(cs.multiplyByConstant(difference, blinding))));
        }

        List<BigInteger> bits = client.apply(new ArgmaxMessage.Equality(blinded));

        List<CipherValue> oneHot = new ArrayList<>(Collections.nCopies(size, (CipherValue) null));
        for (int position = 0; position < size; position++) {
            oneHot.set(order.get(position), IntValue.of(bits.get(position)));
        }
        return oneHot;
    }

    /**
     * Answers a message of the server during encrypted nearest neighbor search. Runs on client
     * side. Messages of argmax are answered by the cryptosystem's {@code answerArgmax}.
     *
     * @param cs Damgard-Geisler-Kroigaard cryptosystem having the private key
     * @param message the message of the server
     * @return ciphertexts to be sent back to the server
     */
    public static List<BigInteger> answerKnn(DamgardGeislerKroigaard cs, ArgmaxMessage message) {
        if (message instanceof ArgmaxMessage.Equality equality) {
            List<BigInteger> answer = new ArrayList<>(equality.payload().size());
            for (BigInteger ciphertext : equality.payload()) {
                BigInteger bit = cs.isZero(ciphertext) ? BigInteger.ONE : BigInteger.ZERO;
                answer.add(asInteger(cs.encrypt(bit)));
            }
            return answer;
        }
        return cs.answerArgmax(message);
    }

    private static List<BigInteger> asIntegers(List<CipherValue> values) {
        List<BigInteger> out = new ArrayList<>(values.size());
        for (CipherValue value : values) {
            out.add(asInteger(value));
        }
        return out;
    }

    private static BigInteger asInteger(CipherValue value) {
        if (!(value instanceof IntValue integer)) {
            throw new IllegalArgumentException("expected an integer ciphertext");
        }
        return integer.value();
    }
}
