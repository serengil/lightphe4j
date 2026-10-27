package io.github.serengil.lightphe.cryptosystems;

import io.github.serengil.lightphe.commons.Threshold;
import io.github.serengil.lightphe.commons.Zkp;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.PartialDecryption;
import io.github.serengil.lightphe.model.Proof;
import io.github.serengil.lightphe.model.Proven;
import io.github.serengil.lightphe.model.value.CipherValue;
import io.github.serengil.lightphe.model.value.IntValue;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

/**
 * Threshold decryption and zero-knowledge proofs shared by Paillier and Damgard-Jurik, whose
 * ciphertexts are {@code g^m * r^n mod n^(s+1)} with {@code s = 1} for Paillier.
 *
 * <ul>
 *   <li>proof of correct decryption: randomness of the ciphertext
 *   <li>proof of membership: 1-out-of-k proof of Damgard and Jurik showing that {@code c * g^-v} is
 *       an n-th power for one of the values v
 *   <li>proof of knowledge of the plaintext and randomness
 *   <li>threshold decryption of Shoup and Damgard-Jurik, with proofs of partial decryption if keys
 *       are generated with safe primes
 * </ul>
 *
 * @param keys the key pair of the cryptosystem
 * @param s the ciphertext modulo is {@code n^(s+1)}
 * @param modulo the ciphertext modulo {@code n^(s+1)}
 * @param algorithm prefix of domains of proofs, e.g. {@code paillier}
 */
record PaillierProofs(Keys keys, int s, BigInteger modulo, String algorithm) {

    private String domain(String statement) {
        return "lightphe/" + algorithm + "/" + statement;
    }

    private BigInteger n() {
        return keys.publicNumber("n");
    }

    List<Keys> generateThresholdKeys(int threshold, int parties) {
        return Threshold.generatePaillierThresholdKeys(keys, s, modulo, threshold, parties);
    }

    PartialDecryption partialDecrypt(CipherValue ciphertext, boolean prove) {
        return Threshold.paillierPartialDecrypt(
                keys,
                AbstractHomomorphic.asInt(ciphertext),
                modulo,
                prove,
                domain("partial-decryption"));
    }

    boolean verifyPartialDecryption(CipherValue ciphertext, PartialDecryption partialDecryption) {
        return Threshold.verifyPaillierPartialDecryption(
                keys,
                AbstractHomomorphic.asInt(ciphertext),
                partialDecryption,
                modulo,
                domain("partial-decryption"));
    }

    BigInteger combinePartialDecryptions(
            CipherValue ciphertext, List<PartialDecryption> partialDecryptions, boolean verify) {
        return Threshold.combinePaillierPartialDecryptions(
                keys,
                AbstractHomomorphic.asInt(ciphertext),
                partialDecryptions,
                modulo,
                verify,
                domain("partial-decryption"));
    }

    Proof proveDecryption(CipherValue ciphertext, BigInteger plaintext) {
        return Zkp.provePaillierDecryption(
                AbstractHomomorphic.asInt(ciphertext), plaintext, n(), keys.privateNumber("phi"));
    }

    boolean verifyDecryption(CipherValue ciphertext, BigInteger plaintext, Proof proof) {
        if (!(ciphertext instanceof IntValue value)) {
            return false;
        }
        return Zkp.verifyPaillierDecryption(value.value(), plaintext, proof, n());
    }

    Proof proveMembership(
            CipherValue ciphertext,
            BigInteger plaintext,
            BigInteger randomKey,
            List<BigInteger> values,
            Object context) {
        BigInteger n = n();
        return Zkp.proveNthPowerOr(
                n,
                modulo,
                Zkp.paillierMembershipCandidates(
                        AbstractHomomorphic.asInt(ciphertext), values, n, modulo),
                randomKey,
                ElGamal.indexOf(values, plaintext),
                domain("membership"),
                Arrays.asList(values, context));
    }

    /** Random key of the homomorphic sum of ciphertexts, as {@code r^n} multiplies. */
    BigInteger combineRandomKeys(List<BigInteger> randomKeys) {
        BigInteger combined = BigInteger.ONE;
        for (BigInteger randomKey : randomKeys) {
            combined = combined.multiply(randomKey).mod(modulo);
        }
        return combined;
    }

    boolean verifyCiphertext(
            CipherValue ciphertext, Proof proof, List<BigInteger> values, Object context) {
        if (!(ciphertext instanceof IntValue value)) {
            return false;
        }
        BigInteger n = n();
        BigInteger c = value.value();
        if (c.signum() <= 0 || c.compareTo(modulo) >= 0 || !c.gcd(n).equals(BigInteger.ONE)) {
            return false;
        }
        return Zkp.verifyNthPowerOr(
                n,
                modulo,
                Zkp.paillierMembershipCandidates(c, values, n, modulo),
                proof,
                domain("membership"),
                Arrays.asList(values, context));
    }

    Proven<CipherValue> proveKnowledge(
            CipherValue ciphertext, BigInteger plaintext, BigInteger randomKey, Object context) {
        Proof proof =
                Zkp.provePaillierKnowledge(
                        AbstractHomomorphic.asInt(ciphertext),
                        plaintext,
                        randomKey,
                        n(),
                        modulo,
                        domain("knowledge"),
                        context);
        return new Proven<>(ciphertext, proof);
    }

    boolean verifyKnowledge(CipherValue ciphertext, Proof proof, Object context) {
        if (!(ciphertext instanceof IntValue value)) {
            return false;
        }
        return Zkp.verifyPaillierKnowledge(
                value.value(), proof, n(), modulo, domain("knowledge"), context);
    }
}
