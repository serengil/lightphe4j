package io.github.serengil.lightphe;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.serengil.lightphe.model.Ciphertext;
import io.github.serengil.lightphe.model.Keys;
import io.github.serengil.lightphe.model.Proven;
import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** Port of {@code tests/test_auction.py}. */
class AuctionTest {

    /**
     * Bidders submit encrypted bids with proofs of knowledge. A bidder who copies someone else's
     * encrypted bid and adds 1 to it homomorphically cannot prove knowledge of the result, so
     * cannot outbid without knowing the bid. After the deadline, the auctioneer decrypts valid bids
     * with proofs and announces the winner.
     */
    @ParameterizedTest(name = "{0}")
    @CsvSource({"Exponential-ElGamal, 128, true", "Paillier, 128, false"})
    void testSealedBidAuction(String algorithmName, int keySize, boolean primeOrder) {
        LightPHE auctioneer = ZkpTest.build(algorithmName, keySize, primeOrder);
        LightPHE publicCs =
                LightPHE.builder()
                        .algorithmName(algorithmName)
                        .keys(Keys.of(auctioneer.cs().keys().publicKey(), null))
                        .build();

        Map<String, Long> bids = new LinkedHashMap<>();
        bids.put("alice", 950L);
        bids.put("bob", 870L);
        bids.put("carol", 910L);
        Map<String, Proven<Ciphertext>> submissions = new LinkedHashMap<>();
        bids.forEach(
                (bidder, bid) ->
                        submissions.put(bidder, publicCs.encryptWithProofOfKnowledge(bid, bidder)));

        // mallory copies alice's encrypted bid, adds 1 to it, and reuses alice's proof
        Proven<Ciphertext> alice = submissions.get("alice");
        submissions.put(
                "mallory", new Proven<>(alice.value().add(publicCs.encrypt(1)), alice.proof()));

        // oscar re-randomizes bob's encrypted bid to make it look different
        Proven<Ciphertext> bob = submissions.get("bob");
        submissions.put(
                "oscar", new Proven<>(publicCs.regenerateCiphertext(bob.value()), bob.proof()));

        // trent submits a copy of carol's submission as is
        submissions.put("trent", submissions.get("carol"));

        Map<String, Ciphertext> valid = new LinkedHashMap<>();
        submissions.forEach(
                (bidder, submission) -> {
                    if (publicCs.verifyKnowledge(submission.value(), submission.proof(), bidder)) {
                        valid.put(bidder, submission.value());
                    }
                });
        assertThat(valid.keySet()).containsExactlyInAnyOrderElementsOf(bids.keySet());

        // after the deadline, auctioneer decrypts valid bids with proofs, and anyone verifies them
        Map<String, Long> opened = new LinkedHashMap<>();
        valid.forEach(
                (bidder, bid) -> {
                    Proven<BigInteger> amount = auctioneer.decryptWithProof(bid);
                    assertThat(publicCs.verifyDecryption(bid, amount.value(), amount.proof()))
                            .isTrue();
                    opened.put(bidder, amount.value().longValueExact());
                });

        assertThat(opened).isEqualTo(bids);
        assertThat(opened.entrySet().stream().max(Map.Entry.comparingByValue()).get().getKey())
                .isEqualTo("alice");
    }
}
