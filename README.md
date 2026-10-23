# lightphe4j

<div align="center">

[![Stars](https://img.shields.io/github/stars/serengil/lightphe4j?color=yellow&style=flat&label=%E2%AD%90%20stars)](https://github.com/serengil/lightphe4j/stargazers)
[![License](http://img.shields.io/:license-MIT-green.svg?style=flat)](https://github.com/serengil/lightphe4j/blob/main/LICENSE)
[![DOI](http://img.shields.io/:DOI-10.3390/sym18050832-blue.svg?style=flat)](https://www.mdpi.com/2073-8994/18/5/832)

</div>

`lightphe4j` is a lightweight homomorphic encryption library for Java supporting various partially
and somewhat homomorphic encryption schemes such as
[`RSA`](https://sefiks.com/2023/03/06/a-step-by-step-partially-homomorphic-encryption-example-with-rsa-in-python/),
[`ElGamal`](https://sefiks.com/2023/03/27/a-step-by-step-partially-homomorphic-encryption-example-with-elgamal-in-python/),
[`Exponential ElGamal`](https://sefiks.com/2023/03/27/a-step-by-step-partially-homomorphic-encryption-example-with-elgamal-in-python/),
[`Elliptic Curve ElGamal`](https://sefiks.com/2018/08/21/elliptic-curve-elgamal-encryption/)
([`Weierstrass`](https://sefiks.com/2016/03/13/the-math-behind-elliptic-curve-cryptography/),
[`Koblitz`](https://sefiks.com/2016/03/13/the-math-behind-elliptic-curves-over-binary-field/) and
[`Edwards`](https://sefiks.com/2018/12/19/a-gentle-introduction-to-edwards-curves/) forms),
[`Paillier`](https://sefiks.com/2023/04/03/a-step-by-step-partially-homomorphic-encryption-example-with-paillier-in-python/),
[`Damgard-Jurik`](https://sefiks.com/2023/10/20/a-step-by-step-partially-homomorphic-encryption-example-with-damgard-jurik-in-python/),
[`Okamoto–Uchiyama`](https://sefiks.com/2023/10/20/a-step-by-step-partially-homomorphic-encryption-example-with-okamoto-uchiyama-in-python/),
[`Benaloh`](https://sefiks.com/2023/10/06/a-step-by-step-partially-homomorphic-encryption-example-with-benaloh-in-python-from-scratch/),
[`Naccache–Stern`](https://sefiks.com/2023/10/26/a-step-by-step-partially-homomorphic-encryption-example-with-naccache-stern-in-python/),
[`Goldwasser–Micali`](https://sefiks.com/2023/10/27/a-step-by-step-partially-homomorphic-encryption-example-with-goldwasser-micali-in-python/),
[`Sander-Young-Yung`](https://sefiks.com/2026/04/02/a-step-by-step-partially-homomorphic-sander-young-yung-example-in-python/) and
[`Boneh-Goh-Nissim`](https://sefiks.com/2026/04/02/a-step-by-step-somewhat-homomorphic-encryption-example-with-boneh-goh-nissim-in-python/),
`Joye-Libert`, `Castagnos-Laguillaumie`, `Ishai-Paskin`, `Damgard-Geisler-Kroigaard`,
`Bresson-Catalano-Pointcheval`, `Camenisch-Shoup`, `Elliptic Curve Paillier`, `Regev`,
`Brakerski-Vaikuntanathan`, `Freeman-Boneh-Goh-Nissim`, `Gentry-Halevi-Vaikuntanathan`. It also
supports [`Catalano-Fiore`](#adding-multiplication-support-to-additive-algorithms) transform to add
one multiplication to additively homomorphic ones.

It is a pure Java port of [LightPHE](https://github.com/serengil/LightPHE), with the elliptic curve
arithmetic of [LightECC](https://github.com/serengil/LightECC) folded in.

Homomorphic encryption lets a party compute on ciphertexts without ever seeing the plaintexts or
holding the private key. That is what makes it possible to offload work to a cloud you do not
trust: the cloud adds, multiplies or combines encrypted values, and only you can read the result.

## Partially vs fully homomorphic encryption

Even though fully homomorphic encryption (FHE) has become available in recent times, when
considering the trade-offs `lightphe4j` emerges as a more efficient and practical choice. If your
specific task does not demand the full homomorphic capabilities, opting for partial homomorphism is
the logical decision.

- 🏎️ Notably faster
- 💻 Demands fewer computational resources
- 📏 Generating much smaller ciphertexts
- 🔑 Distributing much smaller keys
- 🧠 Well-suited for memory-constrained environments
- ⚖️ Strikes a favorable balance for practical use cases

## Installation [![Maven Central](https://img.shields.io/maven-central/v/io.github.serengil/lightphe4j.svg?label=Maven%20Central)](https://central.sonatype.com/artifact/io.github.serengil/lightphe4j)

Requires **Java 17 or newer**. 

To install it via [maven](https://repo1.maven.org/maven2/io/github/serengil/lightphe4j/), add the dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>io.github.serengil</groupId>
    <artifactId>lightphe4j</artifactId>
    <version>0.0.28</version>
</dependency>
```

Then import the entry point:

```java
import io.github.serengil.lightphe.LightPHE;
```

## Summary of homomorphic features of different cryptosystems

| Algorithm | Multiplicatively<br>Homomorphic | Additively<br>Homomorphic | Scalar Multiplication | Bitwise-XOR Homomorphic | Bitwise-AND Homomorphic | Regeneration<br>of Ciphertext | Decision Tree<br>Evaluation | Secure<br>Comparison | Encrypted<br>Argmax |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| RSA | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| ElGamal | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Exponential ElGamal | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Elliptic Curve ElGamal | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Paillier | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Elliptic Curve Paillier | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Damgard-Jurik | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Benaloh | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Naccache-Stern | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Okamoto-Uchiyama | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Joye-Libert | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Castagnos-Laguillaumie | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Damgard-Geisler-Kroigaard | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ |
| Bresson-Catalano-Pointcheval | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Camenisch-Shoup | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Ishai-Paskin | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| Regev | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Goldwasser-Micali | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Sander-Young-Yung | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ |
| Boneh-Goh-Nissim | 1️⃣ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Freeman-Boneh-Goh-Nissim | 1️⃣ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Brakerski-Vaikuntanathan | 1️⃣ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |
| Gentry-Halevi-Vaikuntanathan | 1️⃣ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ |

1️⃣ Boneh-Goh-Nissim, Freeman-Boneh-Goh-Nissim, Brakerski-Vaikuntanathan and
Gentry-Halevi-Vaikuntanathan support one multiplication natively. Most additively homomorphic
algorithms can support one multiplication with
[Catalano-Fiore transform](#adding-multiplication-support-to-additive-algorithms) as well.

## Building a cryptosystem

Building a cryptosystem generates a private and public key pair.

```java
import io.github.serengil.lightphe.LightPHE;

String[] algorithms = {
    "RSA",
    "ElGamal",
    "Exponential-ElGamal",
    "Paillier",
    "Damgard-Jurik",
    "Okamoto-Uchiyama",
    "Benaloh",
    "Naccache-Stern",
    "Goldwasser-Micali",
    "EllipticCurve-ElGamal",
    "Sander-Young-Yung",
    "Boneh-Goh-Nissim",
    "Joye-Libert",
    "Castagnos-Laguillaumie",
    "Ishai-Paskin",
    "Damgard-Geisler-Kroigaard",
    "Bresson-Catalano-Pointcheval",
    "Camenisch-Shoup",
    "EllipticCurve-Paillier",
    "Regev",
    "Brakerski-Vaikuntanathan",
    "Freeman-Boneh-Goh-Nissim",
    "Gentry-Halevi-Vaikuntanathan",
};

LightPHE cs = LightPHE.builder()
        .algorithmName(algorithms[0])
        .build();
```

The builder carries every optional parameter:

| Builder method | Meaning |
| --- | --- |
| `algorithmName(String)` | which cryptosystem to build (required) |
| `keys(Keys)` | an existing private-public key pair |
| `keyFile(Path)` | load a previously exported key pair from disk |
| `keySize(Integer)` | key size in bits, defaulting to 1024. For Regev it is the lattice dimension, for Brakerski-Vaikuntanathan the ring degree, for Freeman-Boneh-Goh-Nissim the bit length of the field size, and for Gentry-Halevi-Vaikuntanathan the lattice dimension in [2, 8] |
| `precision(int)` | digits kept after the decimal point in tensor operations, defaulting to 5 |
| `form(String)` | elliptic curve form: `weierstrass` (default), `edwards` or `koblitz`. Camenisch-Shoup uses it for verifiable encryption |
| `curve(String)` | elliptic curve name, e.g. `secp256k1`, `ed25519`, `k163`. Camenisch-Shoup uses it for verifiable encryption |
| `plaintextLimit(BigInteger)` | upper bound for plaintext values (Benaloh, Sander-Young-Yung, Regev, Brakerski-Vaikuntanathan, Freeman-Boneh-Goh-Nissim, Gentry-Halevi-Vaikuntanathan) |
| `maxTries(int)` | key generation attempts, defaulting to 10000 |
| `boost(String)` | upgrades the algorithm with a transform; `Catalano-Fiore` adds one multiplication to additively homomorphic algorithms |

## Homomorphic operations

The following example demonstrates a simple workflow with an additively homomorphic cryptosystem.
First we build the cryptosystem on premises and define two plaintext values. Next we encrypt them,
which can be done either on premises or in the cloud and does not require the private key.
Homomorphic operations such as addition and scalar multiplication can then be performed on the
ciphertexts — these can be offloaded to the cloud, leveraging its computational power without
revealing the private key or the plaintext. Finally the results are decrypted on premises using the
private key.

```java
import io.github.serengil.lightphe.LightPHE;
import io.github.serengil.lightphe.model.Ciphertext;
import java.math.BigInteger;

// build an additively homomorphic cryptosystem
LightPHE cs = LightPHE.builder().algorithmName("Paillier").build();

// define plaintexts
long m1 = 10000;   // base salary in usd
long m2 = 500;     // wage increase in usd

// encrypt plaintexts - the private key is not required
Ciphertext c1 = cs.encrypt(m1);
Ciphertext c2 = cs.encrypt(m2);

// homomorphic addition - the private key is not required
Ciphertext c3 = c1.add(c2);

// homomorphic scalar multiplication - the private key is not required
double k = 1.05;   // increase something by 5%
Ciphertext c4 = c1.multiply(k);

// decryption - the private key is required
assert cs.decrypt(c3).equals(BigInteger.valueOf(m1 + m2));
assert cs.decrypt(c4).equals(BigInteger.valueOf(10500));
```

If you adopt a multiplicatively homomorphic cryptosystem instead, such as RSA or ElGamal, you can
multiply ciphertexts without revealing the private key or the plaintext.

```java
// build a multiplicatively homomorphic cryptosystem
LightPHE cs = LightPHE.builder().algorithmName("RSA").build();

long m1 = 17;
long m2 = 21;

Ciphertext c1 = cs.encrypt(m1);
Ciphertext c2 = cs.encrypt(m2);

// homomorphic multiplication
Ciphertext c3 = c1.multiply(c2);

assert cs.decrypt(c3).equals(BigInteger.valueOf(m1 * m2));
```

### Ciphertext regeneration

Most homomorphic algorithms let you regenerate a ciphertext without breaking plaintext restoration.
You may repeat this many times to obtain stronger ciphertexts.

```java
Ciphertext c1Prime = cs.regenerateCiphertext(c1);

assert !c1Prime.value().equals(c1.value());
assert cs.decrypt(c1Prime).equals(BigInteger.valueOf(m1));
assert cs.decrypt(c1).equals(BigInteger.valueOf(m1));
```

### Elliptic curve cryptography

ECC is a powerful public-key cryptosystem based on the algebraic structure of elliptic curves over
finite fields. This library supports 3 elliptic curve forms — Weierstrass (default), Edwards and
Koblitz — and 100+ standard curve configurations.

The [Elliptic Curve ElGamal](https://sefiks.com/2018/08/21/elliptic-curve-elgamal-encryption/)
scheme is implemented, offering a secure and efficient homomorphic encryption option.

```java
LightPHE phe = LightPHE.builder()
        .algorithmName("EllipticCurve-ElGamal")
        .form("edwards")
        // .curve("ed448")   // optionally pick a specific curve for the given form
        .build();
```

One of the crucial factors defining the security level of an elliptic curve cryptosystem is the
order of the curve: the number of points on it. A higher order typically corresponds to a stronger
cryptosystem, but comes with a trade-off in computational efficiency, so choosing the curve order is
a decision based on your application's security and performance requirements.

You can enumerate what is available:

```java
import io.github.serengil.lightphe.ecc.curves.CurveForm;
import io.github.serengil.lightphe.ecc.curves.CurveRegistry;

List<String> edwardsCurves = CurveRegistry.listCurves(CurveForm.EDWARDS);
```

See [`curves`](https://github.com/serengil/LightECC#supported-curves) page for a list of all supported forms, curves and their details.

### Decision trees

LightPHE can evaluate decision trees privately. Suppose a bank has a secret decision tree that
decides a customer's credit limit, and a customer has private data. The bank does not want to
reveal its tree, and the customer does not want to reveal their data. The customer sends encrypted
data, the bank runs its tree on it without seeing it, and only the customer can decrypt the
result. The customer learns the credit limit but not the rest of the tree. Two cryptosystems
support this: Ishai-Paskin for trees on yes / no answers, and Damgard-Geisler-Kroigaard for trees
on numeric features.

#### Decision trees with nominal decisions

Ishai-Paskin evaluates trees whose questions have yes / no answers, in a single round: the customer
sends encrypted answers, and the bank sends back the encrypted result.

Let the bank's tree be the following, where questions are numbered 0, 1 and 2 and leaves are
credit limits in thousand dollars.

```
                  Q0: has stable income?
                 /no                    \yes
     Q2: owns a house?              Q1: has existing debt?
       /no        \yes               /no           \yes
      0            5               20         Q2: owns a house?
                                                /no       \yes
                                               5          10
```

Each question is written as `node(question number, what to do if no, what to do if yes)`, and
leaves are `leaf(value)`. So, the tree above becomes:

```java
import static io.github.serengil.lightphe.model.DecisionTree.leaf;
import static io.github.serengil.lightphe.model.DecisionTree.node;

import io.github.serengil.lightphe.model.DecisionTree;

DecisionTree creditLimitTree =
        node(0, node(2, leaf(0), leaf(5)), node(1, leaf(20), node(2, leaf(5), leaf(10))));
```

Then, the customer and the bank run the following steps.

```java
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.List;

// customer builds the cryptosystem and keeps the private key
LightPHE customerCs = LightPHE.builder().algorithmName("Ishai-Paskin").build();

// customer shares only the public key with the bank
customerCs.exportKeys(Path.of("public.txt"), true);

// customer's answers: stable income = yes, existing debt = yes, owns a house = no
List<Integer> answers = List.of(1, 1, 0);

// customer encrypts the answers and sends them to the bank. depth is the maximum
// number of questions on a path of the tree, the bank should share this value
List<List<BigInteger>> encryptedAnswers = customerCs.encryptDecisionTreeInput(answers, 3);

// bank builds its own cryptosystem with the customer's public key
LightPHE bankCs = LightPHE.builder()
        .algorithmName("Ishai-Paskin")
        .keyFile(Path.of("public.txt"))
        .build();

// bank runs its tree on encrypted answers and sends the result back to the customer
Ciphertext encryptedLimit = bankCs.evaluateDecisionTree(creditLimitTree, encryptedAnswers);

// customer decrypts the result - only the customer has the private key
assert customerCs.decrypt(encryptedLimit).equals(BigInteger.valueOf(5));
```

The size of the result grows with the depth of the tree, not with the number of its nodes. Still,
each extra level makes the computation noticeably slower, so this is practical for shallow trees.

#### Decision trees with numeric decisions

Damgard-Geisler-Kroigaard evaluates decision trees with numeric thresholds instead of yes / no
answers, using the secure comparison protocol below at each node. It requires a few rounds of
interaction between the customer and the bank, but its cost grows linearly with the number of
nodes.

Let the bank's tree be the following, where features are numbered 0 (age), 1 (income in thousand
dollars) and 2 (number of open loans), and leaves are credit limits in thousand dollars.

```
                  F1: income <= 40?
                 /yes                \no
       F0: age <= 25?          F2: open loans <= 2?
        /yes      \no            /yes           \no
       0           5            20              10
```

Each decision node is written as `node(feature index, threshold, what to do if feature <=
threshold, what to do otherwise)`, and leaves are `leaf(value)`. So, the tree above becomes:

```java
import static io.github.serengil.lightphe.model.NumericDecisionTree.leaf;
import static io.github.serengil.lightphe.model.NumericDecisionTree.node;

import io.github.serengil.lightphe.model.NumericDecisionTree;

NumericDecisionTree creditLimitTree =
        node(1, 40, node(0, 25, leaf(0), leaf(5)), node(2, 2, leaf(20), leaf(10)));
```

Then, the customer and the bank run the following steps.

```java
// customer: age = 30, income = 75 and open loans = 1
// so, the expected path is income > 40 -> open loans <= 2 -> credit limit of 20
LightPHE customerCs = LightPHE.builder().algorithmName("Damgard-Geisler-Kroigaard").build();
List<List<BigInteger>> encryptedFeatures =
        customerCs.encryptDecisionTreeFeatures(List.of(30L, 75L, 1L), 8);

// bank, having the customer's public key only
LightPHE bankCs = LightPHE.builder()
        .algorithmName("Damgard-Geisler-Kroigaard")
        .keyFile(Path.of("public.txt"))
        .build();
NumericDecisionTree.Comparisons comparisons =
        bankCs.evaluateDecisionTreeComparisons(creditLimitTree, encryptedFeatures);

// customer answers randomly flipped comparisons, so cannot follow the path in the tree
List<BigInteger> encryptedAnswers =
        customerCs.answerDecisionTreeComparisons(comparisons.encryptedComparisons());

// bank keeps the server state secret and finds the reached leaf in encrypted form
List<NumericDecisionTree.EncryptedLeaf> encryptedLeaves =
        bankCs.evaluateDecisionTreeLeaves(comparisons.serverState(), encryptedAnswers);

// customer learns only the credit limit
assert customerCs.decryptDecisionTreeOutput(encryptedLeaves) == 20;
```

### Secure comparison

Damgard-Geisler-Kroigaard lets a client and a server find out whether the client's private value
is less than or equal to the server's private value, without revealing the values to each other.
For instance, a bidder can check whether their bid beats the reserve price of an auction.

```java
// client encrypts its value bit by bit
LightPHE clientCs = LightPHE.builder().algorithmName("Damgard-Geisler-Kroigaard").build();
List<BigInteger> encryptedBid = clientCs.encryptComparisonInput(120, 16);

// server compares it with its own value having the client's public key only
LightPHE serverCs = LightPHE.builder()
        .algorithmName("Damgard-Geisler-Kroigaard")
        .keyFile(Path.of("public.txt"))
        .build();
List<BigInteger> encryptedResult = serverCs.evaluateComparison(encryptedBid, 150);

// client learns only whether bid <= reserve price
assert clientCs.decryptComparison(encryptedResult);
```

### Encrypted argmax

Damgard-Geisler-Kroigaard can also find the index of the maximum among encrypted values. For
instance, a server can compute encrypted class scores of a linear classifier on a client's
encrypted features, and then find the predicted class. The client learns only the index, neither
the scores nor the intermediate comparisons, and the server learns nothing. The protocol needs a
few round trips per value, so the server talks to the client through a callable. Locally, it can
be the client's `answerArgmax` directly. Otherwise, wrap your network call with it - every
`ArgmaxMessage` reports its `type()` for that purpose.

```java
// client encrypts its features
LightPHE clientCs = LightPHE.builder().algorithmName("Damgard-Geisler-Kroigaard").build();
List<Ciphertext> encryptedFeatures = new ArrayList<>();
for (long feature : new long[] {3, 1, 4}) {
    encryptedFeatures.add(clientCs.encrypt(feature));
}

// server computes class scores with its private weights homomorphically
LightPHE serverCs = LightPHE.builder()
        .algorithmName("Damgard-Geisler-Kroigaard")
        .keyFile(Path.of("public.txt"))
        .build();
long[][] weights = {{1, 2, 0}, {0, 1, 3}, {2, 0, 1}};
List<Ciphertext> encryptedScores = new ArrayList<>();
for (long[] classWeights : weights) {
    Ciphertext score = encryptedFeatures.get(0).multiply(classWeights[0]);
    for (int i = 1; i < classWeights.length; i++) {
        score = score.add(encryptedFeatures.get(i).multiply(classWeights[i]));
    }
    encryptedScores.add(score);
}

// server finds the argmax with the client's help - scores must fit into bitLength bits
Ciphertext encryptedClass = serverCs.evaluateArgmax(encryptedScores, 8, clientCs::answerArgmax);

// client learns only the predicted class
assert clientCs.decrypt(encryptedClass).equals(BigInteger.ONE);
```

### Master key decryption

Bresson-Catalano-Pointcheval has two ways to decrypt a ciphertext. Each user decrypts with its own
private key, while an authority holding the master key decrypts ciphertexts of all users. For
instance, a company can let every employee encrypt with their own key, and still recover the data
if an employee leaves. Keep in mind that the master key holder can read everything by design.

```java
// authority generates the master key and publishes its public key
LightPHE authorityCs = LightPHE.builder().algorithmName("Bresson-Catalano-Pointcheval").build();
authorityCs.exportKeys(Path.of("public.txt"), true);

// each user generates its own key pair with the public key of the authority
LightPHE publicCs = LightPHE.builder()
        .algorithmName("Bresson-Catalano-Pointcheval")
        .keyFile(Path.of("public.txt"))
        .build();
LightPHE aliceCs = LightPHE.builder()
        .algorithmName("Bresson-Catalano-Pointcheval")
        .keys(publicCs.generateUserKeys())
        .build();
LightPHE bobCs = LightPHE.builder()
        .algorithmName("Bresson-Catalano-Pointcheval")
        .keys(publicCs.generateUserKeys())
        .build();

Ciphertext aliceCiphertext = aliceCs.encrypt(100).add(aliceCs.encrypt(50));
Ciphertext bobCiphertext = bobCs.encrypt(200);

// users decrypt their own ciphertexts only
assert aliceCs.decrypt(aliceCiphertext).equals(BigInteger.valueOf(150));
assert !aliceCs.decrypt(bobCiphertext).equals(BigInteger.valueOf(200));

// authority decrypts ciphertexts of all users
assert authorityCs.decryptWithMasterKey(aliceCiphertext).equals(BigInteger.valueOf(150));
assert authorityCs.decryptWithMasterKey(bobCiphertext).equals(BigInteger.valueOf(200));
```

Encrypted tensors of any user are decrypted with `decryptTensorWithMasterKey` in the same way.

### Verifiable encryption

Camenisch-Shoup lets you encrypt a secret for someone else and prove that the ciphertext really
contains it, without revealing the secret. For instance, Alice can escrow the private key of her
crypto wallet with a trusted third party. A bank, which knows only her public key, verifies that
the escrowed ciphertext contains its private key, and the trusted third party can recover it only
under the conditions written in the label.

```java
import io.github.serengil.lightphe.ecc.CurvePoint;
import io.github.serengil.lightphe.ecc.LightECC;
import io.github.serengil.lightphe.model.VerifiableCiphertext;

// trusted third party builds the cryptosystem and publishes its public key
LightPHE ttpCs = LightPHE.builder().algorithmName("Camenisch-Shoup").build();
ttpCs.exportKeys(Path.of("public.txt"), true);

// alice's wallet key pair on secp256k1
LightECC ecc = LightECC.of("weierstrass", "secp256k1");
BigInteger privateKey = BigInteger.valueOf(123456789);
CurvePoint publicKey = ecc.g().multiply(privateKey);

// alice encrypts her private key for the trusted third party with a proof
String label = "release only if alice loses access to her wallet";
LightPHE aliceCs = LightPHE.builder()
        .algorithmName("Camenisch-Shoup")
        .keyFile(Path.of("public.txt"))
        .build();
VerifiableCiphertext escrow = aliceCs.encryptVerifiably(privateKey, label);

// bank verifies it with public keys only, without learning alice's private key
LightPHE bankCs = LightPHE.builder()
        .algorithmName("Camenisch-Shoup")
        .keyFile(Path.of("public.txt"))
        .build();
assert bankCs.verifyEncryption(escrow, publicKey, label);

// trusted third party recovers the private key under the same label only
assert ttpCs.decryptVerifiableCiphertext(escrow, label).equals(privateKey);
```

Private keys of other curves can be escrowed by passing `form` and `curve` while building the
cryptosystem. Verifiable ciphertexts reject any modification, so homomorphic operations are
applied to regular ciphertexts created with `encrypt`. Proofs are interoperable with the Python
library.

### Adding multiplication support to additive algorithms

Additively homomorphic algorithms cannot multiply two ciphertexts. Boosting them with
Catalano-Fiore transform adds one multiplication on top of them, without changing the algorithms
themselves. This lets you evaluate degree-2 functions on encrypted data, such as dot products of
two encrypted vectors, variances or squared distances. It supports Paillier, Damgard-Jurik,
Bresson-Catalano-Pointcheval, Camenisch-Shoup, Elliptic Curve Paillier, Joye-Libert,
Castagnos-Laguillaumie, Naccache-Stern, Benaloh and Damgard-Geisler-Kroigaard. A boosted
cryptosystem encrypts with `encryptBoosted`, which returns a `CatalanoFioreCiphertext`.

```java
import io.github.serengil.lightphe.model.CatalanoFioreCiphertext;

// client builds a boosted cryptosystem, and encrypts its private vectors
LightPHE clientCs = LightPHE.builder()
        .algorithmName("Paillier")
        .boost("Catalano-Fiore")
        .build();

long[] x = {3, 1, 4};
long[] y = {1, 5, 9};
List<CatalanoFioreCiphertext> encryptedX = new ArrayList<>();
List<CatalanoFioreCiphertext> encryptedY = new ArrayList<>();
for (int i = 0; i < x.length; i++) {
    encryptedX.add(clientCs.encryptBoosted(x[i]));
    encryptedY.add(clientCs.encryptBoosted(y[i]));
}

// server computes dot product and squared euclidean distance of encrypted vectors
// ciphertexts carry the public key only
CatalanoFioreCiphertext encryptedDot = encryptedX.get(0).multiply(encryptedY.get(0));
CatalanoFioreCiphertext difference = encryptedX.get(0).subtract(encryptedY.get(0));
CatalanoFioreCiphertext encryptedDistance = difference.multiply(difference);
for (int i = 1; i < x.length; i++) {
    encryptedDot = encryptedDot.add(encryptedX.get(i).multiply(encryptedY.get(i)));
    difference = encryptedX.get(i).subtract(encryptedY.get(i));
    encryptedDistance = encryptedDistance.add(difference.multiply(difference));
}

// client decrypts the results
assert clientCs.decrypt(encryptedDot).equals(BigInteger.valueOf(44));
assert clientCs.decrypt(encryptedDistance).equals(BigInteger.valueOf(45));
```

Multiplied ciphertexts can be added and multiplied with constants, but not multiplied with
ciphertexts again. They keep a pair of ciphertexts for every product, so a dot product of length
d grows d times. Only integers are supported.

### Post-quantum security

Most algorithms in LightPHE rely on factoring or discrete logarithm problems, which a large enough
quantum computer could solve with Shor's algorithm. Regev and Brakerski-Vaikuntanathan rely on
learning with errors problems instead, which are believed to be hard for quantum computers too.
Their default key sizes give about 128-bit security against quantum attacks.

Regev is additively homomorphic. Its key size is the lattice dimension, and its default is 2048.

```java
LightPHE cs = LightPHE.builder().algorithmName("Regev").build();

Ciphertext c1 = cs.encrypt(1500);
Ciphertext c2 = cs.encrypt(2500);

assert cs.decrypt(c1.add(c2)).equals(BigInteger.valueOf(4000));
assert cs.decrypt(c1.multiply(3)).equals(BigInteger.valueOf(4500));
```

Brakerski-Vaikuntanathan additionally supports one multiplication of ciphertexts like
Boneh-Goh-Nissim, but without pairings. Its key size is the degree of its polynomial ring, and its
default is 4096.

```java
LightPHE cs = LightPHE.builder().algorithmName("Brakerski-Vaikuntanathan").build();

Ciphertext c1 = cs.encrypt(15);
Ciphertext c2 = cs.encrypt(25);
Ciphertext c3 = cs.encrypt(100);

// one multiplication, then additions and multiplications with constants
assert cs.decrypt(c1.multiply(c2).add(c3)).equals(BigInteger.valueOf(475));
assert cs.decrypt(c1.multiply(c2).multiply(2).add(c1.multiply(c3)))
        .equals(BigInteger.valueOf(2250));
```

Every ciphertext of these algorithms carries a small noise, which grows with each homomorphic
operation, and decryption silently fails once it grows too much. With default settings,
plaintexts must be less than 2^24. Regev has room for thousands of additions or multiplications
with constants up to a few thousands, and a product of Brakerski-Vaikuntanathan has room for
millions of times more noise. You can increase the plaintext space with `plaintextLimit` in
exchange of less room for noise. Floats and tensors are not supported. Public matrices are expanded
from a seed with SHAKE-128 exactly as the Python library does, so exported keys are interoperable.

### Vector embeddings

Homomorphic encryption also works on vector embeddings, which is useful in privacy-preserving
machine learning, secure aggregation and confidential data processing.

```java
import io.github.serengil.lightphe.model.EncryptedTensor;
import java.util.List;

// build an additively homomorphic cryptosystem
LightPHE cs = LightPHE.builder().algorithmName("Paillier").build();

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

// proof of work
List<Double> restored = cs.decryptTensor(c4);
```

Encrypting a tensor runs in parallel across the common fork-join pool, so a large embedding is
encrypted on every available core.

### Key management

Keys can be exported to and restored from disk. The exported format is byte-for-byte the JSON the
Python library writes, so key files can be exchanged between the two implementations.

```java
import java.nio.file.Path;

LightPHE onPrem = LightPHE.builder().algorithmName("Paillier").build();

// export the full key pair, and a public-only copy safe to publish
onPrem.exportKeys(Path.of("secret.json"));
onPrem.exportKeys(Path.of("public.json"), true);

// a party holding only the public key can encrypt and evaluate, but not decrypt
LightPHE cloud = LightPHE.builder()
        .algorithmName("Paillier")
        .keyFile(Path.of("public.json"))
        .build();
```

Building a cryptosystem from a supplied key pair validates it first: a missing `public_key` section
or a missing required sub-field is rejected with an `IllegalArgumentException` naming exactly what
is absent.

## LightPHE Ecosystem

`LightPHE` is available across multiple programming languages with consistent APIs and native performance for each ecosystem. Choose the port that fits your stack:

| Language | Repository | Ecosystem Focus |
| :--- | :--- | :--- |
| **Python** | [`lightphe`](https://github.com/serengil/lightphe) | AI, Research & Prototyping |
| **Go** | [`lightphe-go`](https://github.com/serengil/lightphe-go) | Cloud-Native & High-Throughput Microservices |
| **Java** | [`lightphe4j`](https://github.com/serengil/lightphe4j) | Enterprise, Banking & Legacy Systems |
| **TypeScript** | [`lightphe-ts`](https://github.com/serengil/lightphe-ts) | Client-Side Privacy & Node.js Backend |

## Support

There are many ways to support a project — starring ⭐️ the GitHub repo is just one 🙏

You can also support this work on [Patreon](https://www.patreon.com/serengil?repo=lightphe),
[GitHub Sponsors](https://github.com/sponsors/serengil) or
[Buy Me a Coffee](https://buymeacoffee.com/serengil).

## Citation

Please cite LightPHE in your publications if it helps your research. Here is its BibTeX entry:

```BibTeX
@article{lightphe4j,
  title          = {Sustainable Cryptography: Carbon Asymmetry in Partially Homomorphic Encryption in the Cloud},
  author         = {Ozpinar, Alper and Serengil, Sefik Ilkin},
  journal        = {Symmetry},
  volume         = {18},
  number         = {5},
  pages          = {832},
  url            = {https://www.mdpi.com/2073-8994/18/5/832},
  doi            = {10.3390/sym18050832},
  note           = {Special Issue: Symmetry in Cryptography and Cybersecurity},
  year           = {2026}
}
```

## License

`lightphe4j` is licensed under the MIT License — see [`LICENSE`](LICENSE) for more details.
