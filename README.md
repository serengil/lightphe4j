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
`Lyubashevsky-Peikert-Regev`, `ML-KEM`, `Brakerski-Vaikuntanathan`, `Freeman-Boneh-Goh-Nissim`,
`Gentry-Halevi-Vaikuntanathan`, `Gentry-Sahai-Waters`. It also
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

| Algorithm | Multiplicatively<br>Homomorphic | Additively<br>Homomorphic | Scalar Multiplication | Bitwise-XOR Homomorphic | Bitwise-AND Homomorphic | Regeneration<br>of Ciphertext | Decision Tree<br>Evaluation | Secure<br>Comparison | Encrypted<br>Argmax | Threshold<br>Decryption | Zero-Knowledge<br>Proofs |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| RSA | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| ElGamal | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Exponential ElGamal | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Elliptic Curve ElGamal | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Paillier | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Elliptic Curve Paillier | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Damgard-Jurik | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Benaloh | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Naccache-Stern | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Okamoto-Uchiyama | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Joye-Libert | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Castagnos-Laguillaumie | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Damgard-Geisler-Kroigaard | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| Bresson-Catalano-Pointcheval | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Camenisch-Shoup | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Ishai-Paskin | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| Regev | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Lyubashevsky-Peikert-Regev | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| ML-KEM | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Goldwasser-Micali | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Sander-Young-Yung | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Boneh-Goh-Nissim | 1️⃣ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Freeman-Boneh-Goh-Nissim | 1️⃣ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Brakerski-Vaikuntanathan | 1️⃣ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Gentry-Halevi-Vaikuntanathan | 1️⃣ | ✅ | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Gentry-Sahai-Waters | ✅ | ❌ | ❌ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |

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
    "Lyubashevsky-Peikert-Regev",
    "ML-KEM",
    "Brakerski-Vaikuntanathan",
    "Freeman-Boneh-Goh-Nissim",
    "Gentry-Halevi-Vaikuntanathan",
    "Gentry-Sahai-Waters",
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
| `keySize(Integer)` | key size in bits, defaulting to 1024. For Regev it is the lattice dimension, for Brakerski-Vaikuntanathan, Lyubashevsky-Peikert-Regev and Gentry-Sahai-Waters the ring degree, for ML-KEM the parameter set (512, 768 or 1024), for Freeman-Boneh-Goh-Nissim the bit length of the field size, and for Gentry-Halevi-Vaikuntanathan the lattice dimension in [2, 8] |
| `precision(int)` | digits kept after the decimal point in tensor operations, defaulting to 5 |
| `form(String)` | elliptic curve form: `weierstrass` (default), `edwards` or `koblitz`. Camenisch-Shoup uses it for verifiable encryption |
| `curve(String)` | elliptic curve name, e.g. `secp256k1`, `ed25519`, `k163`. Camenisch-Shoup uses it for verifiable encryption |
| `plaintextLimit(BigInteger)` | upper bound for plaintext values (Benaloh, Sander-Young-Yung, Regev, Brakerski-Vaikuntanathan, Freeman-Boneh-Goh-Nissim, Gentry-Halevi-Vaikuntanathan, Lyubashevsky-Peikert-Regev) |
| `maxTries(int)` | key generation attempts, defaulting to 10000 |
| `boost(String)` | upgrades the algorithm with a transform; `Catalano-Fiore` adds one multiplication to additively homomorphic algorithms |
| `primeOrder(boolean)` | picks the generator of a known prime order while generating ElGamal and Exponential ElGamal keys, which threshold decryption and zero-knowledge proofs require |
| `safePrimes(boolean)` | generates the Paillier or Damgard-Jurik modulus as a product of two safe primes, which proofs of partial decryption require |

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

### Sending ciphertexts over network

Ciphertexts, proofs and messages of interactive protocols can be serialized into json to be sent to another party. Keys are never serialized, the receiver restores ciphertexts with its own public key. `serialize` handles ciphertexts nested in lists and maps, and records such as a ciphertext with its proof, an encrypted update for secure aggregation, or a message sent to the `client` callable of encrypted argmax and nearest neighbor search. The json is the same as the one of the [Python library](https://github.com/serengil/LightPHE), so the two can talk to each other.

```java
// client encrypts its value and sends it to the server
LightPHE clientCs = LightPHE.builder().algorithmName("Paillier").build();
String data = clientCs.serialize(clientCs.encrypt(17));

// server restores the ciphertext with the client's public key only, and computes on it
LightPHE serverCs = LightPHE.builder()
        .algorithmName("Paillier")
        .keys(clientCs.cs().keys().publicOnly())
        .build();
Ciphertext c = serverCs.deserialize(data, Ciphertext.class);
String response = serverCs.serialize(c.add(serverCs.encrypt(25)));

// client decrypts the response
assert clientCs.decrypt(clientCs.deserialize(response, Ciphertext.class)).equals(BigInteger.valueOf(42));

// a single ciphertext can be converted into a map as well
assert clientCs.decrypt(clientCs.fromDict(c.toDict(), Ciphertext.class)).equals(BigInteger.valueOf(17));
```

Records such as `Proven`, `Proof`, `PartialDecryption`, `EncryptedKnnQuery`, `KnnResult` or `EncryptedUpdate` are restored by passing their type to `deserialize`, and lists of them with `deserializeList`. To run an interactive protocol across machines, wrap the network call with the `client` callable:

```java
Function<ArgmaxMessage, List<BigInteger>> client = message -> {
    // e.g. an http request to the client, which answers with
    // clientCs.serialize(clientCs.answerKnn(clientCs.deserialize(body, ArgmaxMessage.class)))
    String body = post(CLIENT_URL, serverCs.serialize(message));
    return serverCs.deserializeList(body, BigInteger.class);
};

KnnResult result = serverCs.evaluateKnn(encryptedQuery, gallery, 2, 16, client);
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

### Hyperplane and naive Bayes classifiers

Together with [decision trees](#decision-trees), Damgard-Geisler-Kroigaard supports the
classifiers of Bost et al. over encrypted data: hyperplane classifiers, e.g. logistic regression or
linear SVM, and naive Bayes. The client encrypts its features, the server evaluates its private
model on them, and finds the predicted class with [encrypted argmax](#encrypted-argmax). The client
learns only the predicted class, and the server learns nothing about the features. Scores of
classes must fit into about 30 bits, so floats must be quantized to integers.

```java
// client encrypts its features: income and debt in thousands, years of employment, late payments
LightPHE clientCs = LightPHE.builder().algorithmName("Damgard-Geisler-Kroigaard").build();
List<Ciphertext> encryptedFeatures =
        Stream.of(85L, 20L, 6L, 0L).map(clientCs::encrypt).toList();

// bank's logistic regression model, quantized by 1000: class 1 approves the loan
LightPHE serverCs = LightPHE.builder()
        .algorithmName("Damgard-Geisler-Kroigaard")
        .keys(Keys.of(clientCs.cs().keys().publicKey(), null))
        .build();
List<List<Long>> weights = List.of(List.of(0L, 0L, 0L, 0L), List.of(42L, -65L, 310L, -900L));
List<Long> biases = List.of(0L, -1200L);

// absolute values of scores must be less than 2^bitLength
Ciphertext encryptedClass = serverCs.evaluateHyperplane(
        encryptedFeatures, weights, 16, clientCs::answerArgmax, biases);
assert clientCs.decrypt(encryptedClass).equals(BigInteger.ONE);
```

Naive Bayes works with categorical features, which the client encrypts as one-hot vectors. The
server quantizes the logarithms of its probabilities, which must be positive, e.g. smoothed with
Laplace smoothing.

```java
// continuing with clientCs and serverCs above
// patient encrypts symptoms: fever (no, yes), cough (none, dry, wet), fatigue (no, yes)
List<List<Ciphertext>> encryptedSymptoms =
        clientCs.encryptNaiveBayesInput(List.of(1, 1, 1), List.of(2, 3, 2));

// clinic's model: P(diagnosis) and P(symptom | diagnosis) for cold, flu and allergy
List<Double> priors = List.of(0.36, 0.36, 0.28);
List<List<List<Double>>> likelihoods = List.of(
        List.of(List.of(0.71, 0.29), List.of(0.12, 0.25, 0.63), List.of(0.71, 0.29)),
        List.of(List.of(0.29, 0.71), List.of(0.12, 0.63, 0.25), List.of(0.29, 0.71)),
        List.of(List.of(0.83, 0.17), List.of(0.57, 0.29, 0.14), List.of(0.67, 0.33)));
Ciphertext diagnosis = serverCs.evaluateNaiveBayes(
        encryptedSymptoms, priors, likelihoods, clientCs::answerArgmax);

// patient learns only the most likely diagnosis: flu
assert clientCs.decrypt(diagnosis).equals(BigInteger.ONE);
```

Scenarios:

- A customer applies for a loan from a mobile app, and the bank runs its credit scoring model on
  the encrypted income and debts, so the customer learns only whether the loan is approved, and the
  bank neither reveals its model nor sees the financial details before the customer agrees to share
  them.
- A patient checks symptoms with an online clinic, whose diagnosis model was trained on years of
  patient records, so the patient learns the most likely diagnosis without revealing the symptoms,
  and the clinic does not give away its model.
- An email client asks a spam filtering service whether a message is spam, and the service
  classifies the encrypted word counts of the message, so it never reads the email.

### Encrypted nearest neighbor search

`lightphe4j` can find the k nearest vectors to an encrypted query, e.g. searching a face embedding
in a gallery, without revealing the query. Embeddings must be quantized to integers first, e.g. by
scaling and rounding. There are two settings.

If the server owns the gallery in plain, the client encrypts its query with
Damgard-Geisler-Kroigaard, and the server finds the nearest vectors with
[encrypted argmax](#encrypted-argmax). The server learns neither the query nor the result, and the
client learns only the indices or labels of the k nearest vectors, neither the distances nor the
other vectors.

```java
import io.github.serengil.lightphe.model.EncryptedKnnQuery;
import io.github.serengil.lightphe.model.KnnResult;

// client encrypts its face embedding, quantized to integers
LightPHE clientCs = LightPHE.builder().algorithmName("Damgard-Geisler-Kroigaard").build();
EncryptedKnnQuery encryptedQuery = clientCs.encryptKnnQuery(List.of(12L, -7L, 33L, 5L));

// server finds the 2 nearest vectors of its gallery - squared distances must fit into bitLength bits
LightPHE serverCs = LightPHE.builder()
        .algorithmName("Damgard-Geisler-Kroigaard")
        .keys(Keys.of(clientCs.cs().keys().publicKey(), null))
        .build();
List<List<Long>> gallery = List.of(
        List.of(10L, -5L, 30L, 4L), List.of(-40L, 22L, 1L, 9L), List.of(13L, -8L, 35L, 6L));
List<Long> people = List.of(101L, 102L, 103L);
KnnResult result = serverCs.evaluateKnn(encryptedQuery, gallery, 2, 16, clientCs::answerKnn, people);

// client learns only who the nearest people are
assert result.labels().stream().map(clientCs::decrypt).toList()
        .equals(List.of(BigInteger.valueOf(103), BigInteger.valueOf(101)));
```

If the gallery itself is stored in an untrusted cloud, the owner encrypts both the gallery and its
queries with the [Catalano-Fiore](#adding-multiplication-support-to-additive-algorithms) boost. The
cloud computes encrypted squared distances with the public key only, and the owner decrypts them to
find the nearest vectors. The cloud learns nothing.

```java
// owner encrypts its gallery once, uploads it, and then encrypts queries
LightPHE ownerCs = LightPHE.builder().algorithmName("Paillier").boost("Catalano-Fiore").build();
List<List<CatalanoFioreCiphertext>> encryptedGallery = gallery.stream()
        .map(vector -> vector.stream().map(ownerCs::encryptBoosted).toList())
        .toList();
List<CatalanoFioreCiphertext> query =
        Stream.of(12L, -7L, 33L, 5L).map(ownerCs::encryptBoosted).toList();

// cloud computes encrypted distances with the public key only
LightPHE cloudCs = LightPHE.builder()
        .algorithmName("Paillier")
        .keys(Keys.of(ownerCs.cs().keys().publicKey(), null))
        .boost("Catalano-Fiore")
        .build();
List<CatalanoFioreCiphertext> encryptedDistances = cloudCs.evaluateKnnDistances(query, encryptedGallery);

// owner decrypts them and finds the nearest vectors
assert ownerCs.decryptKnn(encryptedDistances, 2).indices().equals(List.of(2, 0));
```

Scenarios:

- A user unlocks a door by face, and the building's server matches the encrypted face embedding
  against its gallery of employees, so the server never sees the user's face and the user learns
  only whether they are recognized, not who else is enrolled.
- A bank checks whether a new customer's encrypted face embedding matches anyone on a sanctions
  list held by a screening provider, so the provider does not learn the customer and the bank does
  not get the list.
- A company keeps the face embeddings of its employees in a public cloud, and searches them with
  encrypted queries, so a breach of the cloud reveals neither the gallery nor the queries.
- A retailer recommends products by finding the nearest items to a user's encrypted preference
  vector, so the server does not learn the user's taste.

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

### Threshold decryption

ElGamal, Exponential ElGamal, Elliptic Curve ElGamal, Paillier and Damgard-Jurik support threshold
decryption. ElGamal and Exponential ElGamal keys must be generated with `primeOrder(true)` for
this. A dealer splits the private key into shares, and any `threshold` of `parties` shareholders
decrypt a ciphertext together, whereas fewer shareholders learn nothing. For instance, a board of 5
directors can let any 3 of them decrypt the company's encrypted data, so neither a single director
can read it alone nor losing 2 of them blocks access.

```java
import io.github.serengil.lightphe.model.PartialDecryption;

// dealer splits the private key into 5 shares, any 3 of them can decrypt
LightPHE dealerCs = LightPHE.builder().algorithmName("Paillier").build();
List<Keys> shareKeys = dealerCs.generateThresholdKeys(3, 5);

// dealer forgets the private key, and publishes the public key with threshold parameters
dealerCs.exportKeys(Path.of("public.txt"), true);

// each share key is sent to its own shareholder secretly
List<LightPHE> shareholders = shareKeys.stream()
        .map(keys -> LightPHE.builder().algorithmName("Paillier").keys(keys).build())
        .toList();

// anyone encrypts and computes homomorphically with the public key
LightPHE publicCs = LightPHE.builder()
        .algorithmName("Paillier")
        .keyFile(Path.of("public.txt"))
        .build();
Ciphertext c = publicCs.encrypt(100).add(publicCs.encrypt(50));

// any 3 shareholders decrypt partially, a single partial decryption reveals nothing
List<PartialDecryption> partials = Stream.of(0, 2, 4)
        .map(i -> shareholders.get(i).partialDecrypt(c))
        .toList();

// anyone having the public key combines partial decryptions
assert publicCs.combinePartialDecryptions(c, partials).equals(BigInteger.valueOf(150));
```

Encrypted tensors are decrypted partially with `partialDecryptTensor` and restored with
`combineTensorPartialDecryptions`. The dealer knows the private key while splitting it, so it must
be trusted. By default, partial decryptions are not proven, so a cheating shareholder can cause a
wrong plaintext silently. [Proof of partial decryption](#proof-of-partial-decryption) prevents
this. Exporting keys with `publicOnly = true` drops the share of a shareholder as well.

### Secure aggregation for federated learning

In federated learning, clients train a model on their private data and send only model updates to
a server, but updates can still leak the data. `lightphe4j` lets clients encrypt their updates, the
server sum them without decrypting, and a committee holding shares of the private key decrypt only
the sum with [threshold decryption](#threshold-decryption). Updates are quantized with the precision
of the cryptosystem, and many values are packed into a single ciphertext, so a client encrypts one
ciphertext per chunk instead of one per value. With 1024-bit keys, 40 values fit into a ciphertext.
Paillier and Damgard-Jurik support this.

```java
import io.github.serengil.lightphe.model.Aggregate;
import io.github.serengil.lightphe.model.EncryptedUpdate;

// dealer splits the key among a committee of 5, any 3 of them can decrypt
LightPHE dealerCs = LightPHE.builder().algorithmName("Paillier").safePrimes(true).build();
List<Keys> shareKeys = dealerCs.generateThresholdKeys(3, 5);
List<LightPHE> committee = shareKeys.stream()
        .map(keys -> LightPHE.builder().algorithmName("Paillier").keys(keys).build())
        .toList();
Keys publicKey = Keys.of(dealerCs.cs().keys().publicKey(), null);

// each client encrypts its update with the public key - values must be in [-maxValue, maxValue]
LightPHE clientCs = LightPHE.builder().algorithmName("Paillier").keys(publicKey).build();
List<List<Double>> updates = List.of(
        List.of(0.12, -0.53, 0.98), List.of(0.33, 0.21, -0.47), List.of(-0.25, 0.08, 0.61));
List<EncryptedUpdate> encryptedUpdates = updates.stream()
        .map(update -> clientCs.encryptUpdate(update, 1, 100))
        .toList();

// server sums encrypted updates without decrypting them
LightPHE serverCs = LightPHE.builder().algorithmName("Paillier").keys(publicKey).build();
EncryptedUpdate encryptedSum = serverCs.aggregateUpdates(encryptedUpdates);

// any 3 members decrypt the sum only, and prove their partial decryptions
List<List<PartialDecryption>> partials = committee.subList(0, 3).stream()
        .map(member -> member.partialDecryptAggregate(encryptedSum, true))
        .toList();
Aggregate result = serverCs.combineAggregate(encryptedSum, partials, true);

// mean is [0.0667, -0.08, 0.3733]
assert Math.abs(result.mean().get(1) + 0.08) < 1e-9;
```

The maximum number of clients reserves room in each slot, so that the sum of that many updates
never overflows into the next value, and the server refuses to sum more. Clients must use the same
key, length, precision, maximum value and maximum number of clients. Updates of dropped clients
are simply not summed, and the sum can still be decrypted if up to 2 committee members drop out.
If a single party holds the private key instead of a committee, it restores the sum with
`decryptAggregate`.

Scenarios:

- Hospitals train a model to detect tumors on their own scans, and a central server averages their
  encrypted model updates, so neither the server nor the other hospitals see any hospital's update,
  which could leak information about its patients.
- A keyboard app improves next-word prediction from millions of phones, and a committee of
  independent organizations decrypts only the average update of each round, so no single party,
  including the app maker, can inspect the update of a particular phone.
- Banks build a shared fraud detection model, and verified partial decryptions stop a dishonest
  committee member from slipping a manipulated average into the shared model.

### Zero-knowledge proofs

`lightphe4j` lets you prove facts about ciphertexts and decryptions without revealing the
plaintexts or the private key, and anyone having the public key can verify them. For instance, a
voter proves that a ballot is 0 or 1, an employee proves that an encrypted salary is in a sensible
range, and an authority proves that the announced tally is really what the encrypted tally
contains. A proven value is returned as `Proven<T>`, carrying the value and its `Proof`. Proofs are
made non-interactive with the Fiat-Shamir heuristic, hashing the same transcript as the Python
library.

| Algorithm | Proof of<br>Decryption | Proof of<br>Partial Decryption | Proof of<br>Knowledge | Proof of<br>Allowed Values | Proof of<br>Range | E-Voting | Verifiable<br>Encryption |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ElGamal | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| Exponential ElGamal | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| Elliptic Curve ElGamal | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| Paillier | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| Damgard-Jurik | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| Camenisch-Shoup | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |

ElGamal and Exponential ElGamal keys must be generated with `primeOrder(true)` for proofs. Paillier
and Damgard-Jurik keys must be generated with `safePrimes(true)` for proof of partial decryption.

Proofs take an optional context, public data bound to the proof such as the id of the prover, so a
copied proof is rejected for another context. A context may be `null`, a string, a number, a
boolean, or a list or map of them.

#### Proof of decryption

The private key owner can prove that a ciphertext decrypts to a plaintext, and anyone can check it
with the public key only. ElGamal family uses a Chaum-Pedersen zero-knowledge proof, so the private
key is never revealed. Paillier and Damgard-Jurik reveal the randomness of the ciphertext instead,
which proves the plaintext and reveals nothing about the private key or other ciphertexts.

```java
import io.github.serengil.lightphe.model.Proven;

// private key owner builds the cryptosystem and publishes its public key
LightPHE cs = LightPHE.builder().algorithmName("Exponential-ElGamal").primeOrder(true).build();
cs.exportKeys(Path.of("public.txt"), true);
LightPHE publicCs = LightPHE.builder()
        .algorithmName("Exponential-ElGamal")
        .keyFile(Path.of("public.txt"))
        .build();

Ciphertext c = publicCs.encrypt(17).add(publicCs.encrypt(25));

// private key owner decrypts with a proof
Proven<BigInteger> decryption = cs.decryptWithProof(c);
BigInteger plaintext = decryption.value();

// anyone verifies it with public key only
assert publicCs.verifyDecryption(c, plaintext, decryption.proof());
assert !publicCs.verifyDecryption(c, plaintext.add(BigInteger.ONE), decryption.proof());
```

Scenarios:

- An election authority announces that 5,000 of 8,000 encrypted ballots are yes, and publishes a
  proof, so every voter can check that the announced result is really what the encrypted tally
  contains without trusting the authority.
- A cloud service computes the average salary over encrypted payroll data of a client company and
  decrypts it with a proof, so an external auditor can confirm that the reported average was not
  altered on its way to the board.
- A bank publishes the decrypted total of a day's encrypted transactions together with a proof, so
  a regulator can verify the total without being given the bank's private key or the individual
  transactions.

#### Proof of partial decryption

In [threshold decryption](#threshold-decryption), a cheating shareholder can send a wrong partial
decryption and cause a wrong plaintext silently. A cheating shareholder can even shift the result
by any amount it chooses, e.g. add 50 votes to a party, because lagrange coefficients of other
shareholders are public. Shareholders can opt in to prove that their partial decryptions are
computed with their own shares, and the combiner can opt in to verify them. Then, invalid or
unproven partial decryptions are discarded. Paillier and Damgard-Jurik keys must be generated with
`safePrimes(true)` for this.

```java
// dealer splits the private key into 3 shares, any 2 of them can decrypt
LightPHE dealerCs = LightPHE.builder().algorithmName("Exponential-ElGamal").primeOrder(true).build();
List<LightPHE> shareholders = dealerCs.generateThresholdKeys(2, 3).stream()
        .map(keys -> LightPHE.builder().algorithmName("Exponential-ElGamal").keys(keys).build())
        .toList();

Ciphertext c = dealerCs.encrypt(42);

// shareholders opt in to prove their partial decryptions
List<PartialDecryption> partials = shareholders.stream()
        .map(shareholder -> shareholder.partialDecrypt(c, true))
        .toList();

// anyone verifies a partial decryption with public key only, e.g. to find a cheating shareholder
assert dealerCs.verifyPartialDecryption(c, partials.get(0));

// combiner opts in to verify partial decryptions while combining them
assert dealerCs.combinePartialDecryptions(c, partials, true).equals(BigInteger.valueOf(42));
```

Scenarios:

- Three trustees nominated by competing parties decrypt an election tally together, so a trustee
  who tries to add 50 votes to its own party by tampering with its partial decryption is detected
  and outvoted by the honest two.
- Five hospitals hold shares of a key protecting encrypted patient statistics, and any three of
  them decrypt the yearly average together, so a single hospital cannot quietly bias the published
  average in its favor.
- Servers of a federated learning committee decrypt the sum of encrypted model updates from
  thousands of phones, so a compromised server cannot slip a poisoned update into the global model
  without being caught.
- Two of three auditors are required to open the total of a company's encrypted transactions, so an
  auditor bribed to hide a loss cannot misreport the total.

#### Proof of knowledge

Anyone having the public key can encrypt a value and prove knowledge of it, without revealing it.
Otherwise, someone could copy another one's ciphertext, re-randomize it or modify it
homomorphically, and submit it as their own without knowing the plaintext. The proof is bound to
the ciphertext and a context such as the id of the encryptor.

```java
LightPHE cs = LightPHE.builder().algorithmName("Paillier").build();

// alice submits her sealed bid with a proof of knowledge
Proven<Ciphertext> alice = cs.encryptWithProofOfKnowledge(950, "alice");
assert cs.verifyKnowledge(alice.value(), alice.proof(), "alice");

// mallory outbids alice by adding 1 to her encrypted bid without knowing it, but cannot prove it
Ciphertext malloryBid = alice.value().add(cs.encrypt(1));
assert !cs.verifyKnowledge(malloryBid, alice.proof(), "mallory");
```

Scenarios:

- In a sealed-bid auction, Mallory sees Alice's encrypted bid and submits it plus 1 to win by the
  smallest margin without knowing the amount, but she cannot prove knowledge of that bid, so her
  submission is rejected.
- On a crowdfunding platform, a backer cannot copy a large encrypted pledge of another backer and
  scale it to look generous, because each pledge must come with a proof that its owner knows the
  amount.
- In an encrypted employee survey, a participant cannot re-randomize a colleague's encrypted answer
  and submit it as their own to double its weight, because a re-randomized copy cannot be proven.

#### Proof of allowed values

Anyone having the public key can encrypt a value and prove that it is one of the allowed values,
without revealing which one. Allowed values default to `[0, 1]` when `null` is passed.

```java
LightPHE cs = LightPHE.builder().algorithmName("Paillier").build();
List<Integer> stars = List.of(1, 2, 3, 4, 5);

// a customer rates a product from 1 to 5 stars, and proves it without revealing the rating
Proven<Ciphertext> rating = cs.encryptWithProof(4, stars, "customer-42");

// anyone verifies it with public key only
assert cs.verifyCiphertext(rating.value(), rating.proof(), stars, "customer-42");
assert !cs.verifyCiphertext(rating.value(), rating.proof(), stars, "customer-43");
```

Scenarios:

- An online shop collects encrypted product ratings, and each customer proves that the rating is
  between 1 and 5 stars, so nobody can submit a rating of 1,000 to push the average up while
  individual ratings stay private.
- A company runs an anonymous satisfaction survey with answers from 1 (poor) to 4 (excellent), and
  each employee proves that the encrypted answer is one of them, so the average satisfaction is
  computed homomorphically and a malformed answer cannot corrupt it.
- In [e-voting](#e-voting), each voter proves that the ballot is 0 or 1, so nobody can cast a vote
  of 100 in the homomorphic tally without revealing how they voted.

#### Proof of range

Anyone having the public key can encrypt a value and prove that it is in `[low, high]`, without
revealing it. Proof size grows with the bit length of `high - low`.

```java
LightPHE cs = LightPHE.builder().algorithmName("Paillier").build();

// an employee proves that the encrypted salary is in [0, 500000], so cannot skew the average
Proven<Ciphertext> salary = cs.encryptWithRangeProof(85000, 0, 500000, "alice");

// anyone verifies it with public key only
assert cs.verifyRange(salary.value(), salary.proof(), 0, 500000, "alice");
assert !cs.verifyRange(salary.value(), salary.proof(), 0, 50000, "alice");
```

Scenarios:

- In an industry salary survey, each employee encrypts the salary with a proof that it is between 0
  and 500,000, so a single participant cannot submit a negative or a billion-dollar salary to skew
  the published average.
- A website requires visitors to be adults, and a visitor proves that the encrypted age is between
  18 and 120 without revealing the exact age or birth date.
- In a participatory budget, each citizen allocates up to 1,000 to public projects in encrypted
  form, so allocations are proven to be within the cap while individual preferences stay private.
- A lender accepts an encrypted credit score with a proof that it is between 650 and 850, so the
  applicant shows eligibility without revealing the exact score.

#### E-voting

[Proof of allowed values](#proof-of-allowed-values) makes e-voting possible. Each voter proves that
a ballot is 0 or 1, so cannot cast a vote of 100 in the homomorphic tally. The proof is bound to
the id of the voter, so a copied ballot is rejected. Then, the authority decrypts the tally with a
[proof of decryption](#proof-of-decryption).

```java
// authority builds the cryptosystem and publishes its public key
LightPHE authorityCs =
        LightPHE.builder().algorithmName("Exponential-ElGamal").primeOrder(true).build();
authorityCs.exportKeys(Path.of("public.txt"), true);
LightPHE publicCs = LightPHE.builder()
        .algorithmName("Exponential-ElGamal")
        .keyFile(Path.of("public.txt"))
        .build();

// each voter encrypts a vote of 0 or 1 with a proof, having the public key only
Proven<Ciphertext> alice = publicCs.encryptWithProof(1, null, "alice");
Proven<Ciphertext> bob = publicCs.encryptWithProof(0, null, "bob");

// anyone verifies ballots without decrypting them
assert publicCs.verifyCiphertext(alice.value(), alice.proof(), null, "alice");
assert publicCs.verifyCiphertext(bob.value(), bob.proof(), null, "bob");

// mallory's copy of alice's ballot is rejected
assert !publicCs.verifyCiphertext(alice.value(), alice.proof(), null, "mallory");

// valid ballots are tallied homomorphically, and the authority decrypts the tally with a proof
Ciphertext tally = alice.value().add(bob.value());
Proven<BigInteger> result = authorityCs.decryptWithProof(tally);
assert publicCs.verifyDecryption(tally, result.value(), result.proof());
assert result.value().equals(BigInteger.ONE);
```

For an election of parties, a vote for party `k` can be encrypted as `base^k`, so the tally keeps
the votes of each party in its own digit in that base. The proof guarantees that a voter votes once
for exactly one party. `base` must be greater than the votes a party can get, e.g. 100 allows up to
99 votes per party, and `base^parties` must be less than the modulus. Paillier fits here, as the
tally is a large number.

```java
// a vote for party k is encrypted as 100^k, i.e. 1 for red, 100 for green and 10000 for blue
List<String> parties = List.of("red", "green", "blue");
List<Long> values = List.of(1L, 100L, 10000L);

LightPHE authorityCs = LightPHE.builder().algorithmName("Paillier").build();
Proven<Ciphertext> alice = authorityCs.encryptWithProof(values.get(0), values, "alice");
Proven<Ciphertext> bob = authorityCs.encryptWithProof(values.get(2), values, "bob");
Proven<Ciphertext> carol = authorityCs.encryptWithProof(values.get(0), values, "carol");
assert authorityCs.verifyCiphertext(alice.value(), alice.proof(), values, "alice");

// tally is 2 x 1 + 0 x 100 + 1 x 10000 = 10002, read 2 digits at a time from right: 1 | 00 | 02
Ciphertext tally = alice.value().add(bob.value()).add(carol.value());
BigInteger result = authorityCs.decryptWithProof(tally).value();
assert result.equals(BigInteger.valueOf(10002));
```

Alternatively, for an election of many parties, each voter casts a one-hot ballot, i.e. one
ciphertext per party where only the chosen party is 1, with a proof that exactly one party is
chosen. Summing ballots slot by slot counts the votes of each party separately, so the number of
parties is not limited.

```java
LightPHE authorityCs =
        LightPHE.builder().algorithmName("Exponential-ElGamal").primeOrder(true).build();
List<String> parties = List.of("red", "green", "blue", "yellow");

// each voter encrypts a vote for one party as a one-hot ballot with a proof
Proven<List<Ciphertext>> alice = authorityCs.encryptOneHot(parties.indexOf("red"), 4, "alice");
Proven<List<Ciphertext>> bob = authorityCs.encryptOneHot(parties.indexOf("blue"), 4, "bob");

// anyone verifies ballots without decrypting them
assert authorityCs.verifyOneHot(alice.value(), alice.proof(), "alice");
assert authorityCs.verifyOneHot(bob.value(), bob.proof(), "bob");

// valid ballots are summed slot by slot, so each party's votes are counted in its own ciphertext
List<BigInteger> votes = new ArrayList<>();
for (int k = 0; k < parties.size(); k++) {
    Ciphertext count = alice.value().get(k).add(bob.value().get(k));
    votes.add(authorityCs.decryptWithProof(count).value());
}
assert votes.equals(List.of(BigInteger.ONE, BigInteger.ZERO, BigInteger.ONE, BigInteger.ZERO));
```

Scenarios:

- A city runs a referendum on a new park, and every resident casts an encrypted yes or no ballot
  with a proof, so the city announces the result with a proof of decryption while nobody, including
  the city, learns how an individual voted.
- A national election of a few parties encrypts a vote for party k as `base^k`, so a single
  homomorphic sum and a single decryption reveal the votes of every party at once.
- A national election of dozens of parties uses one-hot ballots of `encryptOneHot` and
  `verifyOneHot`, so each party's votes are counted in its own ciphertext and the number of parties
  is not limited.
- Shareholders of a company vote on the board's proposals, and three independent trustees decrypt
  the tally with [threshold decryption](#threshold-decryption) and
  [proof of partial decryption](#proof-of-partial-decryption), so no single trustee can read or
  alter the result.

#### Verifiable encryption

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

Scenarios:

- Alice escrows the private key of her crypto wallet with a trusted third party, and her bank
  verifies that the escrow really contains the key before granting her a loan, without ever seeing
  the key.
- A company escrows the encryption keys of its employees with a recovery service, so an auditor can
  verify that every key is recoverable if an employee leaves, while neither the auditor nor the
  service can use the keys under normal conditions.
- A crypto exchange verifies that a customer's key is escrowed under conditions agreed with a
  regulator, e.g. release only with a court order, without learning the key itself.

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
quantum computer could solve with Shor's algorithm. Regev, Lyubashevsky-Peikert-Regev, ML-KEM,
Brakerski-Vaikuntanathan and Gentry-Sahai-Waters rely on learning with errors problems instead, which are believed to be hard for quantum computers too.
Their default key sizes give about 128-bit security against quantum attacks.

Regev is additively homomorphic. Its key size is the lattice dimension, and its default is 2048.

```java
LightPHE cs = LightPHE.builder().algorithmName("Regev").build();

Ciphertext c1 = cs.encrypt(1500);
Ciphertext c2 = cs.encrypt(2500);

assert cs.decrypt(c1.add(c2)).equals(BigInteger.valueOf(4000));
assert cs.decrypt(c1.multiply(3)).equals(BigInteger.valueOf(4500));
```

Lyubashevsky-Peikert-Regev is Regev over a polynomial ring, so its security relies on the ring
learning with errors problem like Brakerski-Vaikuntanathan. Its random matrix is replaced by a
single polynomial, so it generates keys and encrypts faster than Regev with the same key and
ciphertext sizes. Its key size is the degree of its polynomial ring, and its default is 2048.

```java
LightPHE cs = LightPHE.builder().algorithmName("Lyubashevsky-Peikert-Regev").build();

Ciphertext c1 = cs.encrypt(1500);
Ciphertext c2 = cs.encrypt(2500);

assert cs.decrypt(c1.add(c2)).equals(BigInteger.valueOf(4000));
assert cs.decrypt(c1.multiply(3)).equals(BigInteger.valueOf(4500));
```

ML-KEM uses the parameter sets standardized by NIST in FIPS 203: ML-KEM-512, ML-KEM-768 and
ML-KEM-1024. It is homomorphic with respect to the exclusive or of 256-bit messages like
Goldwasser-Micali. Its key size is the parameter set, and its default is 768. Notice that this is
the CPA secure public key encryption K-PKE inside ML-KEM, without ciphertext compression and
without the transform that makes ML-KEM CCA secure, because a CCA secure scheme cannot be
homomorphic. So, it is not a FIPS 203 compliant ML-KEM implementation, and its keys and
ciphertexts are not interoperable with other libraries. Its modulus is small, so only a few
ciphertexts can be combined: exclusive or of 6 ciphertexts fails with a probability of about 2^-50
for ML-KEM-768.

```java
LightPHE cs = LightPHE.builder().algorithmName("ML-KEM").build();

BigInteger m1 = new BigInteger("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", 16);
BigInteger m2 = new BigInteger("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321", 16);

Ciphertext c1 = cs.encrypt(m1);
Ciphertext c2 = cs.encrypt(m2);

assert cs.decrypt(c1.xor(c2)).equals(m1.xor(m2));
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

Gentry-Sahai-Waters encrypts bits, and supports both exclusive or and and, so boolean circuits can
be evaluated on encrypted bits with more than one multiplication. Exclusive or is almost free.
Products of products work up to a multiplicative depth of 2, e.g. `(a & b) & (c & d)`, whereas
chains like `acc = acc & fresh`, e.g. carries of a ripple carry adder, can be very long because
each step adds a small fixed noise. Its key size is the degree of its polynomial ring, and its
default is 2048. A ciphertext is about 256 KB.

```java
LightPHE cs = LightPHE.builder().algorithmName("Gentry-Sahai-Waters").build();

Ciphertext a = cs.encrypt(1);
Ciphertext b = cs.encrypt(1);
Ciphertext c = cs.encrypt(0);
Ciphertext d = cs.encrypt(1);

// majority of three bits, and a product of products
assert cs.decrypt(a.and(b).xor(a.and(c)).xor(b.and(c))).equals(BigInteger.ONE);
assert cs.decrypt(a.and(b).and(c.and(d))).equals(BigInteger.ZERO);
```

Every ciphertext of these algorithms carries a small noise, which grows with each homomorphic
operation, and decryption silently fails once it grows too much. With default settings,
plaintexts must be less than 2^24. Regev and Lyubashevsky-Peikert-Regev have room for thousands of additions or multiplications
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
