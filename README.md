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
[`Boneh-Goh-Nissim`](https://sefiks.com/2026/04/02/a-step-by-step-somewhat-homomorphic-encryption-example-with-boneh-goh-nissim-in-python/).

It is a pure Java port of [LightPHE](https://github.com/serengil/LightPHE), with the elliptic curve
arithmetic of [LightECC](https://github.com/serengil/LightECC) folded in. It depends on nothing but
SLF4J at runtime.

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
    <version>0.0.25</version>
</dependency>
```

Then import the entry point:

```java
import io.github.serengil.lightphe.LightPHE;
```

## Summary of homomorphic features of different cryptosystems

| Algorithm | Multiplicatively<br>Homomorphic | Additively<br>Homomorphic | Scalar Multiplication | Bitwise-XOR Homomorphic | Bitwise-AND Homomorphic | Regeneration<br>of Ciphertext |
| --- | --- | --- | --- | --- | --- | --- |
| RSA | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| ElGamal | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ |
| Exponential ElGamal | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ |
| Elliptic Curve ElGamal | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ |
| Paillier | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ |
| Damgard-Jurik | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ |
| Benaloh | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ |
| Naccache-Stern | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ |
| Okamoto-Uchiyama | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ |
| Goldwasser-Micali | ❌ | ❌ | ❌ | ✅ | ❌ | ✅ |
| Sander-Young-Yung | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Boneh-Goh-Nissim | 1️⃣ | ✅ | ✅ | ❌ | ❌ | ✅ |

1️⃣ Boneh-Goh-Nissim allows exactly one multiplication per ciphertext.

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
};

LightPHE cs = LightPHE.builder()
        .algorithmName(algorithms[0])
        .build();
```

The builder carries every optional parameter of the Python constructor:

| Builder method | Meaning |
| --- | --- |
| `algorithmName(String)` | which cryptosystem to build (required) |
| `keys(Keys)` | an existing private-public key pair |
| `keyFile(Path)` | load a previously exported key pair from disk |
| `keySize(Integer)` | key size in bits, defaulting to 1024 |
| `precision(int)` | digits kept after the decimal point in tensor operations, defaulting to 5 |
| `form(String)` | elliptic curve form: `weierstrass` (default), `edwards` or `koblitz` |
| `curve(String)` | elliptic curve name, e.g. `secp256k1`, `ed25519`, `k163` |
| `plaintextLimit(BigInteger)` | upper bound for plaintext values (Benaloh, Sander-Young-Yung) |
| `maxTries(int)` | key generation attempts, defaulting to 10000 |

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
