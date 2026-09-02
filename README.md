# lightphe4j

<div align="center">

[![Tests](https://github.com/serengil/lightphe4j/actions/workflows/tests.yml/badge.svg)](https://github.com/serengil/lightphe4j/actions/workflows/tests.yml)
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

## Installation

Requires **Java 17 or newer**. Add the dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>io.github.serengil</groupId>
    <artifactId>lightphe4j</artifactId>
    <version>0.0.25</version>
</dependency>
```

Or with Gradle:

```groovy
implementation 'io.github.serengil:lightphe4j:0.0.25'
```

Then import the entry point:

```java
import io.github.serengil.lightphe.LightPHE;
```

`lightphe4j` logs through [SLF4J](https://www.slf4j.org/), so it uses whatever binding your
application already provides. Without a binding, SLF4J stays silent. The
`LIGHTPHE_LOG_LEVEL` environment variable acts as an additional floor, carrying the numeric levels
of Python's `logging` module (`10` DEBUG, `20` INFO, `30` WARNING, `40` ERROR, `50` CRITICAL) and
defaulting to INFO.

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

### Operator mapping

Java has no operator overloading, so the Python operators become named methods:

| Python | Java | Available on |
| --- | --- | --- |
| `c1 + c2` | `c1.add(c2)` | `Ciphertext`, `EncryptedTensor` |
| `c1 * c2` | `c1.multiply(c2)` | `Ciphertext`, `EncryptedTensor` |
| `c1 * k`, `k * c1` | `c1.multiply(k)` | `Ciphertext`, `EncryptedTensor` |
| `c1 ^ c2` | `c1.xor(c2)` | `Ciphertext` |
| `c1 & c2` | `c1.and(c2)` | `Ciphertext` |
| `c1 @ t` | `c1.matmul(t)` | `EncryptedTensor` |

Likewise, because Java dispatches on static types, the single Python `encrypt`/`decrypt` pair is
split into `encrypt` / `decrypt` for scalars and `encryptTensor` / `decryptTensor` for vectors.
Unsupported homomorphic operations throw `IllegalArgumentException`, mirroring the Python
`ValueError`.

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
Koblitz — and 141 standard curve configurations, all ported from
[LightECC](https://github.com/serengil/LightECC#supported-curves).

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

## Building from source

The repository ships a `Makefile` wrapping the Maven commands, and a Maven wrapper (`./mvnw`), so
the only thing you need installed is a **JDK 17 or newer**. Run `make` on its own to list every
target, and `make doctor` to see which JDK and Maven the build picked up:

```shell
$ make doctor
JAVA_HOME : /Users/you/OpenJDK/jdk-17.0.2.jdk/Contents/Home
java      : openjdk version "17.0.2" 2022-01-18
maven     : Apache Maven 3.9.9
```

You do not have to set `JAVA_HOME` yourself. `scripts/java-home.sh` looks for a suitable JDK in
your `JAVA_HOME`, the macOS JDK registry, the usual install locations and finally on your `PATH`,
and the build uses the first one that is at least version 17. A stale or wrong `JAVA_HOME` left
over in a shell profile is ignored rather than fatal — a common cause of Maven's unhelpful
`The JAVA_HOME environment variable is not defined correctly`. To force a specific JDK:

```shell
make test JAVA_HOME=/path/to/jdk-21
```

```shell
make test        # run the unit tests
make lint        # formatting + checkstyle + spotbugs
make format      # rewrite the sources in the project code style
make verify      # the full chain: clean, compile, test, package, coverage
make cover       # same, then point at the HTML coverage report
make install     # install the artifacts into your local ~/.m2
make release     # sign and upload to Maven Central
```

| Target | Underlying command | What it does |
| --- | --- | --- |
| `make doctor` | — | reports the JDK and Maven that will be used |
| `make test` | `mvn test` | compiles and runs the test suite |
| `make test-one T=X` | `mvn test -Dtest=X` | runs a single test class |
| `make test-slow` | `mvn test -Djunit.jupiter.conditions.deactivate='*'` | also runs the disabled curve sweep and large-key benchmarks |
| `make format` | `mvn spotless:apply` | reformats with google-java-format, AOSP style |
| `make format-check` | `mvn spotless:check` | fails if anything is unformatted |
| `make checkstyle` | `mvn checkstyle:check` | style and javadoc rules from `config/checkstyle` |
| `make spotbugs` | `mvn compile spotbugs:check` | static analysis, exclusions in `config/spotbugs` |
| `make lint` | all three of the above | what CI gates on |
| `make build` | `mvn -DskipTests package` | jar + sources jar + javadoc jar |
| `make verify` | `mvn clean verify` | see below |
| `make javadoc` | `mvn javadoc:javadoc` | generates the API docs |
| `make deps` | `mvn dependency:tree` | shows the dependency tree |
| `make release` | `mvn clean deploy -Prelease` | signs and stages the release |

### What `mvn clean verify` actually does

Maven runs a fixed *lifecycle*: an ordered list of phases, and naming one phase runs it and
every phase before it. `clean` and `verify` name two phases from two different lifecycles, so
this single command runs:

1. **`clean`** — deletes `target/`, so nothing stale from a previous build survives.
2. **`validate`** — checks the project is well formed.
3. **`compile`** — compiles `src/main/java` into `target/classes` (Lombok runs here as an
   annotation processor).
4. **`test-compile`** — compiles `src/test/java` into `target/test-classes`.
5. **`test`** — runs the suite with Surefire, under the JaCoCo agent. A failing test stops the
   build here.
6. **`package`** — assembles `target/lightphe4j-<version>.jar`, plus the sources and javadoc jars.
7. **`verify`** — runs the checks that only make sense on the packaged artifact; this is where
   the JaCoCo coverage report is written to `target/site/jacoco/`.

The phase it does *not* reach is `install` (copy into your local `~/.m2` so other local projects
can depend on it) and `deploy` (upload to a remote repository). So `mvn clean verify` is the
"prove the whole build is sound, from scratch, without publishing anything" command — which is
exactly what you want in CI and before tagging a release. `mvn clean install` is the same plus
step 8, and is what you want when another project on your machine needs to consume the jar.

### Continuous integration

`.github/workflows/tests.yml` runs on pushes to `main` and on pull requests. It builds on JDK 17
and 21 with `./mvnw verify -DskipTests`, then gates on the same three lint checks `make lint`
runs.

As in the Python project, **the unit tests are switched off in CI**: key generation and the
brute-force discrete logarithms the small-key tests rely on are too resource intensive for hosted
runners. The workflow still compiles both the main and the test sources and packages the jar, so a
broken build or a test that no longer compiles fails the run. The commented-out lines in
`tests.yml` re-enable the suite in one edit. Run `make verify` locally before opening a pull
request.

Releasing is deliberately **not** wired into CI — same as the Python project, where publishing is
the manual `scripts/push-release.sh`. Cutting a release is a local action:

```shell
make verify         # prove the whole build is sound, tests included
make release-check  # dry run: sign and package without uploading
make release        # sign and upload to Maven Central
```

`make release` needs a GPG key for signing and Central Portal credentials under the server id
`central` in `~/.m2/settings.xml`. The pom stages the deployment rather than publishing it, so the
final release is still a deliberate click in the Central Portal.

**[`docs/RELEASING.md`](docs/RELEASING.md)** has the full runbook: namespace verification, publishing
your GPG key, the token setup, and what to check at each step.

## Notes on the port

The port preserves the algorithms, key formats and error semantics of the Python implementation.
Three differences follow from the target language rather than from a change in behaviour:

- **Typed ciphertexts.** Python's `int | tuple | list | EllipticCurvePoint` payload becomes a sealed
  `CipherValue` hierarchy (`IntValue`, `TupleValue`, `PointValue`, `Fp2Value`), so every
  cryptosystem can exhaust the shapes a ciphertext can take without a catch-all branch.
- **Typed key material.** The nested `keys` dictionary becomes `Keys` plus a sealed `KeyValue`
  hierarchy (`Num`, `Point`, `Nested`). A `null` section means absent, which the validator reports
  differently from a section that is present but incomplete.
- **Tensor precision.** A tensor derived from another — by scaling, element-wise multiplication or a
  dot product — keeps the precision of its source. The Python implementation resets it to the
  default of 5 in those paths, which is invisible at the default precision but silently mis-scales a
  cryptosystem built with a different one.

Beyond the ported suite, this repository adds direct coverage for the Koblitz form over binary
fields, which the Python tests skip to keep continuous integration fast.

## Contributing

All PRs are more than welcome! If you are planning to contribute a large patch, please create an
issue first to get any upfront questions or design decisions out of the way.

You should be able to run `make lint` and `make test` successfully before committing.

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
