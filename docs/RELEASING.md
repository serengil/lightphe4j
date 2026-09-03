# Releasing to Maven Central

Publishing goes through the [Central Portal](https://central.sonatype.com) — the system that
replaced the old OSSRH / `oss.sonatype.org` flow. The `pom.xml` is already configured for it: the
`release` profile signs the artifacts with GPG and hands them to the
`central-publishing-maven-plugin`.

**A published version can never be changed or withdrawn.** Central is immutable by design. Work
through the one-time setup, then the checklist, and only then press Publish.

---

## One-time setup

### 1. Central Portal account

Sign in at [central.sonatype.com](https://central.sonatype.com). Signing in with GitHub is the
easiest route, because it makes the next step nearly automatic.

### 2. Verify the `io.github.serengil` namespace

Central will only accept artifacts in a namespace you have proven you own.

1. In the portal, go to **Namespaces → Add Namespace** and enter `io.github.serengil`.
2. The portal shows a verification code, e.g. `abc123xyz456`.
3. Create a **public** GitHub repository under `github.com/serengil` named exactly that code.
4. Click **Verify Namespace** in the portal.
5. Once it flips to *verified*, delete the temporary repository.

If you signed in with the GitHub account `serengil`, the portal may verify `io.github.serengil`
without any of this. Check the Namespaces page first.

### 3. Publish your GPG key

Central verifies every signature against a public keyserver, so **an unpublished key fails
validation**. You have two secret keys; the RSA one is the safer choice for the widest tooling
compatibility:

```shell
# rsa4096, Sefik Serengil <serengil@gmail.com>
gpg --keyserver keyserver.ubuntu.com --send-keys 9FAE35F001E030F089FA5DECE7900A29DAFC64B6
```

Mirror it to a second keyserver so validation does not depend on one host being up:

```shell
gpg --keyserver keys.openpgp.org --send-keys 9FAE35F001E030F089FA5DECE7900A29DAFC64B6
```

Confirm it is visible before releasing — propagation takes a few minutes:

```shell
curl -s "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xE7900A29DAFC64B6" \
  | head -1
```

If you would rather use the ed25519 key (`0E01CA2C97B74BFB`), publish that one instead and pass
`-Dgpg.keyname=0E01CA2C97B74BFB` to the release commands. Both key types are accepted; RSA simply
has fewer edge cases across keyserver software.

### 4. Generate a user token and put it in `~/.m2/settings.xml`

In the portal: **your account → Generate User Token**. It produces a username/password pair — these
are *not* your portal login. Create `~/.m2/settings.xml` (the repository `.gitignore` blocks
`settings.xml` from ever being committed, but `~/.m2` is outside the repo anyway):

```xml
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">
  <servers>
    <server>
      <id>central</id>
      <username>THE_TOKEN_USERNAME</username>
      <password>THE_TOKEN_PASSWORD</password>
    </server>
  </servers>
</settings>
```

The `<id>central</id>` must match `<publishingServerId>central</publishingServerId>` in the pom.

Keep the file to yourself:

```shell
chmod 600 ~/.m2/settings.xml
```

---

## Releasing

### 1. Settle the version

Central rejects `-SNAPSHOT` versions. The pom currently says `0.0.25`, tracking the Python release
this port is based on. Decide deliberately whether that is the number you want for a brand new
Java artifact, since **`0.0.25` can never be reused** once published.

```shell
./mvnw versions:set -DnewVersion=0.1.0     # then commit the change
```

### 2. Prove the build is sound

```shell
make verify
```

Runs the full chain from a clean tree: compile, all 120 tests, package, coverage. Do not skip
this — CI does not run the tests, so this is the only gate.

### 3. Dry run the signing

```shell
make release-check
```

This is `mvn clean verify -Prelease`: it builds, signs every artifact and stops short of
uploading. You should be prompted for your GPG passphrase, and `target/` should end up with a
`.asc` next to each `.jar` and `.pom`.

**Name the key explicitly.** Both of your secret keys carry the same user id
(`Sefik Serengil <serengil@gmail.com>`) and no `default-key` is set in `~/.gnupg/gpg.conf`, so
gpg's choice is ambiguous — and the signature must be made with the key you published to a
keyserver, or Central validation fails:

```shell
make release-check GPG_KEY=9FAE35F001E030F089FA5DECE7900A29DAFC64B6
```

Alternatively, settle it once for every tool by adding to `~/.gnupg/gpg.conf`:

```
default-key 9FAE35F001E030F089FA5DECE7900A29DAFC64B6
```

### 4. Upload

```shell
make release GPG_KEY=9FAE35F001E030F089FA5DECE7900A29DAFC64B6
```

This is `mvn clean deploy -Prelease`. It signs and uploads a *deployment* to the portal. Because
the pom sets `<autoPublish>false</autoPublish>`, nothing is public yet.

### 5. Publish from the portal

Go to **Deployments** in the portal. The deployment moves through `PENDING` → `VALIDATING` →
`VALIDATED`. Read the validation report; if anything failed, drop the deployment, fix it and rerun
step 4 — the version is still free at this point.

When it reads `VALIDATED`, click **Publish**.

### 6. Afterwards

- The artifact reaches Maven Central in roughly 10–30 minutes.
- `search.maven.org` can lag by a few hours; that is indexing, not a failure.
- Tag the release: `git tag v0.1.0 && git push origin v0.1.0`.
- Sanity-check consumption from a scratch project:

  ```shell
  mvn dependency:get -Dartifact=io.github.serengil:lightphe4j:0.1.0
  ```

---

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `401 Unauthorized` on deploy | `settings.xml` server id is not `central`, or the token was regenerated (it invalidates the old one) |
| `403 Forbidden` / namespace error | `io.github.serengil` is not verified, or the pom `groupId` does not sit under it |
| Validation: *missing signature* | the `release` profile was not active — use `make release`, not `mvn deploy` |
| Validation: *PGP key not found* | the key was never pushed to a keyserver, or propagation has not finished |
| GPG hangs or fails headlessly | no terminal for the prompt; pass it explicitly: `make release GPG_KEY=... -Dgpg.passphrase=...` |
| `gpg: skipped "": Invalid user ID` | an empty key name reached gpg — pass `GPG_KEY=<fingerprint>`, and do not set an empty `<keyname>` in the pom |
| Validation: *signature from unknown key* | you signed with a different key than the one you published; check `GPG_KEY` matches the fingerprint you sent to the keyserver |
| `-SNAPSHOT` rejected | Central only accepts release versions |

---

## `groupId` and the Java package

They line up: the `groupId` is `io.github.serengil` and the code lives in
`io.github.serengil.lightphe`.

```java
import io.github.serengil.lightphe.LightPHE;
```

Maven does not require this, but the package name is part of your public API — changing it after
the first release breaks every consumer. It is settled now, before anything is published.
