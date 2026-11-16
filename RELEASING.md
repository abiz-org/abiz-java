# Releasing

Versions are calendar versions, `YYYY.MMDD.N`: the release date, then a build number that starts at 1
(the first release is `2026.1116.1`). Every manifest carries the version, and the git tag is `v` plus
the version. A version, once published, can never be published again with different content.

To release:

1. Set the new version in `pom.xml` (`version` and `scm/tag`), `src/main/java/org/abizrecord/abiz/Abiz.java`, `src/test/java/org/abizrecord/abiz/BundledFilesTest.java` and `README.md` and add it to the changelog or README where the old one appears.
2. Merge to `main` with CI green.
3. Tag the merge commit and push the tag: `git tag -a v<version> -m "<version>" && git push origin v<version>`.
4. The tag starts `.github/workflows/release.yml`, which waits for a reviewer to approve the `maven-central` environment, checks the tag against `pom.xml`, signs the artifacts with GPG and uploads them to the Maven Central Portal (`mvn -Prelease deploy`). `autoPublish` is `false`: a person checks the deployment in the Portal and presses Publish.

The `maven-central` environment holds four secrets: `CENTRAL_TOKEN_USERNAME` and `CENTRAL_TOKEN_PASSWORD` (a Central Portal user token, with an expiry), `MAVEN_GPG_PRIVATE_KEY` (ASCII-armoured; its public key on `keys.openpgp.org`) and `MAVEN_GPG_PASSPHRASE`. The `org.abizrecord` namespace must be verified in the Portal first.

Every publishing environment requires a reviewer's approval, and tags matching `v*` are protected.
