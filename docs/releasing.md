# Releasing

Maintainer steps for publishing a release. Releases are built by
[`.github/workflows/release.yml`](../.github/workflows/release.yml) when a GitHub Release is published.

## Before the first release

1. **Make the first commit on `main`** and push it. Until then the repository has no history.
2. **Run the gate in Release mode.** The `Publish gate` workflow (`gate.yml`, `mode: Release`) needs the
   repository secret that holds the private denylist. Without the secret the Release-mode check fails.
3. **Similarity check.** Compare the repository against any source it should not resemble. This is a manual
   review by the maintainers.
4. **Fixture review.** Confirm every test fixture contains only synthetic data (account `123456789012`,
   no real names, addresses or keys).
5. **Read-through.** Read the README, `docs/` and the help text once from a user's point of view.
6. **Named sign-off.** A named maintainer records approval of the release in the release issue or pull request.
7. **DCO or CLA decision.** Decide whether contributions need a DCO sign-off or a CLA, and record it in
   `CONTRIBUTING.md`.

Checks that need history cannot run before the first commit: the full-history secret scan in the gate,
`eng/Get-Version.ps1` (it counts commits and reads tags), and the check that the release commit is on `main`.
Run a working-tree secret scan with `gitleaks dir` in the meantime.

## Publishing

1. Choose the tag. Use `X.Y.Z` for a stable release or `X.Y.Z-rc.N` for a release candidate. There is no `v`
   prefix. A tag that contains `-` is marked as a prerelease automatically.
2. Create and publish a GitHub Release with that tag, targeting a commit on `main`.
3. The workflow runs the gate, builds and tests, packages six runtime archives, generates a CycloneDX SBOM,
   creates build-provenance and SBOM attestations, and attaches the archives, `SHA256SUMS` and the SBOM
   to the release.

## Verifying a release

Download the archive and `SHA256SUMS`, then check them:

```bash
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify proxylity-<version>-<rid>.tar.gz --repo <owner>/<repo>
gh attestation verify proxylity-<version>-<rid>.tar.gz --repo <owner>/<repo> \
  --predicate-type https://cyclonedx.org/bom
```

Use the `.zip` file for Windows runtimes. The attestation workflow has not run yet: these steps are untested
until the first release is published.
