# Releasing

`controlplane-keycloak` has two publication paths. Pushes to `main` keep the
validated archive as a GitHub Actions artifact and do not create a release or
a tag. A stable release is an immutable GitHub release tagged
`vMAJOR.MINOR.PATCH`, published only after the pinned publisher has checked
that tag against the accepted baseline and the exact archive produced by main
validation.

The project version in this tree is `controlplane-keycloak-checks` **0.1.0**
(`pyproject.toml`). [`release-policy.json`](../release-policy.json) records
release line `0.1`. [`.github/workflows/release.yml`](../.github/workflows/release.yml)
and [`.github/workflows/release-admission.yml`](../.github/workflows/release-admission.yml)
pass that same line into the Spanopticon component-release workflow. The
immutable stable release currently published is
[v0.24.1](https://github.com/hyperme-sh/controlplane-keycloak/releases/tag/v0.24.1).
Cloning `main` does not check out that tag. Compatibility rules for a shared
release line are in [release-policy.md](release-policy.md), which describes
the 0.24.x line those rules were written for. The manifest format lives in
the [Spanopticon release policy](https://github.com/hyperme-sh/spanopticon/blob/main/docs/releases.md).

## Main validation

[`.github/workflows/tooling.yml`](../.github/workflows/tooling.yml) runs on
pull requests and on pushes to `main`. `scripts/check-tooling.sh` builds
`controlplane-keycloak.tar.gz` with deterministic timestamps and ownership,
preserving executable modes, then checks every member against the checkout.
The candidate digest covers the whole archive. The compatibility inventory
covers every realm and reconciliation file under `keycloak/`.

The job uploads:

- `test-evidence` (JUnit from the source tree and from the extracted archive,
  plus contract evidence), retained 30 days
- `tested-dist` on pushes to `main` (the validated archive bytes), retained
  90 days, stored without recompression

Those artifacts are the qualification record for that commit. Merging to
`main`, or a green workflow run, does not create a `test-<commit>` prerelease
and does not create a stable release.

## Qualification snapshots

GitHub prereleases named `test-<commit>` are development snapshots. The
package version embedded in a snapshot does not reserve a stable version.
Receipts live under [`releases/qualification/`](../releases/qualification).
A snapshot stays in that tree; a provenance label on the snapshot does not
make it the accepted release. New test receipts carry an explicit non-stable
classification.

Owning-package validation and artifact validation are separate from stable
release admission.

## Stable publication

Pushing a `v*` tag runs
[`.github/workflows/release.yml`](../.github/workflows/release.yml):

1. Release admission calls
   `hyperme-sh/spanopticon/.github/workflows/component-release.yml` with
   release line `0.1`, the tag name, and the repository variable
   `SPANOPTICON_RELEASE_BASELINE_SHA` (the full 40-character commit SHA of
   the accepted baseline).
2. The publish job runs only after admission succeeds. It uses the pinned
   action `hyperme-sh/.github/actions/release-channel` to publish the exact
   archive from the main validation workflow.

The publisher checks the live release channel, the stable tag's source, and
the asset digests itself. A successful caller job is not acceptance. It
refuses a qualification snapshot. It refuses the tag when the baseline
variable is missing or does not point at an immutable accepted release.
Preparing that baseline is the procedure in
[release-policy.md](release-policy.md): a real
`releases/accepted/release.json`, contract files, and artifact references.
Example digests are not release evidence.

`releases/accepted/` and `SPANOPTICON_RELEASE_BASELINE_SHA` refer to an
actual immutable stable GitHub release. Publishing the archive, deploying
it, and acceptance by other Hypermesh services are separate steps.

## Accepted release

[`releases/accepted/provenance.json`](../releases/accepted/provenance.json)
binds the existing `v0.24.1` release to its GitHub release id, source
revision, and the digests of `controlplane-keycloak.tar.gz` and
`release-manifest.json`. Qualification snapshots stay under
`releases/qualification/` and are not that record. The publisher keeps an
existing valid stable record. This document does not cut a tag or publish a
release.
