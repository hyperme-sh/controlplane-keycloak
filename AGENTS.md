# Keycloak tooling development

This repository owns the realm declaration and its reconciliation helpers.
Keep client scopes, protected identity attributes, mapper ownership and failure
behavior explicit. Run `bash scripts/check-tooling.sh` for offline checks.
Tests must use fake admin APIs and must not call a deployed realm. Runtime admin
scripts require separately configured credentials and deployment authority.

## Package publication permission boundary

Source/package validation keeps its existing runner policy and read-only contents.
The separate `.github/workflows/release.yml` publication job is the narrow exception:
it may use `contents: write` and `actions: read` on disposable `ubuntu-24.04` workers
solely through the exact-pinned shared package publisher. It must not check out or
execute this repository's code, install its packages, or receive private dependency
or deployment credentials. This hosted publication exception does not authorize
moving secret-bearing validation to another runner group. Stable publication must
retain any configured release-admission prerequisite for the exact tag/commit.
