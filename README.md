# Controlplane Keycloak tooling

## Current version authority

Current development version: `0.1.0`. The services remain before the unreleased
0.24.0 milestone. Earlier 0.24/1.0 preparation and publication notes below are
historical and do not authorize those versions. Existing tags and historical
artifacts remain untouched. Development uses exact source pins and rebuilt
artifacts; no prior release is required. Version changes, tags and publication
require the owner's explicit authorization to the agent.

Realm configuration and reconciliation helpers for controlplane clients and
identity-provider brokers. The declaration is `keycloak/import/controlplane-realm.json`.
The Python scripts use the standard library and run directly from `keycloak/`.

## Tools

- `configure_idp_brokers.py`: reconcile broker configuration, frontend logout
  settings and native, host-setup and s3r.ch clients.
- `account_types.py`: protect administrator-owned human/service classification
  and reconcile authentication-method claim mappers.
- `hypermesh_native.py`, `hypermesh_host_setup.py`, `s3rch_web.py`: client
  declarations and reconciliation helpers used by the broker script.
- `idp_enterprise.py`: broker claim classification and mapper declarations.
- `connect_issuer.py`: dedicated issuer client configuration helpers.
- `test_registration.py`: explicitly selected test-environment registration policy.
- `seed_pan_test_identities.py`: test identity provisioning helper.

Import the realm only into an explicitly selected environment. Keycloak skips
an already existing realm during startup import; changing this file does not
reconcile an existing realm. Administrative scripts write to the selected realm.
Deployment owners supply `KEYCLOAK_INTERNAL_URL`, `KC_BOOTSTRAP_ADMIN_USERNAME`
and `KC_BOOTSTRAP_ADMIN_PASSWORD` through their existing secret injection.
Broker credentials use the `KC_IDP_*` variables declared in the scripts.
The checked-in realm contains development defaults and broker placeholders;
environment-specific credential provisioning belongs to the deployment owner.

Public clients use their declared scopes and redirect URIs. Host setup is a
separate client with reduced scopes and audience; consuming services still
check tenant membership and host authority. Account classification is an
administrator binding, not proof derived from email, roles or authentication
alone. Local self-registration remains disabled in the declaration.

## Development and CI

Install uv 0.11.26 and Python 3.13, then run:

```sh
bash scripts/check-tooling.sh
```

The frozen tooling lock supplies pytest. Checks compile all Python helpers,
run offline realm/client/classification tests, build a standalone source archive,
verify every archive member against the checkout and rerun tests from its
extracted contents. The archive keeps `keycloak/`, tests and development files.
CI uses read-only repository permissions and debrunners. Both runs must execute
the same nonempty test inventory with no skips; JUnit evidence is retained.

Offline checks use fake admin APIs. They do not validate live Keycloak tokens,
broker login, real client reconciliation, deployment or dependent service policy.
The identity-seed service integration and live account/issuer suites require
separate service dependencies and a disposable Keycloak environment.

## Administrative endpoint and identity policies

All administrative entry points prefer a nonblank `KEYCLOAK_INTERNAL_URL`, then
accept legacy `KEYCLOAK_URL`, then default to `http://127.0.0.1:8081`. Whitespace
and trailing slashes are normalized. Set the canonical variable for new deployments.

Microsoft uses the generic OIDC broker with exact issuer validation and Microsoft
JWKS signature validation enabled. `common` endpoints support personal accounts
and explicitly approved work directories. During reconciliation, set
`KC_IDP_MICROSOFT_ALLOWED_TENANT_IDS` to a comma-separated list of work-directory
UUIDs. An empty list permits only Microsoft's personal-account tenant. The
`organizations` endpoint requires a nonempty work allowlist; `consumers` permits
only the personal tenant. A specific tenant must be a UUID, not a domain alias.

For first realm import, set `KC_IDP_MICROSOFT_ISSUERS` to the corresponding
comma-separated exact issuer URLs (`https://login.microsoftonline.com/<UUID>/v2.0`).
Its default is the personal-account issuer. If selecting a specific tenant or
work directories at import, configure both endpoints and issuers. Reconciliation
replaces the issuer list from the UUID policy above. Never use `/common/v2.0`, a
wildcard, or an empty issuer to bypass validation. Arbitrary unlisted work tenants
are intentionally refused. These offline checks do not establish live broker login.

Authenticator references have a 300-second lifetime from the completed
authentication step, on both creation and update. Unrelated authenticator settings
are retained; this does not manufacture an authentication-method claim.

The test identity seed initializes passwords for new users and existing users
without a password credential. Existing passwords remain unchanged unless
`--rotate-passwords` is explicitly supplied. A failed or malformed credential
inventory stops seeding instead of assuming that a password is missing.

## Release channels

Main validation retains its exact qualified files in Actions artifacts. It does
not create GitHub releases or tags. Historical `test-<commit>` prereleases remain
qualification evidence and do not establish an accepted stable release.

Stable publication requires an explicit `vMAJOR.MINOR.PATCH` tag, the exact
successful main validation artifact, compatible declared contracts and an actual
immutable stable baseline. The publisher independently verifies that evidence;
successful caller jobs alone cannot establish acceptance. Missing evidence and
first-stable bootstrap remain closed. Package qualification, coordinated consumer
acceptance and runtime deployment remain separate.

## Account closure provisioning

`keycloak/account_closure.py` adopts the private closure tooling from Panopticon
#671/#672. Its default invocation prints a plan without authenticating. An
explicit `--apply` provisions **disabled** reader and worker clients with
distinct secrets and narrowly scoped native management roles. It never enables
these clients, rotates existing credentials, or selects operators automatically.

Configuration uses `KEYCLOAK_INTERNAL_URL` (HTTPS or local loopback), the existing
bootstrap administrator variables, `ACCOUNT_CLOSURE_KEYCLOAK_REALM` (default
`controlplane`), `ACCOUNT_CLOSURE_KEYCLOAK_READER_SECRET`, and
`ACCOUNT_CLOSURE_KEYCLOAK_CLIENT_SECRET`. Secrets belong in the deployment owner's
secret injection, never command arguments or repository files. This tool requires
the canonical endpoint explicitly; it does not fall back to `KEYCLOAK_URL`.

Optional `--human-user-id` / `--service-user-id` arguments require exact native
UUIDs and administrator-owned account classification. The separate operator
audience is `spanopticon-account-closure`; ordinary clients and closure credentials
do not become operators. The `account:close` realm role is not a default grant.
Existing client, mapper, scope or credential drift fails for reconciliation.

Offline tests cover input refusal, transport bounds, disabled credential policy,
operator classification and default-grant rejection, from source and the verified
archive. No deployed realm is contacted. Disposable native-provider and consuming
identity-validator qualification remain in adoption issue #9; source behavior and
offline tests alone do not establish deployment readiness.

## Release qualification

Tooling versions follow the shared 0.24 line. Archives use deterministic timestamps
and ownership while preserving executable modes. The candidate digest binds the
complete archive; compatibility inventory covers every realm/reconciliation file
and mode under `keycloak/`. Source and extracted-archive fake-admin consumers must
pass before publication. Admin modules are inspected without import during contract
export. Offline tests do not authorize or establish deployed realm changes, identity
provider readiness or installer/dependency metadata compatibility.

## Transferred authentication realm contracts

The standalone suite includes the introspection-client, split test-identity and
password-grant restrictions transferred from Panopticon
`d6d9541b72db2eb3f86cb8aedc071794eba116e3` auth tests. They inspect this owner's
realm and seed tooling. Auth runtime cases run in auth-service; the frontend
portal-grant assertions run in controlplane-portal. These are local contract
tests, not live identity-provider acceptance.

## Test qualification and stable acceptance

GitHub `test-<commit>` prereleases are development snapshots. Their embedded
package version does not reserve a stable version. Artifact and consumer evidence
belongs under `releases/qualification`. Owning-package and artifact validation
remain separate from stable release admission. Future test receipts must carry
an explicit non-stable classification.

`releases/accepted` and `SPANOPTICON_RELEASE_BASELINE_SHA` are reserved for an
actual immutable stable GitHub release. The pinned shared guard verifies the live
release channel, stable tag source and asset digests; a test snapshot cannot
become accepted through a provenance label. No stable baseline is recorded until
that release exists. Stable publication remains closed without a valid baseline;
first stable bootstrap and coordinated release qualification remain separate.
No stable version, approval prerequisite or deployment is introduced here.


### Published stable distribution

The accepted record binds the existing immutable `v0.24.1` release to its actual
GitHub release ID, source revision and published asset digests. Test snapshots
remain under `releases/qualification` and do not establish stable acceptance.
Runtime deployment and coordinated consumer acceptance remain separate.

### Actions qualification and stable publication

Main merges and workflow completion do not publish GitHub test releases. Exact
qualification files remain in Actions artifacts with finite retention. The pinned
publisher independently verifies a real immutable stable baseline and refuses
qualification snapshots, even if a caller job reports success. Existing valid
stable records are retained; no release, version change, deployment or human
approval prerequisite is introduced by this correction.

## Age-confirmation ownership

The offline age-confirmation and classification regressions are transferred from
Panopticon `2cd00fd9a7ebb950999571a81be7cb0a24d9264e`; source hashes and
adaptations are recorded in `tests/panopticon-age-transfer-provenance.json`.
The realm, reconciliation helper and native mapper contract include the
administrator-owned confirmation timestamp. Classification refreshes pending
actions, and the broker entry point returns exit 2 if age reconciliation fails.
The standalone `scripts/require-age-confirmation.sh` invokes the same helper.
Existing issuer restrictions, bounded AMR lifetime and admin-endpoint precedence
remain enforced. Offline tests block network access except their own loopback
transport fixture. No deployed realm has been reconciled by this transfer.

This verifies tooling behavior and archive completeness, not live login or portal
acceptance. Operational seeds, public installation defaults and final deployment
artifacts still require the core release review.

## License

First-party tooling is [Apache-2.0](LICENSE). The standalone archive includes the
exact license text and SPDX metadata; dependencies retain their own licenses.
