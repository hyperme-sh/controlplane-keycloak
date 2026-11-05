# Controlplane Keycloak tooling

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
CI uses read-only repository permissions and disposable GitHub-hosted workers.

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

Successful main-push validation retains the validated Keycloak configuration/reconciler archive and publishes
an immutable `test-<commit>` GitHub prerelease. Push a `vMAJOR.MINOR.PATCH`
tag at that tested commit to promote the exact files to a stable release,
without rebuilding. Repository visibility applies to all package assets.
Package metadata versions are preserved; these are GitHub distribution snapshots,
not automatic PyPI publication or service deployment.

Promotion requires the original Actions artifact (90-day requested retention;
organization policy may shorten it). Expired evidence fails closed: validate a
new main revision. The publisher verifies the run, source, workflow and artifact
digest independently of release metadata. Repository immutable releases must be
enabled. See the [shared release contract](https://github.com/hyperme-sh/.github/blob/7749591fccd30d46ba9b0adabe82114001c9d0de/actions/release-channel/README.md).

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

## Test qualification and stable acceptance

GitHub `test-<commit>` prereleases are development snapshots. Their embedded
package version does not reserve a stable version. Artifact and consumer evidence
lives under `releases/qualification`; the current wheel binding is still checked
by package CI, alongside any future explicit stable candidate. Earlier test
snapshot receipts are preserved there with an explicit non-stable classification.

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
