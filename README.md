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
enabled. See the [shared release contract](https://github.com/hyperme-sh/.github/blob/3352fb1347e7920ec1d5cd14792ba3038a81abcb/actions/release-channel/README.md).
