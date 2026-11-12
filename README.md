# controlplane-keycloak

Keycloak realm configuration and reconciliation helpers for Hypermesh
control-plane clients and identity brokers. The declaration is
[`keycloak/import/controlplane-realm.json`](keycloak/import/controlplane-realm.json)
(realm `controlplane`). The Python helpers beside it use the standard library,
talk to the Keycloak Admin API, and bring a live realm in line with that
declaration: public clients, Microsoft / GitHub / Google brokers, account
classification, and the 18+ confirmation gate.

## Why

Renters and hosts sign in to Hypermesh through one control-plane realm. The
portal, the visor and CLI, and host setup each need a stable client, redirect,
scope, and token claim. Keycloak startup import (`--import-realm`) creates a
realm that is not already there and leaves an existing realm unchanged, so
editing the JSON later does not update a running realm. These helpers are that
update path. Broker client secrets stay in the operator's environment and are
never written back into the repository.

## How it works

The realm file is the source of truth for clients, scopes, protocol mappers,
realm roles, and groups. `configure_idp_brokers.py` is the reconcile entry
point. It updates three public clients, then broker credentials and claim
mappers, the portal logout allowlist, and the age-confirmation gate. Each
client step reports its own error and the later steps still run. A second run
updates the same Keycloak client id in place.

| Client | Role |
| --- | --- |
| `controlplane-frontend` | Public authorization-code + PKCE client for the control-plane portal. |
| `hypermesh-native` | Public PKCE and device-code client for the Hypermesh visor and CLI. Redirect is `http://127.0.0.1/callback`. |
| `hypermesh-host-setup` | Device-code client used to sign in while connecting a host. Consent required. Default scopes are `basic` and `email`. Token audience is this client. |
| `s3rch-web` | Public authorization-code + PKCE client for [s3r.ch](https://s3r.ch). Consumers leave it outside the control-plane API client allowlist. |
| `controlplane-mobile` | Public PKCE client for the Expo app. |
| `controlplane-device` | Device-code client for a CLI or embedded sign-in. |
| `controlplane-m2m` | Confidential client-credentials client. The checked-in secret is a development placeholder. |
| `controlplane-api-key` | Public client id used as `azp` when the gateway exchanges an API key for a JWT. |
| `auth-connect-introspection` | Confidential client for payout-session introspection. Applied only by the explicit test issuer step below. |

Realm roles `renter`, `host`, and `admin` are portal grants. Groups `/renter`
and `/host` carry the matching realm roles. The portal and the visor client
both map group membership to a `groups` claim with the full path (`/renter`,
`/host`). Access tokens in the declaration live 300 seconds. The visor client
keeps its own session caps (30 minutes idle, 10 hours max, device code 600
seconds) and uses the realm access-token lifespan.

Identity providers `microsoft`, `github`, and `google` are the login buttons.
Microsoft is the generic OIDC broker with signature validation against
Microsoft's JWKS. Mappers copy broker facts onto the user (`idp_provider`,
`idp_org`, `idp_login`, `idp_account`, `idp_wids`) and session notes onto the
access token (`login_provider`, `entra_tenant_id`, `entra_object_id`).
[Spanopticon](https://github.com/hyperme-sh/spanopticon) stores which enterprise
an organization belongs to. This repository copies the broker claim onto the
user and leaves that binding alone.

`account_types.py` keeps the user-profile attribute `account_type` (`human` or
`service`) editable by an administrator only, and writes it onto tokens.
Browser authenticators it knows (password, OTP, WebAuthn) get an
authentication-method reference with a 300-second lifetime, on create and on
update. Other authenticator settings are left as they are.

`age_confirmation.py` enables Keycloak's terms required action as the 18+
gate, with copy that states the age rule. Accepting stores
`terms_and_conditions` as Unix seconds. The portal treats a missing timestamp
as an unfinished sign-in. Accounts an administrator has classified as
`service`, and Keycloak client service accounts, skip the page.

`account_closure.py` plans, and with `--apply` provisions, two **disabled**
confidential clients (`account-closure-reader`, `account-closure-worker`) for
Spanopticon account closure. They use distinct secrets and narrow
`realm-management` roles. The operator audience is
`spanopticon-account-closure`. The realm role `account:close` is not granted
by default.

Administrative helpers prefer `KEYCLOAK_INTERNAL_URL`, then `KEYCLOAK_URL`,
then `http://127.0.0.1:8081`. Whitespace and a trailing slash are stripped.
`account_closure.py` is the exception: it requires `KEYCLOAK_INTERNAL_URL`
and accepts only HTTPS or HTTP on localhost.

## Practical use

The helpers are not an installable library (`package = false` in
`pyproject.toml`). Run them from a checkout with Python 3.13. They need a
Keycloak you administer. Point them at a realm you mean to change.

The declaration is a lab default: `sslRequired` is `none`, self-registration
is off, `controlplane-m2m` ships with the placeholder secret
`dev-m2m-client-secret-change-me`, and broker client ids fall back to
`unset-*-client-id` until real values are supplied. Put TLS in front of any
Keycloak that is not on your machine, and replace the placeholder secret
before anything uses `controlplane-m2m`.

### First import

Startup import creates `controlplane` when that realm is absent. Copy the
declaration into Keycloak's import directory and start Keycloak with
`--import-realm`. On the usual distribution image that directory is
`/opt/keycloak/data/import`.

```sh
mkdir -p /opt/keycloak/data/import
cp keycloak/import/controlplane-realm.json /opt/keycloak/data/import/
```

Keycloak substitutes `${VAR:default}` in the imported file. For a Microsoft
directory other than personal accounts, set `KC_IDP_MICROSOFT_ISSUERS` to the
comma-separated exact issuer URLs
(`https://login.microsoftonline.com/<directory-uuid>/v2.0`) before that first
start, and set the matching `KC_IDP_MICROSOFT_*` client id, secret, and tenant.
The file's default issuer is the personal-account issuer
`https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0`.
Use a directory UUID, not a domain name. Leave `/common/v2.0`, a wildcard, and
an empty issuer unset: signature checks need an exact issuer list.

After the realm exists, further changes go through the reconcile script.

### Reconcile clients and brokers

From the repository root:

```sh
export KEYCLOAK_INTERNAL_URL=http://127.0.0.1:8081
export KC_BOOTSTRAP_ADMIN_USERNAME=admin
export KC_BOOTSTRAP_ADMIN_PASSWORD='replace-me'

# Leave a provider's pair empty to skip it.
export KC_IDP_MICROSOFT_CLIENT_ID='replace-me'
export KC_IDP_MICROSOFT_CLIENT_SECRET='replace-me'
export KC_IDP_MICROSOFT_TENANT_ID=common
export KC_IDP_MICROSOFT_ALLOWED_TENANT_IDS=''

export KC_IDP_GITHUB_CLIENT_ID='replace-me'
export KC_IDP_GITHUB_CLIENT_SECRET='replace-me'
export KC_IDP_GOOGLE_CLIENT_ID='replace-me'
export KC_IDP_GOOGLE_CLIENT_SECRET='replace-me'

python3 keycloak/configure_idp_brokers.py
```

`KC_IDP_MICROSOFT_TENANT_ID` selects the Microsoft endpoint: `common`,
`organizations`, `consumers`, or one directory UUID.
`KC_IDP_MICROSOFT_ALLOWED_TENANT_IDS` is a comma-separated list of work
directory UUIDs. With `common`, an empty list allows only Microsoft's
personal-account tenant. `organizations` requires a non-empty work list.
`consumers` allows only the personal-account tenant. Reconciliation replaces
the issuer list from that policy.

Exit 0 means the client steps and the age gate both applied. Exit 1 means a
client or broker step failed and the age gate applied; the other client steps
still ran. Missing administrator credentials, or a failure to obtain an admin
token, also exit 1 and write nothing. Exit 2 means the age gate did not apply;
treat that as a failed rollout even when clients were updated. Run the script
again after fixing the cause. A rerun updates the existing client. Secrets stay
out of the log.

`KC_TEST_REGISTRATION=1` on that same command opens self-registration on the
realm it is pointed at (email as username, email verification left off). Use
that only on a disposable test realm. The declaration itself keeps
registration closed, and the password grant on `controlplane-frontend` stays
off.

`PAYMENT_CONNECT_NATIVE_ISSUER_ENABLED=true`, together with
`KC_TEST_REGISTRATION=1` and `AUTH_CONNECT_INTROSPECTION_CLIENT_SECRET`, runs
the test-only payout issuer setup in `connect_issuer.py`. Empty and `false`
skip that step. Any other value is an error. Leave the flag unset when you
are only reconciling the portal and the brokers.

### Account classification

Classification is an administrator binding. It is not inferred from the email
address, from realm roles, or from which broker was used.

```sh
export KEYCLOAK_INTERNAL_URL=http://127.0.0.1:8081
export KC_BOOTSTRAP_ADMIN_USERNAME=admin
export KC_BOOTSTRAP_ADMIN_PASSWORD='replace-me'

python3 keycloak/account_types.py \
  --human-user-id 00000000-0000-0000-0000-000000000000 \
  --service-user-id 00000000-0000-0000-0000-000000000001
```

Arguments are Keycloak user UUIDs. Omit either flag to skip that kind. The
same user cannot be passed as both.

### Age confirmation on its own

`configure_idp_brokers.py` already runs this step. To apply only the gate:

```sh
export KEYCLOAK_INTERNAL_URL=http://127.0.0.1:8081
export KC_BOOTSTRAP_ADMIN_USERNAME=admin
export KC_BOOTSTRAP_ADMIN_PASSWORD='replace-me'
bash scripts/require-age-confirmation.sh
```

A non-zero status means the gate was not applied. People who already have no
`terms_and_conditions` timestamp are asked on their next sign-in.

### Disposable test users

`seed_pan_test_identities.py` creates three accounts in `controlplane` for a
lab realm: `renter` (group and role `renter`), `leaser` (group and role
`host`), and `admin` (realm role `admin`, the portal support role). Passwords
come from `SPANOPTICON_TEST_RENTER_PASSWORD`,
`SPANOPTICON_TEST_LEASER_PASSWORD`, and
`SPANOPTICON_TEST_PORTAL_ADMIN_PASSWORD`. Existing passwords are kept unless
you pass `--rotate-passwords`. A failed or malformed credential read stops the
seed. `--wait-seconds N` waits for Keycloak before seeding.

```sh
export KEYCLOAK_INTERNAL_URL=http://127.0.0.1:8081
export KC_BOOTSTRAP_ADMIN_USERNAME=admin
export KC_BOOTSTRAP_ADMIN_PASSWORD='replace-me'
export SPANOPTICON_TEST_RENTER_PASSWORD='replace-me'
export SPANOPTICON_TEST_LEASER_PASSWORD='replace-me'
export SPANOPTICON_TEST_PORTAL_ADMIN_PASSWORD='replace-me'
python3 keycloak/seed_pan_test_identities.py --wait-seconds 60
```

### Account-closure clients

Without `--apply` the script prints a plan and does not log in:

```sh
python3 keycloak/account_closure.py
```

`--apply` creates the reader and worker clients disabled. They stay disabled,
existing secrets stay in place, and the only operators are the user UUIDs you
pass. Secrets are environment variables:

```sh
export KEYCLOAK_INTERNAL_URL=https://keycloak.example.com
export KC_BOOTSTRAP_ADMIN_USERNAME=admin
export KC_BOOTSTRAP_ADMIN_PASSWORD='replace-me'
export ACCOUNT_CLOSURE_KEYCLOAK_REALM=controlplane
export ACCOUNT_CLOSURE_KEYCLOAK_READER_SECRET='replace-me'
export ACCOUNT_CLOSURE_KEYCLOAK_CLIENT_SECRET='replace-me'
python3 keycloak/account_closure.py --apply \
  --human-user-id 00000000-0000-0000-0000-000000000000
```

`--human-user-id` and `--service-user-id` are optional, repeatable, and must
be exact user UUIDs that already carry the administrator-owned `account_type`.
Drift on an existing closure client, mapper, scope, or secret fails the run.

## How Hypermesh uses it

Hypermesh renters lease capacity and hosts provide it. Both sign in to the
control-plane portal, which is the public client `controlplane-frontend`
(authorization code and PKCE, S256). In this declaration the login redirects
and web origins are the test portal and local development:

- `https://portal.test.hyperme.sh`, including
  `https://portal.test.hyperme.sh/api/auth/callback` and
  `https://portal.test.hyperme.sh/api/auth/callback/keycloak`
- Next.js on `localhost:3000` and `127.0.0.1:3000`
- Vite on `localhost:5173` and `127.0.0.1:5173`

Post-logout redirects, reconciled on every broker run, are
`https://portal.hyperme.sh/signed-out`,
`https://portal.test.hyperme.sh/signed-out`, and the same path on local port
3000.

A person opens the portal, picks Microsoft, GitHub, or Google, and returns to
Keycloak. The 18+ terms page runs before Keycloak issues the authorization
code, so a declined or skipped confirmation never becomes a portal session.
The portal then calls the control plane with that access token. The `groups`
claim tells the portal which surface to open: `/renter` for checkout and
leases (realm role `renter`), `/host` for host status and sell state (realm
role `host`). An administrator assigns those groups. Realm role `admin` is
portal support and is separate from the Keycloak bootstrap administrator
(`KC_BOOTSTRAP_ADMIN_*`). The same `groups` claim is on `hypermesh-native`, so
the visor and CLI can switch tenant with the same membership.

Connecting a machine is a second client. Host setup uses the device
authorization grant on `hypermesh-host-setup` ("Sign in to connect a host").
The access token's audience is that client, and the scopes are `basic` and
`email`. Approval of the host still happens in the dashboard. Callers that
accept the token continue to check tenant membership and host authority.

The visor and CLI use `hypermesh-native`: loopback redirect
`http://127.0.0.1/callback`, PKCE, and the device-code grant. That client is
how an operator on the machine authenticates to the control plane without a
browser session at the portal origin.

Broker claim mappers are what the control plane reads to tell a personal
login from an organization directory (Microsoft tenant id, Google hosted
domain, GitHub login and org). Spanopticon keeps the enterprise binding.
`account_type=service` is how automation passes the age check; a person
cannot get that value by choosing a username.

`s3rch-web` is the OAuth client for s3r.ch
(`/api/identity/oauth/callback` on `s3r.ch`, `www.s3r.ch`, `test.s3r.ch`, and
local Next.js). The renter and host portal uses `controlplane-frontend`.

## Develop and test

Install [uv](https://docs.astral.sh/uv/) 0.11.26 and Python 3.13, then from
the repository root:

```sh
bash scripts/check-tooling.sh
```

That script checks `uv.lock`, compiles `keycloak/`, runs pytest (locked at
9.2.0; the dev dependency is `pytest>=8.4.0`) over `tests/` and
`tests_tools/`, builds `controlplane-keycloak.tar.gz`, checks every archive
member against the checkout, and runs the same tests from the extracted
archive. Both runs must execute the same non-empty test set with no skips.
Historical qualification/candidate digests are retained as provenance and are
not compared with each new development archive. The standalone
`scripts/verify_release_candidate.py` verifier remains available when checking
a specific release candidate against its recorded bytes.

The tests use fake Admin APIs. A green run checks the declaration, the
helpers, and the archive. Live broker login and the identity seed need a
disposable Keycloak and the environment variables above.

`bash scripts/check-native.sh` separately runs the transferred closure regression
against a digest-pinned Keycloak 26.5 container. Docker is required; missing Docker
fails this lane rather than skipping it. Each source/archive run creates its own
realm with random credentials, binds HTTP only to an ephemeral loopback port and
removes its container and anonymous volumes on exit. No configured realm or
administrator credential is used. Signed tokens prove selected human/AI grants,
disabled-by-default clients, protected internal subjects and actual reader/worker
permissions. The native lane also uses immutable identity revision
`5aeff3d2c00568f39ca6e8b75c7e63883d3a510b` to accept the selected human/AI
tokens and reject the unselected human through the actual consumer validator.

Pull requests and pushes to `main` run
[`.github/workflows/tooling.yml`](.github/workflows/tooling.yml), which is
both offline and native scripts. JUnit and the contract evidence are kept as the `test-evidence`
artifact for 30 days. On `main`, the validated archive is the `tested-dist`
artifact for 90 days.
[`.github/workflows/version-policy.yml`](.github/workflows/version-policy.yml)
checks the version recorded for `pyproject.toml`.

## Release and versioning

This checkout's project is `controlplane-keycloak-checks` **0.1.0**
(`pyproject.toml`), on release line `0.1` (`release-policy.json`). Day-to-day
pushes archive that tree in Actions and do not publish a GitHub release. The
immutable stable release recorded for this repository is
[v0.24.1](https://github.com/hyperme-sh/controlplane-keycloak/releases/tag/v0.24.1).
How qualification snapshots, the stable tag, and the publisher relate is in
[docs/releasing.md](docs/releasing.md).

## License

First-party tooling is [Apache-2.0](LICENSE). The source archive includes
that license text. The development dependency (pytest) keeps its own license.

## Configured startup identity

`keycloak/startup_identity.py` runs only after User/Auth binding and ACL
reconciliation of the same private mapping. It creates no password or external
Entra account. It preserves the chosen opaque application subject, adds one
Microsoft federated link, and assigns `realm-management/realm-admin` separately
from application permissions. Conflicting email labels, profile attributes,
broker configuration or prior mappings fail closed. Profile mapping attributes
are administrator-only; retries reuse the same user and link.

The `startup-entra` provider extends Keycloak 26.5 OIDC validation. After
signature, issuer, audience and nonce validation, it accepts only the configured
Entra v2 `iss`/`tid`/`oid`/`sub` tuple and supplies verified tenant/account session
notes to the existing application token mappers. Other accounts are refused by
this dedicated alias. The canonical binding selects its alias explicitly; an
existing alias with another provider type is refused before any user writes.
No provider is deleted, no email-linking flow is added, and the ordinary
Microsoft login alias remains available independently.

If the configured alias does not exist, the command creates it from the exact
Entra tenant and audience plus `STARTUP_ENTRA_CLIENT_SECRET_FILE`, a private
owner-supplied application secret. It creates no Entra application or credential.
The provider JAR must already be installed. `binding.keycloak_admin.enabled`
controls the separate realm-admin grant; false never creates that grant.

Build with `bash scripts/build-startup-provider.sh` and install the resulting
JAR in Keycloak's providers directory before configuring `startup-entra`.
The standalone tooling archive includes the tested JAR and its source. Java
unit tests and Python command contracts run in CI; native owner checks also
verify the provider, user, federated link and separate realm grant. Agents do
not run the native suite. Combined scheduled registration is Infra #923.

The command requires `STARTUP_IDENTITY_ENABLED=1`, `KEYCLOAK_INTERNAL_URL`,
`KEYCLOAK_REALM` and `STARTUP_KEYCLOAK_ADMIN_TOKEN_FILE`; its arguments are private
configuration and preceding owner-result files. Credentials are never returned.
No package version or release authorization changes are implied.
