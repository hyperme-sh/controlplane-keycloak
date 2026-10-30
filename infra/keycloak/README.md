# Keycloak (local dev)

## Admin console vs application login

The **Keycloak Admin Console** at `http://localhost:8081/admin/` uses the **`master`** realm. Sign in with the bootstrap admin from Compose (`KC_BOOTSTRAP_ADMIN_USERNAME` / `KC_BOOTSTRAP_ADMIN_PASSWORD`, e.g. laptop defaults `admin` / `admin123`) — **not** `admin@example.com`. The `user_not_found` / wrong-realm errors in logs usually mean someone tried the app user on the admin console. Keycloak **26+** (`quay.io/keycloak/keycloak:26.5`) uses these `KC_BOOTSTRAP_ADMIN_*` names, not `KEYCLOAK_ADMIN` / `KEYCLOAK_ADMIN_PASSWORD`.

The **`controlplane`** realm dev user `chris@fyberlabs.com` is for the **SPA** (OIDC) only. If you see `expired_code`, close the tab and start the login again (stale OAuth state).

## Database

Compose uses a dedicated Postgres database `keycloak` (`KC_DB_URL` → `jdbc:postgresql://postgres:5432/keycloak`). The file [../postgres/docker-entrypoint-initdb.d/02_create_keycloak_db.sql](../postgres/docker-entrypoint-initdb.d/02_create_keycloak_db.sql) only runs when the Postgres data volume is **first** created. For volumes created earlier, the **`keycloak-db-init`** service in `docker-compose.yaml` creates `keycloak` on each `docker compose up` if it is missing, so Keycloak can connect.

## Issuer and JWKS

- **Public issuer** (matches the `iss` claim in access tokens when you open the admin UI from the host):  
  `http://localhost:8081/realms/controlplane`
- **JWKS** (used by the API to validate RS256 signatures): use **`jwks_uri`** from the realm OpenID configuration. Keycloak **26+**:  
  `http://localhost:8081/realms/controlplane/protocol/openid-connect/certs`  
  (older Keycloak versions used `.../protocol/openid-certs`.)

**Docker Compose:** API containers use **`http://host.docker.internal:8081/.../openid-connect/certs`** with **`extra_hosts: host.docker.internal:host-gateway`** so JWKS is fetched through the host-mapped Keycloak port. `iss` must still match the browser-facing issuer (see `KEYCLOAK_ISSUER` in `docker-compose.yaml`).

## Realm import

On first start with `--import-realm`, Keycloak loads [import/controlplane-realm.json](import/controlplane-realm.json) (realm `controlplane`). Later restarts **skip** an already-imported realm. Changing redirect URIs in git does not update a live `auth.test` client.

`controlplane-frontend` Valid redirect URIs include localhost Next/Vite plus `https://portal.test.hyperme.sh/*`, `https://portal.test.hyperme.sh/api/auth/callback`, and `https://portal.test.hyperme.sh/api/auth/callback/keycloak` (Auth.js Keycloak provider). Web origin: `https://portal.test.hyperme.sh`. Do not add a second client.

After merge, apply those URIs on the live client (existing admin path — no new seed):

1. **Admin Console** — local: `http://localhost:8081/admin/`. On pan-test: SSH or Tailscale to the VM, then `http://127.0.0.1:8081/admin/` (master realm, `KC_BOOTSTRAP_ADMIN_*` / KV `panopticon-test-keycloak-admin-password`). Public `https://auth.test.hyperme.sh/admin/` is denied at HAProxy. Then realm `controlplane` → Clients → `controlplane-frontend` → Valid redirect URIs + Web origins. See [deploy-vm.md](../../docs/deploy-vm.md#keycloak-behind-haproxy).
2. **Admin REST / `kcadm`** — same `admin-cli` token `seed_pan_test_identities.py` already uses. GET `/admin/realms/controlplane/clients?clientId=controlplane-frontend`, then PUT the client representation with the extra URIs. The seed itself only upserts identities + the groups mapper; it does **not** patch redirects.

### OAuth2 / OIDC clients (Phase 3)

| Client ID | Flow | Notes |
|-----------|------|--------|
| `controlplane-frontend` | Authorization Code + **PKCE** | Next.js / Vite web console |
| `controlplane-mobile` | Authorization Code + **PKCE** | Expo / React Native; adjust `redirectUris` for your app scheme |
| `controlplane-device` | **Device Authorization Grant** | CLI, embedded; enable in client **Advanced** if import omits it |
| `hypermesh-native` | Authorization Code + **PKCE S256** and **Device Authorization Grant** | Visor and CLI. Public, no secret. Redirect `http://127.0.0.1/callback` (no port). Session idle 30 min, max 10 h, device code 600 s. |
| `s3rch-web` | Authorization Code + **PKCE S256** | s3r.ch backup door. Public, no secret. Same realm brokers (`microsoft`, `github`, `google`). Redirects are the exact `/api/identity/oauth/callback` URIs on `https://s3r.ch`, `https://www.s3r.ch`, and local Next on port 3000. Not in `KEYCLOAK_ALLOWED_CLIENT_IDS`. |
| `controlplane-m2m` | **Client Credentials** | Confidential; default secret `dev-m2m-client-secret-change-me` — **rotate in prod** |
| `controlplane-api-key` | (placeholder) | `azp` for gateway-minted HS256 tokens; not a Keycloak login client |

JWT validation in the API allows any `azp` in `KEYCLOAK_ALLOWED_CLIENT_IDS` (see `docker-compose.yaml`). API keys are validated separately via [api-keys-service](../../core/api-keys-service/) and exchanged for short-lived HS256 tokens (`API_KEY_EXCHANGE_JWT_SECRET`).

`hypermesh-native` is declared in [import/controlplane-realm.json](import/controlplane-realm.json). `--import-realm` loads that file on first Keycloak start and skips a realm that already exists. [configure_idp_brokers.py](configure_idp_brokers.py) upserts this client on a live realm before the IdP broker step: one row for `clientId=hypermesh-native`, the same internal id on re-run, no client secret. Attributes and client scopes are replaced from that declaration. Protocol mappers are the frontend `groups` mapper plus the `idp_*` claim mappers from `idp_enterprise.token_claim_mappers()`, the same source the live frontend client uses. A hand edit does not keep a longer session, an extra scope, or a stray mapper. A failure of this step, including a network error, is printed on its own as `hypermesh-native client was not applied` and does not depend on the broker step. FyberLabs/infra `terraform/panopticon-test/files/refresh-test.sh` runs that script after compose up, which is the deploy that applies it at `https://auth.test.hyperme.sh`. Do not create the client in the admin console.

The visor and CLI request scope `openid` only. Default client scopes `basic`, `roles`, `email`, `profile`, and `acr` are the accepted meaning of that request. `web-origins`, `address`, `phone`, and `microprofile-jwt` are not assigned. `offline_access` is not assigned. Access tokens stay on the realm lifespan (300s). Client session caps are 30 minutes idle and 10 hours max. Device codes last 600 seconds. Offline session attributes are cleared on each run.

`KEYCLOAK_ALLOWED_CLIENT_IDS` defaults include `hypermesh-native` (Compose and `Settings`). The full revocation path is in [docs/oidc-console.md](../../docs/oidc-console.md): remove the id and recreate the services that read it. Already-issued tenant sessions last up to 900 seconds. To stop Keycloak issuing tokens, set `enabled` to false in the realm file. A console disable is put back on the next refresh. Application code does not put the id back.

`s3rch-web` is declared in the same realm file and upserted by the same script, in its own step after `hypermesh-native` and before the broker update. One row for `clientId=s3rch-web`, the same internal id on re-run, no client secret. Redirect URIs are exact callback paths (no wildcard). Protocol mappers are only `idp_enterprise.token_claim_mappers()`. A failure of this step is printed on its own as `s3rch-web client was not applied` and does not stop the native client or the brokers. Do not create a second IdP or a Microsoft / GitHub / Google app for s3r.ch. Do not add `s3rch-web` to `KEYCLOAK_ALLOWED_CLIENT_IDS`: the backup session is an s3r.ch cookie, not a control-plane access token.

### Host setup device login

`hypermesh-host-setup` displays **Hypermesh host setup** during device consent.
It is a public device-only client with S256 PKCE, default scopes `basic` and
`email`, and no optional scopes. Profile, roles, groups, enterprise IdP claims,
redirect-based login and offline access are excluded. Its explicit audience
mapper lets the dedicated setup endpoints validate the device token.
Subject and email identify the existing account; tenant membership and host
organization authority are checked against the database. Scope reduction does
not replace those authorization checks.

The realm import and `configure_idp_brokers.py` apply the same declaration.
Live refresh removes extra scopes and mappers, and reports host-client failures
separately. The client stays outside `KEYCLOAK_ALLOWED_CLIENT_IDS`. Generic JWT
validation rejects it even if an old deployment override includes it. The
installer calls only `/auth/host-setup/me`, `/auth/host-setup/enrollment/grant`
(host membership only), and `/auth/host-setup/session`. The last endpoint checks
membership and bans, then issues a 15-minute session with a dedicated issuer,
audience and `host_setup` purpose, containing subject, email and tenant only.
It never copies account roles, groups or permissions. Generic tenant-session
validation rejects this session and legacy generic sessions bearing this client
ID. Only registration and certification owner-approval APIs decode it; tenant
headers remain cross-checks. To stop new setup logins, disable the client in
Keycloak's declared configuration; issued sessions expire after 15 minutes.
Deploy this backend/realm change before releasing the installer client change.

Registration and certification owner approval accept the dedicated client and
the legacy `hypermesh-native` client so previously downloaded installers can
finish. Browser registration approval still requires `controlplane-frontend`;
device sign-in alone does not approve a host or enable selling. The visor/CLI
client retains its existing behavior. After rollout, verify the real device
flow on AGX and confirm both the sign-in name and separate host approval.

### Bootstrap user (OIDC / IdP, not a standing password)

The realm file includes `chris@fyberlabs.com` so the test plane has one mailbox without hand-creating a user in the Keycloak UI:

| Field | Value |
|--------|--------|
| Username / email | `chris@fyberlabs.com` |
| Password | none in git (no standing password in the realm import) |
| First login | `UPDATE_PASSWORD` + `CONFIGURE_TOTP` (user required actions; WebAuthn is not required) |

The API seeds **roles** on every environment (`admin`, `user`, `guest`, `billing_manager`) so OIDC JIT can resolve `GUEST` / `ADMIN`. A hashed `ADMIN_PASSWORD` user and 100 fake guests run only when `FASTAPI_ENV=development`. After first OIDC login, `keycloak_sub` is filled and `ADMIN_EMAIL` / `BOOTSTRAP_ADMIN_EMAILS` still promote JIT to `admin`. If you already imported the realm **without** this user, add the user in the Keycloak admin console or wipe Keycloak’s DB/volume and re-import.

Split pan-test users (`renter`, `leaser`, `admin`) are documented below. They are not this mailbox. Controlplane user `admin` is not `KC_BOOTSTRAP_ADMIN_*` (master realm).

### Microsoft Entra — `groups` claim and platform ADMIN

To grant **ADMIN** from Entra membership in a single-tenant setup:

1. In Entra, note the **Object ID** of the admin security group.
2. In Keycloak (broker or token mapper), ensure the access token includes a **`groups`** claim (list of group IDs or names as emitted by your mapper).
3. Set **`ENTRA_ADMIN_GROUP_IDS`** on the API (comma-separated object IDs, case-insensitive). On JIT user create/link, if any token group matches, the user gets the **ADMIN** role.

Alternatively, add the user’s email to **`BOOTSTRAP_ADMIN_EMAILS`** or rely on **`ADMIN_EMAIL`** matching the signed-in account. See [OIDC console env](../../docs/oidc-console.md#backend-compose--env).

## Identity providers (imported brokers)

The realm import declares three brokers so Keycloak (and the Next.js console via `kc_idp_hint`) can offer the same IdPs FyberLabs/infra uses for GitLab: **Microsoft Entra**, **GitHub**, and **Google**. Aliases are `microsoft`, `github`, and `google`.

Client IDs and secrets are **not** committed. Keycloak substitutes `${ENV:default}` placeholders on `--import-realm` (first start only; later restarts skip an existing realm).

| Alias | Display name | Type | Env vars | Default if unset |
|-------|--------------|------|----------|------------------|
| `microsoft` | Microsoft Entra | OpenID Connect (Entra tenant issuer) | `KC_IDP_MICROSOFT_CLIENT_ID`, `KC_IDP_MICROSOFT_CLIENT_SECRET`, `KC_IDP_MICROSOFT_TENANT_ID` | `unset-microsoft-client-*`, tenant `common` |
| `github` | GitHub | GitHub | `KC_IDP_GITHUB_CLIENT_ID`, `KC_IDP_GITHUB_CLIENT_SECRET` | `unset-github-client-*` |
| `google` | Google | Google | `KC_IDP_GOOGLE_CLIENT_ID`, `KC_IDP_GOOGLE_CLIENT_SECRET` | `unset-google-client-*` |

### How to fill client ID / secret

One OAuth app per provider. Do not commit the client id or secret.

| Env var | Key Vault (test plane) |
|---------|------------------------|
| `KC_IDP_MICROSOFT_CLIENT_ID` | `panopticon-test-idp-microsoft-client-id` |
| `KC_IDP_MICROSOFT_CLIENT_SECRET` | `panopticon-test-idp-microsoft-client-secret` |
| `KC_IDP_MICROSOFT_TENANT_ID` | `panopticon-test-idp-microsoft-tenant-id` |
| `KC_IDP_GITHUB_CLIENT_ID` | `panopticon-test-idp-github-client-id` |
| `KC_IDP_GITHUB_CLIENT_SECRET` | `panopticon-test-idp-github-client-secret` |
| `KC_IDP_GOOGLE_CLIENT_ID` | `panopticon-test-idp-google-client-id` |
| `KC_IDP_GOOGLE_CLIENT_SECRET` | `panopticon-test-idp-google-client-secret` |

`refresh-test.sh` reads those names and runs `configure_idp_brokers.py` after Keycloak is up. Import is first-start only, so a realm that already exists does not see new env values until that script updates the broker. Empty client id or secret leaves that broker unchanged. Use real broker credentials only.

The same refresh sets `KC_TEST_REGISTRATION=1`. That opens Register on the live test realm only: email is the username, and email verification stays off because this plane has no mailer. The realm file stays `registrationAllowed: false`, and the password grant stays disabled. An account created there does not move to production and can be lost when the test database is replaced. Do not set `KC_TEST_REGISTRATION` on a production import.

Leave the Microsoft tenant empty or set `common` so one app accepts a personal Microsoft account and a work account. A specific tenant id is organization-only.

The script copies `idp_provider`, the org key (`tid` or hosted domain), and Entra directory role ids (`wids`) onto the access token. It does not map an org to an enterprise. That binding is an organization-owner setting in Panopticon: the owner signs in as a Global Administrator of that tenant, with that Google hosted domain, or as a member of that GitHub org, and saves the link on the enterprise.

A personal account stays an individual: Microsoft tenant `9188040d-6c67-4c5b-b112-36a304b66dad`, Google with no hosted domain, GitHub with no org on the profile. GitHub org membership is not in the default profile.

Register **broker** redirect URIs at each IdP (not the SPA origin):

| Provider | Local callback | Test plane |
|----------|----------------|------------|
| Microsoft Entra | `http://localhost:8081/realms/controlplane/broker/microsoft/endpoint` | `https://auth.test.hyperme.sh/realms/controlplane/broker/microsoft/endpoint` |
| GitHub | `http://localhost:8081/realms/controlplane/broker/github/endpoint` | `https://auth.test.hyperme.sh/realms/controlplane/broker/github/endpoint` |
| Google | `http://localhost:8081/realms/controlplane/broker/google/endpoint` | `https://auth.test.hyperme.sh/realms/controlplane/broker/google/endpoint` |

Other providers (Facebook, X, SAML Entra) can still be added in Admin Console if needed.

### Microsoft Entra ID — redirect URI (AADSTS50011)

Entra validates the **broker callback** Keycloak uses, not the Vite URL. The path includes your realm and the **Identity provider alias** from Keycloak (the slug in the admin URL, e.g. `microsoft`).

Add this **exact** redirect URI in the Entra app registration: **Authentication → Add a platform → Web → Redirect URIs** (or edit an existing Web platform):

```text
http://localhost:8081/realms/controlplane/broker/microsoft/endpoint
```

Replace `microsoft` if your IdP alias is different. In Keycloak: **Identity providers →** your provider → copy the **Redirect URI** shown there and paste it into Entra (match **scheme, host, port, path** — no extra trailing slash unless Keycloak shows one).

If Keycloak is on another host/port (e.g. production), register that full broker URL in Entra instead. Using `https` in Entra but sending `http` from Keycloak (or the reverse) will also trigger `AADSTS50011`.

### Broker users: email in the **access** token

The control plane API only sees the **Bearer access token** on `/account/me`. If the SPA loads in Keycloak but the app says your user is missing, the token often lacks a valid **`email`** (or UPN-style) claim. In the Keycloak admin UI, add an **Identity provider mapper** (or user attribute mapper) so the IdP’s mail/UPN is copied into OIDC claims the client receives, and keep the **`email`** client scope on `controlplane-frontend`. See [OIDC console — backend env](../../docs/oidc-console.md#backend-compose--env) for `OIDC_EXTRA_EMAIL_CLAIMS` if your IdP uses a non-standard claim name.

## MFA

The realm import **configures** OTP (TOTP) and WebAuthn as optional required actions (`CONFIGURE_TOTP`, `webauthn-register`, `webauthn-register-passwordless`, recovery codes). They are **enabled but not default** (`defaultAction: false`) so unattended local smoke that never completes `chris@fyberlabs.com` login still works (`test_mfa_is_optional_but_configured`).

The imported `chris@fyberlabs.com` user has no password in git. First login uses an IdP broker (or a password an admin sets in Admin Console / reset mail). User required actions are `UPDATE_PASSWORD` + `CONFIGURE_TOTP`. WebAuthn stays available and preferred for that mailbox; it is **not** a required action, so it does not block first TEST Checkout. `OIDC_REQUIRE_MFA` stays false until after first login.

### Pan-test identities (renter / leaser / admin)

Three **split** controlplane users for the test plane. Never one user with all roles. `controlplane-frontend` stays public PKCE; direct access grants stay off.

| Username | Email | Portal grant path | Not |
|----------|-------|-------------------|-----|
| `renter` | `renter@test.hyperme.sh` | Keycloak group `/renter` + realm role `renter` → `can_checkout` / `can_see_leases` / mint keys | host |
| `leaser` | `leaser@test.hyperme.sh` | Keycloak group `/host` + realm role `host` → `can_see_host_status` (own host posture / `sell_state`) | `can_checkout`. There is **no** `leaser` role or group. |
| `admin` | `admin@test.hyperme.sh` | New portal realm role `admin` (customer-support / user / org). Not `KC_BOOTSTRAP_ADMIN_*`. After switch-tenant the tenant-session JWT also carries `operator:console`, `operator:support`, `operator:program`, and `operator:resolve`. | renter, host, `can_checkout`, `org:own`, `org:manage`. No refund/coupon API or screens in this seed. RoleNav still switches Renter\|Host. |

`evaluate_portal_controls` reads those Keycloak groups (and same-named realm roles). The `admin` role is org/support admin only: invite/assign/mint/IR. It does **not** inherit renter or host grants.

Keycloak `--import-realm` creates the users/groups/roles on **first** start only, with **no passwords** and **no** `UPDATE_PASSWORD` / `CONFIGURE_TOTP` (do not copy the chris required actions). Re-import is not idempotent for an existing realm. Run the upsert seed after Keycloak is up:

```bash
# Env vars must already be present (refresh injects from KV). Empty fails closed.
./scripts/seed-pan-test-identities.sh
```

The deployment entrypoint validates all required credentials before making any
request, waits up to 60 seconds for `/realms/master`, then calls the existing
seed once. `KEYCLOAK_URL` defaults to loopback `http://127.0.0.1:8081`.
A missing credential, readiness timeout, or seed error returns nonzero. It does
not source `.env`; the caller must inject the vault values into the process
environment, including `KC_BOOTSTRAP_ADMIN_USERNAME` and
`KC_BOOTSTRAP_ADMIN_PASSWORD`. Do not put credentials in command arguments.
`--wait-seconds N` overrides the readiness budget; the raw Python seed retains
its no-wait default. Existing passwords change only with `--rotate-passwords`.

For #210, infra can replace its readiness/invocation block with this entrypoint
after the new revision is live and verified on pan-test. Keep vault passthrough.
No replacement password generation, production invocation, or infra removal is
part of this change.

| Env var | Key Vault secret name |
|---------|-----------------------------|
| `PANOPTICON_TEST_RENTER_PASSWORD` | `panopticon-test-renter-password` |
| `PANOPTICON_TEST_LEASER_PASSWORD` | `panopticon-test-leaser-password` |
| `PANOPTICON_TEST_PORTAL_ADMIN_PASSWORD` | `panopticon-test-portal-admin-password` |

Do **not** reuse `panopticon-test-keycloak-admin-password` (`KC_BOOTSTRAP_ADMIN_PASSWORD`) or `panopticon-test-admin-password` (`ADMIN_PASSWORD`). Put the three values in Key Vault; refresh injects the env names and runs this seed. The seed never generates a password into git. Rerun does not rotate passwords unless you pass `--rotate-passwords`.

Keycloak’s default browser flow already includes **Conditional OTP**: after a user enrolls TOTP (Account Console or an admin-assigned required action), they are prompted. WebAuthn is available as a required action the same way.

To **require** MFA for everyone later: set **Configure OTP** (or WebAuthn) as a default required action in Admin Console, or assign it to a group/role. Do not flip `defaultAction` in the import to `true` unless you want first login to force enrollment for every user (breaks unattended local password smoke tests).

## SPA env (interim Vite / future Next.js)

- `VITE_KEYCLOAK_URL` = `http://localhost:8081` (no trailing slash)
- `VITE_KEYCLOAK_REALM` = `controlplane`
- `VITE_KEYCLOAK_CLIENT_ID` = `controlplane-frontend`

See [frontend OIDC contract](../docs/oidc-console.md) for redirect URIs and client settings shared with Next.js.


The public installer entrypoints are `/auth/host-setup/*` (without `/api/v1`).
Gateway authentication validates the device token only for GET `me`, POST
`enrollment/grant`, and POST `session`. It validates the purpose-bound session
only for registration create/read/complete and certification owner approval or
resume. These paths remain authenticated, with exact method/path matching and
tenant cross-checks; backend ownership checks still apply. Setup credentials
never use the gateway's unverified development fallback. Gateway proxy tests
exercise signed tokens through policy and forwarding, beyond direct service tests.

### Portal sign-out

The portal clears its Auth.js session and tenant cache, then navigates the browser
through Keycloak's OIDC logout endpoint. Keycloak can request logout confirmation;
complete it to end the realm SSO session. Its return page is `/signed-out`, which
stays public until the user chooses to sign in again. This does not sign the user
out of an upstream Microsoft, Google, or GitHub account.

`configure_idp_brokers.py` reconciles the frontend client's explicit test,
production and local post-logout return URLs during deployment. Apply that realm
configuration with the frontend change; changing the import alone does not update
an existing realm. `AUTH_URL`, when configured, supplies the public portal origin.

### Portal logout deployment ordering

The test portal image workflow reconciles and reads back the existing Keycloak
client's logout allowlist before changing the App Service image. It sends the
checked-out reconciler to the single test-plane VM in the configured resource
group. The VM uses its configured managed identity and Key Vault admin password;
credentials remain on the VM. A missing VM, failed reconciliation, or unconfirmed
guest result stops rollout while leaving the current portal image running.
Production realm reconciliation must likewise precede portal rollout.

## Human and AI/service account classification

Private model admission in [Panopticon #374](https://github.com/FyberLabs/panopticon/pull/374)
requires both a named human binding and verified interactive authentication.
`account_type` is an administrator-owned, single-value profile attribute with
only `human` and `service` allowed. Account self-service, registration, and
brokered email/group claims cannot set it. A password, OTP, role, or email alone
does not classify a principal as human. The frontend mapper reads this protected
attribute; client-credential clients always emit `service`.

Use a separate service account/client for an AI or automation process. AI using
a browser account must have `account_type=service`, even if it uses password or
OTP authentication. Do not share a named person's credentials with automation.
An unclassified account remains unable to approve private models. Classification
does not grant any tenant role; #374 separately checks active auditor/admin
membership and purpose-bound frontend sessions. The shared `renter`, `leaser`,
and `admin` test identities are classified as `service`; a separately provisioned
named person is required for human approval tests.

The realm import declares profile protection and token mappers. Keycloak skips
an existing realm during import, so run the following setup on **both fresh and
existing realms**, before enabling private admission:

```sh
# Credentials come from the existing secret injection, not CLI arguments.
# Run beside Keycloak through its private/loopback Admin API.
export KEYCLOAK_INTERNAL_URL=http://127.0.0.1:8081
python3 infra/keycloak/account_types.py

# After an administrator verifies the named person, use the immutable Keycloak
# user UUID from the Admin Console. Repeat flags to classify more accounts.
python3 infra/keycloak/account_types.py --human-user-id <person-user-uuid>
python3 infra/keycloak/account_types.py --service-user-id <ai-user-uuid>
```

The script uses `KC_BOOTSTRAP_ADMIN_USERNAME` and
`KC_BOOTSTRAP_ADMIN_PASSWORD`. It preserves unrelated profile metadata and client
mappers, reconciles its owned mappers, and configures authenticator references on
the realm's current browser flow (`pwd`, `otp`, `webauthn`). These references
record completed authenticators through Keycloak's AMR mapper; the script never
hardcodes `pwd` into tokens or changes authentication requirements. Unsupported
custom flows fail setup rather than manufacturing evidence. Duplicate account
claim mappers also fail setup. Client service accounts cannot be classified as
human by the script. Use only trusted administrators for this operation and do
not configure an upstream broker mapper to write `account_type`.

Existing named people require explicit classification by UUID. New registrations
and brokered users receive no default human classification. Sign in again after
classification to obtain fresh claims; older tokens retain their original claims
until expiry. Broker-only sessions without a completed supported authenticator
remain unable to approve: their authentication flow must provide verified AMR
before rollout. Check `account_type=human`, an actual completed-method `amr`, and
successful tenant-session forwarding with #374 before enabling admission.
Revoking human status also requires revoking existing sessions or waiting for
issued tokens to expire. Disabling private admission is the immediate rollback;
keep the protected attribute and classification evidence.

Relevant Keycloak contracts: [user profile permissions](https://www.keycloak.org/docs/26.5.7/server_admin/index.html#user-profile)
and [token/AMR mappers](https://www.keycloak.org/admin-api/protocol-mappers).

The opt-in live regression runs against a disposable loopback Keycloak 26.5
container, using `KEYCLOAK_CLASSIFICATION_TEST_URL` and
`KEYCLOAK_CLASSIFICATION_TEST_ADMIN_PASSWORD`. It replaces that container's
`controlplane` realm, checks real PKCE and client-credential tokens, and attempts
self-service classification forgery. Never point it at a shared or deployed realm.

## Production account creation

Production keeps local self-registration disabled. New portal accounts use
Microsoft, GitHub or Google; `/signup` starts provider sign-in without
`prompt=create`. Existing local accounts can still sign in. Email/password
registration needs verified email delivery before it can be offered; the
`KC_TEST_REGISTRATION=1` override remains test-plane only. This implements
option 2 from Panopticon #372 without enabling an unconfigured production mailer.
