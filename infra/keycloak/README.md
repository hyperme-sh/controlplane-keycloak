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

`controlplane-frontend` Valid redirect URIs include localhost Next/Vite plus `https://portal.test.hyperme.sh/*`, `https://portal.test.hyperme.sh/api/auth/callback`, and `https://portal.test.hyperme.sh/api/auth/callback/keycloak` (Auth.js Keycloak provider). Web origin: `https://portal.test.hyperme.sh`. Do not invent a second client.

After merge, apply those URIs on the live client (existing admin path — no new seed):

1. **Admin Console** — local: `http://localhost:8081/admin/`. On pan-test: SSH or Tailscale to the VM, then `http://127.0.0.1:8081/admin/` (master realm, `KC_BOOTSTRAP_ADMIN_*` / KV `panopticon-test-keycloak-admin-password`). Public `https://auth.test.hyperme.sh/admin/` is denied at HAProxy. Then realm `controlplane` → Clients → `controlplane-frontend` → Valid redirect URIs + Web origins. See [deploy-vm.md](../../docs/deploy-vm.md#keycloak-behind-haproxy).
2. **Admin REST / `kcadm`** — same `admin-cli` token `seed_pan_test_identities.py` already uses. GET `/admin/realms/controlplane/clients?clientId=controlplane-frontend`, then PUT the client representation with the extra URIs. The seed itself only upserts identities + the groups mapper; it does **not** patch redirects.

### OAuth2 / OIDC clients (Phase 3)

| Client ID | Flow | Notes |
|-----------|------|--------|
| `controlplane-frontend` | Authorization Code + **PKCE** | Next.js / Vite web console |
| `controlplane-mobile` | Authorization Code + **PKCE** | Expo / React Native; adjust `redirectUris` for your app scheme |
| `controlplane-device` | **Device Authorization Grant** | CLI, embedded; enable in client **Advanced** if import omits it |
| `hypermesh-native` | Authorization Code + **PKCE S256** and **Device Authorization Grant** | Visor and CLI. Public, no secret. Redirect `http://127.0.0.1/callback` (no port). `offline_access` is not a default or optional scope. Access tokens use the realm lifespan (300s). |
| `controlplane-m2m` | **Client Credentials** | Confidential; default secret `dev-m2m-client-secret-change-me` — **rotate in prod** |
| `controlplane-api-key` | (placeholder) | `azp` for gateway-minted HS256 tokens; not a Keycloak login client |

JWT validation in the API allows any `azp` in `KEYCLOAK_ALLOWED_CLIENT_IDS` (see `docker-compose.yaml`). API keys are validated separately via [api-keys-service](../../core/api-keys-service/) and exchanged for short-lived HS256 tokens (`API_KEY_EXCHANGE_JWT_SECRET`).

`hypermesh-native` is declared in [import/controlplane-realm.json](import/controlplane-realm.json). `--import-realm` loads that file on first Keycloak start and skips a realm that already exists. [configure_idp_brokers.py](configure_idp_brokers.py) upserts this client on a live realm: one row for `clientId=hypermesh-native`, the same internal id on re-run, no client secret. FyberLabs/infra `terraform/panopticon-test/files/refresh-test.sh` runs that script after compose up, which is the deploy that applies it at `https://auth.test.hyperme.sh`. Do not create the client in the admin console. API `azp` checks always include `hypermesh-native`, including when that refresh script's `KEYCLOAK_ALLOWED_CLIENT_IDS` line was written before this client.

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

`refresh-test.sh` reads those names and runs `configure_idp_brokers.py` after Keycloak is up. Import is first-start only, so a realm that already exists does not see new env values until that script updates the broker. Empty client id or secret leaves that broker unchanged. Do not invent values.

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

The imported `chris@fyberlabs.com` user has no password in git. First login uses an IdP broker (or a password Chris sets in Admin Console / reset mail). User required actions are `UPDATE_PASSWORD` + `CONFIGURE_TOTP`. WebAuthn stays available and preferred for that mailbox; it is **not** a required action, so it does not block first TEST Checkout. `OIDC_REQUIRE_MFA` stays false until after first login.

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
python3 infra/keycloak/seed_pan_test_identities.py
```

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
