# Keycloak (local dev)

## Admin console vs application login

The **Keycloak Admin Console** at `http://localhost:8081/admin/` uses the **`master`** realm. Sign in with the bootstrap admin from Compose (`KEYCLOAK_ADMIN` / `KEYCLOAK_ADMIN_PASSWORD`, e.g. `admin` / `admin123`) — **not** `admin@example.com`. The `user_not_found` / wrong-realm errors in logs usually mean someone tried the app user on the admin console.

The **`controlplane`** realm user `admin@example.com` is for the **SPA** (OIDC) only. If you see `expired_code`, close the tab and start the login again (stale OAuth state).

## Database

Compose uses a dedicated Postgres database `keycloak` (`KC_DB_URL` → `jdbc:postgresql://postgres:5432/keycloak`). The file [../postgres/docker-entrypoint-initdb.d/02_create_keycloak_db.sql](../postgres/docker-entrypoint-initdb.d/02_create_keycloak_db.sql) only runs when the Postgres data volume is **first** created. For volumes created earlier, the **`keycloak-db-init`** service in `docker-compose.yaml` creates `keycloak` on each `docker compose up` if it is missing, so Keycloak can connect.

## Issuer and JWKS

- **Public issuer** (matches the `iss` claim in access tokens when you open the admin UI from the host):  
  `http://localhost:8081/realms/controlplane`
- **JWKS** (used by the API to validate RS256 signatures):  
  `http://localhost:8081/realms/controlplane/protocol/openid-certs`  
  From other Docker services, the same keys are available at:  
  `http://keycloak:8080/realms/controlplane/protocol/openid-certs`

The API should fetch JWKS from the URL reachable inside its network (`keycloak:8080` in Compose) while validating that `iss` equals the **browser-facing** issuer above (see `KEYCLOAK_ISSUER` in `docker-compose.yaml`).

## Realm import

On first start with `--import-realm`, Keycloak loads [import/controlplane-realm.json](import/controlplane-realm.json) (realm `controlplane`, public client `controlplane-frontend` with PKCE).

### Dev bootstrap user (matches API seed)

The realm file includes a **platform admin** user so you can sign in to the SPA without hand-creating a user in the Keycloak UI:

| Field | Value |
|--------|--------|
| Username / email | `admin@example.com` |
| Password | `Test@123!` (same as `ADMIN_PASSWORD` in `docker-compose.yaml`) |

The API seeds a row in PostgreSQL with the same `ADMIN_EMAIL` on startup in `FASTAPI_ENV=development` (see `controlplane-core` `seed_initial_data`). After first OIDC login, `keycloak_sub` is filled on that user. If you already imported the realm **without** this user, add the user in the Keycloak admin console or wipe Keycloak’s DB/volume and re-import.

## Identity providers (configure in Admin Console)

Add brokers under **Identity providers** so users sign in via Keycloak (one hosted login; no per-provider OAuth in FastAPI):

| Provider | Type in Keycloak | Notes |
|----------|------------------|--------|
| Google | OpenID Connect / Google | Client ID + secret from Google Cloud Console |
| GitHub | OpenID Connect / GitHub | OAuth App callback URL → Keycloak broker |
| Microsoft Entra (internal) | OpenID Connect | Tenant-specific issuer + app registration |
| Microsoft Entra (external / multi-tenant) | OpenID Connect | Common endpoint + separate app registration |
| Microsoft Entra (SAML) | SAML 2.0 | Enterprise app SAML metadata |
| Facebook | OpenID Connect / Facebook | App ID + secret |
| X (Twitter) | OAuth 2.0 (often custom) | Fragile; add last |

Use Keycloak docs for each template; redirect URIs must point to Keycloak (not the SPA).

## MFA

Enable **OTP** or **WebAuthn** under **Authentication → Policies** and **Required actions** (e.g. **Configure OTP** for privileged groups). Start with optional TOTP, then require for realm-admin roles in production.

## SPA env (interim Vite / future Next.js)

- `VITE_KEYCLOAK_URL` = `http://localhost:8081` (no trailing slash)
- `VITE_KEYCLOAK_REALM` = `controlplane`
- `VITE_KEYCLOAK_CLIENT_ID` = `controlplane-frontend`

See [frontend OIDC contract](../docs/oidc-console.md) for redirect URIs and client settings shared with Next.js.
