# Keycloak (local dev)

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
