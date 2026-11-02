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
