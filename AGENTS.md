# Keycloak tooling development

This repository owns the realm declaration and its reconciliation helpers.
Keep client scopes, protected identity attributes, mapper ownership and failure
behavior explicit. Run `bash scripts/check-tooling.sh` for offline checks.
Tests must use fake admin APIs and must not call a deployed realm. Runtime admin
scripts require separately configured credentials and deployment authority.
