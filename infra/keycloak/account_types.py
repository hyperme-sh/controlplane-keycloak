#!/usr/bin/env python3
"""Administrator-owned human/service classification for private admission."""

from __future__ import annotations

import argparse
import copy
import os
import sys
import uuid
from pathlib import Path
from urllib.parse import quote

KEYCLOAK_DIR = str(Path(__file__).resolve().parent)
if KEYCLOAK_DIR not in sys.path:
    sys.path.insert(0, KEYCLOAK_DIR)

ATTRIBUTE = {
    "name": "account_type",
    "displayName": "Account type (administrator verified)",
    "multivalued": False,
    "permissions": {"view": ["admin"], "edit": ["admin"]},
    "validations": {"options": {"options": ["human", "service"]}},
}
HUMAN_MAPPER = {
    "name": "account_type",
    "protocol": "openid-connect",
    "protocolMapper": "oidc-usermodel-attribute-mapper",
    "consentRequired": False,
    "config": {
        "user.attribute": "account_type", "claim.name": "account_type",
        "jsonType.label": "String", "multivalued": "false",
        "aggregate.attrs": "false", "id.token.claim": "true",
        "access.token.claim": "true", "userinfo.token.claim": "false",
    },
}
SERVICE_MAPPER = {
    "name": "account_type", "protocol": "openid-connect",
    "protocolMapper": "oidc-hardcoded-claim-mapper", "consentRequired": False,
    "config": {"claim.name": "account_type", "claim.value": "service",
               "jsonType.label": "String", "id.token.claim": "true",
               "access.token.claim": "true", "userinfo.token.claim": "false"},
}
AMR_MAPPER = {
    "name": "verified_authentication_methods", "protocol": "openid-connect",
    "protocolMapper": "oidc-amr-mapper", "consentRequired": False,
    "config": {"id.token.claim": "true", "access.token.claim": "true"},
}
REFERENCES = {
    "auth-username-password-form": "pwd", "auth-otp-form": "otp",
    "webauthn-authenticator": "webauthn",
    "webauthn-authenticator-passwordless": "webauthn",
}


class AccountTypeError(RuntimeError):
    """Configuration failed; no credential or token is included in errors."""


def protected_profile(profile):
    result = copy.deepcopy(profile)
    attributes = result.get("attributes")
    if not isinstance(attributes, list):
        raise AccountTypeError("User profile attributes are unavailable")
    result["attributes"] = [a for a in attributes if a.get("name") != "account_type"] + [copy.deepcopy(ATTRIBUTE)]
    return result


def mapper_matches(current, wanted):
    return all(current.get(k) == value for k, value in wanted.items() if k != "config") and all(
        (current.get("config") or {}).get(k) == value for k, value in wanted["config"].items()
    )


def ensure_mapper(admin, client_id, wanted):
    path = f"/clients/{client_id}/protocol-mappers/models"
    existing = admin.get(path) or []
    # Reject ambiguity rather than leaving another mapper able to override it.
    matches = [m for m in existing if m.get("name") == wanted["name"] or
               (m.get("config") or {}).get("claim.name") == wanted["config"].get("claim.name", "amr") or
               wanted["protocolMapper"] == m.get("protocolMapper") == "oidc-amr-mapper"]
    if len(matches) > 1:
        raise AccountTypeError("Duplicate account classification or AMR mappers")
    if matches:
        current = matches[0]
        if not mapper_matches(current, wanted):
            admin.put(path + "/" + current["id"], {**wanted, "id": current["id"]})
    else:
        admin.post(path, wanted)
    verified = admin.get(path) or []
    if not any(mapper_matches(m, wanted) for m in verified):
        raise AccountTypeError("Token mapper verification failed")


def ensure_references(admin):
    realm = admin.get("")
    flow = realm.get("browserFlow")
    if not flow:
        raise AccountTypeError("Browser authentication flow is unavailable")
    count = 0
    for execution in admin.get(f"/authentication/flows/{quote(flow, safe='')}/executions") or []:
        reference = REFERENCES.get(execution.get("providerId"))
        if reference is None:
            continue
        config_id = execution.get("authenticationConfig")
        if config_id:
            current = admin.get("/authentication/config/" + config_id)
            config = {**(current.get("config") or {}), "default.reference.value": reference}
            if current.get("config") != config:
                admin.put("/authentication/config/" + config_id, {**current, "config": config})
        else:
            admin.post(f"/authentication/executions/{execution['id']}/config", {
                "alias": "admission-amr-" + execution["id"],
                "config": {"default.reference.value": reference},
            })
        count += 1
    if count == 0:
        raise AccountTypeError("No supported interactive browser authenticators found")


def configure(admin):
    profile = protected_profile(admin.get("/users/profile"))
    admin.put("/users/profile", profile)
    verified = admin.get("/users/profile")
    if next((a for a in verified.get("attributes", []) if a.get("name") == "account_type"), None) != ATTRIBUTE:
        raise AccountTypeError("Administrator-only account classification was not applied")
    clients = admin.get("/clients") or []
    frontend = [c for c in clients if c.get("clientId") == "controlplane-frontend"]
    if len(frontend) != 1:
        raise AccountTypeError("Exactly one frontend client is required")
    details = admin.get("/clients/" + frontend[0]["id"])
    if details.get("publicClient") is not True or details.get("serviceAccountsEnabled") or details.get("directAccessGrantsEnabled"):
        raise AccountTypeError("Frontend must remain public PKCE without machine/password grants")
    ensure_mapper(admin, frontend[0]["id"], HUMAN_MAPPER)
    ensure_mapper(admin, frontend[0]["id"], AMR_MAPPER)
    for client in clients:
        if client.get("serviceAccountsEnabled"):
            ensure_mapper(admin, client["id"], SERVICE_MAPPER)
    ensure_references(admin)


def classify(admin, user_id, account_type):
    if account_type not in {"human", "service"}:
        raise AccountTypeError("Unsupported account classification")
    user_id = str(uuid.UUID(user_id))
    current = admin.get("/users/" + user_id)
    if account_type == "human" and (current.get("serviceAccountClientId") or current.get("username", "").startswith("service-account-")):
        raise AccountTypeError("A client service account cannot be classified as human")
    attributes = {**(current.get("attributes") or {}), "account_type": [account_type]}
    admin.put("/users/" + user_id, {**current, "attributes": attributes})
    if (admin.get("/users/" + user_id).get("attributes") or {}).get("account_type") != [account_type]:
        raise AccountTypeError("Account classification verification failed")


def main(argv=None):
    from configure_idp_brokers import AdminClient, ConfigureError, admin_token

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--human-user-id", action="append", default=[])
    parser.add_argument("--service-user-id", action="append", default=[])
    args = parser.parse_args(argv)
    if set(args.human_user_id) & set(args.service_user_id):
        parser.error("An account cannot be both human and service")
    base = os.environ.get("KEYCLOAK_INTERNAL_URL", "http://127.0.0.1:8081")
    username = os.environ.get("KC_BOOTSTRAP_ADMIN_USERNAME", "")
    password = os.environ.get("KC_BOOTSTRAP_ADMIN_PASSWORD", "")
    if not username or not password:
        print("ERROR: Bootstrap administrator credentials are required", file=sys.stderr)
        return 1
    try:
        admin = AdminClient(base, admin_token(base, username, password))
        configure(admin)
        for kind, ids in [("human", args.human_user_id), ("service", args.service_user_id)]:
            for user_id in ids:
                classify(admin, user_id, kind)
    except (AccountTypeError, ConfigureError, ValueError) as exc:
        print(f"ERROR: account classification setup failed: {exc}", file=sys.stderr)
        return 1
    print("Account classification and verified authentication mappers configured")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
