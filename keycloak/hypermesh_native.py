#!/usr/bin/env python3
"""Public client ``hypermesh-native`` for the visor and CLI.

The realm file is the declaration. ``--import-realm`` applies it on first
start only. A live realm is updated by ``ensure_hypermesh_native``, which
``configure_idp_brokers.py`` runs. ``refresh-test.sh`` already calls that
script after Keycloak is up, so the next test refresh creates or updates
this one client. Re-run keeps the same internal id, does not add a second
client, and does not mint a secret.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# Loaded by path from tests and from configure_idp_brokers.py.
_KEYCLOAK_DIR = str(Path(__file__).resolve().parent)
if _KEYCLOAK_DIR not in sys.path:
    sys.path.insert(0, _KEYCLOAK_DIR)

from idp_enterprise import token_claim_mappers

CLIENT_ID = "hypermesh-native"
REDIRECT_URI = "http://127.0.0.1/callback"
REALM_PATH = Path(__file__).resolve().parent / "import" / "controlplane-realm.json"

# What "openid only" means for this client. The visor requests scope openid.
# These defaults are always issued. Optional scopes are empty.
DEFAULT_CLIENT_SCOPES = (
    "basic",
    "roles",
    "email",
    "profile",
    "acr",
)
OPTIONAL_CLIENT_SCOPES: tuple[str, ...] = ()

# 30 min idle, 10 h max, device code 600 s. Strings, as Keycloak stores them.
SESSION_IDLE_TIMEOUT = "1800"
SESSION_MAX_LIFESPAN = "36000"
DEVICE_CODE_LIFESPAN = "600"

DECLARED_ATTRIBUTES = {
    "pkce.code.challenge.method": "S256",
    "oauth2.device.authorization.grant.enabled": "true",
    "client.session.idle.timeout": SESSION_IDLE_TIMEOUT,
    "client.session.max.lifespan": SESSION_MAX_LIFESPAN,
    "oauth2.device.code.lifespan": DEVICE_CODE_LIFESPAN,
}

# Hand-edited values here would outlive the SSO session caps. Every run
# sends null so Keycloak drops them. Access tokens stay on the realm default.
CLEARED_ATTRIBUTES = (
    "client.offline.session.idle.timeout",
    "client.offline.session.max.lifespan",
    "access.token.lifespan",
)

FRONTEND_CLIENT_ID = "controlplane-frontend"


class NativeClientError(RuntimeError):
    """The declared client cannot be applied. The message has no secret."""


def load_realm() -> dict[str, Any]:
    return json.loads(REALM_PATH.read_text(encoding="utf-8"))


def declared_client(realm: dict[str, Any] | None = None) -> dict[str, Any]:
    realm = load_realm() if realm is None else realm
    matches = [item for item in realm.get("clients") or [] if item.get("clientId") == CLIENT_ID]
    if len(matches) != 1:
        raise NativeClientError(f"{CLIENT_ID} must appear once in the realm import")
    return matches[0]


def portal_groups_mapper(realm: dict[str, Any]) -> dict[str, Any]:
    """The frontend ``groups`` claim mapper. CLI switch-tenant uses the same one."""
    matches = [
        item
        for item in realm.get("clients") or []
        if isinstance(item, dict) and item.get("clientId") == FRONTEND_CLIENT_ID
    ]
    if len(matches) != 1:
        raise NativeClientError(f"{FRONTEND_CLIENT_ID} must appear once in the realm import")
    groups = [
        item
        for item in matches[0].get("protocolMappers") or []
        if isinstance(item, dict) and item.get("name") == "groups"
    ]
    if len(groups) != 1:
        raise NativeClientError(f"{FRONTEND_CLIENT_ID} groups mapper must appear once")
    return json.loads(json.dumps(groups[0]))


def declared_protocol_mappers(realm: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Groups from the frontend client, then ``idp_*`` from ``token_claim_mappers``.

    The live frontend client is updated from that same function. The realm
    file must list the identical mappers so first import and refresh agree.
    """
    realm = load_realm() if realm is None else realm
    return [portal_groups_mapper(realm), *token_claim_mappers()]


def validate_declared_client(client: dict[str, Any], realm: dict[str, Any] | None = None) -> None:
    """Fail closed if the realm file drifts from the visor contract."""
    if client.get("clientId") != CLIENT_ID:
        raise NativeClientError(f"clientId must be {CLIENT_ID}")
    if client.get("publicClient") is not True:
        raise NativeClientError(f"{CLIENT_ID} must be a public client")
    if client.get("secret"):
        raise NativeClientError(f"{CLIENT_ID} must not have a client secret")
    if client.get("standardFlowEnabled") is not True:
        raise NativeClientError(f"{CLIENT_ID} must enable the standard flow")
    if client.get("implicitFlowEnabled") is not False:
        raise NativeClientError(f"{CLIENT_ID} must disable the implicit flow")
    if client.get("directAccessGrantsEnabled") is not False:
        raise NativeClientError(f"{CLIENT_ID} must disable direct access grants")
    if client.get("serviceAccountsEnabled") is not False:
        raise NativeClientError(f"{CLIENT_ID} must not enable a service account")
    attrs = client.get("attributes") or {}
    if attrs != DECLARED_ATTRIBUTES:
        raise NativeClientError(f"{CLIENT_ID} attributes must be the declared set")
    if attrs.get("access.token.lifespan"):
        raise NativeClientError(f"{CLIENT_ID} must use the realm access-token lifespan")
    redirects = client.get("redirectUris") or []
    if redirects != [REDIRECT_URI]:
        raise NativeClientError(f"{CLIENT_ID} redirect must be {REDIRECT_URI}")
    parsed = urlparse(REDIRECT_URI)
    if parsed.port is not None or parsed.hostname != "127.0.0.1":
        raise NativeClientError(f"{CLIENT_ID} redirect must be loopback with no port")
    if any("3000" in uri for uri in redirects):
        raise NativeClientError(f"{CLIENT_ID} must not pin port 3000")
    if client.get("webOrigins") not in ([], None):
        raise NativeClientError(f"{CLIENT_ID} does not need web origins")
    default_scopes = list(client.get("defaultClientScopes") or [])
    optional_scopes = list(client.get("optionalClientScopes") or [])
    if "offline_access" in default_scopes or "offline_access" in optional_scopes:
        raise NativeClientError(f"{CLIENT_ID} must not offer offline_access")
    if list(DEFAULT_CLIENT_SCOPES) != default_scopes:
        raise NativeClientError(f"{CLIENT_ID} default client scopes drifted")
    if list(OPTIONAL_CLIENT_SCOPES) != optional_scopes:
        raise NativeClientError(f"{CLIENT_ID} optional client scopes drifted")
    expected = declared_protocol_mappers(realm)
    if client.get("protocolMappers") != expected:
        raise NativeClientError(
            f"{CLIENT_ID} protocol mappers must be the portal groups mapper "
            "plus idp_enterprise.token_claim_mappers()"
        )


def upsert_payload(declared: dict[str, Any], existing: dict[str, Any] | None) -> dict[str, Any]:
    """Representation for create or update. Preserves the Keycloak id.

    Attributes are the declared set, not a merge. Keys that exist only on the
    live client are set to null so a hand edit cannot keep a longer session.
    Offline session attributes and ``access.token.lifespan`` are cleared on
    every run. No secret is copied forward.
    """
    payload = json.loads(json.dumps(declared))
    payload.pop("secret", None)
    payload.pop("id", None)
    attrs = dict(payload.get("attributes") or {})
    if existing:
        if not existing.get("id"):
            raise NativeClientError(f"{CLIENT_ID} update is missing the Keycloak id")
        payload["id"] = existing["id"]
        for key in existing.get("attributes") or {}:
            if key not in attrs:
                attrs[key] = None
    for key in CLEARED_ATTRIBUTES:
        attrs[key] = None
    payload["attributes"] = attrs
    payload["publicClient"] = True
    payload["standardFlowEnabled"] = True
    payload["implicitFlowEnabled"] = False
    payload["directAccessGrantsEnabled"] = False
    payload["serviceAccountsEnabled"] = False
    payload["redirectUris"] = [REDIRECT_URI]
    payload["webOrigins"] = []
    payload["defaultClientScopes"] = list(DEFAULT_CLIENT_SCOPES)
    payload["optionalClientScopes"] = list(OPTIONAL_CLIENT_SCOPES)
    return payload


def undeclared_scope_ids(
    assigned: list[dict[str, Any]],
    desired_names: tuple[str, ...] | list[str],
) -> list[str]:
    desired = set(desired_names)
    return [
        str(item["id"])
        for item in assigned
        if isinstance(item, dict) and item.get("id") and item.get("name") not in desired
    ]


def missing_scope_ids(
    assigned: list[dict[str, Any]],
    desired_names: tuple[str, ...] | list[str],
    catalog_by_name: dict[str, str],
) -> list[str]:
    present = {
        str(item.get("name"))
        for item in assigned
        if isinstance(item, dict) and item.get("name")
    }
    missing: list[str] = []
    for name in desired_names:
        if name == "offline_access" or name in present:
            continue
        scope_id = catalog_by_name.get(name)
        if scope_id:
            missing.append(scope_id)
    return missing


def _as_dicts(body: Any) -> list[dict[str, Any]]:
    if not isinstance(body, list):
        return []
    return [item for item in body if isinstance(item, dict)]


def _find_client(admin: Any) -> dict[str, Any] | None:
    found = _as_dicts(admin.get(f"/clients?clientId={CLIENT_ID}"))
    matches = [item for item in found if item.get("clientId") == CLIENT_ID]
    if len(matches) > 1:
        raise NativeClientError(f"{CLIENT_ID} is duplicated in the realm")
    return matches[0] if matches else None


def _sync_scope_bucket(
    admin: Any,
    client_uuid: str,
    *,
    bucket: str,
    desired: tuple[str, ...] | list[str],
    catalog_by_name: dict[str, str],
) -> None:
    assigned = _as_dicts(admin.get(f"/clients/{client_uuid}/{bucket}"))
    for scope_id in undeclared_scope_ids(assigned, desired):
        admin.delete(f"/clients/{client_uuid}/{bucket}/{scope_id}")
    for scope_id in missing_scope_ids(assigned, desired, catalog_by_name):
        admin.put(f"/clients/{client_uuid}/{bucket}/{scope_id}", None)


def ensure_hypermesh_native(admin: Any, realm: dict[str, Any] | None = None) -> None:
    """Create or update the one native client. Does not touch other clients."""
    source = load_realm() if realm is None else realm
    declared = declared_client(source)
    validate_declared_client(declared, source)
    existing = _find_client(admin)
    payload = upsert_payload(declared, existing)
    if existing is None:
        admin.post("/clients", payload)
        created = _find_client(admin)
        if created is None or not created.get("id"):
            raise NativeClientError(f"{CLIENT_ID} was not created")
        client_uuid = str(created["id"])
        print(f"  {CLIENT_ID} client created")
    else:
        client_uuid = str(existing["id"])
        admin.put(f"/clients/{client_uuid}", payload)
        print(f"  {CLIENT_ID} client updated")

    catalog = {
        str(item["name"]): str(item["id"])
        for item in _as_dicts(admin.get("/client-scopes"))
        if item.get("name") and item.get("id") and item.get("name") != "offline_access"
    }
    _sync_scope_bucket(
        admin,
        client_uuid,
        bucket="default-client-scopes",
        desired=list(declared.get("defaultClientScopes") or []),
        catalog_by_name=catalog,
    )
    _sync_scope_bucket(
        admin,
        client_uuid,
        bucket="optional-client-scopes",
        desired=list(declared.get("optionalClientScopes") or []),
        catalog_by_name=catalog,
    )
    _sync_protocol_mappers(
        admin,
        client_uuid,
        declared_protocol_mappers(source),
    )


def _mapper_identity(spec: dict[str, Any]) -> tuple[Any, ...]:
    return (
        spec.get("protocol"),
        spec.get("protocolMapper"),
        spec.get("consentRequired"),
        json.dumps(spec.get("config") or {}, sort_keys=True),
    )


def _sync_protocol_mappers(
    admin: Any,
    client_uuid: str,
    declared_mappers: list[dict[str, Any]],
) -> None:
    """Declared mappers only. A name that is not declared is deleted."""
    current = _as_dicts(admin.get(f"/clients/{client_uuid}/protocol-mappers/models"))
    declared_by_name = {
        str(item["name"]): item
        for item in declared_mappers
        if item.get("name")
    }
    kept: dict[str, dict[str, Any]] = {}
    for item in current:
        name = str(item.get("name") or "")
        mapper_id = item.get("id")
        if not mapper_id or name not in declared_by_name or name in kept:
            if mapper_id:
                admin.delete(
                    f"/clients/{client_uuid}/protocol-mappers/models/{mapper_id}"
                )
            continue
        kept[name] = item
    for name, spec in declared_by_name.items():
        existing = kept.get(name)
        if existing is None:
            admin.post(f"/clients/{client_uuid}/protocol-mappers/models", spec)
            continue
        if _mapper_identity(existing) == _mapper_identity(spec):
            continue
        updated = dict(spec)
        updated["id"] = existing["id"]
        admin.put(
            f"/clients/{client_uuid}/protocol-mappers/models/{existing['id']}",
            updated,
        )
