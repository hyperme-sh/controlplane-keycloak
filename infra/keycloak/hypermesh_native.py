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
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

CLIENT_ID = "hypermesh-native"
REDIRECT_URI = "http://127.0.0.1/callback"
REALM_PATH = Path(__file__).resolve().parent / "import" / "controlplane-realm.json"

# Realm built-ins minus offline_access. Access tokens stay on the realm
# lifespan (accessTokenLifespan, 300s). Do not set access.token.lifespan.
DEFAULT_CLIENT_SCOPES = (
    "web-origins",
    "acr",
    "profile",
    "roles",
    "email",
    "basic",
)
OPTIONAL_CLIENT_SCOPES = (
    "address",
    "phone",
    "microprofile-jwt",
)


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


def validate_declared_client(client: dict[str, Any]) -> None:
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
    if attrs.get("pkce.code.challenge.method") != "S256":
        raise NativeClientError(f"{CLIENT_ID} must require PKCE S256")
    if attrs.get("oauth2.device.authorization.grant.enabled") != "true":
        raise NativeClientError(f"{CLIENT_ID} must enable the device authorization grant")
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


def upsert_payload(declared: dict[str, Any], existing: dict[str, Any] | None) -> dict[str, Any]:
    """Representation for create or update. Preserves the Keycloak id.

    An empty ``access.token.lifespan`` clears a client override so the realm
    default applies. No secret is copied forward.
    """
    payload = json.loads(json.dumps(declared))
    payload.pop("secret", None)
    payload.pop("id", None)
    attrs = dict(payload.get("attributes") or {})
    had_lifespan_override = False
    if existing:
        if not existing.get("id"):
            raise NativeClientError(f"{CLIENT_ID} update is missing the Keycloak id")
        payload["id"] = existing["id"]
        merged = dict(existing.get("attributes") or {})
        had_lifespan_override = bool(str(merged.get("access.token.lifespan") or "").strip())
        merged.update(attrs)
        attrs = merged
    # Empty string clears a client override. A new client omits the attribute
    # and inherits the realm access-token lifespan.
    if had_lifespan_override:
        attrs["access.token.lifespan"] = ""
    else:
        attrs.pop("access.token.lifespan", None)
    payload["attributes"] = attrs
    payload["publicClient"] = True
    payload["redirectUris"] = [REDIRECT_URI]
    payload["webOrigins"] = []
    return payload


def scope_ids_named(assigned: list[dict[str, Any]], name: str) -> list[str]:
    return [
        str(item["id"])
        for item in assigned
        if isinstance(item, dict) and item.get("name") == name and item.get("id")
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
    for scope_id in scope_ids_named(assigned, "offline_access"):
        admin.delete(f"/clients/{client_uuid}/{bucket}/{scope_id}")
    for scope_id in missing_scope_ids(assigned, desired, catalog_by_name):
        admin.put(f"/clients/{client_uuid}/{bucket}/{scope_id}", None)


def ensure_hypermesh_native(admin: Any, realm: dict[str, Any] | None = None) -> None:
    """Create or update the one native client. Does not touch other clients."""
    declared = declared_client(realm)
    validate_declared_client(declared)
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
