#!/usr/bin/env python3
"""Public client ``s3rch-web`` for the s3r.ch OAuth backup door.

The realm file is the declaration. ``--import-realm`` applies it on first
start only. A live realm is updated by ``ensure_s3rch_web``, which
``configure_idp_brokers.py`` runs. Re-run keeps the same internal id, does
not add a second client, and does not mint a secret.

This client is not a control-plane API caller. It stays out of
``KEYCLOAK_ALLOWED_CLIENT_IDS``. Brokers stay the existing ``microsoft``,
``github``, and ``google`` identity providers.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_KEYCLOAK_DIR = str(Path(__file__).resolve().parent)
if _KEYCLOAK_DIR not in sys.path:
    sys.path.insert(0, _KEYCLOAK_DIR)

from idp_enterprise import token_claim_mappers

CLIENT_ID = "s3rch-web"
REALM_PATH = Path(__file__).resolve().parent / "import" / "controlplane-realm.json"
CALLBACK_PATH = "/api/identity/oauth/callback"

# Exact callbacks: production, public merge-tracking test, and local Next.
REDIRECT_URIS = (
    "https://s3r.ch" + CALLBACK_PATH,
    "https://www.s3r.ch" + CALLBACK_PATH,
    "https://test.s3r.ch" + CALLBACK_PATH,
    "http://localhost:3000" + CALLBACK_PATH,
    "http://127.0.0.1:3000" + CALLBACK_PATH,
)

# openid is requested by s3r.ch. These defaults are what that request means.
# No roles scope: this client does not call the control plane.
DEFAULT_CLIENT_SCOPES = (
    "basic",
    "email",
    "profile",
    "acr",
)
OPTIONAL_CLIENT_SCOPES: tuple[str, ...] = ()

DECLARED_ATTRIBUTES = {
    "pkce.code.challenge.method": "S256",
}

CLEARED_ATTRIBUTES = (
    "client.offline.session.idle.timeout",
    "client.offline.session.max.lifespan",
    "access.token.lifespan",
    "oauth2.device.authorization.grant.enabled",
)


class S3rchClientError(RuntimeError):
    """The declared client cannot be applied. The message has no secret."""


def load_realm() -> dict[str, Any]:
    return json.loads(REALM_PATH.read_text(encoding="utf-8"))


def declared_client(realm: dict[str, Any] | None = None) -> dict[str, Any]:
    realm = load_realm() if realm is None else realm
    matches = [item for item in realm.get("clients") or [] if item.get("clientId") == CLIENT_ID]
    if len(matches) != 1:
        raise S3rchClientError(f"{CLIENT_ID} must appear once in the realm import")
    return matches[0]


def declared_protocol_mappers(realm: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """``idp_*`` claims only. No portal groups mapper."""
    del realm
    return token_claim_mappers()


def validate_declared_client(client: dict[str, Any], realm: dict[str, Any] | None = None) -> None:
    """Fail closed if the realm file drifts from the s3r.ch backup contract."""
    if client.get("clientId") != CLIENT_ID:
        raise S3rchClientError(f"clientId must be {CLIENT_ID}")
    if client.get("publicClient") is not True:
        raise S3rchClientError(f"{CLIENT_ID} must be a public client")
    if client.get("secret"):
        raise S3rchClientError(f"{CLIENT_ID} must not have a client secret")
    if client.get("standardFlowEnabled") is not True:
        raise S3rchClientError(f"{CLIENT_ID} must enable the standard flow")
    if client.get("implicitFlowEnabled") is not False:
        raise S3rchClientError(f"{CLIENT_ID} must disable the implicit flow")
    if client.get("directAccessGrantsEnabled") is not False:
        raise S3rchClientError(f"{CLIENT_ID} must disable direct access grants")
    if client.get("serviceAccountsEnabled") is not False:
        raise S3rchClientError(f"{CLIENT_ID} must not enable a service account")
    if client.get("fullScopeAllowed") is not False:
        raise S3rchClientError(f"{CLIENT_ID} must not allow undeclared scopes")
    attrs = client.get("attributes") or {}
    if attrs != DECLARED_ATTRIBUTES:
        raise S3rchClientError(f"{CLIENT_ID} attributes must be the declared set")
    redirects = list(client.get("redirectUris") or [])
    if redirects != list(REDIRECT_URIS):
        raise S3rchClientError(f"{CLIENT_ID} redirects must be the declared callback list")
    for uri in redirects:
        if "*" in uri:
            raise S3rchClientError(f"{CLIENT_ID} must not use a wildcard redirect")
        parsed = urlparse(uri)
        if not parsed.path.endswith(CALLBACK_PATH):
            raise S3rchClientError(f"{CLIENT_ID} redirect must end at the OAuth callback")
        if parsed.scheme == "https" and parsed.hostname not in {"s3r.ch", "www.s3r.ch", "test.s3r.ch"}:
            raise S3rchClientError(f"{CLIENT_ID} https redirect must be an s3r.ch host")
        if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1"}:
            raise S3rchClientError(f"{CLIENT_ID} http redirect must be loopback")
        if parsed.scheme == "http" and parsed.port != 3000:
            raise S3rchClientError(f"{CLIENT_ID} loopback redirect must use port 3000")
    if client.get("webOrigins") not in ([], None):
        raise S3rchClientError(f"{CLIENT_ID} does not need web origins")
    default_scopes = list(client.get("defaultClientScopes") or [])
    optional_scopes = list(client.get("optionalClientScopes") or [])
    if "offline_access" in default_scopes or "offline_access" in optional_scopes:
        raise S3rchClientError(f"{CLIENT_ID} must not offer offline_access")
    if "roles" in default_scopes or "roles" in optional_scopes:
        raise S3rchClientError(f"{CLIENT_ID} must not request realm roles")
    if list(DEFAULT_CLIENT_SCOPES) != default_scopes:
        raise S3rchClientError(f"{CLIENT_ID} default client scopes drifted")
    if list(OPTIONAL_CLIENT_SCOPES) != optional_scopes:
        raise S3rchClientError(f"{CLIENT_ID} optional client scopes drifted")
    if client.get("protocolMappers") != declared_protocol_mappers(realm):
        raise S3rchClientError(
            f"{CLIENT_ID} protocol mappers must be idp_enterprise.token_claim_mappers()"
        )
    names = [item.get("name") for item in client.get("protocolMappers") or []]
    if "groups" in names:
        raise S3rchClientError(f"{CLIENT_ID} must not copy the portal groups mapper")


def upsert_payload(declared: dict[str, Any], existing: dict[str, Any] | None) -> dict[str, Any]:
    """Representation for create or update. Preserves the Keycloak id.

    Attributes are the declared set, not a merge. Keys that exist only on the
    live client are set to null so a hand edit cannot keep device grant,
    a longer session, or a secret. No secret is copied forward.
    """
    payload = json.loads(json.dumps(declared))
    payload.pop("secret", None)
    payload.pop("id", None)
    attrs = dict(payload.get("attributes") or {})
    if existing:
        if not existing.get("id"):
            raise S3rchClientError(f"{CLIENT_ID} update is missing the Keycloak id")
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
    payload["fullScopeAllowed"] = False
    payload["redirectUris"] = list(REDIRECT_URIS)
    payload["webOrigins"] = []
    payload["defaultClientScopes"] = list(DEFAULT_CLIENT_SCOPES)
    payload["optionalClientScopes"] = list(OPTIONAL_CLIENT_SCOPES)
    payload.pop("secret", None)
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
        raise S3rchClientError(f"{CLIENT_ID} is duplicated in the realm")
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


def ensure_s3rch_web(admin: Any, realm: dict[str, Any] | None = None) -> None:
    """Create or update the one s3r.ch client. Does not touch other clients or IdPs."""
    source = load_realm() if realm is None else realm
    declared = declared_client(source)
    validate_declared_client(declared, source)
    existing = _find_client(admin)
    payload = upsert_payload(declared, existing)
    if existing is None:
        admin.post("/clients", payload)
        created = _find_client(admin)
        if created is None or not created.get("id"):
            raise S3rchClientError(f"{CLIENT_ID} was not created")
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
