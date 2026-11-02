"""Device-only identity client for host setup, reconciled on every realm refresh."""
from __future__ import annotations

import copy
from typing import Any

from hypermesh_native import (
    CLEARED_ATTRIBUTES, DECLARED_ATTRIBUTES, load_realm,
    _as_dicts, _sync_protocol_mappers, _sync_scope_bucket,
)

CLIENT_ID = "hypermesh-host-setup"


class HostSetupClientError(RuntimeError):
    """Host setup client declaration or reconciliation failed."""


def client_spec() -> dict[str, Any]:
    return {
        "clientId": CLIENT_ID,
        "name": "Hypermesh host setup",
        "description": "Sign in to connect a host. Approve the host separately in your dashboard.",
        "enabled": True,
        "publicClient": True,
        "protocol": "openid-connect",
        "standardFlowEnabled": False,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "fullScopeAllowed": False,
        "consentRequired": True,
        "redirectUris": [],
        "webOrigins": [],
        "defaultClientScopes": ["basic", "email"],
        "optionalClientScopes": [],
        "attributes": dict(DECLARED_ATTRIBUTES),
        "protocolMappers": [{
            "name": "host-setup-audience",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "consentRequired": False,
            "config": {
                "included.client.audience": CLIENT_ID,
                "access.token.claim": "true",
                "id.token.claim": "false",
            },
        }],
    }


def ensure_hypermesh_host_setup(admin: Any, realm: dict[str, Any] | None = None) -> None:
    source = load_realm() if realm is None else realm
    expected = client_spec()
    declared = [c for c in source.get("clients", []) if c.get("clientId") == CLIENT_ID]
    if declared != [expected]:
        raise HostSetupClientError(f"{CLIENT_ID} declaration differs from the device-only contract")
    catalog = {str(c["name"]): str(c["id"]) for c in _as_dicts(admin.get("/client-scopes"))
               if c.get("name") and c.get("id")}
    if not set(expected["defaultClientScopes"]).issubset(catalog):
        raise HostSetupClientError(f"{CLIENT_ID} requires basic and email client scopes")
    matches = [c for c in _as_dicts(admin.get(f"/clients?clientId={CLIENT_ID}"))
               if c.get("clientId") == CLIENT_ID]
    if len(matches) > 1:
        raise HostSetupClientError(f"{CLIENT_ID} is duplicated")
    payload = copy.deepcopy(expected)
    existing = matches[0] if matches else None
    for key in (*CLEARED_ATTRIBUTES, *(existing or {}).get("attributes", {})):
        if key not in payload["attributes"]:
            payload["attributes"][key] = None
    if existing:
        if not existing.get("id"):
            raise HostSetupClientError(f"{CLIENT_ID} has no internal id")
        client_uuid = str(existing["id"])
        payload["id"] = client_uuid
        admin.put(f"/clients/{client_uuid}", payload)
    else:
        admin.post("/clients", payload)
        created = [c for c in _as_dicts(admin.get(f"/clients?clientId={CLIENT_ID}"))
                   if c.get("clientId") == CLIENT_ID]
        if len(created) != 1 or not created[0].get("id"):
            raise HostSetupClientError(f"{CLIENT_ID} creation could not be verified")
        client_uuid = str(created[0]["id"])
    for bucket, desired in (("default-client-scopes", expected["defaultClientScopes"]),
                            ("optional-client-scopes", [])):
        _sync_scope_bucket(admin, client_uuid, bucket=bucket, desired=desired, catalog_by_name=catalog)
    _sync_protocol_mappers(admin, client_uuid, expected["protocolMappers"])
    print(f"  {CLIENT_ID} client applied")
