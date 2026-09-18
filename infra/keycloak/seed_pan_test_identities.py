#!/usr/bin/env python3
"""Idempotent pan-test identity seed for realm ``controlplane``.

Creates or updates three split users (never one user with all roles):

* renter@test.hyperme.sh — Keycloak group/role ``renter`` (can_checkout)
* leaser@test.hyperme.sh — Keycloak group/role ``host`` (not a leaser role)
* admin@test.hyperme.sh — Keycloak realm role ``admin`` (portal admin;
  not KC_BOOTSTRAP_ADMIN, not renter, not host)

Passwords are read from env vars that refresh injects from Key Vault
``kv-fyber-cg47`` (``panopticon-test-*``). Empty/missing fails closed.
This script never invents a password and never writes one to git.

Rerun is additive-safe: no duplicate users/groups/roles, and passwords
are not rotated unless ``--rotate-passwords`` is passed.

Uses the master-realm bootstrap admin (``KC_BOOTSTRAP_ADMIN_*``) against
``admin-cli``. Does not enable direct access grants on
``controlplane-frontend``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

REALM = "controlplane"
FRONTEND_CLIENT_ID = "controlplane-frontend"
PORTAL_ROLES = frozenset({"renter", "host", "admin"})
PORTAL_GROUPS = frozenset({"renter", "host"})
FORBIDDEN_NAMES = frozenset({"leaser"})

# Existing KV names that must not be reused for these three accounts.
BOOTSTRAP_KV_PASSWORD = "panopticon-test-keycloak-admin-password"
API_ADMIN_KV_PASSWORD = "panopticon-test-admin-password"


class SeedError(RuntimeError):
    """Fail-closed seed error. Message must never include a secret."""


@dataclass(frozen=True, slots=True)
class Identity:
    username: str
    email: str
    first_name: str
    last_name: str
    groups: tuple[str, ...]
    realm_roles: tuple[str, ...]
    password_env: str
    kv_secret: str


IDENTITIES: tuple[Identity, ...] = (
    Identity(
        username="renter@test.hyperme.sh",
        email="renter@test.hyperme.sh",
        first_name="Pan-test",
        last_name="Renter",
        groups=("renter",),
        realm_roles=("renter",),
        password_env="PANOPTICON_TEST_RENTER_PASSWORD",
        kv_secret="panopticon-test-renter-password",
    ),
    Identity(
        username="leaser@test.hyperme.sh",
        email="leaser@test.hyperme.sh",
        first_name="Pan-test",
        last_name="Leaser",
        groups=("host",),
        realm_roles=("host",),
        password_env="PANOPTICON_TEST_LEASER_PASSWORD",
        kv_secret="panopticon-test-leaser-password",
    ),
    Identity(
        username="admin@test.hyperme.sh",
        email="admin@test.hyperme.sh",
        first_name="Pan-test",
        last_name="Admin",
        groups=(),
        realm_roles=("admin",),
        password_env="PANOPTICON_TEST_PORTAL_ADMIN_PASSWORD",
        kv_secret="panopticon-test-portal-admin-password",
    ),
)


def catalog_invariants() -> None:
    """Static guards. No leaser role/group; no reused bootstrap KV names."""
    names = [ident.username for ident in IDENTITIES]
    if len(names) != len(set(names)):
        raise SeedError("duplicate identity username")
    if len(IDENTITIES) != 3:
        raise SeedError("Chris split requires exactly three identities")
    kv_names = [ident.kv_secret for ident in IDENTITIES]
    if len(kv_names) != len(set(kv_names)):
        raise SeedError("duplicate identity KV secret name")
    reserved = {BOOTSTRAP_KV_PASSWORD, API_ADMIN_KV_PASSWORD}
    overlap = reserved.intersection(kv_names)
    if overlap:
        raise SeedError("identity KV name collides with bootstrap/API admin secret")
    for ident in IDENTITIES:
        if "leaser" in ident.groups or "leaser" in ident.realm_roles:
            raise SeedError("leaser is a username, not a portal role or group")
        if ident.username == "admin" or ident.username == "KC_BOOTSTRAP_ADMIN":
            raise SeedError("portal admin must not reuse the Keycloak bootstrap username")


catalog_invariants()


def require_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not str(value).strip():
        raise SeedError(f"missing or empty {name}")
    return str(value)


def require_passwords() -> dict[str, str]:
    """Fail closed if any identity password env is empty. Do not generate."""
    out: dict[str, str] = {}
    for ident in IDENTITIES:
        out[ident.username] = require_env(ident.password_env)
    return out


def _json_request(
    method: str,
    url: str,
    *,
    token: str | None = None,
    payload: Any = None,
    form: dict[str, str] | None = None,
) -> Any:
    headers: dict[str, str] = {}
    data: bytes | None = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if form is not None:
        data = urllib.parse.urlencode(form).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as resp:
            raw = resp.read()
            if not raw:
                return None
            if resp.headers.get_content_type() == "application/json":
                return json.loads(raw.decode("utf-8"))
            return raw.decode("utf-8")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise SeedError(f"{method} {url} failed: HTTP {exc.code}") from None


def admin_token(base_url: str, username: str, password: str) -> str:
    token_url = f"{base_url.rstrip('/')}/realms/master/protocol/openid-connect/token"
    body = _json_request(
        "POST",
        token_url,
        form={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": username,
            "password": password,
        },
    )
    if not isinstance(body, dict) or not body.get("access_token"):
        raise SeedError("master admin-cli token response missing access_token")
    return str(body["access_token"])


class AdminClient:
    def __init__(self, base_url: str, token: str, realm: str = REALM) -> None:
        self.base = base_url.rstrip("/")
        self.token = token
        self.realm = realm

    def _url(self, path: str) -> str:
        return f"{self.base}/admin/realms/{self.realm}{path}"

    def get(self, path: str) -> Any:
        return _json_request("GET", self._url(path), token=self.token)

    def post(self, path: str, payload: Any) -> Any:
        return _json_request("POST", self._url(path), token=self.token, payload=payload)

    def put(self, path: str, payload: Any) -> Any:
        return _json_request("PUT", self._url(path), token=self.token, payload=payload)

    def delete(self, path: str, payload: Any | None = None) -> Any:
        return _json_request(
            "DELETE", self._url(path), token=self.token, payload=payload
        )


def ensure_realm_role(admin: AdminClient, name: str) -> dict[str, Any]:
    if name in FORBIDDEN_NAMES:
        raise SeedError(f"refusing to create forbidden role {name}")
    try:
        role = admin.get(f"/roles/{urllib.parse.quote(name)}")
        if isinstance(role, dict) and role.get("name") == name:
            return role
    except SeedError:
        pass
    admin.post("/roles", {"name": name, "clientRole": False, "composite": False})
    role = admin.get(f"/roles/{urllib.parse.quote(name)}")
    if not isinstance(role, dict):
        raise SeedError(f"role {name} missing after create")
    return role


def _group_name(group: dict[str, Any]) -> str:
    return str(group.get("name") or "").strip().lower()


def ensure_group(admin: AdminClient, name: str) -> dict[str, Any]:
    if name in FORBIDDEN_NAMES:
        raise SeedError(f"refusing to create forbidden group {name}")
    groups = admin.get("/groups?briefRepresentation=false") or []
    for group in groups:
        if isinstance(group, dict) and _group_name(group) == name:
            return group
    admin.post("/groups", {"name": name})
    groups = admin.get("/groups?briefRepresentation=false") or []
    for group in groups:
        if isinstance(group, dict) and _group_name(group) == name:
            return group
    raise SeedError(f"group {name} missing after create")


def ensure_group_realm_role(
    admin: AdminClient, group: dict[str, Any], role: dict[str, Any]
) -> None:
    gid = group["id"]
    mapped = admin.get(f"/groups/{gid}/role-mappings/realm") or []
    names = {str(item.get("name")) for item in mapped if isinstance(item, dict)}
    if role["name"] in names:
        return
    admin.post(f"/groups/{gid}/role-mappings/realm", [role])


def find_user(admin: AdminClient, ident: Identity) -> dict[str, Any] | None:
    for query in (
        f"/users?username={urllib.parse.quote(ident.username)}&exact=true",
        f"/users?email={urllib.parse.quote(ident.email)}&exact=true",
    ):
        found = admin.get(query) or []
        for user in found:
            if not isinstance(user, dict):
                continue
            if str(user.get("username")) == ident.username:
                return user
            if str(user.get("email") or "").lower() == ident.email.lower():
                return user
    return None


def upsert_user(admin: AdminClient, ident: Identity) -> tuple[dict[str, Any], bool]:
    existing = find_user(admin, ident)
    body = {
        "username": ident.username,
        "email": ident.email,
        "enabled": True,
        "emailVerified": True,
        "firstName": ident.first_name,
        "lastName": ident.last_name,
        "requiredActions": [],
    }
    created = False
    if existing is None:
        admin.post("/users", body)
        created = True
        existing = find_user(admin, ident)
        if existing is None:
            raise SeedError(f"user {ident.username} missing after create")
    else:
        uid = existing["id"]
        admin.put(f"/users/{uid}", {**body, "id": uid})
        existing = find_user(admin, ident) or existing
    return existing, created


def set_password(admin: AdminClient, user_id: str, password: str) -> None:
    admin.put(
        f"/users/{user_id}/reset-password",
        {"type": "password", "value": password, "temporary": False},
    )


def reconcile_realm_roles(
    admin: AdminClient, user_id: str, wanted: tuple[str, ...], roles: dict[str, dict]
) -> None:
    mapped = admin.get(f"/users/{user_id}/role-mappings/realm") or []
    have = {
        str(item.get("name")): item
        for item in mapped
        if isinstance(item, dict) and item.get("name")
    }
    to_add = [roles[name] for name in wanted if name not in have]
    to_remove = [
        have[name]
        for name in have
        if name in PORTAL_ROLES and name not in wanted
    ]
    if to_add:
        admin.post(f"/users/{user_id}/role-mappings/realm", to_add)
    if to_remove:
        admin.delete(f"/users/{user_id}/role-mappings/realm", to_remove)


def reconcile_groups(
    admin: AdminClient, user_id: str, wanted: tuple[str, ...], groups: dict[str, dict]
) -> None:
    mapped = admin.get(f"/users/{user_id}/groups") or []
    have = {
        _group_name(item): item
        for item in mapped
        if isinstance(item, dict) and _group_name(item)
    }
    for name in wanted:
        if name not in have:
            admin.put(f"/users/{user_id}/groups/{groups[name]['id']}", {})
    for name, group in have.items():
        if name in PORTAL_GROUPS and name not in wanted:
            admin.delete(f"/users/{user_id}/groups/{group['id']}")


def ensure_groups_mapper(admin: AdminClient) -> None:
    clients = admin.get(f"/clients?clientId={FRONTEND_CLIENT_ID}") or []
    if not clients:
        raise SeedError(f"client {FRONTEND_CLIENT_ID} not found")
    client = clients[0]
    if client.get("publicClient") is not True:
        raise SeedError(f"{FRONTEND_CLIENT_ID} must stay a public PKCE client")
    if client.get("directAccessGrantsEnabled"):
        raise SeedError(f"{FRONTEND_CLIENT_ID} must keep direct access grants off")
    cid = client["id"]
    mappers = admin.get(f"/clients/{cid}/protocol-mappers/models") or []
    for mapper in mappers:
        if not isinstance(mapper, dict):
            continue
        if mapper.get("protocolMapper") != "oidc-group-membership-mapper":
            continue
        claim = (mapper.get("config") or {}).get("claim.name")
        if claim == "groups":
            return
    admin.post(
        f"/clients/{cid}/protocol-mappers/models",
        {
            "name": "groups",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-group-membership-mapper",
            "consentRequired": False,
            "config": {
                "full.path": "true",
                "id.token.claim": "true",
                "access.token.claim": "true",
                "claim.name": "groups",
                "userinfo.token.claim": "true",
            },
        },
    )


def seed(
    *,
    base_url: str,
    bootstrap_username: str,
    bootstrap_password: str,
    passwords: dict[str, str],
    rotate_passwords: bool = False,
) -> dict[str, str]:
    """Upsert identities. Returns username → created|updated|password-set."""
    catalog_invariants()
    token = admin_token(base_url, bootstrap_username, bootstrap_password)
    admin = AdminClient(base_url, token)
    ensure_groups_mapper(admin)

    roles = {name: ensure_realm_role(admin, name) for name in ("renter", "host", "admin")}
    groups = {name: ensure_group(admin, name) for name in ("renter", "host")}
    ensure_group_realm_role(admin, groups["renter"], roles["renter"])
    ensure_group_realm_role(admin, groups["host"], roles["host"])

    actions: dict[str, str] = {}
    for ident in IDENTITIES:
        user, created = upsert_user(admin, ident)
        uid = str(user["id"])
        reconcile_realm_roles(admin, uid, ident.realm_roles, roles)
        reconcile_groups(admin, uid, ident.groups, groups)
        if created or rotate_passwords:
            set_password(admin, uid, passwords[ident.username])
            actions[ident.username] = "created" if created else "password-rotated"
        else:
            actions[ident.username] = "updated"
    return actions


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--rotate-passwords",
        action="store_true",
        help="Reset the three user passwords from env. Default is leave existing passwords.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        passwords = require_passwords()
        bootstrap_user = require_env("KC_BOOTSTRAP_ADMIN_USERNAME")
        bootstrap_password = require_env("KC_BOOTSTRAP_ADMIN_PASSWORD")
        base_url = os.environ.get("KEYCLOAK_URL", "http://127.0.0.1:8081").strip()
        if not base_url:
            raise SeedError("missing or empty KEYCLOAK_URL")
        actions = seed(
            base_url=base_url,
            bootstrap_username=bootstrap_user,
            bootstrap_password=bootstrap_password,
            passwords=passwords,
            rotate_passwords=args.rotate_passwords,
        )
    except SeedError as exc:
        print(f"seed failed: {exc}", file=sys.stderr)
        return 1
    for username, action in actions.items():
        print(f"{username}: {action}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
