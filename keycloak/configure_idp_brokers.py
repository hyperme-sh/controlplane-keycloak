#!/usr/bin/env python3
"""Push Microsoft, GitHub, and Google broker apps into an existing realm.

``--import-realm`` runs on first start only. A live controlplane realm keeps
the placeholder client id until this updates it. Credentials come from env
vars that refresh injects from Key Vault. Empty values skip that provider.
This script never invents a client id or secret and never prints one.
Which enterprise an organization belongs to is saved by that organization's
owner in spanopticon. This script does not apply an operator map.

The same process upserts ``hypermesh-native``, ``hypermesh-host-setup`` and
``s3rch-web`` from the realm file, each in its own step, before the broker
update. A failure of one client step is reported on its own and still lets
the other steps run. Re-run updates each client in place and does not create
a second one. ``s3rch-web`` does not add an identity provider.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from admin_endpoint import admin_endpoint

sys.path.insert(0, str(Path(__file__).resolve().parent))

from hypermesh_host_setup import HostSetupClientError, ensure_hypermesh_host_setup
from hypermesh_native import NativeClientError, ensure_hypermesh_native
from s3rch_web import S3rchClientError, ensure_s3rch_web
from idp_enterprise import (
    claim_copy_mappers,
    microsoft_endpoints,
    token_claim_mappers,
)
from test_registration import apply_test_registration

REALM = "controlplane"
FRONTEND_CLIENT_ID = "controlplane-frontend"

BROKERS = (
    ("microsoft", "KC_IDP_MICROSOFT_CLIENT_ID", "KC_IDP_MICROSOFT_CLIENT_SECRET", "KC_IDP_MICROSOFT_TENANT_ID"),
    ("github", "KC_IDP_GITHUB_CLIENT_ID", "KC_IDP_GITHUB_CLIENT_SECRET", ""),
    ("google", "KC_IDP_GOOGLE_CLIENT_ID", "KC_IDP_GOOGLE_CLIENT_SECRET", ""),
)


class ConfigureError(RuntimeError):
    """Fail closed. The message must not include a secret."""


def _env(name: str) -> str:
    return os.environ.get(name, "").strip()


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
        raise ConfigureError(f"{method} {url} failed: HTTP {exc.code}") from None


def admin_token(base_url: str, username: str, password: str) -> str:
    body = _json_request(
        "POST",
        f"{base_url.rstrip('/')}/realms/master/protocol/openid-connect/token",
        form={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": username,
            "password": password,
        },
    )
    if not isinstance(body, dict) or not body.get("access_token"):
        raise ConfigureError("master admin-cli token response missing access_token")
    return str(body["access_token"])


class AdminClient:
    def __init__(self, base_url: str, token: str) -> None:
        self.base = base_url.rstrip("/")
        self.token = token

    def _url(self, path: str) -> str:
        return f"{self.base}/admin/realms/{REALM}{path}"

    def get(self, path: str) -> Any:
        return _json_request("GET", self._url(path), token=self.token)

    def post(self, path: str, payload: Any) -> Any:
        return _json_request("POST", self._url(path), token=self.token, payload=payload)

    def put(self, path: str, payload: Any) -> Any:
        return _json_request("PUT", self._url(path), token=self.token, payload=payload)

    def delete(self, path: str) -> Any:
        return _json_request("DELETE", self._url(path), token=self.token)


def _provider(admin: AdminClient, alias: str) -> dict[str, Any] | None:
    try:
        found = admin.get(f"/identity-provider/instances/{alias}")
    except ConfigureError:
        return None
    return found if isinstance(found, dict) else None


def update_broker_app(
    admin: AdminClient,
    alias: str,
    client_id: str,
    client_secret: str,
    tenant: str,
) -> None:
    if not client_id or not client_secret:
        print(f"  skip {alias}: client id or secret is empty")
        return
    current = _provider(admin, alias)
    if current is None:
        raise ConfigureError(f"identity provider {alias} is missing")
    config = dict(current.get("config") or {})
    config["clientId"] = client_id
    config["clientSecret"] = client_secret
    if alias == "microsoft":
        config.update(microsoft_endpoints(tenant, _env("KC_IDP_MICROSOFT_ALLOWED_TENANT_IDS")))
    current["config"] = config
    admin.put(f"/identity-provider/instances/{alias}", current)
    print(f"  updated {alias} client id")


def _mappers(admin: AdminClient, alias: str) -> list[dict[str, Any]]:
    found = admin.get(f"/identity-provider/instances/{alias}/mappers") or []
    return [item for item in found if isinstance(item, dict)]


def upsert_mapper(admin: AdminClient, spec: dict[str, Any]) -> None:
    alias = str(spec["identityProviderAlias"])
    name = str(spec["name"])
    existing = next((item for item in _mappers(admin, alias) if item.get("name") == name), None)
    if existing is None:
        admin.post(f"/identity-provider/instances/{alias}/mappers", spec)
        return
    spec = dict(spec)
    spec["id"] = existing.get("id")
    admin.put(
        f"/identity-provider/instances/{alias}/mappers/{existing['id']}",
        spec,
    )


def ensure_portal_logout(admin: AdminClient) -> str:
    clients = admin.get(f"/clients?clientId={FRONTEND_CLIENT_ID}") or []
    client = next(
        (
            item
            for item in clients
            if isinstance(item, dict) and item.get("clientId") == FRONTEND_CLIENT_ID
        ),
        None,
    )
    if not isinstance(client, dict) or not client.get("id"):
        raise ConfigureError(f"client {FRONTEND_CLIENT_ID} is missing")
    client_id = str(client["id"])
    # Reconcile logout for existing realms as well as fresh imports.
    details = admin.get(f"/clients/{client_id}")
    attributes = dict(details.get("attributes") or {})
    logout_uris = "##".join((
        "https://portal.test.hyperme.sh/signed-out",
        "https://portal.hyperme.sh/signed-out",
        "http://localhost:3000/signed-out",
        "http://127.0.0.1:3000/signed-out",
    ))
    if attributes.get("post.logout.redirect.uris") != logout_uris:
        attributes["post.logout.redirect.uris"] = logout_uris
        admin.put(f"/clients/{client_id}", {**details, "attributes": attributes})
    verified = admin.get(f"/clients/{client_id}")
    if (verified.get("attributes") or {}).get("post.logout.redirect.uris") != logout_uris:
        raise ConfigureError("portal logout allowlist did not converge")
    return client_id


def ensure_token_claims(admin: AdminClient) -> None:
    client_id = ensure_portal_logout(admin)
    current = admin.get(f"/clients/{client_id}/protocol-mappers/models") or []
    by_name = {
        str(item.get("name")): item
        for item in current
        if isinstance(item, dict)
    }
    for spec in token_claim_mappers():
        existing = by_name.get(str(spec["name"]))
        if existing is None:
            admin.post(f"/clients/{client_id}/protocol-mappers/models", spec)
            continue
        spec = dict(spec)
        spec["id"] = existing.get("id")
        admin.put(
            f"/clients/{client_id}/protocol-mappers/models/{existing['id']}",
            spec,
        )


def open_test_registration(admin: AdminClient) -> None:
    if _env("KC_TEST_REGISTRATION") != "1":
        return
    realm = admin.get("")
    if not isinstance(realm, dict):
        raise ConfigureError("controlplane realm is missing")
    admin.put("", apply_test_registration(realm))
    print("  test-plane registration open")


def configure(admin: AdminClient) -> None:
    any_app = False
    for alias, client_env, secret_env, tenant_env in BROKERS:
        client_id = _env(client_env)
        client_secret = _env(secret_env)
        tenant = _env(tenant_env) if tenant_env else ""
        if client_id or client_secret:
            any_app = True
        update_broker_app(admin, alias, client_id, client_secret, tenant)
    for spec in claim_copy_mappers():
        upsert_mapper(admin, spec)
    if not any_app:
        print("  IdP client credentials empty; brokers left unchanged")
    ensure_token_claims(admin)
    open_test_registration(admin)


def apply_realm_updates(admin: AdminClient) -> int:
    """Native, host setup and s3r.ch clients, then brokers. Each failure is its own error.

    The test refresh treats a non-zero exit from this process as one
    non-fatal warning. Each client line is printed on its own so that
    warning is not the only record of a failure. A network error on one
    client step is the same line, and the later steps still run.
    """
    failed = False
    try:
        ensure_hypermesh_native(admin)
    except (NativeClientError, ConfigureError, urllib.error.URLError) as exc:
        failed = True
        print(
            f"ERROR: hypermesh-native client was not applied: {exc}",
            file=sys.stderr,
        )
    try:
        ensure_hypermesh_host_setup(admin)
    except (HostSetupClientError, ConfigureError, urllib.error.URLError) as exc:
        failed = True
        print(f"ERROR: hypermesh-host-setup client was not applied: {exc}", file=sys.stderr)
    try:
        ensure_s3rch_web(admin)
    except (S3rchClientError, ConfigureError, urllib.error.URLError) as exc:
        failed = True
        print(
            f"ERROR: s3rch-web client was not applied: {exc}",
            file=sys.stderr,
        )
    try:
        configure(admin)
    except ConfigureError as exc:
        failed = True
        print(f"ERROR: IdP broker configure failed: {exc}", file=sys.stderr)
    # Native payout issuer setup is an explicit sandbox operation, never a
    # consequence of importing a realm file or enabling an unrelated broker.
    flag = _env("PAYMENT_CONNECT_NATIVE_ISSUER_ENABLED")
    if flag not in ("", "false", "true"):
        failed = True
        print("ERROR: invalid native issuer enablement", file=sys.stderr)
    elif flag == "true":
        try:
            if _env("KC_TEST_REGISTRATION") != "1":
                raise ValueError("Test issuer profile required")
            from connect_issuer import configure as configure_connect_issuer
            configure_connect_issuer(admin, _env("AUTH_CONNECT_INTROSPECTION_CLIENT_SECRET"))
        except (ValueError, ConfigureError, urllib.error.URLError):
            failed = True
            print("ERROR: native payout issuer was not applied; reconcile issuer configuration", file=sys.stderr)
    return 1 if failed else 0


def main() -> int:
    base = admin_endpoint()
    username = _env("KC_BOOTSTRAP_ADMIN_USERNAME")
    password = _env("KC_BOOTSTRAP_ADMIN_PASSWORD")
    if not username or not password:
        raise ConfigureError("missing KC_BOOTSTRAP_ADMIN_USERNAME or password")
    token = admin_token(base, username, password)
    return apply_realm_updates(AdminClient(base, token))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ConfigureError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
