"""Explicit test-only native payout issuer provisioning; never creates a user or role."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from urllib.parse import quote

from account_types import AMR_MAPPER, AccountTypeError, ensure_mapper

FLOW = "spanopticon-connect-browser-v1"
CLIENT = "auth-connect-introspection"
FRONTEND = "controlplane-frontend"
LOA = "conditional-level-of-authentication"
AMR_MAX_AGE_SECONDS = 300


class ConnectIssuerError(ValueError):
    """Fixed diagnostics only; no provider bodies, credentials or token claims."""


def one(rows, predicate, reason):
    found = [row for row in rows if predicate(row)]
    if len(found) != 1:
        raise ConnectIssuerError(reason)
    return found[0]


def executions(admin, alias):
    return admin.get(f"/authentication/flows/{quote(alias, safe='')}/executions")


def client(admin, name):
    rows = admin.get("/clients?clientId=" + quote(name, safe=""))
    if len(rows) > 1:
        raise ConnectIssuerError("Ambiguous issuer client")
    return rows[0] if rows else None


def ensure_introspection(admin, secret):
    if (
        not isinstance(secret, str)
        or not 32 <= len(secret) <= 512
        or not secret.isascii()
        or any(not 33 <= ord(c) <= 126 for c in secret)
    ):
        raise ConnectIssuerError("Private introspection credential required")
    realm = json.loads(
        (Path(__file__).parent / "import/controlplane-realm.json").read_text()
    )
    wanted = copy.deepcopy(
        one(
            realm["clients"],
            lambda c: c["clientId"] == CLIENT,
            "Missing introspection declaration",
        )
    )
    current = client(admin, CLIENT)
    if current is None:
        admin.post("/clients", {**wanted, "secret": secret})
        current = client(admin, CLIENT)
    if current is None:
        raise ConnectIssuerError("Introspection creation unverified")
    path = "/clients/" + current["id"]
    # Never rotate an existing credential or silently repair a permissive client.
    if any(current.get(k) != value for k, value in wanted.items() if k != "name"):
        raise ConnectIssuerError("Introspection client policy differs")
    if admin.get(path + "/client-secret").get("value") != secret:
        raise ConnectIssuerError(
            "Introspection credential differs; rotation requires reconciliation"
        )
    if admin.get(path + "/scope-mappings") or admin.get(
        path + "/protocol-mappers/models"
    ):
        raise ConnectIssuerError(
            "Introspection client has unexpected grants or mappers"
        )
    if (
        current.get("redirectUris")
        or current.get("webOrigins")
        or current.get("authorizationServicesEnabled")
    ):
        raise ConnectIssuerError("Introspection client has unexpected access")


def configure_execution(admin, execution, values, alias, source_configs):
    config_id = execution.get("authenticationConfig")
    current = admin.get("/authentication/config/" + config_id) if config_id else {}
    config = {**current.get("config", {}), **values}
    if current.get("config") == config and config_id not in source_configs:
        return
    # Copy configurations too: no PUT against a config shared by the realm flow.
    if config_id and config_id not in source_configs:
        admin.put("/authentication/config/" + config_id, {**current, "config": config})
        return
    admin.post(
        "/authentication/executions/" + execution["id"] + "/config",
        {"alias": alias, "config": config},
    )


def otp_scope(rows):
    otp = one(
        rows,
        lambda e: e.get("providerId") == "auth-otp-form",
        "Exactly one OTP execution required",
    )
    if otp.get("requirement") not in {"ALTERNATIVE", "REQUIRED"}:
        raise ConnectIssuerError("OTP execution is disabled or unsupported")
    index = rows.index(otp)
    parent = next(
        (
            e
            for e in reversed(rows[:index])
            if e.get("level") == otp["level"] - 1 and e.get("authenticationFlow")
        ),
        None,
    )
    if parent is None or parent.get("requirement") != "CONDITIONAL":
        raise ConnectIssuerError("Unsupported OTP parent flow")
    start = rows.index(parent) + 1
    end = next(
        (i for i in range(start, len(rows)) if rows[i]["level"] <= parent["level"]),
        len(rows),
    )
    children = rows[start:end]
    allowed = {
        "conditional-user-configured",
        "conditional-credential",
        "auth-otp-form",
        LOA,
    }
    if any(
        e.get("authenticationFlow") or e.get("providerId") not in allowed
        for e in children
        if e.get("requirement") != "DISABLED"
    ):
        raise ConnectIssuerError("Unsupported enabled second-factor execution")
    configured = one(
        children,
        lambda e: e.get("providerId") == "conditional-user-configured",
        "OTP configuration condition required",
    )
    if configured.get("requirement") != "REQUIRED":
        raise ConnectIssuerError("OTP configuration condition differs")
    return parent, otp, children


def configure(admin, secret):
    frontend = client(admin, FRONTEND)
    if (
        frontend is None
        or frontend.get("publicClient") is not True
        or frontend.get("standardFlowEnabled") is not True
        or frontend.get("directAccessGrantsEnabled")
        or frontend.get("serviceAccountsEnabled")
    ):
        raise ConnectIssuerError("Normal public browser PKCE client required")
    if (frontend.get("attributes") or {}).get("pkce.code.challenge.method") != "S256":
        raise ConnectIssuerError("Browser PKCE must remain S256")
    realm = admin.get("")
    source = realm.get("browserFlow")
    if not source or source == FLOW:
        raise ConnectIssuerError("Independent realm browser flow required")
    source_rows = executions(admin, source)
    otp_scope(source_rows)
    source_configs = {
        e["authenticationConfig"] for e in source_rows if e.get("authenticationConfig")
    }
    source_values = {
        key: copy.deepcopy(admin.get("/authentication/config/" + key))
        for key in source_configs
    }
    flows = admin.get("/authentication/flows")
    targets = [f for f in flows if f["alias"] == FLOW]
    if len(targets) > 1:
        raise ConnectIssuerError("Ambiguous native browser flow")
    target_id = targets[0]["id"] if targets else None
    override = (frontend.get("authenticationFlowBindingOverrides") or {}).get("browser")
    if override not in (None, "", target_id):
        raise ConnectIssuerError("Existing browser override requires reconciliation")
    ensure_introspection(admin, secret)
    if not targets:
        admin.post(
            f"/authentication/flows/{quote(source, safe='')}/copy", {"newName": FLOW}
        )
    target = one(
        admin.get("/authentication/flows"),
        lambda f: f["alias"] == FLOW,
        "Native flow creation unverified",
    )
    rows = executions(admin, FLOW)
    parent, otp, children = otp_scope(rows)
    # The copied password form and OTP are the only references mapped to pwd/otp.
    password = one(
        rows,
        lambda e: e.get("providerId") == "auth-username-password-form",
        "Password form required",
    )
    if password["requirement"] != "REQUIRED":
        raise ConnectIssuerError("Password execution must remain required")
    for execution, reference in ((password, "pwd"), (otp, "otp")):
        configure_execution(
            admin,
            execution,
            {
                "default.reference.value": reference,
                # Keycloak defaults to zero: the first factor otherwise expires
                # while the user enters OTP or the browser exchanges its code.
                "default.reference.maxAge": str(AMR_MAX_AGE_SECONDS),
            },
            "connect-amr-" + execution["id"],
            source_configs,
        )
    if otp["requirement"] != "REQUIRED":
        admin.put(
            f"/authentication/flows/{quote(FLOW, safe='')}/executions",
            {**otp, "requirement": "REQUIRED"},
        )
    loa = [e for e in children if e.get("providerId") == LOA]
    if not loa:
        alias = admin.get("/authentication/flows/" + parent["flowId"])["alias"]
        admin.post(
            f"/authentication/flows/{quote(alias, safe='')}/executions/execution",
            {"provider": LOA},
        )
        _, _, children = otp_scope(executions(admin, FLOW))
    loa = one(
        children,
        lambda e: e.get("providerId") == LOA,
        "Ambiguous authentication-level condition",
    )
    if loa["requirement"] != "REQUIRED":
        admin.put(
            f"/authentication/flows/{quote(FLOW, safe='')}/executions",
            {**loa, "requirement": "REQUIRED"},
        )
    configure_execution(
        admin,
        loa,
        {"loa-condition-level": "2", "loa-max-age": "0"},
        "connect-loa2-" + loa["id"],
        source_configs,
    )
    try:
        ensure_mapper(admin, frontend["id"], AMR_MAPPER)
    except AccountTypeError:
        raise ConnectIssuerError(
            "Browser authentication-method mapper differs"
        ) from None
    verified_rows = executions(admin, FLOW)
    _, verified_otp, verified_children = otp_scope(verified_rows)
    verified_loa = one(
        verified_children,
        lambda e: e.get("providerId") == LOA,
        "Authentication-level condition missing",
    )
    if (
        verified_otp["requirement"] != "REQUIRED"
        or verified_loa["requirement"] != "REQUIRED"
    ):
        raise ConnectIssuerError("Native second-factor requirements unverified")
    loa_config = admin.get(
        "/authentication/config/" + verified_loa["authenticationConfig"]
    )["config"]
    if any(
        loa_config.get(k) != v
        for k, v in {"loa-condition-level": "2", "loa-max-age": "0"}.items()
    ):
        raise ConnectIssuerError("Native authentication-level configuration unverified")
    for execution in verified_rows:
        config_id = execution.get("authenticationConfig")
        if config_id and execution.get("requirement") != "DISABLED":
            config = admin.get("/authentication/config/" + config_id).get("config", {})
            reference = config.get("default.reference.value", "")
            expected = {
                "auth-username-password-form": "pwd",
                "auth-otp-form": "otp",
            }.get(execution.get("providerId"))
            if expected and (
                reference != expected
                or config.get("default.reference.maxAge") != str(AMR_MAX_AGE_SECONDS)
            ):
                raise ConnectIssuerError("Authentication-method reference unverified")
            if not expected and set(str(reference).replace(",", " ").split()) & {
                "pwd",
                "otp",
            }:
                raise ConnectIssuerError("Unexpected authentication-method reference")
    if any(
        admin.get("/authentication/config/" + key) != value
        for key, value in source_values.items()
    ):
        raise ConnectIssuerError("Realm default authenticator configuration changed")
    if executions(admin, source) != source_rows:
        raise ConnectIssuerError("Realm default flow changed during provisioning")
    # Bind only after the complete new flow and private client are verified.
    current = client(admin, FRONTEND)
    admin.put(
        "/clients/" + frontend["id"],
        {
            **current,
            "authenticationFlowBindingOverrides": {
                **(current.get("authenticationFlowBindingOverrides") or {}),
                "browser": target["id"],
            },
        },
    )
    if (client(admin, FRONTEND).get("authenticationFlowBindingOverrides") or {}).get(
        "browser"
    ) != target["id"]:
        raise ConnectIssuerError("Native browser binding unverified")
