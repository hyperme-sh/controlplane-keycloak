"""Provision disabled, separate account-closure credentials and explicit operators.

No deployment, activation, automatic operator assignment or credential rotation.
The reader and worker use distinct credentials and narrowly scoped native roles.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from urllib.parse import quote, urlsplit

ROLE = "account:close"
OPERATOR_AUDIENCE = "spanopticon-account-closure"
OPERATOR_SCOPE = "account-closure-operator"
READER = "account-closure-reader"
WORKER = "account-closure-worker"
PURPOSES = {READER: "view-users", WORKER: "manage-users"}
PROTECTED_ATTRIBUTE = "account_closure_protected"
PROTECTED_PROFILE = {
    "name": PROTECTED_ATTRIBUTE, "displayName": "Protected internal account",
    "multivalued": False, "permissions": {"view": ["admin"], "edit": ["admin"]},
    "validations": {"options": {"options": ["true"]}},
}


class ClosureSetupError(ValueError):
    """Fixed diagnostics; never include provider bodies, credentials or tokens."""


def identifier(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError
    except (ValueError, AttributeError):
        raise ClosureSetupError("An exact native user UUID is required") from None
    return value


def rows(value):
    if not isinstance(value, list) or len(value) >= 1000 or not all(isinstance(item, dict) for item in value):
        raise ClosureSetupError("Complete native identity inventory unavailable")
    return value


def client(admin, name):
    matches = [item for item in rows(admin.get("/clients?clientId=" + quote(name, safe="")))
               if item.get("clientId") == name]
    if len(matches) > 1 or (matches and not matches[0].get("id")):
        raise ClosureSetupError("Ambiguous native identity client")
    return matches[0] if matches else None


def client_spec(name):
    if name not in PURPOSES:
        raise ClosureSetupError("Unknown closure credential purpose")
    return {
        "clientId": name, "name": name, "protocol": "openid-connect",
        "enabled": False, "publicClient": False, "clientAuthenticatorType": "client-secret",
        "serviceAccountsEnabled": True, "standardFlowEnabled": False,
        "implicitFlowEnabled": False, "directAccessGrantsEnabled": False,
        "fullScopeAllowed": False, "authorizationServicesEnabled": False,
        "redirectUris": [], "webOrigins": [], "defaultClientScopes": ["basic"],
        "optionalClientScopes": [],
        "attributes": {"oauth2.device.authorization.grant.enabled": "false",
                       "oidc.ciba.grant.enabled": "false", "standard.token.exchange.enabled": "false",
                       "use.refresh.tokens": "false",
                       "client_credentials.use_refresh_token": "false"},
        "protocolMappers": [
            # Match account_types.py's service-account classification so its
            # realm reconciliation and this private-client policy coexist.
            {"name": "account_type", "protocol": "openid-connect",
             "protocolMapper": "oidc-hardcoded-claim-mapper", "consentRequired": False,
             "config": {"claim.name": "account_type", "claim.value": "service",
                        "jsonType.label": "String", "id.token.claim": "true",
                        "access.token.claim": "true", "userinfo.token.claim": "false",
                        "introspection.token.claim": "true"}},
            {"name": "closure-management-roles", "protocol": "openid-connect",
             "protocolMapper": "oidc-usermodel-client-role-mapper", "consentRequired": False,
             "config": {"usermodel.clientRoleMapping.clientId": "realm-management",
                        "claim.name": "resource_access.realm-management.roles",
                        "jsonType.label": "String", "multivalued": "true",
                        "access.token.claim": "true", "id.token.claim": "false",
                        "userinfo.token.claim": "false", "introspection.token.claim": "false"}},
            {"name": "closure-management-audience", "protocol": "openid-connect",
             "protocolMapper": "oidc-audience-mapper", "consentRequired": False,
             "config": {"included.client.audience": "realm-management",
                        "access.token.claim": "true", "id.token.claim": "false", "introspection.token.claim": "false", "userinfo.token.claim": "false"}},
        ],
    }


def validate_secrets(reader, worker, other_secrets=()):
    for secret in (reader, worker):
        if not isinstance(secret, str) or not 32 <= len(secret) <= 512 or not secret.isascii() or any(
            not 33 <= ord(character) <= 126 for character in secret
        ):
            raise ClosureSetupError("Distinct strong closure client credentials required")
    if reader == worker or any(secret and secret in {reader, worker} for secret in other_secrets):
        raise ClosureSetupError("Closure credentials must be distinct from each other and service tokens")


def ensure_protected_profile(admin):
    profile = admin.get("/users/profile")
    attributes = profile.get("attributes") if isinstance(profile, dict) else None
    if not isinstance(attributes, list):
        raise ClosureSetupError("Native profile policy unavailable")
    current = [item for item in attributes if isinstance(item, dict) and item.get("name") == PROTECTED_ATTRIBUTE]
    if not current:
        admin.put("/users/profile", {**profile, "attributes": [*attributes, copy.deepcopy(PROTECTED_PROFILE)]})
        profile = admin.get("/users/profile")
        current = [item for item in profile.get("attributes", []) if item.get("name") == PROTECTED_ATTRIBUTE]
    if len(current) != 1 or any(current[0].get(key) != value for key, value in PROTECTED_PROFILE.items()) or current[0].get("required"):
        raise ClosureSetupError("Protected account metadata requires explicit reconciliation")


def service_accounts(admin):
    # A service-account link is native client state, never a username/email guess.
    result = {}
    for native in rows(admin.get("/clients?first=0&max=1000")):
        if native.get("serviceAccountsEnabled") is not True:
            continue
        if not native.get("id") or not isinstance(native.get("clientId"), str):
            raise ClosureSetupError("Native service-account binding unavailable")
        user = admin.get("/clients/" + quote(native["id"], safe="") + "/service-account-user")
        subject = identifier(user.get("id") if isinstance(user, dict) else None)
        if subject in result:
            raise ClosureSetupError("Ambiguous native service-account binding")
        result[subject] = native["clientId"]
    return result


def operators(admin, human_ids, service_ids):
    if len(human_ids) + len(service_ids) > 1000 or set(human_ids) & set(service_ids):
        raise ClosureSetupError("Unambiguous explicit operator assignments required")
    if human_ids or service_ids:
        profile = admin.get("/users/profile")
        attributes = profile.get("attributes") if isinstance(profile, dict) else None
        classified = [item for item in attributes if isinstance(item, dict) and item.get("name") == "account_type"] if isinstance(attributes, list) else []
        if len(classified) != 1 or classified[0].get("permissions") != {"view": ["admin"], "edit": ["admin"]}:
            raise ClosureSetupError("Administrator-owned account classification required")
    linked_services = service_accounts(admin) if human_ids or service_ids else {}
    found = []
    for kind, values in (("human", human_ids), ("service", service_ids)):
        for subject in sorted(set(values)):
            identifier(subject)
            user = admin.get("/users/" + quote(subject, safe=""))
            if not isinstance(user, dict) or user.get("id") != subject or user.get("enabled") is not True:
                raise ClosureSetupError("Exact enabled native operator not found")
            if (user.get("attributes") or {}).get("account_type") != [kind]:
                raise ClosureSetupError("Administrator-verified operator account type required")
            service = linked_services.get(subject)
            if (kind == "service") != bool(service) or service in PURPOSES:
                raise ClosureSetupError("Closure credentials cannot become closure operators")
            found.append(subject)
    return found


def ensure_role(admin):
    matched = [item for item in rows(admin.get("/roles?search=" + quote(ROLE, safe="")))
               if item.get("name") == ROLE]
    if not matched:
        admin.post("/roles", {"name": ROLE, "composite": False, "clientRole": False,
                              "description": "Explicit global native account-closure operator"})
    role = admin.get("/roles/" + quote(ROLE, safe=""))
    if not isinstance(role, dict) or role.get("name") != ROLE or not role.get("id") or role.get("composite") or role.get("clientRole"):
        raise ClosureSetupError("Closure operator role must be a single native realm role")
    realm = admin.get("")
    default = realm.get("defaultRole") if isinstance(realm, dict) else None
    if not isinstance(default, dict) or not default.get("id"):
        raise ClosureSetupError("Native default-role inventory unavailable")
    pending, seen = [default["id"]], set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        if current == role["id"] or len(seen) > 1000:
            raise ClosureSetupError("Closure operator authority cannot be a default grant")
        for child in rows(admin.get("/roles-by-id/" + quote(current, safe="") + "/composites")):
            if child.get("id") == role["id"]:
                raise ClosureSetupError("Closure operator authority cannot be a default grant")
            if child.get("composite"):
                if not child.get("id"):
                    raise ClosureSetupError("Native default-role inventory unavailable")
                pending.append(child["id"])
    pending_groups = []
    for group in rows(admin.get("/default-groups")):
        if not group.get("id"):
            raise ClosureSetupError("Native default-group inventory unavailable")
        pending_groups.append(group["id"])
    seen_groups = set()
    while pending_groups:
        group_id = pending_groups.pop()
        if group_id in seen_groups:
            continue
        seen_groups.add(group_id)
        if len(seen_groups) > 1000:
            raise ClosureSetupError("Native default-group inventory exceeds limit")
        path = "/groups/" + quote(group_id, safe="")
        effective = rows(admin.get(path + "/role-mappings/realm/composite"))
        if any(item.get("id") == role["id"] for item in effective):
            raise ClosureSetupError("Closure operator authority cannot be a default group grant")
        group = admin.get(path)
        if not isinstance(group, dict) or group.get("id") != group_id:
            raise ClosureSetupError("Native default-group ancestry unavailable")
        parent = group.get("parentId")
        if parent:
            pending_groups.append(parent)
        elif not isinstance(group.get("path"), str) or group["path"].count("/") > 1:
            raise ClosureSetupError("Native default-group ancestry unavailable")
    return role


def mapper_matches(actual, wanted):
    # Keycloak omits deprecated consentRequired on mapper readback. These
    # clients cannot initiate interactive authorization or consent flows.
    if actual.get("consentRequired") is not None and actual.get("consentRequired") is not False:
        return False
    return all(actual.get(key) == value for key, value in wanted.items() if key != "consentRequired")


def ensure_credential(admin, name, secret, manager):
    wanted = client_spec(name)
    current = client(admin, name)
    created = current is None
    if created:
        admin.post("/clients", {**copy.deepcopy(wanted), "secret": secret})
        current = client(admin, name)
    if current is None:
        raise ClosureSetupError("Closure credential creation unverified")
    path = "/clients/" + quote(current["id"], safe="")
    details = admin.get(path)
    if not isinstance(details, dict):
        raise ClosureSetupError("Native closure client unavailable")
    for key, value in wanted.items():
        if key in {"name", "attributes", "defaultClientScopes", "optionalClientScopes", "protocolMappers"}:
            continue
        observed = details.get(key)
        # Keycloak omits this flag when authorization services are absent.
        if key == "authorizationServicesEnabled" and observed is None:
            observed = False
        if type(observed) is not type(value) or observed != value:
            raise ClosureSetupError("Existing closure client policy differs: " + key)
    if any((details.get("attributes") or {}).get(key) != value for key, value in wanted["attributes"].items()):
        raise ClosureSetupError("Closure client grant policy differs")
    current_secret = admin.get(path + "/client-secret")
    if not isinstance(current_secret, dict) or current_secret.get("value") != secret:
        raise ClosureSetupError("Existing closure credential differs; rotation requires reconciliation")
    if created:
        # Client creation inherits realm scopes even when their names are in
        # ClientRepresentation. Narrow only this newly created disabled client.
        catalog = rows(admin.get("/client-scopes"))
        basic = [item for item in catalog if item.get("name") == "basic"]
        if len(basic) != 1 or not basic[0].get("id"):
            raise ClosureSetupError("Native basic client scope unavailable")
        for bucket, expected_names in (("default-client-scopes", {"basic"}), ("optional-client-scopes", set())):
            linked = rows(admin.get(path + "/" + bucket))
            for item in linked:
                if item.get("name") not in expected_names:
                    if not item.get("id"):
                        raise ClosureSetupError("Native scope linkage unavailable")
                    admin.delete(path + "/" + bucket + "/" + quote(item["id"], safe=""))
            if bucket == "default-client-scopes" and not any(item.get("name") == "basic" for item in linked):
                admin.put(path + "/" + bucket + "/" + quote(basic[0]["id"], safe=""), {})
    for bucket, expected in (("default-client-scopes", {"basic"}), ("optional-client-scopes", set())):
        if {item.get("name") for item in rows(admin.get(path + "/" + bucket))} != expected:
            raise ClosureSetupError("Closure credential has unexpected shared scopes")
    if created:
        initial_mappers = rows(admin.get(path + "/protocol-mappers/models"))
        for wanted_mapper in wanted["protocolMappers"]:
            named = [item for item in initial_mappers if item.get("name") == wanted_mapper["name"]]
            if not named:
                admin.post(path + "/protocol-mappers/models", wanted_mapper)
            elif len(named) != 1 or not mapper_matches(named[0], wanted_mapper):
                raise ClosureSetupError("Native closure mapper creation differs")
    actual_mappers = rows(admin.get(path + "/protocol-mappers/models"))
    if len(actual_mappers) != len(wanted["protocolMappers"]) or any(
        not any(mapper_matches(actual, expected) for actual in actual_mappers)
        for expected in wanted["protocolMappers"]
    ):
        raise ClosureSetupError("Closure credential token mappers differ")
    user = admin.get(path + "/service-account-user")
    subject = identifier(user.get("id") if isinstance(user, dict) else None)
    attributes = user.get("attributes") or {}
    if not isinstance(attributes, dict):
        raise ClosureSetupError("Native protected account metadata unavailable")
    if attributes.get(PROTECTED_ATTRIBUTE) != ["true"]:
        admin.put("/users/" + subject, {**user, "attributes": {**attributes, PROTECTED_ATTRIBUTE: ["true"]}})
    protected = admin.get("/users/" + subject)
    if not isinstance(protected, dict) or protected.get("id") != subject or (protected.get("attributes") or {}).get(PROTECTED_ATTRIBUTE) != ["true"]:
        raise ClosureSetupError("Native protected account metadata unverified")
    role = admin.get("/clients/" + manager + "/roles/" + PURPOSES[name])
    if not isinstance(role, dict) or role.get("name") != PURPOSES[name] or not role.get("id") or role.get("clientRole") is not True or role.get("containerId") != manager:
        raise ClosureSetupError("Native management role unavailable")
    # Keycloak 26.5 view-users is a read-only composite containing exactly
    # query-users and query-groups; manage-users is not a composite.
    expected_children = {"query-users", "query-groups"} if name == READER else set()
    children = rows(admin.get("/roles-by-id/" + quote(role["id"], safe="") + "/composites"))
    if role.get("composite") is not bool(expected_children) or {item.get("name") for item in children} != expected_children or any(
        item.get("clientRole") is not True or item.get("containerId") != manager or item.get("composite") is not False
        for item in children
    ):
        raise ClosureSetupError("Native management role composition differs")
    role_path = "/users/" + subject + "/role-mappings/clients/" + manager
    assigned = rows(admin.get(role_path))
    if assigned and {item.get("id") for item in assigned} != {role["id"]}:
        raise ClosureSetupError("Closure credential has unexpected management grants")
    scope_path = path + "/scope-mappings/clients/" + manager
    scoped = rows(admin.get(scope_path))
    if scoped and {item.get("id") for item in scoped} != {role["id"]}:
        raise ClosureSetupError("Closure credential has unexpected role scopes")
    if not assigned:
        admin.post(role_path, [role])
    if not scoped:
        admin.post(scope_path, [role])
    if {item.get("id") for item in rows(admin.get(role_path))} != {role["id"]} or {
        item.get("id") for item in rows(admin.get(scope_path))
    } != {role["id"]}:
        raise ClosureSetupError("Closure credential grants unverified")
    # Direct realm-management mappings are insufficient: a realm composite can
    # smuggle management authority into both the scope and the service account.
    inventory = admin.get(path + "/scope-mappings")
    if not isinstance(inventory, dict) or rows(inventory.get("realmMappings", [])):
        raise ClosureSetupError("Closure credential has unexpected realm scopes")
    clients = inventory.get("clientMappings")
    if not isinstance(clients, dict) or set(clients) != {"realm-management"}:
        raise ClosureSetupError("Closure credential scope inventory differs")
    mapping = clients["realm-management"]
    if (not isinstance(mapping, dict) or mapping.get("id") != manager
            or mapping.get("client") != "realm-management"
            or {item.get("id") for item in rows(mapping.get("mappings"))} != {role["id"]}):
        raise ClosureSetupError("Closure credential scope inventory differs")
    # The composite endpoint includes authority inherited through realm roles
    # and groups. Reader authority must remain exactly view-users and its two
    # read-only children; worker authority must remain exactly manage-users.
    effective = rows(admin.get(role_path + "/composite"))
    expected_roles = [role, *children]
    keys = ("id", "name", "clientRole", "containerId", "composite")
    if len(effective) != len(expected_roles) or any(
        not any(all(actual.get(key) == expected.get(key) for key in keys)
                for actual in effective)
        for expected in expected_roles
    ):
        raise ClosureSetupError("Closure credential effective management grants differ")
    return subject


def ensure_operator_scope(admin, role, *, human_ids, service_ids):
    """Only role holders receive the dedicated audience on selected clients."""
    catalog = rows(admin.get("/client-scopes"))
    found = [item for item in catalog if item.get("name") == OPERATOR_SCOPE]
    if len(found) > 1:
        raise ClosureSetupError("Ambiguous native operator scope")
    if not found:
        admin.post("/client-scopes", {
            "name": OPERATOR_SCOPE, "protocol": "openid-connect",
            "attributes": {"include.in.token.scope": "false", "display.on.consent.screen": "false"},
        })
        found = [item for item in rows(admin.get("/client-scopes")) if item.get("name") == OPERATOR_SCOPE]
    if len(found) != 1 or not found[0].get("id") or found[0].get("protocol") != "openid-connect":
        raise ClosureSetupError("Native operator scope unavailable")
    scope_id = found[0]["id"]
    path = "/client-scopes/" + quote(scope_id, safe="")
    wanted = [
        {"name": "closure-operator-audience", "protocol": "openid-connect",
         "protocolMapper": "oidc-audience-mapper", "consentRequired": False,
         "config": {"included.custom.audience": OPERATOR_AUDIENCE, "access.token.claim": "true",
                    "id.token.claim": "false", "userinfo.token.claim": "false", "introspection.token.claim": "false"}},
        {"name": "closure-operator-role", "protocol": "openid-connect",
         "protocolMapper": "oidc-usermodel-realm-role-mapper", "consentRequired": False,
         "config": {"claim.name": "realm_access.roles", "jsonType.label": "String", "multivalued": "true",
                    "access.token.claim": "true", "id.token.claim": "false",
                    "userinfo.token.claim": "false", "introspection.token.claim": "false"}},
    ]
    mappers = rows(admin.get(path + "/protocol-mappers/models"))
    for expected in wanted:
        named = [item for item in mappers if item.get("name") == expected["name"]]
        if not named:
            admin.post(path + "/protocol-mappers/models", expected)
        elif len(named) != 1 or not mapper_matches(named[0], expected):
            raise ClosureSetupError("Native operator scope mapper differs")
    mappers = rows(admin.get(path + "/protocol-mappers/models"))
    if len(mappers) != len(wanted) or any(not any(mapper_matches(item, expected) for item in mappers) for expected in wanted):
        raise ClosureSetupError("Native operator scope mapper inventory differs")
    mapped = admin.get(path + "/scope-mappings")
    if not isinstance(mapped, dict) or mapped.get("clientMappings"):
        raise ClosureSetupError("Native operator role scope differs")
    realm_roles = rows(mapped.get("realmMappings", []))
    if realm_roles and {item.get("id") for item in realm_roles} != {role["id"]}:
        raise ClosureSetupError("Native operator role scope differs")
    if not realm_roles:
        admin.post(path + "/scope-mappings/realm", [role])
    if {item.get("id") for item in rows(admin.get(path + "/scope-mappings/realm"))} != {role["id"]}:
        raise ClosureSetupError("Native operator role scope unverified")
    # Never make this a realm-wide default scope. Native role gating is still
    # required on client links so unselected users receive no closure audience.
    if any(item.get("id") == scope_id for item in rows(admin.get("/default-default-client-scopes"))):
        raise ClosureSetupError("Operator scope cannot be a realm-wide default")
    selected_clients = {"controlplane-frontend"} if human_ids else set()
    linked = service_accounts(admin) if service_ids else {}
    selected_clients.update(linked[subject] for subject in service_ids)
    for name in sorted(selected_clients):
        native = client(admin, name)
        if native is None or name in PURPOSES or name == "hypermesh-host-setup":
            raise ClosureSetupError("Explicit native operator client unavailable")
        client_path = "/clients/" + quote(native["id"], safe="")
        current = rows(admin.get(client_path + "/default-client-scopes"))
        if not any(item.get("id") == scope_id for item in current):
            admin.put(client_path + "/default-client-scopes/" + quote(scope_id, safe=""), {})
        if not any(item.get("id") == scope_id for item in rows(admin.get(client_path + "/default-client-scopes"))):
            raise ClosureSetupError("Native operator client scope unverified")


def configure(admin, reader_secret, worker_secret, *, human_ids=(), service_ids=(), other_secrets=()):
    validate_secrets(reader_secret, worker_secret, other_secrets)
    if len(human_ids) + len(service_ids) > 1000 or set(human_ids) & set(service_ids):
        raise ClosureSetupError("Unambiguous explicit operator assignments required")
    for subject in (*human_ids, *service_ids):
        identifier(subject)
    ensure_protected_profile(admin)
    targets = operators(admin, human_ids, service_ids)
    role = ensure_role(admin)
    management = client(admin, "realm-management")
    if management is None:
        raise ClosureSetupError("Native realm management client unavailable")
    service_subjects = {
        ensure_credential(admin, READER, reader_secret, management["id"]),
        ensure_credential(admin, WORKER, worker_secret, management["id"]),
    }
    if service_subjects & set(targets):
        raise ClosureSetupError("Closure credentials cannot become closure operators")
    if targets:
        ensure_operator_scope(admin, role, human_ids=human_ids, service_ids=service_ids)
    for subject in targets:
        path = "/users/" + subject + "/role-mappings/realm"
        existing = rows(admin.get(path))
        if not any(item.get("id") == role["id"] for item in existing):
            admin.post(path, [role])
        if not any(item.get("id") == role["id"] for item in rows(admin.get(path))):
            raise ClosureSetupError("Explicit native closure operator grant unverified")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class NativeAdmin:
    """Bounded provisioning transport; no redirects or environment proxies."""

    def __init__(self, base, realm, token):
        parsed = urlsplit(base)
        if parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.hostname or not (
            parsed.scheme == "https" or (parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"})
        ):
            raise ClosureSetupError("Trusted HTTPS or local-loopback administrator transport required")
        if not isinstance(realm, str) or not realm or len(realm) > 128 or realm in {".", ".."}:
            raise ClosureSetupError("Exact native realm required")
        self.base = base.rstrip("/")
        self.root = self.base + "/admin/realms/" + quote(realm, safe="")
        self.token = token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())

    def _request(self, method, url, *, payload=None, form=None, authenticated=True):
        headers = {}
        if authenticated:
            headers["Authorization"] = "Bearer " + self.token
        data = None
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with self.opener.open(request, timeout=10) as response:
                raw = response.read(2 * 1024 * 1024 + 1)
                if len(raw) > 2 * 1024 * 1024:
                    raise ClosureSetupError("Native provisioning response exceeds limit")
                return json.loads(raw) if raw else None
        except (urllib.error.HTTPError, urllib.error.URLError, OSError, ValueError):
            raise ClosureSetupError("Native provisioning request unavailable") from None

    @classmethod
    def login(cls, base, realm, username, password):
        admin = cls(base, realm, "")
        token = admin._request("POST", admin.base + "/realms/master/protocol/openid-connect/token",
                               form={"grant_type": "password", "client_id": "admin-cli",
                                     "username": username, "password": password}, authenticated=False)
        value = token.get("access_token") if isinstance(token, dict) else None
        if not isinstance(value, str) or not value:
            raise ClosureSetupError("Native provisioning credential unavailable")
        admin.token = value
        return admin

    def get(self, path):
        return self._request("GET", self.root + path)

    def post(self, path, payload):
        return self._request("POST", self.root + path, payload=payload)

    def put(self, path, payload):
        return self._request("PUT", self.root + path, payload=payload)

    def delete(self, path, payload=None):
        return self._request("DELETE", self.root + path, payload=payload)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--human-user-id", action="append", default=[])
    parser.add_argument("--service-user-id", action="append", default=[])
    args = parser.parse_args(argv)
    for subject in (*args.human_user_id, *args.service_user_id):
        identifier(subject)
    if not args.apply:
        print(json.dumps({"clients": list(PURPOSES), "enabled": False,
                          "human_user_ids": args.human_user_id, "service_user_ids": args.service_user_id}))
        return 0
    base = os.environ.get("KEYCLOAK_INTERNAL_URL", "")
    parsed = urlsplit(base)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.hostname or not (
        parsed.scheme == "https" or (parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"})
    ):
        raise ClosureSetupError("Trusted HTTPS or local-loopback administrator transport required")
    username = os.environ.get("KC_BOOTSTRAP_ADMIN_USERNAME", "")
    password = os.environ.get("KC_BOOTSTRAP_ADMIN_PASSWORD", "")
    if not username or not password:
        raise ClosureSetupError("Native provisioning administrator required")
    reader_secret = os.environ.get("ACCOUNT_CLOSURE_KEYCLOAK_READER_SECRET", "")
    worker_secret = os.environ.get("ACCOUNT_CLOSURE_KEYCLOAK_CLIENT_SECRET", "")
    other_secrets = [os.environ.get(name, "") for name in (
        "ACCOUNT_CLOSURE_GUARD_TOKEN", "ACCOUNT_CLOSURE_OPERATIONS_TOKEN",
        "KEYCLOAK_CLIENT_SECRET", "AUTH_CONNECT_INTROSPECTION_CLIENT_SECRET",
        "KC_BOOTSTRAP_ADMIN_PASSWORD")]
    validate_secrets(reader_secret, worker_secret, other_secrets)
    if len(args.human_user_id) + len(args.service_user_id) > 1000 or set(args.human_user_id) & set(args.service_user_id):
        raise ClosureSetupError("Unambiguous explicit operator assignments required")
    configure(NativeAdmin.login(base, os.environ.get("ACCOUNT_CLOSURE_KEYCLOAK_REALM", "controlplane"), username, password),
              reader_secret, worker_secret,
              human_ids=args.human_user_id, service_ids=args.service_user_id,
              other_secrets=other_secrets)
    print("Closure credentials provisioned disabled; explicit operator assignments verified")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ClosureSetupError:
        print("ERROR: closure identity setup requires reconciliation", file=sys.stderr)
        raise SystemExit(1) from None
