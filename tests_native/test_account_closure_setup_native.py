"""Actual Keycloak provisioning in a disposable realm; never a deployed provider."""

import importlib.util
import uuid
from pathlib import Path

import docker
import httpx
import jwt
import pytest
from controlplane_identity.security.keycloak_jwt import KeycloakJWTValidator
import time

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("closure_setup", ROOT / "keycloak/account_closure.py")
setup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(setup)


KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak@sha256:8d44614c74798322c4e07fbe0ecb15cfbb5879d69b484628555f58ade06f0d8c"


@pytest.fixture(scope="module")
def provider():
    # No configured provider, credentials, host port or persistent volume is used.
    # Missing Docker is a failure in this explicit native lane, never a skip.
    client = docker.DockerClient(base_url="unix:///var/run/docker.sock")
    client.ping()
    secret = uuid.uuid4().hex + uuid.uuid4().hex
    container = None
    try:
        if not client.images.list(name=KEYCLOAK_IMAGE):
            client.images.pull(KEYCLOAK_IMAGE)
        container = client.containers.run(KEYCLOAK_IMAGE,
            command="start-dev --http-port=8080 --hostname-strict=false",
            environment={"KC_BOOTSTRAP_ADMIN_USERNAME": "closure-provision-admin",
                         "KC_BOOTSTRAP_ADMIN_PASSWORD": secret},
            ports={"8080/tcp": ("127.0.0.1", None)}, detach=True)
        container.reload()
        binding = container.attrs["NetworkSettings"]["Ports"]["8080/tcp"][0]
        assert binding["HostIp"] == "127.0.0.1"
        base = "http://127.0.0.1:" + binding["HostPort"]
        with httpx.Client(base_url=base, timeout=15, trust_env=False, follow_redirects=False) as transport:
            deadline = time.monotonic() + 180
            while True:
                try:
                    ready = transport.get("/realms/master/.well-known/openid-configuration")
                    if ready.status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                if time.monotonic() >= deadline:
                    raise AssertionError("Disposable Keycloak did not become ready")
                time.sleep(0.5)
            token = transport.post("/realms/master/protocol/openid-connect/token", data={
                "grant_type": "password", "client_id": "admin-cli",
                "username": "closure-provision-admin", "password": secret})
            token.raise_for_status()
            realm = "closure-provision-" + uuid.uuid4().hex
            result = transport.post("/admin/realms", headers={"Authorization": "Bearer " + token.json()["access_token"]},
                                    json={"realm": realm, "enabled": True})
            assert result.status_code == 201
            admin = setup.NativeAdmin.login(base, realm, "closure-provision-admin", secret)
            yield admin, transport, base, realm
    finally:
        if container is not None:
            container.remove(force=True, v=True)
        client.close()


def verified_token(transport, base, realm, client_id, *, subject, secret=None, username=None, password=None):
    data = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": secret}
    if username is not None:
        data = {"grant_type": "password", "client_id": client_id, "username": username, "password": password}
    response = transport.post(f"/realms/{realm}/protocol/openid-connect/token", data=data)
    assert response.status_code == 200
    value = response.json()["access_token"]
    assert "refresh_token" not in response.json() or username is not None
    keys = transport.get(f"/realms/{realm}/protocol/openid-connect/certs").json()["keys"]
    header = jwt.get_unverified_header(value)
    key = jwt.PyJWK.from_dict(next(item for item in keys if item["kid"] == header["kid"]))
    claims = jwt.decode(value, key.key, algorithms=["RS256"], issuer=f"{base}/realms/{realm}", options={"verify_aud": False})
    assert claims["sub"] == subject and claims["azp"] == client_id
    return value, claims


def test_native_disabled_credentials_exact_human_ai_grants_and_runtime_permissions(provider, monkeypatch):
    # This fixture verifies the native provider and scoped JWT contract; it must
    # never call any environment-configured deployed retirement authority.
    monkeypatch.setenv("ACCOUNT_CLOSURE_ENFORCEMENT_ENABLED", "false")
    for variable in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(variable, raising=False)
    admin, transport, base, realm = provider
    reader, worker = uuid.uuid4().hex + uuid.uuid4().hex, uuid.uuid4().hex + uuid.uuid4().hex
    setup.configure(admin, reader, worker)
    clients = {name: setup.client(admin, name) for name in setup.PURPOSES}
    original_ids = {name: client["id"] for name, client in clients.items()}
    classification_spec = importlib.util.spec_from_file_location("account_types", ROOT / "keycloak/account_types.py")
    classification = importlib.util.module_from_spec(classification_spec)
    classification_spec.loader.exec_module(classification)
    for native in clients.values():
        classification.ensure_mapper(admin, native["id"], classification.SERVICE_MAPPER)
    setup.configure(admin, reader, worker)
    assert {name: setup.client(admin, name)["id"] for name in setup.PURPOSES} == original_ids
    subjects = {}
    for name, native in clients.items():
        assert admin.get("/clients/" + native["id"])["enabled"] is False
        user = admin.get("/clients/" + native["id"] + "/service-account-user")
        subjects[name] = user["id"]
        assert user["attributes"][setup.PROTECTED_ATTRIBUTE] == ["true"]
        response = transport.post(f"/realms/{realm}/protocol/openid-connect/token", data={
            "grant_type": "client_credentials", "client_id": name,
            "client_secret": reader if name == setup.READER else worker})
        assert response.status_code in {400, 401}

    # Use the existing administrator-owned account-type contract. No user can
    # self-classify to gain a global role, and this setup grants no default role.
    profile = admin.get("/users/profile")
    account_type = {"name": "account_type", "displayName": "Account type", "multivalued": False,
                    "permissions": {"view": ["admin"], "edit": ["admin"]},
                    "validations": {"options": {"options": ["human", "service"]}}}
    admin.put("/users/profile", {**profile, "attributes": [*profile["attributes"], account_type]})
    password = uuid.uuid4().hex + uuid.uuid4().hex
    humans = []
    for number in range(2):
        username = "human-" + uuid.uuid4().hex
        admin.post("/users", {"username": username, "enabled": True, "emailVerified": True,
                             "email": username + "@example.invalid", "firstName": "Native", "lastName": "Human",
                             "attributes": {"account_type": ["human"]},
                             "credentials": [{"type": "password", "value": password, "temporary": False}]})
        human = next(user for user in admin.get("/users?username=" + username) if user["username"] == username)
        humans.append((human["id"], username))
    login_client = "controlplane-frontend"
    admin.post("/clients", {"clientId": login_client, "enabled": True, "publicClient": True,
                           "standardFlowEnabled": False, "directAccessGrantsEnabled": True, "fullScopeAllowed": True,
                           "protocolMappers": [{"name": "local-adult-proof", "protocol": "openid-connect",
                               "protocolMapper": "oidc-hardcoded-claim-mapper",
                               "config": {"claim.name": "terms_and_conditions", "claim.value": "1700000000",
                                          "jsonType.label": "String", "access.token.claim": "true"}}]})
    ai_client, ai_secret = "operator-ai-" + uuid.uuid4().hex, uuid.uuid4().hex + uuid.uuid4().hex
    admin.post("/clients", {"clientId": ai_client, "enabled": True, "publicClient": False,
                           "secret": ai_secret, "serviceAccountsEnabled": True, "fullScopeAllowed": True,
                           "standardFlowEnabled": False, "directAccessGrantsEnabled": False})
    ai = setup.client(admin, ai_client)
    ai_user = admin.get("/clients/" + ai["id"] + "/service-account-user")
    admin.put("/users/" + ai_user["id"], {**ai_user, "attributes": {"account_type": ["service"]}})
    setup.configure(admin, reader, worker, human_ids=[humans[0][0]], service_ids=[ai_user["id"]])
    setup.configure(admin, reader, worker, human_ids=[humans[0][0]], service_ids=[ai_user["id"]])
    human_value, human_claims = verified_token(transport, base, realm, login_client, subject=humans[0][0], username=humans[0][1], password=password)
    ai_value, ai_claims = verified_token(transport, base, realm, ai_client, subject=ai_user["id"], secret=ai_secret)
    unselected_value, unselected = verified_token(transport, base, realm, login_client, subject=humans[1][0], username=humans[1][1], password=password)
    assert setup.ROLE in human_claims["realm_access"]["roles"]
    assert setup.ROLE in ai_claims["realm_access"]["roles"]
    assert setup.ROLE not in unselected["realm_access"]["roles"]
    assert setup.OPERATOR_AUDIENCE in human_claims["aud"]
    assert setup.OPERATOR_AUDIENCE in ai_claims["aud"]
    assert setup.OPERATOR_AUDIENCE not in unselected.get("aud", [])
    validator = KeycloakJWTValidator(f"{base}/realms/{realm}/protocol/openid-connect/certs",
                                    f"{base}/realms/{realm}", "ignored-generic-client")
    allowed = frozenset({login_client, ai_client})
    assert validator.validate_closure_operator_sync(human_value, client_ids=allowed)["sub"] == humans[0][0]
    assert validator.validate_closure_operator_sync(ai_value, client_ids=allowed)["sub"] == ai_user["id"]
    with pytest.raises(jwt.InvalidTokenError):
        validator.validate_closure_operator_sync(unselected_value, client_ids=allowed)
    for subject in (humans[0][0], ai_user["id"]):
        assigned = admin.get("/users/" + subject + "/role-mappings/realm")
        assert sum(item["name"] == setup.ROLE for item in assigned) == 1

    protected = admin.get("/users/" + subjects[setup.READER])
    admin.put("/users/" + protected["id"], {**protected, "attributes": {**protected["attributes"], "account_type": ["service"]}})
    with pytest.raises(setup.ClosureSetupError, match="cannot become closure operators"):
        setup.configure(admin, reader, worker, service_ids=[protected["id"]])
    assert all(item["name"] != setup.ROLE for item in admin.get("/users/" + protected["id"] + "/role-mappings/realm"))

    # Reconciliation refuses automatic authority through default role trees or
    # default groups, rather than silently granting closure to future accounts.
    role = admin.get("/roles/" + setup.ROLE)
    default = admin.get("")["defaultRole"]
    admin.post("/roles-by-id/" + default["id"] + "/composites", [role])
    try:
        with pytest.raises(setup.ClosureSetupError, match="cannot be a default grant"):
            setup.configure(admin, reader, worker, human_ids=[humans[1][0]])
    finally:
        admin.delete("/roles-by-id/" + default["id"] + "/composites", [role])
    group_name = "automatic-" + uuid.uuid4().hex
    admin.post("/groups", {"name": group_name})
    group = next(item for item in admin.get("/groups?search=" + group_name) if item["name"] == group_name)
    admin.post("/groups/" + group["id"] + "/role-mappings/realm", [role])
    admin.put("/default-groups/" + group["id"], {})
    try:
        with pytest.raises(setup.ClosureSetupError, match="cannot be a default group grant"):
            setup.configure(admin, reader, worker, human_ids=[humans[1][0]])
    finally:
        admin.delete("/groups/" + group["id"])
    assert all(item["name"] != setup.ROLE for item in admin.get("/users/" + humans[1][0] + "/role-mappings/realm"))

    root = f"/admin/realms/{realm}"
    target = humans[1][0]
    for name, native in clients.items():
        # Only this isolated test realm is activated to prove actual permissions.
        admin.put("/clients/" + native["id"], {"enabled": True})
        value, claims = verified_token(transport, base, realm, name, subject=subjects[name], secret=reader if name == setup.READER else worker)
        expected = {"view-users", "query-users", "query-groups"} if name == setup.READER else {"manage-users"}
        assert set(claims["resource_access"]["realm-management"]["roles"]) == expected
        assert setup.ROLE not in claims.get("realm_access", {}).get("roles", [])
        assert claims["account_type"] == "service"
        headers = {"Authorization": "Bearer " + value}
        reply = transport.get(root + "/users/" + subjects[name], headers=headers)
        assert reply.status_code == 200 and reply.json()["attributes"][setup.PROTECTED_ATTRIBUTE] == ["true"]
        assert transport.get(root + "/users/" + target, headers=headers).status_code == 200
        assert transport.put(root + "/clients/" + native["id"], headers=headers, json={"enabled": False}).status_code == 403
        changed = transport.put(root + "/users/" + target, headers=headers, json={"enabled": False})
        assert changed.status_code == (403 if name == setup.READER else 204)
        logout = transport.post(root + "/users/" + target + "/logout", headers=headers)
        assert logout.status_code == (403 if name == setup.READER else 204)
        deleted = transport.delete(root + "/users/" + target, headers=headers)
        assert deleted.status_code == (403 if name == setup.READER else 204)
        if name == setup.WORKER:
            assert transport.get(root + "/users/" + target, headers=headers).status_code == 404
