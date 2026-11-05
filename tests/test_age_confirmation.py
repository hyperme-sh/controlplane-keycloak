"""18+ confirmation on the controlplane realm import and the live reconciler."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
KEYCLOAK = ROOT / "keycloak"
REALM_PATH = KEYCLOAK / "import" / "controlplane-realm.json"
sys.path.insert(0, str(KEYCLOAK))

import age_confirmation as age
import configure_idp_brokers as brokers
from test_registration import apply_test_registration


def _realm() -> dict:
    return json.loads(REALM_PATH.read_text(encoding="utf-8"))


def _profile(realm: dict) -> dict:
    raw = realm["components"]["org.keycloak.userprofile.UserProfileProvider"][0]["config"][
        "kc.user.profile.config"
    ][0]
    return json.loads(raw)


def test_age_confirmation_covers_email_registration_and_each_social_provider() -> None:
    """Email registration and each broker create a user via Keycloak addUser.

    addUser attaches every enabled default required action before a code is
    issued. The registration checkbox is not the gate: Keycloak 26.5 does not
    store the timestamp from that checkbox.
    """
    realm = _realm()
    action = next(item for item in realm["requiredActions"] if item["alias"] == age.ACTION)
    assert action["providerId"] == age.ACTION
    assert action["name"] == age.ACTION_NAME
    assert action["enabled"] is True
    assert action["defaultAction"] is True
    assert action["priority"] == 20
    assert realm["registrationAllowed"] is False

    opened = apply_test_registration(realm)
    assert opened["registrationAllowed"] is True
    opened_action = next(item for item in opened["requiredActions"] if item["alias"] == age.ACTION)
    assert opened_action["enabled"] is True
    assert opened_action["defaultAction"] is True

    assert realm["internationalizationEnabled"] is True
    assert realm["supportedLocales"] == ["en"]
    assert realm["defaultLocale"] == "en"
    assert realm["localizationTexts"]["en"] == age.AGE_COPY
    for text in age.AGE_COPY.values():
        assert "18" in text

    providers = {item["alias"]: item for item in realm["identityProviders"]}
    assert set(providers) == set(age.SOCIAL_PROVIDERS)
    for alias in age.SOCIAL_PROVIDERS:
        provider = providers[alias]
        assert provider["enabled"] is True
        assert provider["linkOnly"] is False
        assert provider["firstBrokerLoginFlowAlias"] == "first broker login"

    attribute = next(item for item in _profile(realm)["attributes"] if item["name"] == age.ATTRIBUTE)
    assert attribute == age.PROFILE_ATTRIBUTE
    assert attribute["permissions"] == {"view": ["admin"], "edit": ["admin"]}
    for client_id in age.INTERACTIVE_CLIENTS:
        client = next(item for item in realm["clients"] if item["clientId"] == client_id)
        claim = next(mapper for mapper in client["protocolMappers"] if mapper["name"] == age.ATTRIBUTE)
        assert claim == age.AGE_CLAIM_MAPPER
        account_type = next(mapper for mapper in client["protocolMappers"] if mapper["name"] == "account_type")
        assert account_type["config"]["claim.name"] == "account_type"


def test_imported_people_are_asked_and_automation_accounts_are_not() -> None:
    users = {user["username"]: user for user in _realm()["users"]}
    chris = users["chris@fyberlabs.com"]
    assert chris["attributes"]["account_type"] == ["human"]
    assert age.ACTION in chris["requiredActions"]
    assert age.portal_sign_in_allowed(chris) is False

    for username in ("renter", "leaser", "admin"):
        user = users[username]
        assert user["attributes"]["account_type"] == ["service"]
        assert user["requiredActions"] == []
        assert age.ATTRIBUTE not in user["attributes"]
        assert age.is_automation_account(user) is True
        assert age.portal_sign_in_allowed(user) is True


def test_person_without_confirmation_cannot_reach_the_portal_until_timestamp_is_stored() -> None:
    person = {
        "username": "ada@example.com",
        "attributes": {"account_type": ["human"], "keep": ["yes"]},
        "requiredActions": ["UPDATE_PASSWORD"],
    }
    blocked = age.sync_required_action(person)
    assert blocked is not None
    assert blocked["requiredActions"] == ["UPDATE_PASSWORD", age.ACTION]
    assert blocked["attributes"]["keep"] == ["yes"]
    assert age.portal_sign_in_allowed(blocked) is False
    assert age.sync_required_action(blocked) is None

    declined = age.decline_age_confirmation(blocked)
    assert age.ATTRIBUTE not in declined["attributes"]
    assert age.portal_sign_in_allowed(declined) is False

    confirmed = age.accept_age_confirmation(blocked, timestamp=1_761_900_000)
    assert confirmed["attributes"]["terms_and_conditions"] == ["1761900000"]
    assert confirmed["attributes"]["keep"] == ["yes"]
    assert confirmed["requiredActions"] == ["UPDATE_PASSWORD"]
    assert age.confirmed_timestamp(confirmed) == 1_761_900_000
    assert age.portal_sign_in_allowed(confirmed) is True
    assert age.sync_required_action(confirmed) is None


def test_stale_action_is_cleared_once_the_timestamp_is_present() -> None:
    user = {
        "username": "ada@example.com",
        "attributes": {age.ATTRIBUTE: ["1700000000"]},
        "requiredActions": [age.ACTION, "CONFIGURE_TOTP"],
    }
    updated = age.sync_required_action(user)
    assert updated is not None
    assert updated["requiredActions"] == ["CONFIGURE_TOTP"]
    assert age.portal_sign_in_allowed(updated) is True


def test_client_service_account_is_not_held_for_age_confirmation() -> None:
    machine = {
        "username": "service-account-controlplane-m2m",
        "serviceAccountClientId": "controlplane-m2m",
        "attributes": {},
        "requiredActions": [age.ACTION],
    }
    updated = age.sync_required_action(machine)
    assert updated is not None
    assert updated["requiredActions"] == []
    assert age.portal_sign_in_allowed(updated) is True
    assert age.confirmed_timestamp(updated) is None


def test_chosen_service_account_prefix_does_not_skip_age_confirmation() -> None:
    person = {
        "username": "service-account-bypass@gmail.com",
        "attributes": {},
        "requiredActions": [],
    }
    assert age.is_automation_account(person) is False
    updated = age.sync_required_action(person)
    assert updated is not None
    assert updated["requiredActions"] == [age.ACTION]
    assert age.portal_sign_in_allowed(updated) is False


def test_zero_and_blank_timestamps_do_not_count_as_confirmation() -> None:
    for value in ("0", "", "nope"):
        user = {"username": "ada@example.com", "attributes": {age.ATTRIBUTE: [value]}, "requiredActions": []}
        assert age.confirmed_timestamp(user) is None
        assert age.portal_sign_in_allowed(user) is False


def test_accept_rejects_a_non_positive_timestamp() -> None:
    user = {"username": "ada@example.com", "attributes": {}, "requiredActions": [age.ACTION]}
    with pytest.raises(age.AgeConfirmationError):
        age.accept_age_confirmation(user, 0)


class _Admin:
    def __init__(self) -> None:
        self.realm = {"internationalizationEnabled": False, "registrationAllowed": False}
        self.action = {
            "alias": age.ACTION,
            "name": "Terms and Conditions",
            "providerId": age.ACTION,
            "enabled": False,
            "defaultAction": False,
            "priority": 20,
            "config": {},
        }
        self.texts: dict[str, dict[str, str]] = {}
        self.profile = {"attributes": [{"name": "username", "multivalued": False}], "groups": []}
        self.clients = [
            {"id": client_id.split("-")[-1], "clientId": client_id}
            for client_id in age.INTERACTIVE_CLIENTS
        ]
        self.clients[0]["id"] = "frontend"
        self.mappers: dict[str, list[dict]] = {item["id"]: [] for item in self.clients}
        self.users = {
            "human": {
                "id": "human",
                "username": "ada@example.com",
                "attributes": {"account_type": ["human"]},
                "requiredActions": ["UPDATE_PASSWORD"],
                "access": {"manage": True},
            },
            "confirmed": {
                "id": "confirmed",
                "username": "confirmed@example.com",
                "attributes": {age.ATTRIBUTE: ["1700000000"]},
                "requiredActions": [age.ACTION],
            },
            "service": {
                "id": "service",
                "username": "renter",
                "attributes": {"account_type": ["service"]},
                "requiredActions": [age.ACTION],
            },
            "m2m": {
                "id": "m2m",
                "username": "service-account-controlplane-m2m",
                "serviceAccountClientId": "controlplane-m2m",
                "attributes": {},
                "requiredActions": [age.ACTION],
            },
        }
        self.puts: list[str] = []
        self.posts: list[str] = []
        self.order: list[tuple[str, str]] = []

    def get(self, path: str):
        if path == "":
            return copy.deepcopy(self.realm)
        if path == f"/authentication/required-actions/{age.ACTION}":
            return copy.deepcopy(self.action)
        if path == "/users/profile":
            return copy.deepcopy(self.profile)
        if path.startswith("/clients?"):
            return list(self.clients)
        if path.startswith("/clients/") and path.endswith("/protocol-mappers/models"):
            return copy.deepcopy(self.mappers[path.split("/")[2]])
        if path.startswith("/users?"):
            return [{"id": user["id"], "username": user["username"]} for user in self.users.values()]
        if path.startswith("/users/"):
            return copy.deepcopy(self.users[path.split("/")[2]])
        if path.startswith("/localization/"):
            return dict(self.texts.get(path.split("/")[2], {}))
        raise AssertionError(path)

    def put(self, path: str, payload):
        self.puts.append(path)
        self.order.append(("put", path))
        if path == "":
            self.realm = payload
            return
        if path == f"/authentication/required-actions/{age.ACTION}":
            self.action = payload
            return
        if path == "/users/profile":
            self.profile = payload
            return
        if "/protocol-mappers/models/" in path:
            client_id = path.split("/")[2]
            mapper_id = path.rsplit("/", 1)[-1]
            self.mappers[client_id] = [
                {**payload, "id": mapper_id} if item["id"] == mapper_id else item
                for item in self.mappers[client_id]
            ]
            return
        if path.startswith("/users/"):
            self.users[path.split("/")[2]] = payload
            return
        raise AssertionError(path)

    def post(self, path: str, payload):
        self.posts.append(path)
        self.order.append(("post", path))
        if path.startswith("/localization/"):
            self.texts.setdefault(path.split("/")[2], {}).update(payload)
            return
        if path.startswith("/clients/") and path.endswith("/protocol-mappers/models"):
            client_id = path.split("/")[2]
            self.mappers[client_id].append({**payload, "id": f"{client_id}-{payload['name']}"})
            return
        raise AssertionError(path)


def test_reconcile_asks_existing_people_and_skips_automation(capsys) -> None:
    admin = _Admin()
    age.ensure_age_confirmation(admin)
    assert admin.action["enabled"] is True
    assert admin.action["defaultAction"] is True
    assert admin.action["name"] == age.ACTION_NAME
    assert admin.realm["internationalizationEnabled"] is True
    assert admin.realm["defaultLocale"] == "en"
    assert admin.realm["registrationAllowed"] is False
    assert admin.texts["en"] == age.AGE_COPY
    stored = next(item for item in admin.profile["attributes"] if item["name"] == age.ATTRIBUTE)
    assert stored == age.PROFILE_ATTRIBUTE
    assert admin.users["human"]["requiredActions"] == ["UPDATE_PASSWORD", age.ACTION]
    assert "access" not in admin.users["human"]
    assert admin.users["confirmed"]["requiredActions"] == []
    assert admin.users["confirmed"]["attributes"][age.ATTRIBUTE] == ["1700000000"]
    assert admin.users["service"]["requiredActions"] == []
    assert admin.users["m2m"]["requiredActions"] == []
    for client in admin.clients:
        names = {item["name"] for item in admin.mappers[client["id"]]}
        assert age.ATTRIBUTE in names
        assert "account_type" in names
    assert "1 existing account will be asked on next sign-in" in capsys.readouterr().out
    text_at = next(
        index for index, (method, path) in enumerate(admin.order)
        if method == "post" and path.startswith("/localization/")
    )
    action_at = next(
        index for index, (method, path) in enumerate(admin.order)
        if method == "put" and path.endswith("/" + age.ACTION)
    )
    assert text_at < action_at

    puts = len(admin.puts)
    posts = len(admin.posts)
    age.ensure_age_confirmation(admin)
    assert admin.puts[puts:] == []
    assert len(admin.posts) > posts


def test_failed_age_copy_does_not_enable_the_stock_terms_action() -> None:
    admin = _Admin()
    original = admin.post

    def post(path, payload):
        if path.startswith("/localization/"):
            raise RuntimeError("localization unavailable")
        original(path, payload)

    admin.post = post
    with pytest.raises(RuntimeError, match="localization unavailable"):
        age.ensure_age_confirmation(admin)
    assert admin.action["enabled"] is False
    assert admin.action["defaultAction"] is False


def test_reconcile_fails_closed_when_the_required_action_is_missing() -> None:
    admin = _Admin()
    admin.action = {"alias": "other", "providerId": "other"}
    with pytest.raises(age.AgeConfirmationError, match="missing"):
        age.ensure_age_confirmation(admin)


def test_broker_updates_do_not_swallow_the_age_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[str] = []
    monkeypatch.setattr(brokers, "ensure_hypermesh_native", lambda _admin: None)
    monkeypatch.setattr(brokers, "ensure_hypermesh_host_setup", lambda _admin: None)
    monkeypatch.setattr(brokers, "ensure_s3rch_web", lambda _admin: None)
    monkeypatch.setattr(brokers, "configure", lambda _admin: called.append("brokers"))
    monkeypatch.setattr(brokers, "ensure_age_confirmation", lambda _admin: called.append("age"))
    assert brokers.apply_realm_updates(object()) == 0
    assert called == ["brokers"]


def test_age_confirmation_failure_blocks_rollout(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setenv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
    monkeypatch.setenv("KC_BOOTSTRAP_ADMIN_PASSWORD", "pw")
    monkeypatch.setattr(brokers, "admin_token", lambda *args, **kwargs: "token")
    monkeypatch.setattr(brokers, "AdminClient", lambda *args, **kwargs: object())
    monkeypatch.setattr(brokers, "apply_realm_updates", lambda admin: 1)

    def boom(admin):
        raise age.AgeConfirmationError("profile was not applied")

    monkeypatch.setattr(brokers, "ensure_age_confirmation", boom)
    assert brokers.main() == 2
    assert "age confirmation blocked rollout" in capsys.readouterr().err

    monkeypatch.setattr(brokers, "ensure_age_confirmation", lambda admin: None)
    assert brokers.main() == 1


def test_age_confirmation_script_is_a_blocking_entrypoint() -> None:
    script = (ROOT / "scripts" / "require-age-confirmation.sh").read_text(encoding="utf-8")
    assert "set -euo pipefail" in script
    invoked = [line.strip() for line in script.splitlines() if "python3" in line]
    assert invoked == ['exec python3 "$ROOT/keycloak/age_confirmation.py"']
