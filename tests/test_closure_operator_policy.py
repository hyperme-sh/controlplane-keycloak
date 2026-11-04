"""Offline regression coverage for the adopted native authority boundaries."""

import copy
import uuid

import pytest

from test_account_closure_setup import setup


class ReadOnlyAdmin:
    def __init__(self, replies):
        self.replies = replies

    def get(self, path):
        return copy.deepcopy(self.replies[path])

    def __getattr__(self, name):
        raise AssertionError(f"Policy validation attempted a write: {name}")


@pytest.mark.parametrize("name", [setup.READER, setup.WORKER])
def test_credentials_are_disabled_and_separate_from_interactive_authority(name):
    spec = setup.client_spec(name)
    assert spec["enabled"] is False
    assert spec["serviceAccountsEnabled"] is True
    for flag in ("publicClient", "standardFlowEnabled", "implicitFlowEnabled",
                 "directAccessGrantsEnabled", "fullScopeAllowed", "authorizationServicesEnabled"):
        assert spec[flag] is False
    assert spec["redirectUris"] == spec["webOrigins"] == spec["optionalClientScopes"] == []
    assert spec["defaultClientScopes"] == ["basic"]
    assert all(value == "false" for value in spec["attributes"].values())
    audience = next(m for m in spec["protocolMappers"] if m["name"] == "closure-management-audience")
    assert audience["config"]["included.client.audience"] == "realm-management"
    assert setup.OPERATOR_AUDIENCE == "spanopticon-account-closure"
    assert setup.PURPOSES == {setup.READER: "view-users", setup.WORKER: "manage-users"}


@pytest.fixture
def operator_inventory():
    human, service = str(uuid.uuid4()), str(uuid.uuid4())
    replies = {
        "/users/profile": {"attributes": [{"name": "account_type", "permissions": {
            "view": ["admin"], "edit": ["admin"]}}]},
        "/clients?first=0&max=1000": [{"id": "ai-client", "clientId": "explicit-ai", "serviceAccountsEnabled": True}],
        "/clients/ai-client/service-account-user": {"id": service},
        "/users/" + human: {"id": human, "enabled": True, "attributes": {"account_type": ["human"]}},
        "/users/" + service: {"id": service, "enabled": True, "attributes": {"account_type": ["service"]}},
    }
    return human, service, replies


def test_only_exact_explicit_classified_native_operators_are_selected(operator_inventory):
    human, service, replies = operator_inventory
    assert setup.operators(ReadOnlyAdmin(replies), [human], [service]) == [human, service]
    assert setup.operators(ReadOnlyAdmin({}), [], []) == []


@pytest.mark.parametrize("fault", ["self-edit", "disabled", "wrong-id", "unclassified", "service-as-human", "credential-as-operator", "missing-link"])
def test_invalid_operator_authority_is_refused_without_writes(operator_inventory, fault):
    human, service, replies = operator_inventory
    if fault == "self-edit":
        replies["/users/profile"]["attributes"][0]["permissions"]["edit"] = ["user", "admin"]
    elif fault == "disabled":
        replies["/users/" + human]["enabled"] = False
    elif fault == "wrong-id":
        replies["/users/" + human]["id"] = service
    elif fault == "unclassified":
        replies["/users/" + human]["attributes"] = {}
    elif fault == "service-as-human":
        replies["/clients/ai-client/service-account-user"]["id"] = human
    elif fault == "credential-as-operator":
        replies["/clients?first=0&max=1000"][0]["clientId"] = setup.WORKER
    else:
        replies["/clients?first=0&max=1000"] = []
    with pytest.raises(setup.ClosureSetupError):
        setup.operators(ReadOnlyAdmin(replies), [human], [service])


@pytest.mark.parametrize("via_group", [False, True])
def test_default_role_or_group_cannot_grant_operator_authority(via_group):
    role = {"id": "closure", "name": setup.ROLE, "composite": False, "clientRole": False}
    replies = {
        "/roles?search=account%3Aclose": [role],
        "/roles/account%3Aclose": role,
        "": {"defaultRole": {"id": "default"}},
        "/roles-by-id/default/composites": [] if via_group else [role],
        "/default-groups": [{"id": "group"}],
        "/groups/group/role-mappings/realm/composite": [role],
    }
    with pytest.raises(setup.ClosureSetupError, match="default"):
        setup.ensure_role(ReadOnlyAdmin(replies))


@pytest.mark.parametrize("value", [{}, [None], [{}] * 1000])
def test_incomplete_native_inventory_is_not_treated_as_empty(value):
    with pytest.raises(setup.ClosureSetupError, match="inventory"):
        setup.rows(value)
