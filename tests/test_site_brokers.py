"""Offline contracts for optional, disabled provider staging."""
import importlib
from pathlib import Path
from unittest.mock import Mock

import pytest


@pytest.fixture
def broker(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "keycloak"))
    module = importlib.import_module("configure_idp_brokers")
    monkeypatch.setattr(module, "_env", lambda name: "")
    return module


def test_no_credentials_means_no_admin_calls(broker):
    admin = Mock()
    broker.prepare_site_brokers(admin)
    assert not admin.mock_calls


def test_partial_credentials_refuse_before_writes(broker, monkeypatch):
    admin = Mock()
    monkeypatch.setattr(broker, "_env", {"KC_IDP_GITHUB_S3RCH_CLIENT_ID": "new-client"}.get)
    with pytest.raises(broker.ConfigureError, match="Incomplete site broker credentials"):
        broker.prepare_site_brokers(admin)
    assert not admin.mock_calls


def test_staging_copies_only_safe_template_fields(broker, monkeypatch):
    values = {"KC_IDP_GITHUB_S3RCH_CLIENT_ID": "new-client",
              "KC_IDP_GITHUB_S3RCH_CLIENT_SECRET": "new-secret"}
    monkeypatch.setattr(broker, "_env", values.get)
    admin = Mock()
    template = {"providerId": "github", "firstBrokerLoginFlowAlias": "approved-flow",
                "storeToken": True, "mappers": [{"name": "operator"}],
                "config": {"clientId": "old", "clientSecret": "old", "defaultScope": "read:user"}}
    monkeypatch.setattr(broker, "_provider", lambda admin, alias: template if alias == "github" else None)
    broker.prepare_site_brokers(admin)
    path, staged = admin.post.call_args.args
    assert path == "/identity-provider/instances"
    assert staged["alias"] == "github-s3rch"
    assert staged["firstBrokerLoginFlowAlias"] == "approved-flow"
    assert not staged["enabled"] and staged["hideOnLogin"]
    assert not staged["storeToken"] and not staged["addReadTokenRoleOnCreate"]
    assert "mappers" not in staged
    assert staged["config"] == {"clientId": "new-client", "clientSecret": "new-secret",
                                "defaultScope": "read:user"}
    assert template["config"]["clientSecret"] == "old"


def test_existing_matching_alias_is_left_alone(broker, monkeypatch):
    values = {"KC_IDP_GITHUB_S3RCH_CLIENT_ID": "new-client",
              "KC_IDP_GITHUB_S3RCH_CLIENT_SECRET": "new-secret"}
    monkeypatch.setattr(broker, "_env", values.get)
    admin = Mock()
    monkeypatch.setattr(broker, "_provider", lambda admin, alias: {
        "config": {"clientId": "new-client"}, "enabled": True,
    })
    broker.prepare_site_brokers(admin)
    assert not admin.mock_calls
