from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

def test_checked_in_introspection_client_is_confidential_and_has_no_login_flows():
    import json
    from pathlib import Path

    realm = json.loads(
        (
            REPO_ROOT
            / "keycloak/import/controlplane-realm.json"
        ).read_text()
    )
    client = next(
        c for c in realm["clients"] if c["clientId"] == "auth-connect-introspection"
    )
    assert client["publicClient"] is False
    assert client["clientAuthenticatorType"] == "client-secret"
    assert all(
        client[k] is False
        for k in (
            "standardFlowEnabled",
            "implicitFlowEnabled",
            "directAccessGrantsEnabled",
            "serviceAccountsEnabled",
            "fullScopeAllowed",
        )
    )
    assert (
        "secret" not in client
    )  # Keycloak generates it; no reusable secret is checked in.


def test_realm_disables_password_grants():
    realm = (
        REPO_ROOT / "keycloak" / "import" / "controlplane-realm.json"
    ).read_text()
    assert realm.count('"directAccessGrantsEnabled": false') >= 1
    assert '"directAccessGrantsEnabled": true' not in realm


def test_pan_test_seed_fixtures_stay_split():
    source = (
        REPO_ROOT / "keycloak" / "seed_pan_test_identities.py"
    ).read_text()
    assert 'username="renter"' in source
    assert 'username="leaser"' in source
    assert 'username="admin"' in source
    assert "renter@test.hyperme.sh" in source
    assert "leaser@test.hyperme.sh" in source
    assert "admin@test.hyperme.sh" in source
    assert (
        "Never one user with all roles" in source
        or "never one user with all roles" in source
    )
    assert source.count("realm_roles=(") == 3
    assert 'realm_roles=("renter",)' in source
    assert 'realm_roles=("host",)' in source
    assert 'realm_roles=("admin",)' in source
    assert 'realm_roles=("renter", "host", "admin")' not in source
