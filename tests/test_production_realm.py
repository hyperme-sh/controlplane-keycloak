"""Production import cannot inherit fixture credentials or permissive redirects."""
import runpy
from pathlib import Path

import pytest

render = runpy.run_path(str(Path(__file__).resolve().parents[1] /
                           "keycloak" / "production_realm.py"))["render"]
CALLBACKS = {
    "fyberlabs-web": "https://fyberlabs.com/auth/callback",
    "controlplane-frontend": "https://portal.hyperme.sh/api/auth/callback/keycloak",
    "s3rch-web": "https://s3r.ch/api/identity/oauth/callback",
    "windage-web": "https://tennesseewindage.com/auth/callback",
}


def test_production_import_leaves_login_disabled():
    realm = render(CALLBACKS)
    assert realm["realm"] == "controlplane"
    assert realm["sslRequired"] == "all"
    assert not realm["users"] and not realm["identityProviders"]
    for client in realm["clients"]:
        assert client["redirectUris"] == [CALLBACKS[client["clientId"]]]
        assert client["attributes"]["pkce.code.challenge.method"] == "S256"
        assert not client["enabled"] and not client["directAccessGrantsEnabled"]
        assert "secret" not in client


@pytest.mark.parametrize("callback", [
    "https://test.s3r.ch/auth/callback", "http://s3r.ch/auth/callback",
    "https://s3r.ch/*", "https://s3r.ch:443/auth/callback",
    "https://s3r.ch@foreign.example/auth/callback", "https://s3r.ch/auth/../callback",
])
def test_production_import_refuses_noncanonical_callbacks(callback):
    with pytest.raises(ValueError, match="Exact production callback"):
        render(CALLBACKS | {"s3rch-web": callback})
