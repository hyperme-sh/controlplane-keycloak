"""Render a clean production issuer bootstrap realm without users or secrets."""
import argparse
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

SITES = {
    "fyberlabs-web": {"fyberlabs.com", "www.fyberlabs.com"},
    "controlplane-frontend": {"hyperme.sh", "portal.hyperme.sh"},
    "s3rch-web": {"s3r.ch"},
    "windage-web": {"tennesseewindage.com", "www.tennesseewindage.com"},
}


def validate_callback(client_id, value):
    if not isinstance(value, str) or not value.isascii() or any(
        character.isspace() or character in "*\\%?#" for character in value
    ):
        raise ValueError("Exact production callback required")
    url = urlsplit(value)
    if (url.scheme != "https" or url.netloc not in SITES[client_id]
            or not re.fullmatch(r"/[A-Za-z0-9._~!$&'()+,;=:@/-]+", url.path)
            or any(part in (".", "..") for part in url.path.split("/"))):
        raise ValueError("Exact production callback required")
    return value


def render(callbacks):
    if not isinstance(callbacks, dict) or set(callbacks) != set(SITES):
        raise ValueError("All four production site callbacks are required")
    clients = []
    for client_id in sorted(SITES):
        callback = validate_callback(client_id, callbacks[client_id])
        clients.append({
            "clientId": client_id,
            "protocol": "openid-connect",
            "enabled": False,
            "publicClient": True,
            "fullScopeAllowed": False,
            "defaultClientScopes": ["basic", "email", "profile", "acr"],
            "optionalClientScopes": [],
            "standardFlowEnabled": True,
            "implicitFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": False,
            "redirectUris": [callback],
            "attributes": {"pkce.code.challenge.method": "S256"},
        })
    return {
        "realm": "controlplane",
        "enabled": True,
        "sslRequired": "all",
        "registrationAllowed": False,
        "resetPasswordAllowed": False,
        "bruteForceProtected": True,
        "clients": clients,
        "users": [],
        "identityProviders": [],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("callbacks", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(render(json.loads(args.callbacks.read_text())), indent=2))
    except (OSError, ValueError):
        parser.exit(2, "Production realm inputs refused\n")


if __name__ == "__main__":
    main()
