"""Individual vs organization facts copied from brokered IdPs.

Microsoft, Google, and GitHub each use one OAuth app. A personal account
stays an individual. Which enterprise an organization belongs to is an
organization-owner setting in Panopticon, not a Key Vault map.

Microsoft personal accounts use the public tenant
``9188040d-6c67-4c5b-b112-36a304b66dad``. ``common`` on the app accepts both
personal and work accounts; a specific tenant id is organization-only.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

PROVIDERS = ("microsoft", "google", "github")
# Microsoft documents this tenant id for personal Microsoft accounts.
MSA_TENANT_ID = "9188040d-6c67-4c5b-b112-36a304b66dad"
_TENANT_RE = re.compile(r"[A-Za-z0-9-]{1,64}\Z")


class IdpMapError(ValueError):
    """The tenant id is not usable. No secret text."""


@dataclass(frozen=True, slots=True)
class AccountMapping:
    account: str
    org: str | None


def microsoft_endpoints(tenant: str | None) -> dict[str, str]:
    """Authorization endpoints. Empty tenant stays ``common`` (personal + work)."""
    chosen = (tenant or "").strip() or "common"
    if not _TENANT_RE.fullmatch(chosen):
        raise IdpMapError("microsoft tenant id is not usable")
    base = f"https://login.microsoftonline.com/{chosen}"
    return {
        "authorizationUrl": f"{base}/oauth2/v2.0/authorize",
        "tokenUrl": f"{base}/oauth2/v2.0/token",
        "logoutUrl": f"{base}/oauth2/v2.0/logout",
        "issuer": f"{base}/v2.0",
        "jwksUrl": f"{base}/discovery/v2.0/keys",
    }


def _text(value: Any) -> str:
    return str(value).strip() if isinstance(value, str) else ""


def _github_orgs(claims: dict[str, Any]) -> list[str]:
    raw = claims.get("orgs")
    if isinstance(raw, str) and raw.strip():
        return [raw.strip()]
    if isinstance(raw, list):
        return [str(item).strip() for item in raw if str(item).strip()]
    single = _text(claims.get("idp_org"))
    return [single] if single else []


def classify_idp_account(provider: str, claims: dict[str, Any]) -> AccountMapping:
    """Personal stays individual. The enterprise link is not decided here."""
    kind = provider.strip().lower()
    if kind not in PROVIDERS:
        raise IdpMapError("unknown identity provider")
    if kind == "microsoft":
        tid = _text(claims.get("tid")) or _text(claims.get("idp_org"))
        if not tid or tid.lower() == MSA_TENANT_ID:
            return AccountMapping("individual", None)
        return AccountMapping("organization", tid)
    if kind == "google":
        hosted = _text(claims.get("hd")) or _text(claims.get("idp_org"))
        if not hosted:
            return AccountMapping("individual", None)
        return AccountMapping("organization", hosted)
    orgs = _github_orgs(claims)
    if orgs:
        return AccountMapping("organization", orgs[0])
    return AccountMapping("individual", None)


def _mapper(
    name: str,
    alias: str,
    mapper_type: str,
    config: dict[str, str],
) -> dict[str, Any]:
    return {
        "name": name,
        "identityProviderAlias": alias,
        "identityProviderMapper": mapper_type,
        "config": {"syncMode": "FORCE", **config},
    }


def claim_copy_mappers() -> list[dict[str, Any]]:
    """Copy org facts onto the user. The enterprise binding is not a mapper."""
    return [
        _mapper(
            "microsoft-provider",
            "microsoft",
            "hardcoded-attribute-idp-mapper",
            {"attribute": "idp_provider", "attribute.value": "microsoft"},
        ),
        _mapper(
            "microsoft-tenant",
            "microsoft",
            "oidc-user-attribute-idp-mapper",
            {"claim": "tid", "user.attribute": "idp_org"},
        ),
        _mapper(
            "microsoft-directory-roles",
            "microsoft",
            "oidc-user-attribute-idp-mapper",
            {"claim": "wids", "user.attribute": "idp_wids"},
        ),
        _mapper(
            "fyber-individual-microsoft",
            "microsoft",
            "oidc-advanced-attribute-idp-mapper",
            {
                "claims": json.dumps(
                    [{"key": "tid", "value": MSA_TENANT_ID}],
                    separators=(",", ":"),
                ),
                "attributes": json.dumps(
                    [{"key": "idp_account", "value": "individual"}],
                    separators=(",", ":"),
                ),
            },
        ),
        _mapper(
            "google-provider",
            "google",
            "hardcoded-attribute-idp-mapper",
            {"attribute": "idp_provider", "attribute.value": "google"},
        ),
        _mapper(
            "google-hosted-domain",
            "google",
            "oidc-user-attribute-idp-mapper",
            {"claim": "hd", "user.attribute": "idp_org"},
        ),
        _mapper(
            "github-provider",
            "github",
            "hardcoded-attribute-idp-mapper",
            {"attribute": "idp_provider", "attribute.value": "github"},
        ),
        _mapper(
            "github-login",
            "github",
            "github-user-attribute-mapper",
            {"jsonField": "login", "userAttribute": "idp_login"},
        ),
    ]


def token_claim_mappers() -> list[dict[str, Any]]:
    """Put the broker attributes on the access token. No secret material."""
    names = (
        ("idp_provider", "idp_provider"),
        ("idp_org", "idp_org"),
        ("idp_login", "idp_login"),
        ("idp_account", "idp_account"),
        ("idp_wids", "idp_wids"),
    )
    found = []
    for claim, attribute in names:
        config = {
            "user.attribute": attribute,
            "claim.name": claim,
            "jsonType.label": "String",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true",
        }
        if claim == "idp_wids":
            config["multivalued"] = "true"
        found.append(
            {
                "name": claim,
                "protocol": "openid-connect",
                "protocolMapper": "oidc-usermodel-attribute-mapper",
                "consentRequired": False,
                "config": config,
            }
        )
    return found
