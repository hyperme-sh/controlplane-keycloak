"""Individual vs organization account classification for brokered IdPs.

Microsoft, Google, and GitHub each use one OAuth app. A personal account
stays an individual. An organization account (Entra tenant, Google hosted
domain, GitHub org) maps to an enterprise legal name when that org key is
in the operator map. The map is JSON from Key Vault, never a value in git.

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
_ORG_KEY_RE = re.compile(r"[A-Za-z0-9._@-]{1,256}\Z")


class IdpMapError(ValueError):
    """The enterprise map or tenant id is not usable. No secret text."""


@dataclass(frozen=True, slots=True)
class AccountMapping:
    account: str
    org: str | None
    enterprise: str | None


def parse_enterprise_map(raw: str | None) -> dict[str, dict[str, str]] | None:
    """Return None when unset. ``{}`` clears managed enterprise mappers."""
    if raw is None or not str(raw).strip():
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise IdpMapError("enterprise map is not JSON") from exc
    if not isinstance(data, dict):
        raise IdpMapError("enterprise map must be a JSON object")
    unknown = set(data) - set(PROVIDERS)
    if unknown:
        raise IdpMapError("enterprise map has an unknown provider")
    parsed: dict[str, dict[str, str]] = {}
    for provider in PROVIDERS:
        table = data.get(provider) or {}
        if not isinstance(table, dict):
            raise IdpMapError(f"{provider} enterprise map must be an object")
        cleaned: dict[str, str] = {}
        for key, legal_name in table.items():
            org_key = str(key).strip()
            name = str(legal_name).strip()
            if not _ORG_KEY_RE.fullmatch(org_key):
                raise IdpMapError(f"{provider} org key is not usable")
            if not name or len(name) > 512 or any(ch in name for ch in "\r\n"):
                raise IdpMapError(f"{provider} enterprise name is not usable")
            cleaned[org_key] = name
        parsed[provider] = cleaned
    return parsed


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


def classify_idp_account(
    provider: str,
    claims: dict[str, Any],
    enterprise_map: dict[str, dict[str, str]] | None,
) -> AccountMapping:
    """Personal stays individual. A mapped org key becomes that enterprise."""
    kind = provider.strip().lower()
    if kind not in PROVIDERS:
        raise IdpMapError("unknown identity provider")
    table = (enterprise_map or {}).get(kind) or {}
    if kind == "microsoft":
        tid = _text(claims.get("tid")) or _text(claims.get("idp_org"))
        if not tid or tid.lower() == MSA_TENANT_ID:
            return AccountMapping("individual", None, None)
        return AccountMapping("organization", tid, table.get(tid))
    if kind == "google":
        hosted = _text(claims.get("hd")) or _text(claims.get("idp_org"))
        if not hosted:
            return AccountMapping("individual", None, None)
        return AccountMapping("organization", hosted, table.get(hosted))
    orgs = _github_orgs(claims)
    for org in orgs:
        if org in table:
            return AccountMapping("organization", org, table[org])
    if orgs:
        return AccountMapping("organization", orgs[0], None)
    return AccountMapping("individual", None, None)


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


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return (cleaned or "org")[:48]


def claim_copy_mappers() -> list[dict[str, Any]]:
    """Copy the org claim onto the user. Present even when the map is empty."""
    return [
        _mapper(
            "microsoft-tenant",
            "microsoft",
            "oidc-user-attribute-idp-mapper",
            {"claim": "tid", "user.attribute": "idp_org"},
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
            "google-hosted-domain",
            "google",
            "oidc-user-attribute-idp-mapper",
            {"claim": "hd", "user.attribute": "idp_org"},
        ),
        _mapper(
            "github-login",
            "github",
            "github-user-attribute-mapper",
            {"jsonField": "login", "userAttribute": "idp_login"},
        ),
    ]


def enterprise_mappers(
    enterprise_map: dict[str, dict[str, str]],
) -> list[dict[str, Any]]:
    """One mapper per org key. GitHub fires only when that org is on the profile."""
    claim_for = {"microsoft": "tid", "google": "hd", "github": "idp_org"}
    mapper_for = {
        "microsoft": "oidc-advanced-attribute-idp-mapper",
        "google": "oidc-advanced-attribute-idp-mapper",
        "github": "oidc-advanced-attribute-idp-mapper",
    }
    found: list[dict[str, Any]] = []
    for provider, table in enterprise_map.items():
        for org_key, legal_name in sorted(table.items()):
            found.append(
                _mapper(
                    f"fyber-enterprise-{provider}-{_slug(org_key)}",
                    provider,
                    mapper_for[provider],
                    {
                        "claims": json.dumps(
                            [{"key": claim_for[provider], "value": org_key}],
                            separators=(",", ":"),
                        ),
                        "attributes": json.dumps(
                            [
                                {"key": "enterprise", "value": legal_name},
                                {"key": "idp_account", "value": "organization"},
                            ],
                            separators=(",", ":"),
                        ),
                    },
                )
            )
    return found


def token_claim_mappers() -> list[dict[str, Any]]:
    """Put the broker attributes on the access token. No secret material."""
    names = (
        ("idp_org", "idp_org"),
        ("idp_login", "idp_login"),
        ("idp_account", "idp_account"),
        ("enterprise", "enterprise"),
    )
    return [
        {
            "name": claim,
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-attribute-mapper",
            "consentRequired": False,
            "config": {
                "user.attribute": attribute,
                "claim.name": claim,
                "jsonType.label": "String",
                "id.token.claim": "true",
                "access.token.claim": "true",
                "userinfo.token.claim": "true",
            },
        }
        for claim, attribute in names
    ]
