#!/usr/bin/env python3
"""18+ confirmation before a person can finish portal sign-in.

Keycloak's ``TERMS_AND_CONDITIONS`` required action is the gate. It is
enabled and marked as a default action, so a user created by email
registration or by first login through Microsoft, GitHub, or Google cannot
finish sign-in until they accept. Accept stores the user attribute
``terms_and_conditions`` as Unix seconds. Decline leaves the action in place
and issues no authorization code, so the portal session is never created.

The registration-form checkbox (``registration-terms-and-conditions``) only
checks that a box was ticked. In Keycloak 26.5 its success step does not
write the timestamp, and stacking it on the required action would ask twice.
The required action is the single confirmation.

Import does not update a realm that already exists. ``ensure_age_confirmation``
adds the action to every existing person who has no timestamp, which is what
asks them on their next sign-in. ``configure_idp_brokers.py`` runs that step
after its other updates and returns exit 2 when it fails. Exit 1 from that
process is only the non-fatal client warning. ``scripts/require-age-confirmation.sh``
is the same gate with no other steps; a nonzero status blocks rollout.

Keycloak 26.5 will skip this required action when the authorization request
sets ``kc_action=TERMS_AND_CONDITIONS`` (CVE-2026-118959). The portal therefore
refuses a session unless the token carries this timestamp. ``account_type=service``
is the automation exception and is not a person.

Shared automation (``account_type=service``, which only an administrator can
set, and Keycloak client service accounts identified by
``serviceAccountClientId``) is not a person and cannot complete the page.
A username that merely starts with ``service-account-`` is not enough: an
identity-provider user can choose that name. The pending action is removed
only from real automation accounts so client-credentials and the pan-test
harness keep working.
"""

from __future__ import annotations

import copy
from typing import Any

ACTION = "TERMS_AND_CONDITIONS"
ATTRIBUTE = "terms_and_conditions"
ACTION_NAME = "Age confirmation (18+)"
PAGE_SIZE = 100
# Admin GET includes these read-only fields. Sending them back on PUT is rejected.
_USER_PUT_OMIT = {
    "access",
    "credentials",
    "disableableCredentialTypes",
    "totp",
    "userProfileMetadata",
}

# Shown on the Keycloak required-action page. 18+ is the rule.
AGE_COPY = {
    "termsTitle": "Confirm you are at least 18",
    "termsText": (
        "<p>Portal accounts are for people who are at least 18 years old.</p>"
        "<p>Choose I'm at least 18 only if that is true. If you are under 18, "
        "decline. Without this confirmation the account cannot sign in.</p>"
    ),
    "doAccept": "I'm at least 18",
    "doDecline": "I'm under 18",
    "acceptTerms": "I'm at least 18",
    "termsAcceptanceRequired": "You must confirm that you are at least 18.",
}

PROFILE_ATTRIBUTE = {
    "name": ATTRIBUTE,
    "displayName": "Age confirmed at (Unix seconds)",
    "permissions": {"view": ["admin"], "edit": ["admin"]},
    "validations": {"pattern": {"pattern": "^[1-9][0-9]*$"}},
    "multivalued": False,
}

SOCIAL_PROVIDERS = ("microsoft", "github", "google")
AGE_CLAIM_MAPPER = {
    "name": ATTRIBUTE,
    "protocol": "openid-connect",
    "protocolMapper": "oidc-usermodel-attribute-mapper",
    "consentRequired": False,
    "config": {
        "user.attribute": ATTRIBUTE,
        "claim.name": ATTRIBUTE,
        "jsonType.label": "long",
        "multivalued": "false",
        "id.token.claim": "true",
        "access.token.claim": "true",
        "userinfo.token.claim": "true",
        "introspection.token.claim": "true",
    },
}
ACCOUNT_TYPE_CLAIM_MAPPER = {
    "name": "account_type",
    "protocol": "openid-connect",
    "protocolMapper": "oidc-usermodel-attribute-mapper",
    "consentRequired": False,
    "config": {
        "user.attribute": "account_type",
        "claim.name": "account_type",
        "jsonType.label": "String",
        "multivalued": "false",
        "aggregate.attrs": "false",
        "id.token.claim": "true",
        "access.token.claim": "true",
        "userinfo.token.claim": "false",
        "introspection.token.claim": "true",
    },
}
# Browser, device, and native sign-in. Machine clients are not in this list.
INTERACTIVE_CLIENTS = (
    "controlplane-frontend",
    "controlplane-mobile",
    "controlplane-device",
    "hypermesh-native",
)


class AgeConfirmationError(RuntimeError):
    """Age confirmation was not applied. The message must not include a secret."""


def confirmed_timestamp(user: dict[str, Any]) -> int | None:
    """Unix seconds stored by Keycloak when the person accepts, or None."""
    values = (user.get("attributes") or {}).get(ATTRIBUTE) or []
    if not isinstance(values, list):
        return None
    for value in values:
        text = str(value)
        if text.isdigit() and int(text) > 0:
            return int(text)
    return None


def is_automation_account(user: dict[str, Any]) -> bool:
    """Administrator classification, or a real Keycloak client service account.

    The username is not evidence. Broker login will accept an address or
    login the caller chose, including one that starts with ``service-account-``.
    """
    if user.get("serviceAccountClientId"):
        return True
    account_type = (user.get("attributes") or {}).get("account_type") or []
    return isinstance(account_type, list) and account_type[:1] == ["service"]


def portal_sign_in_allowed(user: dict[str, Any]) -> bool:
    """A portal code is issued only after the age action is gone.

    Automation accounts are not people. Everyone else needs a stored
    timestamp and must not still have the required action pending.
    """
    pending = ACTION in (user.get("requiredActions") or [])
    if is_automation_account(user):
        return not pending
    return confirmed_timestamp(user) is not None and not pending


def accept_age_confirmation(user: dict[str, Any], timestamp: int) -> dict[str, Any]:
    """Record acceptance the way Keycloak's required action does."""
    if timestamp <= 0:
        raise AgeConfirmationError("Age confirmation timestamp must be Unix seconds")
    attributes = {**(user.get("attributes") or {}), ATTRIBUTE: [str(timestamp)]}
    actions = [item for item in (user.get("requiredActions") or []) if item != ACTION]
    return {**user, "attributes": attributes, "requiredActions": actions}


def decline_age_confirmation(user: dict[str, Any]) -> dict[str, Any]:
    """Decline clears any timestamp and keeps sign-in blocked."""
    attributes = {**(user.get("attributes") or {})}
    attributes.pop(ATTRIBUTE, None)
    actions = list(user.get("requiredActions") or [])
    if ACTION not in actions:
        actions.append(ACTION)
    return {**user, "attributes": attributes, "requiredActions": actions}


def sync_required_action(user: dict[str, Any]) -> dict[str, Any] | None:
    """Return an updated user when required actions must change, else None."""
    actions = list(user.get("requiredActions") or [])
    if is_automation_account(user) or confirmed_timestamp(user) is not None:
        if ACTION not in actions:
            return None
        kept = [item for item in actions if item != ACTION]
        return {**user, "requiredActions": kept}
    if ACTION in actions:
        return None
    return {**user, "requiredActions": [*actions, ACTION]}


def profile_with_age_attribute(profile: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(profile)
    attributes = result.get("attributes")
    if not isinstance(attributes, list):
        raise AgeConfirmationError("User profile attributes are unavailable")
    result["attributes"] = [
        item for item in attributes if item.get("name") != ATTRIBUTE
    ] + [copy.deepcopy(PROFILE_ATTRIBUTE)]
    return result


def _action_needs_update(current: dict[str, Any]) -> bool:
    return not (
        current.get("enabled") is True
        and current.get("defaultAction") is True
        and current.get("providerId") == ACTION
        and current.get("alias") == ACTION
        and current.get("name") == ACTION_NAME
    )


def _ensure_required_action(admin: Any) -> None:
    path = f"/authentication/required-actions/{ACTION}"
    current = admin.get(path)
    if not isinstance(current, dict) or current.get("providerId") != ACTION:
        raise AgeConfirmationError("TERMS_AND_CONDITIONS required action is missing")
    if _action_needs_update(current):
        admin.put(path, {
            "alias": ACTION,
            "name": ACTION_NAME,
            "providerId": ACTION,
            "enabled": True,
            "defaultAction": True,
            "priority": current.get("priority", 20),
            "config": current.get("config") or {},
        })
    verified = admin.get(path)
    if not isinstance(verified, dict) or _action_needs_update(verified):
        raise AgeConfirmationError("Age confirmation required action was not applied")


def _ensure_localization(admin: Any) -> None:
    realm = admin.get("")
    if not isinstance(realm, dict):
        raise AgeConfirmationError("controlplane realm is missing")
    locales = list(realm.get("supportedLocales") or [])
    changed = False
    if realm.get("internationalizationEnabled") is not True:
        realm["internationalizationEnabled"] = True
        changed = True
    if "en" not in locales:
        locales.append("en")
        realm["supportedLocales"] = locales
        changed = True
    if not realm.get("defaultLocale"):
        realm["defaultLocale"] = "en"
        changed = True
    if changed:
        admin.put("", realm)
    for locale in realm.get("supportedLocales") or ["en"]:
        admin.post(f"/localization/{locale}", AGE_COPY)
        stored = admin.get(f"/localization/{locale}") or {}
        if not isinstance(stored, dict) or any(stored.get(key) != value for key, value in AGE_COPY.items()):
            raise AgeConfirmationError("Age confirmation text was not applied")


def _ensure_profile(admin: Any) -> None:
    current = admin.get("/users/profile")
    if not isinstance(current, dict):
        raise AgeConfirmationError("User profile is unavailable")
    updated = profile_with_age_attribute(current)
    if updated != current:
        admin.put("/users/profile", updated)
    verified = admin.get("/users/profile")
    attributes = (verified or {}).get("attributes") or []
    stored = next((item for item in attributes if item.get("name") == ATTRIBUTE), None)
    if stored is None or any(stored.get(key) != value for key, value in PROFILE_ATTRIBUTE.items()):
        raise AgeConfirmationError("Age confirmation attribute was not applied")


def _each_user_id(admin: Any):
    first = 0
    while True:
        batch = admin.get(f"/users?first={first}&max={PAGE_SIZE}") or []
        if not isinstance(batch, list):
            raise AgeConfirmationError("Keycloak user listing failed")
        for item in batch:
            if isinstance(item, dict) and item.get("id"):
                yield str(item["id"])
        if len(batch) < PAGE_SIZE:
            return
        first += PAGE_SIZE


def apply_user_age_gate(admin: Any, user: dict[str, Any]) -> bool:
    """Match the required action to the user's current account type.

    Returns true when a person who still needs to confirm was given the action.
    """
    updated = sync_required_action(user)
    if updated is None:
        return False
    user_id = str(user.get("id") or "")
    if not user_id:
        raise AgeConfirmationError("Age confirmation user id is missing")
    asked = ACTION in (updated.get("requiredActions") or []) and ACTION not in (user.get("requiredActions") or [])
    payload = {key: value for key, value in updated.items() if key not in _USER_PUT_OMIT}
    admin.put(f"/users/{user_id}", payload)
    stored = admin.get(f"/users/{user_id}") or {}
    if sorted(stored.get("requiredActions") or []) != sorted(updated.get("requiredActions") or []):
        raise AgeConfirmationError("Age confirmation required action was not stored on the user")
    return asked


def _mapper_matches(current: dict[str, Any], wanted: dict[str, Any]) -> bool:
    config = current.get("config") or {}
    return (
        current.get("name") == wanted["name"]
        and current.get("protocol") == wanted["protocol"]
        and current.get("protocolMapper") == wanted["protocolMapper"]
        and current.get("consentRequired") is False
        and all(config.get(key) == value for key, value in wanted["config"].items())
    )


def _ensure_mapper(admin: Any, client_id: str, wanted: dict[str, Any], *, replace: bool) -> None:
    clients = admin.get(f"/clients?clientId={client_id}") or []
    client = next(
        (item for item in clients if isinstance(item, dict) and item.get("clientId") == client_id),
        None,
    )
    if not isinstance(client, dict) or not client.get("id"):
        raise AgeConfirmationError(f"{client_id} client is missing")
    path = f"/clients/{client['id']}/protocol-mappers/models"
    existing = [item for item in (admin.get(path) or []) if isinstance(item, dict)]
    claim = wanted["config"]["claim.name"]
    matches = [
        item for item in existing
        if item.get("name") == wanted["name"] or (item.get("config") or {}).get("claim.name") == claim
    ]
    if len(matches) > 1:
        raise AgeConfirmationError(f"Duplicate {claim} token mappers on {client_id}")
    if not matches:
        admin.post(path, dict(wanted))
    elif replace and not _mapper_matches(matches[0], wanted):
        admin.put(f"{path}/{matches[0]['id']}", {**wanted, "id": matches[0]["id"]})
    if replace:
        verified = [item for item in (admin.get(path) or []) if isinstance(item, dict)]
        if not any(_mapper_matches(item, wanted) for item in verified):
            raise AgeConfirmationError(f"{claim} token claim was not applied on {client_id}")


def _ensure_interactive_claims(admin: Any) -> None:
    """Every interactive client must emit the timestamp. Machine clients do not."""
    for client_id in INTERACTIVE_CLIENTS:
        _ensure_mapper(admin, client_id, ACCOUNT_TYPE_CLAIM_MAPPER, replace=True)
        _ensure_mapper(admin, client_id, AGE_CLAIM_MAPPER, replace=True)


def _sync_existing_users(admin: Any) -> int:
    asked = 0
    for user_id in _each_user_id(admin):
        current = admin.get(f"/users/{user_id}")
        if not isinstance(current, dict):
            raise AgeConfirmationError("Keycloak user lookup failed")
        if apply_user_age_gate(admin, current):
            asked += 1
    return asked


def ensure_age_confirmation(admin: Any) -> None:
    """Ask existing people to confirm they are at least 18 on next sign-in.

    The 18+ copy is stored and checked before the required action is enabled.
    Otherwise a person can accept Keycloak's stock terms page, get the same
    timestamp, and pass the portal and API checks without seeing the age rule.
    """
    _ensure_localization(admin)
    _ensure_profile(admin)
    _ensure_interactive_claims(admin)
    _ensure_required_action(admin)
    asked = _sync_existing_users(admin)
    label = "account" if asked == 1 else "accounts"
    print(f"  age confirmation: {asked} existing {label} will be asked on next sign-in")


def main() -> int:
    """Apply the gate. Exit 2 blocks rollout. This is not the broker warning exit."""
    import os
    import sys
    import urllib.error

    from configure_idp_brokers import AdminClient, ConfigureError, admin_token

    from admin_endpoint import admin_endpoint

    base = admin_endpoint()
    username = os.environ.get("KC_BOOTSTRAP_ADMIN_USERNAME", "").strip()
    password = os.environ.get("KC_BOOTSTRAP_ADMIN_PASSWORD", "")
    if not username or not password:
        print("ERROR: age confirmation blocked rollout: bootstrap administrator credentials are required", file=sys.stderr)
        return 2
    try:
        ensure_age_confirmation(AdminClient(base, admin_token(base, username, password)))
    except (AgeConfirmationError, ConfigureError, urllib.error.URLError, OSError) as exc:
        print(f"ERROR: age confirmation blocked rollout: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
