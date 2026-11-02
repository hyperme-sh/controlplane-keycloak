"""Self-registration for the test plane only.

The realm import keeps ``registrationAllowed`` false, so a first start does
not offer Register. ``refresh-test.sh`` sets ``KC_TEST_REGISTRATION=1`` and
the broker configure step applies these fields to the live realm. The
password grant stays off. Email verification stays off because this plane
has no mailer.
"""

from __future__ import annotations

from typing import Any


def apply_test_registration(realm: dict[str, Any]) -> dict[str, Any]:
    updated = dict(realm)
    updated["registrationAllowed"] = True
    updated["registrationEmailAsUsername"] = True
    updated["verifyEmail"] = False
    return updated
