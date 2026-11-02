"""Consistent endpoint selection for administrative tools."""
import os


def admin_endpoint() -> str:
    """Prefer the canonical variable; retain the legacy deployment alias."""
    return (os.environ.get("KEYCLOAK_INTERNAL_URL", "").strip()
            or os.environ.get("KEYCLOAK_URL", "").strip()
            or "http://127.0.0.1:8081").rstrip("/")
