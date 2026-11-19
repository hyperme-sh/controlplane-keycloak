"""Fail-closed broker patch contract; deployment and credentials belong to Infra.

Inputs must come from an authenticated owner adapter, never from token claims or
an untrusted candidate's self-reported deployment state. This module makes no
network calls and cannot start a writer or activate a binding.
"""
import hashlib
import json
import math
import re
from urllib.parse import urlsplit


class Refused(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Refused(reason)


def stamp(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def public_keys(jwks):
    require(isinstance(jwks, dict) and isinstance(jwks.get("keys"), list), "missing JWKS")
    result = {}
    for key in jwks["keys"]:
        require(isinstance(key, dict), "invalid key")
        require(not set(key).intersection({"d", "p", "q", "dp", "dq", "qi", "k"}), "private key material")
        if key.get("use") == "enc":
            continue
        require(key.get("kty") == "RSA" and key.get("alg") == "RS256"
                and key.get("use") == "sig", "unsupported signing key")
        kid = key.get("kid")
        require(isinstance(kid, str) and kid and kid not in result, "ambiguous signing key")
        require(all(isinstance(key.get(k), str) and re.fullmatch(r"[A-Za-z0-9_-]+", key[k]) for k in ("n", "e")), "invalid public key")
        result[kid] = stamp({k: key[k] for k in ("kty", "n", "e")})
    require(bool(result), "no signing keys")
    return result


def discovery(document, issuer):
    url = urlsplit(issuer)
    require(url.scheme == "https" and url.hostname and not url.username and not url.password
            and not url.query and not url.fragment and issuer.rstrip("/") == issuer, "invalid issuer")
    require(document.get("issuer") == issuer, "issuer changed")
    root = issuer + "/protocol/openid-connect"
    for key, suffix in {"authorization_endpoint": "/auth", "token_endpoint": "/token", "jwks_uri": "/certs"}.items():
        require(document.get(key) == root + suffix, "endpoint changed")
    for key, needed in {"response_types_supported": {"code"},
                        "grant_types_supported": {"authorization_code", "refresh_token"},
                        "code_challenge_methods_supported": {"S256"}}.items():
        require(isinstance(document.get(key), list) and needed.issubset(document[key]), "client protocol unavailable")


def client_contract(client):
    """Only declared public code/PKCE clients participate in this canary."""
    require(client.get("enabled") is True and client.get("publicClient") is True
            and client.get("standardFlowEnabled") is True, "client unavailable")
    require(all(client.get(k) is False for k in ("implicitFlowEnabled", "directAccessGrantsEnabled", "serviceAccountsEnabled", "fullScopeAllowed")), "client authority widened")
    require(client.get("attributes", {}).get("pkce.code.challenge.method") == "S256", "PKCE required")
    redirects = client.get("redirectUris")
    require(isinstance(redirects, list) and bool(redirects), "callback unavailable")
    for redirect in redirects:
        url = urlsplit(redirect)
        require(url.scheme == "https" and url.hostname and not url.username and not url.password
                and not url.fragment and "*" not in redirect, "callback not bounded")
    return {k: v for k, v in client.items() if k not in {"id", "name", "description"}}


def compatible_realms(baseline, candidate, clients):
    """Conservative realm declaration compatibility, not engine DB downgrade."""
    require(bool(clients) and len(set(clients)) == len(clients), "declared clients required")
    # Unknown realm fields are not silently classified as backward-compatible.
    ignored = {"clients", "displayName", "displayNameHtml"}
    old_policy = {k: v for k, v in baseline.items() if k not in ignored}
    new_policy = {k: v for k, v in candidate.items() if k not in ignored}
    require(old_policy == new_policy, "realm compatibility changed")
    contracts = {}
    for name in clients:
        selected = []
        for realm in (baseline, candidate):
            matches = [c for c in realm.get("clients", []) if c.get("clientId") == name]
            require(len(matches) == 1, "declared client missing or ambiguous")
            selected.append(client_contract(matches[0]))
        require(selected[0] == selected[1], "client contract changed")
        contracts[name] = selected[0]
    return stamp({"protected": old_policy, "clients": contracts})


def observed(snapshot, *, issuer, revision, now, max_age=60):
    require(isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{40}", revision), "source revision required")
    require(snapshot.get("revision") == revision, "wrong serving revision")
    require(type(max_age) in (int, float) and 0 < max_age <= 300, "invalid observation window")
    sampled = snapshot.get("observed_at")
    require(type(sampled) in (int, float) and math.isfinite(sampled)
            and 0 <= now - sampled <= max_age, "stale observation")
    discovery(snapshot["discovery"], issuer)
    return public_keys(snapshot["jwks"])


def continuity(baseline, candidate, *, issuer, baseline_revision, candidate_revision, now, max_age=60):
    previous = observed(baseline, issuer=issuer, revision=baseline_revision, now=now, max_age=max_age)
    current = observed(candidate, issuer=issuer, revision=candidate_revision, now=now, max_age=max_age)
    require(all(current.get(k) == v for k, v in previous.items()), "signing key continuity lost")
    return {"issuer": issuer, "baseline_revision": baseline_revision,
            "candidate_revision": candidate_revision, "signing_keys_sha256": stamp(current)}


def session_continuity(before, after, *, issuer, client, subject, now):
    """Claims must already have signature, issuer and expiry verified by consumer."""
    for claims in (before, after):
        require(claims.get("iss") == issuer and claims.get("azp") == client
                and claims.get("sub") == subject, "session authority changed")
        require(type(claims.get("exp")) in (int, float) and claims["exp"] > now, "session expired")
        require(isinstance(claims.get("sid"), str) and bool(claims["sid"]), "session unavailable")
    require(before["sid"] == after["sid"], "session ownership lost")
    return {"client": client, "session_continuity": True}


def handoff(state, *, source, destination, store, schema, now, max_age=60):
    """Authorize a start only after the owner confirms the previous writer fenced.

The caller must hold Infra's durable unit/resource claim and write intent before
executing. Recovery uses the same absolute desired-state check with roles reversed.
"""
    require(source != destination and all(isinstance(v, str) and v for v in (source, destination, store, schema)), "invalid handoff binding")
    require(state.get("store") == store and state.get("schema") == schema, "durable ownership changed")
    require(state.get("signing_owner") == store and state.get("session_owner") == store, "split durable ownership")
    sampled = state.get("observed_at")
    require(type(sampled) in (int, float) and math.isfinite(sampled)
            and 0 <= now - sampled <= max_age, "stale fencing observation")
    require(state.get("fenced", {}).get(source) is True, "previous writer not fenced")
    writers = state.get("writers")
    require(writers in ([], [destination]), "unexpected active writer")
    require(state.get("schema_compatible") is True, "schema rollback unavailable")
    return "verify" if writers else "start"
