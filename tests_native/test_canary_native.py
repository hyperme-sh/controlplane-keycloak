"""Disposable CI broker checks. No deployed clients, users or providers."""
import base64
import copy
import hashlib
import runpy
import time
import uuid
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlsplit

import jwt
import pytest

from test_account_closure_setup_native import provider  # Existing owned CI setup/cleanup.

ROOT = Path(__file__).resolve().parents[1]
C = runpy.run_path(str(ROOT / 'keycloak/canary_contract.py'))
# Source attribution is supplied by CI deployment metadata in production. This
# single-container fixture does not claim to run two deployed source revisions.
BASELINE, CANDIDATE = 'a' * 40, 'b' * 40


class LoginForm(HTMLParser):
    def __init__(self, text):
        super().__init__(); self.action = None; self.feed(text)

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == 'form' and values.get('id') == 'kc-form-login':
            self.action = values['action']


def login(transport, issuer, client, username, password):
    verifier = uuid.uuid4().hex + uuid.uuid4().hex
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    state = uuid.uuid4().hex
    callback = 'https://canary.example.invalid/' + client
    page = transport.get(issuer + '/protocol/openid-connect/auth', params={
        'client_id': client, 'redirect_uri': callback, 'response_type': 'code',
        'scope': 'openid', 'state': state, 'code_challenge': challenge,
        'code_challenge_method': 'S256', 'prompt': 'login'})
    page.raise_for_status()
    action = LoginForm(page.text).action
    assert action
    action = urljoin(str(page.url), action)
    assert urlsplit(action).netloc == urlsplit(issuer).netloc
    response = transport.post(action, data={'username': username, 'password': password, 'credentialId': ''})
    assert response.status_code == 302
    location = response.headers['location']
    assert location.split('?')[0] == callback
    query = parse_qs(urlsplit(location).query)
    assert query['state'] == [state]
    tokens = transport.post(issuer + '/protocol/openid-connect/token', data={
        'grant_type': 'authorization_code', 'client_id': client, 'redirect_uri': callback,
        'code': query['code'][0], 'code_verifier': verifier})
    tokens.raise_for_status()
    return tokens.json()


def claims(transport, issuer, token):
    keys = transport.get(issuer + '/protocol/openid-connect/certs').raise_for_status().json()
    kid = jwt.get_unverified_header(token)['kid']
    key = jwt.PyJWK.from_dict(next(k for k in keys['keys'] if k['kid'] == kid and k.get('use') == 'sig' and k.get('alg') == 'RS256'))
    # Keycloak access-token audience may be account; client binding uses azp.
    return jwt.decode(token, key.key, algorithms=['RS256'], issuer=issuer,
                      options={'verify_aud': False, 'require': ['exp', 'iat', 'sub', 'iss', 'sid', 'azp']})


def observe(transport, issuer, revision):
    return {'revision': revision, 'observed_at': time.time(),
            'discovery': transport.get(issuer + '/.well-known/openid-configuration').raise_for_status().json(),
            'jwks': transport.get(issuer + '/protocol/openid-connect/certs').raise_for_status().json()}


def test_declared_client_login_refresh_and_realm_patch_rollback(provider):
    admin, transport, base, _ = provider
    name = 'canary-' + uuid.uuid4().hex
    issuer = base + '/realms/' + name
    clients = ['controlplane-frontend', 's3rch-web']
    password = uuid.uuid4().hex + uuid.uuid4().hex
    username = 'canary-' + uuid.uuid4().hex
    # Use the actual production renderer's scope/grant policy. Only isolated
    # fixture bindings (realm, callbacks, enablement and user) differ.
    render = runpy.run_path(str(ROOT / 'keycloak/production_realm.py'))['render']
    baseline = render({'fyberlabs-web': 'https://fyberlabs.com/auth/callback',
        'controlplane-frontend': 'https://portal.hyperme.sh/api/auth/callback/keycloak',
        's3rch-web': 'https://s3r.ch/api/identity/oauth/callback',
        'windage-web': 'https://tennesseewindage.com/auth/callback'})
    baseline['realm'] = name
    for client in baseline['clients']:
        if client['clientId'] in clients:
            client['enabled'] = True
            client['redirectUris'] = ['https://canary.example.invalid/' + client['clientId']]
    baseline['users'] = [{'username': username, 'enabled': True, 'emailVerified': True,
        'email': username + '@example.invalid', 'firstName': 'Canary', 'lastName': 'Fixture',
        'credentials': [{'type': 'password', 'value': password, 'temporary': False}]}]
    candidate = copy.deepcopy(baseline); candidate['displayName'] = 'Candidate patch'
    assert C['compatible_realms'](baseline, candidate, clients)
    headers = {'Authorization': 'Bearer ' + admin.token}
    realm_url = base + '/admin/realms/' + name
    transport.post(base + '/admin/realms', headers=headers, json=baseline).raise_for_status()
    try:
        initial = observe(transport, issuer, BASELINE)
        sessions = {c: login(transport, issuer, c, username, password) for c in clients}
        original = {c: claims(transport, issuer, t['access_token']) for c, t in sessions.items()}
        for display, revision in [('Candidate patch', CANDIDATE), ('', BASELINE)]:
            transport.put(realm_url, headers=headers, json={'displayName': display}).raise_for_status()
            current = observe(transport, issuer, revision)
            C['continuity'](initial, current, issuer=issuer, baseline_revision=BASELINE,
                            candidate_revision=revision, now=time.time())
            for client in clients:
                refreshed = transport.post(issuer + '/protocol/openid-connect/token', data={
                    'grant_type': 'refresh_token', 'client_id': client,
                    'refresh_token': sessions[client]['refresh_token']}).raise_for_status().json()
                after = claims(transport, issuer, refreshed['access_token'])
                C['session_continuity'](original[client], after, issuer=issuer, client=client,
                                        subject=original[client]['sub'], now=time.time())
                sessions[client] = refreshed
                # Current-client code/PKCE login still works after each direction.
                assert claims(transport, issuer, login(transport, issuer, client, username, password)['access_token'])['azp'] == client
        # Fenced process handoff on the same private durable store. This is a
        # same-engine restart qualification, not a database engine upgrade.
        container = admin.canary_container
        container.stop(timeout=30)
        container.reload()
        assert container.status == 'exited'
        store = 'isolated-h2:' + container.id
        state = {'store': store, 'schema': 'same-engine', 'signing_owner': store,
                 'session_owner': store, 'observed_at': time.time(),
                 'fenced': {'baseline': True}, 'writers': [], 'schema_compatible': True}
        assert C['handoff'](state, source='baseline', destination='candidate',
                            store=store, schema='same-engine', now=time.time()) == 'start'
        container.start()
        deadline = time.monotonic() + 180
        while True:
            try:
                import httpx
                response = transport.get(issuer + '/.well-known/openid-configuration')
                if response.status_code == 200:
                    break
            except httpx.TransportError:
                pass
            assert time.monotonic() < deadline, 'Disposable restart did not become ready'
            time.sleep(0.5)
        admin.token = admin.canary_reauthenticate()
        headers = {'Authorization': 'Bearer ' + admin.token}
        current = observe(transport, issuer, CANDIDATE)
        C['continuity'](initial, current, issuer=issuer, baseline_revision=BASELINE,
                        candidate_revision=CANDIDATE, now=time.time(), max_age=300)
        for client in clients:
            tokens = transport.post(issuer + '/protocol/openid-connect/token', data={
                'grant_type': 'refresh_token', 'client_id': client,
                'refresh_token': sessions[client]['refresh_token']}).raise_for_status().json()
            C['session_continuity'](original[client], claims(transport, issuer, tokens['access_token']),
                                    issuer=issuer, client=client, subject=original[client]['sub'], now=time.time())
            sessions[client] = tokens
        # Wrong-client refresh must not transfer session ownership.
        denied = transport.post(issuer + '/protocol/openid-connect/token', data={
            'grant_type': 'refresh_token', 'client_id': clients[1],
            'refresh_token': sessions[clients[0]]['refresh_token']})
        assert denied.status_code in (400, 401)
        for field, value in [('revokeRefreshToken', True), ('browserFlow', 'other')]:
            with pytest.raises(C['Refused']):
                C['compatible_realms'](baseline, candidate | {field: value}, clients)
    finally:
        transport.delete(realm_url, headers=headers).raise_for_status()
