"""Offline owner-adapter doubles; no deployed issuer or token verification."""
import copy
import runpy
from pathlib import Path

import pytest

C = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'keycloak/canary_contract.py'))
ISSUER = 'https://auth.example.invalid/realms/isolated'
A, B = 'a' * 40, 'b' * 40


def snapshot(revision):
    root = ISSUER + '/protocol/openid-connect'
    return {'revision': revision, 'observed_at': 100,
            'discovery': {'issuer': ISSUER, 'authorization_endpoint': root + '/auth',
                          'token_endpoint': root + '/token', 'jwks_uri': root + '/certs',
                          'response_types_supported': ['code'],
                          'grant_types_supported': ['authorization_code', 'refresh_token'],
                          'code_challenge_methods_supported': ['S256']},
            'jwks': {'keys': [{'kid': 'fixture', 'kty': 'RSA', 'alg': 'RS256', 'use': 'sig', 'n': 'AQAB', 'e': 'AQAB'}]}}


def check(a, b):
    return C['continuity'](a, b, issuer=ISSUER, baseline_revision=A, candidate_revision=B, now=110)


def test_exact_revision_and_key_continuity():
    assert check(snapshot(A), snapshot(B))['candidate_revision'] == B


@pytest.mark.parametrize('fault', ['issuer', 'endpoint', 'key', 'missing', 'duplicate', 'private', 'stale', 'future', 'revision', 'pkce'])
def test_refuses_unattributed_or_incompatible_observation(fault):
    value = snapshot(B)
    if fault == 'issuer': value['discovery']['issuer'] += '/other'
    if fault == 'endpoint': value['discovery']['token_endpoint'] = 'https://foreign.invalid/token'
    if fault == 'key': value['jwks']['keys'][0]['n'] = 'changed'
    if fault == 'missing': value['jwks']['keys'] = []
    if fault == 'duplicate': value['jwks']['keys'] *= 2
    if fault == 'private': value['jwks']['keys'][0]['d'] = 'private'
    if fault == 'stale': value['observed_at'] = 0
    if fault == 'future': value['observed_at'] = 111
    if fault == 'revision': value['revision'] = A
    if fault == 'pkce': value['discovery']['code_challenge_methods_supported'] = ['plain']
    with pytest.raises(C['Refused']): check(snapshot(A), value)


def realm():
    return {'realm': 'isolated', 'clients': [{'clientId': 'declared', 'enabled': True,
        'publicClient': True, 'standardFlowEnabled': True, 'implicitFlowEnabled': False,
        'directAccessGrantsEnabled': False, 'serviceAccountsEnabled': False,
        'fullScopeAllowed': False, 'attributes': {'pkce.code.challenge.method': 'S256'},
        'redirectUris': ['https://client.example.invalid/callback']}]}


def test_realm_allows_metadata_only_patch_and_refuses_authority_change():
    before = realm(); after = copy.deepcopy(before); after['displayName'] = 'Candidate'
    assert C['compatible_realms'](before, after, ['declared'])
    after['clients'][0]['directAccessGrantsEnabled'] = True
    with pytest.raises(C['Refused']): C['compatible_realms'](before, after, ['declared'])


@pytest.mark.parametrize('field,value', [('revokeRefreshToken', True), ('roles', {'realm': []}), ('browserFlow', 'new-flow')])
def test_refuses_session_or_schema_policy_change(field, value):
    before = realm(); after = copy.deepcopy(before); after[field] = value
    with pytest.raises(C['Refused']): C['compatible_realms'](before, after, ['declared'])


def test_verified_claims_must_retain_session_and_subject():
    claims = {'iss': ISSUER, 'azp': 'declared', 'sub': 'subject', 'sid': 'session', 'exp': 200}
    args = dict(issuer=ISSUER, client='declared', subject='subject', now=110)
    assert C['session_continuity'](claims, claims | {'exp': 250}, **args)
    for field in ['sid', 'sub', 'azp', 'iss']:
        with pytest.raises(C['Refused']): C['session_continuity'](claims, claims | {field: 'other'}, **args)


def state():
    return {'store': 'owner-db', 'schema': 'approved-schema', 'signing_owner': 'owner-db',
            'session_owner': 'owner-db', 'observed_at': 100, 'fenced': {'baseline': True},
            'writers': [], 'schema_compatible': True}


def handoff(s, **overrides):
    return C['handoff'](s, **(dict(source='baseline', destination='candidate', store='owner-db', schema='approved-schema', now=110) | overrides))


def test_interrupted_start_is_absolute_and_recovery_requires_reverse_fence():
    s = state(); assert handoff(s) == 'start'
    s['writers'] = ['candidate']; assert handoff(s) == 'verify'
    with pytest.raises(C['Refused']): handoff(s, source='candidate', destination='baseline')
    s['writers'] = []; s['fenced']['candidate'] = True
    assert handoff(s, source='candidate', destination='baseline') == 'start'


@pytest.mark.parametrize('field,value', [('writers', ['baseline']), ('writers', ['baseline', 'candidate']),
    ('fenced', {}), ('store', 'foreign'), ('signing_owner', 'foreign'), ('session_owner', 'foreign'),
    ('schema', 'unknown'), ('schema_compatible', False), ('observed_at', 0)])
def test_fencing_refuses_missing_or_unsafe_owner_state(field, value):
    with pytest.raises(C['Refused']): handoff(state() | {field: value})
