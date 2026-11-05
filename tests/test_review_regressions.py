"""Administrative setup regressions use fake APIs, never a live realm."""
import copy
import importlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'keycloak'))
endpoint = importlib.import_module('admin_endpoint')
brokers = importlib.import_module('configure_idp_brokers')
accounts = importlib.import_module('account_types')
seed = importlib.import_module('seed_pan_test_identities')
idp = importlib.import_module('idp_enterprise')


@pytest.mark.parametrize('canonical,legacy,expected', [
    (' https://internal.example/ ', 'https://legacy.example', 'https://internal.example'),
    ('', ' https://legacy.example/ ', 'https://legacy.example'),
    (' ', '', 'http://127.0.0.1:8081'),
])
def test_all_admin_entrypoints_use_the_same_endpoint(monkeypatch, canonical, legacy, expected):
    monkeypatch.setenv('KEYCLOAK_INTERNAL_URL', canonical)
    monkeypatch.setenv('KEYCLOAK_URL', legacy)
    monkeypatch.setenv('KC_BOOTSTRAP_ADMIN_USERNAME', 'test-admin')
    monkeypatch.setenv('KC_BOOTSTRAP_ADMIN_PASSWORD', 'fake-only')
    seen = []
    monkeypatch.setattr(brokers, 'admin_token', lambda base, *args: seen.append(base) or 'fake-token')
    monkeypatch.setattr(brokers, 'apply_realm_updates', lambda admin: 0)
    monkeypatch.setattr(brokers, 'ensure_age_confirmation', lambda admin: None)
    monkeypatch.setattr(accounts, 'configure', lambda admin: None)
    monkeypatch.setattr(seed, 'require_passwords', lambda: {})
    monkeypatch.setattr(seed, 'seed', lambda **kwargs: seen.append(kwargs['base_url']) or {})
    assert brokers.main() == accounts.main([]) == seed.main([]) == 0
    assert seen == [expected] * 3


@pytest.mark.parametrize('existing', [False, True])
def test_amr_create_and_update_bound_lifetime_preserve_other_settings(existing):
    class Admin:
        config = {'id': 'config', 'config': {'unrelated': 'keep', 'default.reference.maxAge': '0'}}
        writes = []
        def get(self, path):
            if path == '': return {'browserFlow': 'browser'}
            if path.endswith('/executions'):
                return [{'id': 'execution', 'providerId': 'auth-username-password-form',
                         **({'authenticationConfig': 'config'} if existing else {})}]
            return copy.deepcopy(self.config)
        def put(self, path, body): self.writes.append(body)
        def post(self, path, body): self.writes.append(body)
    admin = Admin()
    accounts.ensure_references(admin)
    config = admin.writes[-1]['config']
    assert config['default.reference.value'] == 'pwd'
    assert config['default.reference.maxAge'] == '300'
    if existing: assert config['unrelated'] == 'keep'


@pytest.mark.parametrize('credentials,created,rotate,expected', [
    ([], False, False, 'password-set'),
    ([{'type': 'otp'}], False, False, 'password-set'),
    ([{'type': 'password'}], False, False, 'updated'),
    ([{'type': 'password'}], False, True, 'password-rotated'),
    ([], True, False, 'created'),
])
def test_seed_initializes_missing_passwords_without_rotating_existing(monkeypatch, credentials, created, rotate, expected):
    writes = []
    class Admin:
        def __init__(self, *args): pass
        def get(self, path):
            assert path.endswith('/credentials')
            return credentials
    monkeypatch.setattr(seed, 'AdminClient', Admin)
    monkeypatch.setattr(seed, 'admin_token', lambda *args: 'fake')
    for name in ['ensure_groups_mapper', 'ensure_group_realm_role', 'reconcile_realm_roles', 'reconcile_groups']:
        monkeypatch.setattr(seed, name, lambda *args: None)
    monkeypatch.setattr(seed, 'ensure_realm_role', lambda admin, name: {'id': name})
    monkeypatch.setattr(seed, 'ensure_group', lambda admin, name: {'id': name})
    monkeypatch.setattr(seed, 'upsert_user', lambda admin, ident: ({'id': ident.username}, created))
    monkeypatch.setattr(seed, 'set_password', lambda admin, uid, password: writes.append(uid))
    result = seed.seed(base_url='https://unused.example', bootstrap_username='fake',
                       bootstrap_password='fake', passwords={i.username: 'fake' for i in seed.IDENTITIES},
                       rotate_passwords=rotate)
    assert set(result.values()) == {expected}
    assert writes == ([] if expected == 'updated' else [i.username for i in seed.IDENTITIES])


WORK = '11111111-1111-4111-8111-111111111111'
OTHER = '22222222-2222-4222-8222-222222222222'


@pytest.mark.parametrize('tenant,allowlist,accepted', [
    ('common', WORK, {WORK, idp.MSA_TENANT_ID}),
    (None, '', {idp.MSA_TENANT_ID}),
    ('organizations', WORK, {WORK}),
    ('consumers', WORK, {idp.MSA_TENANT_ID}),
    (WORK, OTHER, {WORK}),
])
def test_microsoft_exact_issuer_policy(tenant, allowlist, accepted):
    config = idp.microsoft_endpoints(tenant, allowlist)
    issuers = set(config['issuer'].split(','))
    assert issuers == {f'https://login.microsoftonline.com/{value}/v2.0' for value in accepted}
    assert f'https://login.microsoftonline.com/{OTHER}/v2.0' not in issuers
    assert 'https://evil.example/' not in issuers
    assert config['validateSignature'] == config['useJwksUrl'] == 'true'


@pytest.mark.parametrize('tenant,allowlist', [('organizations', ''), ('common', 'bad'), ('example.com', ''), ('https://evil.example', '')])
def test_invalid_or_unbounded_work_tenant_policy_refused(tenant, allowlist):
    with pytest.raises(idp.IdpMapError): idp.microsoft_endpoints(tenant, allowlist)


def test_realm_import_default_matches_reconciler_personal_issuer():
    realm = json.loads((ROOT / 'keycloak/import/controlplane-realm.json').read_text())
    config = next(p for p in realm['identityProviders'] if p['alias'] == 'microsoft')['config']
    assert config['issuer'] == '${KC_IDP_MICROSOFT_ISSUERS:' + idp.microsoft_endpoints(None)['issuer'] + '}'
    assert config['validateSignature'] == config['useJwksUrl'] == 'true'


def test_broker_reconciliation_replaces_invalid_common_issuer(monkeypatch):
    monkeypatch.setenv('KC_IDP_MICROSOFT_ALLOWED_TENANT_IDS', WORK)
    class Admin:
        body = None
        def get(self, path): return {'config': {'issuer': 'https://login.microsoftonline.com/common/v2.0', 'unrelated': 'keep'}}
        def put(self, path, body): self.body = body
    admin = Admin()
    brokers.update_broker_app(admin, 'microsoft', 'fake-id', 'fake-secret', 'common')
    assert admin.body['config']['issuer'] == idp.microsoft_endpoints('common', WORK)['issuer']
    assert admin.body['config']['unrelated'] == 'keep'
