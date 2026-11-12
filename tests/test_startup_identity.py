import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest
from urllib.parse import unquote

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'keycloak'))
from startup_identity import reconcile,StartupConflict
from startup_contract import fingerprint


class Admin:
    def __init__(self,c):
        self.users={};self.links={};self.roles={};self.profile={'attributes':[]};self.fail=False
        self.realm=c['binding']['keycloak_admin']['realm'];self.alias=c['binding']['entra']['broker']
        self.provider={'alias':self.alias,'providerId':'startup-entra','enabled':True,'config':{'issuer':'https://login.microsoftonline.com/'+c['binding']['entra']['tenant_id']+'/v2.0','clientId':c['binding']['entra']['audience'],'clientSecret':'synthetic-only','validateSignature':'true','useJwksUrl':'true'}}
    def get_optional(self,path):
        if path.startswith('/identity-provider/instances/'):return copy.deepcopy(self.provider)
        return copy.deepcopy(self.users.get(path.split('/')[-1]))
    def get(self,path):
        if path.startswith('/users?email='):return [copy.deepcopy(u) for u in self.users.values() if u['email']==unquote(path.split('=',1)[1].split('&')[0])]
        if path=='':return {'realm':self.realm}
        if path=='/identity-provider/instances/'+self.alias:return copy.deepcopy(self.provider)
        if path=='/clients?clientId=realm-management':return [{'id':'management'}]
        if path=='/clients/management/roles/realm-admin':return {'id':'realm-admin','name':'realm-admin'}
        if path=='/users/profile':return copy.deepcopy(self.profile)
        if path.endswith('/federated-identity'):return copy.deepcopy(self.links.get(path.split('/')[2],[]))
        if '/role-mappings/' in path:return copy.deepcopy(self.roles.get(path.split('/')[2],[]))
        raise AssertionError(path)
    def post(self,path,body):
        if path=='/identity-provider/instances':self.provider=copy.deepcopy(body);return
        if path=='/partialImport':
            assert body['ifResourceExists']=='FAIL'
            body=body['users'][0]
            if body['id'] in self.users:raise ValueError('duplicate')
            self.users[body['id']]=copy.deepcopy(body);return
        if path.endswith('/federated-identity/'+self.alias):
            self.links[path.split('/')[2]]=[copy.deepcopy(body)];return
        if '/role-mappings/' in path:
            if self.fail:self.fail=False;raise RuntimeError('interrupted')
            self.roles[path.split('/')[2]]=copy.deepcopy(body);return
        raise AssertionError(path)
    def put(self,path,body):
        if path=='/users/profile':self.profile=copy.deepcopy(body)
        elif path=='/identity-provider/instances/'+self.alias:self.provider=copy.deepcopy(body)
        elif path.startswith('/users/'):self.users[path.split('/')[-1]].update(copy.deepcopy(body))
        else:raise AssertionError(path)


class StartupTests(unittest.TestCase):
    def setUp(self):
        self.config=json.loads((ROOT/'tests/fixtures/startup-identity.json').read_text());stamp=fingerprint(self.config)
        self.person={'person_id':'00000000-0000-4000-8000-000000000110','broker_subject':'00000000-0000-4000-8000-000000000110',
            'tenant_id':self.config['owner']['tenant_id'],'mapping_sha256':stamp,'status':'bound'}
        self.acl={'person_id':self.person['person_id'],'mapping_sha256':stamp,'status':'reconciled'}
        self.admin=Admin(self.config)
    def test_first_run_and_retry_keep_one_identity_and_separate_admin(self):
        first=reconcile(self.admin,self.config,self.person,self.acl)
        before=copy.deepcopy(self.admin.__dict__)
        self.assertEqual(reconcile(self.admin,self.config,self.person,self.acl),first)
        self.assertEqual(before,self.admin.__dict__)
        self.assertEqual(len(self.admin.users),1)
        self.assertEqual(first['application_permissions'],[])
        self.assertTrue(first['keycloak_admin'])
    def test_partial_failure_resumes_without_duplicate_or_credential_creation(self):
        self.admin.fail=True
        with self.assertRaises(RuntimeError):reconcile(self.admin,self.config,self.person,self.acl)
        reconcile(self.admin,self.config,self.person,self.acl)
        self.assertEqual(len(self.admin.users),1)
        self.assertNotIn('credentials',next(iter(self.admin.users.values())))
    def test_same_email_refuses_before_mutation(self):
        self.admin.users['attacker']={'id':'attacker','email':self.config['owner']['profile']['email']}
        before=copy.deepcopy(self.admin.__dict__)
        with self.assertRaises(StartupConflict):reconcile(self.admin,self.config,self.person,self.acl)
        self.assertEqual(before,self.admin.__dict__)
    def test_changed_mapping_or_untrusted_broker_cannot_grant(self):
        for change in [{'issuer':'https://wrong.invalid'},{'validateSignature':'false'},{'startupMapping':'other'}]:
            admin=Admin(self.config);admin.provider['config'].update(change)
            with self.assertRaises(StartupConflict):reconcile(admin,self.config,self.person,self.acl)
            self.assertFalse(admin.users)
    def test_prior_owner_required(self):
        with self.assertRaises(StartupConflict):reconcile(self.admin,self.config,self.person,dict(self.acl,status='pending'))
        self.assertFalse(self.admin.users)
    def test_shared_contract_copy(self):
        record=json.loads((ROOT/'keycloak/startup_contract_source.json').read_text())
        self.assertEqual(record['sha256'],hashlib.sha256((ROOT/'keycloak/startup_contract.py').read_bytes()).hexdigest())


class ExplicitBoundaryTests(unittest.TestCase):
    setUp=StartupTests.setUp
    def test_wrong_provider_type_refuses_before_writes(self):
        self.admin.provider['providerId']='oidc'
        before=copy.deepcopy(self.admin.__dict__)
        with self.assertRaises(StartupConflict):reconcile(self.admin,self.config,self.person,self.acl)
        self.assertEqual(before,self.admin.__dict__)

    def test_keycloak_admin_false_does_not_create_a_role(self):
        from startup_contract import binding_fingerprint
        self.config['binding']['keycloak_admin']['enabled']=False
        self.config['binding_sha256']=binding_fingerprint(self.config['binding'])
        self.person['mapping_sha256']=self.acl['mapping_sha256']=fingerprint(self.config)
        result=reconcile(self.admin,self.config,self.person,self.acl)
        self.assertFalse(result['keycloak_admin']);self.assertFalse(self.admin.roles)

    def test_new_dedicated_alias_requires_explicit_application_secret(self):
        self.admin.provider=None
        with self.assertRaises(StartupConflict):reconcile(self.admin,self.config,self.person,self.acl)
        self.assertFalse(self.admin.users)
        result=reconcile(self.admin,self.config,self.person,self.acl,entra_secret='synthetic-configured-secret')
        self.assertEqual(result['status'],'reconciled')
        self.assertEqual(self.admin.provider['providerId'],'startup-entra')

    def test_completed_role_revocation_is_not_implicitly_restored(self):
        reconcile(self.admin,self.config,self.person,self.acl)
        self.admin.roles={}
        before=copy.deepcopy(self.admin.__dict__)
        with self.assertRaises(StartupConflict):reconcile(self.admin,self.config,self.person,self.acl)
        self.assertEqual(before,self.admin.__dict__)
