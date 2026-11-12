"""Reconcile the configured application's broker link and separate realm grant."""
import json
from urllib.parse import quote, urlsplit
from startup_contract import validate, fingerprint


class StartupConflict(ValueError):pass


def reconcile(admin,config,person,acl,*,entra_secret=None):
    config=validate(config)
    entra=config['binding']['entra'];alias=entra['broker'];provider_path='/identity-provider/instances/'+quote(alias,safe='')
    realm=config['binding']['keycloak_admin']['realm']
    if admin.get('').get('realm') != realm:raise StartupConflict('Configured Keycloak realm differs')
    stamp=fingerprint(config)
    if (person.get('status')!='bound' or person.get('mapping_sha256')!=stamp or
        person.get('tenant_id')!=config['owner']['tenant_id'] or not person.get('broker_subject') or
        acl.get('status')!='reconciled' or acl.get('mapping_sha256')!=stamp or acl.get('person_id')!=person.get('person_id')):
        raise StartupConflict('Bound User/Auth and reconciled ACL mapping required')
    subject=person['broker_subject'];encoded=quote(subject,safe='')
    username='startup-'+person['person_id']
    current=admin.get_optional('/users/'+encoded)
    same_email=admin.get('/users?email='+quote(config['owner']['profile']['email'],safe='')+'&exact=true')
    if any(u['id']!=subject for u in same_email):raise StartupConflict('Account label conflicts with another Keycloak record')
    attributes={'startup_mapping':[stamp],'startup_person_id':[person['person_id']],'account_type':['human']}
    if current:
        if (not current.get('enabled') or current.get('email','').lower()!=config['owner']['profile']['email'].lower() or
            any(current.get('attributes',{}).get(k)!=v for k,v in attributes.items())):
            raise StartupConflict('Keycloak user '+subject+' has a conflicting configured binding')
    provider=admin.get_optional(provider_path)
    create_provider=provider is None
    if create_provider:
        if not entra_secret:raise StartupConflict('Configured Entra application secret required for new broker')
        issuer=entra['issuer'];base='https://login.microsoftonline.com/'+entra['tenant_id']
        provider={'alias':alias,'providerId':'startup-entra','enabled':True,'trustEmail':False,
            'storeToken':False,'config':{'issuer':issuer,'clientId':entra['audience'],'clientSecret':entra_secret,
            'validateSignature':'true','useJwksUrl':'true','syncMode':'IMPORT','defaultScope':'openid profile email',
            'disableUserInfo':'true','authorizationUrl':base+'/oauth2/v2.0/authorize',
            'tokenUrl':base+'/oauth2/v2.0/token','jwksUrl':base+'/discovery/v2.0/keys'}}
    broker=dict(provider.get('config') or {})
    if provider.get('providerId') != 'startup-entra' or not provider.get('enabled'):
        raise StartupConflict('Configured startup-entra broker must be installed before reconciliation')
    if broker.get('startupMapping') not in (None,stamp):raise StartupConflict('Shared Microsoft broker mapping conflicts')
    expected_issuer=entra['issuer']
    if expected_issuer not in broker.get('issuer','').split(','):
        raise StartupConflict('Shared Microsoft broker must already trust the configured tenant issuer')
    if broker.get('validateSignature')!='true' or broker.get('useJwksUrl')!='true':
        raise StartupConflict('Verified Microsoft signatures required')
    if broker.get('clientId') != entra['audience'] or not broker.get('clientSecret') or broker['clientSecret'].startswith('${'):
        raise StartupConflict('Shared Microsoft application configuration required')
    links=admin.get('/users/'+encoded+'/federated-identity') if current else []
    microsoft=[link for link in links if link.get('identityProvider')==alias]
    if len(microsoft)>1:raise StartupConflict('Ambiguous Microsoft broker link')
    upstream=entra['subject']
    if microsoft and microsoft[0]['userId'] != upstream:raise StartupConflict('Configured upstream subject conflicts')
    if broker.get('startupSubject') not in (None,upstream):raise StartupConflict('Stored Microsoft subject conflicts')
    clients=admin.get('/clients?clientId=realm-management')
    if len(clients)!=1:raise StartupConflict('Realm management client unavailable')
    management=clients[0]['id'];role=admin.get('/clients/'+quote(management,safe='')+'/roles/realm-admin')
    role_path='/users/'+encoded+'/role-mappings/clients/'+quote(management,safe='')
    roles=admin.get(role_path) if current else []
    enabled=config['binding']['keycloak_admin']['enabled']
    present=any(r['id']==role['id'] for r in roles)
    if present and not enabled:raise StartupConflict('Existing Keycloak admin grant conflicts with configuration')
    completed=current and current.get('attributes',{}).get('startup_complete')==['true']
    if completed and (not microsoft or broker.get('startupMapping')!=stamp or present!=enabled):
        raise StartupConflict('Completed startup mapping changed; refusing implicit restoration')
    # Protect mapping attributes before writing them. Never loosen existing rules.
    profile=admin.get('/users/profile');declared=list(profile.get('attributes',[]))
    for name in (*attributes,'startup_complete'):
        matches=[a for a in declared if a['name']==name]
        if matches and matches[0].get('permissions',{}).get('edit')!=['admin']:
            raise StartupConflict('Protected profile attribute conflicts: '+name)
        if not matches:declared.append({'name':name,'permissions':{'view':['admin'],'edit':['admin']},'multivalued':False})
    if create_provider:admin.post('/identity-provider/instances',provider)
    if declared!=profile.get('attributes',[]):admin.put('/users/profile',{**profile,'attributes':declared})
    if current is None:
        try:
            admin.post('/partialImport',{'ifResourceExists':'FAIL','users':[{'id':subject,'username':username,'email':config['owner']['profile']['email'],'emailVerified':False,
                'enabled':True,'firstName':'Configured','lastName':'Operator','attributes':attributes}]})
        except Exception:
            # A concurrent identical create may win. Only its exact mapping is reusable.
            found=admin.get_optional('/users/'+encoded)
            if not found or any(found.get('attributes',{}).get(k)!=v for k,v in attributes.items()):raise
        current=admin.get_optional('/users/'+encoded)
        if not current or current.get('attributes',{}).get('startup_mapping')!=[stamp]:
            raise StartupConflict('Created Keycloak identity differs from selected subject')
    if not microsoft:
        try:admin.post('/users/'+encoded+'/federated-identity/'+quote(alias,safe=''),{'identityProvider':alias,'userId':upstream,'userName':username})
        except Exception:
            found=admin.get('/users/'+encoded+'/federated-identity')
            if not any(x.get('identityProvider')==alias and x.get('userId')==upstream for x in found):raise
    broker.update(startupMapping=stamp,startupTenant=config['binding']['entra']['tenant_id'],startupAccount=config['binding']['entra']['object_id'],
        startupIssuer=expected_issuer,startupSubject=upstream,startupEmail=config['owner']['profile']['email'])
    desired={**provider,'providerId':'startup-entra','trustEmail':False,'config':broker}
    if desired!=provider:admin.put(provider_path,desired)
    if enabled and not present:admin.post(role_path,[role])
    if not completed:
        admin.put('/users/'+encoded,{'attributes':{**current.get('attributes',{}),'startup_complete':['true']}})
    return {'status':'reconciled','schema_version':1,'mapping_sha256':stamp,'person_id':person['person_id'],
            'broker_subject':subject,'keycloak_admin':enabled,'application_permissions':[]}


def main():
    import argparse
    import os
    import urllib.error
    import urllib.request
    from pathlib import Path
    from account_closure import NativeAdmin
    from startup_contract import load,read_private
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--bound-person',type=Path,required=True)
    parser.add_argument('--acl-result',type=Path,required=True)
    args=parser.parse_args()
    if os.environ.get('STARTUP_IDENTITY_ENABLED')!='1':raise StartupConflict('Startup identity is not enabled')
    class Admin(NativeAdmin):
        def get_optional(self,path):
            request=urllib.request.Request(self.root+path,headers={'Authorization':'Bearer '+self.token})
            try:
                with self.opener.open(request,timeout=10) as response:return json.loads(response.read(2*1024*1024))
            except urllib.error.HTTPError as error:
                if error.code==404:return None
                raise StartupConflict('Keycloak identity lookup unavailable') from None
    token=read_private(Path(os.environ['STARTUP_KEYCLOAK_ADMIN_TOKEN_FILE'])).decode().strip()
    secret_path=os.environ.get('STARTUP_ENTRA_CLIENT_SECRET_FILE')
    secret=read_private(Path(secret_path)).decode().strip() if secret_path else None
    admin=Admin(os.environ['KEYCLOAK_INTERNAL_URL'],os.environ.get('KEYCLOAK_REALM','controlplane'),token)
    result=reconcile(admin,load(args.config),json.loads(args.bound_person.read_text()),json.loads(args.acl_result.read_text()),entra_secret=secret)
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':main()
