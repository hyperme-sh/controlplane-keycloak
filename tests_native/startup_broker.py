"""Synthetic signed upstream used only by the disposable Keycloak CI contract."""
import base64
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
import threading
import time
from urllib.parse import parse_qs,urlencode,urlsplit
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt


@contextmanager
def upstream(config):
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    jwk=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()));jwk.update(kid='startup-test',use='sig',alg='RS256')
    state={'nonce':'','changes':{},'requests':0}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def send(self,value):
            raw=json.dumps(value).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(raw)
        def do_GET(self):
            if self.path=='/keys':self.send({'keys':[jwk]})
            else:self.send_error(404)
        def do_POST(self):
            if self.path!='/token':self.send_error(404);return
            self.rfile.read(int(self.headers.get('Content-Length','0')))
            state['requests']+=1;entra=config['binding']['entra'];now=int(time.time())
            claims={'iss':entra['issuer'],'aud':entra['audience'],'sub':entra['subject'],'tid':entra['tenant_id'],
                'oid':entra['object_id'],'ver':'2.0','nonce':state['nonce'],'iat':now,'exp':now+120,
                'email':config['owner']['profile']['email'],'preferred_username':'configured-test','name':'Configured Operator'}
            claims.update(state['changes'])
            token=jwt.encode(claims,key,algorithm='RS256',headers={'kid':'startup-test'})
            self.send({'access_token':'synthetic-unused','id_token':token,'token_type':'Bearer','expires_in':120})
    server=ThreadingHTTPServer(('0.0.0.0',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:yield 'http://host.docker.internal:'+str(server.server_port),state
    finally:server.shutdown();server.server_close();thread.join(timeout=5)


def broker_login(transport,base,realm,config,state):
    client=config['owner']['broker']['audience'];callback='https://startup-callback.example.invalid/complete'
    verifier='a'*64;challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    transport.cookies.clear()
    response=transport.get(base+'/realms/'+realm+'/protocol/openid-connect/auth',params={'client_id':client,
        'redirect_uri':callback,'response_type':'code','scope':'openid','state':'synthetic-browser-state',
        'nonce':'downstream-nonce','code_challenge':challenge,'code_challenge_method':'S256',
        'kc_idp_hint':config['binding']['entra']['broker']})
    # Follow only Keycloak redirects. The fake authorization UI supplies a code;
    # the actual broker must exchange it and validate the signed upstream token.
    for _ in range(5):
        location=response.headers.get('location','')
        if '/authorize?' in location:break
        assert response.status_code in (302,303),response.text[:500]
        assert location.startswith(base),location
        response=transport.get(location)
    query=parse_qs(urlsplit(location).query)
    state['nonce']=query['nonce'][0]
    response=transport.get(query['redirect_uri'][0],params={'code':'synthetic-code','state':query['state'][0]})
    for _ in range(5):
        location=response.headers.get('location','')
        if location.startswith(callback):break
        if response.status_code not in (302,303):return None
        assert location.startswith(base),location
        response=transport.get(location)
    query=parse_qs(urlsplit(location).query)
    if 'code' not in query:return None
    assert query['state']==['synthetic-browser-state']
    token=transport.post(base+'/realms/'+realm+'/protocol/openid-connect/token',data={
        'grant_type':'authorization_code','client_id':client,'redirect_uri':callback,
        'code':query['code'][0],'code_verifier':verifier})
    assert token.status_code==200,token.text
    value=token.json()['access_token'];keys=transport.get(base+'/realms/'+realm+'/protocol/openid-connect/certs').json()['keys']
    kid=jwt.get_unverified_header(value)['kid'];key=jwt.PyJWK.from_dict(next(k for k in keys if k['kid']==kid))
    return jwt.decode(value,key.key,algorithms=['RS256'],audience=client,issuer=base+'/realms/'+realm)
