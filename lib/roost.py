import base64
import json
import pycurl
import StringIO

import gss

DEFAULT_SERVER = 'https://roost-api.mit.edu'
DEFAULT_SERVICE = 'HTTP@roost-api.mit.edu'

class Error(Exception):
    def __init__(self, code, contents):
        self.code = code
        self.contents = contents
    def __str__(self):
        return self.contents

def to_str(s):
    if isinstance(s, unicode):
        return s.encode('utf-8')
    return s

def http_request(options, method, path, headers, data=None):
    headers = map(to_str, headers)
    buf = StringIO.StringIO()

    # Some parameters, etc., borrowed from stripe-python
    curl = pycurl.Curl()
    try:
        curl.setopt(pycurl.URL, options.server + path)
        curl.setopt(pycurl.WRITEFUNCTION, buf.write)
        curl.setopt(pycurl.NOSIGNAL, 1)
        curl.setopt(pycurl.CONNECTTIMEOUT, 30)
        curl.setopt(pycurl.TIMEOUT, 80)
        if method == 'GET':
            curl.setopt(pycurl.HTTPGET, 1)
        elif method == 'POST':
            curl.setopt(pycurl.POST, 1)
            headers += ['Content-Type: application/json']
            curl.setopt(pycurl.POSTFIELDS, json.dumps(data))
        else:
            # Until we actually use DELETE for something. cURL's API is
            # weird.
            raise ValueError('Unknown method')
        curl.setopt(pycurl.HTTPHEADER, headers)
        curl.perform()
        code = curl.getinfo(pycurl.HTTP_CODE)
        if code != 200:
            raise Error(code, buf.getvalue().strip())
        return buf.getvalue()
    finally:
        curl.close()

def get_auth_token(options, client, create_user=False):
    client_name = gss.import_name(client, gss.KRB5_NT_PRINCIPAL_NAME)
    target_name = gss.import_name(options.service, gss.C_NT_HOSTBASED_SERVICE)
    cred = gss.acquire_cred(client_name, initiate=True)
    # TODO(davidben): Mutual auth with channel-binding? Server doesn't
    # support it but there may be some hope of use having enough
    # control to use tls-unique. Without it, mutual auth isn't super
    # useful.
    gss_ctx = gss.create_initiator(target_name, credential=cred,
                                   mechanism=gss.KRB5_MECHANISM)
    token = gss_ctx.init_sec_context()
    if not gss_ctx.is_established():
        raise Exception('Context should establish in one leg!')

    result = json.loads(http_request(options, 'POST', '/v1/auth', [], {
                'principal': client,
                'token': base64.b64encode(token),
                'createUser': create_user
                }))
    return result['authToken'], (result['expires'] / 1000.)

def get(options, token, path):
    return json.loads(http_request(
            options, 'GET', path,
            ['Authorization: Bearer ' + token]))

def post(options, token, path, data):
    return json.loads(http_request(
            options, 'POST', path,
            ['Authorization: Bearer ' + token], data))
