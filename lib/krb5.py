import base64
import ctypes
import functools

import krb5_ctypes

__all__ = ['Context']

class Error(Exception):
    def __init__(self, ctx_raw, code):
        self.code = code
        msg_c = krb5_ctypes.krb5_get_error_message(ctx_raw, code)
        self.message = msg_c.value
        krb5_ctypes.krb5_free_error_message(ctx_raw, msg_c)

    def __str__(self):
        return self.message

def check_error(fn):
    if fn.restype is not krb5_ctypes.krb5_error_code:
        return fn
    @functools.wraps(fn)
    def wrapped(ctx, *args):
        ret = fn(ctx, *args)
        if ret:
            raise Error(ctx, ret)
        return ret
    return wrapped

krb5_init_context = check_error(krb5_ctypes.krb5_init_context)
krb5_free_context = check_error(krb5_ctypes.krb5_free_context)
krb5_cc_default = check_error(krb5_ctypes.krb5_cc_default)
krb5_cc_new_unique = check_error(krb5_ctypes.krb5_cc_new_unique)
krb5_cc_close = check_error(krb5_ctypes.krb5_cc_close)
krb5_cc_get_principal = check_error(krb5_ctypes.krb5_cc_get_principal)
krb5_free_principal = check_error(krb5_ctypes.krb5_free_principal)
krb5_unparse_name = check_error(krb5_ctypes.krb5_unparse_name)
krb5_free_unparsed_name = check_error(krb5_ctypes.krb5_free_unparsed_name)
krb5_build_principal = check_error(krb5_ctypes.krb5_build_principal)
krb5_get_credentials = check_error(krb5_ctypes.krb5_get_credentials)
krb5_cc_store_cred = check_error(krb5_ctypes.krb5_cc_store_cred)
krb5_free_creds = check_error(krb5_ctypes.krb5_free_creds)
krb5_free_ticket = check_error(krb5_ctypes.krb5_free_ticket)
krb5_mk_1cred = check_error(krb5_ctypes.krb5_mk_1cred)
krb5_rd_cred = check_error(krb5_ctypes.krb5_rd_cred)
krb5_init_keyblock = check_error(krb5_ctypes.krb5_init_keyblock)
krb5_auth_con_setsendsubkey = check_error(krb5_ctypes.krb5_auth_con_setsendsubkey)
krb5_auth_con_setrecvsubkey = check_error(krb5_ctypes.krb5_auth_con_setrecvsubkey)
krb5_free_keyblock_contents = check_error(krb5_ctypes.krb5_free_keyblock_contents)
krb5_auth_con_setflags = check_error(krb5_ctypes.krb5_auth_con_setflags)
krb5_auth_con_init = check_error(krb5_ctypes.krb5_auth_con_init)
krb5_auth_con_free = check_error(krb5_ctypes.krb5_auth_con_free)
krb5_string_to_enctype = check_error(krb5_ctypes.krb5_string_to_enctype)
krb5_c_string_to_key = check_error(krb5_ctypes.krb5_c_string_to_key)
krb5_free_data = check_error(krb5_ctypes.krb5_free_data)
krb5_free_tgt_creds = check_error(krb5_ctypes.krb5_free_tgt_creds)
krb5_copy_creds = check_error(krb5_ctypes.krb5_copy_creds)
krb5_get_init_creds_opt_init = \
    check_error(krb5_ctypes.krb5_get_init_creds_opt_init)
krb5_get_init_creds_password = \
    check_error(krb5_ctypes.krb5_get_init_creds_password)
krb5_get_init_creds_opt_set_forwardable = \
    check_error(krb5_ctypes.krb5_get_init_creds_opt_set_forwardable)


# This one is weird and takes no context. But the free function does??
def krb5_decode_ticket(*args):
    ret = krb5_ctypes.krb5_decode_ticket(*args)
    if ret:
        raise Error(krb5_ctypes.krb5_context(), ret)
    return ret

def to_str(obj):
    if isinstance(obj, str):
        return obj
    if isinstance(obj, unicode):
        return obj.encode('utf-8')
    raise TypeError('Expected string')

class Context(object):
    def __init__(self):
        self._handle = krb5_ctypes.krb5_context()
        krb5_init_context(self._handle)

    def __del__(self):
        if bool(self._handle):
            krb5_free_context(self._handle)

    def cc_default(self):
        ccache = CCache(self)
        krb5_cc_default(self._handle, ccache._handle)
        return ccache

    def build_principal(self, realm, name):
        realm = to_str(realm)
        name = [to_str(comp) for comp in name]
        principal = Principal(self)
        name_args = [ctypes.c_char_p(comp) for comp in name]
        name_args.append(ctypes.c_char_p())
        krb5_build_principal(self._handle,
                             principal._handle,
                             len(realm),
                             ctypes.c_char_p(realm),
                             *name_args)
        return principal

    def decode_ticket(self, data):
        data = to_str(data)
        data_c = krb5_ctypes.krb5_data()
        # Why do I need this dance...
        data_c.data = ctypes.cast(
            ctypes.c_char_p(data),
            ctypes.POINTER(ctypes.c_char))
        data_c.length = len(data)
        return self._decode_ticket(data_c)

    def _decode_ticket(self, data_c):
        ticket = Ticket(self)
        krb5_decode_ticket(data_c, ticket._handle)
        return ticket

class CCache(object):
    def __init__(self, ctx):
        self._ctx = ctx
        self._handle = krb5_ctypes.krb5_ccache()

    def __del__(self):
        if bool(self._handle):
            krb5_cc_close(self._ctx._handle, self._handle)

    def get_principal(self):
        principal = Principal(self._ctx)
        krb5_cc_get_principal(self._ctx._handle,
                              self._handle,
                              principal._handle)
        return principal

    def get_credentials(self, client, server,
                        cache_only=False,
                        user_to_user=False):
        flags = 0
        if cache_only:
            flags |= krb5_ctypes.KRB5_GC_CACHED
        if user_to_user:
            flags |= krb5_ctypes.KRB5_GC_USER_USER

        in_creds = krb5_ctypes.krb5_creds()
        in_creds.client = client._handle
        in_creds.server = server._handle
        # TODO(davidben): If we care, pass in parameters for the other
        # options too.
        creds = Credentials(self._ctx)
        krb5_get_credentials(self._ctx._handle, flags, self._handle, in_creds,
                             creds._handle)
        return creds

class Principal(object):
    def __init__(self, ctx):
        self._ctx = ctx
        self._handle = krb5_ctypes.krb5_principal()

    def __del__(self):
        if bool(self._handle):
            krb5_free_principal(self._ctx._handle, self._handle)

    def unparse_name(self):
        name_c = ctypes.c_char_p()
        krb5_unparse_name(self._ctx._handle, self._handle, name_c)
        name = name_c.value
        krb5_free_unparsed_name(self._ctx._handle, name_c)
        return name

    def __str__(self):
        return self.unparse_name()

    def __repr__(self):
        return '<%s: %s>' % (self.__class__.__name__, self.unparse_name())

class Credentials(object):
    def __init__(self, ctx):
        self._ctx = ctx
        self._handle = krb5_ctypes.krb5_creds_ptr()

    def __del__(self):
        if bool(self._handle):
            krb5_free_creds(self._ctx._handle, self._handle)

    def decode_ticket(self):
        return self._ctx._decode_ticket(self._handle.contents.ticket)
    def decode_second_ticket(self):
        return self._ctx._decode_second_ticket(
            self._handle.contents.second_ticket)

    def to_dict(self):
        # TODO(davidben): More sensible would be to put this format
        # into roost.py and expose all the attributes in the public
        # API. But whatever.
        ret = { }
        client_data = self._handle.contents.client.contents
        ret['crealm'] = client_data.realm.as_str()
        ret['cname'] = {
            'nameType': client_data.type,
            'nameString': [client_data.data[i].as_str()
                           for i in xrange(client_data.length)],
            }
        ret['ticket'] = self.decode_ticket().to_dict()
        keyblock = self._handle.contents.keyblock
        ret['key'] = {
            'keytype': keyblock.enctype,
            'keyvalue': base64.b64encode(keyblock.contents_as_str())
        }
        flags = self._handle.contents.ticket_flags
        ret['flags'] = [(1 if (flags & (1 << (31 - i))) else 0)
                        for i in range(32)]
        # Webathena times are milliseconds, Kerberos uses seconds
        ret['authtime'] = self._handle.contents.times.authtime * 1000
        if self._handle.contents.times.starttime:
            ret['starttime'] = self._handle.contents.times.starttime * 1000
        ret['endtime'] = self._handle.contents.times.endtime * 1000
        if self._handle.contents.times.renew_till:
            ret['renewTill'] = self._handle.contents.times.renew_till * 1000
        server_data = self._handle.contents.server.contents
        ret['srealm'] = server_data.realm.as_str()
        ret['sname'] = {
            'nameType': server_data.type,
            'nameString': [server_data.data[i].as_str()
                           for i in xrange(server_data.length)],
            }

        return ret

        # TODO(cyphers): figure out why we would want the part below, and why it
        # throws a floating point exception.

        addrs = []
        i = 0
        while bool(self._handle.contents.addresses[i]):
            addr = self._handle.contents.addresses[i].contents
            addrs.append({
                    'addrType': addr.addrtype,
                    'address': addr.contents_as_str()
            })
            i += 1
        if addrs:
            ret['caddr'] = addrs

        return ret

class Ticket(object):
    def __init__(self, ctx):
        self._ctx = ctx
        self._handle = krb5_ctypes.krb5_ticket_ptr()

    def __del__(self):
        if bool(self._handle):
            krb5_free_ticket(self._ctx._handle, self._handle)

    def to_dict(self):
        ret = { }
        ret['tktVno'] = 5
        server_data = self._handle.contents.server.contents
        ret['realm'] = server_data.realm.as_str()
        ret['sname'] = {
            'nameType': server_data.type,
            'nameString': [server_data.data[i].as_str()
                           for i in xrange(server_data.length)],
            }
        ret['encPart'] = {
            'kvno': self._handle.contents.enc_part.kvno,
            'etype': self._handle.contents.enc_part.enctype,
            'cipher': base64.b64encode(
                self._handle.contents.enc_part.ciphertext.as_str()),
        }
        return ret
