import ctypes
import functools

import gss_ctypes

def _display_status(status_value, status_type):
    ret = []
    status_string = gss_ctypes.gss_buffer_desc()
    message_context = gss_ctypes.OM_uint32()
    for _ in xrange(8):
        gss_display_status(status_value, status_type,
                           None, message_context, status_string)
        try:
            ret.append(status_string.as_str())
        finally:
            gss_release_buffer(status_string)
        if message_context.value == 0:
            break
    return ret

class Error(Exception):
    def __init__(self, major, minor):
        self.major = major
        self.minor = minor
        self.messages = []
        if major != gss_ctypes.GSS_S_FAILURE:
            self.messages += _display_status(major, gss_ctypes.GSS_C_GSS_CODE)
        if minor:
            self.messages += _display_status(minor, gss_ctypes.GSS_C_MECH_CODE)

    def __str__(self):
        return '; '.join(self.messages)

def check_error(fn):
    @functools.wraps(fn)
    def wrapped(*args):
        minor = gss_ctypes.OM_uint32()
        ret = fn(minor, *args)
        if gss_ctypes.GSS_ERROR(ret):
            raise Error(ret, minor.value)
        return ret
    return wrapped

gss_acquire_cred = check_error(gss_ctypes.gss_acquire_cred)
gss_release_cred = check_error(gss_ctypes.gss_release_cred)
gss_init_sec_context = check_error(gss_ctypes.gss_init_sec_context)
gss_delete_sec_context = check_error(gss_ctypes.gss_delete_sec_context)
gss_display_status = check_error(gss_ctypes.gss_display_status)
gss_display_name = check_error(gss_ctypes.gss_display_name)
gss_import_name = check_error(gss_ctypes.gss_import_name)
gss_release_name = check_error(gss_ctypes.gss_release_name)
gss_release_oid_set = check_error(gss_ctypes.gss_release_oid_set)
gss_release_buffer = check_error(gss_ctypes.gss_release_buffer)
gss_canonicalize_name = check_error(gss_ctypes.gss_canonicalize_name)

def to_str(obj):
    if isinstance(obj, str):
        return obj
    if isinstance(obj, unicode):
        return obj.encode('utf-8')
    raise TypeError('Expected string')

__all__ = [
    'C_NT_HOSTBASED_SERVICE',
    'C_NT_EXPORT_NAME',
    'KRB5_NT_PRINCIPAL_NAME',
    'KRB5_MECHANISM',
    'import_name',
    'acquire_cred',
    'create_initiator',
    ]

class OID(object):
    def __init__(self, handle, copy=False):
        if copy:
            self._data = ctypes.string_at(handle.elements,
                                          handle.length)
            self._handle = gss_ctypes.gss_OID_desc()
            self._handle.elements = ctypes.cast(ctypes.c_char_p(self._data),
                                                ctypes.c_void_p)
            self._handle.length = len(self._data)
        else:
            self._handle = handle

def oid_list_to_oid_set(oids):
    oid_set = gss_ctypes.gss_OID_set_desc()
    oid_set_elems = (gss_ctypes.gss_OID_desc * len(oids))()
    oid_set_data = []
    oid_set.count = len(oids)
    oid_set.elements = oid_set_elems
    for i, mech in enumerate(oids):
        data = ctypes.string_at(mech._handle.elements,
                                mech._handle.length)
        oid_set_elems[i].length = len(data)
        oid_set_elems[i].elements = ctypes.cast(ctypes.c_char_p(data),
                                                ctypes.c_void_p)
        oid_set_data.append(data)
    return (oid_set, (oid_set_elems, oid_set_data))

C_NT_HOSTBASED_SERVICE = OID(gss_ctypes.GSS_C_NT_HOSTBASED_SERVICE.contents)
C_NT_EXPORT_NAME = OID(gss_ctypes.GSS_C_NT_EXPORT_NAME.contents)

KRB5_MECHANISM = OID(gss_ctypes.gss_mech_krb5.contents)
KRB5_NT_PRINCIPAL_NAME = OID(gss_ctypes.GSS_KRB5_NT_PRINCIPAL_NAME.contents)

def import_name(inp, oid):
    inp = to_str(inp)
    name = Name()
    inp_buf = gss_ctypes.gss_buffer_desc()
    inp_buf.length = len(inp)
    inp_buf.value = ctypes.cast(ctypes.c_char_p(inp), ctypes.c_void_p)
    gss_import_name(inp_buf, oid._handle, name._handle)
    return name

def acquire_cred(name=None,
                 time_req=gss_ctypes.GSS_C_INDEFINITE,
                 desired_mechs=None,
                 initiate=False,
                 accept=False):
    if initiate:
        if accept:
            cred_usage = gss_ctypes.GSS_C_BOTH
        else:
            cred_usage = gss_ctypes.GSS_C_INITIATE
    elif accept:
        cred_usage = gss_ctypes.GSS_C_ACCEPT
    else:
        raise ValueError('Set either accept or initiate to True')

    desired_mech_set = None
    if desired_mechs is not None:
        desired_mech_set, _storage = oid_list_to_oid_set(desired_mechs)

    cred = Credential()
    print gss_acquire_cred(name._handle if name else None,
                     time_req, desired_mech_set,
                     cred_usage, cred._handle,
                     None, None)
    return cred

def create_initiator(*args, **kwargs):
    return InitContext(*args, **kwargs)

class Name(object):
    def __init__(self):
        self._handle = gss_ctypes.gss_name_t()

    def __del__(self):
        if bool(self._handle):
            gss_release_name(self._handle)

    def display(self):
        buf = gss_ctypes.gss_buffer_desc()
        oid = gss_ctypes.gss_OID()
        gss_display_name(self._handle, buf, oid)
        try:
            return (buf.as_str(), OID(oid.contents))
        finally:
            gss_release_buffer(buf)

    def canonicalize(self, oid):
        name = Name()
        gss_canonicalize_name(self._handle, oid._handle, name._handle)
        return name

    def __str__(self):
        return self.display()[0]

    def __repr__(self):
        return '<%s: %s>' % (self.__class__.__name__, str(self))

class Credential(object):
    def __init__(self):
        self._handle = gss_ctypes.gss_cred_id_t()

    def __del__(self):
        if bool(self._handle):
            gss_release_cred(self._handle)

class Context(object):
    def __init__(self, cred):
        self._cred = cred
        self._handle = gss_ctypes.gss_ctx_id_t()
        self._is_established = False
        self._actual_flags = 0
        self._mechanism = None

    def __del__(self):
        if hasattr(self, '_handle') and bool(self._handle):
            buf = gss_ctypes.gss_buffer_desc()
            gss_delete_sec_context(self._handle, buf)
            gss_release_buffer(buf)

    def is_established(self):
        return self._is_established

class InitContext(Context):
    def __init__(self, target,
                 credential=None,
                 mechanism=None,
                 delegate=False,
                 mutual=False,
                 replay=False,
                 sequence=False,
                 confidentiality=False,
                 integrity=False,
                 anonymous=False,
                 time_req=0,
                 channel_bindings=None):
        if channel_bindings is not None:
            raise NotImplemented('channel_bindings')
        Context.__init__(self, credential)
        self._target = target
        self._mechanism = mechanism
        flags = 0
        if delegate:
            flags |= gss_ctypes.GSS_C_DELEG_FLAG
        if mutual:
            flags |= gss_ctypes.GSS_C_MUTUAL_FLAG
        if replay:
            flags |= gss_ctypes.GSS_C_REPLAY_FLAG
        if sequence:
            flags |= gss_ctypes.GSS_C_SEQUENCE_FLAG
        if confidentiality:
            flags |= gss_ctypes.GSS_C_CONF_FLAG
        if integrity:
            flags |= gss_ctypes.GSS_C_INTEG_FLAG
        if anonymous:
            flags |= gss_ctypes.GSS_C_ANON_FLAG
        self._flags = flags
        self._time_req = time_req

    def init_sec_context(self, token=None):
        if token is not None:
            token = to_str(token)
            token_buf = gss_ctypes.gss_buffer_desc()
            token_buf.length = len(token)
            token_buf.value = ctypes.cast(ctypes.c_char_p(token),
                                          ctypes.c_void_p)
        else:
            token_buf = None

        output_buf = gss_ctypes.gss_buffer_desc()
        actual_mech = gss_ctypes.gss_OID()
        actual_flags = gss_ctypes.OM_uint32()

        ret = gss_init_sec_context(
            self._cred._handle if self._cred else None,
            self._handle, self._target._handle,
            self._mechanism._handle if self._mechanism else None,
            self._flags, self._time_req, None, token_buf,
            # Output params
            actual_mech, output_buf, actual_flags, None)
        output_token = output_buf.as_str()
        gss_release_buffer(output_buf)
        self._actual_flags = actual_flags.value
        self._mechanism = OID(actual_mech.contents)

        if (ret & gss_ctypes.GSS_S_CONTINUE_NEEDED) == 0:
            self._is_established = True

        return output_token
