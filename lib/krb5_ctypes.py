import ctypes

# Library
libkrb5 = ctypes.cdll.LoadLibrary("libkrb5.so.3")

# Constants
KRB5_GC_USER_USER = 1
KRB5_GC_CACHED = 2

# Types
krb5_int32 = ctypes.c_int32
krb5_deltat = krb5_int32
krb5_error_code = krb5_int32
krb5_magic = krb5_error_code
krb5_flags = krb5_int32
krb5_enctype = krb5_int32
krb5_octet = ctypes.c_ubyte
krb5_timestamp = krb5_int32
krb5_boolean = ctypes.c_uint
krb5_addrtype = krb5_int32
krb5_authdatatype = krb5_int32
krb5_prompt_type = krb5_int32
krb5_kvno = ctypes.c_uint

class _krb5_get_init_creds_opt(ctypes.Structure): pass
krb5_get_init_creds_opt = ctypes.POINTER(_krb5_get_init_creds_opt)
class _krb5_context(ctypes.Structure): pass
krb5_context = ctypes.POINTER(_krb5_context)
class _krb5_ccache(ctypes.Structure): pass
krb5_ccache = ctypes.POINTER(_krb5_ccache)

class krb5_data(ctypes.Structure):
    _fields_ = [('magic', krb5_magic),
                ('length', ctypes.c_uint),
                ('data', ctypes.POINTER(ctypes.c_char))]

    def as_str(self):
        return ctypes.string_at(self.data, self.length)

class _krb5_prompt(ctypes.Structure):
    _fields_ = [('prompt', ctypes.c_char_p),
                ('hidden', ctypes.c_int),
                ('reply', ctypes.POINTER(krb5_data)),
                ('type', krb5_prompt_type)]
krb5_prompt = ctypes.POINTER(_krb5_prompt)

class krb5_principal_data(ctypes.Structure):
    _fields_ = [('magic', krb5_magic),
                ('realm', krb5_data),
                ('data', ctypes.POINTER(krb5_data)),
                ('length', krb5_int32),
                ('type', krb5_int32)]
krb5_principal = ctypes.POINTER(krb5_principal_data)
krb5_const_principal = ctypes.POINTER(krb5_principal_data)

class krb5_keyblock(ctypes.Structure):
    _fields_ = [('magic', krb5_magic),
                ('enctype', krb5_enctype),
                ('length', ctypes.c_uint),
                ('contents', ctypes.POINTER(krb5_octet))]
    def contents_as_str(self):
        return ctypes.string_at(self.contents, self.length)

class krb5_ticket_times(ctypes.Structure):
    _fields_ = [('authtime', krb5_timestamp),
                ('starttime', krb5_timestamp),
                ('endtime', krb5_timestamp),
                ('renew_till', krb5_timestamp)]

class krb5_address(ctypes.Structure):
    _fields_ = [('magic', krb5_magic),
                ('addrtype', krb5_addrtype),
                ('length', ctypes.c_uint),
                ('contents', ctypes.POINTER(krb5_octet))]
    def contents_as_str(self):
        return ctypes.string_at(self.contents, self.length)

class krb5_authdata(ctypes.Structure):
    _fields_ = [('magic', krb5_magic),
                ('ad_type', krb5_authdatatype),
                ('length', ctypes.c_uint),
                ('contents', ctypes.POINTER(krb5_octet))]

class krb5_creds(ctypes.Structure):
    _fields_ = [('magic', krb5_magic),
                ('client', krb5_principal),
                ('server', krb5_principal),
                ('keyblock', krb5_keyblock),
                ('times', krb5_ticket_times),
                ('is_skey', krb5_boolean),
                ('ticket_flags', krb5_flags),
                ('addresses', ctypes.POINTER(ctypes.POINTER(krb5_address))),
                ('ticket', krb5_data),
                ('second_ticket', krb5_data),
                ('authdata', ctypes.POINTER(ctypes.POINTER(krb5_authdata)))]
krb5_creds_ptr = ctypes.POINTER(krb5_creds)

class krb5_enc_data(ctypes.Structure):
    _fields_ = [('magic', krb5_magic),
                ('enctype', krb5_enctype),
                ('kvno', krb5_kvno),
                ('ciphertext', krb5_data)]

# Transcribe this later if we ever care about it.
class krb5_enc_tkt_part(ctypes.Structure): pass

class krb5_ticket(ctypes.Structure):
    _fields_ = [('magic', krb5_magic),
                ('server', krb5_principal),
                ('enc_part', krb5_enc_data),
                ('enc_part2', krb5_enc_tkt_part)]
krb5_ticket_ptr = ctypes.POINTER(krb5_ticket)

# Don't do the conversion on return.
class _c_char_p_noconv(ctypes.c_char_p): pass

# Functions
krb5_init_context = libkrb5.krb5_init_context
krb5_init_context.restype = krb5_error_code
krb5_init_context.argtypes = (ctypes.POINTER(krb5_context),)

krb5_free_context = libkrb5.krb5_free_context
krb5_free_context.restype = None
krb5_free_context.argtypes = (krb5_context,)

krb5_cc_default = libkrb5.krb5_cc_default
krb5_cc_default.restype = krb5_error_code
krb5_cc_default.argtypes = (krb5_context, ctypes.POINTER(krb5_ccache))

krb5_cc_close = libkrb5.krb5_cc_close
krb5_cc_close.restype = krb5_error_code
krb5_cc_close.argtypes = (krb5_context, krb5_ccache)

krb5_cc_new_unique = libkrb5.krb5_cc_new_unique
krb5_cc_new_unique.restype = krb5_error_code
krb5_cc_new_unique.argtypes = (krb5_context,
                              ctypes.c_char_p,
                              ctypes.c_char_p,
                              ctypes.POINTER(krb5_ccache))

'''
krb5_prompter_posix = libkrb5.krb5_prompter_posix
krb5_prompter_posix.restype = krb5_error_code
krb5_prompter_posix.argtypes = (krb5_context,
                                ctypes.c_void_p,
                                ctypes.c_char_p,
                                ctypes.c_char_p,
                                ctypes.c_int,
                                krb5_prompt)
'''

# Function pointer type to pass in to the get_init_creds function
krb5_prompter_fct_t = ctypes.CFUNCTYPE(krb5_error_code,
                                krb5_context,
                                ctypes.c_void_p,
                                ctypes.c_char_p,
                                ctypes.c_char_p,
                                ctypes.c_int,
                                krb5_prompt)

krb5_get_init_creds_opt_init = libkrb5.krb5_get_init_creds_opt_init
krb5_get_init_creds_opt_init.restype = krb5_error_code
krb5_get_init_creds_opt_init.argtypes = (krb5_get_init_creds_opt,)

krb5_get_init_creds_password = libkrb5.krb5_get_init_creds_password
krb5_get_init_creds_password.restype = krb5_error_code
krb5_get_init_creds_password.argtypes = (krb5_context,
                                krb5_creds_ptr,
                                krb5_principal,
                                ctypes.c_char_p,
                                krb5_prompter_fct_t,
                                ctypes.c_void_p,
                                krb5_deltat,
                                ctypes.c_char_p,
                                krb5_get_init_creds_opt)


krb5_cc_get_principal = libkrb5.krb5_cc_get_principal
krb5_cc_get_principal.restype = krb5_error_code
krb5_cc_get_principal.argtypes = (krb5_context,
                                  krb5_ccache,
                                  ctypes.POINTER(krb5_principal))

krb5_free_principal = libkrb5.krb5_free_principal
krb5_free_principal.restype = None
krb5_free_principal.argtypes = (krb5_context, krb5_principal)

krb5_unparse_name = libkrb5.krb5_unparse_name
krb5_unparse_name.restype = krb5_error_code
krb5_unparse_name.argtypes = (krb5_context,
                              krb5_const_principal,
                              ctypes.POINTER(ctypes.c_char_p))

krb5_free_unparsed_name = libkrb5.krb5_free_unparsed_name
krb5_free_unparsed_name.restype = None
krb5_free_unparsed_name.argtypes = (krb5_context, ctypes.c_char_p)

krb5_get_error_message = libkrb5.krb5_get_error_message
krb5_get_error_message.restype = _c_char_p_noconv
krb5_get_error_message.argtypes = (krb5_context, krb5_error_code)

krb5_free_error_message = libkrb5.krb5_free_error_message
krb5_free_error_message.restype = None
krb5_free_error_message.argtypes = (krb5_context, ctypes.c_char_p)

krb5_build_principal = libkrb5.krb5_build_principal
krb5_build_principal.restype = krb5_error_code
# This takes varargs. Supposedly things using the C calling convention
# can take extra args in ctypes?
krb5_build_principal.argtypes = (krb5_context,
                                 ctypes.POINTER(krb5_principal),
                                 ctypes.c_uint,
                                 ctypes.POINTER(ctypes.c_char))

krb5_get_credentials = libkrb5.krb5_get_credentials
krb5_get_credentials.restype = krb5_error_code
krb5_get_credentials.argtypes = (krb5_context,
                                 krb5_flags,
                                 krb5_ccache,
                                 krb5_creds_ptr,
                                 ctypes.POINTER(krb5_creds_ptr))

krb5_free_creds = libkrb5.krb5_free_creds
krb5_free_creds.restype = None
krb5_free_creds.argtypes = (krb5_context, krb5_creds_ptr)

krb5_decode_ticket = libkrb5.krb5_decode_ticket
krb5_decode_ticket.restype = krb5_error_code
krb5_decode_ticket.argtypes = (ctypes.POINTER(krb5_data),
                               ctypes.POINTER(krb5_ticket_ptr))

krb5_free_ticket = libkrb5.krb5_free_ticket
krb5_free_ticket.restype = None
krb5_free_ticket.argtypes = (krb5_context, krb5_ticket_ptr)
