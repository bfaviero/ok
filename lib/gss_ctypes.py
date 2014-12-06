import ctypes

# Library
libgssapi_krb5 = ctypes.cdll.LoadLibrary("libgssapi_krb5.so.2")

# Types
class gss_name_struct(ctypes.Structure): pass
gss_name_t = ctypes.POINTER(gss_name_struct)

class gss_cred_id_struct(ctypes.Structure): pass
gss_cred_id_t = ctypes.POINTER(gss_cred_id_struct)

class gss_ctx_id_struct(ctypes.Structure): pass
gss_ctx_id_t = ctypes.POINTER(gss_ctx_id_struct)

gss_uint32 = ctypes.c_uint32
gss_int32 = ctypes.c_int32
OM_uint32 = gss_uint32

class gss_OID_desc(ctypes.Structure):
    _fields_ = [('length', OM_uint32),
                ('elements', ctypes.c_void_p)]
gss_OID = ctypes.POINTER(gss_OID_desc)

class gss_OID_set_desc(ctypes.Structure):
    _fields_ = [('count', ctypes.c_size_t),
                ('elements', gss_OID)]
gss_OID_set = ctypes.POINTER(gss_OID_set_desc)

class gss_buffer_desc(ctypes.Structure):
    _fields_ = [('length', ctypes.c_size_t),
                ('value', ctypes.c_void_p)]

    def as_str(self):
        return ctypes.string_at(self.value, self.length)

gss_buffer_t = ctypes.POINTER(gss_buffer_desc)

class gss_channel_bindings_struct(ctypes.Structure):
    _fields_ = [('initiator_addrtype', OM_uint32),
                ('initiator_address', gss_buffer_desc),
                ('acceptor_addrtype', OM_uint32),
                ('acceptor_address', gss_buffer_desc),
                ('application_data', gss_buffer_desc)]
gss_channel_bindings_t = ctypes.POINTER(gss_channel_bindings_struct)

gss_qop_t = OM_uint32
gss_cred_usage_t = ctypes.c_int

# Constants
GSS_C_DELEG_FLAG = 1
GSS_C_MUTUAL_FLAG = 2
GSS_C_REPLAY_FLAG = 4
GSS_C_SEQUENCE_FLAG = 8
GSS_C_CONF_FLAG = 16
GSS_C_INTEG_FLAG = 32
GSS_C_ANON_FLAG = 64
GSS_C_PROT_READY_FLAG = 128
GSS_C_TRANS_FLAG = 256
GSS_C_DELEG_POLICY_FLAG = 32768

GSS_C_BOTH = 0
GSS_C_INITIATE = 1
GSS_C_ACCEPT = 2

GSS_C_GSS_CODE = 1
GSS_C_MECH_CODE = 2

GSS_C_INDEFINITE = 0xffffffff

GSS_S_COMPLETE = 0

GSS_C_CALLING_ERROR_OFFSET = 24
GSS_C_ROUTINE_ERROR_OFFSET = 16
GSS_C_SUPPLEMENTARY_OFFSET = 0
GSS_C_CALLING_ERROR_MASK = 0377
GSS_C_ROUTINE_ERROR_MASK = 0377
GSS_C_SUPPLEMENTARY_MASK = 0177777

def GSS_CALLING_ERROR(x):
    return ((x) & (GSS_C_CALLING_ERROR_MASK << GSS_C_CALLING_ERROR_OFFSET))
def GSS_ROUTINE_ERROR(x):
    return ((x) & (GSS_C_ROUTINE_ERROR_MASK << GSS_C_ROUTINE_ERROR_OFFSET))
def GSS_SUPPLEMENTARY_INFO(x):
    return ((x) & (GSS_C_SUPPLEMENTARY_MASK << GSS_C_SUPPLEMENTARY_OFFSET))
def GSS_ERROR(x):
    return ((x) & ((GSS_C_CALLING_ERROR_MASK << GSS_C_CALLING_ERROR_OFFSET) |
                   (GSS_C_ROUTINE_ERROR_MASK << GSS_C_ROUTINE_ERROR_OFFSET)))

GSS_S_CALL_INACCESSIBLE_READ = ((1) << GSS_C_CALLING_ERROR_OFFSET)
GSS_S_CALL_INACCESSIBLE_WRITE = ((2) << GSS_C_CALLING_ERROR_OFFSET)
GSS_S_CALL_BAD_STRUCTURE = ((3) << GSS_C_CALLING_ERROR_OFFSET)

GSS_S_BAD_MECH = ((1) << GSS_C_ROUTINE_ERROR_OFFSET)
GSS_S_BAD_NAME = ((2) << GSS_C_ROUTINE_ERROR_OFFSET)
GSS_S_BAD_NAMETYPE = ((3) << GSS_C_ROUTINE_ERROR_OFFSET)
GSS_S_BAD_BINDINGS = ((4) << GSS_C_ROUTINE_ERROR_OFFSET)
GSS_S_BAD_STATUS = ((5) << GSS_C_ROUTINE_ERROR_OFFSET)
GSS_S_BAD_SIG = ((6) << GSS_C_ROUTINE_ERROR_OFFSET)
GSS_S_NO_CRED = ((7) << GSS_C_ROUTINE_ERROR_OFFSET)
GSS_S_NO_CONTEXT = ((8) << GSS_C_ROUTINE_ERROR_OFFSET)
GSS_S_DEFECTIVE_TOKEN = ((9) << GSS_C_ROUTINE_ERROR_OFFSET)
GSS_S_DEFECTIVE_CREDENTIAL = ((10) << GSS_C_ROUTINE_ERROR_OFFSET)
GSS_S_CREDENTIALS_EXPIRED = ((11) << GSS_C_ROUTINE_ERROR_OFFSET)
GSS_S_CONTEXT_EXPIRED = ((12) << GSS_C_ROUTINE_ERROR_OFFSET)
GSS_S_FAILURE = ((13) << GSS_C_ROUTINE_ERROR_OFFSET)
GSS_S_BAD_QOP = ((14) << GSS_C_ROUTINE_ERROR_OFFSET)
GSS_S_UNAUTHORIZED = ((15) << GSS_C_ROUTINE_ERROR_OFFSET)
GSS_S_UNAVAILABLE = ((16) << GSS_C_ROUTINE_ERROR_OFFSET)
GSS_S_DUPLICATE_ELEMENT = ((17) << GSS_C_ROUTINE_ERROR_OFFSET)
GSS_S_NAME_NOT_MN = ((18) << GSS_C_ROUTINE_ERROR_OFFSET)
GSS_S_BAD_MECH_ATTR = ((19) << GSS_C_ROUTINE_ERROR_OFFSET)

GSS_S_CONTINUE_NEEDED = (1 << (GSS_C_SUPPLEMENTARY_OFFSET + 0))
GSS_S_DUPLICATE_TOKEN = (1 << (GSS_C_SUPPLEMENTARY_OFFSET + 1))
GSS_S_OLD_TOKEN = (1 << (GSS_C_SUPPLEMENTARY_OFFSET + 2))
GSS_S_UNSEQ_TOKEN = (1 << (GSS_C_SUPPLEMENTARY_OFFSET + 3))
GSS_S_GAP_TOKEN = (1 << (GSS_C_SUPPLEMENTARY_OFFSET + 4))

gss_mech_krb5 = gss_OID.in_dll(libgssapi_krb5, "gss_mech_krb5")

GSS_C_NT_HOSTBASED_SERVICE = gss_OID.in_dll(libgssapi_krb5,
                                            "GSS_C_NT_HOSTBASED_SERVICE")
GSS_C_NT_EXPORT_NAME = gss_OID.in_dll(libgssapi_krb5,
                                      "GSS_C_NT_EXPORT_NAME")
GSS_KRB5_NT_PRINCIPAL_NAME = gss_OID.in_dll(libgssapi_krb5,
                                            "GSS_KRB5_NT_PRINCIPAL_NAME")

# Functions
gss_acquire_cred = libgssapi_krb5.gss_acquire_cred
gss_acquire_cred.restype = OM_uint32
gss_acquire_cred.argtypes = (ctypes.POINTER(OM_uint32),
                             gss_name_t,
                             OM_uint32,
                             gss_OID_set,
                             gss_cred_usage_t,
                             ctypes.POINTER(gss_cred_id_t),
                             ctypes.POINTER(gss_OID_set),
                             ctypes.POINTER(OM_uint32))

gss_release_cred = libgssapi_krb5.gss_release_cred
gss_release_cred.restype = OM_uint32
gss_release_cred.argtypes = (ctypes.POINTER(OM_uint32),
                             ctypes.POINTER(gss_cred_id_t))

gss_init_sec_context = libgssapi_krb5.gss_init_sec_context
gss_init_sec_context.restype = OM_uint32
gss_init_sec_context.argtypes = (ctypes.POINTER(OM_uint32),
                                 gss_cred_id_t,
                                 ctypes.POINTER(gss_ctx_id_t),
                                 gss_name_t,
                                 gss_OID,
                                 OM_uint32,
                                 OM_uint32,
                                 gss_channel_bindings_t,
                                 gss_buffer_t,
                                 ctypes.POINTER(gss_OID),
                                 gss_buffer_t,
                                 ctypes.POINTER(OM_uint32),
                                 ctypes.POINTER(OM_uint32))

gss_delete_sec_context = libgssapi_krb5.gss_delete_sec_context
gss_delete_sec_context.restype = OM_uint32
gss_delete_sec_context.argtypes = (ctypes.POINTER(OM_uint32),
                                   ctypes.POINTER(gss_ctx_id_t),
                                   gss_buffer_t)

gss_display_status = libgssapi_krb5.gss_display_status
gss_display_status.restype = OM_uint32
gss_display_status.argtypes = (ctypes.POINTER(OM_uint32),
                               OM_uint32,
                               ctypes.c_int,
                               gss_OID,
                               ctypes.POINTER(OM_uint32),
                               gss_buffer_t)

gss_display_name = libgssapi_krb5.gss_display_name
gss_display_name.restype = OM_uint32
gss_display_name.argtypes = (ctypes.POINTER(OM_uint32),
                             gss_name_t,
                             gss_buffer_t,
                             ctypes.POINTER(gss_OID))

gss_import_name = libgssapi_krb5.gss_import_name
gss_import_name.restype = OM_uint32
gss_import_name.argtypes = (ctypes.POINTER(OM_uint32),
                            gss_buffer_t,
                            gss_OID,
                            ctypes.POINTER(gss_name_t))

gss_release_name = libgssapi_krb5.gss_release_name
gss_release_name.restype = OM_uint32
gss_release_name.argtypes = (ctypes.POINTER(OM_uint32),
                             ctypes.POINTER(gss_name_t))

gss_release_buffer = libgssapi_krb5.gss_release_buffer
gss_release_buffer.restype = OM_uint32
gss_release_buffer.argtypes = (ctypes.POINTER(OM_uint32),
                               gss_buffer_t)

gss_release_oid_set = libgssapi_krb5.gss_release_oid_set
gss_release_oid_set.restype = OM_uint32
gss_release_oid_set.argtypes = (ctypes.POINTER(OM_uint32),
                                ctypes.POINTER(gss_OID_set))

gss_canonicalize_name = libgssapi_krb5.gss_canonicalize_name
gss_canonicalize_name.restype = OM_uint32
gss_canonicalize_name.argtypes = (ctypes.POINTER(OM_uint32),
                                  gss_name_t,
                                  gss_OID,
                                  ctypes.POINTER(gss_name_t))
