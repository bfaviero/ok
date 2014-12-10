import sys
import shutil
import getpass
import lib.krb5 as krb5
import lib.krb5_ctypes as krb5_ctypes
import ctypes
import binascii
import ctypes
import pdb
import json
import gc
#import IPython
from kerberos_serializer import *

gc.disable()
CC_PATH = '/tmp/krb5cc_1000'

# Delete the default cache
def clear_service_ticket_jank():
    os.remove(CC_PATH)


# Store a service ticket in the default cache (kind of)
def store_service_ticket_jank(creds, userid, realm='ATHENA.MIT.EDU'):
    ctx = krb5.Context()
    creds = deserialize_cred(ctx, creds)

    old_user = 'bcyphers'
    old_realm = 'ATHENA.MIT.EDU'

    old = open('krb5cc_1000', 'r')
    new = open(CC_PATH, 'w')
    for line in old:
        new.write(line.replace(old_user, userid).replace(old_realm, realm))
    old.close()
    new.close()

    ctx = krb5.Context()
    ccache = ctx.cc_default()

    principal_ptr = krb5_ctypes.krb5_principal(
                        krb5_ctypes.krb5_principal_data())

    krb5.krb5_cc_store_cred(ctx._handle, ccache._handle.contents,
                            creds._handle)


# Store a service ticket in a private ccache for the specified user
# This is throwing segfaults; should find out why
def store_service_ticket(creds, userid, realm='ATHENA.MIT.EDU'):
    ctx = krb5.Context()
    ccache = ctx.cc_default()

    principal_ptr = krb5_ctypes.krb5_principal(
                        krb5_ctypes.krb5_principal_data())

    print 'building principal:',
    krb5.krb5_build_principal(ctx._handle,
                         principal_ptr,
                         len(realm),
                         ctypes.c_char_p(realm),
                         ctypes.c_char_p(userid),
                         None)

    print principal_ptr.contents
    print 'building ccache'

    ccache_ptr = krb5_ctypes.krb5_ccache(krb5_ctypes._krb5_ccache())

    print 'initializing ccache'
    cc = ccache_ptr.contents
    cc.data = krb5_ctypes.krb5_pointer(ctypes.byref(krb5_ctypes.krb5_data()))
    for field_name, field_type in cc._fields_:
        print field_name, getattr(cc, field_name)

    krb5.krb5_cc_initialize(ctx._handle, ccache_ptr, principal_ptr.contents)
    ccache._handle = ccache_ptr

    print 'storing creds'

    krb5.krb5_cc_store_cred(ctx._handle, ccache._handle.contents,
                            creds._handle)


# Get a ticket for a specific service.
def get_service_ticket(userid, tgt_creds, service, realm='ATHENA.MIT.EDU'):
    # the service name must be a list
    svc_args = service.split('/')

    # create a context
    ctx = krb5.Context()
    tgt_creds = deserialize_cred(ctx, tgt_creds)

    # create a new in-memory credential cache to hold the credentials
    ccache = krb5.CCache(ctx)
    ccache_ptr = krb5_ctypes.krb5_ccache(krb5_ctypes._krb5_ccache())

    # c function to allocate the cache
    krb5.krb5_cc_new_unique(ctx._handle, ctypes.c_char_p('MEMORY'),
                            None, ccache_ptr)

    # Store the tgt credentials here
    krb5.krb5_cc_store_cred(ctx._handle, ccache_ptr.contents, tgt_creds._handle)

    # set the python object's c pointer
    ccache._handle = ccache_ptr

    principal = ctx.build_principal(realm, [userid])
    service = ctx.build_principal(realm, svc_args)
    creds = ccache.get_credentials(principal, service)

    return serialize_cred(ctx, creds)


# Get a ticket-granting ticket.
def get_tgt(userid, passwd, realm='ATHENA.MIT.EDU'):
    # create a context and credentials object
    # the PyCredentials object overrides davidben's implementation to prevent
    # python double-freeing memory
    ctx = krb5.Context()
    creds = krb5.PyCredentials(ctx)

    # the default constructor leaves this pointer null, so we have
    # to initialize it with a real struct
    creds._handle = krb5_ctypes.krb5_creds_ptr(krb5_ctypes.krb5_creds())
    principal = ctx.build_principal(realm, [userid])

    # initialize the credential options
    creds_opt = krb5_ctypes.krb5_get_init_creds_opt_ptr(
            krb5_ctypes._krb5_get_init_creds_opt())
    krb5.krb5_get_init_creds_opt_init(creds_opt)

    # make the ticket forwardable
    krb5.krb5_get_init_creds_opt_set_forwardable(creds_opt, ctypes.c_int(1))

    # get the credentials by passing in our info
    krb5.krb5_get_init_creds_password(
                    ctx._handle.contents,           # context
                    creds._handle,                  # credentials pointer
                    principal._handle.contents,     # principal struct
                    ctypes.c_char_p(passwd),        # password string
                    krb5_ctypes.krb5_prompter_fct_t(lambda: 0),  # krb5_prompter_fct*
                    None,                           # void* prompter_data
                    krb5_ctypes.krb5_deltat(0),     # start time: 0 == NOW
                    None,                           # in_tkt_service - name of TGS
                    creds_opt)                      # krb5_get_init_creds_opt_ptr

    return serialize_cred(ctx, creds)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        raise "Error: format is ./kerberos_client.py <username> <service>"
    uname, service = sys.argv[1:]

    # default to using afs
    sargs = service if service else 'afs/athena.mit.edu'

    # I won't store this I swear
    passwd = getpass.getpass()
    tgt_creds = get_tgt(uname, passwd)

    print 'TGT generated:'
    print
    print tgt_creds
    print

    svc_creds = get_service_ticket(uname, tgt_creds, sargs)

    print 'Service ticket generated:'
    print
    print svc_creds
    print

    store_service_ticket_jank(svc_creds, uname)
