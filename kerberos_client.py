from flask import Flask
from subprocess import Popen, PIPE
import base64
import json
import pycurl
import StringIO
import sys
import getpass
from flask import Flask
from subprocess import Popen, PIPE
from base64 import urlsafe_b64encode, urlsafe_b64decode
# import gssapi
import os
import subprocess
import lib.krb5 as krb5
import lib.krb5_ctypes as krb5_ctypes
import ctypes
import lib.gss as gss
import IPython


# For testing
def acquire_creds(realm='ATHENA.MIT.EDU', svc_name=['afs', 'athena.mit.edu']):
    # Get a context, and load the credential cache.
    ctx = krb5.Context()
    ccache = ctx.cc_default()

    # Get principal names.
    principal = ccache.get_principal()

    service = ctx.build_principal(realm, svc_name)
    creds = ccache.get_credentials(principal, service)
    return creds


# Get a ticket for a specific service.
def get_service_ticket(userid, tgt_creds, svc_args,
        realm='ATHENA.MIT.EDU'):

    # use davidben's handy c library wrappers, in lib/
    ctx = krb5.Context()

    # create a new in-memory ccache to hold the credentials
    ccache = krb5.CCache(ctx)
    ccache_ptr = krb5_ctypes.krb5_ccache(krb5_ctypes._krb5_ccache())

    print 'creating new ccache'
    krb5.krb5_cc_new_unique(ctx._handle, ctypes.c_char_p('MEMORY'),
                            None, ccache_ptr)

    # Store the tgt credentials here
    print 'storing credentials'
    krb5.krb5_cc_store_cred(ctx._handle, ccache_ptr.contents, tgt_creds._handle)
    ccache._handle = ccache_ptr

    print 'getting client principal:',
    principal = ctx.build_principal(realm, [userid])

    print principal

    print 'building service principal:',
    service = ctx.build_principal(realm, svc_args)
    print service

    print 'loading creds'
    creds = ccache.get_credentials(principal, service)

    return creds


# Get a ticket-granting ticket.
def get_tgt(userid, passwd, realm='ATHENA.MIT.EDU'):
    ctx = krb5.Context()
    creds = krb5.Credentials(ctx)

    # Not sure why the default constructor leaves this pointer null
    creds._handle = krb5_ctypes.krb5_creds_ptr(krb5_ctypes.krb5_creds())
    principal = ctx.build_principal(realm, [userid])

    # initialize the credential options
    creds_opt = krb5_ctypes.krb5_get_init_creds_opt_ptr(
            krb5_ctypes._krb5_get_init_creds_opt())
    krb5.krb5_get_init_creds_opt_init(creds_opt)

    krb5.krb5_get_init_creds_opt_set_forwardable(creds_opt, ctypes.c_int(1))

    # get the credentials by passing in our info
    krb5.krb5_get_init_creds_password(
                    ctx._handle.contents,           # context
                    creds._handle,                  # credentials pointer
                    principal._handle.contents,     # principal struct
                    ctypes.c_char_p(passwd),        # password string
                    #ctypes.byref(krb5_ctypes.krb5_prompter_posix), # krb5_prompter_fct*
                    krb5_ctypes.krb5_prompter_fct_t(lambda: 0),  # krb5_prompter_fct*
                    None,                           # void* prompter_data
                    #ctypes.c_void_p(),             # void* prompter_data
                    krb5_ctypes.krb5_deltat(0),     # start time: 0 == NOW
                    None,                                 # in_tkt_service - name of TGS
                    #ctypes.c_char_p('krbtgt/' + realm),  # in_tkt_service - name of TGS
                    creds_opt)  # krb5_get_init_creds_opt_ptr

    return creds


if __name__ == '__main__':
    if len(sys.argv) < 2:
        raise "Error: format is ./kerberos_client.py <username> <service>"
    uname, service = sys.argv[1:]

    # default to using afs
    sargs = service.split('/') if service else ['afs', 'athena.mit.edu']

    # I won't store this I swear
    passwd = getpass.getpass()
    tgt_creds = get_tgt(uname, passwd)

    print 'TGT generated:'
    print
    print tgt_creds.to_dict()
    print

    svc_creds = get_service_ticket(uname, tgt_creds, svc_args=sargs)

    print
    print 'Service ticket generated:'
    print
    print svc_creds.to_dict()

