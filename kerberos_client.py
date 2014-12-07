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
import lib.gss as gss

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
def get_service_ticket(userid, svc_args, tgt_creds, realm='ATHENA.MIT.EDU'):
    # use davidben's handy c library wrappers to get the service ticket
    ctx = krb5.Context()

    # create a new in-memory ccache to hold the credentials
    ccache = krb5.CCache(ctx)
    krb5.krb5_cc_new_unique(ctx._handle,                # context
            krb5_ctypes.ctypes.c_char_p('MEMORY'),      # type
            krb5_ctypes.ctypes.c_char_p(),              # hint (blank)
            ccache._handle)

    # Store the tgt credentials here
    krb5.krb5_store_cred(ctx._handle,
            ccache._handle,
            tgt_creds._handle)

    #ccache = ctx.cc_default()

    # Store tgt in ccache file temporarily
    #tmp_dir = os.path.join('/tmp', urlsafe_b64encode(userid + '@' + realm))
    #if not os.path.exists(tmp_dir):
        #os.mkdirs(tmp_dir)
    #tgt_file = os.path.join(tmp_dir, 'krb5cc')

    #with open(tgt_file, 'w') as tgtf:
        #tgtf.write(urlsafe_b64decode(tgt))

    # Get principal names
    principal = ccache.get_principal()

    service = ctx.build_principal(realm, svc_args)
    creds = ccache.get_credentials(principal, service)

    #os.remove(tgt_file)

    return creds.to_dict()['ticket']


# XXX Broken
def get_tgt(userid, passwd, realm='ATHENA.MIT.EDU'):
    ctx = krb5.Context()
    krb5.krb5_get_init_creds_password(ctx._handle,
                                krb5_creds_ptr,
                                krb5_principal,
                                ctypes.c_char_p,
                                None, # krb5_prompter_ftc *
                                None, # void* prompter_data
                                krb5_deltat,
                                ctypes.c_char_p,
                                ctypes.POINTER(krb5_get_init_creds_opt)
                                ctypes.POINTER(krb5_ccache))


# Get a ticket-granting ticket. This part works.
def get_tgt_kinit(userid, passwd, realm='ATHENA.MIT.EDU'):
    tmp_dir = os.path.join('/tmp', urlsafe_b64encode(userid + '@' + realm))
    if not os.path.exists(tmp_dir):
        os.mkdirs(tmp_dir)

    tgt_file = os.path.join(tmp_dir, 'krb5cc')

    KINIT_PATH = '/usr/bin/kinit'
    kinit_args = [KINIT_PATH, '-f', '-c', tgt_file, userid + '@' + realm]
    print ' '.join(kinit_args)

    # exec kinit
    kinit = subprocess.Popen(kinit_args, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    print kinit.communicate(passwd + '\n')    # write password
    retcode = kinit.wait()                        # wait for completion

    if str(retcode) == '0':
        # get the generated tgt
        tgt = open(tgt_file, 'r').read()
        # delete cached tgt
        os.remove(tgt_file)
    else:
        raise Exception("Error: kinit returned code " + str(retcode))

    return urlsafe_b64encode(tgt)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise "Error: format is <username> <service>"
    uname, service = sys.argv[1:]
    passwd = getpass.getpass()
    tgt = get_tgt(uname, passwd)
    print 'TGT generation success. Ticket is as follows:'
    print
    print tgt
    print
    svc_ticket = get_service_ticket(uname, service, tgt)
    print
    print svc_ticket

