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
from base64 import urlsafe_b64encode
# import gssapi
import os
import subprocess
import lib.krb5 as krb5
import lib.krb5_ctypes as krb5_ctypes
import lib.gss as gss

# For testing
def acquire_creds(realm, service):
    # Get a context, and load the credential cache.
    ctx = krb5.Context()
    ccache = ctx.cc_default()

    # Get principal names.
    principal = ccache.get_principal()

    #zephyr = ctx.build_principal('ATHENA.MIT.EDU', ['zephyr', 'zephyr'])
    service = ctx.build_principal(realm, service)
    creds = ccache.get_credentials(principal, zephyr)
    return creds

# Get a ticket for a specific service.
def get_service_ticket(userid, service, tgt, realm='ATHENA.MIT.EDU'):
    # use davidben's handy c library wrappers to get the service ticket
    ctx = krb5.Context()
    ccache = krb5.CCache(ctx)

    # create a new in-memory ccache to hold the credentials
    krb5.krb5_cc_new_unique(ctx._handle,                # context
            krb5_ctypes.ctypes.c_char_p('MEMORY'),      # type
            krb5_ctypes.ctypes.c_char_p(),              # hint (blank)
            ccache._handle)
    #ccache = ctx.cc_default()

    # TODO: store tgt in ccache

    # Get principal names.
    principal = ccache.get_principal()

    service = ctx.build_principal(realm, service)
    creds = ccache.get_credentials(principal, zephyr)

    return ticket


# Get a ticket-granting ticket. This part works.
def get_tgt(userid, passwd, realm='ATHENA.MIT.EDU'):
    tmp_dir = os.path.join('/tmp', urlsafe_b64encode(userid + '@' + realm))
    if not os.path.exists(tmp_dir):
        os.mkdirs(tmp_dir)

    tgt_file = os.path.join(tmp_dir, 'krb5cc')
    keytab_file = os.path.join('/etc', urlsafe_b64encode(userid + '@' + realm))

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

    return tgt


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

