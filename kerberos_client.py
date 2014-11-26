from flask import Flask
from subprocess import Popen, PIPE
from base64 import urlsafe_b64encode
import sys
import getpass
# import gssapi
import os
import subprocess


# Get a ticket for a specific service. Doesn't work yet.
def get_service_ticket(userid, service, tgt, realm='ATHENA.MIT.EDU'):
    tmp_dir = os.path.join('/tmp', urlsafe_b64encode(userid + '@' + realm))
    if not os.path.exists(tmp_dir):
        os.makedirs(tmp_dir)

    tgt_cache = os.path.join(tmp_dir, 'krb5cc_tgt')
    ticket_file = os.path.join(tmp_dir, 'krb5cc_svc')
    keytab_file = os.path.join('/etc', urlsafe_b64encode(userid + '@' + realm))

    # write the tgt to a temporary cache file
    open(tgt_cache, 'w+').write(tgt)

    # execute kinit, tell it to use cached tgt
    KINIT_PATH = '/usr/bin/kinit'
    kinit_args = [KINIT_PATH, '-f', '-c', ticket_file, '-I', tgt_cache,
                  '-S', service, userid + '@' + realm]
    print ' '.join(kinit_args)
    kinit = subprocess.Popen(kinit_args, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    print kinit.wait()

    # delete the cached tgt
    os.remove(tgt_cache)

    # read the new ticket and then delete it
    ticket = open(ticket_file).read()
    os.remove(ticket_file)

    return ticket


# Get a ticket-granting ticket. This part works.
def get_tgt(userid, passwd, realm='ATHENA.MIT.EDU'):
    tmp_dir = os.path.join('/tmp', urlsafe_b64encode(userid + '@' + realm))
    if not os.path.exists(tmp_dir):
        os.makedir(tmp_dir)

    tgt_file = os.path.join(tmp_dir, 'krb5cc')
    keytab_file = os.path.join('/etc', urlsafe_b64encode(userid + '@' + realm))

    KINIT_PATH = '/usr/bin/kinit'
    kinit_args = [KINIT_PATH, '-f', '-c', tgt_file, userid + '@' + realm]
    print ' '.join(kinit_args)

    # exec kinit
    kinit = subprocess.Popen(kinit_args, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    print kinit.communicate(passwd + '\n')    # write password
    print kinit.wait()                        # wait for completion

    # get the generated tgt
    tgt = open(tgt_file, 'r').read()
    # delete cached tgt
    os.remove(tgt_file)

    return tgt


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise "Error: format is <username> <service>"
    uname, service = sys.argv[1:]
    passwd = getpass.getpass()
    tgt = get_tgt(uname, passwd)
    print tgt
    svc_ticket = get_service_ticket(uname, service, tgt)
    print 'success!'
    print
    print svc_ticket

