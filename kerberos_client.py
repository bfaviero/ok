from flask import Flask
from subprocess import Popen, PIPE
from base64 import urlsafe_b64encode
import os


def get_service_ticket(userid, service, tgt, realm='ATHENA.MIT.EDU'):
    tgt_cache = os.path.join('/tmp', urlsafe_b64encode(userid + '@' + realm),
            'krb5cc_tgt')
    ticket_file = os.path.join('/tmp', urlsafe_b64encode(userid + '@' + realm),
            'krb5cc_svc')
    keytab_file = os.path.join('/etc', urlsafe_b64encode(userid + '@' + realm))

    # write the tgt to a temporary cache file
    open(tgt_cache).write(tgt)

    # execute kinit, tell it to use cached tgt
    KINIT_PATH = '/usr/bin/kinit'
    kinit_args = [KINIT_PATH, '-f', '-c', ticket_file,'-k', keytab_file,
            '-I', tgt_cache, '-S', service, userid + '@' + realm]
    kinit = subprocess.Popen(kinit_args, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    kinit.wait()

    # delete the cached tgt
    os.remove(tgt_cache)

    # read the new ticket and delete it
    ticket = open(ticket_file).read()
    os.remove(ticket_file)

    return ticket


def get_tgt(userid, passwd, realm='ATHENA.MIT.EDU'):
    tgt_file = os.path.join('/tmp', urlsafe_b64encode(userid + '@' + realm),
            'krb5cc')
    keytab_file = os.path.join('/etc', urlsafe_b64encode(userid + '@' + realm))

    KINIT_PATH = '/usr/bin/kinit'
    kinit_args = [KINIT_PATH, '-f', '-c', tgt_file, '-k', keytab_file, userid + '@' + realm]

    # exec kinit
    kinit = subprocess.Popen(kinit_args, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    kinit.stdin.write(passwd + '\n')    # write password
    kinit.wait()                        # wait for completion

    # get the generated tgt
    tgt = open(tgt_file).read()
    os.remove(tgt_file)     # delete cached tgt

    return tgt
