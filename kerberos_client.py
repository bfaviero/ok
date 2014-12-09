import sys
import shutil
import getpass
import lib.krb5 as krb5
import lib.krb5_ctypes as krb5_ctypes
import ctypes
import binascii
import ctypes
#import IPython
import base64
import json
from base64 import urlsafe_b64encode, urlsafe_b64decode

def store_service_ticket_jank(creds, userid, realm='ATHENA.MIT.EDU'):
    old_user = 'bcyphers'
    old_realm = 'ATHENA.MIT.EDU'
    with open('krb5cc_1000', 'r') as old:
        new = open('/tmp/krb5cc_1000', 'w')
        for line in old:
            new.write(line.replace(old_user, userid).replace(old_realm, realm))
        new.close()

    ctx = krb5.Context()
    ccache = ctx.cc_default()

    principal_ptr = krb5_ctypes.krb5_principal(
                        krb5_ctypes.krb5_principal_data())

    krb5.krb5_cc_store_cred(ctx._handle, ccache._handle.contents,
                            creds._handle)

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
    krb5.krb5_cc_initialize(ctx._handle, ccache_ptr, principal_ptr.contents)
    ccache._handle = ccache_ptr

    print 'storing creds'

    krb5.krb5_cc_store_cred(ctx._handle, ccache._handle.contents,
                            creds._handle)


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

    return creds


SERIALIZE = 1
DESERIALIZE = 2
def serialize_or_deserialize_cred(context_obj, arg,s_or_d):
	"""helper function for (de)serialization"""

	context = context_obj._handle

	PTR = krb5_ctypes.ctypes.POINTER # takes type and outputs type
	ptr = krb5_ctypes.ctypes.pointer # takes var and outputs var

	auth_context = krb5_ctypes.krb5_auth_context()
	krb5.krb5_auth_con_init(context,ptr(auth_context))
	try:
		# we don't need replay protection for this data
		# and we don't want to have to maintain a replay cache
		krb5.krb5_auth_con_setflags(context, auth_context, 0)

		enctype = krb5_ctypes.krb5_enctype()

		# we use aes128 becasue its fast on modern computers
		# and we don't care about encryption security here because for all
		# we care, we could return the data unencrypted
		krb5.krb5_string_to_enctype("aes128-cts",ptr(enctype))


		# kerberos only exports/imports encrypted creds
		# but we do encryption at another layer of our design
		# so we just use dummy encryption keys and salts here
		string = krb5_ctypes.krb5_data()
		string.data = ctypes.cast(ctypes.c_char_p("asdf"),PTR(ctypes.c_char))
		string.length=5 # we include the null terminator

		salt = krb5_ctypes.krb5_data()
		salt.data = ctypes.cast(ctypes.c_char_p("asdf"),PTR(ctypes.c_char))
		salt.length=5 # we include the null terminator

		key = krb5_ctypes.krb5_keyblock()
		krb5.krb5_c_string_to_key(context, enctype, ptr(string), ptr(salt),
					  ptr(key))
		try:
			if s_or_d == SERIALIZE:
				# setup pcreds
				pcreds = arg._handle

				# setup ppdata
				pdata = PTR(krb5_ctypes.krb5_data)()
				ppdata = ptr(pdata)


				krb5.krb5_auth_con_setsendsubkey(context, auth_context, key)

				krb5.krb5_mk_1cred(context, auth_context, pcreds, ppdata, None)
				try:
					encoded_cred = binascii.hexlify(bytearray(
						  [pdata.contents.data[i]
						   for i in range(pdata.contents.length)] ))
					return encoded_cred
				finally:
					krb5.krb5_free_data(context, pdata)
			elif s_or_d == DESERIALIZE:
				# setup pcreddata
				databytes = list(binascii.unhexlify(arg))
				c_databytes = (ctypes.c_char*len(databytes))(*databytes)
				creddata = krb5_ctypes.krb5_data()
				creddata.data = ctypes.cast(c_databytes, PTR(ctypes.c_char))
				creddata.length = len(databytes)
				pcreddata = ptr(creddata)

				# setup pppcreds
				ppcreds = PTR(PTR(krb5_ctypes.krb5_creds))()
				pppcreds = ptr(ppcreds)

				krb5.krb5_auth_con_setrecvsubkey(context, auth_context, key)

				krb5.krb5_rd_cred(context, auth_context, pcreddata,
						  pppcreds, None)
				try:
					creds = ppcreds.contents[0]
					creds_obj = krb5.Credentials(context_obj)
					krb5.krb5_copy_creds(context, ptr(creds),
							     ptr(creds_obj._handle))
					return creds_obj

				finally:
					krb5.krb5_free_tgt_creds(context, ppcreds)
		finally:
			krb5.krb5_free_keyblock_contents(context,ptr(key))
	finally:
		krb5.krb5_auth_con_free(context, auth_context)


def serialize_cred(context_obj, creds_obj):
	"""Takes a Context and Credentials object (krb5.py) and returns a hex serialized
	version of the credentials object suitable for importing with deserialize_cred"""
	return serialize_or_deserialize_cred(context_obj,creds_obj,SERIALIZE)


def deserialize_cred(context_obj, encoded_cred):
	"""Takes a Context object (krb5.py) and a hex encoded Credential object created by
	serailize_cred and returns a Credentials object created via deserialization."""
	return serialize_or_deserialize_cred(context_obj,encoded_cred,DESERIALIZE)


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

    # example useage of serialize_cred and deserialize_cred:
    #ctx = krb5.Context()

    #ser_cred = serialize_cred(ctx, tgt_creds)
    #print ser_cred
    #print deserialize_cred(ctx, ser_cred).to_dict()

    svc_creds = get_service_ticket(uname, tgt_creds, svc_args=sargs)

    print
    print 'Service ticket generated:'
    print
    print svc_creds.to_dict()
    print

    store_service_ticket_jank(svc_creds, uname)

