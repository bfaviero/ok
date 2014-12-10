import sys
import shutil
import getpass
import lib.krb5 as krb5
import lib.krb5_ctypes as krb5_ctypes
import ctypes
import binascii
import ctypes
from base64 import urlsafe_b64encode, urlsafe_b64decode
import json

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
