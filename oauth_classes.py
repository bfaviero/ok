import json
import pdb
from ok_crypto import Cipher
import CONFIG

class Client():
    def __init__(self, client_id, client_secret, _redirect_uris):
        self.client_id = client_id
        self.client_secret = client_secret
        self._redirect_uris = _redirect_uris
        self.default_scopes = ['tgt']

    def save(self, mongo):
        mongo.clients.insert({
        	'client_id' : self.client_id,
            'client_secret': self.client_secret,
            '_redirect_uris': self._redirect_uris
        })

        return self

    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris#.split()
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

    @staticmethod
    def get(mongo, client_id):
        client =  mongo.clients.find_one({"client_id": client_id}, {'_id': False})
        print client
        # pdb.set_trace()
        return Client(**client)

class Grant():
    def __init__(self, user, password, client_id, redirect_uri):
        self.user = user
        self.password = password
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        # self.expires = expires
        # pdb.set_trace()
        self.scopes = ["tgt"]

    def encrypt_to_string(self, secret):
        code = json.dumps({
        	'user': self.user,
        	'password' : self.password,
        	'client_id' : self.client_id,
        	'redirect_uri' : self.redirect_uri,
        	})
        
        enc = Cipher.encrypt(code, secret)        
    	return  enc


    @staticmethod
    def decrypt(enc, secret):
    	code = Cipher.decrypt(enc, secret)

    	vals = json.loads(code)

    	user = vals['user']
    	password = vals['password']
    	client_id = vals['client_id']
    	redirect_uri = vals['redirect_uri']

        return Grant(user, password, client_id, redirect_uri)

    def delete(self, mongo):
    	#no need to delete since we never saved it
    	return True



class Token():
    def __init__(self, tgt, client_id, username):
        self.tgt = tgt
        self.client_id = client_id
        self.user = user

    def encrypt_to_string(self, secret):
        code = json.dumps({
        	'tgt': self.tgt,
        	'client_id' : self.client_id,
        	'user' : self.user,
        	})

    	return Cipher.encrypt(code, secret)


    @staticmethod
    def decrypt(enc, secret):
    	code = Cipher.decrypt(enc, secret)

    	vals = json.loads(code)

    	user = vals['user']
    	password = vals['tgt']
    	client_id = vals['client_id']

        return Token(tgt, client_id, user)

