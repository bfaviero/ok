import json
import pdb
from ok_crypto import Cipher
import CONFIG

class Client():
    def __init__(self, _id, secret, _redirect_uris):
        self._id = _id
        self.secret = secret
        self._redirect_uris = _redirect_uris
        self.default_scopes = ['tgt']

    def save(self, mongo):
        mongo.clients.insert({
        	'_id' : self._id,
            'secret': self.secret,
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
        client =  mongo.clients.find_one({"_id": client_id})
        print client
        # pdb.set_trace()
        return Client(**client)

class Grant():
    def __init__(self, username, password, client_id, tgt):
        self.username = username
        self.password = password
        self.client_id = client_id
        self.tgt = tgt
        # self.redirect_uri = redirect_uri
        # self.expires = expires
        # pdb.set_trace()
        self.scopes = ["tgt"]

    def encrypt_to_string(self, secret):
        code = json.dumps({
        	'username':username,
        	'password' : password,
        	'client_id' : client_id,
        	'tgt' : tgt,
        	})

    	return Cipher.encrypt(code, secret)


    @staticmethod
    def decrypt(enc, secret):
    	code = Cipher.decrypt(enc, secret)

    	vals = json.load(code)

    	username = vals['username']
    	password = vals['password']
    	client_id = vals['client_id']
    	tgt = vals['tgt']

        return Grant(username, password, client_id, tgt)

    def delete(self, mongo):
    	#no need to delete since we never saved it
    	return True



class Token():
    def __init__(self, tgt, client_id, username):
        self.tgt = tgt
        #self.expires = expires
        self.client_id = client_id
        self.username = username

        self.access_token = json.dumps({
        	'tgt' : tgt,
        	'client_id' : client_id,
        	'username':username
        	})

    def save(mongo):
        mongo.tokens.insert({
                'access_token' : self.access_token,
                'tgt' : self.tgt,
                'client_id' : self.client_id,
                'username'   : self.username
            })

    @staticmethod
    def find(mongo, query):
        return mogno.tokens.find(query)

    @staticmethod
    def get(mongo, token):
        mongo.tokens.find_one({"access_token": token})

	def encrypt(self, secret):
		access_token = Cipher.encrypt(self.access_token, secret)
        return EncryptedToken(access_token)

