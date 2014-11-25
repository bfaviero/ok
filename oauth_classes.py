import pdb
from crypt import Cipher

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
    def __init__(self, user_id, client_id, code, redirect_uri, expires):
        self.user_id = user_id
        self.client_id = client_id
        self.code = code
        self.redirect_uri = redirect_uri
        self.expires = expires
        # self.scopes = ["tgt"]


    def save(self, mongo):
        mongo.clients.insert({
            '_id': client_id,
            'secret':secret,
            '_redirect_uris':  _redirect_uris
        })

    @staticmethod
    def get(mogno, client_id):
        grant =  mongo.grants.find_one({'client_id':client_id, 'code':code})
        return Grant(**grant)

    def delete(self, mongo):
        mongo.grants.remove({'client_id':self.client_id, 'code':self.code})
        return self



class Token():
    def __init__(self, access_token, expires, client_id, user_id):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.token_type = token_type
        self.expires = expires
        self.client_id = client_id
        self.user_id = user_id

    def save(mongo):
        mongo.tokens.insert({
                'access_token' : self.access_token,
                'refresh_token' : self.refresh_token,
                'token_type'    : self.token_type,
                'expires'   : self.expires,
                'client_id' : self.client_id,
                'user_id'   : self.user_id
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

class EncryptedToken():
	def __init__(self, access_token):
		self.access_token = access_token

	def decrypt(self, enc, secret):
		original_value = Cipher.decrypt(enc, secret)
        return original_value
