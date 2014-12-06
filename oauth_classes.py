import json
import pdb
from ok_crypto import Cipher
import SERVER_CONFIG as CONFIG
from datetime import datetime, timedelta
import pickle

class Client():
    def __init__(self, client_id, client_secret, _redirect_uris):
        self.client_id = client_id
        self.client_secret = client_secret
        self._redirect_uris = _redirect_uris
        self.default_scopes = ['tgt']

    def save(self):
        with open(CONFIG.clients_db_file, 'r') as db:
            clients = pickle.load(db)

        with open(CONFIG.clients_db_file, 'w') as db:

            clients[self.client_id] = {
                'client_id'     : self.client_id,
                'client_secret': self.client_secret,
                '_redirect_uris': self._redirect_uris
            }

            pickle.dump(clients, db)
        
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
    def get(client_id):
        with open(CONFIG.clients_db_file, 'r') as db:
            clients = pickle.load(db)

        if client_id not in clients:
            return None

        client = clients[client_id]

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

    def delete(self):
    	#no need to delete since we never saved it
    	return True



class Token():
    def __init__(self, tgt, client_id, user, redirect_uri, expires):
        self.tgt = tgt
        self.client_id = client_id
        self.user = user
        self.redirect_uri = redirect_uri
        self.expires = expires
        self.scopes = ['tgt']

    def encrypt_to_string(self, secret):
        code = json.dumps({
        	'tgt': self.tgt,
        	'client_id' : self.client_id,
            'user' : self.user,
        	'redirect_uri' : self.redirect_uri,
            'expires' : self.expires.strftime(CONFIG.time_fmt)
        	})

    	return Cipher.encrypt(code, secret)


    @staticmethod
    def decrypt(enc, secret):
    	code = Cipher.decrypt(enc, secret)

    	vals = json.loads(code)

    	tgt = vals['tgt']
        client_id = vals['client_id']
        user = vals['user']
        redirect_uri = vals['redirect_uri']
    	expires = datetime.strptime( vals['expires'], CONFIG.time_fmt)

        return Token(tgt, client_id, user, redirect_uri, expires)

