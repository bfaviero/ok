class Client():
	def __init__(self, client_id, secret, _redirect_uris):
	    self.client_id = "example_app"
	    self.client_secret = "abc123"
	    _redirect_uris = ["secret_callback"]

	def save(self, mogno):
		mongo.clients.insert({
			'client_id': client_id,
			'secret':secret,
			'_redirect_uris': _redirect_uris
		})

		return self

	@staticmethod
	def get(mongo, client_id):
		client =  mongo.clients.find_one({"client_id": client_id})
    	return Client(client**)

    @property
    def client_type(self):
        if self.is_confidential:
            return 'confidential'
        return 'public'

    @property
    def redirect_uris(self):
        if self._redirect_uris:
            return self._redirect_uris.split()
        return []

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0]

class Grant():
	def __init__(self, user_id, client_id, code, redirect_uri, expires):
   		self.user_id = user_id
   		self.client_id = client_id
   		self.code = code
   		self.redirect_uri = redirect_uri
   		self.expires = expires

   	def save(self, mongo):
   		mongo.clients.insert({
   			'_id': client_id,
   			'secret':secret,
   			'_redirect_uris':  _redirect_uris
   		})

	@staticmethod
	def get(mogno, client_id):
		grant =  mongo.grants.find_one({'client_id':client_id, 'code':code})
    	return Grant(grant**)

    def delete(self):
        mongo.grants.remove({'client_id':client_id, 'code':code})
        return self


class Token(db.Model):
	def __init__(self, access_token, refresh_token, token_type, expires, client_id, user_id):
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
				'token_type'	: self.token_type
				'expires'	: self.expires,
				'client_id'	: self.client_id,
				'user_id'	: self.user_id
			})

	@staticmethod
	def find(mongo, query):
		return mogno.tokens.find(query)

	@staticmethod
	def get(mongo, token):
		mongo.tokens.find_one({"access_token": token})

    def delete(self):
        mongo.remove({'access_token': self.access_token})
        return self