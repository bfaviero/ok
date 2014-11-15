from datetime import datetime, timedelta
from flask_oauthlib.provider import OAuth2Provider
from flask import Flask
from flask import session, request
from flask import render_template, redirect
import pymongo

app = Flask(__name__)
oauth = OAuth2Provider(app)


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


@oauth.clientgetter
def load_client(client_id):
    return Client.get(client_id)

@oauth.grantgetter
def load_grant(client_id, code):
    return Grant.get(client_id=client_id, code=code).first()

@oauth.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):
    # decide the expires time yourself
    GRANT_LIFETIME = 100
    expires = datetime.utcnow() + timedelta(seconds=GRANT_LIFETIME)
    grant = Grant(
        client_id=client_id,
        code=code['code'],
        redirect_uri=request.redirect_uri,
        _scopes=' '.join(request.scopes),
        user=get_current_user(),
        expires=expires,
        insert = True
    )
    return grant


@oauth.tokengetter
def load_token(access_token=None, refresh_token=None):
    if access_token:
        return Token.get(access_token=access_token)

@oauth.tokensetter
def save_token(token, request, *args, **kwargs):
    toks = Token.find({
    	'client_id':request.client.client_id,
        'user_id':request.user.id
    })
    # make sure that every client has only one token connected to a user
    for t in toks:
        mongo.tokens.remove(t)

    expires_in = token.pop('expires_in')
    expires = datetime.utcnow() + timedelta(seconds=expires_in)

    tok = Token(
        access_token=token['access_token'],
        refresh_token=token['refresh_token'],
        token_type=token['token_type'],
        _scopes=token['scope'],
        expires=expires,
        client_id=request.client.client_id,
        user_id=request.user.id,
    )
    tok.save(token)
    return tok



if __name__ == '__main__':
    db.create_all()
    app.run()	