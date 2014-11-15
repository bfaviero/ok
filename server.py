from datetime import datetime, timedelta
from flask_oauthlib.provider import OAuth2Provider
from flask import Flask
from flask import session, request
from flask import render_template, redirect
import pymongo

app = Flask(__name__)
oauth = OAuth2Provider(app)


class Client():
	def __init__(self, client_id, secret, _redirect_uris, insert=False):
		#add check that client isn't already there
		if insert:
	    	mongo.clients.insert({'client_id': client_id, 'secret':secret, '_redirect_uris', _redirect_uris})
	    self.client_id = "example_app"
	    self.client_secret = "abc123"
	    _redirect_uris = ["secret_callback"]

	@staticmethod
	def get_client(self, mongo, client_id):
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
	def __init__(self, user_id, client_id, code, redirect_uri, expires, insert=False):
		if insert:
   			mongo.clients.insert({'_id': client_id, 'secret':secret, '_redirect_uris', _redirect_uris})

   		self.user_id = user_id
   		self.client_id = client_id
   		self.code = code
   		self.redirect_uri = redirect_uri
   		self.expires = expires

	@staticmethod
	def get_grant(self, mongo, client_id):
		grant =  mongo.grants.find_one({'client_id':client_id, 'code':code})
    	return Grant(grant**)

    def delete(self):
        mongo.grants.remove({'client_id':client_id, 'code':code})
        return self


class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(
        db.String(40), db.ForeignKey('client.client_id'),
        nullable=False,
    )
    client = db.relationship('Client')

    user_id = db.Column(
        db.Integer, db.ForeignKey('user.id')
    )
    user = db.relationship('User')

    # currently only bearer is supported
    token_type = db.Column(db.String(40))

    access_token = db.Column(db.String(255), unique=True)
    refresh_token = db.Column(db.String(255), unique=True)
    expires = db.Column(db.DateTime)
    _scopes = db.Column(db.Text)

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self

    @property
    def scopes(self):
        if self._scopes:
            return self._scopes.split()
        return []


@oauth.clientgetter
def load_client(client_id):
    return Client.get_client(client_id)

@oauth.grantgetter
def load_grant(client_id, code):
    return Grant.query.filter_by(client_id=client_id, code=code).first()

@oauth.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):
    # decide the expires time yourself
    expires = datetime.utcnow() + timedelta(seconds=100)
    grant = Grant(
        client_id=client_id,
        code=code['code'],
        redirect_uri=request.redirect_uri,
        _scopes=' '.join(request.scopes),
        user=get_current_user(),
        expires=expires
    )
    db.session.add(grant)
    db.session.commit()
    return grant


@oauth.tokengetter
def load_token(access_token=None, refresh_token=None):
    if access_token:
        return Token.query.filter_by(access_token=access_token).first()
    elif refresh_token:
        return Token.query.filter_by(refresh_token=refresh_token).first()


@oauth.tokensetter
def save_token(token, request, *args, **kwargs):
    toks = Token.query.filter_by(client_id=request.client.client_id,
                                 user_id=request.user.id)
    # make sure that every client has only one token connected to a user
    for t in toks:
        db.session.delete(t)

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
    db.session.add(tok)
    db.session.commit()
    return tok



if __name__ == '__main__':
    db.create_all()
    app.run()	