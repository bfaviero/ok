from datetime import datetime, timedelta
from flask_oauthlib.provider import OAuth2Provider
from flask import Flask
from flask import session, request
from flask import render_template, redirect
import pymongo

from oauth_classes import Client, Grant, Token

app = Flask(__name__)
oauth = OAuth2Provider(app)


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