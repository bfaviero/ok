from datetime import datetime, timedelta
from flask import Flask
from flask import session, request
from flask import render_template, redirect
import pymongo
import kerberos_client
from flask_oauthlib.provider import OAuth2Provider

from oauth_classes import Client, Grant, Token, EncryptedToken
import CONFIG
import pdb

app = Flask(__name__)
oauth = OAuth2Provider(app)

@oauth.clientgetter
def load_client(client_id):
    print client_id
    return Client.get(mongo,client_id)

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
        return EncryptedToken(access_token=access_token).depcrypt(CONFIG.token_secret)

@oauth.tokensetter
def save_token(token, request, *args, **kwargs):
    #no need to save token
    return token

def tgt_token_generator(req):
    print req
    
    print req.body
    username = req.body['username']
    password = req.body['password']
    tgt = username + password  #kerberos_client.get_tgt(username, password)
    return Token(tgt).encrypt(CONFIG.secret)


app.config['OAUTH2_PROVIDER_TOKEN_GENERATOR'] = tgt_token_generator


@app.route('/oauth/authorize', methods=['GET', 'POST'])
# @require_login
@oauth.authorize_handler
def authorize(*args, **kwargs):
    if request.method == 'GET':
        print kwargs
        client_id = kwargs.get('client_id')
        client = Client.get(mongo, client_id)
        # pdb.set_trace()
        kwargs['client'] = client
        print kwargs
        kwargs['username'] = request.args.get('username')
        return render_template('authorize.html', **kwargs)

    confirm = request.form.get('confirm', 'no')
    return confirm == 'yes' 



@app.route('/ticket/<serice>')
@oauth.require_oauth('tgt')
def service_ticket(service_name):
    return kerberos_client.get_service_ticket(tgt, service_name)


def setup():
    mongo.drop_collection('clients')
    Client('test_client_1', "secret1", ['http://localhost:5001/secret_callback']).save(mongo)


if __name__ == '__main__':
    global mongo
    pymongo.MongoClient("localhost", 27017).drop_database('ok')
    mongo = pymongo.MongoClient("localhost", 27017).ok
    setup()
    app.debug = True
    app.run()   

    #http://localhost:5000/oauth/authorize?client_id=test_client_1&response_type=token&username=test_user