from datetime import datetime, timedelta
from flask import Flask
from flask import session, request
from flask import render_template, redirect
import pymongo
import kerberos_client
from flask_oauthlib.provider import OAuth2Provider
import logging
from oauth_classes import Client, Grant, Token
import CONFIG
import pdb

app = Flask(__name__)
oauth = OAuth2Provider(app)

logging.basicConfig(format='%(asctime)s : %(levelname)s : %(message)s', level=logging.INFO)


# @app.before_request
# def debug():
#     pdb.set_trace()

@oauth.clientgetter
def load_client(client_id):
    print client_id
    return Client.get(mongo,client_id)

@oauth.grantgetter
def load_grant(client_id, code):
    #code is our encrypted data structure
    g =  Grant.decrypt(code, CONFIG.secret)
    return g

@oauth.grantsetter
def save_grant(client_id, code, req, *args, **kwargs):
    #we don't save grant for security reasons
    return True

@oauth.tokengetter
def load_token(access_token=None, refresh_token=None):
    if access_token:
        return Token.depcrypt(access_token, CONFIG.secret)


@oauth.tokensetter
def save_token(token, request, *args, **kwargs):
    #no need to save token
    return token

def tgt_token_generator(req):
    code = req.body['code'] 
    g =  Grant.decrypt(code, CONFIG.secret)
    tgt = "test"#kerberos_client.get_tgt(g.user, g.password)
    redirect_uri = req.body['redirect_uri']
    token = Token(tgt, g.client_id, g.user, redirect_uri).encrypt_to_string(CONFIG.secret)
    print "token with tgt aquired for %s is %s" % (g.user, token)
    return token # .encrypt(CONFIG.secret1).access_token


app.config['OAUTH2_PROVIDER_TOKEN_GENERATOR'] = tgt_token_generator

def make_tgt(username, password):
    return username+password


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

@app.route('/oauth/token', methods=['POST'])
@oauth.token_handler
def access_token():
    return None


@app.route('/ticket/<serice>')
@oauth.require_oauth('tgt')
def service_ticket(service_name):
    return kerberos_client.get_service_ticket(tgt, service_name)


def setup():
    mongo.drop_collection('clients')
    Client('test_client_1', "secret_1", ['http://localhost:5001/callback/ok_server']).save(mongo)


if __name__ == '__main__':
    global mongo
    pymongo.MongoClient("localhost", 27017).drop_database('ok')
    mongo = pymongo.MongoClient("localhost", 27017).ok
    setup()
    app.debug = True
    app.run()

    #http://localhost:5000/oauth/authorize?client_id=test_client_1&response_type=code&username=test_user&redirect_uri=http%3A%2F%2Flocalhost%3A5001%2Fcallback
