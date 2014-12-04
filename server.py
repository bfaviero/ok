from datetime import datetime, timedelta
from flask import Flask
from flask import session, request, jsonify
from flask import render_template, redirect
import kerberos_client
from flask_oauthlib.provider import OAuth2Provider
import logging
from oauth_classes import Client, Grant, Token
import CONFIG
import pdb
from datetime import datetime, timedelta
import pickle 

app = Flask(__name__)
oauth = OAuth2Provider(app)

logging.basicConfig(format='%(asctime)s : %(levelname)s : %(message)s', level=logging.INFO)


# @app.before_request
# def debug():
#     pdb.set_trace()

@oauth.clientgetter
def load_client(client_id):
    return Client.get(client_id)

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
        return Token.decrypt(access_token, CONFIG.secret)


@oauth.tokensetter
def save_token(token, request, *args, **kwargs):
    #no need to save token
    return token

def tgt_token_generator(req):
    code = req.body['code'] 
    g =  Grant.decrypt(code, CONFIG.secret)
    tgt = 'test' #kerberos_client.get_tgt(g.user, g.password)
    redirect_uri = req.body['redirect_uri']
    expires = datetime.utcnow() + timedelta(seconds=100)
    token = Token(tgt, g.client_id, g.user, redirect_uri, expires).encrypt_to_string(CONFIG.secret)
    print "token with tgt aquired for %s is %s" % (g.user, token)
    return token 


app.config['OAUTH2_PROVIDER_TOKEN_GENERATOR'] = tgt_token_generator


@app.route('/oauth/authorize', methods=['GET', 'POST'])
# @require_login
@oauth.authorize_handler
def authorize(*args, **kwargs):
    if request.method == 'GET':
        print kwargs
        client_id = kwargs.get('client_id')
        client = Client.get(client_id)
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

@app.route('/username')
@oauth.require_oauth('tgt')
def username():
    token = request.oauth.Authorization[len("Bearer "):]
    t = Token.decrypt(token, CONFIG.secret)
    return jsonify(username = t.user, token=token)



def setup():
    with open(CONFIG.clients_db_file, 'w') as db:
        pickle.dump({}, db)
    Client('test_client_1', "secret_1", ['http://localhost:5001/callback/ok_server']).save()


if __name__ == '__main__':
    setup()
    app.debug = True
    app.run()

    #http://localhost:5000/oauth/authorize?client_id=test_client_1&response_type=code&username=test_user&redirect_uri=http%3A%2F%2Flocalhost%3A5001%2Fcallback
