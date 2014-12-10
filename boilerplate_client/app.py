from flask import Flask, redirect, url_for, render_template, session
from flask.ext.sqlalchemy import SQLAlchemy
from oauth import OAuthSignIn
import pdb
import CLIENT_CONFIG as CONFIG
from OpenSSL import SSL
import pickle


app = Flask(__name__)
app.config['OAUTH_CREDENTIALS'] = {
    'ok_server' : {
        'id' : 'max_client_2',
        'secret' : "W6b4FSwb9J3jSo6IB+ijIXVEvqIOPLsN" #CONFIG.client_secret
    }
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/authenticated')
def authenticated():
    if 'username' not in session:
        return redirect(url_for('index'))

    s = pickle.loads(session['oauth_session'])

    return render_template('authenticated.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/authorize/<provider>')
def oauth_authorize(provider):
    oauth = OAuthSignIn.get_provider(provider)
    return oauth.authorize()


@app.route('/callback/<provider>')
def oauth_callback(provider):
    oauth = OAuthSignIn.get_provider(provider)
    oauth_session = oauth.callback()
    res = oauth_session.get('username').json()
    session['authenticated'] = True
    session['username'] = res['username']
    session['tgt'] = res['token']

    return redirect(url_for('authenticated'))


if __name__ == '__main__':
    # db.create_all()
    app.secret_key = CONFIG.secret_key

    context = SSL.Context(ssl.PROTOCOL_TLSv1_2)
    #context.use_privatekey_file('ssl.key')
    #context.use_certificate_file('ssl.crt')
    #app.run(port=5001, debug=True, host='0.0.0.0', ssl_context=context)
    app.run(port=5001, debug=True, host='0.0.0.0',ssl_context='adhoc')
