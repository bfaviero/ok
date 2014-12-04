from flask import Flask, redirect, url_for, render_template, session
from flask.ext.sqlalchemy import SQLAlchemy
from oauth import OAuthSignIn
import pdb
import CONFIG



app = Flask(__name__)
app.config['OAUTH_CREDENTIALS'] = {
    'facebook': {
        'id': '403910233098150',
        'secret': '76902abc26b1c5e12907792103161788'
    },
    'ok_server' : {
        'id' : 'test_client_1',
        'secret' : CONFIG.client_secret
    }
}


# class User(UserMixin, db.Model):
#     __tablename__ = 'users'
#     id = db.Column(db.Integer, primary_key=True)
#     social_id = db.Column(db.String(64), nullable=False, unique=True)
#     email = db.Column(db.String(64), nullable=True)



@app.route('/')
def index():
    return render_template('index.html')

def index_url():
    return url_for('index')


@app.route('/authenticated')
def authenticated():
    if 'username' not in session:
        return redirect(index_url())

    return render_template('authenticated.html')

def authenticated_url():
    return url_for('authenticated')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(index_url())


@app.route('/authorize/<provider>')
def oauth_authorize(provider):
    oauth = OAuthSignIn.get_provider(provider)
    return oauth.authorize()


@app.route('/callback/<provider>')
def oauth_callback(provider):
    # if not current_user.is_anonymous():
    #     return redirect(index_url())
    # if social_id is None:
    #     flash('Authentication failed.')
    #     return redirect(index_url())
    # user = User.query.filter_by(social_id=social_id).first()
    # if not user:
    #     user = User(social_id=social_id, email=email)
    #     db.session.add(user)
    #     db.session.commit()
    # login_user(user, True)
    oauth = OAuthSignIn.get_provider(provider)
    # pdb.set_rtace()
    res = oauth.callback()
    session['authenticated'] = True
    session['username'] = res['username']
    session['tgt'] = res['token']
    print 'successfully authenticated: ' + res['username']
    return redirect(authenticated_url())


if __name__ == '__main__':
    # db.create_all()
    app.secret_key = CONFIG.secret_key
    app.run(port=5001, debug=True)