from flask_oauthlib.provider import OAuth2Provider

app = Flask(__name__)
oauth = OAuth2Provider(app)