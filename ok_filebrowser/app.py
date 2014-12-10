from flask import Flask, redirect, url_for, render_template, session, Response, request
from werkzeug import secure_filename
from flask.ext.sqlalchemy import SQLAlchemy
from oauth import OAuthSignIn
import pdb
import CLIENT_CONFIG as CONFIG
from OpenSSL import SSL
import cgi
import json
import elFinder

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

@app.route('/connector',methods=['GET', 'POST'])
def connector():


    # configure per request connector options
    user = session['username']
    root = '/afs/athena.mit.edu/user/%s/%s/%s' % (user[0], user[1], user)

    print root

    # kerberos_client.store_service_ticket_jank(session['afs_ticket'])

    opts = {''
    ## required options
    # 'root': '/path/to/files', # full path to your files
    # 'URL': 'http://mydomain.tld/path/to/files' # can be absolute or relative
    'root': root,
    'URL': 'http://localhost:5001'+root,
    ## other options
    # 'debug': True,
    }


    # init connector and pass options
    elf = elFinder.connector(opts)

    # fetch only needed GET/POST parameters
    httpRequest = {}
    files = []
    if request.method == 'POST':
        form = request.form
        files = request.files
    elif request.method == 'GET':
        form = request.args
    for field in elf.httpAllowedParameters:
        if field in form:
            httpRequest[field] = form.get(field)

            # Django hack by Kidwind
            if field == 'targets[]' and hasattr(form, 'getlist'):
                httpRequest[field] = form.getlist(field)

        # handle CGI upload
        if field == 'upload[]' and len(files) !=  0:
            upFiles = {}
            cgiUploadFiles = files['upload[]']
            if not isinstance(cgiUploadFiles, list):
                cgiUploadFiles = [cgiUploadFiles]
            for up in cgiUploadFiles:
                if up.filename:
                    upFiles[up.filename] = up.stream # pack dict(filename: filedescriptor)
            httpRequest[field] = upFiles
            httpRequest['cmd'] = 'upload'


    # run connector with parameters
    status, header, response = elf.run(httpRequest)

    # get connector output and print it out
    # code below is tested with apache only (maybe other server need other method?)
    res = ""
    # if status == 200:
    #     res +=  'Status: 200' + '\n'
    # elif status == 403:
    #     res += 'Status: 403' + '\n'
    # elif status == 404:
    #     res += 'Status: 404' + '\n'

    # if len(header) >= 1:
    #     for h, v in header.iteritems():
    #         res += h + ': ' + v  + '\n'
    # res += '\n'

    if not response is None and status == 200:
        # send file
        if 'file' in response and isinstance(response['file'], file):
            res +=  response['file'].read() + '\n'
            response['file'].close()
        # output json
        else:
            res +=  json.dumps(response, indent = True)  + '\n'

    # kerberos_client.clear_service_ticket(session)

    return Response(res, status = status, mimetype = 'application/json')

@app.route('/authenticated')
def authenticated():
    if 'afs_ticket' not in session:
        return redirect(url_for('index'))



    return render_template('filebrowser.html')

@app.route('/logout')
def logout():
    session.clear()
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
    session['afs_ticket'] = oauth_session.get('/ticket/AFS').json()["ticket"]

    return redirect(url_for('authenticated'))


if __name__ == '__main__':
    # db.create_all()
    app.secret_key = CONFIG.secret_key
    # context = SSL.Context(SSL.PROTOCOL_TLSv1_2)
    app.run(port=5001, debug=True, host='0.0.0.0', ssl_context='adhoc')
