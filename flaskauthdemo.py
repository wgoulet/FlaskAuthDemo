from flask import Flask, Response, redirect, url_for, request, session, abort, render_template
from flask_login import LoginManager, UserMixin, \
                                        login_required, login_user, logout_user 

from user import FlaskDemoUser
import os
import re
import sys
import pprint
import json
import pickle
import requests
from authlib.integrations.flask_client import OAuth
import jwt

app = Flask(__name__)

app.config.update(
    DEBUG = True,
    SECRET_KEY = 'secret_xxx'
)


userdict = {}
with open('./passwd.txt','r') as file:
    for line in file:
        uname,passwd = line.rstrip().split(":")
        userdict[uname] = passwd

with open('./creds.txt','r') as file:
    creds = json.load(file)

pp = pprint.PrettyPrinter(stream=sys.stderr)
pp.pprint(userdict)

for key in creds:
    pp.pprint(key)
    pp.pprint(creds[key])

oauth = OAuth(app)

oauth.register(
    name='keycloak',
    client_id=creds['clientid'],
    client_secret=creds['clientsecret'],
    access_token_url=creds['oauth2token'],
    access_token_params=None,
    authorize_url=creds['oauth2authz'],
    authorize_params=None,
    api_base_url=creds['apiendpoint'],
    server_metadata_url=creds['openiddoc'],
    client_kwargs={'scope': 'openid profile groups'}
)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@app.route('/login',methods=['GET','POST'])
def login():
    redirect_uri = url_for('authorize', _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    token = oauth.keycloak.authorize_access_token()
    # Safe to use this without validating the token because authlib
    # already validated the token for me, using this method because
    # stable version of authlib doesn't seem to support decoding id_tokens
    pp.pprint("id token")
    pp.pprint(token['id_token'])
    pp.pprint("access token")
    pp.pprint(token['access_token'])
    idclaims = jwt.decode(token['id_token'],verify=False)
    pp.pprint("id claims")
    pp.pprint(idclaims)
    # Get user details from the access_token
    grouplist = []
    if 'groups' in idclaims.keys():
        for group in idclaims['groups']:
            grouplist.append(group)
    user = FlaskDemoUser(id=idclaims['sub'])
    user.name = idclaims['preferred_username']
    user.groups = grouplist
    user.claims = idclaims
    # Saving the user who logged in in a datafile I
    # can refer to later
    pickle.dump(user,open("{0}.db".format(user.id),'wb'))
    login_user(user)
    return redirect('/')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return Response("<p>Logged out</p>")

@app.route("/")
@login_required
def home():
    return render_template("home.html")

@login_manager.user_loader
def load_user(userid):
    pp.pprint("login manager callback")
    user = pickle.load(open("{0}.db".format(userid),'rb'))
    pp.pprint(user.id)
    pp.pprint(user.name)
    pp.pprint(user.groups)
    return user

if __name__=="__main__":
    app.run(host='0.0.0.0')


