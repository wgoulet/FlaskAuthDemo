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
from authlib.flask.client import OAuth

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
    name='AzureAD',
    client_id=creds['clientid'],
    client_secret=creds['clientsecret'],
    access_token_url=creds['oauth2token'],
    access_token_params=None,
    authorize_url=creds['oauth2authz'],
    authorize_params=None,
    api_base_url=creds['apiendpoint'],
    client_kwargs={'scope': 'openid'}
)
azured = oauth.create_client('AzureAD')


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@app.route('/login',methods=['GET','POST'])
def login():
    redirect_uri = url_for('authorize', _external=True)
    pp.pprint(redirect_uri)
    return azured.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    token = azured.authorize_access_token()
    pp.pprint(token) 
    resp = azured.get('me')
    profile = resp.json()
    #pp.pprint(profile)
    user = FlaskDemoUser(id=profile['id'])
    user.name = profile['userPrincipalName']
    pp.pprint(user.id)
    pp.pprint(user.name)

    pickle.dump(user,open("{0}.db".format(user.id),'wb'))
    login_user(user)
    # do something with the token and profile
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
    u = FlaskDemoUser(userid)
    pp.pprint("login manager callback")
    pp.pprint(u.id)
    pp.pprint(u.name)
    user = pickle.load(open("{0}.db".format(userid),'rb'))
    
    return user

if __name__=="__main__":
    app.run(host='0.0.0.0')


