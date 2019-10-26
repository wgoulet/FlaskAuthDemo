from flask import Flask, Response, redirect, url_for, request, session, abort, render_template
from flask_login import LoginManager, UserMixin, \
                                        login_required, login_user, logout_user 

from user import FlaskDemoUser
import os
import re
import sys
import pprint
import json

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

secret = creds['clientsecret']
pp.pprint(secret)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if password == userdict[username]:
            user = FlaskDemoUser(username)
            login_user(user)
            return redirect(request.args.get("next"))
        else:
            return abort(401)
    else:
        return Response('''
        <form action="" method="post">
        <p><input type=text name=username>
        <p><input type=password name=password>
        <p><input type=submit value=Login>
        </form>
        ''')
        
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
    return FlaskDemoUser(userid)

if __name__=="__main__":
    app.run(host='0.0.0.0')


