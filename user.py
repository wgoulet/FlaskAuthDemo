from flask import Flask, Response, redirect, url_for, request, session, abort
from flask_login import LoginManager, UserMixin, \
                                        login_required, login_user, logout_user 

class FlaskDemoUser(UserMixin):
    def __init__(self,id):
        self.id = id
        self.name = None
        self.groups = []
