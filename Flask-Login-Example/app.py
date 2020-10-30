"""Flask Login Example and instagram fallowing find"""

from flask import Flask, url_for, render_template, request, redirect, session
from instagram import getfollowedby, getname
from flask import Flask
from flask_pymongo import PyMongo
import bcrypt
from flask_jwt import JWT, jwt_required, current_identity
from werkzeug.security import safe_str_cmp
from flask_bcrypt import Bcrypt
from bson.json_util import dumps
from bson.objectid import ObjectId
from flask import jsonify, request
from werkzeug.security import generate_password_hash,check_password_hash

app = Flask(__name__)

app.secret_key = 'secretkey'
app.config['MONGO_URI'] = "mongodb://localhost:27017/sree01"

mongo = PyMongo(app)
data = mongo.db.user


class User(object):
    def __init__(self, username, password):
        self.username = username
        self.password = password

users = [User('sriram', 'abc@123'),User('sreekanth', 'xyz@123')]

username_table = {u.username: u for u in users}
def authenticate(username, password):
    user = username_table.get(username, None)
    if user and safe_str_cmp(user.password.encode('utf-8'), password.encode('utf-8')):
        return user



@app.route('/', methods=['GET', 'POST'])
def home():
    """ Session control"""
    if 'username' in session:
        return "Your  are login user it is " + session['username']
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login Form"""

    if request.method == 'POST':
        login_us = request.form.get('username').encode('utf-8')
        login_ps = request.form.get('username').encode('utf-8')
        corret_usr = mongo.db.user.find_one({'uname': login_us})
        print(login_us)
        if corret_usr is not None:
            session['username'] = request.form.get('username')
            return render_template('index.html')

    return render_template('login.html')

@app.route('/register/', methods=['GET', 'POST'])
def register():
    """Register Form"""
    if request.method == 'POST':
        print(request.form.get('username'))
        corrent_us = mongo.db.user.find_one({'uname': request.form.get('username').encode('utf-8')})
        print(corrent_us)
        if corrent_us is None:
            username = request.form.get('username').encode('utf-8')
            password = request.form.get('password').encode('utf-8')

            haspws = bcrypt.hashpw(password,bcrypt.gensalt())
            data = mongo.db.user.insert_one({'uname': username, 'psw': haspws})
            session['username'] = request.form.get('username')
            return redirect(url_for('login'))
        return 'This user is already exists!'
    return render_template('register.html')



if __name__ == '__main__':
    app.secret_key = 'secretkey'
    jwt = JWT(app, authenticate)
    app.run(host='127.0.0.1', port=5000, debug=True)