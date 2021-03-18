from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
import jwt
import os
from flask_marshmallow import Marshmallow
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

app.config['SECRET_KEY']= 'Secret'
app.config['SQLALCHEMY_DATABASE_URI']= 'sqlite:///' + os.path.join(basedir, 'database.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']= True

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(50), unique = True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(80), unique = True)
    password = db.Column(db.String(50))

def token_required(f): 
    @wraps(f) 
    def decorated(*args, **kwargs): 
        token = None
        if 'x-access-token' in request.headers: 
            token = request.headers['x-access-token'] 
        if not token: 
            return jsonify('Token is missing !!')
   
        try:  
            # data = jwt.decode(token, app.config['SECRET_KEY']) 
            user = User.query.filter_by(user_id = user_id).first() 
        except: 
            return jsonify('Token is invalid !!')
        return  f(user, *args, *kwargs) 
   
    return decorated 

@app.route('/user', methods=['GET'])
@token_required
def users():
    users = User.query.all()
    output = [] 
    for user in users:  
        output.append({ 
            'public_id': user.user_id, 
            'name' : user.name, 
            'email' : user.email 
        }) 
   
    return jsonify({'users': output}) 


@app.route('/user/login', methods =['POST']) 
def login(): 
    email = request.json['email']
    password = request.json['password'] 

    if not email or not password: 
        return make_response("Login required !!") 
   
    user = User.query.filter_by(email = email).first() 
   
    if not user: 
        return make_response("User does not exist !!") 
   
    if check_password_hash(user.password, password): 
        token = jwt.encode({ 
            'user_id': user.user_id, 
            'exp' : datetime.utcnow() + timedelta(minutes = 30) 
        }, app.config['SECRET_KEY']) 
   
        return make_response(jsonify({'token' : token})) 
    return make_response("Wrong Password !!" )  
   
# signup route 
@app.route('/user/signup', methods =['POST']) 
def signup(): 
    name = request.json['name']
    email = request.json['email']
    password = request.json['password']

    user = User.query.filter_by(email = email).first() 
    if not user: 
        user = User( 
            user_id = str(uuid.uuid4()), 
            name = name, 
            email = email, 
            password = generate_password_hash(password) 
        ) 
        db.session.add(user) 
        db.session.commit() 
   
        return make_response('Successfully registered.') 
    else: 
        return make_response('User already exists. Please Log in.')

   
 
   
if __name__ == "__main__": 
    app.debug = True
    app.run() 

