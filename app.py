from flask import Flask,request,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_jwt_extended import create_access_token,JWTManager,get_jwt_identity,jwt_required,get_jwt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded
import os
from dotenv import load_dotenv
from datetime import timedelta

load_dotenv()

app = Flask(__name__)
CORS(app)

limiter = Limiter(app=app, key_func=get_remote_address)
@app.errorhandler(RateLimitExceeded)
def handle_rate_limit(e):
    return jsonify({"error": "too many attempts, please try again later"}), 429

app.config['SECRET_KEY']=os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI']=os.environ.get('DATABASE_URL')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=2)

db=SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt=JWTManager(app)

class User(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    email_id=db.Column(db.String(200),nullable=False,unique=True)
    hashed_password=db.Column(db.String(200),nullable=False)

class Files(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    user_id=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)
    file_name=db.Column(db.String(150),nullable=False)
    content=db.Column(db.String(500),nullable=False)

class TokenBlocklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True, unique=True)

with app.app_context():
    db.create_all()

@app.route('/register',methods=['POST'])
def register():
    data=request.get_json()
    email_id=data.get('email')
    password=data.get('password')

    if not email_id or not password:
        return jsonify({'error':'email id and password required'}),400

    existing_user = User.query.filter_by(email_id=email_id).first()
    if existing_user:
        return jsonify({"error": "registration failed"}), 400

    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(email_id=email_id, hashed_password=hashed_pw)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "user registered"}), 201

@app.route('/login',methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data=request.get_json()
    email_id=data.get('email')
    password=data.get('password')

    if not email_id or not password:
        return jsonify({'error':'email id and password required'}),400

    existing_user = User.query.filter_by(email_id=email_id).first()
    if existing_user and bcrypt.check_password_hash(existing_user.hashed_password, password):
        access_token=create_access_token(identity=str(existing_user.id))
        return jsonify({"message":"login successful", "access_token": access_token,"token": access_token}), 200
    else:
        return jsonify({"error": "login failed"}), 400

@app.route('/me', methods=['GET'])
@jwt_required()
def me():
    current_user_id = get_jwt_identity()
    user = User.query.get(int(current_user_id))
    if not user:
        return jsonify({"error": "user not found"}), 404
    else:
        return jsonify({"id": user.id, "email_id": user.email_id}), 200



@jwt.token_in_blocklist_loader
def check_blocklist(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    token = TokenBlocklist.query.filter_by(jti=jti).first()
    return token is not None

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    revoked_token = TokenBlocklist(jti=jti)
    db.session.add(revoked_token)
    db.session.commit()
    return jsonify({"message": "logout successful"}), 200

@app.route('/files', methods=['GET'])
@jwt_required()
def files():
    current_user_id = get_jwt_identity()
    user = User.query.get(int(current_user_id))
    files = Files.query.filter_by(user_id=int(user.id)).all()
    return jsonify([{"id": f.id, "file_name": f.file_name} for f in files]), 200

@app.route('/files', methods=['POST'])
@jwt_required()
def add_file():
    user_id = get_jwt_identity()
    data = request.get_json()
    new_file = Files(user_id=int(user_id), file_name=data.get('file_name'), content=data.get('content'))
    db.session.add(new_file)
    db.session.commit()
    return jsonify({"message": "file added"}), 201

@app.route('/files/<int:file_id>', methods=['GET'])
@jwt_required()
def get_file(file_id):
    user_id = get_jwt_identity()
    file = Files.query.get(file_id)
    if not file:
        return jsonify({"error": "file not found"}), 404
    if file.user_id != int(user_id):
        return jsonify({"error": "access denied"}), 403
    return jsonify({"id": file.id, "file_name": file.file_name, "content": file.content}), 200


if __name__ == "__main__":
    app.run(debug=True)

