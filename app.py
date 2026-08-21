from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI']='postgresql://postgres:root@localhost:5432/login_db'
db=SQLAlchemy(app)

class User(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    email_id=db.Column(db.String(200),nullable=False,unique=True)
    hashed_password=db.Column(db.String(200),nullable=False)

class Files(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    user_id=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)
    file_name=db.Column(db.String(150),nullable=False)
    content=db.Column(db.String(500),nullable=False)

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)

