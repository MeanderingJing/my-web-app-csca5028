#!/usr/bin/env python3


import os
from datetime import timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity



app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL','postgresql://myuser:mypassword@localhost:5436/mydatabase')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'your_jwt_secret_key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False       

# Initialize extensions
CORS(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# User model for authentication
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'
    
    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)
    

# Initialize the database


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    email = data.get("email")

    # Validate input
    if not username or not password or not email:
        return jsonify({"msg": "Username, password, and email are required"}), 400  
    
    # Check if username or email already exists
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already exists"}), 400
    
    # Hash the password and save the user
    new_user = User(username=username, email=email)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"msg": "User registered successfully"}), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    # Validate input
    if not username or not password:
        return jsonify({"msg": "Username and password are required"}), 400
    
    # Check if user exists and password is correct
    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid username or password"}), 401    
    
    # Create JWT token
    access_token = create_access_token(identity=str(user.id))
    return jsonify({'access_token': access_token, 'username': user.username}), 200


# @app.route("/")
# def main():
#     return '''
#      <form action="/echo_user_input" method="POST">
#          <input name="user_input">
#          <input type="submit" value="Submit!">
#      </form>
#      '''


# @app.route("/echo_user_input", methods=["POST"])
# def echo_input():
#     input_text = request.form.get("user_input", "")
#     return "You entered: " + input_text

@app.route("/echo_user_input", methods=["POST"])
@jwt_required()
def echo_input():
    data = request.get_json()
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404    
    input_text = data.get("user_input", "")
    return jsonify({"message": f"You entered: {input_text}", "username": user.username}), 200

@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    return jsonify({
        "username": user.username,
        "email": user.email
    }), 200

# if __name__ == "__main__":
#     with app.app_context():
#         db.create_all()
#     app.run(debug=True)

