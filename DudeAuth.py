from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
import bcrypt
from datetime import datetime, timedelta
import os
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your_jwt_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///dudeauth.db')
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)

jwt = JWTManager(app)
db = SQLAlchemy(app)
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
limiter = Limiter(key_func=get_remote_address, app=app)

class DudeUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    confirmed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    dude_level = db.Column(db.Integer, default=1)
    dude_points = db.Column(db.Integer, default=0)

class DudeRevokedToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(120), unique=True, nullable=False)

def send_dude_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_USERNAME']
    )
    mail.send(msg)

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    token = db.session.query(DudeRevokedToken.id).filter_by(jti=jti).scalar()
    return token is not None

def generate_dude_greeting():
    greetings = [
        "Welcome, dude!",
        "Sup, bro!",
        "Hey there, cool cat!",
        "What's hangin', dude?",
        "Yo, dude! Nice to see ya!"
    ]
    return random.choice(greetings)

@app.route('/dudeauth/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({"msg": "Missing username, email or password, dude!"}), 400

    hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
    
    if DudeUser.query.filter_by(username=data['username']).first() or DudeUser.query.filter_by(email=data['email']).first():
        return jsonify({"msg": "Whoa dude, this username or email already exists!"}), 400

    new_dude = DudeUser(username=data['username'], email=data['email'], password=hashed_password)
    db.session.add(new_dude)
    db.session.commit()

    token = s.dumps(data['email'], salt='email-confirm')
    confirm_url = f"http://127.0.0.1:5000/dudeauth/confirm_email/{token}"
    html = f"Hey dude! Click this rad link to confirm your email: <a href='{confirm_url}'>Confirm Email</a>"
    
    send_dude_email(data['email'], 'Confirm Your DudeAuth Email', html)
    return jsonify({"msg": "You're registered, dude! Check your email to confirm your account."}), 201

@app.route('/dudeauth/confirm_email/<token>', methods=['GET'])
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        return jsonify({"msg": "Bummer dude, the token has expired."}), 400
    except Exception:
        return jsonify({"msg": "Not cool, man. Invalid token."}), 400

    dude = DudeUser.query.filter_by(email=email).first()
    if dude and not dude.confirmed:
        dude.confirmed = True
        dude.dude_points += 10
        db.session.commit()
        return jsonify({"msg": "Radical! Email confirmed. You can now log in, dude."}), 200
    else:
        return jsonify({"msg": "Bummer, dude. Invalid token or already confirmed."}), 400

@app.route('/dudeauth/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"msg": "Dude, where's your username or password?"}), 400

    dude = DudeUser.query.filter_by(username=data['username']).first()

    if not dude or not bcrypt.checkpw(data['password'].encode('utf-8'), dude.password):
        return jsonify({"msg": "Not cool, dude. Bad username or password."}), 401

    if not dude.confirmed:
        return jsonify({"msg": "Chill out, dude. Confirm your email first."}), 403

    access_token = create_access_token(identity=dude.username)
    refresh_token = create_access_token(identity=dude.username, fresh=False)
    dude.last_login = datetime.utcnow()
    dude.dude_points += 5
    db.session.commit()
    
    greeting = generate_dude_greeting()
    return jsonify(greeting=greeting, access_token=access_token, refresh_token=refresh_token)

@app.route('/dudeauth/reset_password', methods=['POST'])
@limiter.limit("3 per hour")
def reset_password():
    email = request.json.get('email')
    if not email:
        return jsonify({"msg": "Dude, where's the email?"}), 400

    dude = DudeUser.query.filter_by(email=email).first()

    if not dude:
        return jsonify({"msg": "Bummer, dude. No user with this email."}), 404

    token = s.dumps(email, salt='password-reset')
    reset_url = f"http://127.0.0.1:5000/dudeauth/reset_password_confirm/{token}"
    html = f"Hey dude! Click this gnarly link to reset your password: <a href='{reset_url}'>Reset Password</a>"

    send_dude_email(email, 'Reset Your DudeAuth Password', html)
    return jsonify({"msg": "Chill, dude. Password reset email sent. Check your inbox."}), 200

@app.route('/dudeauth/reset_password_confirm/<token>', methods=['POST'])
def reset_password_confirm(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)
    except SignatureExpired:
        return jsonify({"msg": "Not cool, man. The token has expired."}), 400
    except Exception:
        return jsonify({"msg": "Bogus token, dude."}), 400

    dude = DudeUser.query.filter_by(email=email).first()
    if not dude:
        return jsonify({"msg": "Bummer, dude. Invalid token or user not found."}), 400

    new_password = request.json.get('new_password')
    if not new_password:
        return jsonify({"msg": "Dude, where's the new password?"}), 400

    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    dude.password = hashed_password
    db.session.commit()
    return jsonify({"msg": "Awesome, dude! Password has been reset."}), 200

@app.route('/dudeauth/protected', methods=['GET'])
@jwt_required()
def protected():
    current_dude = get_jwt_identity()
    return jsonify(logged_in_as=current_dude, msg="You're in the VIP area, dude!"), 200

@app.route('/dudeauth/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_dude = get_jwt_identity()
    new_access_token = create_access_token(identity=current_dude)
    return jsonify(access_token=new_access_token, msg="Here's your fresh token, dude!")

@app.route('/dudeauth/logout', methods=['DELETE'])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    revoked_token = DudeRevokedToken(jti=jti)
    db.session.add(revoked_token)
    db.session.commit()
    return jsonify({"msg": "Catch you later, dude! Successfully logged out."}), 200

@app.route('/dudeauth/dude_status', methods=['GET'])
@jwt_required()
def dude_status():
    current_dude = get_jwt_identity()
    dude = DudeUser.query.filter_by(username=current_dude).first()
    return jsonify({
        "dude_level": dude.dude_level,
        "dude_points": dude.dude_points,
        "msg": f"You're a level {dude.dude_level} dude with {dude.dude_points} radical points!"
    })

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
