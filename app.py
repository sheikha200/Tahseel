from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
import hashlib
import re
import os
from cryptography.fernet import Fernet
import logging

# ======================
# APP SETUP
# ======================
app = Flask(__name__)
app.secret_key = "leen_secure_key"

# ======================
# LOGGING
# ======================
logging.basicConfig(filename='security.log', level=logging.INFO)

# ======================
# FERNET KEY (Render Safe)
# ======================
key = os.environ.get("FERNET_KEY")

if not key:
    raise Exception("FERNET_KEY is missing in Render")

try:
    cipher_suite = Fernet(key.encode())
except Exception:
    raise Exception("Invalid FERNET_KEY format")
print("KEY =", repr(os.environ.get("FERNET_KEY")))
# ======================
# DATABASE (Render Safe)
# ======================
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/tahseel_final.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100))
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(256))
    role = db.Column(db.String(20))
    secret_note = db.Column(db.LargeBinary)
    failed_attempts = db.Column(db.Integer, default=0)
    locked = db.Column(db.Boolean, default=False)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        fullname = request.form['fullname']
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        if len(password) < 6 or not re.search(r"\d", password):
            flash("Weak password!")
            return redirect(url_for('register'))

        hashed_pw = hash_password(password)

        try:
            new_user = User(
                fullname=fullname,
                username=username,
                password=hashed_pw,
                role=role
            )
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('index'))

        except:
            flash("User exists!")

    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = hash_password(request.form['password'])

    user = User.query.filter_by(username=username).first()

    # FIX 1: user not found
    if not user:
        flash("User not found!")
        return redirect(url_for('index'))

    # locked account
    if user.locked:
        flash("Account locked!")
        return redirect(url_for('index'))

    # correct password
    if user.password == password:
        user.failed_attempts = 0
        db.session.commit()

        session['user_id'] = user.id

        logging.info(f"User {username} logged in")

        if user.role == 'admin':
            return render_template('admin_dashboard.html', user=user.username)

        note = ""
        if user.secret_note:
            note = cipher_suite.decrypt(user.secret_note).decode()

        return render_template('student_dashboard.html', user=user.username, note=note)

    # wrong password
    user.failed_attempts += 1

    if user.failed_attempts >= 3:
        user.locked = True

    db.session.commit()

    logging.warning(f"Failed login attempt for {username}")

    flash("Wrong password!")
    return redirect(url_for('index'))

@app.route('/save_note', methods=['POST'])
def save_note():
    # FIX 2: حماية session
    if 'user_id' not in session:
        return redirect(url_for('index'))

    user = User.query.get(session['user_id'])

    note_text = request.form['note']
    user.secret_note = cipher_suite.encrypt(note_text.encode())

    db.session.commit()

    flash("Note Saved Securely!")
    return redirect(url_for('index'))
    
with app.app_context():
    db.create_all()
