# -*- coding: utf-8 -*-
# ==============================================================================
# Copyright (c) 2024 Xavier de Carné de Carnavalet
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# ==============================================================================

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort, flash, make_response
from flask_mysqldb import MySQL
from flask_session import Session
import yaml
import requests
import bcrypt
import hashlib
import pyotp
import random
import pyqrcode
import json
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)


limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["10000 per day", "2000 per hour"]
)

csrf = CSRFProtect(app)

# Configure secret key and Flask-Session
app.config['SECRET_KEY'] = '6LfvfLApAAAAAPRbNh_h-j7ZEfA4pJ-LXbk208nF'
app.config['SESSION_TYPE'] = 'filesystem'  # Options: 'filesystem', 'redis', 'memcached', etc.
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True  # To sign session cookies for extra security
app.config['SESSION_FILE_DIR'] = './sessions'  # Needed if using filesystem type

# Load database configuration from db.yaml or configure directly here
db_config = yaml.load(open('db.yaml'), Loader=yaml.FullLoader)
app.config['MYSQL_HOST'] = db_config['mysql_host']
app.config['MYSQL_USER'] = db_config['mysql_user']
app.config['MYSQL_PASSWORD'] = db_config['mysql_password']
app.config['MYSQL_DB'] = db_config['mysql_db']

mysql = MySQL(app)

GOOGLE_RECAPTCHA_SITE_KEY = '6LfvfLApAAAAABC2Lo-4RAi6JE6CgJ8Lysa3xnir'
GOOGLE_RECAPTCHA_SECRET_KEY = '6LfvfLApAAAAAPRbNh_h-j7ZEfA4pJ-LXbk208nF'
GOOGLE_RECAPTCHA_VERIFY_URL = 'https://www.google.com/recaptcha/api/siteverify'


# Initialize the Flask-Session
Session(app)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("3 per minute", methods=["POST"])
def login():
    error = None
    session.clear()
    if request.method == 'POST':
        secret_response = request.form['g-recaptcha-response']
        verify_response = requests.post(
            url=f'{GOOGLE_RECAPTCHA_VERIFY_URL}?secret={GOOGLE_RECAPTCHA_SECRET_KEY}&response={secret_response}').json()
        
        if verify_response['success']:
            userDetails = request.form
            username = userDetails['username']
            password = userDetails['password']
            
            cur = mysql.connection.cursor()
            cur.execute("SELECT password FROM users WHERE username=%s", (username,))
            sqlpw = cur.fetchone()
            
            cur.execute("SELECT user_id FROM users WHERE username=%s", (username,))
            account = cur.fetchone()
            
            if sqlpw and bcrypt.checkpw(password.encode('utf-8'), sqlpw[0].encode('utf-8')):
                session['username'] = username
                session['user_id'] = account[0]
                return redirect(url_for('login2FA'))
            else:
                error = 'Invalid credentials'
        else:
            error = 'Invalid reCAPTCHA. Please try again.'
    return render_template('login.html', error=error, site_key=GOOGLE_RECAPTCHA_SITE_KEY)



@app.route('/login2FA', methods=['GET', 'POST'])
def login2FA():
    error = None
    if 'username' not in session:
        abort(403)
    username = session.get('username')
    account = session.get('user_id')
    session.pop('otp_status', None)

    cur = mysql.connection.cursor()
    cur.execute("SELECT sec_key FROM users WHERE username=%s", (username,))
    secKey = cur.fetchone()[0]
    cur.close()


    if request.method == 'POST':
        details = request.form
        otp = details['otp']
        print(f"input otp: {otp}")
        
        if pyotp.TOTP(secKey).verify(otp):
            session['otp_status'] = 'verified'
            return redirect(url_for('index'))
        else:
            cur = mysql.connection.cursor()
            cur.execute("SELECT rec_key FROM users WHERE username=%s", (username,))
            recoveryKeyHash = cur.fetchone()[0]
            
            cur.close()
            
            print(bcrypt.checkpw(otp.encode('utf-8'), recoveryKeyHash.encode('utf-8')))
            
            if recoveryKeyHash and bcrypt.checkpw(otp.encode('utf-8'), recoveryKeyHash.encode('utf-8')):

                session['otp_status'] = 'verified'
                return redirect(url_for('index'))
            else:
                error = 'Invalid code. Please try again.'
            
        error = 'Invalid code. Please try again.'

    return render_template('login2FA.html', error=error, username=username, account=account)


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        secret_response = request.form['g-recaptcha-response']
        verify_response = requests.post(
            url=f'{GOOGLE_RECAPTCHA_VERIFY_URL}?secret={GOOGLE_RECAPTCHA_SECRET_KEY}&response={secret_response}').json()
        
        Pwnedcount = 0

        if verify_response['success']:
            userDetails = request.form
            username = userDetails['username']
            password = userDetails['password']
            
            
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            password_sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            response = requests.get(f"https://api.pwnedpasswords.com/range/{password_sha1[:5]}")
            suffix = password_sha1[5:]
            matches = [line for line in response.text.split('\n') if line.startswith(suffix)]

            
            if matches:
                Pwnedcount = int(matches[0].split(':')[1])
                print(f"pwned: {Pwnedcount} times")

            # error = 'This password has been pwned. Please choose a different password.'
            if Pwnedcount > 0:
                error = 'This password has been pwned. Please choose a different password.'
                return render_template('register.html', error=error)
            else:
                cur = mysql.connection.cursor()
                cur.execute("SELECT user_id FROM users WHERE username=%s", (username,))
                if cur.fetchone() is not None:
                    error = 'User already exists. Please choose a different username.'
                else:
                    otpKey = pyotp.random_base32()
                    
                    recoveryKey = str(random.randint(100000, 999999))
                    print(f"recoveryKey: {recoveryKey}")
                    
                    session['regUser'] = username
                    session['password'] = hashed
                    session['otpKey'] = otpKey
                    session['recoveryKey'] = recoveryKey
                    
                    return redirect(url_for('connectTo2FA'))
        else:
            error = 'Invalid reCAPTCHA. Please try again.'
    return render_template('register.html', error=error)

@app.route('/changeAuthenticators', methods=['GET', 'POST'])
def changeAuthenticators():
    error = None
    if 'username' not in session:
        abort(403)
        
    username = session.get('username')
    account = session.get('user_id')

    if request.method == 'POST':
        details = request.form
        otp = details['otp']
        print(f"input otp: {otp}")
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT rec_key FROM users WHERE username=%s", (username,))
        recoveryKeyHash = cur.fetchone()[0]
        
        cur.close()
        
        print(bcrypt.checkpw(otp.encode('utf-8'), recoveryKeyHash.encode('utf-8')))
        
        if recoveryKeyHash and bcrypt.checkpw(otp.encode('utf-8'), recoveryKeyHash.encode('utf-8')):
            
            return redirect(url_for('changeAuthenticators_showQR'))
            
        else:
            error = 'Invalid code. Please try again.'
            

    return render_template('changeAuthenticators.html', error=error)

@app.route('/changeAuthenticators_showQR', methods=['GET', 'POST'])
def changeAuthenticators_showQR():
    if 'username' not in session:
        abort(403)
        
    username = session.get('username')
    account = session.get('user_id')

    cur = mysql.connection.cursor()
    cur.execute("SELECT sec_key FROM users WHERE username=%s", (username,))
    secKey = cur.fetchone()[0]
    cur.close()
    
    
    url_qr = pyotp.totp.TOTP(secKey).provisioning_uri(name=username, issuer_name='ChatApp')
    url = pyqrcode.create(url_qr)
    url.svg('static/qr.svg', scale=6)

    if request.method == 'POST':
        session.clear()
        return redirect(url_for('login'))
            
    return render_template('changeAuthenticators_showQR.html')

@app.route('/store_ecdh_public_key', methods=['POST'])
def store_ecdh_public_key():
    data = request.get_json()
    username = data['username']
    public_key = data['publickey']
    try:
        with open('static/ecdh_public_key.json', 'r') as f:
            ecdh_public_keys = json.load(f)
    except FileNotFoundError:
        print("file not found")
        ecdh_public_keys = {}
    except json.JSONDecodeError:
        print("json decode error")
        ecdh_public_keys = {}

    ecdh_public_keys[username] = public_key
    
    # print
    print(f"ecdh_public_keys: {ecdh_public_keys}")

    # Save the keys back to the file
    with open('static/ecdh_public_key.json', 'w') as f:
        json.dump(ecdh_public_keys, f)

    return '', 204

@app.route('/connectTo2FA', methods=['GET', 'POST'])
def connectTo2FA():
    error = None
    
    if 'regUser' not in session:
        abort(403)
    username = session.get('regUser')
    hashed = session.get('password')
    otpKey = session.get('otpKey')
    recoveryKey = session.get('recoveryKey')
            
    recoveryKeyHash = bcrypt.hashpw(recoveryKey.encode('utf-8'), bcrypt.gensalt())

    url_qr = pyotp.totp.TOTP(otpKey).provisioning_uri(name=username, issuer_name='ChatApp')
    url = pyqrcode.create(url_qr)
    url.svg('static/qr.svg', scale=6)

    if request.method == 'POST':
        details = request.form
        otp = details['otp']
        print(f"input otp: {otp}")
        
        if pyotp.TOTP(otpKey).verify(otp):
                    
            print(username)
            print(hashed)
            print(otpKey)
            print(recoveryKeyHash)
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO users(username, password, sec_key, rec_key) VALUES(%s, %s, %s, %s)", (username, hashed, otpKey, recoveryKeyHash,))
            mysql.connection.commit()
            cur.close()
            
            
            
            session.pop('regUser', None)
            session.pop('password', None)
            session.pop('otpKey', None)
            session.pop('recoveryKey', None)
            
            return redirect(url_for('login'))
        
        else:
            error = 'Invalid OTP. Please try again.'

    return render_template('connectTo2FA.html', error=error, username=username, secKey=str(otpKey), recoveryKey=recoveryKey)

# part2 ================================================================

@app.route('/')
def index():
    if 'user_id' not in session:
        print("otp_status not in session")
        return redirect(url_for('login'))
    
    sender_id = session['user_id']
    resp = make_response(render_template('chat.html', sender_id=sender_id))
    resp.headers['Content-Security-Policy'] = "default-src * 'unsafe-inline' 'unsafe-eval'"
    return resp

@app.route('/users')
def users():
    if 'user_id' not in session:
        abort(403)

    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id, username FROM users")
    user_data = cur.fetchall()
    cur.close()

    filtered_users = [[user[0], user[1]] for user in user_data if user[0] != session['user_id']]
    return {'users': filtered_users}

@app.route('/current_user')
def current_user():
    if 'user_id' not in session:
        abort(403)
    return {'user_id': session['user_id'], 'username': session['username']}

# get ECDH public key by username
@app.route('/get_ecdh_public_key', methods=['POST'])
def get_ecdh_public_key():
    data = request.get_json()
    username = data['username']
    try:
        with open('static/ecdh_public_key.json', 'r') as f:
            ecdh_public_keys = json.load(f)
    except FileNotFoundError:
        print("file not found")
        ecdh_public_keys = {}
    except json.JSONDecodeError:
        print("json decode error")
        ecdh_public_keys = {}

    public_key = ecdh_public_keys.get(username, None)
    return {'public_key': public_key}

@app.route('/fetch_messages')
def fetch_messages():
    if 'user_id' not in session:
        abort(403)

    last_message_id = request.args.get('last_message_id', 0, type=int)
    peer_id = request.args.get('peer_id', type=int)
    
    cur = mysql.connection.cursor()
    query = """SELECT message_id,sender_id,receiver_id,message_text,created_at FROM messages 
               WHERE message_id > %s AND 
               ((sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s))
               ORDER BY message_id ASC"""
    cur.execute(query, (last_message_id, peer_id, session['user_id'], session['user_id'], peer_id))

    # Fetch the column names
    column_names = [desc[0] for desc in cur.description]
    # Fetch all rows, and create a list of dictionaries, each representing a message
    messages = [dict(zip(column_names, row)) for row in cur.fetchall()]

    cur.close()
    return jsonify({'messages': messages})

@app.route('/send_message', methods=['POST'])
def send_message():
    if not request.json or not 'message_text' in request.json:
        abort(400)  # Bad request if the request doesn't contain JSON or lacks 'message_text'
    if 'user_id' not in session or 'otp_status' not in session:
        abort(403)

    # Extract data from the request
    sender_id = session['user_id']
    receiver_id = request.json['receiver_id']
    message_text = request.json['message_text']

    # Assuming you have a function to save messages
    save_message(sender_id, receiver_id, message_text)
    
    return jsonify({'status': 'success', 'message': 'Message sent'}), 200

def save_message(sender, receiver, message):
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO messages (sender_id, receiver_id, message_text) VALUES (%s, %s, %s)", (sender, receiver, message,))
    mysql.connection.commit()
    cur.close()

@app.route('/erase_chat', methods=['POST'])
def erase_chat():
    if 'user_id' not in session or 'otp_status' not in session:
        abort(403)

    peer_id = request.json['peer_id']
    cur = mysql.connection.cursor()
    query = "DELETE FROM messages WHERE ((sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s))"
    cur.execute(query, (peer_id, session['user_id'], session['user_id'], peer_id))
    mysql.connection.commit()

    # Check if the operation was successful by evaluating affected rows
    if cur.rowcount > 0:
        return jsonify({'status': 'success'}), 200
    else:
        return jsonify({'status': 'failure'}), 200

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been successfully logged out.', 'info')  # Flash a logout success message
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)

