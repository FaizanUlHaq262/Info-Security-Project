from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_bcrypt import Bcrypt
from email_validator import validate_email, EmailNotValidError
import sqlite3
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "key"

bcrypt = Bcrypt(app)

# Email configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "mariakhanz1352@gmail.com"
SMTP_PASSWORD = "afdk kdan qoiq kjnp"
SENDER_EMAIL = "mariakhanz1352@gmail.com"


def sqlite_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = sqlite_connection()
    cursor = conn.cursor()
    cursor.execute('''DROP TABLE IF EXISTS users''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_verified BOOLEAN DEFAULT FALSE,
            verification_token TEXT,
            token_expiry TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()


def generate_verification_token():
    return secrets.token_urlsafe(32)


def send_verification_email(email, token):
    msg = MIMEMultipart('alternative')
    msg['From'] = SENDER_EMAIL
    msg['To'] = email
    msg['Subject'] = "Verify Your Email Address"
    
    verify_link = url_for('verify_email', token=token, _external=True)
    html_content = f"""<html>
        <body>
            <h2>Email Verification</h2>
            <p>Please click the link below to verify your email:</p>
            <a href="{verify_link}">Verify Email</a>
        </body>
    </html>"""
    msg.attach(MIMEText(html_content, 'html'))

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.sendmail(SENDER_EMAIL, email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        try:
            validate_email(email)
        except EmailNotValidError as e:
            flash(str(e))
            return redirect(url_for('register'))

        if len(password) < 6:
            flash('Password must be at least 6 characters long')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        verification_token = generate_verification_token()
        token_expiry = datetime.now() + timedelta(days=1)

        conn = sqlite_connection()
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO users (username, email, password, verification_token, token_expiry) 
                VALUES (?, ?, ?, ?, ?)
            ''', (username, email, hashed_password, verification_token, token_expiry))
            conn.commit()

            if send_verification_email(email, verification_token):
                flash('Registration successful! Please check your email to verify your account.')
            else:
                flash('Registration successful but failed to send verification email.')

            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists')
            return redirect(url_for('register'))
        finally:
            conn.close()
    return render_template('register.html')


@app.route('/verify_email/<token>')
def verify_email(token):
    conn = sqlite_connection()
    cursor = conn.cursor()
    user = cursor.execute('''
        SELECT * FROM users 
        WHERE verification_token = ? 
        AND token_expiry > CURRENT_TIMESTAMP 
        AND is_verified = FALSE
    ''', (token,)).fetchone()

    if user:
        cursor.execute('''
            UPDATE users 
            SET is_verified = TRUE, verification_token = NULL, token_expiry = NULL 
            WHERE id = ?
        ''', (user['id'],))
        conn.commit()
        flash('Email verified successfully! You can now log in.')
    else:
        flash('Invalid or expired verification link.')

    conn.close()
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = sqlite_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user['password'], password):
            if not user['is_verified']:
                flash('Please verify your email address before logging in.')
                return redirect(url_for('login'))

            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        else:
            flash('Incorrect email or password.')

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('You need to log in first')
        return redirect(url_for('login'))

    username = session.get('username')
    return render_template('dashboard.html', username=username)


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out')
    return redirect(url_for('login'))


init_db()

if __name__ == '__main__':
    app.run(debug=True)