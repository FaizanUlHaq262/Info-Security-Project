from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_bcrypt import Bcrypt
from email_validator import validate_email, EmailNotValidError
import sqlite3
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets
import string
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = "key"

bcrypt = Bcrypt(app)

#email configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "mariakhanz1352@gmail.com"
SMTP_PASSWORD = "afdk kdan qoiq kjnp"
SENDER_EMAIL = "mariakhanz1352@gmail.com"

def sqlite_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():      #added the otp fields for the database, expiration, attempts, and code itself
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
            token_expiry TIMESTAMP,
            otp TEXT,
            otp_expiry TIMESTAMP,
            otp_attempts INTEGER DEFAULT 0
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

def generate_otp(length=6):     #generates a 6 digit otp, helps with securing otp codes
    """Generate a secure numeric OTP."""
    return ''.join(secrets.choice(string.digits) for _ in range(length))

def send_otp_email(email, otp):
    msg = MIMEMultipart('alternative')
    msg['From'] = SENDER_EMAIL
    msg['To'] = email
    msg['Subject'] = "Your One-Time Password (OTP)"

    html_content = f"""<html>
        <body>
            <h2>OTP Verification</h2>
            <p>Your One-Time Password (OTP) is: <strong>{otp}</strong></p>
            <p>This OTP is valid for 10 minutes.</p>
            <p>If you did not request this, please contact support immediately.</p>
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
        print(f"Error sending OTP email: {e}")
        return False

@app.route('/')
def index():
    if 'user_id' in session and session.get('is_authenticated'):
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
        token_expiry = datetime.now() + timedelta(days=1)       #to secure usage of codes so it dies after a certain time

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
        AND token_expiry > ? 
        AND is_verified = FALSE
    ''', (token, datetime.now())).fetchone()

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

        if user and bcrypt.check_password_hash(user['password'], password):
            if not user['is_verified']:
                flash('Please verify your email address before logging in.')
                conn.close()
                return redirect(url_for('login'))

            # Generate OTP
            otp = generate_otp()
            otp_expiry = datetime.now() + timedelta(minutes=10)

            # Update user with OTP details
            conn.execute('''
                UPDATE users 
                SET otp = ?, otp_expiry = ?, otp_attempts = 0 
                WHERE id = ?
            ''', (otp, otp_expiry, user['id']))
            conn.commit()

            # Send OTP via email
            if send_otp_email(user['email'], otp):
                session['pending_user_id'] = user['id']
                conn.close()
                return redirect(url_for('verify_otp'))
            else:
                flash('Failed to send OTP. Please try again.')
        else:
            flash('Incorrect email or password.')
        conn.close()

    return render_template('login.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'pending_user_id' not in session:
        flash('No pending OTP verification found. Please log in again.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp_input = request.form['otp']
        user_id = session['pending_user_id']

        conn = sqlite_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

        if user:
            # Check if OTP is expired
            if datetime.now() > datetime.strptime(user['otp_expiry'], '%Y-%m-%d %H:%M:%S.%f'):
                flash('OTP has expired. Please request a new one.')
                conn.close()
                return redirect(url_for('verify_otp'))

            # Check OTP attempts
            if user['otp_attempts'] >= 5:
                flash('Too many incorrect attempts. Please request a new OTP.')
                conn.close()
                return redirect(url_for('verify_otp'))

            # Verify OTP
            if otp_input == user['otp']:
                # Successful verification
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_authenticated'] = True

                # Clear OTP fields
                conn.execute('''
                    UPDATE users 
                    SET otp = NULL, otp_expiry = NULL, otp_attempts = 0 
                    WHERE id = ?
                ''', (user_id,))
                conn.commit()

                # Remove pending_user_id from session
                session.pop('pending_user_id', None)

                conn.close()
                flash('Logged in successfully!')
                return redirect(url_for('dashboard'))
            else:
                # Increment OTP attempts
                conn.execute('''
                    UPDATE users 
                    SET otp_attempts = otp_attempts + 1 
                    WHERE id = ?
                ''', (user_id,))
                conn.commit()
                remaining_attempts = 5 - (user['otp_attempts'] + 1)
                flash(f'Incorrect OTP. You have {remaining_attempts} attempts left.')
        else:
            flash('User not found.')
        conn.close()

    return render_template('otp.html')

@app.route('/resend_otp')
def resend_otp():
    if 'pending_user_id' not in session:
        flash('No pending OTP verification found. Please log in again.')
        return redirect(url_for('login'))

    user_id = session['pending_user_id']
    conn = sqlite_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

    if user:
        # Generate new OTP
        otp = generate_otp()
        otp_expiry = datetime.now() + timedelta(minutes=10)

        # Update OTP details
        conn.execute('''
            UPDATE users 
            SET otp = ?, otp_expiry = ?, otp_attempts = 0 
            WHERE id = ?
        ''', (otp, otp_expiry, user_id))
        conn.commit()

        # Send OTP via email
        if send_otp_email(user['email'], otp):
            flash('A new OTP has been sent to your email.')
        else:
            flash('Failed to send OTP. Please try again.')
    else:
        flash('User not found.')

    conn.close()
    return redirect(url_for('verify_otp'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session or not session.get('is_authenticated'):
        flash('You need to log in first')
        return redirect(url_for('login'))

    username = session.get('username')
    return render_template('dashboard.html', username=username)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out')
    return redirect(url_for('login'))

# Error Handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

init_db()

if __name__ == '__main__':
    app.run(debug=True)
