from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime
import bcrypt
import os
from dotenv import load_dotenv
import random
from datetime import timedelta
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail


load_dotenv()  

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")  


def send_email(to_email, subject, message):
    from_email = os.getenv('FROM_EMAIL')
    api_key = os.getenv('SENDGRID_API_KEY')

    msg = Mail(
        from_email=from_email,
        to_emails=to_email,
        subject=subject,
        plain_text_content=message
    )

    try:
        sg = SendGridAPIClient(api_key)
        response = sg.send(msg)
        return response.status_code  # 202 means success
    except Exception as e:
        print(f"Error sending email: {e}")
        return None


# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
db = client['nepsentix']
users_col = db['users']

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if users_col.find_one({'email': email}):
            flash("Email already exists.")
            return redirect(url_for('register'))

        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        users_col.insert_one({
            "username": username,
            "email": email,
            "password_hash": hashed,
            "created_at": datetime.utcnow()
        })
        flash("Registration successful. Please log in.")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = users_col.find_one({'email': email})
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash']):
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        flash("Invalid credentials.")
    return render_template('login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = users_col.find_one({'email': email})
        if user:
            otp = str(random.randint(100000, 999999))
            expiry = datetime.utcnow() + timedelta(minutes=10)

            users_col.update_one(
                {'email': email},
                {'$set': {'otp_code': otp, 'otp_expiry': expiry}}
            )

            message = f"""Hello {user['username']},

            Your OTP for password reset is: {otp}

            It expires in 10 minutes.

            If you didn’t request this, please ignore this email.

            — NepSentiX Team"""

            send_email(
                to_email=email,
                subject="NepSentiX OTP Password Reset",
                message=message
            )

            flash("OTP sent to your email.")
            return render_template('verify_otp.html', email=email)
        else:
            flash("No user found with that email.")
    return render_template('forgot_password.html')
@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    email = request.form['email']
    otp = request.form['otp']
    new_password = request.form['new_password']

    user = users_col.find_one({'email': email})

    if not user:
        flash("Invalid email.")
        return redirect(url_for('forgot_password'))

    if 'otp_code' not in user or 'otp_expiry' not in user:
        flash("Please request OTP first.")
        return redirect(url_for('forgot_password'))

    if user['otp_code'] != otp:
        flash("Invalid OTP.")
        return render_template('verify_otp.html', email=email)

    if datetime.utcnow() > user['otp_expiry']:
        flash("OTP expired. Please request again.")
        return redirect(url_for('forgot_password'))

    # Update password and clear OTP fields
    hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    users_col.update_one(
        {'email': email},
        {'$set': {'password_hash': hashed},
         '$unset': {'otp_code': "", 'otp_expiry': ""}}
    )

    flash("Password reset successful. Please login.")
    return redirect(url_for('login'))

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        flash("Login required.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        current_pw = request.form['current_password']
        new_pw = request.form['new_password']

        user = users_col.find_one({'_id': ObjectId(session['user_id'])})
        if user and bcrypt.checkpw(current_pw.encode('utf-8'), user['password_hash']):
            hashed = bcrypt.hashpw(new_pw.encode('utf-8'), bcrypt.gensalt())
            users_col.update_one({'_id': user['_id']}, {'$set': {'password_hash': hashed}})
            flash("Password changed successfully.")
            return redirect(url_for('dashboard'))
        else:
            flash("Incorrect current password.")

    return render_template('change_password.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please login first.")
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.")
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
