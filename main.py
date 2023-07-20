import datetime
from flask import Flask, render_template, request, redirect, url_for
from flask_cors import CORS  # Import the CORS module
import pyotp
import hashlib
import bcrypt
from google.auth.transport import requests
from google.oauth2 import id_token
import os

# ... other imports and code ...

GOOGLE_CLIENT_ID = "129234542490-meodoecpke86mcs86fgt6r7nen2d0s2c.apps.googleusercontent.com"

# Temporary data storage (replace this with database interaction later)
users = []

app = Flask(__name__)




# Set the Referrer-Policy header for all responses
@app.after_request
def add_referrer_policy_header(response):
    response.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
    return response


@app.route('/')
def welcome():
    return render_template('welcome.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if id_token:
            # The user has signed in with Google, so we don't need to check for username and password
            return redirect(url_for('jobs'))
        else:
            # The user has not signed in with Google, so we need to check for username and password
            username = request.form.get('username')
            password = request.form.get('password')

            if username and password:
                # Find the user in the database based on the provided username
                user = next((u for u in users if u['username'] == username), None)

                if user:
                    # Retrieve the stored hashed password for the user
                    stored_password = user['password'].encode()

                    # Validate the password using bcrypt
                    if bcrypt.checkpw(password.encode(), stored_password):
                        # Successful login: redirect to a dashboard or home page
                        return redirect(url_for('jobs'))
                    else:
                        # Incorrect password: show an error message
                        error = "Incorrect password. Please try again."
                        return render_template('login.html', error=error)

                else:
                    # User not found: show an error message
                    error = "User not found. Please check your username."
                    return render_template('login.html', error=error)

            # Both username and password were not provided
            # Show an error message
            error = "Please enter both username and password."
            return render_template('login.html', error=error)

    # If it's a GET request, render the login page
    return render_template('login.html', GOOGLE_CLIENT_ID=GOOGLE_CLIENT_ID)








@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/jobs')
def jobs():
    return render_template('jobs.html')

@app.route('/skills')
def skills():
    return render_template('skills.html')

@app.route('/contacts')
def contacts():
    return render_template('contacts.html')



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Step 5: Generate Secret Key
        secret = pyotp.random_base32()

        # Hash the password using bcrypt (secure password hashing)
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        # Temporary data storage (replace this with database interaction later)
        users.append({'username': username, 'email': email, 'password': hashed_password, 'secret_key': secret})

        # Redirect to a page indicating successful registration
        return redirect('/success')

    return render_template('register.html')

@app.route('/success')
def success():
    return "Registration Successful! You can now log in with your Google Authenticator."


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)