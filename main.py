import datetime
from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def welcome():
    return render_template('welcome.html')

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

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=True)