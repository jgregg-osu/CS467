from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/home')
def second_home():
    return render_template('home.html')

if __name__ == '__main__':
    app.run()