import datetime

from flask import Flask, render_template

from google.cloud import datastore

import os

os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = '../keys/job-tracker-app-392713-ac5aaa57e530.json'

app = Flask(__name__)
datastore_client = datastore.Client()


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/instructions')
def instructions():
    return render_template('instructions.html')

@app.route('/skills')
def skills():
    return render_template('skills.html')

@app.route('/jobs')
def jobs():
    return render_template('jobs.html')

@app.route('/contacts')
def contacts():
    return render_template('contacts.html')


def store_time(dt):
    entity = datastore.Entity(key=datastore_client.key("visit"))
    entity.update({"timestamp": dt})

    datastore_client.put(entity)


def fetch_times(limit):
    query = datastore_client.query(kind="visit")
    query.order = ["-timestamp"]

    times = query.fetch(limit=limit)

    return times


if __name__ == "__main__":
    # This is used when running locally only. When deploying to Google App
    # Engine, a webserver process such as Gunicorn will serve the app. This
    # can be configured by adding an `entrypoint` to app.yaml.
    # Flask's development server will automatically serve static files in
    # the "static" directory. See:
    # http://flask.pocoo.org/docs/1.0/quickstart/#static-files. Once deployed,
    # App Engine itself will serve those files as configured in app.yaml.
    app.run(host="127.0.0.1", port=8080, debug=True)