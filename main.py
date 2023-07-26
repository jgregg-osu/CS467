import datetime, google, os

from flask import Flask, render_template, request

from google.cloud import datastore

#os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = '../keys/job-tracker-app-392713-ac5aaa57e530.json'

app = Flask(__name__)
datastore_client = datastore.Client()


user_data = None










# #!############################################
# def login():
#   """Logs in the user with their Google account."""

#   credentials, project = google.auth.default()
#   datastore_client = google.cloud.datastore.Client(project=project)

#   user_id = credentials.id_token['sub']
#   user_data = datastore_client.get(user_id)

#   if user_data is None:
#     return None

#   return user_data

# def create_account():
#   """Creates a new account for the user."""

#   credentials, project = google.auth.default()
#   datastore_client = google.cloud.datastore.Client(project=project)

#   user_id = credentials.id_token['sub']
#   user_data = {
#     'id': user_id,
#     'email': credentials.id_token['email'],
#     'name': credentials.id_token['name'],
#   }

#   datastore_client.put(user_data)

#   return user_data
#!############################################




@app.route('/')
def home():
    return render_template('index.html')

@app.route('/instructions')
def instructions():
    return render_template('instructions.html')

@app.route('/skills')
def skills():
    return render_template('skills.html')

@app.route('/edit_skills')
def edit_skills():
    return render_template('edit_skills.html')

@app.route('/jobs')
def jobs():
    return render_template('jobs.html')

@app.route('/edit_jobs')
def edit_jobs():
    return render_template('edit_jobs.html')

@app.route('/contacts')
def contacts():
    user_id = request.args.get('user_id')

    query = datastore.Query('contacts')
    query.add_filter('id', '=', user_id)
    #results = datastore.query(query)   # Bard failed here. ChatGPT had to save the day.
    results = query.fetch()        

    contacts = []
    for contact in results:
        contacts.append({
            'name': contact['name'],
            'company': contact['company'],
            'title': contact['title'],
            'phone': contact['phone'],
            'email': contact['email'],
        })
    return render_template('contacts.html', user_data=user_data, contacts=contacts)

@app.route('/edit_contacts')
def edit_contacts():
    return render_template('edit_contacts.html')


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