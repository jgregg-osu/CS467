from flask import Flask, redirect, url_for, session, render_template, request
from flask_oauthlib.client import OAuth
from google.cloud import datastore
import requests
import os
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
import constants
from flask_bcrypt import Bcrypt
import json
import uuid
import skills_module
import ast

os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = 'keys/job-tracker-app-392713-cc69c2226a63.json'

app = Flask(__name__)
datastore_client = datastore.Client()
app.secret_key = os.urandom(24)
bcrypt = Bcrypt(app)
oauth = OAuth(app)

google = oauth.remote_app(
    'google',
    consumer_key='659922551489-fv356bauic9p6odg9t8hhlk75eg5ol83.apps.googleusercontent.com',
    consumer_secret='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',
    request_token_params={
        'scope': 'email',
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)

@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        return google.authorize(callback=url_for('authorized', _external=True))
    else:
        return render_template('index.html')

@app.route('/logout', methods=['POST'])
def logout():
        session.pop('user', None)
        return redirect(url_for('index'))

@app.route('/login/authorized', methods=['POST', 'GET'])
def authorized():
    response = google.authorized_response()
    if response is None or response.get('access_token') is None:
        return 'Access denied: reason={}, error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        )

    # Get the ID token from the response
    id_token_response = response.get('id_token')
    if id_token_response is None:
        return 'Failed to get the ID token from Google response.'

    try:
        id_info = id_token.verify_oauth2_token(id_token_response, google_requests.Request())
        user_id = id_info.get('sub')
        if user_id is None:
            return 'Failed to get user information from Google ID token.'
    except ValueError as e:
        return f'Failed to decode and verify the Google ID token: {e}'

    session['user'] = user_id

    query = datastore_client.query(kind=constants.user)
    users = list(query.fetch())
    for user in users:
        if user['id'] == user_id:
            return redirect(url_for('skills'))

    user_entity = datastore.entity.Entity(key=datastore_client.key(constants.user))
    user_entity['id'] = user_id
    user_entity['skills'] = []
    user_entity['jobs'] = []
    user_entity['contacts'] = []
    datastore_client.put(user_entity)

    return redirect(url_for('skills'))

@google.tokengetter
def get_google_oauth_token():
    return session.get('user')


# Set the Referrer-Policy header for all responses
@app.after_request
def add_referrer_policy_header(response):
    response.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
    return response

@app.route('/login-normal', methods=['POST'])
def loginNormal():
    if request.method == 'POST':
       
        # The user has not signed in with Google, so we need to check for username and password
        username = request.form.get('username')
        password = request.form.get('password')

        if username and password:
            query = datastore_client.query(kind=constants.user)
            users = list(query.fetch())
            
            for user in users:
                if user['id'] == username:
                   
                    if bcrypt.check_password_hash(user['password'], password):
                        session['user'] = username
                        return redirect(url_for('skills'))
                    else:
                        # Incorrect password: show an error message
                        error = "Incorrect password. Please try again."
                        return render_template('index.html', error=error)
                    
    error = "Please enter both username and password."
    return render_template('index.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirmedPassword = request.form['confirm-password']
        if password != confirmedPassword:
            return render_template('index.html')

        # Hash the password using bcrypt (secure password hashing)
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        user_entity = datastore.entity.Entity(key=datastore_client.key(constants.user))
        user_entity['id'] = username
        user_entity['password'] = hashed_password
        user_entity['skills'] = []
        user_entity['jobs'] = []
        user_entity['contacts'] = []
        datastore_client.put(user_entity)

        session['user'] = username
        return redirect('/skills')
    else:
        return render_template('index.html')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/instructions')
def instructions():
    return render_template('instructions.html')

@app.route('/skills')
def skills():
    if not verify_logged_in():
        return logout()
    sorted_job_skills = get_job_skills()

    return render_template('skills.html', job_skills=sorted_job_skills)

def get_job_skills():
    """gets all skills required for jobs and compiles array of dictioaries
    holding each skill with a percentage of jobs its used for and if the user
    has learned the skill or not"""
    user = getUser()
    jobs = user['jobs']
    skills = user['skills']
    skills_array = []
    for skill in skills:
        skills_array.append(skill['skill_name'].lower())
    skills_for_jobs_dict = {}
    skills_added = []
    total_jobs = 0
    for job in jobs:
        total_jobs += 1
        job_skills = job['skills']
        for skill in job_skills:
            if skill.lower() in skills_added:
                skills_for_jobs_dict[skill] += 1
            else:
                skills_for_jobs_dict[skill] = 1
            skills_added.append(skill.lower())
    # have dict with each skill and number of jobs it appears in
    display_skills_array = []
    for skill, count in skills_for_jobs_dict.items():
        percentage = str(int((count / total_jobs) * 100)) + "%"
        learned = (skill in skills_array)
        skill_display = {'skill': skill, 'percentage': percentage, 'count': count, 'learned': learned}
        display_skills_array.append(skill_display)
    # display set not sorted
    sorted_job_skills = sorted(display_skills_array, key=lambda x: x['count'], reverse=True)

    return sorted_job_skills

@app.route('/edit_skills')
def edit_skills():
    return render_template('edit_skills.html')

@app.route('/jobs', methods=['GET'])
def jobs():
    if not verify_logged_in():
            return logout()
    if request.method == 'GET':
        user = getUser()
        jobs = user['jobs']
        skills = skills_module.skills
        skills_json = json.dumps(skills)
        return render_template('jobs.html', jobs=jobs, skills=skills_json)
    else:
        render_template('index.html')

@app.route('/savejob', methods=['POST'])
def savejob():
    if request.method == 'POST':
        job_data = request.get_json()
        title = job_data.get('Title')
        salary = job_data.get('Salary')
        skills = job_data.get('Skills')
        start_date = job_data.get('Start Date')
        contact = job_data.get('Contact')

        user = getUser()

        user['jobs'].append({
        'title': title,
        'salary': salary,
        'skills': skills,
        'start_date': start_date,
        'contact': contact
        })
        datastore_client.put(user)
    
        return ('successfully created', 201)
    else:
        return ({'Error': 'Job not created'}, 400)

@app.route('/deletejob', methods=['POST'])
def delete_job():
    if request.method == 'POST':
        # Get the job ID from the request body
        data = request.get_json()
        index = int(data.get('index'))
        if index is None:
            return ({"error": "Job not provided"}, 400)
        # Delete the job from the Datastore
        user = getUser()
        user['jobs'].pop(index)
        datastore_client.put(user)

        return ('', 204)
    else:
        return ({'Error': 'Delete unsuccesful'}, 400)

@app.route('/edit_jobs', methods=['GET'])
def edit_jobs():
    if request.method == 'GET':
        index = int(request.args.get('index'))
        user = getUser()
        job = user['jobs'][index]
        skills = skills_module.skills
        skills_json = json.dumps(skills)
        selected_skills = job['skills']
       
        return render_template('edit_jobs.html', job=job, index=index, skills=skills_json, selected_skills=selected_skills)
    else:
        render_template('jobs.html')

@app.route('/saveJobEdit', methods=['POST'])
def saveJobEdit():
    if request.method == 'POST':
        index = int(request.form.get('index'))
        title = request.form.get('title')
        salary = request.form.get('salary')
        skills = ast.literal_eval(request.form.get('skills'))
        start_date = request.form.get('start_date')
        contact = request.form.get('contacts')
       

        # Update the job in the jobs list if the index is valid
        if index >= 0:
            user = getUser()
            jobs = user['jobs']
            if index < len(jobs):
                jobs[index]['title'] = title
                jobs[index]['salary'] = salary
                jobs[index]['skills'] = skills
                jobs[index]['start_date'] = start_date
                jobs[index]['contact'] = contact
                datastore_client.put(user)

        return render_template('jobs.html', jobs=user['jobs'])
    else:
        return render_template('index.html')

@app.route('/contacts')
def contacts():
    if not verify_logged_in():
        return logout()
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

@app.route('/listings')
def listings():
    if not verify_logged_in():
        return logout()

    return render_template('listings.html')

def verify_logged_in():
    if 'user' in session:
        return True
    return False

def getUser():
    query = datastore_client.query(kind=constants.user)
    query.add_filter('id', '=', session.get('user'))
    users = list(query.fetch())
    user = users[0]
    return user


if __name__ == "__main__":
    # This is used when running locally only. When deploying to Google App
    # Engine, a webserver process such as Gunicorn will serve the app. This
    # can be configured by adding an `entrypoint` to app.yaml.
    # Flask's development server will automatically serve static files in
    # the "static" directory. See:
    # http://flask.pocoo.org/docs/1.0/quickstart/#static-files. Once deployed,
    # App Engine itself will serve those files as configured in app.yaml.
    app.run(host="127.0.0.1", port=8080, debug=True)