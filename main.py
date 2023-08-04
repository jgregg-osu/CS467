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


import skills_module
#import ast

os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = 'keys/cs467-394002-67a08c8a3380.json'


app = Flask(__name__)
datastore_client = datastore.Client()
app.secret_key = os.urandom(24)
bcrypt = Bcrypt(app)
oauth = OAuth(app)
google = oauth.remote_app(
    'google',
    # consumer_key='659922551489-fv356bauic9p6odg9t8hhlk75eg5ol83.apps.googleusercontent.com',
    # consumer_secret='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',


    # Jonathan's version
    consumer_key='44071086643-7vml5kuk78a41s350lqv5nqvrkbr07q4.apps.googleusercontent.com',
    consumer_secret='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',


    #Chasen key
    # consumer_key='768902936273-3lbm236f7lnj0sc4s394k13al04hnqao.apps.googleusercontent.com',
    # consumer_secret='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',
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
            # return f"users: {json.dumps(user, indent=2)}, user['id]: {str(user['id'])}, user_id: {str(user_id)}"
            # return 'Can you see this?'
            return redirect(url_for('skills'))
    user_entity = datastore.entity.Entity(key=datastore_client.key(constants.user))
    user_entity['id'] = user_id
    user_entity['skills'] = []
    user_entity['jobs'] = []
    user_entity['contacts'] = []
    datastore_client.put(user_entity)
    # return 'Can you see this? 2'
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

    if request.method == 'GET':
        user = getUser()
        user_skills = user['skills']

        # Filter out any skill entries with a None value
        my_skills = [{'skill': skill.get('skill'), 'experience': skill.get('experience')} for skill in user_skills if skill.get('skill') is not None]
        
        # Extract the names of all skills in "my_skills"
        my_skill_names = [skill['skill'] for skill in my_skills]

        # Add print statements here to check the values of job_skills and my_skills
        print("job_skills:", sorted_job_skills)
        print("my_skills:", my_skills)

        return render_template('skills.html', my_skills=my_skills, job_skills=sorted_job_skills, my_skill_names=my_skill_names)

    else:
        render_template('index.html')


def get_job_skills():
    """Gets all skills required for jobs and compiles an array of dictionaries
    holding each skill with a percentage of jobs it's used for and if the user
    has learned the skill or not"""
    user = getUser()
    jobs = user['jobs']
    skills = user['skills']
    skills_array = []

    for skill in skills:
        # Check if the 'skill_name' key exists before accessing it
        if 'skill_name' in skill:
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

    # Have a dictionary with each skill and the number of jobs it appears in
    display_skills_array = []

    for skill, count in skills_for_jobs_dict.items():
        percentage = str(int((count / total_jobs) * 100)) + "%"
        learned = (skill in skills_array)
        skill_display = {'skill': skill, 'percentage': percentage, 'count': count, 'learned': learned}
        display_skills_array.append(skill_display)

    # Display set not sorted
    sorted_job_skills = sorted(display_skills_array, key=lambda x: x['count'], reverse=True)

    return sorted_job_skills


@app.route('/saveSkill', methods=['POST'])
def saveSkill():
    if request.method == 'POST':
        skill_data = request.get_json()
        skillTitle = skill_data.get('Skill')
        experienceLevel = skill_data.get('Experience Level')

        # Get the current user's entity
        user = getUser()

        # Add the new skill data to the user's skills list
        user['skills'].append({
            'skill': skillTitle,
            'experience': experienceLevel,
        })

        # Save the updated user entity in the database
        datastore_client.put(user)

        return ('successfully created', 201)
    else:
        return ({'Error': 'Skill not created'}, 400)

@app.route('/edit_skills')
def edit_skills():
    return render_template('edit_skills.html')


@app.route('/deleteSkill', methods=['POST'])
def delete_skill():
    if request.method == 'POST':
        # Get the skill ID from the request body
        data = request.get_json()
        index = int(data.get('index'))
        if index is None:
            return ({"error": "Skill not provided"}, 400)
        # Delete the job from the Datastore
        user = getUser()
        user['skills'].pop(index)
        datastore_client.put(user)

        return ('', 204)
    else:
        return ({'Error': 'Delete unsuccesful'}, 400)


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
        skills = json.loads(request.form.get('skills'))
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


# @app.route('/contacts')
# def contacts():
#     query = datastore_client.query(kind=constants.user)
#     users = list(query.fetch())
#     for user in users:
#         print(user.key.id)
#         print(False)
#     if not verify_logged_in():
#         return logout()
#     return render_template('contacts.html')

# @app.route('/contacts')
# def contacts():
#     user_id = session.get('user')
#     return render_template('contacts.html', user_id=user_id)

@app.route('/contacts')
def contacts():
    # Retrieve the user_id from the session
    user_id = session.get('user')
    if not user_id:
        return redirect(url_for('login'))
    # Fetch the user entity associated with the user_id
    query = datastore_client.query(kind=constants.user)
    query.add_filter('id', '=', user_id)
    results = list(query.fetch())
    user_entity = results[0]
    return render_template('contacts.html', user_entity=user_entity)
    

# @app.route('/add_contacts', methods=['POST'])
# def add_contacts():
#     return 'works'
#     return render_template('contacts.html')

@app.route('/saveContact', methods=['POST'])
def saveContact():
    if request.method == 'POST':
        contact_data = request.get_json()
        name = contact_data.get('name')
        company = contact_data.get('company')
        title = contact_data.get('title')
        phone = contact_data.get('phone')
        email = contact_data.get('email')

        user = getUser()

        user['contacts'].append({
        'name': name,
        'company': company,
        'title': title,
        'phone': phone,
        'email': email,
        })
        datastore_client.put(user)
    
        return ('successfully created', 201)
    else:
        return ({'Error': 'Contact not created'}, 400)


@app.route('/delete_contacts', methods=['POST'])
def delete_contact():
    if request.method == 'POST':
        # Get the job ID from the request body
        data = request.get_json()
        index = int(data.get('index'))
        if index is None:
            return ({"error": "Contact not provided"}, 400)
        # Delete the job from the Datastore
        user = getUser()
        user['contacts'].pop(index)
        datastore_client.put(user)

        return ('', 204)
    else:
        return ({'Error': 'Delete unsuccesful'}, 400)
    # if request.method == 'POST':
    #     contact_data = request.get_json()
    #     index = contact_data.get('index')

    #     user = getUser()

    #     entity_id = user['id']
    #     entity_key = datastore_client.key('user', entity_id, 'contacts', index)
    #     datastore_client.delete(entity_key)


    #     # del user['contacts'][index]
    #     # datastore_client.put(user)
    
    #     return ('successfully deleted', 201)
    # else:
    #     return ({'Error': 'Contact not deleted'}, 400)


@app.route('/edit_contacts')
def edit_contacts():
    return render_template('edit_contacts.html')


@app.route('/listings', methods=['GET', 'POST'])
def listings():
    if not verify_logged_in():
        return logout()
    if request.method == 'GET':
        return render_template('listings.html', results=[])
    elif request.method == 'POST':
        ################################
        # app id
        # app key
        ###############################
        url = "http://api.adzuna.com:80/v1/api/jobs/us/search/1"
        jobTitle = request.form.get("job-title")
        location = request.form.get("location")
        params = {
            "app_id": app_id,
            "app_key": app_key,
            "results_per_page": 10,
            "what": jobTitle,
            "where": location,
            "sort_by": "salary",
            "content-type": "application/json"
        }
        response = requests.get(url, params=params)
        data = response.json()
        job_listings = []
        for job in data.get("results", []):
            average_salary = (job.get("salary_min", 0) + job.get("salary_max", 0)) / 2
            job_listings.append({
                "title": job.get("title", ""),
                "location": job.get("location", {}).get("display_name", ""),
                "company": job.get("company", {}).get("display_name", ""),
                "average_salary": average_salary
            })
        return render_template('listings.html', results=job_listings)
    else:
        return render_template('index.html')


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