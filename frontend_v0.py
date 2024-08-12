import datetime
import json
from flask import Flask, request, jsonify, render_template, redirect, session, url_for, flash
import requests
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import os
import google_auth_oauthlib.flow
import flask

app = Flask(__name__)
app.secret_key = '$123321$' 

# Your Google OAuth 2.0 Client Configuration
CLIENT_CONFIG = {"web":{"client_id":"286365376596-j08s8o63gfpqeh951hea2poppo6ascii.apps.googleusercontent.com","project_id":"email-430207","auth_uri":"https://accounts.google.com/o/oauth2/auth","token_uri":"https://oauth2.googleapis.com/token","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs","client_secret":"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","redirect_uris":["https://emfe-fires-projects-5c2c6ff4.vercel.app/oauth2callback","https://sheepdog-refined-lioness.ngrok-free.app/oauth2callback","http://localhost/oauth2callback","http://localhost:5000","http://localhost:5000/oauth2callback"]}}

SCOPES = ['https://www.googleapis.com/auth/spreadsheets', 'https://mail.google.com/']

@app.route('/', methods=['GET'])
def home():
    return jsonify({"message": "Service is live"}), 200

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        session['user_email'] = email
        session['user_pass'] = password
        print(f"Signup attempt with email: {email}")
        return redirect(url_for('registration'))
    return render_template('signup.html')

@app.route('/registration', methods=['GET'])
def registration():
    email = session.get('user_email')
    if not email:
        return jsonify({"error": "Email parameter missing"}), 400

    try:
        flow = google_auth_oauthlib.flow.Flow.from_client_config(CLIENT_CONFIG, SCOPES)
        flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

        authorization_url, state = flow.authorization_url(
              # Enable offline access so that you can refresh an access token without
              # re-prompting the user for permission. Recommended for web server apps.
              access_type='offline',
              # Enable incremental authorization. Recommended as a best practice.
              include_granted_scopes='true',prompt='consent')
        
          # Store the state so the callback can verify the auth server response.
        flask.session['state'] = state
        return flask.redirect(authorization_url)
    except Exception as e:
        print(f"Error generating token: {str(e)}")
        return jsonify({"error": "Error generating token", "details": str(e)}), 500

@app.route('/oauth2callback', methods=['GET'])
def oauth2callback():
    if not session.get('user_email'):
        return jsonify({"error": "User not authenticated"}), 401

    try:
        state = flask.session['state']
        flow = google_auth_oauthlib.flow.Flow.from_client_config(CLIENT_CONFIG, SCOPES)
        flow.redirect_uri = flask.url_for('oauth2callback', _external=True)
        print(f"Redirect URI: {flow.redirect_uri}")
        authorization_response = flask.request.url
        flow.fetch_token(authorization_response=authorization_response)
        print(f"Authorization response URL: {request.url}")
        credentials = flow.credentials
        flask.session['credentials'] = credentials_to_dict(credentials)
        try:
            signup_url = 'https://sheepdog-refined-lioness.ngrok-free.app/signup'
            signup_response = requests.post(signup_url, json={'email': session.get('user_email'), 'password': session.get('user_pass')})
            print(f"Signup response: {signup_response.status_code} - {signup_response.text}")

            if signup_response.status_code == 200:
                token_url = 'https://sheepdog-refined-lioness.ngrok-free.app/generate_client_token'
                token_response = requests.post(token_url, json={'email': session.get('user_email'), 'password': session.get('user_pass'),'token_info': credentials_to_dict(credentials)})
                flash('SUCCESSFULLY SIGN UP')
                if token_response.status_code == 200:
                    flash('Credentials created, please log in again')
                    return redirect(url_for('login'))
                else:
                    return jsonify({"error": "Token generation failed", "status_code": token_response.status_code}), 500
            else:
                flash('EMAIL IS ALREADY IN USE')
        except Exception as e:
            print(f"Error updating token: {str(e)}")
    except Exception as e:
        print(f"Error fetching token: {str(e)}")
        return jsonify({"error": "Error fetching token", "details": str(e)}), 500

    if not flow.credentials:
        return jsonify({"error": "Failed to obtain credentials"}), 500
    
    print(flask.session['credentials'])
    creds = flow.credentials
    token_info = {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": CLIENT_CONFIG['web']['client_id'],
        "client_secret": CLIENT_CONFIG['web']['client_secret'],
        "scopes": SCOPES,
        "expiry": creds.expiry.isoformat() if creds.expiry else None
    }

    session['token_info'] = token_info
    return redirect(url_for('login'))


def credentials_to_dict(credentials):
  print(credentials)
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes,
          'expiry': '2024-08-05T07:25:50.100955'}

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        creds = session['credentials']
        print(f"Login attempt with email: {email} and creds {creds}")

        # Log in the user
        login_response = requests.post('https://sheepdog-refined-lioness.ngrok-free.app/login', json={'email': email, 'password': password})
        print(f"Login response: {login_response.status_code} - {login_response.text}")

        if login_response.status_code == 200:
            auth_status = login_response.json().get('message')
            sheet_url = login_response.json().get('sheet_url')
            if auth_status:
                session['user_email'] = email
                session['credentials'] = auth_status
                session['sheet_url'] = sheet_url
                return redirect(url_for('Msheet'))
            else:
                return redirect(url_for('generate_google_token'))
        else:
            return jsonify({"error": "Login failed", "status_code": login_response.status_code}), 500
    return render_template('login.html')

@app.route('/Msheet', methods=['GET', 'POST'])
def Msheet():
    if request.method == 'POST':
        email = session.get('user_email')
        sheet_url = session.get('sheet_url')
        
        if not email:
            return jsonify({"error": "User not logged in"}), 401
        input_sheet_url = request.form['sheet_url']
        if sheet_url is None:
            try:
                response = requests.post('https://sheepdog-refined-lioness.ngrok-free.app/update_sheet_url', json={'email': email, 'sheet_url': input_sheet_url })

                if response.status_code == 200:
                    session['sheet_url'] = input_sheet_url
                    flash('SHEET URL UPDATED SUCCESSFULLY')
                    return redirect(url_for('Msheet'))
                else:
                    flash('FAILED ')
                    return redirect(url_for('Msheet'))
            except Exception as e:
                flash('UNEXPECTED ERROR PLEASE TRY AGAIN')
                print(f"Error: {e}")
                return redirect(url_for('Msheet'))
        else:
            flash('SHEET URL ALREADY EXIST')
            return redirect(url_for('Msheet'))
    sheet_url = session.get('sheet_url')
    updated = session.get('updated')
    updated = bool(updated)
    print(sheet_url , updated)
    return render_template('sheeturl.html', url=sheet_url, updated=updated)

@app.route('/gsheetworking', methods=['GET', 'POST'])
def gsheetworking():
    if request.method == 'POST':
        email = session.get('user_email')
        credentials = session.get('credentials')
        sheet_url = session.get('sheet_url')
        if not email:
            return jsonify({"error": "User not logged in"}), 401
        if not credentials:
            return jsonify({"error": "No credentials found"}), 500
        if not sheet_url:
            return jsonify({"error": "No sheet url found"}), 501
        
        no_of_pages = request.form.get('noOfPages')
        if no_of_pages is not None:
            try:
                no_of_pages = int(no_of_pages)
            except ValueError:
                return jsonify({"error": "Invalid value for noOfPages, must be an integer"}), 400
        try:
            data = {
                'cred': credentials,
                'email': email,
                'sheet_url': sheet_url,
                'platform': request.form.get('platform'),
                'titleInfo': request.form.get('titleInfo', '').split(', '),
                'roles': request.form.get('roles', '').split(', '),
                'industry': request.form.get('industry', '').split(', '),
                'locations': request.form.get('locations', '').split(', '),
                'required': request.form.get('required'),
                'noOfPages': no_of_pages
            }
            print(data)
        except Exception as e:
            print(f"Error: {e}")
        try:
            response = requests.post('https://sheepdog-refined-lioness.ngrok-free.app/googlesheetWorking', json=data)

            if response.status_code == 200:
                session['updated'] = True
                flash('SHEET UPDATED SUCCESSFULLY')
                return redirect(url_for('Msheet'))
            else:
                flash('FAILED UPDATING SHEET')
                return redirect(url_for('gsheetworking'))
        except Exception as e:
            flash('UNEXPECTED ERROR PLEASE TRY AGAIN')
            print(f"Error: {e}")
            return redirect(url_for('gsheetworking'))
    return render_template('gsheetWorking.html')

@app.route('/gmailworking', methods=['GET', 'POST'])
def gamilworking():
    if request.method == 'POST':
        email = session.get('user_email')
        credentials = session.get('credentials')
        sheet_url = session.get('sheet_url')
        print(sheet_url)
        if not email:
            return jsonify({"error": "User not logged in"}), 401
        if not credentials:
            return jsonify({"error": "No credentials found"}), 500
        if not sheet_url:
            return jsonify({"error": "No sheet url found"}), 501
        data = {
            'cred': credentials,
            'email': email,
            'sheet_url': sheet_url,
            'platform': request.form.get('platform'),
            'titleInfo': request.form.get('titleInfo', '').split(', '),
            'roles': request.form.get('roles', '').split(', '),
            'industry': request.form.get('industry', '').split(', '),
            'locations': request.form.get('locations', '').split(', '),
            'required': request.form.get('required'),
        }
        try:
            response = requests.post('https://sheepdog-refined-lioness.ngrok-free.app/gmailWorking', json=data)
            if response.status_code == 200:
                session['updated'] = True
                flash('GMAIL UPDATED SUCCESSFULLY')
                return redirect(url_for('Msheet'))
            else:
                flash('FAILED UPDATING GMAIL')
                return redirect(url_for('gamilworking'))
        except Exception as e:
            flash('UNEXPECTED ERROR PLEASE TRY AGAIN')
            print(f"Error: {e}")
            return redirect(url_for('gamilworking'))
    return render_template('gmailWorking.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
