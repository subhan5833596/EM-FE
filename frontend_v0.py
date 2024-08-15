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

@app.route('/', methods=['GET'])
def home():
    return jsonify({"message": "Service is live"}), 200

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Step 1: Register the user
        signup_url = 'http://127.0.0.1:3232/signup'
        signup_response = requests.post(signup_url, json={'email': email, 'password': password})

        if signup_response.status_code == 200:
            session['user_email'] = email
            return redirect(url_for('login'))
        else:
            return jsonify({"error": "Signup failed", "status_code": signup_response.status_code}), 500
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        print(f"Login attempt with email: {email}")

        # Log in the user
        login_response = requests.post('http://127.0.0.1:3232/login', json={'email': email, 'password': password})
        print(f"Login response: {login_response.status_code} - {login_response.text}")

        if login_response.status_code == 200:
            auth_status = login_response.json().get('message')
            sheet_url = login_response.json().get('sheet_url')
            if auth_status:
                session['user_email'] = email
                session['user_pass'] = password
                session['sheet_url'] = sheet_url
                return redirect(url_for('Msheet'))
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
                response = requests.post('http://127.0.0.1:3232/update_sheet_url', json={'email': email, 'sheet_url': input_sheet_url })

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
        sheet_url = session.get('sheet_url')
        if not email:
            return jsonify({"error": "User not logged in"}), 401
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
            response = requests.post('http://127.0.0.1:3232/googlesheetWorking', json=data)

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
def gmailworking():
    if request.method == 'POST':
        email = session.get('user_email')
        password = session.get('user_pass')
        sheet_url = session.get('sheet_url')
        print(sheet_url)
        if not email:
            return jsonify({"error": "User not logged in"}), 401
       
        data = {
            'email': email,
            'sheet_url' : sheet_url,
            'subject': request.form.get('subject'),
            'mailmsg': request.form.get('email'),
            'time': request.form.get('timeToStart'),
            'clink': request.form.get('calendlyLink'),
            'password' : password
        }
        print(data)
        subject = data.get('subject')
        if subject:
            try:
                response = requests.post('http://127.0.0.1:3232/gmailWorking', json=data)
                if response.status_code == 200:
                    session['updated'] = True
                    flash('STARTED SENDING MAILS')
                    return redirect(url_for('Msheet'))
                else:
                    flash('FAILED SENDING MAILS')
                    return redirect(url_for('gmailworking'))
            except Exception as e:
                flash('UNEXPECTED ERROR PLEASE TRY AGAIN')
                print(f"Error: {e}")
                return redirect(url_for('gmailworking'))
    return render_template('gmailWorking.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
