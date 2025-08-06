import os
import json
import urllib.parse
import sqlite3
import datetime
import io

from google.oauth2 import service_account
import google.auth
import requests
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session, g
from google.auth.transport.requests import AuthorizedSession
from flask import abort
from werkzeug.exceptions import BadRequest

app = Flask(__name__)
app.secret_key = os.urandom(24)

# --- Constants and Config ---
WEBRISK_API_ENDPOINT = "https://webrisk.googleapis.com"
DATABASE = 'submissions.db'

# Supported threat types for different APIs
LOOKUP_API_SUPPORTED_THREAT_TYPES = [
    "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"
]
EVALUATE_API_SUPPORTED_THREAT_TYPES = [
    "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"
]
SUBMISSION_THREAT_TYPES = [
    "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
    "SOCIAL_ENGINEERING_EXTENDED_COVERAGE"
]

# --- Database Functions ---
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None: db.close()

def init_db():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='submissions';")
    if cursor.fetchone() is None:
        cursor.execute("""
            CREATE TABLE submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                submitted_at TIMESTAMP NOT NULL,
                project_id TEXT NOT NULL,
                submitted_uri TEXT NOT NULL,
                threat_types TEXT NOT NULL,
                operation_name TEXT NOT NULL
            );
        """)
        db.commit()
        print("Initialized the database and created the 'submissions' table.")

@app.cli.command('init-db')
def init_db_command():
    init_db()

def log_submission(project_id, uri, threat_types_list, operation_name):
    db = get_db()
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    threat_types_json = json.dumps(threat_types_list)
    try:
        db.execute('INSERT INTO submissions (submitted_at, project_id, submitted_uri, threat_types, operation_name) VALUES (?, ?, ?, ?, ?)',(timestamp, project_id, uri, threat_types_json, operation_name))
        db.commit()
    except sqlite3.Error as e:
        flash(f"Warning: Submission succeeded but failed to log to local DB. Error: {e}", "warning")

def get_all_submissions(limit=50):
    if not os.path.exists(DATABASE): return []
    try:
        db = get_db()
        return db.execute('SELECT id, submitted_at, project_id, submitted_uri, operation_name FROM submissions ORDER BY submitted_at DESC LIMIT ?', (limit,)).fetchall()
    except sqlite3.OperationalError:
        flash("Warning: Could not fetch submission history. The database might be initializing.", "warning")
        return []

# --- Credential Helpers ---
def get_sa_credentials_from_info(key_info_dict):
    if not key_info_dict: raise ValueError("Service Account Key info is required.")
    try:
        return service_account.Credentials.from_service_account_info(key_info_dict, scopes=["https://www.googleapis.com/auth/cloud-platform"]), key_info_dict.get("client_email")
    except KeyError as e: raise ValueError(f"Invalid SA key structure. Missing: {e}")

def parse_uploaded_sa_key(file_storage):
    if not file_storage or not file_storage.filename: raise ValueError("No SA Key file selected.")
    try: return json.loads(file_storage.read().decode('utf-8'))
    except Exception as e: raise ValueError(f"Error reading SA Key file: {e}")

# --- Parsing Helpers ---
def get_display_attributes(confidence_string):
    if not confidence_string: return 'safe', False
    confidence_lower = confidence_string.lower()
    is_risky, display_class = False, 'safe'
    if 'extremely_high' in confidence_lower or 'high' in confidence_lower:
        display_class, is_risky = 'high', True
    elif 'medium' in confidence_lower:
        display_class, is_risky = 'medium', True
    elif 'low' in confidence_lower:
        display_class = 'low'
    return display_class, is_risky

def parse_evaluation_results(uri, response_text):
    try: response_data = json.loads(response_text)
    except json.JSONDecodeError: return None
    scores_by_type, evaluations = {}, []
    all_scores, high_risk_detected = response_data.get('scores', []), False
    for score in all_scores:
        if score and score.get('threatType'):
            confidence_value = score.get('confidenceLevel') or score.get('confidence')
            if confidence_value: scores_by_type[score.get('threatType')] = confidence_value
    for threat_type in EVALUATE_API_SUPPORTED_THREAT_TYPES:
        confidence = scores_by_type.get(threat_type, 'SAFE')
        display_class, is_risky = get_display_attributes(confidence)
        if is_risky: high_risk_detected = True
        evaluations.append({'type': threat_type, 'confidence': confidence.replace('_', ' ').title(), 'display_class': display_class})
    return {'uri': uri, 'scanned_at': datetime.datetime.now().strftime('%b %d, %Y, %I:%M:%S %p'), 'evaluations': evaluations, 'high_risk_detected': high_risk_detected, 'raw_json': json.dumps(response_data, indent=2)}

# This block ensures the database is created when a new Cloud Run instance starts.
with app.app_context():
    init_db()

# --- Routes ---
@app.route('/')
def index():
    session_data = {k: session.pop(k, None) for k in ['last_action', 'api_status', 'error_message', 'operation_name', 'operation_id_checked']}
    raw_api_response = session.pop('api_response', None)
    pretty_api_response = None
    if raw_api_response:
        try: pretty_api_response = json.dumps(json.loads(raw_api_response), indent=2)
        except (json.JSONDecodeError, TypeError): pretty_api_response = raw_api_response
    active_tab = session.pop('active_tab', 'scan')
    return render_template('index.html',
        submission_threat_types=SUBMISSION_THREAT_TYPES,
        submissions=get_all_submissions(),
        scan_history=session.get('scan_history', []),
        lookup_history=session.get('lookup_history', []),
        api_response=pretty_api_response, active_tab=active_tab, **session_data
    )

@app.route('/clear_cached_key')
def clear_cached_key():
    if 'cached_sa_key' in session:
        session.pop('cached_sa_key', None)
        flash("Cached Service Account Key has been cleared.", "success")
    return redirect(url_for('index'))

@app.route('/lookup', methods=['POST'])
def handle_lookup():
    api_key = request.form.get('user_api_key')
    uri_to_lookup = request.form.get('uri_lookup')
    if not api_key or not uri_to_lookup:
        flash("Lookup Error: API Key and URI are required.", "error")
        session['active_tab'] = 'scan'
        return redirect(url_for('index'))
    error_message = None
    try:
        params = [('threatTypes', t) for t in LOOKUP_API_SUPPORTED_THREAT_TYPES]
        params.append(('uri', uri_to_lookup))
        lookup_url = f"{WEBRISK_API_ENDPOINT}/v1/uris:search?key={api_key}"
        response = requests.get(lookup_url, params=params)
        response.raise_for_status()
        response_data = response.json()
        threat_found = 'threat' in response_data and response_data['threat']
        parsed_result = {
            'uri': uri_to_lookup,
            'scanned_at': datetime.datetime.now().strftime('%b %d, %Y, %I:%M:%S %p'),
            'threat_found': threat_found,
            'threat_info': response_data.get('threat', {}),
            'raw_json': json.dumps(response_data, indent=2)
        }
        lookup_history = session.get('lookup_history', [])
        lookup_history.insert(0, parsed_result)
        session['lookup_history'] = lookup_history[:10]
        flash(f"Lookup complete: {'Threat found' if threat_found else 'No threat found'}.", "warning" if threat_found else "success")
    except requests.exceptions.RequestException as e:
        error_message = f"API Request Failed: {e}. Response: {e.response.text if e.response else 'N/A'}"
    except Exception as e:
        error_message = f"An unexpected error occurred during lookup: {e}"
    if error_message: flash(error_message, "error")
    session['active_tab'] = 'scan'
    return redirect(url_for('index'))

@app.route('/evaluate', methods=['POST'])
def handle_evaluate():
    api_key = request.form.get('user_api_key')
    uri_to_evaluate = request.form.get('uri_evaluate')
    if not api_key or not uri_to_evaluate:
        flash("Evaluate Error: API Key and URI are required.", "error"); return redirect(url_for('index'))
    api_response_text, error_message = "", None
    try:
        evaluate_url = f"https://webrisk.googleapis.com/v1eap1:evaluateUri?key={api_key}"
        request_body = { 'uri': uri_to_evaluate, 'threatTypes': EVALUATE_API_SUPPORTED_THREAT_TYPES }
        headers = { 'Content-Type': 'application/json', 'User-Agent': 'Flask-Web-Risk-UI/4.0' }
        response = requests.post(evaluate_url, headers=headers, json=request_body)
        api_response_text = response.text
        response.raise_for_status()
        parsed_result = parse_evaluation_results(uri_to_evaluate, api_response_text)
        if parsed_result:
            scan_history = session.get('scan_history', [])
            scan_history.insert(0, parsed_result)
            session['scan_history'] = scan_history[:10]
            flash("Evaluation successful.", "success")
        else:
            error_message = "Could not parse a valid evaluation from the API response."
    except requests.exceptions.RequestException as e:
        error_message = f"API Request Failed: {e}. Response: {e.response.text if e.response else 'N/A'}"
    except Exception as e:
        error_message = f"An unexpected error occurred during evaluate: {e}"
    if error_message: flash(error_message, "error")
    session['active_tab'] = 'scan'
    return redirect(url_for('index'))

@app.route('/submit', methods=['POST'])
def handle_submission():
    api_response_text, error_message, operation_name = "", None, None
    try:
        user_project_id = request.form.get('user_project_id')
        uri_to_submit = request.form.get('uri_submit')
        threat_types = request.form.getlist('submission_threat_type')
        if not all([user_project_id, uri_to_submit, threat_types]):
            raise ValueError("Project ID, URI, and at least one Threat Type are required.")
        sa_key_file = request.files.get('user_sa_key_file_submit')
        key_info = None
        if sa_key_file and sa_key_file.filename:
            key_info = parse_uploaded_sa_key(sa_key_file)
            session['cached_sa_key'] = key_info
            flash("Service Account Key has been cached for this session.", "info")
        elif 'cached_sa_key' in session:
            key_info = session['cached_sa_key']
        else:
            raise ValueError("A Service Account Key file is required. Please upload one.")
        credentials, _ = get_sa_credentials_from_info(key_info)
        authed_session = AuthorizedSession(credentials)
        submit_url = f"{WEBRISK_API_ENDPOINT}/v1/projects/{user_project_id}/uris:submit"
        payload = {"submission": {"uri": uri_to_submit, "threatTypes": threat_types}}
        response = authed_session.post(submit_url, headers={'Content-Type': 'application/json'}, json=payload)
        api_response_text = response.text
        response.raise_for_status()
        operation_name = response.json().get('name')
        if operation_name:
            log_submission(user_project_id, uri_to_submit, threat_types, operation_name)
            flash(f"Submission successful! Operation: {operation_name}", "success")
    except (ValueError, BadRequest, json.JSONDecodeError) as e: error_message = f"Configuration Error: {e}"
    except requests.exceptions.RequestException as e: error_message = f"API Request Failed: {e}. Response: {e.response.text if e.response else 'N/A'}"
    except Exception as e: error_message = f"An unexpected error occurred: {e}"
    if error_message: flash(error_message, "error")
    session['active_tab'] = 'submit'
    session['last_action'] = 'submit'; session['api_response'] = api_response_text
    session['operation_name'] = operation_name
    return redirect(url_for('index'))

@app.route('/check_status', methods=['POST'])
def handle_check_status():
    api_response_text, error_message, operation_id = "", None, request.form.get('operation_id')
    try:
        user_project_id = request.form.get('user_project_id')
        if not all([user_project_id, operation_id]):
            raise ValueError("Project ID and Operation ID are required.")
        sa_key_file = request.files.get('user_sa_key_file_check')
        key_info = None
        if sa_key_file and sa_key_file.filename:
            key_info = parse_uploaded_sa_key(sa_key_file)
            session['cached_sa_key'] = key_info
            flash("Service Account Key has been cached for this session.", "info")
        elif 'cached_sa_key' in session:
            key_info = session['cached_sa_key']
        else:
            raise ValueError("A Service Account Key file is required.")
        credentials, _ = get_sa_credentials_from_info(key_info)
        authed_session = AuthorizedSession(credentials)
        full_op_name = operation_id if '/' in operation_id else f"projects/{user_project_id}/operations/{operation_id}"
        check_url = f"{WEBRISK_API_ENDPOINT}/v1/{full_op_name}"
        response = authed_session.get(check_url, headers={'Content-Type': 'application/json'})
        api_response_text = response.text
        response.raise_for_status()
        flash("Operation status retrieved successfully.", "success")
    except (ValueError, BadRequest, json.JSONDecodeError) as e: error_message = f"Configuration Error: {e}"
    except requests.exceptions.RequestException as e: error_message = f"API Request Failed: {e}. Response: {e.response.text if e.response else 'N/A'}"
    except Exception as e: error_message = f"An unexpected error occurred: {e}"
    if error_message: flash(error_message, "error")
    session['active_tab'] = 'submit'
    session['last_action'] = 'check_status'; session['api_response'] = api_response_text
    session['operation_id_checked'] = operation_id
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)