```python
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
import smtplib
import random
from datetime import datetime
import firebase_admin
from firebase_admin import credentials, firestore
import os
import logging
from dotenv import load_dotenv
from google.oauth2 import id_token
from google.auth.transport import requests

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Firebase Initialization (Moved to top for consistency and clarity)
try:
    # Construct Firebase credentials from environment variables
    firebase_credentials = {
        "type": os.getenv("FIREBASE_TYPE"),
        "project_id": os.getenv("FIREBASE_PROJECT_ID"),
        "private_key_id": os.getenv("FIREBASE_PRIVATE_KEY_ID"),
        "private_key": os.getenv("FIREBASE_PRIVATE_KEY").replace("\\n", "\n"),
        "client_email": os.getenv("FIREBASE_CLIENT_EMAIL"),
        "client_id": os.getenv("FIREBASE_CLIENT_ID"),
        "auth_uri": os.getenv("FIREBASE_AUTH_URI"),
        "token_uri": os.getenv("FIREBASE_TOKEN_URI"),
        "auth_provider_x509_cert_url": os.getenv("FIREBASE_AUTH_PROVIDER_CERT_URL"),
        "client_x509_cert_url": os.getenv("FIREBASE_CLIENT_CERT_URL"),
        "universe_domain": os.getenv("FIREBASE_UNIVERSE_DOMAIN"),
    }

    # Initialize Firebase Admin SDK
    cred = credentials.Certificate(firebase_credentials)
    firebase_admin.initialize_app(cred)
    db = firestore.client()
    tasks_ref = db.collection("tasks")
    users_ref = db.collection("users")
    logging.info("Firebase initialized successfully.")  # Log successful initialization
except Exception as e:
    logging.critical(f"Firebase initialization failed: {e}")  # Log critical errors
    # Consider a graceful shutdown or alternative behavior if Firebase fails

# Google Auth
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")

@app.route('/google_login', methods=['POST'])
def google_login():
    """
    Handles Google login via a POST request.

    Verifies the Google ID token, checks if the user exists, and logs the user in.

    Returns:
        JSON: {"status": "success", "message": "Google login successful"} on success,
              or {"status": "error", "message": "..."} with an error message on failure.
    """
    try:
        token = request.json.get('credential')
        if not token:
            return jsonify({"status": "error", "message": "Missing token"}), 400

        # Verify the token
        idinfo = id_token.verify_oauth2_token(token, requests.Request(), GOOGLE_CLIENT_ID)
        email = idinfo['email']

        # Check if the user exists in the database
        user_doc = users_ref.document(email).get()
        if not user_doc.exists:
            return jsonify({"status": "error", "message": "No account found. Please sign up first."}), 401

        # Log the user in
        session['user'] = email
        return jsonify({"status": "success", "message": "Google login successful"}), 200

    except ValueError as e:
        logging.error(f"Google login failed: {e}")
        return jsonify({"status": "error", "message": "Invalid token"}), 400
    except Exception as e:
        logging.exception(f"Unexpected error during Google login: {e}") # Use exception to include stack trace
        return jsonify({"status": "error", "message": "An unexpected error occurred"}), 500


# Google Sign up
@app.route('/google_signup', methods=['POST'])
def google_signup():
    """
    Handles Google signup via a POST request.

    Verifies the Google ID token, creates a new user in the database, and logs the user in.

    Returns:
        JSON: {"status": "success", "message": "Google signup successful"} on success,
              or {"status": "error", "message": "..."} with an error message on failure.
    """
    try:
        token = request.json.get('credential')
        if not token:
            return jsonify({"status": "error", "message": "Missing token"}), 400

        # Verify the token
        idinfo = id_token.verify_oauth2_token(token, requests.Request(), GOOGLE_CLIENT_ID)
        email = idinfo['email']
        name = idinfo.get('name', 'Google User')  # Fallback if no name is provided

        # Check if the user already exists
        user_doc = users_ref.document(email).get()
        if user_doc.exists:
            return jsonify({"status": "error", "message": "Account already exists. Please login instead."}), 409

        # Save new user with email and name, no password
        users_ref.document(email).set({
            'email': email,
            'username': name,
            'google_signup': True
        })

        # Log the user in
        session['user'] = email
        return jsonify({"status": "success", "message": "Google signup successful"}), 200

    except ValueError as e:
        logging.error(f"Google signup failed: {e}")
        return jsonify({"status": "error", "message": "Invalid token"}), 400
    except Exception as e:
        logging.exception(f"Unexpected error during Google signup: {e}") # Use exception to include stack trace
        return jsonify({"status": "error", "message": "An unexpected error occurred"}), 500


# SMTP Configuration
SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = int(os.getenv('SMTP_PORT'))
SMTP_EMAIL = os.getenv('SMTP_EMAIL')
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')

# Helper function to send OTP
def send_otp(email, otp):
    """
    Sends a One-Time Password (OTP) to the specified email address.

    Args:
        email (str): The recipient's email address.
        otp (int): The OTP to send.

    Raises:
        Exception: If there's an error sending the email.
    """
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            message = f"Subject: Verify Your Email\n\nYour OTP is: {otp}"
            server.sendmail(SMTP_EMAIL, email, message)
        logging.info(f"OTP sent to {email}")
    except Exception as e:
        logging.error(f"Failed to send OTP to {email}: {e}")


# ---  Signup and Email Verification ---
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """
    Handles user signup via a GET or POST request.

    - GET: Renders the signup form.
    - POST: Processes the signup form submission.  Sends an OTP for verification.

    Returns:
        - GET: Renders 'signup.html'.
        - POST: Redirects to 'verify_email' on success, or renders 'signup.html' with an error message on failure.
    """
    if request.method == 'POST':
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')

        if not all([email, username, password]):
            return render_template('signup.html', message="All fields are required.", message_type="error")

        if users_ref.document(email).get().exists:
            return render_template('signup.html', message="User already exists", message_type="error")

        try:
            otp = random.randint(100000, 999999)
            hashed_password = generate_password_hash(password)

            send_otp(email, otp)
            session['temp_user'] = {'email': email, 'username': username, 'password': hashed_password, 'otp': otp}
            return redirect(url_for('verify_email'))

        except Exception as e:
            logging.exception(f"Error during signup: {e}") # Use exception to include stack trace
            return render_template('signup.html', message="An error occurred. Please try again.", message_type="error")

    return render_template('signup.html')

@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    """
    Handles email verification via a GET or POST request.

    - GET: Renders the email verification form (not implemented in this code).
    - POST: Verifies the OTP entered by the user.

    Returns:
        JSON: {"success": true} on successful verification,
              or {"success": false, "error": "..."} with an error message on failure.
    """
    if request.method == 'POST':
        otp = request.form.get('otp')
        temp_user = session.get('temp_user')

        if not temp_user:
            logging.error("Session expired or temp_user missing.")
            return jsonify({"success": False, "error": "Session expired. Please sign up again."}), 400

        try:
            if otp and int(otp) == temp_user['otp']:
                users_ref.document(temp_user['email']).set({
                    'username': temp_user['username'],
                    'password': temp_user['password']
                })
                session.pop('temp_user', None)
                logging.info("Email verified successfully for user: %s", temp_user['email'])
                return jsonify({"success": True}), 200
            else:
                logging.warning("Invalid OTP entered for user: %s", temp_user['email'])
                return jsonify({"success": False, "error": "Invalid OTP. Please try again."}), 400
        except (ValueError, KeyError) as e:
            logging.error("Error during OTP verification: %s", e)
            return jsonify({"success": False, "error": "Invalid OTP or session data."}), 400
        except Exception as e:
            logging.exception(f"Unexpected error during OTP verification: {e}") # Use exception to include stack trace
            return jsonify({"success": False, "error": "An unexpected error occurred."}), 500


# --- Login and Logout ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles user login via a GET or POST request.

    - GET: Renders the login form.
    - POST: Processes the login form submission.

    Returns:
        - GET: Renders 'login.html'.
        - POST: JSON: {"status": "success", "message": "Login successful"} on success,
                       or {"status": "error", "message": "..."} with an error message on failure.
    """
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not all([email, password]):
            return jsonify({"status": "error", "message": "Email and password are required"}), 400

        user_doc = users_ref.document(email).get()
        if user_doc.exists:
            user_data = user_doc.to_dict()
            if check_password_hash(user_data['password'], password):
                session['user'] = email
                logging.info(f"User {email} logged in successfully.")
                return jsonify({"status": "success", "message": "Login successful"}), 200
            else:
                logging.warning(f"Invalid password for user: {email}")
                return jsonify({"status": "error", "message": "Invalid credentials"}), 401
        else:
            logging.warning(f"User does not exist: {email}")
            return jsonify({"status": "error", "message": "User does not exist"}), 404

    return render_template('login.html')

@app.route('/logout')
def logout():
    """
    Handles user logout.

    Removes the 'user' from the session.

    Returns:
        Redirects to the 'login' route.
    """
    session.pop('user', None)
    return redirect(url_for('login'))


# --- Index/Main Page ---
@app.route('/')
def index():
    """
    Serves the index/main page.

    Requires the user to be logged in.

    Returns:
        - Redirects to 'login' if the user is not logged in.
        - Renders 'index.html' with tasks if the user is logged in.
    """
    if 'user' not in session:
        return redirect(url_for('login'))
    tasks = load_tasks()
    return render_template('index.html', tasks=tasks)


def load_tasks():
    """
    Loads tasks for the current user.

    Returns:
        dict: A dictionary where keys are dates and values are lists of tasks.
    """
    if 'user' not in session:
        return {}
    email = session['user']
    tasks = {}
    docs = tasks_ref.document(email).collection("tasks").stream()
    for doc in docs:
        data = doc.to_dict()
        logging.debug(f"Loaded document: {doc.id}, data: {data}")  # Log loaded data
        if 'slots' not in data:
            data['slots'] = []
        data['slots'] = [slot for slot in data['slots'] if not slot.get('deleted', False)]
        for slot in data['slots']:
            slot['tasks'] = [task for task in slot['tasks'] if not task.get('deleted', False)]
        data['slots'].sort(key=lambda slot: datetime.strptime(slot['deadline'], "%H:%M"))
        tasks[doc.id] = data['slots']
    return tasks


# --- Utility Functions ---
def rearrange_slots(email, date):
    """
    Rearrange the slots for a given date in ascending order of slot deadlines.

    Args:
        email (str): The user's email.
        date (str): The date for which to rearrange slots.
    """
    doc_ref = tasks_ref.document(email).collection("tasks").document(date)
    doc = doc_ref.get()
    if doc.exists:
        slots = doc.to_dict().get('slots', [])
        slots.sort(key=lambda slot: datetime.strptime(slot['deadline'], "%H:%M"))
        doc_ref.set({'slots': slots})


# --- Forgot Password and Reset Password ---
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """
    Handles the forgot password process via GET or POST request.

    - GET: Renders the forgot password form.
    - POST: Sends an OTP to the user's email for password reset.

    Returns:
        - GET: Renders 'forgot_password.html'.
        - POST: JSON: {"status": "success", "message": "Password reset instructions sent"} on success,
                       or {"status": "error", "message": "..."} with an error message on failure.
    """
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            return jsonify({"status": "error", "message": "Email is required"}), 400

        user_doc = users_ref.document(email).get()
        if user_doc.exists():
            try:
                otp = random.randint(100000, 999999)
                send_otp(email, otp)
                session['reset_password'] = {'email': email, 'otp': otp}
                logging.info(f"Password reset requested for {email}. OTP sent.")
                return jsonify({"status": "success", "message": "Password reset instructions sent"}), 200
            except Exception as e:
                logging.exception(f"Error sending OTP for password reset: {e}")
                return jsonify({"status": "error", "message": "Failed to initiate password reset. Please try again."}), 500
        else:
            logging.warning(f"Password reset requested for non-existent email: {email}")
            return jsonify({"status": "error", "message": "Email not registered"}), 404

    return render_template('forgot_password.html')


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    """
    Handles the password reset process via GET or POST request.

    - GET: Renders the reset password form (not explicitly implemented in this code).
    - POST: Validates the OTP and updates the user's password.

    Returns:
        JSON: {"status": "success", "message": "Password reset successfully"} on success,
              or {"status": "error", "message": "..."} with an error message on failure.
    """
    if request.method == 'POST':
        otp = request.form.get('otp')
        new_password = request.form.get('new_password')
        reset_data = session.get('reset_password')

        if not otp or not new_password:
            return jsonify({"status": "error", "message": "OTP and new password are required"}), 400

        try:
            if reset_data and int(otp) == reset_data['otp']:
                hashed_password = generate_password_hash(new_password)
                users_ref.document(reset_data['email']).update({'password': hashed_password})
                session.pop('reset_password', None)
                logging.info(f"Password reset successfully for {reset_data['email']}.")
                return jsonify({"status": "success", "message": "Password reset successfully"}), 200
            else:
                logging.warning("Invalid OTP entered during password reset.")
                return jsonify({"status": "error", "message": "Invalid OTP"}), 400
        except ValueError:
            logging.error("Invalid OTP format during password reset.")
            return jsonify({"status": "error", "message": "Invalid OTP format. OTP must be a number."}), 400
        except Exception as e:
            logging.exception(f"Error during password reset: {e}")
            return jsonify({"status": "error", "message": "An unexpected error occurred"}), 500

    return render_template('reset_password.html')


# --- User Details ---
@app.route('/get_user_details', methods=['GET'])
def get_user_details():
    """
    Retrieves user details.

    Returns:
        JSON: {'name': username, 'email': email} if user is logged in,
              or {'error': 'User not logged in'} with a 401 status if not logged in.
    """
    if 'user' in session:
        email = session['user']
        user_doc = users_ref.document(email).get()
        if user_doc.exists:
            user_data = user_doc.to_dict()
            return jsonify({'name': user_data.get('username', ''), 'email': email})
    return jsonify({'error': 'User not logged in'}), 401


# --- Task Management ---
@app.route('/add_slot', methods=['POST'])
def add_slot():
    """
    Adds a new time slot for a given date.

    Requires the user to be logged in.

    Returns:
        JSON: {"status": "success"} on success,
              or {"status": "error", "message": "Unauthorized"} on failure.
    """
    if 'user' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"})
    email = session['user']
    date = request.form.get('date')
    slot_deadline = request.form.get('slot_deadline')

    if date and slot_deadline:
        doc_ref = tasks_ref.document(email).collection("tasks").document(date)
        doc = doc_ref.get()
        slots = doc.to_dict().get('slots', []) if doc.exists else []
        slots.append({'deadline': slot_deadline, 'tasks': []})
        doc_ref.set({'slots': slots})
        rearrange_slots(email, date)  # Rearrange slots after adding

    return jsonify({"status": "success"})


@app.route('/add_task', methods=['POST'])
def add_task():
    """
    Adds a new task to a specified time slot.

    Requires the user to be logged in.

    Accepts data in JSON or form data format.

    Returns:
        JSON: {"status": "success"} on success,
              or {"status": "error", "message": "..."} with an error message on failure.
    """
    if 'user' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"}), 401
    email = session['user']

    # Accept JSON or form data
    if request.is_json:
        data = request.get_json()
        date = data.get('date')
        slot_index = int(data.get('slot_index'))
        task_name = data.get('task_name')
    else:
        date = request.form.get('date')
        slot_index = int(request.form.get('slot_index'))
        task_name = request.form.get('task_name')

    if date and task_name is not None:
        doc_ref = tasks_ref.document(email).collection("tasks").document(date)
        doc = doc_ref.get()
        slots = doc.to_dict().get('slots', []) if doc.exists else []
        if slot_index < len(slots):
            slots[slot_index]['tasks'].append({'task': task_name, 'checked': False, 'progress': 0, 'deleted': False})
            doc_ref.set({'slots': slots})
            rearrange_slots(email, date)
            return jsonify({"status": "success"}), 200
        else:
            return jsonify({"status": "error", "message": "Invalid slot index"}), 400
    return jsonify({"status": "error", "message": "Missing data"}), 400


@app.route('/update_task_progress', methods=['POST'])
def update_task_progress():
    """
    Updates the progress of a specific task.

    Requires the user to be logged in.

    Returns:
        JSON: {"status": "success"} on success,
              or {"status": "error", "message": "Unauthorized"} on failure.
    """
    if 'user' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"})
    email = session['user']
    date = request.form.get('date')
    slot_index = int(request.form.get('slot_index'))
    task_index = int(request.form.get('task_index'))
    progress = int(request.form.get('progress'))

    doc_ref = tasks_ref.document(email).collection("tasks").document(date)
    doc = doc_ref.get()
    if doc.exists:
        slots = doc.to_dict().get('slots', [])
        slots[slot_index]['tasks'][task_index]['progress'] = progress
        doc_ref.set({'slots': slots})

    return jsonify({"status": "success"})


@app.route('/toggle_task', methods=['POST'])
def toggle_task():
    """
    Toggles the 'checked' status of a task.

    Requires the user to be logged in.

    Returns:
        JSON: {"status": "success"} on success,
              or {"status": "error", "message": "Unauthorized"} on failure.
    """
    if 'user' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"})
    email = session['user']
    date = request.form.get('date')
    slot_index = int(request.form.get('slot_index'))
    task_index = int(request.form.get('task_index'))

    doc_ref = tasks_ref.document(email).collection("tasks").document(date)
    doc = doc_ref.get()
    if doc.exists:
        slots = doc.to_dict().get('slots', [])
        slots[slot_index]['tasks'][task_index]['checked'] = not slots[slot_index]['tasks'][task_index]['checked']
        doc_ref.set({'slots': slots})

    return jsonify({"status": "success"})


@app.route('/get_tasks_for_date', methods=['POST'])
def get_tasks_for_date():
    """
    Retrieves tasks for a given date.

    Requires the user to be logged in.

    Returns:
        JSON: A list of tasks for the specified date, or an empty list if no tasks are found.
    """
    if 'user' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"})
    email = session['user']
    date = request.form.get('date')
    doc_ref = tasks_ref.document(email).collection("tasks").document(date)
    doc = doc_ref.get()
    if doc.exists:
        return jsonify(doc.to_dict().get('slots', []))
    return jsonify([])


@app.route('/delete_slot', methods=['POST'])
def delete_slot():
    """
    Deletes a time slot for a given date.

    Requires the user to be logged in.

    Returns:
        JSON: {"status": "success"} on success,
              or {"status": "error", "message": "Unauthorized"} on failure.
    """
    if 'user' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"})
    email = session['user']
    date = request.form.get('date')
    slot_index = int(request.form.get('slot_index'))

    doc_ref = tasks_ref.document(email).collection("tasks").document(date)
    doc = doc_ref.get()
    if doc.exists:
        slots = doc.to_dict().get('slots', [])
        if 0 <= slot_index < len(slots):
            del slots[slot_index]
            logging.debug(f"Deleted slot {slot_index} for date {date}")
            doc_ref.set({'slots': slots})
            rearrange_slots(email, date)  # Rearrange slots after deletion
        else:
            logging.warning(f"Slot index {slot_index} out of range for date {date}")
    else:
        logging.warning(f"Document for date {date} does not exist")

    return jsonify({"status": "success"})


@app.route('/delete_task', methods=['POST'])
def delete_task():
    """
    Deletes a task from a specified time slot.

    Requires the user to be logged in.

    Accepts data in JSON or form data format.

    Returns:
        JSON: {"status": "success"} on success,
              or {"status": "error", "message": "..."} with an error message on failure.
    """
    if 'user' not in session:
        return jsonify({"status": "error", "message": "Unauthorized"})
    email = session['user']

    # Accept JSON or form data
    if request.is_json:
        data = request.get_json()
        date = data.get('date')
        slot_index = int(data.get('slot_index'))
        task_index = int(data.get('task_index'))
    else:
        date = request.form.get('date')
        slot_index = int(request.form.get('slot_index'))
        task_index = int(request.form.get('task_index'))

    doc_ref = tasks_ref.document(email).collection("tasks").document(date)
    doc = doc_ref.get()
    if doc.exists:
        slots = doc.to_dict().get('slots', [])
        if slot_index < len(slots) and task_index < len(slots[slot_index]['tasks']):
            del slots[slot_index]['tasks'][task_index]
            doc_ref.set({'slots': slots})
            rearrange_slots(email, date)
            return jsonify({"status": "success"}), 200
        else:
            return jsonify({"status": "error", "message": "Invalid slot/task index"}), 400
    return jsonify({"status": "error", "message": "Document not found"}), 404


# --- Summary Page ---
@app.route('/summary')
def summary():
    """
    Serves the summary page.

    Requires the user to be logged in.

    Returns:
        - Redirects to 'login' if the user is not logged in.
        - Renders 'summary.html' with tasks if the user is logged in.
    """
    if 'user' not in session:
        return redirect(url_for('login'))
    tasks = load_tasks()
    return render_template('summary.html', tasks=tasks)


# --- Static Files (Manifest and Service Worker) ---
@app.route('/manifest.json')
def manifest():
    """
    Serves the manifest.json file.

    Returns:
        The contents of 'manifest.json' with the correct MIME type.
    """
    return send_from_directory('.', 'manifest.json', mimetype='application/manifest+json')


@app.route('/service-worker.js')
def service_worker():
    """
    Serves the service-worker.js file.

    Returns:
        The contents of 'service-worker.js' with the correct MIME type.
    """
    return send_from_directory('.', 'service-worker.js', mimetype='application/javascript')


@app.route('/static/<path:filename>')
def static_files(filename):
    """
    Serves static files from the 'static' directory.

    Args:
        filename (str): The name of the file to serve.

    Returns:
        The contents of the specified file from the 'static' directory.
    """
    return send_from_directory('static', filename)


# --- Run the App ---
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
```