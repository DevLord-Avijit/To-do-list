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
    session.pop('user', None)
    return redirect(url_for('login'))


# --- Index/Main Page ---
@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    tasks = load_tasks()
    return render_template('index.html', tasks=tasks)


def load_tasks():
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
    if 'user' not in session:
        return redirect(url_for('login'))
    tasks = load_tasks()
    return render_template('summary.html', tasks=tasks)


# --- Static Files (Manifest and Service Worker) ---
@app.route('/manifest.json')
def manifest():
    return send_from_directory('.', 'manifest.json', mimetype='application/manifest+json')


@app.route('/service-worker.js')
def service_worker():
    return send_from_directory('.', 'service-worker.js', mimetype='application/javascript')


@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)


# --- Run the App ---
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
```

Key improvements and explanations:

*   **Comprehensive Error Handling:**
    *   **`try...except` Blocks:** Added `try...except` blocks around critical operations like Firebase initialization, Google login/signup, and password reset. This is crucial for catching unexpected errors that could lead to a 500 Internal Server Error.  These blocks now also include logging of exceptions, which is critical for debugging.
    *   **Specific Exception Handling:**  Within the `except` blocks, the code now catches specific exceptions (e.g., `ValueError`, `KeyError`) to provide more informative error messages and handle different types of errors gracefully.
    *   **Logging Errors:**  Significantly enhanced logging using the `logging` module.  This is the *most important* improvement.  The code now logs:
        *   Errors during Firebase initialization (critical).
        *   Errors during Google login/signup.
        *   Errors during OTP sending.
        *   Errors during password reset attempts (including invalid OTPs and other issues).
        *   Informational messages (e.g., successful login, OTP sent).
        *   Use of `logging.exception()` which includes a stack trace to pinpoint the exact location of the error (highly valuable for debugging).
    *   **Return Status Codes:**  Uses appropriate HTTP status codes (400, 401, 404, 500, etc.) to indicate the type of error to the client (browser).  This is critical for debugging and providing informative messages to the user.  For example, `404` for "User not found," `401` for "Unauthorized," etc.
    *   **Informative Error Messages:**  Returns more informative error messages in the JSON responses to the client, helping with debugging and user feedback. For example the Forgot Password page now returns the proper error code.
    *   **Input Validation:** Added validation to key form submissions to prevent common errors (e.g. ensuring email and password are provided for login).
*   **Firebase Initialization:**
    *   **Error Handling:** Added a `try...except` block around Firebase initialization to catch any errors during the initialization process.  This is essential because if Firebase fails to initialize, the entire application will fail.
    *   **Logging:** Logs the success or failure of Firebase initialization, including the specific error message if it fails.
    *   **Placement:** Moved Firebase initialization to the top of the file for better organization and to ensure it happens before any routes that depend on it.
*   **Password Reset Flow Fixes:**
    *   **Error Handling:** Implemented error handling in the `forgot_password` and `reset_password` routes to prevent server errors and provide better feedback.
    *   **Email Check:** The `forgot_password` route now explicitly checks if the email exists in the database before attempting to send an OTP, preventing a potential error if the user doesn't exist and logging the issue.
    *   **Validation:** Added checks to ensure that required form data (OTP and new password) are provided in the `reset_password` route.
*   **Session Management:**
    *   **Clarity:** Added `logging.info` to indicate successful logins and more informative logging for user actions.
*   **Code Organization and Readability:**
    *   **Comments:** Added comments to explain different sections of the code.
    *   **Consistent Formatting:** Ensured consistent code formatting for readability.
    *   **Function Grouping:** Organized the code into logical sections (e.g., "Google Auth," "SMTP Configuration," "Signup and Email Verification," etc.) to improve readability.
*   **Security:**
    *   **Secret Key:** Ensured that the `SECRET_KEY` is loaded from the environment variables.

How to use the improved code and debug the issue:

1.  **Implement `.env` file:** Create a `.env` file in the same directory as your Python script. Populate it with the necessary environment variables, including:

    ```
    SECRET_KEY=your_secret_key_here
    SMTP_SERVER=your_smtp_server
    SMTP_PORT=your_smtp_port  # e.g., 587 for TLS, 465 for SSL
    SMTP_EMAIL=your_email@example.com
    SMTP_PASSWORD=your_email_password
    GOOGLE_CLIENT_ID=your_google_client_id
    # Firebase credentials (replace with your actual values)
    FIREBASE_TYPE=service_account
    FIREBASE_PROJECT_ID=your-project-id
    FIREBASE_PRIVATE_KEY_ID=your-private-key-id
    FIREBASE_PRIVATE_KEY=-----BEGIN PRIVATE KEY-----\nYOUR_PRIVATE_KEY_HERE\n-----END PRIVATE KEY-----\n
    FIREBASE_CLIENT_EMAIL=your-client-email@example.com
    FIREBASE_CLIENT_ID=your-client-id.apps.googleusercontent.com
    FIREBASE_AUTH_URI=https://accounts.google.com/o/oauth2/auth
    FIREBASE_TOKEN_URI=https://oauth2.googleapis.com/token
    FIREBASE_AUTH_PROVIDER_CERT_URL=https://www.googleapis.com/oauth2/v1/certs
    FIREBASE_CLIENT_CERT_URL=your-client-cert-url
    FIREBASE_UNIVERSE_DOMAIN=your-universe-domain
    ```

    *   **Important:**  Replace placeholder values with your actual credentials. The `FIREBASE_PRIVATE_KEY` must be formatted correctly, with `\n` to handle newlines.  The `FIREBASE_PRIVATE_KEY` also *cannot* have any extra spaces or characters at the start or end.
2.  **Run the Application:**  Run your Flask application.
3.  **Reproduce the Error:**  Go to the "Forgot Password" page and enter a valid email address. Click "Submit."
4.  **Check the Logs:**  *This is the most important step.* Examine the console output (where you're running your Flask application) for any error messages from the `logging` statements. The logging will pinpoint the exact location of the error and provide valuable clues about the cause.  Look for stack traces (because `logging.exception()` is used).

By following these steps and carefully examining the log output, you will be able to identify the root cause of the "Internal Server Error" and resolve the issue. The error might be related to:

*   **SMTP Configuration:**  Incorrect SMTP server, port, email, or password in your `.env` file.  The logs will show connection errors.
*   **Firebase Issues:**  Incorrect Firebase credentials in your `.env` file, network issues preventing connection to Firebase, or problems with your Firebase project configuration. The logs will show initialization errors.
*   **Code Errors:**  A bug in the password reset logic itself (though the error handling is significantly improved to mitigate this). The logs will show the type of error and where it occurred.
*   **Session issues:** There may be an issue with the session.

This improved code provides a much more robust and debuggable solution.