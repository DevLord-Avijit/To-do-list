# 📅 To-Do List App with Flask & Firebase

## 🚀 Overview
This is a **To-Do List Web App** built using **Flask, HTML, CSS, and JavaScript**, with **Firebase** as the database. The app allows users to:
- Sign up/login using **Google Authentication** or **Email OTP verification**.
- Choose a specific date and create **slots** with a deadline.
- Add **tasks** inside slots, each having a **progress bar** to track completion.

## 🛠️ Features
- 🔑 **User Authentication** (Google Auth & Email OTP verification)
- 📆 **Date-based To-Do List**
- ⏳ **Slots with Deadlines**
- ✅ **Tasks with Progress Tracking**
- 🔥 **Firebase Integration** for database management
- ✉️ **Email Notifications** using Flask-Mail
- 🎨 **Responsive UI** with HTML, CSS, and JS

## 📂 Project Structure
```
📦 todo-list-app
├── 📁 static
│   ├── 📁 css
│  
├── 📁 templates
│   ├── index.html
│   ├── login.html
│   ├── signup.html
│   ├── forgot_password.html
|   └──reset_password.html
│   └── verify_email.html
├── requirements.txt
├── README.md
└── app.py
└── .env
```

## 🏗️ Installation & Setup
### 1️⃣ Clone the Repository
```sh
 git clone https://github.com/DevLord-Avijit/To-do-list.git
 cd To-do-list
```

### 2️⃣ Create a Virtual Environment
```sh
 python -m venv venv
 source venv/bin/activate  # On Mac/Linux
 venv\Scripts\activate     # On Windows
```

### 3️⃣ Install Dependencies
```sh
 pip install -r requirements.txt
```

### 4️⃣ Configure Firebase
1. Create a Firebase project at [Firebase Console](https://console.firebase.google.com/).
2. Enable **Authentication** (Google & Email/Password).
3. Get your Firebase Admin SDK JSON key and place it in the project folder.
4. Set up Firebase credentials in `.env`:
```ini
FIREBASE_CREDENTIALS=your_firebase_admin_sdk.json
SECRET_KEY=your_secret_key
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_email_password
```
5. Set up the full `.env`:
```ini
SECRET_KEY=your_secret_key_here
FIREBASE_CREDENTIALS_PATH=your-firebase-credentials.json

# SMTP Configuration - Get these from Gmail
# 1. Go to Gmail Account Settings
# 2. Enable 2-Step Verification
# 3. Create an App Password
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_EMAIL=your.email@gmail.com
SMTP_PASSWORD=your_app_password_here

# Firebase Keys
# Get these from Firebase Console (https://console.firebase.google.com):
# 1. Go to Project Settings
# 2. Service Accounts tab
# 3. Generate new private key
FIREBASE_TYPE=service_account
FIREBASE_PROJECT_ID=your_project_id
FIREBASE_PRIVATE_KEY_ID=your_private_key_id
FIREBASE_PRIVATE_KEY="your_private_key_here"
FIREBASE_CLIENT_EMAIL=your_client_email
FIREBASE_CLIENT_ID=your_client_id
FIREBASE_AUTH_URI=https://accounts.google.com/o/oauth2/auth
FIREBASE_TOKEN_URI=https://oauth2.googleapis.com/token
FIREBASE_AUTH_PROVIDER_CERT_URL=https://www.googleapis.com/oauth2/v1/certs
FIREBASE_CLIENT_CERT_URL=your_client_cert_url
FIREBASE_UNIVERSE_DOMAIN=googleapis.com

# Google OAuth Credentials
# Get these from Google Cloud Console (https://console.cloud.google.com):
# 1. Create a new project or select existing
# 2. Enable OAuth 2.0
# 3. Configure OAuth consent screen
# 4. Create OAuth client ID credentials
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
```

### 5️⃣ Run the Flask App
```sh
 python run.py
```
Or use Gunicorn for production:
```sh
 gunicorn -w 4 -b 0.0.0.0:5000 run:app
```

## 🔑 Authentication
- **Google Auth**: Uses Firebase Authentication for login/signup.
- **Email OTP Verification**: OTP is sent via email using Flask-Mail.

## 📊 Task Management Workflow
1. **Choose a Date** 📅
2. **Add Slots** 🕒 (Slots are identified by their deadline)
3. **Add Tasks** 📝 inside slots
4. **Track Progress** 📈 using a progress bar

## 📦 Dependencies
```txt
Gunicorn==20.1.0
Flask
Flask-WTF
Flask-Login
Flask-SQLAlchemy
Flask-Mail
Werkzeug
Jinja2
itsdangerous
WTForms
requests
gunicorn
python-dotenv
firebase_admin
flask-session
email_validator
```

## 🌍 Live Demo
[🔗 Visit the To-Do List App](https://tasks.avijitsingh.ct.ws)

## 🤝 Contributing
Feel free to contribute! Fork the repository, make your changes, and submit a pull request.

## 📜 License
This project is licensed under the MIT License.

---
💡 **Made  by Avijit Singh**
