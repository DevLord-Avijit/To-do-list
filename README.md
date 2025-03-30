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
```

## 🏗️ Installation & Setup
### 1️⃣ Clone the Repository
```sh
 git clone https://github.com/yourusername/todo-list-app.git
 cd todo-list-app
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


## 🤝 Contributing
Feel free to contribute! Fork the repository, make your changes, and submit a pull request.

## 📜 License
This project is licensed under the MIT License.

---
💡 **Made  by Avijit Singh**
