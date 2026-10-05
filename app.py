from flask import Flask, jsonify, request
from flask_cors import CORS
import sqlite3
import os
from werkzeug.utils import secure_filename

from security.password import hash_password, verify_password

app = Flask(__name__)

CORS(app)

DATABASE = "sylora.db"

# =========================
# FILE UPLOAD SETTINGS
# =========================

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"pdf", "txt", "docx"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


# =========================
# DATABASE
# =========================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_database():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# =========================
# HOME
# =========================

@app.route("/")
def home():
    return jsonify({
        "status": "success",
        "message": "SYLORA backend is running"
    })


# =========================
# SECURITY STATUS
# =========================

@app.route("/api/security-status")
def security_status():
    return jsonify({
        "application": "SYLORA",
        "security": "enabled",
        "features": [
            "Input Validation",
            "Password Hashing",
            "Cryptography",
            "Secure File Upload"
        ]
    })


# =========================
# REGISTER
# =========================

@app.route("/api/register", methods=["POST"])
def register():

    data = request.get_json()

    if not data:
        return jsonify({
            "status": "error",
            "message": "No data received"
        }), 400

    name = data.get("name", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not name or not email or not password:
        return jsonify({
            "status": "error",
            "message": "All fields are required"
        }), 400

    if len(password) < 8:
        return jsonify({
            "status": "error",
            "message": "Password must be at least 8 characters"
        }), 400

    password_hash = hash_password(password)

    try:

        conn = get_db()

        conn.execute("""
            INSERT INTO users (name, email, password_hash)
            VALUES (?, ?, ?)
        """, (name, email, password_hash))

        conn.commit()
        conn.close()

        return jsonify({
            "status": "success",
            "message": "Account created successfully"
        }), 201

    except sqlite3.IntegrityError:

        return jsonify({
            "status": "error",
            "message": "Email already registered"
        }), 409


# =========================
# LOGIN
# =========================

@app.route("/api/login", methods=["POST"])
def login():

    data = request.get_json()

    if not data:
        return jsonify({
            "status": "error",
            "message": "No data received"
        }), 400

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({
            "status": "error",
            "message": "Email and password are required"
        }), 400

    conn = get_db()

    user = conn.execute("""
        SELECT * FROM users
        WHERE email = ?
    """, (email,)).fetchone()

    conn.close()

    if not user:
        return jsonify({
            "status": "error",
            "message": "Invalid email or password"
        }), 401

    if not verify_password(user["password_hash"], password):
        return jsonify({
            "status": "error",
            "message": "Invalid email or password"
        }), 401

    return jsonify({
        "status": "success",
        "message": "Login successful",
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"]
        }
    })


# =========================
# FILE UPLOAD
# =========================

@app.route("/api/upload", methods=["POST"])
def upload_file():

    if "file" not in request.files:
        return jsonify({
            "status": "error",
            "message": "No file uploaded"
        }), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify({
            "status": "error",
            "message": "No file selected"
        }), 400

    if not allowed_file(file.filename):
        return jsonify({
            "status": "error",
            "message": "Only PDF, TXT and DOCX files are allowed"
        }), 400

    filename = secure_filename(file.filename)

    filepath = os.path.join(
        app.config["UPLOAD_FOLDER"],
        filename
    )

    file.save(filepath)

    return jsonify({
        "status": "success",
        "message": "File uploaded successfully",
        "filename": filename
    })


# =========================
# START SERVER
# =========================

if __name__ == "__main__":

    init_database()

    app.run(debug=True)
