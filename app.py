from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
import sqlite3
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "change-this-secret-key-before-deploying"

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
UPLOAD_DIR = BASE_DIR / "uploads"
DB_PATH = INSTANCE_DIR / "users.db"

INSTANCE_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)

ALLOWED_EXTENSIONS = {"txt"}


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            firstname TEXT NOT NULL,
            lastname TEXT NOT NULL,
            email TEXT NOT NULL,
            address TEXT NOT NULL,
            stored_filename TEXT,
            original_filename TEXT,
            word_count INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def count_words(file_path):
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    return len(text.split())


@app.route("/")
def index():
    return redirect(url_for("register"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = request.form["username"].strip()
    password = request.form["password"]
    firstname = request.form["firstname"].strip()
    lastname = request.form["lastname"].strip()
    email = request.form["email"].strip()
    address = request.form["address"].strip()
    uploaded_file = request.files.get("file")

    if not all([username, password, firstname, lastname, email, address]):
        flash("Please fill in all required fields.")
        return redirect(url_for("register"))

    stored_filename = None
    original_filename = None
    word_count = 0

    if uploaded_file and uploaded_file.filename:
        if not allowed_file(uploaded_file.filename):
            flash("Only .txt files are allowed.")
            return redirect(url_for("register"))

        original_filename = uploaded_file.filename
        safe_name = secure_filename(uploaded_file.filename)
        stored_filename = f"{username}_{safe_name}"
        file_path = UPLOAD_DIR / stored_filename
        uploaded_file.save(file_path)
        word_count = count_words(file_path)

    password_hash = generate_password_hash(password)

    try:
        conn = get_db_connection()
        conn.execute("""
            INSERT INTO users
            (username, password_hash, firstname, lastname, email, address,
             stored_filename, original_filename, word_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            username, password_hash, firstname, lastname, email, address,
            stored_filename, original_filename, word_count
        ))
        conn.commit()
        conn.close()
    except sqlite3.IntegrityError:
        if stored_filename:
            try:
                (UPLOAD_DIR / stored_filename).unlink(missing_ok=True)
            except OSError:
                pass
        flash("That username already exists. Please choose another one.")
        return redirect(url_for("register"))

    return redirect(url_for("profile", username=username))


@app.route("/profile/<username>")
def profile(username):
    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    conn.close()

    if user is None:
        return "User not found", 404

    return render_template("profile.html", user=user)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form["username"].strip()
    password = request.form["password"]

    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    conn.close()

    if user and check_password_hash(user["password_hash"], password):
        return redirect(url_for("profile", username=username))

    flash("Invalid username or password.")
    return redirect(url_for("login"))


@app.route("/download/<username>")
def download_file(username):
    conn = get_db_connection()
    user = conn.execute(
        "SELECT stored_filename, original_filename FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    conn.close()

    if user is None or not user["stored_filename"]:
        return "No uploaded file found", 404

    return send_from_directory(
        UPLOAD_DIR,
        user["stored_filename"],
        as_attachment=True,
        download_name=user["original_filename"]
    )


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
