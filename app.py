
import os
import hashlib
import sqlite3
import hmac

from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "venv", "templates")
STATIC_DIR = os.path.join(TEMPLATE_DIR, "static")

app = Flask(
    __name__,
    template_folder=TEMPLATE_DIR,
    static_folder=STATIC_DIR,
)
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY", "dev-only-change-this-key"
)

DATABASE = "users.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                salt BLOB NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)


def hash_password(password, salt):
    return hashlib.sha256(
        salt + password.encode("utf-8")
    ).hexdigest()


@app.route("/")
def home():
    if "username" in session:
        return render_template(
            "dashboard.html",
            username=session["username"]
        )
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or len(username) > 50:
            flash("Enter a username (up to 50 characters).")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters.")
            return render_template("register.html")

        salt = os.urandom(16)
        password_hash = hash_password(password, salt)

        try:
            with get_db() as conn:
                conn.execute(
                    """INSERT INTO users
                       (username, salt, password_hash)
                       VALUES (?, ?, ?)""",
                    (username, salt, password_hash)
                )
            flash("Registration successful. Please log in.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("That username is already registered.")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()

        if user:
            candidate_hash = hash_password(
                password, user["salt"]
            )
            if hmac.compare_digest(
                candidate_hash, user["password_hash"]
            ):
                session.clear()
                session["username"] = user["username"]
                return redirect(url_for("home"))

        flash("Invalid username or password.")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/security-demo")
def security_demo():
    salt1 = os.urandom(16)
    salt2 = os.urandom(16)

    # Use a fixed demo password, never a real user password.
    demo_password = "DemoPassword123!"

    hash1 = hashlib.sha256(
        salt1 + demo_password.encode("utf-8")
    ).hexdigest()

    hash2 = hashlib.sha256(
        salt2 + demo_password.encode("utf-8")
    ).hexdigest()

    return render_template(
        "security_demo.html",
        salt1=salt1.hex(),
        salt2=salt2.hex(),
        hash1=hash1,
        hash2=hash2
    )


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
