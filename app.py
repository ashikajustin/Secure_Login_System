from flask import Flask, request, redirect, url_for, session, render_template_string
import sqlite3
import bcrypt
import re
import os

app = Flask(__name__)

# Secret key for Flask sessions
app.secret_key = os.environ.get(
    "SECRET_KEY",
    "change-this-secret-key-before-production"
)

DATABASE = "users.db"


# ---------------- DATABASE ----------------

def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def init_database():
    connection = get_db_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


# ---------------- HOME ----------------

@app.route("/")
def home():

    if "user_id" in session:
        return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Secure Login System</title>

            <style>
                body {
                    font-family: Arial;
                    background: #f2f2f2;
                    text-align: center;
                    padding-top: 80px;
                }

                .box {
                    background: white;
                    width: 450px;
                    margin: auto;
                    padding: 35px;
                    border-radius: 10px;
                    box-shadow: 0 0 10px #ccc;
                }

                a {
                    display: inline-block;
                    margin: 10px;
                    padding: 10px 20px;
                    background: #337ab7;
                    color: white;
                    text-decoration: none;
                    border-radius: 5px;
                }
            </style>
        </head>

        <body>
            <div class="box">

                <h1>Secure Login System</h1>

                <h2>Welcome, {{ username }}!</h2>

                <p>You are successfully logged in.</p>

                <a href="/logout">Logout</a>

            </div>
        </body>
        </html>
        """, username=session["username"])

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secure Login System</title>

        <style>
            body {
                font-family: Arial;
                background: #f2f2f2;
                text-align: center;
                padding-top: 80px;
            }

            .box {
                background: white;
                width: 450px;
                margin: auto;
                padding: 35px;
                border-radius: 10px;
                box-shadow: 0 0 10px #ccc;
            }

            a {
                display: inline-block;
                margin: 10px;
                padding: 10px 20px;
                background: #337ab7;
                color: white;
                text-decoration: none;
                border-radius: 5px;
            }
        </style>
    </head>

    <body>
        <div class="box">

            <h1>Secure Login System</h1>

            <p>Secure user authentication using bcrypt.</p>

            <a href="/register">Register</a>
            <a href="/login">Login</a>

        </div>
    </body>
    </html>
    """)


# ---------------- REGISTER ----------------

@app.route("/register", methods=["GET", "POST"])
def register():

    message = ""
    success = False

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Username validation
        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
            message = (
                "Username must contain 3-30 characters "
                "and use only letters, numbers, and underscore."
            )

        # Password validation
        elif len(password) < 8:
            message = "Password must contain at least 8 characters."

        else:

            connection = get_db_connection()

            # Check whether username already exists
            existing_user = connection.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,)
            ).fetchone()

            if existing_user:
                message = "Username already exists."

            else:

                # Hash password using bcrypt
                password_hash = bcrypt.hashpw(
                    password.encode("utf-8"),
                    bcrypt.gensalt()
                ).decode("utf-8")

                # Parameterized query protects against SQL injection
                connection.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hash)
                )

                connection.commit()
                connection.close()

                return redirect(url_for("login", registered="1"))

            connection.close()

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Register</title>

        <style>
            body {
                font-family: Arial;
                background: #f2f2f2;
                text-align: center;
                padding-top: 50px;
            }

            .box {
                background: white;
                width: 400px;
                margin: auto;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 0 10px #ccc;
            }

            input {
                width: 90%;
                padding: 10px;
                margin: 10px;
            }

            button {
                padding: 10px 25px;
                background: #337ab7;
                color: white;
                border: none;
                border-radius: 5px;
            }

            .error {
                color: red;
            }

            a {
                color: #337ab7;
            }
        </style>
    </head>

    <body>

        <div class="box">

            <h1>Register</h1>

            {% if message %}
                <p class="error">{{ message }}</p>
            {% endif %}

            <form method="POST">

                <input
                    type="text"
                    name="username"
                    placeholder="Username"
                    required
                >

                <input
                    type="password"
                    name="password"
                    placeholder="Password"
                    required
                >

                <button type="submit">Register</button>

            </form>

            <p>
                Already have an account?
                <a href="/login">Login</a>
            </p>

        </div>

    </body>
    </html>
    """, message=message)


# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET", "POST"])
def login():

    message = (
        "Registration successful. Please log in."
        if request.args.get("registered") == "1"
        else ""
    )

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        connection = get_db_connection()

        # Parameterized query protects against SQL injection
        user = connection.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        connection.close()

        if user:

            stored_hash = user["password_hash"].encode("utf-8")

            # Check password against bcrypt hash
            if bcrypt.checkpw(
                password.encode("utf-8"),
                stored_hash
            ):

                session["user_id"] = user["id"]
                session["username"] = user["username"]

                return redirect(url_for("home"))

        message = "Invalid username or password."

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login</title>

        <style>
            body {
                font-family: Arial;
                background: #f2f2f2;
                text-align: center;
                padding-top: 50px;
            }

            .box {
                background: white;
                width: 400px;
                margin: auto;
                padding: 30px;
                border-radius: 10px;
                box-shadow: 0 0 10px #ccc;
            }

            input {
                width: 90%;
                padding: 10px;
                margin: 10px;
            }

            button {
                padding: 10px 25px;
                background: #337ab7;
                color: white;
                border: none;
                border-radius: 5px;
            }

            .error {
                color: red;
            }

            .success {
                color: green;
            }

            a {
                color: #337ab7;
            }
        </style>
    </head>

    <body>

        <div class="box">

            <h1>Login</h1>

            {% if message %}
                <p class="{% if 'successful' in message %}success{% else %}error{% endif %}">
                    {{ message }}
                </p>
            {% endif %}

            <form method="POST">

                <input
                    type="text"
                    name="username"
                    placeholder="Username"
                    required
                >

                <input
                    type="password"
                    name="password"
                    placeholder="Password"
                    required
                >

                <button type="submit">Login</button>

            </form>

            <p>
                Don't have an account?
                <a href="/register">Register</a>
            </p>

        </div>

    </body>
    </html>
    """, message=message)


# ---------------- LOGOUT ----------------

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("home"))


# ---------------- START APPLICATION ----------------

if __name__ == "__main__":

    init_database()

    app.run(debug=False)