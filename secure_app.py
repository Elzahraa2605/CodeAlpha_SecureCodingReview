# secure_app.py - remediated version of vulnerable_app.py (each fix is tagged F1..F9)
import os
import re
import sqlite3
import subprocess

from flask import Flask, abort, request, send_from_directory, session
from markupsafe import escape
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["APP_SECRET_KEY"]                        # F1 secret comes from the environment
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
FILES_DIR = os.path.abspath("files")
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
db = sqlite3.connect("users.db", check_same_thread=False)
db.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT UNIQUE, password TEXT, bio TEXT)")


@app.route("/register", methods=["POST"])
def register():
    name, pw = request.form.get("name", ""), request.form.get("password", "")
    if not (3 <= len(name) <= 32 and len(pw) >= 12):                           # input validation
        abort(400)
    db.execute("INSERT INTO users(name, password) VALUES (?, ?)",              # F3 parameterized query
               (name, generate_password_hash(pw)))                             # F2 salted, slow hash (scrypt/pbkdf2)
    db.commit()
    return "registered", 201


@app.route("/login", methods=["POST"])
def login():
    row = db.execute("SELECT id, password FROM users WHERE name = ?", (request.form.get("name", ""),)).fetchone()
    if not row or not check_password_hash(row[1], request.form.get("password", "")):
        abort(401)
    session["uid"] = row[0]
    return "welcome"


@app.route("/hello")
def hello():
    return f"<h1>Hello {escape(request.args.get('name', ''))}</h1>"            # F4 output escaping


@app.route("/ping")
def ping():
    if "uid" not in session:                                                   # F5 authentication required
        abort(401)
    host = request.args.get("host", "")
    if not HOST_RE.match(host):                                                # F5 allow-list validation
        abort(400)
    out = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=5)  # F5 no shell
    return f"<pre>{escape(out.stdout)}</pre>"


@app.route("/download")
def download():
    return send_from_directory(FILES_DIR, request.args.get("file", ""))        # F6 blocks ../ traversal


@app.route("/profile/<int:uid>")
def profile(uid):
    if session.get("uid") != uid:                                              # F7 authorization check
        abort(403)
    row = db.execute("SELECT name, bio FROM users WHERE id = ?", (uid,)).fetchone()
    return {"name": row[0], "bio": row[1]} if row else abort(404)


@app.route("/load", methods=["POST"])
def load():
    data = request.get_json(silent=True)                                       # F8 JSON instead of pickle
    if not isinstance(data, dict):
        abort(400)
    return {"keys": sorted(data)}


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=False)                                     # F9 localhost only, debug off
