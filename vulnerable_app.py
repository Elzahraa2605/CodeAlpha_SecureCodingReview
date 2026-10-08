# vulnerable_app.py - INTENTIONALLY INSECURE demo app used for the code review. Never deploy.
import hashlib
import pickle
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)
app.config["SECRET_KEY"] = "super-secret-123"                                  # F1 hardcoded secret
db = sqlite3.connect("users.db", check_same_thread=False)
db.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, password TEXT, bio TEXT)")


@app.route("/register", methods=["POST"])
def register():
    pw = hashlib.md5(request.form["password"].encode()).hexdigest()            # F2 weak, unsalted hash
    db.execute(f"INSERT INTO users(name, password) VALUES('{request.form['name']}', '{pw}')")  # F3 SQL injection
    db.commit()
    return "registered"


@app.route("/login", methods=["POST"])
def login():
    pw = hashlib.md5(request.form["password"].encode()).hexdigest()            # F2
    row = db.execute(f"SELECT id FROM users WHERE name='{request.form['name']}' AND password='{pw}'").fetchone()  # F3
    return "welcome" if row else ("denied", 401)


@app.route("/hello")
def hello():
    return f"<h1>Hello {request.args.get('name', '')}</h1>"                    # F4 reflected XSS


@app.route("/ping")
def ping():
    return subprocess.check_output("ping -c 1 " + request.args["host"], shell=True)  # F5 command injection


@app.route("/download")
def download():
    return open("files/" + request.args["file"]).read()                        # F6 path traversal


@app.route("/profile/<int:uid>")
def profile(uid):                                                              # F7 no auth check (IDOR)
    return str(db.execute(f"SELECT name, bio FROM users WHERE id={uid}").fetchone())


@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))                                     # F8 insecure deserialization


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)                                        # F9 debug mode + bind all interfaces
