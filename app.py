from flask import Flask, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
from cs50 import SQL

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///healthquest.db")

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.context_processor
def inject_user():
    if session.get("user_id"):
        user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        if user:
            return dict(user=user[0])
    return dict(user=None)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function

@app.route("/")
def index():
    return render_template("index.html")
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not request.form.get("username"):
            return render_template("login.html", info="username invalid")
        elif not request.form.get("password"):
            return render_template("login.html", info="password invalid")
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return render_template("login.html", info="username/password incorrect")
        session["user_id"] = rows[0]["id"]
        return redirect("/")
    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form.get("username")
        passw = request.form.get("password")
        rpassw = request.form.get("rpassword")
        if (
            not username
            or len(db.execute("SELECT * FROM users WHERE username = ?", username)) != 0
        ):
            return render_template("register.html", info="username taken/invalid")
        if passw != rpassw or not passw:
            return render_template(
                "register.html", info="password invalid / password do not match"
            )
        db.execute(
            "INSERT INTO users (username, hash) VALUES (?, ?)",
            username,
            generate_password_hash(passw),
        )
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", username
        )
        session["user_id"] = rows[0]["id"]
    return redirect("/")

@app.route("/emergency")
def emergency():
    return render_template("emergency.html")

@app.route("/quickcheck")
def progress():
        return render_template("progress.html")

@app.route("/challenges")
def challenges():
        return render_template("challenges.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")