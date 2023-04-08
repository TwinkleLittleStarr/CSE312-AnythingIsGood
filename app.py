from flask import Flask, render_template, redirect
import pymongo
import flask
from werkzeug.security import generate_password_hash

mongo_client = pymongo.MongoClient("mongo")
db = mongo_client["cse312"]

user_collection = db['users']  # database to store the users

app = Flask(__name__)

def escape_text(text):  # comment security
    new_text = ''
    if '&' in text:  # security, replace & to &amp
        new_text = text.replace('&', "&amp")
    if '<' in text:  # security, replace < to &lt
        new_text = text.replace('<', '&lt')
    if '>' in text:  # security, replace > to &gt
        new_text = text.replace('>', '&gt')
    return new_text

def valid_text(text):
    if len(text) != 0:
        return text

@app.route('/')
def index():  # homepage
    return render_template("index.html")


@app.route('/register', methods=['POST', 'GET'])
def register():  # new users need to sign up, go to log in page after sign up
    if flask.request.method == 'POST':
        Username = escape_text(flask.request.form['username'])
        Password = flask.request.form['password']
        if (not valid_text(Username) and len(Password) < 6):  # username should not be empty, password should has at least 6 characters
            return render_template("register.html", signUpStatus="Invalid input")

        hashed_password = generate_password_hash(Password)  # generate password in hash

        # Insert new user into the database
        user = {"username": Username, "password": hashed_password}
        user_collection.insert_one(user)

        # Redirect to login page after registration
        return redirect("/login")
    else:
        return render_template("register.html")

@app.route('/login')
def login():  # all users need to login in, go to personal page after login in go to
    return render_template("login.html")

@app.route('/logout', methods=['GET'])
def logout():
    if flask.request.method == 'GET':
        return render_template("index.html")


@app.route('/courses')
def courses():  # put application's code here
    return render_template("courses.html")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)  # localhost:8080
