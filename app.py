import secrets
import bcrypt
from flask import Flask, render_template, redirect, make_response, session, url_for
import pymongo
import flask
from flask_socketio import SocketIO
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string

mongo_client = pymongo.MongoClient("mongo")
db = mongo_client["cse312"]

user_collection = db['users']  # database to store the username and password
course_collection = db['courses']  # database to store the course
cookies_collection = db["cookies"]

app = Flask(__name__)
app.secret_key = "cjqojcoqqocoqq"


def escape_text(text):  # comment security
    if (not isinstance(text, str)):
        return
    return text.replace('&', '&#38;').replace('<', '&#60;').replace('>', '&#62;')


def valid_text(text):
    if len(text) != 0:
        return text

def check_auth_token():
    token = session.get("token")
    if token:
        cookie = cookies_collection.find_one({"authToken": token})
        if cookie:
            return True
    return False


@app.route('/')
def index():  # homepage
    return render_template("index.html")


@app.route('/register', methods=['POST', 'GET'])
def register():
    # new users need to sign up, go to log in page after sign up
    if flask.request.method == 'POST':
        username = escape_text(flask.request.form['username'])
        password = flask.request.form['password']

        # username should not be empty, password should have at least 6 characters
        if (not valid_text(username) and len(password) < 6):
            return render_template("register.html", registerStatus="Invalid input")

        dic_username = list(user_collection.find({"username": username}))
        if len(dic_username) != 0:  # Check if username is already in use
            return render_template("register.html", registerStatus="Username already been used")

        else:
            hashed_password = generate_password_hash(password)  # generate password in hash for security

            # Insert new user into the database
            user_collection.insert_one({"username": username, "password": hashed_password})

            # Redirect to login page after registration
            return render_template("login.html")
    else:
        return render_template("register.html")


@app.route('/login', methods=['POST', 'GET'])
def login():
    if flask.request.method == 'POST':
        username_list = list()
        username = escape_text(flask.request.form['username'])
        password = flask.request.form['password']
        username_dic = user_collection.find_one({"username": username}, {"_id": 0})

        if not username_dic:
            # If the username does not exist in the database, return to the login page
            return render_template("login.html", loginStatus="No Account, please register first")
        else:
            if not check_password_hash(username_dic['password'], password):

                # If password is incorrect, return to the login page
                return render_template("login.html", loginStatus="Incorrect Password")
            else:
                # If both username and password are correct, go to personal homepage
                token = session.get("token")
                if token and check_auth_token():
                    # If authentication token is already present and valid, skip login and go to personal homepage
                    return render_template("index.html", user=username)

                token = secrets.token_hex(16)
                hashedToken = bcrypt.hashpw(token.encode(), bcrypt.gensalt())
                user_collection.update_one({"username": username}, {"$set": {"authToken": hashedToken}})
                session["token"] = hashedToken  # Create cookie for authentication token
                cookies_collection.insert_one({"username": username, "authToken": hashedToken})

                return render_template("index.html", username=username, authToken=hashedToken)
    else:
        token = session.get("token")
        if token and check_auth_token():
            username = cookies_collection.find_one({"authToken": token})['username']
            return render_template("index.html", username=username)

        return render_template("login.html")


@app.route('/logout', methods=['GET'])
def logout():  # click logout
    if flask.request.method == 'GET':
        # unimplemented, may need something about cookie
        return render_template("index.html")


@app.route('/create', methods=['POST', 'GET'])
def create():  # users can create courses
    if flask.request.method == 'POST':
        course_name = escape_text(flask.request.form['coursename'])  # user can add course name
        course_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8))  # course id, generate randomly
        description = escape_text(flask.request.form['descript'])  # user can add course description

        # user =

        # need to insert the instructor later, do the cookie first
        course_collection.insert_one({"coursename": course_name, "course_id": course_id, "descript": description})
        return render_template("courses.html", course_name=course_name, course_id=course_id, des=description)
    else:
        return render_template("create.html")


@app.route('/courses', methods=['GET'])
def courses():  # display all courses
    all_courses = course_collection.find({}, {"_id": 0})
    return render_template("courses.html", course=all_courses)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)  # localhost:8080
