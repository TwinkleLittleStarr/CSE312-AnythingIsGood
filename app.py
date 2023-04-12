import secrets
import bcrypt
from flask import Flask, render_template, redirect, session, request, url_for
import pymongo
import flask
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string

mongo_client = pymongo.MongoClient("mongo")
db = mongo_client["cse312"]

user_collection = db['users']  # database to store the username and password
course_collection = db['courses']  # database to store the course
cookies_collection = db["cookies"]  # database to store the cookies

app = Flask(__name__)
app.secret_key = "cjqojcoqqocoqq"


def escape_text(text):  # comment security
    if (not isinstance(text, str)):
        return
    return text.replace('&', '&#38;').replace('<', '&#60;').replace('>', '&#62;')


def valid_text(text):
    if len(text) != 0:
        return text

def check_cookies():
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
        if (not valid_text(username) or len(password) < 6):
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
                token = secrets.token_hex(16)
                hashedToken = bcrypt.hashpw(token.encode(), bcrypt.gensalt())
                user_collection.update_one({"username": username}, {"$set": {"authToken": hashedToken}})
                session["token"] = hashedToken  # Create cookie for authentication token
                session["username"] = username
                cookies_collection.insert_one({"username": username, "authToken": hashedToken})

                return render_template("index.html", username=username)
    else:
        # If both username and password are correct, go to personal homepage
        token = session.get("token")
        if token and check_cookies():
            username = cookies_collection.find_one({"authToken": token})['username']
            return render_template("index.html", username=username)

        return render_template("login.html")


@app.route('/logout', methods=['GET'])
def logout():  # click logout
    if flask.request.method == 'GET':
        token = session.get('token')
        if token:
            cookies_collection.delete_one({'token': token})  # Delete session cookie from database
            session.pop('token', None)  # invalidate cookies
        return render_template("index.html")


@app.route('/create', methods=['POST', 'GET'])
def create():  # users can create courses
    if flask.request.method == 'POST':
        course_name = escape_text(flask.request.form['course_name'])  # user can add course name
        course_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8))  # course id, generate randomly
        description = escape_text(flask.request.form['descript'])  # user can add course description

        instructor = session.get('username')  # user in the cookie is the instructor of the course

        course_collection.insert_one({"course_name": course_name, "course_id": course_id, "descript": description, "instructor": instructor})
        return render_template("course.html", course_name=course_name, course_id=course_id, instructor=instructor, descript=description)
    else:
        return render_template("create.html")


@app.route('/courses', methods=['GET', 'POST'])
def courses():  # display all courses
    if flask.request.method == 'GET':
        all_courses = course_collection.find({}, {"_id": 0})
        return render_template("courses.html", all_courses=all_courses)

@app.route('/course', methods=['GET', 'POST'])
def course():
    course_name = request.full_path
    course_name =course_name.split("=")[1]
    selected_course = course_collection.find_one({"course_name": course_name})  # find course name

    instructor = selected_course.get('instructor')
    description = selected_course.get('descript')
    course_id = selected_course.get('course_id')

    if flask.request.method == 'POST':
        print("in to POST")
        # POST when users click enroll
        student = session.get('username')
        if student == selected_course.get('instructor'):
            return render_template("course.html", course_name=course_name, instructor=instructor, descript=description, courseStatus="You are the instructor")
        else:
            # Check if the student is already enrolled in the course
            enrolled_student = user_collection.find_one({"username": student, "course_name": course_name})
            if enrolled_student:
                return render_template("course.html", course_name=course_name, instructor=instructor, descript=description, courseStatus="You are already enrolled in this course")
            else:
                # Insert the course name in user's database
                user_collection.insert_one({"username": student, "course_name": course_name})
                # Insert the student name in the course's database
                course_collection.update_one({"course_name": course_name}, {"$push": {"students": student}})
                # my_course = user_collection.find_one({"username": student})
                return render_template("my.html", course_name=course_name, instructor=instructor, descript=description, my_course=my_course)

    else:
        if selected_course:

            # display the course name, instructor, course id, and description
            return render_template("course.html", course_name=course_name, instructor=instructor, descript=description, course_id=course_id)

@app.route('/my', methods=['GET'])
def my():
    student = session.get('username')
    # Retrieve the enrolled courses for the logged-in user
    enrolled_courses = user_collection.find({"username": student})
    return render_template("my.html", courses=enrolled_courses)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)  # localhost:8080