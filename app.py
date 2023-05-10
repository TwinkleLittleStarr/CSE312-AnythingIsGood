import secrets
import bcrypt
from flask import Flask, render_template, session, request, make_response, redirect, url_for
import pymongo
import flask
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string
import urllib.parse

from flask_socketio import SocketIO, emit

mongo_client = pymongo.MongoClient("mongo")
db = mongo_client["cse312"]
question_id = db['id']

user_collection = db['users']  # database to store the username and password
course_collection = db['courses']  # database to store the course
cookies_collection = db["cookies"]  # database to store the cookies
questions_collection = db["questions"]  # database to store the questions
answers_collection = db["answers"]
grades_collection = db["grades"]

app = Flask(__name__)
app.secret_key = "cjqojcoqqocoqq"
socketio = SocketIO(app)

def user_in_course(username, course_name):
    result = user_collection.find_one({"username": username, "course_name": course_name})
    if result:
        return True
    else:
        return False

def escape_text(text):
    return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

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

def nextid():
    # from last semester lecture recording
    # HW1 AO2
    id = question_id.find_one({})
    if id:
        next_id = int(id['last_id']) + 1
        question_id.update_one({}, {'$set': {'last_id': next_id}})
        return next_id
    else:
        question_id.insert_one({'last_id': 1})
        return 1

def grade_answers(question_id):
    question = questions_collection.find_one({'question_id': question_id})
    if not question:
        return

    correct_option = question['correct_option']
    course_name = question['course_name']
    question_text = question['question_text']
    answers = answers_collection.find({'question_id': question_id})

    for answer in answers:
        username = answer['username']
        user_answer = answer['answer']
        is_correct = user_answer == correct_option
        if is_correct:
            points = 1
        else:
            points = 0

        grades_collection.update_one(
            {'username': username, 'question_id': question_id, 'course_name': course_name, 'question_text': question_text},
            {'$set': {'is_correct': is_correct, 'points': points, 'user_answer': user_answer}},
            upsert=True
        )


@app.route('/')
def index():  # homepage
    return render_template("index.html")


@app.after_request
def apply_nosniff(response):  # add non-sniff to the photo
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.route('/register', methods=['POST', 'GET'])
def register():
    # new users need to sign up, go to log in page after sign up
    if flask.request.method == 'POST':
        username = escape_text(flask.request.form['username'])  # escaped
        password = flask.request.form['password']

        # username should not be empty, password should have at least 6 characters
        if (not valid_text(username) or len(password) < 6):
            return render_template("register.html", registerStatus="Invalid input")

        dic_username = list(user_collection.find({"username": username}))
        if len(dic_username) != 0:  # Check if username is already in use
            return render_template("register.html", registerStatus="Username already been used")

        else:
            hashed_password = generate_password_hash(password)  # generate password in hash for security
            # salt = bcrypt.gensalt()
            # hashed_password = bcrypt.hashpw(password.encode(), salt)

            # Insert new user into the database
            user_collection.insert_one({"username": username, "password": hashed_password})

            # Redirect to login page after registration
            return render_template("login.html")
    else:
        return render_template("register.html")


@app.route('/login', methods=['POST', 'GET'])
def login():
    if flask.request.method == 'POST':
        username = escape_text(flask.request.form['username'])  #escaped
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

                # return render_template("index.html", username=username)
                resp = make_response(render_template("index.html", username=username))
                resp.set_cookie("auth_token", token, httponly=True)   # Add auth_token in the cookie
                return resp
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
    if 'username' not in session:
        return redirect(url_for('login'))
    if flask.request.method == 'POST':
        # course name escaped
        course_name = escape_text(flask.request.form['course_name'])  # user can add course name
        
        existing_course = course_collection.find_one({"course_name": course_name})
        if existing_course:
            return render_template("create.html", createStatus="A course with the same name already exists.")

        course_id = ''.join(random.choices(string.ascii_letters + string.digits, k=8))  # course id, generate randomly
        # course description  escaped
        description = escape_text(flask.request.form['descript'])  # user can add course description

        instructor = session.get('username')  # user in the cookie is the instructor of the course

        user_collection.insert_one({"username": instructor, "course_name": course_name})
        course_collection.insert_one({"course_name": course_name, "course_id": course_id, "descript": description, "instructor": instructor})
        return render_template("course.html", course_name=course_name, course_id=course_id, instructor=instructor, descript=description, result=True, role=True)
    else:
        return render_template("create.html")


@app.route('/courses', methods=['GET', 'POST'])
def courses():  # display all courses
    if 'username' not in session:
        return redirect(url_for('login'))
    if flask.request.method == 'GET':
        print("in the Get")
        all_courses = course_collection.find({}, {"_id": 0})
        return render_template("courses.html", all_courses=all_courses)


@app.route('/course', methods=['GET', 'POST'])
def course():
    course_name = request.full_path.split("=", 1)[1]
    print("coursename1 -->", course_name)
    course_name = urllib.parse.unquote(course_name)
    print("coursename2 -->", course_name)

    selected_course = course_collection.find_one({"course_name": course_name})  # find course name
    print("selected_course -->", selected_course)

    instructor = selected_course.get('instructor')
    description = selected_course.get('descript')
    course_id = selected_course.get('course_id')

    if flask.request.method == 'POST':
        student = session.get('username')
        if student == selected_course.get('instructor'):
            return render_template("course.html", course_name=course_name, instructor=instructor, descript=description, courseStatus="You are the instructor")
        else:
            # Check if the student is already enrolled in the course
            enrolled_student = course_collection.find_one({"course_name": course_name, "students": student})
            if enrolled_student:
                return render_template("course.html", course_name=course_name, instructor=instructor, descript=description)
            else:
                # Insert the course name in user's database
                user_collection.insert_one({"username": student, "course_name": course_name})
                # Insert the student name in the course's database
                course_collection.update_one({"course_name": course_name}, {"$push": {"students": student}})
                my_course = user_collection.find({"username": student})
                return render_template("my.html", my_course=my_course)

    else:
        if selected_course:
            username = session.get('username')
            result = user_in_course(username, course_name)

            if username == instructor:
                course_questions = questions_collection.find({"course_name": course_name})
                question_ids = [q["_id"] for q in course_questions]
                all_grades = list(answers_collection.find({"question_id": {"$in": question_ids}}))
                return render_template("course.html", course_name=course_name, instructor=instructor,
                                       descript=description, course_id=course_id, role=True, grades=all_grades,
                                       result=result)
            else:
                enrolled_student = course_collection.find_one({"course_name": course_name, "students": username})
                if enrolled_student:
                    student_grades = list(answers_collection.find({'username': username}))
                    return render_template("course.html", course_name=course_name, instructor=instructor,
                                           descript=description, course_id=course_id, role=False, grades=student_grades,
                                           result=result)
                else:
                    return render_template("course.html", course_name=course_name, instructor=instructor,
                                           descript=description, course_id=course_id, result=result)


@app.route('/my', methods=['GET', 'POST'])
def my():
    if flask.request.method == 'GET':
        student = session.get('username')
        # Retrieve the enrolled courses for the logged-in user
        my_course = user_collection.find({"username": student})
        return render_template("my.html", my_course=my_course)


@app.route('/question', methods=['GET'])
def question():
    if flask.request.method == 'GET':
        user = session.get('username')
        course_name = request.full_path.split("=")[1]
        course_name = urllib.parse.unquote(course_name)

        print('course_name2 -->', course_name)
        selected_course = course_collection.find_one({"course_name": course_name})  # find course name
        courseQuestions = questions_collection.find_one({"course_name": course_name}, sort=[("question_id", -1)])
        print("questions", courseQuestions)

        if courseQuestions == None:
            return render_template("question.html", empty=True)

        else:
            if user == selected_course.get('instructor'):
                # The user is an instructor
                return render_template("question.html", user_role="instructor", course_name=course_name, question=courseQuestions, role=True, empty=False)
            else:
                # The user is a student
                return render_template("question.html", user_role="student", course_name=course_name, question=courseQuestions, role=False, empty=False)


@app.route('/createQuestion', methods=['POST', 'GET'])
def create_question():
    if flask.request.method == 'POST':
        question_id = nextid()
        course_name = escape_text(flask.request.form['course_name'])
        question_text = escape_text(flask.request.form['question_text'])
        options = flask.request.form.getlist('options[]')
        print("options", options)
        correct_option = escape_text(flask.request.form['correct_option'])

        questions_collection.insert_one({
            "question_id": question_id,
            "course_name": course_name,
            "question_text": question_text,
            "options": options,
            'correct_option': correct_option,
            'is_active': False
        })

        # question = questions_collection.find_one({"course_name": course_name})

        return redirect(url_for('courses'))

    else:
        user = session.get('username')
        course_name = request.full_path.split("=", 1)[1]
        course_name = urllib.parse.unquote(course_name)
        selected_course = course_collection.find_one({"course_name": course_name})
        if user != selected_course.get('instructor'):
            return "you are not instructor", 401
        else:
            return render_template("createQuestion.html")


@socketio.on('question_event')
def question_event(data):
    action = data.get('action')
    question_id = data.get('question_id')

    if action == 'start':
        print("in start")
        questions_collection.update_one({'question_id': question_id}, {'$set': {'is_active': True}})
        emit('question_started', question_id, broadcast=True)

    elif action == 'stop':
        print("in stop")
        questions_collection.update_one({'question_id': question_id}, {'$set': {'is_active': False}})
        grade_answers(question_id)
        emit('question_stopped', question_id, broadcast=True)

    elif action == 'submit':
        username = escape_text(data.get('username'))
        answer = escape_text(data.get('answer'))

        print(username)

        question = questions_collection.find_one({'question_id': question_id})

        if not question or not question['is_active']:
            emit('answer_not_accepted', {'message': 'Question is not active'})
            return

        existing_answer = answers_collection.find_one({'username': username, 'question_id': question_id})

        if existing_answer:
            emit('answer_not_accepted', {'message': 'You have already submitted an answer for this question'})
            return

        answers_collection.insert_one({
            'username': username,
            'question_id': question_id,
            'answer': answer
        })
        emit('answer_accepted', {'message': 'Answer submitted successfully'})


@app.route('/gradebook', methods=['GET'])
def get_grades():
    user_answer = ''
    if flask.request.method == 'GET':
        user = session.get('username')
        course_name = request.full_path.split("=", 1)[1]
        course_name = urllib.parse.unquote(course_name)

        if not user or not course_name:
            return "Unauthorized", 401

        selected_course = course_collection.find_one({"course_name": course_name})
        if not selected_course:
            return "Course not found", 404

        grade_user = grades_collection.find_one({"course_name": course_name}, sort=[("question_id", -1)])

        if grade_user == None:
            return render_template("gradebook.html", empty=True)

        all_grades = list(grades_collection.find({"course_name": course_name}))
        total_points = {}
        for grade in all_grades:
            if grade["username"] not in total_points:
                total_points[grade["username"]] = 0
            total_points[grade["username"]] += grade["points"]

        if user == selected_course.get('instructor'):
            # The user is an instructor
            userlist = []
            all_grades = list(grades_collection.find({"course_name": course_name}))
            for grade in all_grades:
                username = grade["username"]
                if username not in userlist:
                    userlist.append(username)
            return render_template("gradebook.html", roster=all_grades, total_points=total_points, user=userlist, role=True, empty=False)
        else:
            # The user is a student
            user_grades = list(grades_collection.find({"username": user, "course_name": course_name}))
            return render_template("gradebook.html", user_grades=user_grades, total_points=total_points[user], role=False, empty=False)


@app.route('/roster', methods=['GET'])
def roster():
    if flask.request.method == 'GET':
        user = session.get('username')
        course_name = request.full_path.split("=", 1)[1]
        course_name = urllib.parse.unquote(course_name)

        if not user:
            return "Unauthorized", 401

        selected_course = course_collection.find_one({"course_name": course_name})
        if not selected_course:
            return "Course not found", 404

        if selected_course.get('students') is None:
            print("why none")
            return render_template("roster.html", empty=True)

        if user == selected_course.get('instructor'):
            print("I am instructor")
            students = list(course_collection.find({"course_name": course_name}))
            for student in students:
                s = student["students"]

            return render_template("roster.html", course_name=course_name, students=s, empty=False)


if __name__ == '__main__':
    # app.run(host='0.0.0.0', port=5000)  # localhost:8080
    socketio.run(app, host="0.0.0.0", port=5000)
