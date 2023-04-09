from flask import Flask, render_template, redirect
import pymongo
import flask
from werkzeug.security import generate_password_hash

mongo_client = pymongo.MongoClient("mongo")
db = mongo_client["cse312"]

user_collection = db['users']  # database to store the users

app = Flask(__name__)


def escape_text(text):  # comment security
    if (not isinstance(text, str)):
        return
    return text.replace('&', '&#38;').replace('<', '&#60;').replace('>', '&#62;')


def valid_text(text):
    if len(text) != 0:
        return text


@app.route('/')
def index():  # homepage
    return render_template("index.html")


@app.route('/register', methods=['POST', 'GET'])
def register():
    # new users need to sign up, go to log in page after sign up
    if flask.request.method == 'POST':
        Username = escape_text(flask.request.form['username'])
        Password = flask.request.form['password']
        # username should not be empty, password should have at least 6 characters
        if (not valid_text(Username) and len(Password) < 6):
            return render_template("register.html", registerStatus="Invalid input")
        else:
            # hashed_password = generate_password_hash(Password)  # generate password in hash
            # Insert new user into the database
            print("username", Username)
            user_collection.insert_one({"username": Username, "password": Password})
            print(user_collection)
            # Redirect to login page after registration
            return render_template("login.html")
            # return redirect("/login")
    else:
        return render_template("register.html")


@app.route('/login', methods=['POST', 'GET'])
def login():
    if flask.request.method == 'POST':
        username_list = list()
        username = escape_text(flask.request.form['username'])
        password = flask.request.form['password']
        username_dic = user_collection.find_one({"username": username}, {"_id": 0})
        print(username_dic)

        if not username_dic:
            # If the username does not exist in the database, return to the login page
            return render_template("login.html", loginStatus="No Account, please register first")
        else:
            if username_dic['password'] != password:
                # If password is incorrect, return to the login page
                return render_template("login.html", loginStatus="Incorrect Password")
            else:
                # If both username and password are correct, go to personal homepage
                return render_template("index.html", user=username_dic)

    else:
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
