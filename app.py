from flask import Flask, render_template
import pymongo
import flask

mongo_client = pymongo.MongoClient("mongo")
db = mongo_client["cse312"]

user_collection = db['users']  # database to store the users

app = Flask(__name__)


@app.route('/')
def index():  # put application's code here
    return render_template("index.html")


@app.route('/register')
def register():  # put application's code here
    return render_template("register.html")


@app.route('/login')
def login():  # put application's code here
    return render_template("login.html")


@app.route('/courses')
def courses():  # put application's code here
    return render_template("courses.html")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)  # localhost:8080
