from flask import Flask, render_template

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
    app.run(debug=True)
