import re
from flask import Flask, render_template, redirect, request, session, flash
from flask_bcrypt import Bcrypt
from mysqlconnection import connectToMySQL

SCHEMA = "solo_project"
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
INVALID_PASSWORD_REGEX = re.compile(r'^([^0-9]*|[^A-Z]*)$')

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "$$$hoiimtemmie0$$$$"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/users/create', methods=['POST'])
def users_new():
    valid = True

    if len(request.form['name']) < 2:
        flash("Last name must be at least 2 characters")
        valid = False

    if not EMAIL_REGEX.match(request.form['email']):
        flash("Email must be valid")
        valid = False

    if len(request.form['pw']) < 8:
        flash("Password must be at least 8 characters")
        valid = False

    if INVALID_PASSWORD_REGEX.match(request.form['pw']):
        flash("Password must have at least one uppercase character and at least one number")
        valid = False
    
    if request.form['pw'] != request.form['confirm_pw']:
        flash("Passwords must match")
        valid = False

    db = connectToMySQL(SCHEMA)
    validate_email_query = 'SELECT id FROM users WHERE email=%(email)s;'
    form_data = {
        'email': request.form['email']
    }
    existing_users = db.query_db(validate_email_query, form_data)

    if existing_users:
        flash("Email already in use")
        valid = False

    if not valid:
        # redirect to the form page, don't create user
        return redirect('/')
    
    # hash user's password
    pw_hash = bcrypt.generate_password_hash(request.form['pw'])
    # create a user and log them in
    db = connectToMySQL(SCHEMA)
    create_query = "INSERT INTO users (name, email, password) VALUES (%(name)s, %(mail)s, %(pw)s);"
    create_data = {
        'name': request.form['name'],
        'mail': request.form['email'],
        'pw': pw_hash
    }
    user_id = db.query_db(create_query, create_data)
    session['user_id'] = user_id
    return redirect('/gigs')

@app.route("/login", methods=["POST"])
def login_user():
    is_valid = True

    if len(request.form['email']) < 1:
        is_valid = False
        flash("Please enter your email")
    if len(request.form['password']) < 1:
        is_valid = False
        flash("Please enter your password")
    
    if not is_valid:
        return redirect("/")
    else:
        mysql = connectToMySQL('solo_project')
        query = "SELECT * FROM users WHERE users.email = %(email)s"
        data = {
            'email': request.form['email']
        }
        user = mysql.query_db(query, data)
        if user:
            hashed_password = user[0]['password']
            if bcrypt.check_password_hash(hashed_password, request.form['password']):
                session['user_id'] = user[0]['id']
                user_id = session['user_id']
                print("*"*50)
                print(f'Login successful! User {user_id} added to session. Redirecting . . .')
                return redirect("/gigs")
            else:
                flash("Password is invalid")
                return redirect("/")
        else:
            flash("Please use a valid email address")
            return redirect("/")

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# GET methods

# @app.route("/")
# def index():
#     print("index render")
#     return render_template('index.html')

@app.route("/gigs")
def allGigs():
    if 'user_id' not in session:
        return redirect('/')
    else:
        mysql = connectToMySQL('solo_project')
        gigs = mysql.query_db('SELECT * FROM gigs')
        mysql = connectToMySQL(('solo_project'))
        user = mysql.query_db('SELECT * FROM users WHERE id = {}'.format(session['user_id']))
        return render_template('viewAll.html', gigs = gigs, user = user[0])

@app.route("/users/<id>")
def userGigs(id):
    print("*"*50)
    print ("userEvents render")
    mysql = connectToMySQL('solo_project')
    user = mysql.query_db('SELECT * FROM users WHERE id = {}'.format(session['user_id']))
    mysql = connectToMySQL('solo_project')
    gigs = mysql.query_db('SELECT * FROM gigs')
    return render_template('userEvents.html', user = user[0], gigs = gigs)

@app.route("/gigs/<id>")
def viewOne(id):
    mysql = connectToMySQL(SCHEMA)
    gig = mysql.query_db('SELECT * FROM gigs WHERE id = {}'.format(id))
    mysql = connectToMySQL('solo_project')
    user = mysql.query_db('SELECT * FROM users WHERE id = {}'.format(session['user_id']))
    return render_template('viewOne.html', gig = gig[0], user = user[0])

@app.route("/gigs/new")
def newGig():
    mysql = connectToMySQL('solo_project')
    user = mysql.query_db('SELECT * FROM users WHERE id = {}'.format(session['user_id']))
    return render_template('addNew.html', user = user[0])

@app.route("/gigs/create", methods=['POST'])
def createGig():
    valid = True

    if len(request.form['name']) < 2:
        flash("Gig name must be at least 2 characters")
        valid = False

    if len(request.form['location']) < 2:
        flash("Gig location must be at least 2 characters")
        valid = False

    if len(request.form['date']) < 2:
        flash("A date is required")
        valid = False

    if not valid:
        return redirect("/gigs/new")

    mysql = connectToMySQL(SCHEMA)
    query = 'INSERT INTO gigs (name, location, date, description) VALUES (%(name)s, %(location)s, %(date)s, %(description)s)'
    data = {
        "name": request.form['name'],
        "location": request.form['location'],
        "date": request.form['date'],
        "description": request.form['description']
    }
    gig = mysql.query_db(query, data)
    return redirect("/gigs")

@app.route("/gigs/<id>/delete")
def deleteGig(id):
    mysql = connectToMySQL(SCHEMA)
    gig = mysql.query_db('DELETE FROM gigs WHERE id = {}'.format(id))
    return redirect('/gigs')

@app.route("/gigs/<id>/edit")
def editGig(id):
    mysql = connectToMySQL(SCHEMA)
    gig = mysql.query_db('SELECT * FROM gigs WHERE id = {}'.format(id))
    mysql = connectToMySQL(SCHEMA)
    user = mysql.query_db('SELECT * FROM users WHERE id = {}'.format(session['user_id']))
    return render_template("edit.html", gig = gig[0], user=user[0])
if __name__ == "__main__":
    app.run(debug=True)