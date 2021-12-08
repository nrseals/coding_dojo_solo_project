from flask import Flask, render_template, request, redirect
app = Flask(__name__)

# GET methods

@app.route("/")
def index():
    print("index render")
    return render_template('index.html')

@app.route("/gigs")
def allGigs():
    mysql = connectToMySQL('flask')
    gigs = mysql.query_db('SELECT * FROM gigs')
    print(friends)
    return render_template('viewAll.html')

@app.route("/users/<id>")
def userGigs(id):
    print ("userEvents render")
    print(id)
    return render_template('userEvents.html')

@app.route("gigs/<id>")
def viewOne(id):
    print("View One render")
    print(id)
    return render_template('viewOne.html')

@app.route("/gigs/new")
def newGig():
    print("New Gig render")
    return render_template('addNew.html')

# POST Methods

@app.route("/users/register", methods=["POST"])
def create_user():
    print("Got post info!")
    print(request.form)
    return redirect("/")

# @app.route("/users/login")
# if user == valid, store in session, redirect to /gigs
# else render index.html w/errors 


if __name__ == "__main__":
    app.run(debug=True)