from .meta import *

import datetime
import bcrypt
from flask import flash, request,redirect,session, render_template, request, url_for

@app.route("/")
def index():
    """
    Main Page.
    """

    #Get data from the DB using meta function
    
    rows = query_db("SELECT * FROM product")
    app.logger.info(rows)
    
    return flask.render_template("index.html",
                                 bookList = rows)


@app.route("/products", methods=["GET","POST"])
def products():
    """
    Single Page (ish) Application for Products
    """
    theItem = flask.request.args.get("item")
    if theItem:
        
        #We Do A Query for It
        itemQry = query_db(f"SELECT * FROM product WHERE id = ?",[theItem], one=True)

        #And Associated Reviews
        #reviewQry = query_db("SELECT * FROM review WHERE productID = ?", [theItem])
        theSQL = f"""
        SELECT * 
        FROM review
        INNER JOIN user ON review.userID = user.id
        WHERE review.productID = {itemQry['id']};
        """
        reviewQry = query_db(theSQL)
        
        #If there is form interaction and they put something in the basket
        if flask.request.method == "POST":

            quantity = flask.request.form.get("quantity")
            try:
                quantity = int(quantity)
            except ValueError:
                flask.flash("Error Buying Item")
                return flask.render_template("product.html",
                                             item = itemQry,
                                             reviews=reviewQry)
            
            app.logger.warning("Buy Clicked %s items", quantity)
            
            #And we add something to the Session for the user to keep track
            basket = flask.session.get("basket", {})

            basket[theItem] = quantity
            flask.session["basket"] = basket
            flask.flash("Item Added to Cart")

            
        return flask.render_template("product.html",
                                     item = itemQry,
                                     reviews=reviewQry)
    else:
        
        books = query_db("SELECT * FROM product")        
        return flask.render_template("products.html",
                                     books = books)


# ------------------
# USER Level Stuff
# ---------------------
    
@app.route("/user/login", methods=["GET", "POST"])
def login():
    """
    Login Page
    """
    if request.method == "POST":
        # Get data
        user_email = request.form.get("email")
        user_password = request.form.get("password").encode('utf-8')
        app.logger.info(f"Attempt to login as {user_email}")

        theQry = "SELECT * FROM User WHERE email = ?"
        userQry = query_db(theQry, [user_email], one=True)

        if userQry is None:
            flash("No such user")
        else:
            app.logger.info("User found")
            stored_password_hash = userQry["password"].encode('utf-8')  # assuming this is the hashed password from the database
            if bcrypt.checkpw(user_password, stored_password_hash):
                app.logger.info(f"Login as {user_email} successful")
                session["user"] = userQry["id"]
                flash("Login successful")
                return redirect(url_for("index"))
            else:
                flash("Password is incorrect")
    return render_template("login.html")

@app.route("/user/create", methods=["GET", "POST"])
def create():
    """ Create a new account. """

    if request.method == "GET":
        return render_template("create_account.html")
    
    # Get the form data
    email = request.form.get("email")
    password = request.form.get("password")
    check_password = request.form.get("password2")
    terms = request.form.get("terms")

    def is_strong_password(password):
        if len(password) < 8:
            return False
        if not any(char.isdigit() for char in password):
            return False
        if not any(char.isupper() for char in password):
            return False
        if not any(char.islower() for char in password):
            return False
        if all(char.isalnum() for char in password):  # Checks for absence of special characters
            return False
        return True

    # Sanity checks
    if not email or not password or not check_password: 
        flash("Not all info supplied")
    elif not is_strong_password(password):
        flash("The password should contain at least 8 characters, including 1 special character, 1 uppercase letter, and 1 numerical value.")
    elif password != check_password:
        flash("Passwords don't match")
    elif not terms:
        flash("Please read and accept the terms and conditions")
    else:
        # Checking if the user already exists
        theQry = "SELECT * FROM User WHERE email = ?"                                                 
        userQry = query_db(theQry, [email], one=True)
    
        if userQry:
            flash("A user with that email already exists")
        else:
            # Create the user with hashed password
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            theQry = "INSERT INTO user (email, password) VALUES (?, ?)"
            write_db(theQry, [email, hashed_password])

            flash("Account created, you can now login")
            return redirect(url_for("login"))

    return render_template("create_account.html", email=email)

@app.route("/user/<userId>/settings")
def settings(userId):
    """
    Update a users settings, 
    Allow them to make reviews
    """

    theQry = "Select * FROM User WHERE id = ?"                                                  
    thisUser =  query_db(theQry, one=True)

    
    if not thisUser:
        flask.flash("No Such User")
        return flask.redirect(flask.url_for("index"))

    #Purchases
    theSQL = f"Select * FROM purchase WHERE userID = {userId}"
    purchaces = query_db(theSQL)

    theSQL = """
    SELECT productId, date, product.name
    FROM purchase
    INNER JOIN product ON purchase.productID = product.id
    WHERE userID = {0};
    """.format(userId)

    purchaces = query_db(theSQL)
    
    return flask.render_template("usersettings.html",
                                 user = thisUser,
                                 purchaces = purchaces)

    
@app.route("/logout")
def logout():
    """
    Login Page
    """
    flask.session.clear()
    return flask.redirect(flask.url_for("index"))
    


@app.route("/user/<userId>/update", methods=["GET","POST"])
def updateUser(userId):
    """
    Process any chances from the user settings page
    """

    theQry = "Select * FROM User WHERE id = ?"
    thisUser = query_db(theQry, one=True)
    if not thisUser:
        flask.flash("No Such User")
        return flask.redirect(flask_url_for("index"))

    #otherwise we want to do the checks
    if flask.request.method == "POST":
        current = flask.request.form.get("current")
        password = flask.request.form.get("password")
        app.logger.info("Attempt password update for %s from %s to %s", userId, current, password)
        app.logger.info("%s == %s", current, thisUser["password"])
        if current:
            if current == thisUser["password"]:
                app.logger.info("Password OK, update")
                #Update the Password
                theSQL = f"UPDATE user SET password = '{password}' WHERE id = {userId}"
                app.logger.info("SQL %s", theSQL)
                write_db(theSQL)
                flask.flash("Password Updated")
                
            else:
                app.logger.info("Mismatch")
                flask.flash("Current Password is incorrect")
            return flask.redirect(flask.url_for("settings",
                                                userId = thisUser['id']))

            
    
        flask.flash("Update Error")

    return flask.redirect(flask.url_for("settings", userId=userId))

# -------------------------------------
#
# Functionality to allow user to review items
#
# ------------------------------------------
from flask import Flask, request, redirect, url_for, render_template, flash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Replace with your secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///your_database.db'  # Update with your database URI
app.config['UPLOAD_FOLDER'] = '/path/to/uploaded/images'  # Update with your upload folder path
db = SQLAlchemy(app)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    item_id = db.Column(db.Integer, nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    review_text = db.Column(db.String(500), nullable=False)
    image_path = db.Column(db.String(100), nullable=True)

# Ensure to run this once to set up the database
# db.create_all()

@app.route("/review/<int:user_id>/<int:item_id>", methods=["GET", "POST"])
def review_item(user_id, item_id):
    if request.method == "POST":
        rating = request.form.get("rating")
        review_text = request.form.get("review")
        file = request.files.get('review_image')
        image_path = None

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(image_path)

        # Insert or update review in the database
        review = Review.query.filter_by(user_id=user_id, item_id=item_id).first()
        if review:
            review.rating = rating
            review.review_text = review_text
            review.image_path = image_path if image_path else review.image_path
        else:
            new_review = Review(user_id=user_id, item_id=item_id, rating=rating, review_text=review_text, image_path=image_path)
            db.session.add(new_review)

        db.session.commit()
        flash("Review submitted successfully")
        return redirect(url_for('index'))

    # Logic to display the review form
    # Replace this with your actual method to fetch item details
    item = {'name': 'Example Item', 'image': 'example_image.jpg'}  
    return render_template("review_template.html", item=item)

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



if __name__ == "__main__":
    app.run(debug=True)

@app.route("/review/<userId>/<itemId>", methods=["GET", "POST"])
def reviewItem(userId, itemId):
    """Add a Review"""

    #Handle input
    if flask.request.method == "POST":
        reviewStars = flask.request.form.get("rating")
        reviewComment = flask.request.form.get("review")

        #Clean up review whitespace
        reviewComment = reviewComment.strip()
        reviewId = flask.request.form.get("reviewId")

        app.logger.info("Review Made %s", reviewId)
        app.logger.info("Rating %s  Text %s", reviewStars, reviewComment)

        if reviewId:
            #Update an existing oe
            app.logger.info("Update Existing")

            theSQL = f"""
            UPDATE review
            SET stars = {reviewStars},
                review = '{reviewComment}'
            WHERE
                id = {reviewId}"""

            app.logger.debug("%s", theSQL)
            write_db(theSQL)

            flask.flash("Review Updated")
            
        else:
            app.logger.info("New Review")

            theSQL = f"""
            INSERT INTO review (userId, productId, stars, review)
            VALUES ({userId}, {itemId}, {reviewStars}, '{reviewComment}');
            """

            app.logger.info("%s", theSQL)
            write_db(theSQL)

            flask.flash("Review Made")

    #Otherwise get the review
    theQry = f"SELECT * FROM product WHERE id = {itemId};"
    item = query_db(theQry, one=True)
    
    theQry = f"SELECT * FROM review WHERE userID = {userId} AND productID = {itemId};"
    review = query_db(theQry, one=True)
    app.logger.debug("Review Exists %s", review)

    return flask.render_template("reviewItem.html",
                                 item = item,
                                 review = review,
                                 )

# ---------------------------------------
#
# BASKET AND PAYMEN
#
# ------------------------------------------



@app.route("/basket", methods=["GET","POST"])
def basket():

    #Check for user
    if not flask.session["user"]:
        flask.flash("You need to be logged in")
        return flask.redirect(flask.url_for("index"))


    theBasket = []
    #Otherwise we need to work out the Basket
    #Get it from the session
    sessionBasket = flask.session.get("basket", None)
    if not sessionBasket:
        flask.flash("No items in basket")
        return flask.redirect(flask.url_for("index"))

    totalPrice = 0
    for key in sessionBasket:
        theQry = f"SELECT * FROM product WHERE id = {key}"
        theItem =  query_db(theQry, one=True)
        quantity = int(sessionBasket[key])
        thePrice = theItem["price"] * quantity
        totalPrice += thePrice
        theBasket.append([theItem, quantity, thePrice])
    
        
    return flask.render_template("basket.html",
                                 basket = theBasket,
                                 total=totalPrice)

@app.route("/basket/payment", methods=["GET", "POST"])
def pay():
    """
    Fake paymeent.

    YOU DO NOT NEED TO IMPLEMENT PAYMENT
    """
    
    if not flask.session["user"]:
        flask.flash("You need to be logged in")
        return flask.redirect(flask.url_for("index"))

    #Get the total cost
    cost = flask.request.form.get("total")


    
    #Fetch USer ID from Sssion
    theQry = "Select * FROM User WHERE id = {0}".format(flask.session["user"])
    theUser = query_db(theQry, one=True)

    #Add products to the user
    sessionBasket = flask.session.get("basket", None)

    theDate = datetime.datetime.utcnow()
    for key in sessionBasket:

        #As we should have a trustworthy key in the basket.
        theQry = "INSERT INTO PURCHASE (userID, productID, date) VALUES ({0},{1},'{2}')".format(theUser['id'],
                                                                                              key,
                                                                                              theDate)
                                                                                              
        app.logger.debug(theQry)
        write_db(theQry)

    #Clear the Session
    flask.session.pop("basket", None)

    
    return flask.render_template("pay.html",
                                 total=cost)



# ---------------------------
# HELPER FUNCTIONS
# ---------------------------


@app.route('/uploads/<name>')
def serve_image(name):
    """
    Helper function to serve an uploaded image
    """
    return flask.send_from_directory(app.config["UPLOAD_FOLDER"], name)


@app.route("/initdb")
def database_helper():
    """
    Helper / Debug Function to create the initial database

    You are free to ignore scurity implications of this
    """
    init_db()
    return "Done"

