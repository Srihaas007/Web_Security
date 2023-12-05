from .meta import *

import datetime
import bcrypt
from flask import flash, request,redirect,session, render_template, request, url_for
from werkzeug.utils import secure_filename
import os



UPLOAD_FOLDER = 'C:/Users/sriha/Desktop/UNI/6005-CW-Teplate-main (1)/6005-CW-Teplate-main/app/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit



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
    
    if flask.request.method == "POST":
        # Get data
        user_email = flask.request.form.get("email")
        password = flask.request.form.get("password")
        app.logger.info("Attempt to login as %s:%s", user_email, password)

        # Check if the user is an admin
        admin_query = "SELECT * FROM admin WHERE email = ?"
        admin_data = query_db(admin_query, [user_email], one=True)

        if admin_data:
            app.logger.info("Admin is OK")
            admin_password = admin_data["password"]
            
            if password == admin_password:
                app.logger.info("Login as %s (Admin) Success", admin_data["email"])
                flask.session["admin"] = True  # Set an 'admin' flag in the session
                flask.session["user"] = admin_data["id"]
                flask.flash("Logged in as Admin Successful")
                return flask.render_template("admin_dashboard.html")

        # If not an admin, check if it's a regular user
        user_query = "SELECT * FROM user WHERE email = ?"
        user_data = query_db(user_query, [user_email], one=True)

        if user_data:
            app.logger.info("User is OK")
            hashed_db_password = user_data["password"]
            
            if check_password(password, hashed_db_password):
                app.logger.info("Login as %s Success", user_data["email"])
                flask.session["admin"] = False  # Set 'admin' flag to False
                flask.session["user"] = user_data["id"]
                flask.flash("Login Successful")
                return flask.redirect(flask.url_for("index"))
            else:
                flask.flash("Password is Incorrect")

        else:
            flask.flash("No Such User or Admin")

    return flask.render_template("login.html")


@app.route("/admin/admin_dashboard", methods=["GET", "POST"])
def admin_dashboard():
    if 'admin' not in flask.session:
        flask.flash('Please log in as an admin.')
        return flask.redirect(flask.url_for('login'))

    # Connect to the SQLite database
    conn = sqlite3.connect('DATABASE')  # Corrected database file path
    cursor = conn.cursor()

    # Get a list of all tables in the database
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    print(tables)  # Print the table names to check if they are fetched correctly

    table_data = []

    # Iterate over the tables and retrieve column information for each
    for table in tables:
        table_name = table[0]

        # Get column information for the current table
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = cursor.fetchall()
        print(columns)  

        table_data.append({
            'table_name': table_name,
            'columns': [column[1] for column in columns],  # Extract column names
        })

    # Close the database connection
    conn.close()

    return flask.render_template("admin_dashboard.html", table_data=table_data)



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

@app.route('/user/terms.html')
def terms():
    return flask.render_template('terms.html')

@app.route('/user/newseller_registration.html')
def newseller_registration():
    return flask.render_template('newseller_registration.html')

@app.route("/user/seller", methods=["GET", "POST"])
def seller():
    is_seller = False  # Initialize as False

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        try:
            conn = get_db()
            cursor = conn.cursor()

            # Check if the user is already a seller
            check_query = "SELECT * FROM seller WHERE email = ?"
            cursor.execute(check_query, (email,))
            existing_seller = cursor.fetchone()

            # Check if the email and password match a user in the 'user' table
            user_query = "SELECT * FROM user WHERE email = ?"
            cursor.execute(user_query, (email,))
            user_data = cursor.fetchone()

            if existing_seller:
                is_seller = True  # Set to True if the user is a seller
                session["is_seller"] = True  # Store seller information in the session
                flash("Seller already exists with this email.")
            elif not user_data:
                flash("No user found with this email.")
            elif not bcrypt.checkpw(password.encode('utf-8'), user_data["password"]):
                flash("Password is incorrect.")
            else:
                # Securely hash the password
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

                # Add the email and hashed password to the seller table
                insert_query = "INSERT INTO seller (email, password) VALUES (?, ?)"
                cursor.execute(insert_query, (email, hashed_password))
                conn.commit()

                is_seller = True  # Set to True after becoming a seller
                session["is_seller"] = True  # Store seller information in the session
                flash("Congratulations! You are now a seller.")

            # Redirect the user to the seller.html page or any other desired page
            return redirect(url_for("seller"))
        except sqlite3.Error as e:
            # Handle SQLite errors (e.g., constraint violations)
            flash("SQLite error: " + str(e))
        except Exception as e:
            # Handle other exceptions (e.g., file I/O errors)
            flash("An error occurred while becoming a seller: " + str(e))
        finally:
            conn.close()

    return render_template("seller.html", is_seller=is_seller)



# Define the allowed file extensions for image uploads
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Function to check if a file has an allowed extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/user/add_products', methods=['GET', 'POST'])
def add_products():
    if 'user' not in session:
        flash('Please log in to add products.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Get product details from the form
        name = request.form.get('name')
        description = request.form.get('description')
        price = request.form.get('price')
        image = request.files.get('image')

        # Validate the form data
        if not name or not description or not price or not image:
            flash('Please fill out all fields.')
        else:
            # Handle the uploaded image (you can save it to a directory)
            if image:
                # Save the image to your desired directory
                image_filename = secure_filename(image.filename)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))

                # Insert the new product into the database
                insert_query = """
                INSERT INTO product (name, description, price, image, seller_id)
                VALUES (?, ?, ?, ?, ?)
                """
                seller_id = session['user']
                write_db(insert_query, [name, description, price, image_filename, seller_id])

                flash('Product added successfully.')
                return redirect(url_for('edit_products'))

    return render_template('add_products.html')

@app.route('/user/edit_products')
def edit_products():
    if 'user' not in session:
        flash('Please log in to edit your products.')
        return redirect(url_for('login'))

    user_id = session['user']

    # Fetch the seller's products from the product table
    products_query = "SELECT * FROM product WHERE seller_id = ?"
    products = query_db(products_query, [user_id])

    return render_template('edit_products.html', products=products)

@app.route('/user/edit_products/<int:product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    if 'user' not in session:
        flash('Please log in to edit your products.')
        return redirect(url_for('login'))

    user_id = session['user']

    # Fetch the product from the database
    product_query = "SELECT * FROM product WHERE id = ? AND seller_id = ?"
    product = query_db(product_query, [product_id, user_id], one=True)

    if not product:
        flash('Product not found or you do not have permission to edit it.')
        return redirect(url_for('edit_products'))

    if request.method == 'POST':
        # Get updated product details from the form
        name = request.form.get('name')
        description = request.form.get('description')
        price = request.form.get('price')

        # Validate the form data
        if not name or not description or not price:
            flash('Please fill out all fields.')
        else:
            # Update the product information in the database
            update_query = """
            UPDATE product
            SET name = ?, description = ?, price = ?
            WHERE id = ? AND seller_id = ?
            """
            write_db(update_query, [name, description, price, product_id, user_id])

            flash('Product updated successfully.')
            return redirect(url_for('edit_products'))

    return render_template('edit_product.html', product=product)




@app.route("/user/<userId>/settings")
def settings(userId):
    """
    Update a user's settings, 
    Allow them to make reviews
    """

    theQry = "Select * FROM User WHERE id = ?"
    thisUser = query_db(theQry, [userId], one=True)  # Pass userId as a parameter

    if not thisUser:
        flash("No Such User")
        return redirect(url_for("index"))

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

@app.route("/review/<userId>/<itemId>", methods=["GET", "POST"])
def reviewItem(userId, itemId):
    """Add or Update a Review with optional image upload."""

    if request.method == "POST":
        reviewStars = request.form.get("rating")
        reviewComment = request.form.get("review").strip()
        reviewId = request.form.get("reviewId")
        file = request.files.get('review_image')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename) # Correctly getting just the filename
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename) # Path to save the file
            file.save(file_path) # Saving the file

            if reviewId:
                # Update with just the filename, not the full path
                update_query = f"""
                UPDATE review
                SET stars = {reviewStars},
                    review = '{reviewComment}',
                    image_path = '{filename}'
                WHERE id = {reviewId}
                """
                write_db(update_query)
                flash("Review Updated")
            else:
                # Insert with just the filename
                insert_query = f"""
                INSERT INTO review (userId, productId, stars, review, image_path)
                VALUES ({userId}, {itemId}, {reviewStars}, '{reviewComment}', '{filename}');
                """
                write_db(insert_query)
                flash("Review Added")

    # Fetch the review
    product_query = f"SELECT * FROM product WHERE id = {itemId};"
    item = query_db(product_query, one=True)
    
    review_query = f"SELECT * FROM review WHERE userID = {userId} AND productID = {itemId};"
    review = query_db(review_query, one=True)

    return render_template("reviewItem.html", item=item, review=review)

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return flask.send_from_directory(app.config['UPLOAD_FOLDER'], filename)




# ---------------------------------------
#
# BASKET AND PAYMENT
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
        theQry = "INSERT INTO PURCHASE (userID, productID, date) VALUES (?,?,?)".format(theUser['id'],
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

