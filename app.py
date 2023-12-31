# Import necessary modules
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_required, UserMixin, login_user, logout_user, current_user
import mysql.connector
from flask_cors import CORS
import json

# MySQL database connection
mysql = mysql.connector.connect(user='web', password='webPass',
  host='127.0.0.1',
  database='SupplyChainManager')

# Flask app initialization
app = Flask(__name__)
app.secret_key = 'supply_chain_secret_key'
CORS(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, userID, userName, userType):
        self.id = userID
        self.userName = userName
        self.userType = userType

# Loader function for Flask-Login
@login_manager.user_loader
def load_user(userID):
    user = query_user_by_id(userID)
    if user:
        return user
    else:
        return None

# Database query function to get user by ID
def query_user_by_id(userID):
    select_query = 'SELECT * FROM User WHERE userID = %s'
    cursor = mysql.cursor()
    cursor.execute(select_query, (userID,))
    user = cursor.fetchone()
    
    if user:
        return User(user[0], user[1], user[2])
    else:
        return None

# Route for user signup    
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    signup_alert = None
    if request.method == 'POST':
        userName = request.form['userName']
        userType = request.form['userType']
        password = request.form['password']

        # Hash the password before storing it
        hashed_password = bcrypt.generate_password_hash(password)

        # Insert user details into the database
        insert_query = '''
            INSERT INTO User (userName, UserType, Password)
            VALUES (%s, %s, %s)
        '''
        cursor = mysql.cursor(); #create a connection to the SQL instance
        cursor.execute(insert_query, (userName, userType, hashed_password))
        mysql.commit()
        flash("Signup successful! Please login.", "success")
        signup_alert = "Signup successful! Please wait a moment."
        return render_template('signup.html', signup_alert=signup_alert)

    return render_template('signup.html')

# Route for user login	
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        userName = request.form['userName']
        userType = request.form['userType']
        password = request.form['password']

        # Check if the user exists and the password is correct
        select_query = 'SELECT * FROM User WHERE userName = %s AND userType = %s'
        cursor = mysql.cursor(); #create a connection to the SQL instance
        cursor.execute(select_query, (userName, userType))
        user = cursor.fetchone()
        if user and bcrypt.check_password_hash(user[3], password):
            # Set user information in the session
            session['userID'] = user[0]
            session['userName'] = user[1]
            session['userType'] = user[2]

            login_user(User(user[0], user[1], user[2]))

            if session['userType'] == "Supplier":
                return redirect(url_for('supplier_dashboard'));
            else:
                return redirect(url_for('customer_dashboard'));
        else:
            return 'Invalid userName or password'

    return render_template('login.html')

# Route for customer dashboard
@app.route("/customer_dashboard")
@login_required
def customer_dashboard():
    if current_user.is_authenticated and current_user.userType == "Customer":
        cur = mysql.cursor()
        cur.execute('''SELECT p.*, u.userName FROM Product p JOIN User u ON p.userID = u.userID''')
        results  = cur.fetchall()
        products = []
        for row in results :
            product = {
                'productID': row[0],
                'ProductName': row[1],
                'Price': row[2],
                'Rating': row[3],
                'ProductDescription': row[4],
                'userName': row[6]
            }
            products.append(product)
        return render_template('customer.html', products=products)
    else:
        return 'Access denied. You are not a customer.'

# Route for supplier dashboard     
@app.route("/supplier_dashboard")
@login_required
def supplier_dashboard():
    if current_user.is_authenticated and current_user.userType == "Supplier":
        cur = mysql.cursor()
        cur.execute('''SELECT * FROM Product WHERE userID = %s''', (session['userID'],))
        results  = cur.fetchall()
        products = []
        for row in results :
            product = {
                'productID': row[0],
                'ProductName': row[1],
                'Price': row[2],
                'Rating': row[3],
                'ProductDescription': row[4],
                'userID': row[5]
            }
            products.append(product)
        return render_template('supplier.html', products=products)
    else:
        return 'Access denied. You are not a Supplier.'

# Route for user logout
@app.route('/logout', methods=['POST'])
def logout():
    logout_user()
    # Clear session data
    session.pop('userID', None)
    session.pop('userName', None)
    session.pop('userType', None)
    return redirect(url_for('login'))

# Default route
@app.route("/") 
def defaultPage():
    if current_user.is_authenticated:
        if current_user.userType == "Supplier":
            return redirect(url_for('supplier_dashboard'))
        else:
            return redirect(url_for('customer_dashboard'))
    else:
        return redirect(url_for('login'))
    
# Route for adding a new product
@app.route('/add_product', methods=['GET','POST'])
@login_required
def add_product():
    if current_user.userType == "Supplier":
        try:
            if request.method == 'POST':
                productName = request.form['productName']
                price = request.form['price']
                rating = request.form['rating']
                productDescription = request.form['productDescription']
                userID = session.get('userID')
                
                # Insert product into the Product table
                insert_query = '''
                    INSERT INTO Product (productName, price, rating, productDescription, userID)
                    VALUES (%s, %s, %s, %s, %s)
                '''
                cursor = mysql.cursor()
                cursor.execute(insert_query, (productName, price, rating, productDescription, userID))
                mysql.commit()

            return redirect(url_for('supplier_dashboard'))
        except Exception as e:
            return jsonify({'error': str(e)}), 500

# Route for updating a product
@app.route('/update_product/<int:product_id>', methods=['GET','PUT'])
@login_required
def update_product(product_id):
    if current_user.userType == "Supplier":
        try:
            if request.method == 'PUT':
                data = request.get_json()
                productName = data.get('new_product_name')
                price = data.get('new_price')
                rating = data.get('new_rating')
                productDescription = data.get('new_product_description')
                userID = session.get('userID')
                productID = product_id

                # Update product in the Product table
                update_query = '''
                    UPDATE Product
                    SET productName = %s, price = %s, rating = %s, productDescription = %s
                    WHERE productID = %s;
                '''
                cursor = mysql.cursor()
                resp = cursor.execute(update_query, (productName, price, rating, productDescription, productID))
                mysql.commit()

                return jsonify({'message': 'Product updated successfully'}), 200

        except Exception as e:
            return jsonify({'error': str(e)}), 500

# Route for deleting a product
@app.route('/delete_product/<int:product_id>', methods=['GET','DELETE'])
@login_required
def delete_product(product_id):
    if current_user.userType == "Supplier":
        try:
            if request.method == 'DELETE':
                delete_query = '''
                    DELETE FROM Product WHERE ProductID = %s
                '''
                cursor = mysql.cursor()
                cursor.execute(delete_query, (product_id,))
                mysql.commit()

                return jsonify({'message': 'Product deleted successfully'}), 200

        except Exception as e:
            return jsonify({'error': str(e)}), 500

# Route for filtering a product
@app.route('/filter/<filter_value>')
@login_required
def filter_method(filter_value):
    if current_user.is_authenticated and current_user.userType == "Customer":
        cursor = mysql.cursor()
        if(filter_value == "priceLTH"):
            filterQuery='''SELECT p.*, u.userName FROM Product p JOIN User u ON p.userID = u.userID order By price'''
        elif(filter_value == "priceHTL"):
            filterQuery='''SELECT p.*, u.userName FROM Product p JOIN User u ON p.userID = u.userID order By price DESC'''
        elif(filter_value == "ratingLTH"):
            filterQuery='''SELECT p.*, u.userName FROM Product p JOIN User u ON p.userID = u.userID order By rating'''
        elif(filter_value == "ratingHTL"):
            filterQuery='''SELECT p.*, u.userName FROM Product p JOIN User u ON p.userID = u.userID order By rating DESC'''
        else:
            filterQuery='''SELECT p.*, u.userName FROM Product p JOIN User u ON p.userID = u.userID'''
        cursor.execute(filterQuery);
        results = cursor.fetchall()
        products = []
        for row in results :
            product = {
                'productID': row[0],
                'ProductName': row[1],
                'Price': row[2],
                'Rating': row[3],
                'ProductDescription': row[4],
                'userName': row[6]
            }
            products.append(product)
        return jsonify(products), 200
    else:
        return 'Access denied. You are not a customer.'

# Route for searching a product    
@app.route('/search/<search_term>')
@login_required
def search_method(search_term):
    if current_user.is_authenticated and current_user.userType == "Customer":
        cursor = mysql.cursor()
        query = '''
        SELECT p.*, u.userName
        FROM Product p
        JOIN User u ON p.userID = u.userID
        WHERE p.productName LIKE %s
            OR p.productDescription LIKE %s
        '''
        cursor.execute(query, ('%'+ search_term + '%', '%' + search_term + '%'))
        results = cursor.fetchall()
        products = []
        for row in results :
            product = {
                'productID': row[0],
                'ProductName': row[1],
                'Price': row[2],
                'Rating': row[3],
                'ProductDescription': row[4],
                'userName': row[6]
            }
            products.append(product)
        return jsonify(products), 200
    else:
        return 'Access denied. You are not a customer.'
      
if __name__ == "__main__":
  app.run(host='0.0.0.0',port='8080', ssl_context=('cert.pem', 'privkey.pem')) #Run the flask app at port 8080
