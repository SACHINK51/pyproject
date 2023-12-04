from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_required, UserMixin, login_user, logout_user, current_user
import mysql.connector
from flask_cors import CORS
import json
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector

mysql = mysql.connector.connect(user='web', password='webPass',
  host='127.0.0.1',
  database='SupplyChainManager')

from logging.config import dictConfig

dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})


app = Flask(__name__)
app.secret_key = 'supply_chain_secret_key'
CORS(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, userID, userName, userType):
        self.id = userID
        self.userName = userName
        self.userType = userType

@login_manager.user_loader
def load_user(userID):
    user = query_user_by_id(userID)
    if user:
        return user
    else:
        return None

def query_user_by_id(userID):
    # Replace this with your actual database query
    select_query = 'SELECT * FROM User WHERE userID = %s'
    cursor = mysql.cursor()
    cursor.execute(select_query, (userID,))
    user = cursor.fetchone()
    
    if user:
        return User(user[0], user[1], user[2])
    else:
        return None
    
@app.route('/signup', methods=['GET', 'POST'])
def signup():
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

        return 'Signup successful!'

    return render_template('signup.html')
	
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
        print('products', products)
        return render_template('customer.html', products=products)
    else:
        return 'Access denied. You are not a customer.'
    
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
        print('products', products)
        return render_template('supplier.html', products=products)
    else:
        return 'Access denied. You are not a customer.'


@app.route('/logout', methods=['POST'])
def logout():
    logout_user()
    # Clear session data
    session.pop('userID', None)
    session.pop('userName', None)
    session.pop('userType', None)
    return redirect(url_for('login'))

@app.route("/") 
def defaultPage():
    if current_user.is_authenticated:
        if current_user.userType == "Supplier":
            return redirect(url_for('supplier_dashboard'))
        else:
            return redirect(url_for('customer_dashboard'))
    else:
        return redirect(url_for('login'))
    

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


@app.route('/update_product/<int:product_id>', methods=['GET','PUT'])
@login_required
def update_product(product_id):
    if current_user.userType == "Supplier":
        try:
            print('request.method = ',request.method)
            if request.method == 'PUT':
                data = request.get_json()
                print(data)
                productName = data.get('new_product_name')
                price = data.get('new_price')
                rating = data.get('new_rating')
                productDescription = data.get('new_product_description')
                print('product_id = ',product_id)
                print('sessionID = ', session.get('userID'))
                userID = session.get('userID')
                productID = product_id

                # Update product in the Product table
                update_query = '''
                    UPDATE Product
                    SET productName = %s, price = %s, rating = %s, productDescription = %s
                    WHERE productID = %s;
                '''
                print('update_query',update_query)
                cursor = mysql.cursor()
                resp = cursor.execute(update_query, (productName, price, rating, productDescription, productID))
                print(resp)
                mysql.commit()

                return jsonify({'message': 'Product updated successfully'}), 200

        except Exception as e:
            return jsonify({'error': str(e)}), 500

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
        
if __name__ == "__main__":
  app.run(host='0.0.0.0',port='8080', ssl_context=('cert.pem', 'privkey.pem')) #Run the flask app at port 8080
