from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_required, UserMixin, login_user
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
    def __init__(self, user_id, username, user_type):
        self.id = user_id
        self.username = username
        self.user_type = user_type

# @login_manager.user_loader
# def load_user(user_id):
#     user = query_user_by_id(user_id)

#     if user:
#         return User(user['user_id'], user['username'], user['user_type'])
#     else:
#         return None

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['userName']
        user_type = request.form['userType']
        password = request.form['password']

        # Hash the password before storing it
        hashed_password = bcrypt.generate_password_hash(password)

        # Insert user details into the database
        insert_query = '''
            INSERT INTO User (UserName, UserType, Password)
            VALUES (%s, %s, %s)
        '''
        cursor = mysql.cursor(); #create a connection to the SQL instance
        cursor.execute(insert_query, (username, user_type, hashed_password))
        mysql.commit()

        return 'Signup successful!'

    return render_template('signup.html')
	
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['userName']
        user_type = request.form['userType']
        password = request.form['password']

        # Check if the user exists and the password is correct
        select_query = 'SELECT * FROM User WHERE userName = %s AND userType = %s'
        cursor = mysql.cursor(); #create a connection to the SQL instance
        cursor.execute(select_query, (username, user_type))
        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user[3], password):
            # Set user information in the session
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['user_type'] = user[2]

            login_user(User(user[0], user[1], user[2]))

            if session['user_type'] == "Supplier":
                return render_template('supplier.html')
            else:
                return redirect(url_for('customer_dashboard'));
        else:
            return 'Invalid username or password'

    return render_template('login.html')

@app.route("/customer_dashboard")
@login_required
def customer_dashboard():
    if current_user.is_authenticated and current_user.user_type == "Customer":
        cur = mysql.cursor()
        cur.execute('''SELECT * FROM Product''')
        rv = cur.fetchall()
        products = []

        for row in rv:
            product = {
                'ProductName': row[0].replace('\n', ' '),
                'Price': row[1],
                'Rating': row[2],
                'ProductDescription': row[3],
                'ID': row[4]
            }
            products.append(product)

        return render_template('customer.html', products=products)
    else:
        return 'Access denied. You are not a customer.'

@app.route('/logout')
def logout():
    logout_user()
    # Clear session data
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('user_type', None)
    return redirect(url_for('login'))

@app.route("/") #Default - Show Data
def hello(): # Name of the method
    cur = mysql.cursor() #create a connection to the SQL instance
    cur.execute('''SELECT * FROM Product''') # execute an SQL statment
    rv = cur.fetchall() #Retreive all rows returend by the SQL statment
    Results=[]
    for row in rv: #Format the Output Results and add to return string
        Result={}
        Result['ProductName']=row[0].replace('\n',' ')
        Result['Price']=row[1]
        Result['Rating']=row[2]
        Result['ProductDescription']=row[3]
        Result['ID']=row[4]
        Results.append(Result)
    response={'Results':Results, 'count':len(Results)}
    ret=app.response_class(
        response=json.dumps(response),
        status=200,
        mimetype='application/json'
    )
    return ret #Return the data in a string format

@app.route('/supplier', methods=['GET', 'POST'])
def supplier():
    if request.method == 'POST':
        # Get product details from the form
        product_name = request.form['productName']
        price = request.form['price']
        rating = request.form['rating']
        product_description = request.form['productDescription']

        # Insert product into the Product table
        insert_query = '''
            INSERT INTO Product (ProductName, Price, Rating, ProductDescription)
            VALUES (%s, %s, %s, %s)
        '''
        cursor = mysql.cursor(); #create a connection to the SQL instance
        cursor.execute(insert_query, (product_name, price, rating, product_description))
        mysql.commit()
        
        return render_template('supplier.html')
	
@app.route("/update", methods=['GET', 'POST']) # Update Student
def update():
    if request.method == 'POST':
        productID = request.form['ID']
        new_product_name = request.form['new_product_name']
        new_price = request.form['new_price']
        new_rating = request.form['new_rating']
        new_product_description = request.form['new_product_description']
        cur = mysql.cursor()
        s = '''UPDATE Product SET productName = '{}', price = '{}', rating = '{}', productDescription = '{}' WHERE productID = {};'''.format(new_product_name, new_price, new_rating, new_product_description, productID)
        app.logger.info(s)
        cur.execute(s)
        mysql.commit()

        return render_template('supplier.html')
    
@app.route("/load/<int:product_id>")
def load_product(product_id):
    cur = mysql.connection.cursor()
    cur.execute('''SELECT * FROM Product WHERE productID = %s''', (product_id,))
    result = cur.fetchone()

    if result:
        response = {
            'ProductName': result[0],
            'Price': result[1],
            'Rating': result[2],
            'ProductDescription': result[3],
            'ID': result[4]
        }
        return jsonify(response), 200
    else:
        return "Product not found", 404
    
@app.route("/delete/<int:product_id>", methods=["DELETE"])
def delete_product(product_id):
    cur = mysql.connection.cursor()
    cur.execute('''DELETE FROM Product WHERE productID = %s''', (product_id,))
    mysql.connection.commit()
    return render_template('supplier.html')

if __name__ == "__main__":
  app.run(host='0.0.0.0',port='8080', ssl_context=('cert.pem', 'privkey.pem')) #Run the flask app at port 8080
