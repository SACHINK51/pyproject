from flask import Flask
from flask import render_template
from flask import request
import mysql.connector
from flask_cors import CORS
import json
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector

mysql = mysql.connector.connect(user='web', password='webPass',
  host='127.0.0.1',
  database='student')

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
CORS(app)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        user_type = request.form['userType']
        password = request.form['password']

        # Hash the password before storing it
        hashed_password = generate_password_hash(password, method='sha256')

        # Insert user details into the database
        insert_query = '''
            INSERT INTO User (Username, UserType, Password)
            VALUES (%s, %s, %s)
        '''
        cursor.execute(insert_query, (username, user_type, hashed_password))
        conn.commit()

        return 'Signup successful!'

    return render_template('signup.html')
	
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        user_type = request.form['userType']
        password = request.form['password']

        # Check if the user exists and the password is correct
        select_query = 'SELECT * FROM User WHERE Username = %s AND UserType = %s'
        cursor.execute(select_query, (username, user_type))
        user = cursor.fetchone()

        if user and check_password_hash(user[3], password):
            # Set user information in the session
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['user_type'] = user[2]

            return 'Login successful!'
        else:
            return 'Invalid username or password'

    return render_template('login.html')
	
@app.route('/add', methods=['GET', 'POST'])
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
        cursor.execute(insert_query, (product_name, price, rating, product_description))
        conn.commit()

        return 'Product added successfully!'

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

        return '{"Result":"Success"}'
    else:
        return render_template('update.html')

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
if __name__ == "__main__":
  app.run(host='0.0.0.0',port='8080', ssl_context=('cert.pem', 'privkey.pem')) #Run the flask app at port 8080
