import flask
from flask import request, jsonify
import sqlite3
import hashlib
from helpers import login_required
from flask_bcrypt import generate_password_hash, check_password_hash

app = flask.Flask(__name__)
app.config["DEBUG"] = True

DATABASE = './database.db'CONN = sqlite3.connect(DATABASE)
CURSOR = CONN.cursor()


def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
        
    return d

CURSOR.row_factory = dict_factory

@app.route('/', methods=['GET'])
@login_required
def home():
    return '''<h1>WellPlated API</h1>
<p>API for the backend of the WellPlated App</p>'''



@app.route('/signup', methods=['POST'])
def api_signup():
    if(request.method=='POST'):
        data = request.get_json()
        print(data)
        CURSOR.execute("INSERT INTO users(username,password,email) VALUES('"+str(data['username'])+"','"+str(data['password'])+"','"+str(data['email'])"')")
        CONN.commit()
        return jsonify(data)



@app.route('/login', methods=['GET', 'POST'])
def api_login():
    if request.method == 'POST':
      data = request.get_json()
      print(data)
      auth_user = await authenticate_user(data['username'], data['password'])
      if auth_user:
            token = await tokenize(auth_user)
            return {"access_token": token, "token_type": "bearer"}


def tokenize(user_data: dict) -> str:
    return jwt.encode(
        {
            'user_id': user_data['id'],
            'email': user_data['email'],
            'hashed_password': user_data['hashed_password'],
            'exp': datetime.utcnow() + timedelta(minutes=30)
        },
        SECRET_KEY,
        algorithm="HS256")

def authenticate_user(username: str, hashed_password: str) -> dict:
    existing_user = CURSOR.execute("SELECT * FROM users WHERE email="+username).fetchall()
    if existing_user and check_password_hash(existing_user['password'],
                                             hashed_password):
        return user_helper(existing_user)

"""
@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return redirect("/login")  # old version render_template("login.html")
"""
@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()  #session.pop('username', None)

    # Redirect user to login form
    return redirect("/")


@app.route('/recipes/all', methods=['GET'])
def api_all_orders():
    CURSOR.row_factory = dict_factory
    return jsonify(CURSOR.execute("SELECT * FROM Orders").fetchall())       


@app.errorhandler(404)
def page_not_found(e):
    return "<h1>404</h1><p>The location could not be found </p>", 404


"""
@app.route('/api/v1/locations/restaurants/all', methods=['GET'])
def api_all_restaurants():
    conn = sqlite3.connect('datav2.db')
    c = conn.cursor()
    c.row_factory = dict_factory
    return jsonify(c.execute("SELECT * FROM Restaurants").fetchall())

@app.route('/api/v1/locations/customers/all', methods=['GET'])
def api_all_customers():
    conn = sqlite3.connect('datav2.db')
    c = conn.cursor()
    c.row_factory = dict_factory
    return jsonify(c.execute("SELECT * FROM Customers").fetchall())

@app.route('/api/v1/orders/all', methods=['GET'])
def api_all_orders():
    conn = sqlite3.connect('datav2.db')
    c = conn.cursor()
    c.row_factory = dict_factory
    return jsonify(c.execute("SELECT * FROM Orders").fetchall())




@app.route('/api/v1/locations/restaurants', methods=['GET'])
def api_resturant_specific():
    
    query_parameters = request.args
    
    spot_id = query_parameters.get('id')
    address = query_parameters.get('Address')
    phone= query_parameters.get('Phone')
    
    query = "SELECT * FROM Restaurants WHERE"
    to_filter = []
    
    if spot_id:
        query+= ' id=? AND'
        to_filter.append(spot_id)
    if address:
        query+= ' Address=? AND'
        to_filter.append(address)
    if phone:
        query+= ' Phone=? AND'
        to_filter.append(address)

    if not(phone or address or spot_id):
        return page_not_found(404)
    
    query = query[:-4] + ';'
    
    conn = sqlite3.connect('datav2.db')
    conn.row_factory = dict_factory
    cur = conn.cursor()
    
    results = cur.execute(query, to_filter).fetchall()
    
    return jsonify(results)


@app.route('/api/v1/locations/spots', methods=['GET'])
def api_spots_specific():
    
    query_parameters = request.args
    
    spot_id = query_parameters.get('id')
    address = query_parameters.get('Address')
    type = query_parameters.get('Type')
    
    query = "SELECT * FROM Spots WHERE"
    to_filter = []
    
    if spot_id:
        query+= ' id=? AND'
        to_filter.append(spot_id)
    if address:
        query+= ' Address=? AND'
        to_filter.append(address)
    if type:
        query+= ' Type=? AND'
        to_filter.append(type)
    if not(address or spot_id or type):
        return page_not_found(404)
    
    query = query[:-4] + ';'
    
    conn = sqlite3.connect('datav2.db')
    conn.row_factory = dict_factory
    cur = conn.cursor()
    
    results = cur.execute(query, to_filter).fetchall()
    
    return jsonify(results)

@app.route('/api/v1/locations/customers', methods=['GET'])
def api_id_specific():
    
    query_parameters = request.args
    
    spot_id = query_parameters.get('id')
    name = query_parameters.get('Name')
    address=query_parameters.get('Address')
    
    query = "SELECT * FROM customers WHERE"
    to_filter = []
    
    if spot_id:
        query+= ' id=? AND'
        to_filter.append(spot_id)
    if address:
        query+= ' Address=? AND'
        to_filter.append(address)
    
    if name:
        query+= ' name=? AND'
        to_filter.append(address)

    if not(name or address or spot_id):
        return page_not_found(404)
    
    query = query[:-4] + ';'
    
    conn = sqlite3.connect('datav2.db')
    conn.row_factory = dict_factory
    cur = conn.cursor()
    
    results = cur.execute(query, to_filter).fetchall()
    
    return jsonify(results)
    
    # Create an empty list for our results
    
    

    # Loop through the data and match results that fit the requested ID.
    # IDs are unique, but other fields might return many results
  
            
    """


app.run()

