from google.cloud import datastore
from flask import Flask, request, jsonify
from requests_oauthlib import OAuth2Session
from google.oauth2 import id_token
from google.auth import crypt, jwt
from google.auth.transport import requests
import requests as reqq
# import constants


# This disables the requirement to use HTTPS so that you can test locally.
import os 
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
client = datastore.Client()

# OAuth2 Credentials
client_id = '418557233753-t5c6u154tjrajkitgfpsjk0r4ajvget8.apps.googleusercontent.com'
client_secret = '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'

# This is the page that you will use to decode and collect the info from
# the Google authentication flow
redirect_uri = 'https://final-project-333515.uk.r.appspot.com/profile'

# These let us get basic info to identify a user and not much else
# they are part of the Google People API
scope = ['https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile', 'openid']
oauth = OAuth2Session(client_id, client_secret, redirect_uri=redirect_uri, scope=scope)

# This link will redirect users to begin the OAuth flow with Google
@app.route('/')
def index():
	authorization_url, state = oauth.authorization_url('https://accounts.google.com/o/oauth2/auth',	access_type="offline", prompt="select_account")
	return  '<h1>Welcome</h1>\n <p>Click <a href=%s>here</a> to log in or create a new account.</p>' % authorization_url

# This is where users will be redirected back to and where you can collect
# the JWT for use in future requests
@app.route('/profile')
def oauthroute():
	token = oauth.fetch_token('https://accounts.google.com/o/oauth2/token', authorization_response=request.url, client_secret=client_secret)
	req = requests.Request()
	id_info = id_token.verify_oauth2_token(token['id_token'], req, client_id)

	# Search database for user
	query = client.query(kind="users")
	query.add_filter("sub", "=", id_info['sub'])
	result = list(query.fetch())

	# Create a new user if they don't exist in the database
	if len(result) == 0:
		new_user = datastore.entity.Entity(key=client.key('users'))
		new_user.update({'email': id_info['email'], 'sub': id_info['sub']})
		client.put(new_user)
		return (("<h2>Your account has been created.  Following are your private creds:</h2>\n	<p>JWT: %s</p>\n	<p>Unique ID (sub): %s</p>\n" % (token['id_token'], id_info['sub'])), 201)
	elif len(result) == 1:
		return (("<h2>Deja vu! Welcome back friend!</h2>\n	<p>JWT: %s</p>\n	<p>Unique ID (sub): %s</p>\n" % (token['id_token'], id_info['sub'])), 200)


# Route for a unique user
@app.route('/users/<uid>', methods=['GET'])
def get_user_id(uid):
	if request.method == 'GET':

		jwt_sub = verifyJWT()
		if jwt_sub == 'fail':
			return(jsonify({'Error': 'Could not verify JWT!'}), 401)
		elif jwt_sub == 'nojwt':
			return (jsonify({'Error': 'JWT was not given!'}), 401)
		
		# Verify that the request is authorized to access user
		if jwt_sub != uid:
			return(jsonify({'Error': 'You do not have access to this user!'}), 401)
			
		# Find user with sub
		query = client.query(kind='users')
		query.add_filter("sub", "=", uid)
		results = list(query.fetch())

		# Throw error is user does not exist in database
		if len(results) == 0:
			return(jsonify({'Error': 'This user does not exist!\n'}), 401)

		# Add respective id to each object
		for e in results:
			e["id"] = e.key.id
			e["self"] = request.url

		return (jsonify(results), 200)


# Route for all restaurants for specific user
@app.route('/restaurants/<uid>', methods=['GET'])
def restaurants_get_users(uid):
    if request.method == 'GET':
        jwt_sub = verifyJWT()
        if jwt_sub == 'fail':
            return(jsonify({'Error': 'Could not verify JWT!'}), 401)
        elif jwt_sub == 'nojwt':
            return (jsonify({'Error': 'JWT was not given!'}), 401)
		
        # Find restaurants for a specific owner
        query = client.query(kind='restaurants')
        query.add_filter("owner", "=", jwt_sub)
        results = list(query.fetch())

        # Throw error is user does not exist in database
		if len(results) == 0:
			return(jsonify({'Error': 'No restaurants exist for this user!\n'}), 401)
        
        # Add id and url to each restaurant
        for e in results:
            e["id"] = e.key.id
            e["self"] = request.url_root + 'restaurants/' + str(e.key.id)

        return(jsonify({'restaurants': results}), 200)

# Route for restaurants
@app.route('/restaurants', methods=['POST', 'GET'])
def restaurants_post_get():
    
    # Create new restaurant
    if request.method == 'POST':
        jwt_sub = verifyJWT()
        if jwt_sub == 'fail':
            return(jsonify({'Error': 'Could not verify JWT!'}), 401)
        elif jwt_sub == 'nojwt':
            return (jsonify({'Error': 'JWT was not given!'}), 401)

        # Grab content from request payload
        content = request.get_json()

        # Check to see if all properties are given - No need to validate
        if len(content) != 3:
            return (jsonify({"Error": "The request object is missing at least one of the required attributes"}), 400)
		
        # Add all restaurants in database to list
        query = client.query(kind='restaurants')
        results = list(query.fetch())
        
        # Check if restaurant already in database
        for e in results:
            if e["title"] == content["title"]:
                if e["location"] == content["location"]:
                    return (jsonify({"Error": "A restaurant with the same name already exists! Please try a new name."}), 403) # Return 403 if not unique
        
        # Add new restaurant to database
        new_restaurant = datastore.entity.Entity(key=client.key('restaurants'))
        new_restaurant.update({"title": content["title"], "type": content["type"], "location": content["location"], "owner": jwt_sub, "orders": [], "completed_orders": []})
        client.put(new_restaurant)

        # Return new restaurant object
        new_restaurant.update({'id': new_restaurant.key.id, 'self': request.url + "/" + str(new_restaurant.key.id)})
        return (jsonify(new_restaurant), 201)
    
    # Read existing restaurant
    elif request.method == 'GET':
        jwt_sub = verifyJWT()
        if jwt_sub == 'fail':
            return(jsonify({'Error': 'Could not verify JWT!'}), 401)
        elif jwt_sub == 'nojwt':
            return (jsonify({'Error': 'JWT was not given!'}), 401)

        # Check restaurants in database 
        query = client.query(kind="restaurants")
        query.add_filter('owner', '=', jwt_sub)  # by user id
        q_limit = int(request.args.get('limit', '5')) # 5 items per page
        q_offset = int(request.args.get('offset', '0')) # start from beginning of list
        l_iterator = query.fetch(limit= q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages)) 

        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        
        # Add id and url for each restaurant
        for e in results:
            e["id"] = e.key.id
            e["self"] = request.url_root + 'restaurants/' + str(e.key.id)
            
            # restaurants with orders
            if e['orders']:
                for single_order in e['orders']:
                    order_key = client.key("orders", single_order['id'])
                    order = client.get(key=order_key) # get order in database by id
                    # add order values
                    single_order['name'] = order['name']
                    single_order['time'] = order['time']
                    single_order['table'] = order['table']
                    single_order['completed'] = order['completed']
                    single_order["self"] = request.url_root + "orders/" + str(single_order['id'])
             
            # restaurants with completed orders
            if e['completed_orders']:
                for single_corder in e['completed_orders']:
                    corder_key = client.key("orders", single_corder['id'])
                    corder = client.get(key=corder_key) # get completed order in database by id
                    # add completed order values
                    single_corder['name'] = corder['name']
                    single_corder['time'] = corder['time']
                    single_corder['table'] = corder['table']
                    single_corder['completed'] = corder['completed']
                    single_corder["self"] = request.url_root + "orders/" + str(single_corder['id'])

        # return restaurants with pagination
        output = {"retaurants": results}
        if next_url:
            output["next"] = next_url
        output['total'] = len(list(query.fetch()))
        return (jsonify(output), 200)

    # Update all restaurants not allowed  
    elif request.method == 'PUT':
        return(jsonify({"Error": "This API doesn't allow you to edit all restaurants!"}), 405)
    
    # Delete all restaurants not allowed
    elif request.method == 'DELETE':
        return(jsonify({"Error": "This API doesn't allow you to delete all restaurants!"}), 405)
    
    else:
        return ('Unknown Error', 500)        

# Route for orders
@app.route('/orders', methods=['POST', 'GET'])

def orders_post_get():
    
    # Create order
    if request.method == 'POST':
        jwt_sub = verifyJWT()
        if jwt_sub == 'fail':
            return(jsonify({'Error': 'Could not verify JWT!'}), 401)
        elif jwt_sub == 'nojwt':
            return (jsonify({'Error': 'JWT was not given!'}), 401)

        # Grab content from request body
        content = request.get_json()
            
        # Check to see if all properties are given - No need to validate
        if len(content) != 3:
            return (jsonify({"Error": "The request object is missing at least one of the required attributes"}), 400)
        
        # Prevent duplicate orders
        for e in results:
            if e["name"] == content["name"] and e["table"] == content["table"] and e["time"] == content["time"]:
                return (jsonify({"Error": "An order with the same name already exists!"}), 403) # Return 403 if not unique
        
        # Add new order to database 
        new_order = datastore.entity.Entity(key=client.key("orders"))
        new_order.update({'name': content['name'], 'rid': None, 'completed': False, "table": content["table"], "time": content["time"], "owner": jwt_sub})
        client.put(new_order)

        # Return new order object
        new_order.update({'id': new_order.key.id, 'self': request.url + "/" + str(new_order.key.id)})
        return (jsonify(new_order), 201)
	
    # Read orders 
    elif request.method == 'GET':
        jwt_sub = verifyJWT()
        if jwt_sub == 'fail':
            return(jsonify({'Error': 'Could not verify JWT!'}), 401)
        elif jwt_sub == 'nojwt':
            return (jsonify({'Error': 'JWT was not given!'}), 401)

        # Check orders in database 
        query = client.query(kind="orders")
        query.add_filter('owner', '=', jwt_sub) # by user id
        q_limit = int(request.args.get('limit', '5')) # 5 items per page
        q_offset = int(request.args.get('offset', '0')) # start from beginning of list
        l_iterator = query.fetch(limit= q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))

        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        
        # Add id and url for each restaurant
        for e in results:
            e["id"] = e.key.id
            e["self"] = request.url_root + 'orders/' + str(e.key.id)
            output = {"orders": results} # all of the orders by user id
        
        if next_url:
            output["next"] = next_url 
        output['total'] = len(list(query.fetch()))
        return (jsonify(output), 200)

    # Update all orders not allowed  
    elif request.method == 'PUT':
        return(jsonify({"Error": "This API doesn't allow you to edit all orders!"}), 405)
    
    # Delete all orders not allowed  
    elif request.method == 'DELETE':
        return(jsonify({"Error": "This API doesn't allow you to delete all orders!"}), 405)
    
    else:
        return ('Unknown Error', 500)

# Route for orders of a specific restaurant
@app.route('/restaurants/<rid>/orders', methods=['POST', 'GET'])
def orders_post_restaurants(rid):

    # Read orders of restaurant for given id    
    if request.method == 'GET':
        jwt_sub = verifyJWT()
        if jwt_sub == 'fail':
            return(jsonify({'Error': 'Could not verify JWT!'}), 401)
        elif jwt_sub == 'nojwt':
            return (jsonify({'Error': 'JWT was not given!'}), 401)

        # Get restaurant by id
        restaurant_key = client.key("restaurants", int(rid))
        restaurant = client.get(key=restaurant_key)

        if restaurant == None:
            return (jsonify({'Error': 'This restaurant does not exist!'}), 401)

        if restaurant['owner'] != jwt_sub:
            return (jsonify({'Error': 'You do not own this restaurant!'}), 401)

        # Get all orders for given restaurant id
        query = client.query(kind="orders")
        query.add_filter("rid", "=", rid)
        query.add_filter("completed", "=", False) 
        orders = list(query.fetch()) # non-completed

        query = client.query(kind="orders")
        query.add_filter("rid", "=", rid)
        query.add_filter("completed", "=", True)
        corders = list(query.fetch()) # completed

        for e in orders:
            e["id"] = e.key.id
            e["self"] = request.url_root + "orders/" + str(e.key.id)
        
        for e in corders:
            e["id"] = e.key.id
            e["self"] = request.url_root + "orders/" + str(e.key.id)

        return(jsonify({'orders': orders, 'completed_orders': corders}), 200)

    # Create order for given restaurant	
    elif request.method == 'POST':
        jwt_sub = verifyJWT()
        if jwt_sub == 'fail':
            return(jsonify({'Error': 'Could not verify JWT!'}), 401)
        elif jwt_sub == 'nojwt':
            return (jsonify({'Error': 'JWT was not given!'}), 401)

        restaurant_key = client.key("restaurants", int(rid))
        restaurant = client.get(key=restaurant_key)

        if restaurant == None:
            return (jsonify({'Error': 'This restaurant does not exist!'}), 401)

        if restaurant['owner'] != jwt_sub:
            return (jsonify({'Error': 'You do not own this restaurant!'}), 401)

        # Grab content from request body
        content = request.get_json()
        
        # Check to see if all properties are given - No need to validate
        if len(content) != 3:
            return (jsonify({"Error": "The request object is missing at least one of the required attributes"}), 400)
		
        # Create new order from request
        new_order = datastore.entity.Entity(key=client.key("orders"))
        new_order.update({'name': content['name'], 'rid': rid, 'completed': False, "table": content["table"], "time": content["time"], "owner": jwt_sub})
        client.put(new_order)

        # Put new order in restaurant
        restaurant['orders'].append({'id': new_order.key.id, 'owner': jwt_sub, 'rid': rid})
        client.put(restaurant)

        # Return object
        restaurant.update({'id': restaurant.key.id, 'self': request.url_root + "restaurants/" + str(restaurant.key.id)})
        for order in restaurant['orders']:
            order['self'] = request.url_root + "orders/" + str(order['id'])
        return (jsonify(restaurant), 201)

# Route for given order of specific restaurant
@app.route('/restaurants/<rid>/orders/<oid>', methods=['PUT'])

# Update Existing Restaurant
def put_order_restaurant(rid, oid):
	if request.method == 'PUT':
		jwt_sub = verifyJWT()
		if jwt_sub == 'fail':
			return(jsonify({'Error': 'Could not verify JWT!'}), 401)
		elif jwt_sub == 'nojwt':
			return (jsonify({'Error': 'JWT was not given!'}), 401)

        # Get restaurant by id 
		restaurant_key = client.key("restaurants", int(rid))
		restaurant = client.get(key=restaurant_key)
		
        # Get specific order by id
        order_key = client.key("orders", int(oid))
        order = client.get(key=order_key)

        # Error handling
		if restaurant == None:
			return (jsonify({"Error": "This restaurant does not exist!"}), 404)
		if order == None:
			return (jsonify({"Error": "This order does not exist!"}), 404)
		if restaurant['owner'] != jwt_sub:
			return (jsonify({'Error': 'You do not own this restaurant!'}), 401)
		elif order['owner'] != jwt_sub:
			return (jsonify({'Error': 'You do not own this order!'}), 401)

		for r_order in restaurant['orders']:
			if r_order['id'] == int(oid):
				return (jsonify({'Error': 'This order is already placed!'}), 403)
		
        # Add order object to restaurant orders
		restaurant['orders'].append({'id': order.key.id, 'owner': order['owner'], 'rid': rid})
		client.put(restaurant)
		order['rid'] = rid
		client.put(order)

		return(jsonify(''), 204)

# Route for a unique order
@app.route('/orders/<oid>', methods=['GET', 'DELETE', 'PUT', 'PATCH'])

def orders_get_delete_put_patch(oid):

    # Update a specific order
    if request.method == 'PUT' or request.method == 'PATCH':
        jwt_sub = verifyJWT()
        if jwt_sub == 'fail':
            return(jsonify({'Error': 'Could not verify JWT!'}), 401)
        elif jwt_sub == 'nojwt':
            return (jsonify({'Error': 'JWT was not given!'}), 401)
        
        # Look-up order in database
        order_key = client.key("orders", int(oid))
        order = client.get(key=order_key)

        # Error Handling
        if order == None:
            return (jsonify({'Error': 'This order does not exist!'}), 401) 
        if order['owner'] != jwt_sub:
            return (jsonify({'Error': 'You did not place this order!'}), 401)

        # Grab content from request body
        content = request.get_json()
        
        # No content, no change
        if len(content) == 0:
            return (jsonify({"Error": "The request object is missing!"}), 400)

        # Update properties for valid order content
        for prop in content:
            if prop == 'completed' and type(content.get(prop)) == bool: # changing completed a property
                if order["rid"]: # is assigned to restaurant
                    
                    # Get corresponding restaurant
                    restaurant_key = client.key("restaurants", int(order['rid']))
                    restaurant = client.get(key=restaurant_key) 
                    
                    # Update order status
                    if order['completed'] == False and content.get(prop) == True:
                        restaurant['orders'].remove({'id': order.key.id, 'owner': jwt_sub, 'rid': str(restaurant.key.id)})
                        restaurant['completed_orders'].append({'id': order.key.id, 'owner': jwt_sub, 'rid': str(restaurant.key.id)})
                    elif order['completed'] == True and content.get(prop) == False:
                        restaurant['completed_orders'].remove({'id': order.key.id, 'owner': jwt_sub, 'rid': str(restaurant.key.id)})
                        restaurant['orders'].append({'id': order.key.id, 'owner': jwt_sub, 'rid': str(restaurant.key.id)})
                    client.put(restaurant)
                order["completed"] = content.get(prop)
            elif prop == 'name' and type(content.get(prop)) == str:
                order["name"] = content.get(prop)
            elif prop == 'table' and type(content.get(prop)) == int:
                order["table"] = content.get(prop)
            elif prop == 'time' and type(content.get(prop)) == str:
                order["time"] = content.get(prop)
            else:
                return (jsonify({"Error": "Invalid content!"}), 400)
        client.put(order)  # save to database

        # Add id and url to order
        order['id'] = order.key.id
        order['self'] = request.url
        
        return(jsonify(order), 201)
    
    # Read for specific order
    elif request.method == 'GET':
        jwt_sub = verifyJWT()
        if jwt_sub == 'fail':
            return(jsonify({'Error': 'Could not verify JWT!'}), 401)
        elif jwt_sub == 'nojwt':
            return (jsonify({'Error': 'JWT was not given!'}), 401)
        
        # Look-up order in database
        order_key = client.key("orders", int(oid))
        order = client.get(key= order_key)

        # Error handling
        if order == None:
            return (jsonify({'Error': 'This order does not exist!'}), 404)
        if order['owner'] != jwt_sub:
            return (jsonify({'Error': 'You do not own this order!'}), 401)
        
        # Add id and url to order
        order['id'] = order.key.id
        order['self'] = request.url
        
        return(jsonify(order), 200)
    
    # Delete specific order 
    elif request.method == 'DELETE':
        jwt_sub = verifyJWT()
        if jwt_sub == 'fail':
            return(jsonify({'Error': 'Could not verify JWT!'}), 401)
        elif jwt_sub == 'nojwt':
            return (jsonify({'Error': 'JWT was not given!'}), 401)

        # Look-up order in database
        order_key = client.key("orders", int(oid))
        order = client.get(key=order_key)

        # Error handling
        if order == None:
            return (jsonify({"Error": "No order with this id exists"}), 404)
        elif order['owner'] != jwt_sub:
            return (jsonify({'Error': 'You did not make this order!'}), 401)
		
        # Order assigned to a restaurant
        if order['rid']:
            restaurant_key = client.key("restaurants", int(order['rid']))
            restaurant = client.get(key=restaurant_key) # look-up restaurant
            
            if order['completed']:
                restaurant['completed_orders'].remove({'id': order.key.id, 'owner': jwt_sub, 'rid': str(restaurant.key.id)})
            else:
                restaurant['orders'].remove({'id': order.key.id, 'owner': jwt_sub, 'rid': str(restaurant.key.id)})
            client.put(restaurant) # save to database
	
        client.delete(order) 			
        return(jsonify(''), 204)

# Route for a unique restaurant
@app.route('/restaurants/<rid>', methods=['GET', 'DELETE', 'PUT', 'PATCH'])

def restaurants_get_delete(rid):
    
    # Update specific restaurant    
    if request.method == 'PUT' or request.method == 'PATCH':
        jwt_sub = verifyJWT()
        if jwt_sub == 'fail':
            return(jsonify({'Error': 'Could not verify JWT!'}), 401)
        elif jwt_sub == 'nojwt':
            return (jsonify({'Error': 'JWT was not given!'}), 401)

        # Look-up restaurant in database
        restaurant_key = client.key("restaurants", int(rid))
        restaurant = client.get(key=restaurant_key)

        # Error handling
        if restaurant == None:
            return (jsonify({'Error': 'This restaurant does not exist!'}), 404)
        if restaurant['owner'] != jwt_sub:
            return (jsonify({'Error': 'You do not own this restaurant!'}), 401)
		
        # Grab content from request body
        content = request.get_json()
        
        # No content, no change
        if len(content) == 0:
            return (jsonify({"Error": "The request object is missing!"}), 400)

        # Update properties for valid restaurant content
        for prop in content:
            if prop == 'title' and type(content.get(prop)) == str:
                restaurant["title"] = content.get(prop)
            elif prop == 'type' and type(content.get(prop)) == str:
                restaurant["type"] = content.get(prop)
            elif prop == 'location' and type(content.get(prop)) == str:
                restaurant["location"] = content.get(prop)
            else:
                return (jsonify({"Error": "Invalid content!"}), 400)

        client.put(restaurant) # save to database

        # Add id and url to object
        restaurant['id'] = restaurant.key.id
        restaurant['self'] = request.url
		
        # Update current orders
        if restaurant['orders']:
            for single_order in restaurant['orders']:
                order_key = client.key("orders", single_order['id'])
                order = client.get(key=order_key)
                single_order['name'] = order['name']
                single_order['time'] = order['time']
                single_order['table'] = order['table']
                single_order['completed'] = order['completed']
                single_order["self"] = request.url_root + "orders/" + str(single_order['id'])
        
        # Update completed orders
        if restaurant['completed_orders']:
            for corder in restaurant['completed_orders']:
                co_key = client.key("orders", corder['id'])
                order = client.get(key=co_key)
                corder['name'] = order['name']
                corder['time'] = order['time']
                corder['table'] = order['table']
                corder['completed'] = order['completed']
                corder["self"] = request.url_root + "orders/" + str(corder['id'])
        return(jsonify(restaurant), 201)
    
    # Read existing restaurant
    elif request.method == 'GET':
        jwt_sub = verifyJWT()
        if jwt_sub == 'fail':
            return(jsonify({'Error': 'Could not verify JWT!'}), 401)
        elif jwt_sub == 'nojwt':
            return (jsonify({'Error': 'JWT was not given!'}), 401)

        # Look-up in database
        restaurant_key = client.key("restaurants", int(rid))
        restaurant = client.get(key=restaurant_key)

        # Error Handling
        if 'application/json' not in request.accept_mimetypes:
            return (jsonify({"Error": "Specified content type not supported"}), 406)
        if restaurant == None:
            return (jsonify({"Error": "This restaurant does not exist!"}), 404)
        if restaurant['owner'] != jwt_sub:
            return (jsonify({'Error': 'You do not own this restaurant!'}), 401)

        # Add id and url to object
        restaurant['id'] = restaurant.key.id
        restaurant['self'] = request.url
        
        # Update current orders
        if restaurant['orders']:
            for single_order in restaurant['orders']:
                order_key = client.key("orders", single_order['id'])
                order = client.get(key=order_key)
                single_order['name'] = order['name']
                single_order['time'] = order['time']
                single_order['table'] = order['table']
                single_order['completed'] = order['completed']
                single_order['self'] = request.url_root + "orders/" + str(single_order['id'])
        
        # Update completed orders
        if restaurant['completed_orders']:
            for corder in restaurant['completed_orders']:
                co_key = client.key("orders", corder['id'])
                order = client.get(key=co_key)
                corder['name'] = order['name']
                corder['time'] = order['time']
                corder['table'] = order['table']
                corder['completed'] = order['completed']
                corder["self"] = request.url_root + "orders/" + str(corder['id'])
        return(jsonify(restaurant), 201)
    
    # Delete specific restaurant
    elif request.method == 'DELETE':
        jwt_sub = verifyJWT()
        if jwt_sub == 'fail':
            return(jsonify({'Error': 'Could not verify JWT!'}), 401)
        elif jwt_sub == 'nojwt':
            return (jsonify({'Error': 'JWT was not given!'}), 401)

        # Look-up specific restaurant
        restaurant_key = client.key("restaurants", int(rid))
        restaurant = client.get(key=restaurant_key)

        # Error handling
        if restaurant == None:
            return (jsonify({'Error': 'This restaurant does not exist!'}), 404)	
        if restaurant['owner'] != jwt_sub:
            return (jsonify({'Error': 'You do not own this restaurant!'}), 401)
		
        # Delete current orders
        if restaurant['orders']:
            for order in restaurant['orders']:
                gorder_key = client.key("orders", order['id'])
                gorder = client.get(key=gorder_key)
                gorder['rid'] = None
                client.put(gorder)
        
        # Delete completed orders
        if restaurant['completed_orders']:
            for order in restaurant['completed_orders']:
                gorder_key = client.key("orders", order['id'])
                gorder = client.get(key=gorder_key)
                gorder['rid'] = None
                client.put(gorder)
		
        client.delete(restaurant)
        return(jsonify(''), 204)

def verifyJWT():
	# Get JWT from Authorization header
	req = requests.Request()
	jwt_token = request.headers.get('Authorization')
	if jwt_token:
		jwt_token = jwt_token.split(" ")[1]
		# Check to see if JWT is valid
		try:
			jwt_sub = id_token.verify_oauth2_token(jwt_token, req, client_id)['sub']
		except:
			return 'fail'
	else:
		# Return 401 if no JWT is given
		return 'nojwt'
	return jwt_sub

if __name__ == '__main__':
	app.run(host='127.0.0.1', port=8080, debug=True)