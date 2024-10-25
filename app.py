from flask import Flask, redirect, url_for, render_template, request, jsonify
from pymongo import MongoClient
import jwt
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime,timedelta
from bson import ObjectId
import os 
from werkzeug.utils import secure_filename
from flask_cors import CORS
from os.path import join,dirname
from dotenv import load_dotenv

dotenv_path = join(dirname(__file__),'.env')
load_dotenv(dotenv_path)

#Env
MONGODB_URI = os.environ.get('MONGODB_URI')
DBNAME = os.environ.get('DBNAME')
SECRET_KEY = os.environ.get('SECRET_KEY')

client = MongoClient(
    MONGODB_URI)
db = client[DBNAME]

app = Flask(__name__)

app.config['SECRET_KEY'] = SECRET_KEY
app.config['UPLOAD_FOLDERS'] = {
    'user': 'static/user/',
    'recipe': 'static/recipe/'
}
CORS(app)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_file(file, upload_folder):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename) 
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        name, ext = os.path.splitext(filename)
        filename = f"{name}_{timestamp}{ext}"
        file_path = os.path.join(upload_folder, filename)  
        file.save(file_path)  
        return filename  
    return None

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", None)
        if token:
            token = token.split(" ")[1]
        if not token:
            return {"success": False,"message": "Authentication token is missing!", "error": "Unauthorized"}, 401
        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            print(data)
            current_user = db.users.find_one({'_id': ObjectId(data['user_id'])})
            if not current_user:
                return {"success": False,"message": "Invalid or inactive user!", "error": "Unauthorized"}, 401
        except jwt.ExpiredSignatureError:
            return {"success": False,"message": "Token has expired!", "error": "Unauthorized"}, 401
        except jwt.InvalidTokenError:
            return {"success": False,"message": "Invalid token!", "error": "Unauthorized"}, 401
        except Exception as e:
            return {"success": False,"message": "An error occurred", "error": str(e)}, 500

        return f(current_user, *args, **kwargs)
    return decorated


# Register
@app.route('/api/register', methods=['POST'])
def register():
    name = request.form['name']
    username = request.form['username']
    password = request.form['password']
    password_hash = generate_password_hash(password)
    user = db.users.find_one({'username': username})
    if user:
        return jsonify({"success": False,"message": "User already exist"}), 401
    doc = {
        'name': name,
        'username': username,
        'password': password_hash,
        'profile_pic': 'default.jpg'
    }
    db.users.insert_one(doc)
    return jsonify({"success": True,'message': 'User registered successfully!'}),200


# Login
@app.route('/api/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = db.users.find_one({'username': username})
    print(check_password_hash(user['password'],password))
    
    if user and check_password_hash(user['password'],password):
        payload = {
        'user_id': str(user['_id']),
        'exp': datetime.utcnow() + timedelta(hours=24) 
        }
        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({
            "success": True,
            'message':'Logged in successfully',
            'token':token
        }),200
    else:
        return jsonify({"success": False,"message": "User not found"}), 401 
    
# Add recipe 
@app.route('/api/add_recipe', methods=['POST'])
@token_required 
def add_recipe(current_user):
    recipe_name = request.form['recipe_name']
    category = request.form['category']
    serving = request.form['serving']
    duration = request.form['duration']
    desc = request.form['desc']
    ingredients = request.form['ingredients']
    directions = request.form['directions']
    recipe_pic = request.files.get('recipe_pic') 
    
    if recipe_pic and allowed_file(recipe_pic.filename):
        filename = save_file(recipe_pic, app.config['UPLOAD_FOLDERS']['recipe'])   
    else:
        filename = None  
    doc = {
        'user': current_user['username'],
        'recipe_name': recipe_name,
        'category': category,
        'serving':serving,
        'duration':duration,
        'desc':desc,
        'ingredients': ingredients,
        'directions' :directions,
        'recipe_pic': filename,
        'date_created':datetime.now().strftime('%Y-%m-%d')
    }
    db.recipes.insert_one(doc)
    return jsonify({"success": True,'message': 'Recipe created successfully!'}),200

# All Recipes 
@app.route('/api/recipes',methods=['GET'])
@token_required 
def get(current_user):
    category = request.args.get('category')
    user = request.args.get('user') 
    query = {}
    if category:
        query['category'] = category
    
    if user:
        query['user'] = user
        
    recipes = list(db.recipes.find(query))    

    recipes_list = []
    for recipe in recipes:
        recipe['_id'] = str(recipe['_id'])  
        recipes_list.append(recipe)
    return jsonify({"success": True,'message':'Recipes retrieved successfully','recipes': recipes_list}),200

#Recipes by ID
@app.route('/api/recipes/<recipe_id>',methods=['GET'])
@token_required
def get_recipes_by_id(current_user,recipe_id):
    object_id = ObjectId(recipe_id)
    recipe = db.recipes.find_one({'_id': object_id})
    recipe['_id'] = str(recipe['_id'])
    return jsonify({"success": True,'message': 'Recipes retrieved successfully', 'recipe': recipe})

#Update Recipe
@app.route('/api/update_recipe/<recipe_id>', methods=['PUT'])
@token_required
def update_recipe(current_user, recipe_id):
    recipe = db.recipes.find_one({'_id': ObjectId(recipe_id)})
    recipe_name = request.form['recipe_name']
    category = request.form['category']
    serving = request.form['serving']
    duration = request.form['duration']
    desc = request.form['desc']
    ingredients = request.form['ingredients']
    directions = request.form['directions']

    recipe_pic = request.files.get('recipe_pic') 
    
    if recipe_pic and allowed_file(recipe_pic.filename):
        # Remove the old file if it exists
        old_file_path = os.path.join(app.config['UPLOAD_FOLDERS']['recipe'], recipe['recipe_pic'])
        if recipe['recipe_pic'] and os.path.exists(old_file_path):
            os.remove(old_file_path)
        filename = save_file(recipe_pic, app.config['UPLOAD_FOLDERS']['recipe'])   
    else:
        filename = recipe['recipe_pic']  
    update_doc = {
        'recipe_name': recipe_name,
        'category': category,
        'serving':serving,
        'duration':duration,
        'desc':desc,
        'ingredients': ingredients,
        'directions' :directions,
        'recipe_pic': filename
    }
    db.recipes.update_one({'_id': ObjectId(recipe_id)}, {'$set': update_doc})
    return jsonify({"success": True,'message': 'Recipe updated successfully!'})


@app.route('/api/delete_recipe/<recipe_id>',methods=['DELETE'])
@token_required
def delete_recipe(current_user,recipe_id):
    object_id = ObjectId(recipe_id)
    recipe = db.recipes.find_one({'_id': object_id})
    if recipe:
        filename = recipe['recipe_pic']
        file_path = os.path.join(app.config['UPLOAD_FOLDERS']['recipe'], filename)
        if os.path.exists(file_path):
             os.remove(file_path)    
    db.recipes.delete_one({'_id': object_id})
    return jsonify({"success": True,'message': 'Recipe deleted successfully!'})


#Update Profile
@app.route('/api/update_profile', methods=['PUT'])
@token_required
def update_profile(current_user):
    name = request.form['name']
    bio = request.form['bio']
    profile_pic = request.files.get('profile_pic')
    
    if profile_pic and allowed_file(profile_pic.filename):
        # Remove the old file if it exists
        old_file_path = os.path.join(app.config['UPLOAD_FOLDERS']['user'], current_user['profile_pic'])
        if current_user.get('profile_pic') and current_user['profile_pic'] != 'default.jpg' and os.path.exists(old_file_path):
            os.remove(old_file_path)
        filename = save_file(profile_pic, app.config['UPLOAD_FOLDERS']['user'])   
    else:
        filename = current_user['profile_pic']  
    update_doc = {
        'name':name,
        'bio':bio,
        'profile_pic': filename
    }
    db.users.update_one({'_id': ObjectId(current_user['_id'])}, {'$set': update_doc})
    return jsonify({"success": True,'message': 'Profile updated successfully!'})

# Profile by ID
@app.route('/api/user/<user_id>',methods=['GET'])
@token_required
def get_user_by_id(current_user,user_id):
    user = db.users.find_one({'_id': ObjectId(user_id)})
    user['_id'] = str(user['_id'])
    return jsonify({"success": True,'message': 'Profile retrieved successfully', 'user': user})

# Learn Public API
@app.route('/public',methods=['GET','POST'])
def recipes():
    return jsonify('You can access this')

# Learn Private API
@app.route('/private')
@token_required
def auth(current_user):
   return jsonify({'message': 'JWT is verified. Welcome to your private page!'})



if __name__ == '__main__':
    #DEBUG is SET to TRUE. CHANGE FOR PROD
    app.run(port=5000,debug=True)