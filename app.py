from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from bson.objectid import ObjectId

# Initialize Flask app and configure it
app = Flask(__name__)
app.config["SECRET_KEY"] = "your_secret_key"
app.config["MONGO_URI"] = "mongodb://localhost:27017/business_data"

mongo = PyMongo(app)

@app.route('/')
def home():
    return "API is running!"

def require_token(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        token = auth_header.split(" ")[1] if auth_header else None
        if not token:
            return jsonify({"message": "Missing authentication token"}), 401
        try:
            jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Expired token"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token"}), 401
        return func(*args, **kwargs)
    return decorated

@app.route('/user/register', methods=['POST'])
def register_user():
    user_data = request.json
    username, password = user_data.get("username"), user_data.get("password")

    if mongo.db.users.find_one({"username": username}):
        return jsonify({"message": "Username already taken"}), 409

    mongo.db.users.insert_one({
        "username": username,
        "password": generate_password_hash(password)
    })
    return jsonify({"message": "Registration successful"}), 201

@app.route('/user/login', methods=['POST'])
def login_user():
    credentials = request.json
    username, password = credentials.get("username"), credentials.get("password")
    user = mongo.db.users.find_one({"username": username})

    if not user or not check_password_hash(user["password"], password):
        return jsonify({"message": "Login failed"}), 401

    token = jwt.encode({
        "user": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    }, app.config["SECRET_KEY"], algorithm="HS256")
    return jsonify({"token": token})

@app.route('/businesses', methods=['POST'])
@require_token
def add_business():
    business_data = request.json
    if not all(key in business_data for key in ["name", "address", "type"]):
        return jsonify({"message": "All fields are required"}), 400

    mongo.db.businesses.insert_one({
        "name": business_data["name"],
        "address": business_data["address"],
        "type": business_data["type"],
        "created_at": datetime.datetime.utcnow()
    })
    return jsonify({"message": "Business added"}), 201

@app.route('/businesses', methods=['GET'])
@require_token
def list_businesses():
    business_list = list(mongo.db.businesses.find())
    for item in business_list:
        item["_id"] = str(item["_id"])
    return jsonify(business_list), 200

@app.route('/businesses/<business_id>', methods=['GET'])
@require_token
def get_business(business_id):
    try:
        business = mongo.db.businesses.find_one({"_id": ObjectId(business_id)})
        if not business:
            return jsonify({"message": "Business not found"}), 404
        business["_id"] = str(business["_id"])
        return jsonify(business), 200
    except Exception:
        return jsonify({"message": "Invalid business ID"}), 400

@app.route('/businesses/<business_id>', methods=['PUT'])
@require_token
def modify_business(business_id):
    try:
        update_data = request.json
        result = mongo.db.businesses.update_one(
            {"_id": ObjectId(business_id)},
            {"$set": {
                "name": update_data["name"],
                "address": update_data["address"],
                "type": update_data["type"]
            }}
        )
        if result.matched_count == 0:
            return jsonify({"message": "Business not found"}), 404
        return jsonify({"message": "Business updated"}), 200
    except Exception:
        return jsonify({"message": "Invalid business ID"}), 400

@app.route('/businesses/<business_id>', methods=['DELETE'])
@require_token
def remove_business(business_id):
    try:
        result = mongo.db.businesses.delete_one({"_id": ObjectId(business_id)})
        if result.deleted_count == 0:
            return jsonify({"message": "Business not found"}), 404
        return jsonify({"message": "Business deleted"}), 200
    except Exception:
        return jsonify({"message": "Invalid business ID"}), 400

@app.route('/businesses/search', methods=['GET'])
@require_token
def search_businesses():
    filters = {}
    if "type" in request.args:
        filters["type"] = request.args.get("type")
    if "location" in request.args:
        filters["address"] = {"$regex": request.args.get("location"), "$options": "i"}

    sort_by = request.args.get("sort_by", "created_at")
    limit = int(request.args.get("limit", 100))

    results = list(mongo.db.businesses.find(filters).sort(sort_by).limit(limit))
    for item in results:
        item["_id"] = str(item["_id"])
    return jsonify(results), 200

@app.route('/businesses/aggregate', methods=['GET'])
@require_token
def aggregate_businesses():
    pipeline = [
        {
            "$group": {
                "_id": "$type",
                "count": {"$sum": 1},
                "businesses": {"$push": {"name": "$name", "address": "$address"}}
            }
        },
        {
            "$sort": {"count": -1}
        }
    ]
    results = list(mongo.db.businesses.aggregate(pipeline))
    return jsonify(results), 200

if __name__ == "__main__":
    app.run(debug=True)
