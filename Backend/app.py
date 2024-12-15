from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
from pymongo import MongoClient
import bcrypt

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# MongoDB connection setup (replace with your MongoDB URI)
MONGO_URI = "mongodb://localhost:27017/foo"

client = MongoClient(MONGO_URI)
db = client.get_database()  # Get your database name
users_collection = db.users  # Define a collection to store users

# Pinata API keys (Hardcoded)
PINATA_API_KEY = "e37cae33f004843ee47e"
PINATA_SECRET_API_KEY = "2d98ae8ea775e4ea2d4c55f2445bf8ab958450ae41249d2aae205a33c5117bcd"

@app.route('/')
def home():
    return "Welcome to the Decentralized File Storage Backend!"

# Upload file to Pinata
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected for uploading"}), 400

    url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
    headers = {
        "pinata_api_key": PINATA_API_KEY,
        "pinata_secret_api_key": PINATA_SECRET_API_KEY
    }
    files = {"file": file.stream}

    response = requests.post(url, headers=headers, files=files)
    if response.status_code == 200:
        ipfs_hash = response.json()["IpfsHash"]
        return jsonify({"message": "File uploaded successfully!", "ipfs_hash": ipfs_hash}), 200
    else:
        return jsonify({"error": response.json()}), response.status_code

# Fetch uploaded files (mocked for simplicity)
@app.route('/files', methods=['GET'])
def get_files():
    try:
        # Fetch files from the MongoDB collection 'foo'
        files = list(db.foo.find({}, {"_id": 0, "name": 1, "ipfs_hash": 1}))
        return jsonify(files), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Delete file from Pinata
@app.route('/delete/<ipfs_hash>', methods=['DELETE'])
def delete_file(ipfs_hash):
    url = f"https://api.pinata.cloud/pinning/unpin/{ipfs_hash}"
    headers = {
        "pinata_api_key": PINATA_API_KEY,
        "pinata_secret_api_key": PINATA_SECRET_API_KEY
    }

    response = requests.delete(url, headers=headers)
    if response.status_code == 200:
        return jsonify({"message": "File deleted successfully!"}), 200
    else:
        return jsonify({"error": response.json()}), response.status_code

# User signup route
@app.route('/signup', methods=['POST'])
def signup_user():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    # Check if the email already exists
    existing_user = users_collection.find_one({"email": email})
    if existing_user:
        return jsonify({"error": "User already exists. Please log in."}), 400

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Store user in the MongoDB collection
    users_collection.insert_one({
        "email": email,
        "password": hashed_password
    })

    return jsonify({"message": "User registered successfully!"}), 201

# User login route
@app.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    # Check if user exists
    user = users_collection.find_one({"email": email})
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Check password
    if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        return jsonify({"error": "Invalid password"}), 400

    return jsonify({"message": "Login successful"}), 200

if __name__ == '__main__':
    app.run(debug=True)
