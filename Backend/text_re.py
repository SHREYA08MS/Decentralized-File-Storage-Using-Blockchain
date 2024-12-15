from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import bcrypt
import requests

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# MongoDB connection setup (replace with your MongoDB URI)
MONGO_URI = "mongodb://localhost:27017/foo"
client = MongoClient(MONGO_URI)
db = client.get_database('foo')  # Replace 'mini' with your database name
users_collection = db.users  # Collection to store user data
files_collection = db.files  # Collection to store file metadata

# Pinata API keys
PINATA_API_KEY = "e37cae33f004843ee47e"
PINATA_SECRET_API_KEY = "2d98ae8ea775e4ea2d4c55f2445bf8ab958450ae41249d2aae205a33c5117bcd"

@app.route('/')
def home():
    return "Welcome to the Decentralized File Storage Backend!"

# User signup route
@app.route('/signup', methods=['POST'])
def signup_user():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    existing_user = users_collection.find_one({"email": email})
    if existing_user:
        return jsonify({"error": "User already exists. Please log in."}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        users_collection.insert_one({"email": email, "password": hashed_password})
    except Exception as e:
        return jsonify({"error": f"Error occurred during signup: {str(e)}"}), 500
    
    return jsonify({"message": "User registered successfully!"}), 201

# User login route
@app.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    user = users_collection.find_one({"email": email})
    if not user:
        return jsonify({"error": "User not found"}), 404

    if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
        return jsonify({"error": "Invalid password"}), 400

    return jsonify({"message": "Login successful"}), 200

# Upload file to Pinata and save metadata to MongoDB
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files or not request.form.get('email'):
        return jsonify({"error": "File and user email are required"}), 400

    file = request.files['file']
    email = request.form['email']

    if file.filename == '':
        return jsonify({"error": "No file selected for uploading"}), 400

    url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
    headers = {
        "pinata_api_key": PINATA_API_KEY,
        "pinata_secret_api_key": PINATA_SECRET_API_KEY
    }
    files = {"file": file.stream}

    try:
        response = requests.post(url, headers=headers, files=files)
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Error occurred while uploading to Pinata: {str(e)}"}), 500

    if response.status_code == 200:
        ipfs_hash = response.json()["IpfsHash"]
        try:
            files_collection.insert_one({
                "email": email,
                "file_name": file.filename,
                "ipfs_hash": ipfs_hash
            })
        except Exception as e:
            return jsonify({"error": f"Error occurred while saving file metadata: {str(e)}"}), 500
        
        return jsonify({"message": "File uploaded successfully!", "ipfs_hash": ipfs_hash}), 200
    else:
        return jsonify({"error": response.json()}), response.status_code

# Fetch uploaded files for a specific user
@app.route('/files', methods=['GET'])
def get_files():
    email = request.args.get('email')
    if not email:
        return jsonify({"error": "User email is required"}), 400

    try:
        user_files = files_collection.find({"email": email})
        files = [{"file_name": file['file_name'], "ipfs_hash": file['ipfs_hash']} for file in user_files]
    except Exception as e:
        return jsonify({"error": f"Error occurred while fetching files: {str(e)}"}), 500

    return jsonify(files), 200

# Delete file from Pinata and MongoDB
@app.route('/delete/<ipfs_hash>', methods=['DELETE'])
def delete_file(ipfs_hash):
    email = request.args.get('email')
    if not email:
        return jsonify({"error": "User email is required"}), 400

    file_entry = files_collection.find_one({"ipfs_hash": ipfs_hash, "email": email})
    if not file_entry:
        return jsonify({"error": "File not found or unauthorized"}), 404

    url = f"https://api.pinata.cloud/pinning/unpin/{ipfs_hash}"
    headers = {
        "pinata_api_key": PINATA_API_KEY,
        "pinata_secret_api_key": PINATA_SECRET_API_KEY
    }

    try:
        response = requests.delete(url, headers=headers)
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Error occurred while deleting from Pinata: {str(e)}"}), 500

    if response.status_code == 200:
        try:
            files_collection.delete_one({"ipfs_hash": ipfs_hash, "email": email})
        except Exception as e:
            return jsonify({"error": f"Error occurred while deleting file metadata: {str(e)}"}), 500
        
        return jsonify({"message": "File deleted successfully!"}), 200
    else:
        return jsonify({"error": response.json()}), response.status_code

# Run the Flask application
if __name__ == '__main__':
    app.run(port=5000, debug=True)
