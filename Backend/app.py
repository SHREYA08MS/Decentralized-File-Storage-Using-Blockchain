from flask import Flask, request, jsonify
from flask_cors import CORS
import requests

app = Flask(__name__)
CORS(app)

@app.route('/')
def home():
    return "Welcome to the Decentralized File Storage Backend!"

# Pinata API keys
PINATA_API_KEY = "e37cae33f004843ee47e"
PINATA_SECRET_API_KEY = "2d98ae8ea775e4ea2d4c55f2445bf8ab958450ae41249d2aae205a33c5117bcd"

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
    # Replace this with actual logic to fetch uploaded files, e.g., from a database
    files = [
        {"name": "example.png", "ipfs_hash": "QmXoypizjW3WknFiJnKLwHCq1b3ZCsdBEgL9ekzEzkJo1o"}
    ]
    return jsonify(files), 200

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


if __name__ == '__main__':
    app.run(debug=True)
