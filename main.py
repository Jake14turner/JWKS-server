from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import jwt
import json
import rsa
import base64

app = Flask(__name__)

# Load the RSA keys
with open("private.txt", "rb") as f:
    private_key = f.read()

with open("public.txt", "rb") as f:
    public_key = f.read()

# Function to base64url encode a number
def base64url_encode(value):
    """Encodes a value to base64url."""
    return base64.urlsafe_b64encode(value.to_bytes((value.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('=')

# JWK Configuration
JWK_KEYS = {
    "keys": [
        {
            "kty": "RSA",
            "alg": "RS256",  # This should match the signing algorithm
            "kid": "unique-key-id",  # Ensure this matches the 'kid' in the JWT header
            "use": "sig",
            "n": base64url_encode(rsa.PublicKey.load_pkcs1(public_key).n),  # Base64url-encoded modulus
            "e": base64url_encode(65537)  # Base64url-encoded exponent
        }
    ]
}

@app.route('/auth', methods=['POST'])
def auth():
    username = request.json.get('username')
    password = request.json.get('password')
    expired = request.args.get('expired')  # Check for 'expired' query parameter

    if username == 'userABC' and password == 'password123':
        # Determine expiration time based on the 'expired' parameter
        if expired == 'true':
            # Set expiration time to the past (e.g., 10 minutes ago)
            expiration = datetime.utcnow() - timedelta(minutes=10)
        else:
            # Set expiration to 10 minutes in the future
            expiration = datetime.utcnow() + timedelta(minutes=10)

        headers = {"kid": "unique-key-id"}  # Set your key ID here
        token = jwt.encode({'exp': expiration}, private_key, algorithm='RS256', headers=headers)  # Ensure RS256 is used
        return jsonify(token=token), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    return jsonify(JWK_KEYS), 200

@app.route('/secure-endpoint', methods=['GET'])
def secure_endpoint():
    token = request.headers.get('Authorization').split()[1]  # Assuming "Bearer <token>"
    try:
        payload = jwt.decode(token, public_key, algorithms=['RS256'])
        return jsonify({"message": "Token is valid", "payload": payload}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token has expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401

if __name__ == '__main__':
    app.run(port=8080)
