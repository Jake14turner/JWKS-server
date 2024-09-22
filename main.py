import datetime
import jwt
from flask import Flask, request, jsonify, render_template_string
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

#start flask for ui
app = Flask(__name__)

#store RSA keys and metadata
keys = {}
count = 0  #key ID counter

#HTML template for the web interface
html_form = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>JWT Handler</title>
</head>
<body>
    <h1>JWT Web Interface</h1>

    <div style="float: left; width: 45%;">
        <h2>Submit JWT for Decoding</h2>
        <form action="/receive-token" method="post">
            <label for="token">JWT:</label>
            <input type="text" id="token" name="token" required>
            <button type="submit">Submit Token</button>
        </form>
        {% if decoded_message %}
            <h3>Decoded Payload</h3>
            <pre>{{ decoded_message }}</pre>
        {% elif error_message %}
            <h3>Error</h3>
            <p>{{ error_message }}</p>
        {% endif %}
    </div>

    <div style="float: right; width: 45%;">
        <h2>Generate JWT</h2>
        <form action="/auth" method="post">
            <label for="name">Name:</label>
            <input type="text" id="name" name="name" required><br><br>
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required><br><br>
            <button type="submit">Generate Token</button>
        </form>
        {% if generated_token %}
            <h3>Generated JWT</h3>
            <pre>{{ generated_token }}</pre>
        {% endif %}
    </div>
    
    <div style="clear: both; margin-top: 20px;">
        <h2>Public JWKS</h2>
        <a href="/jwks" target="_blank">
            <button>Go to JWKS Endpoint</button>
        </a>
    </div>
</body>
</html>
"""

#generate keypair using rsa from cryptography library
def generate_rsa_keypair(kid, expiry_minutes=30):
    #generate private key from rsa and store it in private_key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    #generate the public key, it will be derived from the private key, private.public()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    #store the keys together along with the exiry in keys. Kid will be updated for each key
    keys[kid] = {
        'private_key': private_key,
        'public_key': public_key,
        'expiry': datetime.datetime.utcnow() + datetime.timedelta(minutes=expiry_minutes)
    }
    return private_key, public_key

#render the ui
@app.route('/')
def index():
    return render_template_string(html_form)

#create a section on the ui where the user can input a token to verify it and view the info
@app.route('/receive-token', methods=['POST'])
def receive_token():
    #user can input a token into token
    token = request.form.get('token')
    #if they dont enter anything tell them its missing
    if not token:
        return render_template_string(html_form, error_message="Token is missing")

    try:
    #loop through the key array to check each one against the entered token. If the entered token is the correct one, display hat ones contentes
        decoded_message = None
        for key_data in keys.values():
            try:
                decoded_message = jwt.decode(token, key_data['public_key'], algorithms=["RS256"])
                break
            #if its an invalid key, throw error
            except jwt.ExpiredSignatureError:
                continue
            #if the token is expired throw error
            except jwt.InvalidTokenError:
                continue

            #if the decoded message made it into the variable, then display it.
        if decoded_message:
            return render_template_string(html_form, decoded_message=decoded_message)
        else:
            return render_template_string(html_form, error_message="Invalid or expired token")

    except jwt.InvalidTokenError:
        return render_template_string(html_form, error_message="Invalid token")

@app.route('/auth', methods=['POST'])
#generate token method
def generate_token():
    #get a username and password (just as example data that should be stored and retrieved when a valid token is given)
    name = request.form.get('name')
    password = request.form.get('password')
    #count variable for the kid
    global count
    count += 1

    #ensure both text fields are entered
    if not name or not password:
        return render_template_string(html_form, error_message="Name and Password are required")



    expired = request.args.get('expired') == 'true'

    if expired:
     
        expired_key = next((key_data for key_data in keys.values() if key_data['expiry'] < datetime.datetime.utcnow()), None)

        if not expired_key:
            return render_template_string(html_form, error_message="No expired keys available")

        private_key = expired_key['private_key']
        kid = list(keys.keys())[list(keys.values()).index(expired_key)]
        exp_time = datetime.datetime.utcnow() - datetime.timedelta(minutes=30)  # already expired

    else:
    
    #set the kid = count
        kid = str(count)
    #pass the current kid and desired expiration time for keys into the generate_rsa_keypair function and get the private and public keys from it
        private_key, public_key = generate_rsa_keypair(kid, expiry_minutes=30)
        exp_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)

    #initaite the header value
    header = {
        "kid": kid,
        "alg": "RS256"
    }

    #initate the payload values
    payload = {
        "name": name,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=1)
    }
    

    #encode the payload and header
    token = jwt.encode(payload, private_key, algorithm="RS256", headers=header)
    
    return render_template_string(html_form, generated_token=token)

@app.route('/jwks', methods=['GET'])
#method to get jwks public keys
def jwks():
    current_time = datetime.datetime.utcnow()
    jwks_keys = []
    #loop through all kid's in keys so we hit each key we have generated. Only print the information that is not expired
    for kid, key_data in keys.items():
        if key_data['expiry'] > current_time:
            jwks_keys.append({
                "kty": "RSA",
                "kid": kid,
                "use": "sig",
                "alg": "RS256",
                "n": key_data['public_key'].decode(), 
                "e": "AQAB"  
            })


    return jsonify({"keys": jwks_keys})

if __name__ == '__main__':
    app.run(port=8080, debug=True)
