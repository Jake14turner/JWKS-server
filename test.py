import unittest
import jwt
from another import app, keys  # Import your Flask app and keys dictionary
from flask import json

class JWTTestCase(unittest.TestCase):

    def setUp(self):
        """Set up the test client before each test."""
        self.app = app.test_client()
        self.app.testing = True

    def tearDown(self):
        """Clean up any data after each test."""
        keys.clear()  # Clear the keys after each test to avoid cross-contamination

    def test_generate_valid_token(self):
        """Test that a valid token is generated and returned."""
        response = self.app.post('/auth', data=dict(name="testuser", password="password"))
        self.assertEqual(response.status_code, 200)
        data = response.data.decode('utf-8')
        self.assertIn('Generated JWT', data)

    def test_generate_expired_token(self):
        # Set up an expired key
        self.app.post('/auth?expired=true', data={'name': 'test', 'password': 'password'})
        response = self.app.post('/auth?expired=true', data={'name': 'test', 'password': 'password'})
    
    # Check the response for the token
        data = response.get_data(as_text=True)
        self.assertIn('Generated JWT', data)

    def test_generate_expired_token(self):
        """Test that an expired token is generated when requested."""
        response = self.app.post('/auth?expired=true', data=dict(name="testuser", password="password"))
        self.assertEqual(response.status_code, 200)
        data = response.data.decode('utf-8')
        self.assertIn('Generated JWT', data)

        # Now test if the token is indeed expired
        token = self.extract_token_from_html(data)
        with self.assertRaises(jwt.ExpiredSignatureError):
            self.decode_token(token)

    def test_decode_valid_token(self):
        """Test that a valid token can be decoded."""
        # Generate a valid token
        response = self.app.post('/auth', data=dict(name="testuser", password="password"))
        data = response.data.decode('utf-8')
        token = self.extract_token_from_html(data)

        # Decode the token
        response = self.app.post('/receive-token', data=dict(token=token))
        self.assertEqual(response.status_code, 200)
        self.assertIn('Decoded Payload', response.data.decode('utf-8'))

    def test_decode_expired_token(self):
        """Test that an expired token is correctly handled."""
        # Generate an expired token
        response = self.app.post('/auth?expired=true', data=dict(name="testuser", password="password"))
        data = response.data.decode('utf-8')
        token = self.extract_token_from_html(data)

        # Try decoding the expired token
        response = self.app.post('/receive-token', data=dict(token=token))
        self.assertEqual(response.status_code, 200)
        self.assertIn('Invalid or expired token', response.data.decode('utf-8'))

    def extract_token_from_html(self, html_data):
        """Helper function to extract the token from the HTML page."""
        token_start = html_data.find('<pre>') + 5
        token_end = html_data.find('</pre>')
        return html_data[token_start:token_end]

    def decode_token(self, token):
        """Helper function to decode the token using the keys dictionary."""
        for key_data in keys.values():
            return jwt.decode(token, key_data['public_key'], algorithms=["RS256"])

if __name__ == '__main__':
    unittest.main()
