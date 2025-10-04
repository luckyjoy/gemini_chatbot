import os
import sqlite3
import requests # New: Import requests for manual API call
import json     # New: Import json for handling JSON payloads
from datetime import timedelta
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_jwt_extended import (
    create_access_token, jwt_required, JWTManager, get_jwt_identity, unset_jwt_cookies
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Define the model and API endpoint to use
OPENAI_MODEL = "gpt-3.5-turbo"
OPENAI_API_URL = "https://api.openai.com/v1/chat/completions" # OpenAI Chat API endpoint

# --- App and Configuration Setup ---
app = Flask(__name__)

# --- NEW: Define Absolute Database Path ---
# Define the path to the 'instance' directory
INSTANCE_DIR = os.path.join(app.root_path, 'instance')
# Define the absolute path for the SQLite database file
DB_PATH = os.path.join(INSTANCE_DIR, 'chatbot.db')

# Load keys and credentials from environment
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
ADMIN_USER = os.environ.get("ADMIN_USER", "default_admin") # Load from .env
ADMIN_PASS = os.environ.get("ADMIN_PASS", "default_pass") # Load from .env

# Configuration - Using values loaded from .env
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-super-secret-key') # Used for sessions, etc.
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'another-default-jwt-secret') # Used for signing JWTs
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_TOKEN_LOCATION'] = ['headers'] # Ensure JWT is only read from headers

# Database Configuration (SQLite)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DB_PATH 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
jwt = JWTManager(app)

# --- Database Model ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# --- Startup and Context Management ---

@app.teardown_appcontext
def shutdown_session(exception=None):
    """Closes the database session at the end of the request or application context."""
    db.session.remove()

# --- Security Enhancement: Add common security headers ---
@app.after_request
def add_security_headers(response):
    """Adds common security headers to all responses."""
    # Prevents clickjacking attacks
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # Prevents browsers from trying to guess content type
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # Enables XSS filtering in older browsers
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Forces connection over HTTPS for future requests (max-age is 1 year)
    # NOTE: 'adhoc' SSL is not fully secure, but we enforce this header as best practice.
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

# Initialize database and default user if necessary
@app.before_request
def create_tables():
    # Ensure the 'instance' directory exists
    if not os.path.exists(INSTANCE_DIR):
        os.makedirs(INSTANCE_DIR, exist_ok=True)
        print("[DEBUG] Created 'instance' directory.")
    
    # Check if the database file already exists using the absolute path
    if not os.path.exists(DB_PATH):
        with app.app_context():
            db.create_all()
            
            # --- UPDATED: Use ENV variables for Admin Creation ---
            if User.query.filter_by(username=ADMIN_USER).first() is None:
                admin_user = User(username=ADMIN_USER)
                admin_user.set_password(ADMIN_PASS) 
                db.session.add(admin_user)
                db.session.commit()
                print(f"[DEBUG] Created default user from ENV: {ADMIN_USER}/{ADMIN_PASS}")
            # --- END UPDATED ---

# --- Authentication Routes ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    # POST request handling
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"msg": "Missing username or password"}), 400

    username = data['username']
    password = data['password']
    
    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        # Create the access token using the user's username as the identity
        access_token = create_access_token(identity=username)
        print(f"[DEBUG] Login SUCCESS for user: {username}. Returning JWT.")
        return jsonify(access_token=access_token), 200
    
    print(f"[DEBUG] Login FAILED for user: {username}")
    return jsonify({"msg": "Bad username or password"}), 401

@app.route('/logout')
def logout():
    # The actual token removal happens client-side (removal from localStorage)
    # We simply redirect to the login page
    response = redirect(url_for('login'))
    # Optionally, clear any auth cookies if they were being used
    unset_jwt_cookies(response) 
    flash('You have been logged out.', 'success')
    return response

# --- Main Application Routes ---

@app.route('/')
def home():
    # The client-side (index.html) already handles the redirect if a token is missing.
    # However, to ensure the user always hits /login first after a server restart 
    # and to simplify the client-side logic slightly:
    
    # Check if an Authorization header is present (only needed if we are checking JWT on the '/' route, 
    # but the client-side check in index.html is cleaner).
    
    # Simpler approach: If the user is unauthenticated, the client-side JS in index.html
    # will call logoutAndRedirect(), which redirects to /logout, which then redirects to /login.
    # To prevent this indirect loop, we will rely only on the client-side logic in index.html
    # and the explicit server-side check on the /chat route.
    
    # For a clean startup, we can just ensure that if the app is accessed without an explicit
    # path, it redirects to the login page, unless the client-side token check passes.
    # But since the client-side in index.html already handles redirecting to logout/login
    # if no token is found, we just render index.html here.
    return render_template('index.html')

@app.route('/chat', methods=['POST'])
@jwt_required()
def chat():
    # Get the user's identity (username) from the JWT
    current_user_id = get_jwt_identity()
    data = request.get_json()
    user_message = data.get('message')

    if not user_message:
        return jsonify({'msg': 'No message provided'}), 400

    print(f"[DEBUG] User {current_user_id} sent: {user_message}")

    try:
        if not OPENAI_API_KEY:
             raise ValueError("OPENAI_API_KEY environment variable is not set. Chat disabled.")
        
        # 1. Define Request Headers
        headers = {
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json",
        }

        # 2. Define Request Payload
        payload = {
            "model": OPENAI_MODEL,
            "messages": [
                {"role": "system", "content": "You are a helpful and concise AI assistant, running on Flask."},
                {"role": "user", "content": user_message}
            ],
            "max_tokens": 150, # Optional: Limit response length
            "temperature": 0.7
        }

        # 3. Make the Manual HTTP POST Request
        response = requests.post(
            OPENAI_API_URL, 
            headers=headers, 
            data=json.dumps(payload)
        )
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)

        # 4. Process the Response
        api_data = response.json()
        
        # Extract the response text safely
        ai_response = api_data['choices'][0]['message']['content']

        print(f"[DEBUG] AI responded.")
        return jsonify({'response': ai_response}), 200

    except requests.exceptions.HTTPError as errh:
        error_details = errh.response.json()
        print(f"[ERROR] HTTP Error: {error_details}")
        
        status_code = errh.response.status_code
        
        if status_code in [401, 403, 429]:
            # Provide a mock response for common API errors (Authentication, Permissions, Rate Limit, Quota)
            mock_response = (
                "It looks like the OpenAI API is currently unavailable or has exceeded its quota (HTTP "
                f"{status_code}). I am currently unable to answer your query. Please check your "
                "API key, plan, and billing details."
            )
            # Return 200 so the client displays the error message gracefully as an AI response
            return jsonify({'response': mock_response}), 200 
        
        # For other HTTP errors, return the raw error message and status code
        return jsonify({'msg': f'OpenAI API Error (HTTP {errh.response.status_code}): {error_details.get("error", {}).get("message", "Unknown error")}'}), errh.response.status_code
    except Exception as e:
        print(f"[ERROR] Chat failed: {e}")
        # Return a JSON error message for application failures
        return jsonify({'msg': f'An application error occurred: {e}'}), 500

if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc')
