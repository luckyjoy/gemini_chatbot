import os
import sqlite3
# Removed 'requests' and 'json' as the 'google-genai' SDK will be used.
from datetime import timedelta
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from flask_jwt_extended import (
    create_access_token, jwt_required, JWTManager, get_jwt_identity, unset_jwt_cookies
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# NEW: Import the Google GenAI SDK
from google import genai
from google.genai.errors import APIError

# Load environment variables from .env file
load_dotenv()

# Define the model to use and the API key environment variable name
GEMINI_MODEL = "gemini-2.5-flash" # Use a modern and efficient Gemini model
# Note: The 'google-genai' SDK automatically looks for the 'GEMINI_API_KEY'
# in the environment, but we'll manually check and set the key if needed.
# We will use the existing OPENAI_API_KEY value from the .env for simplicity,
# but rename the variable locally to reflect the actual key used.

# --- App and Configuration Setup ---
app = Flask(__name__)

# --- NEW: Define Absolute Database Path ---
# Define the path to the 'instance' directory
INSTANCE_DIR = os.path.join(app.root_path, 'instance')
# Define the absolute path for the SQLite database file
DB_PATH = os.path.join(INSTANCE_DIR, 'chatbot.db')

# Load keys and credentials from environment
# Load the key using the correct environment variable name: GOOGLE_API_KEY
GEMINI_API_KEY = os.environ.get("GOOGLE_API_KEY", "") 

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

# NEW: Initialize the Gemini Client
try:
    if not GEMINI_API_KEY:
        raise ValueError("GEMINI_API_KEY (from OPENAI_API_KEY in .env) is not set.")
    # Initialize the client with the explicitly defined API key
    client = genai.Client(api_key=GEMINI_API_KEY)
    print("[DEBUG] Gemini client initialized successfully.")
except Exception as e:
    print(f"[ERROR] Failed to initialize Gemini client: {e}")
    # Set client to None, the chat function will handle the error
    client = None


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
    return render_template('index.html')

@app.route('/chat', methods=['POST'])
@jwt_required()
def chat():
    global client
    current_user_id = get_jwt_identity()
    data = request.get_json()
    user_message = data.get('message')

    if not user_message:
        return jsonify({'msg': 'No message provided'}), 400

    print(f"[DEBUG] User {current_user_id} sent: {user_message}")

    try:
        if client is None:
             raise ValueError("Gemini client is not initialized. Check API key.")
        
        # 1. Configuration for the model
        config = genai.types.GenerateContentConfig(
            # System instruction to define the AI's persona
            system_instruction="You are a helpful and concise AI assistant, running on Flask and powered by Google Gemini.",
            # safety_settings and other configs can be added here
        )

        # 2. Call the Gemini API
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=user_message, # Simple text input
            config=config,
        )

        # 3. Process the Response
        ai_response = response.text

        print(f"[DEBUG] AI responded.")
        return jsonify({'response': ai_response}), 200

    except APIError as e:
        print(f"[ERROR] Gemini API Error: {e}")
        # Provide a mock response for API errors (Authentication, Rate Limit, etc.)
        mock_response = (
            "It looks like the Gemini API is currently unavailable or has encountered an error. "
            f"I am currently unable to answer your query. Error details: {e}"
        )
        # Return 200 so the client displays the error message gracefully as an AI response
        return jsonify({'response': mock_response}), 200 
    
    except ValueError as e:
        print(f"[ERROR] Chat failed due to configuration: {e}")
        # Specific error for missing API key/config
        mock_response = (
            f"The application is missing a critical configuration: {e}"
        )
        return jsonify({'response': mock_response}), 200 

    except Exception as e:
        print(f"[ERROR] Application failed: {e}")
        # Return a JSON error message for application failures
        return jsonify({'msg': f'An application error occurred: {e}'}), 500

if __name__ == '__main__':
    # Use the 'adhoc' SSL context for running locally over HTTPS
    app.run(debug=True, ssl_context='adhoc')