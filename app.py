import os
import sqlite3
import json # NEW: For history.json
from datetime import timedelta, datetime # NEW: For history.json timestamps
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

# Define the model and file paths
GEMINI_MODEL = "gemini-2.5-flash" 
HISTORY_FILE = "history.json" # New: Central storage for all user chat sessions

# --- App and Configuration Setup ---
app = Flask(__name__)

# --- NEW: Define Absolute Database Path ---
INSTANCE_DIR = os.path.join(app.root_path, 'instance')
DB_PATH = os.path.join(INSTANCE_DIR, 'chatbot.db')

# Load keys and credentials from environment
# Using GOOGLE_API_KEY as defined in the README/updated .env
GEMINI_API_KEY = os.environ.get("GOOGLE_API_KEY", "") 

ADMIN_USER = os.environ.get("ADMIN_USER", "default_admin") 
ADMIN_PASS = os.environ.get("ADMIN_PASS", "default_pass")

# Configuration 
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-super-secret-key')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'another-default-jwt-secret')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_TOKEN_LOCATION'] = ['headers']

# Database Configuration (SQLite)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DB_PATH 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
jwt = JWTManager(app)

# NEW: Initialize the Gemini Client
try:
    if not GEMINI_API_KEY:
        raise ValueError("GOOGLE_API_KEY is not set in the environment.") 
    client = genai.Client(api_key=GEMINI_API_KEY)
    print("[DEBUG] Gemini client initialized successfully.")
except Exception as e:
    print(f"[ERROR] Failed to initialize Gemini client: {e}")
    client = None


# --- Chat History Management Functions (NEW) ---

def load_all_chat_data():
    """Loads the entire content of history.json."""
    if not os.path.exists(HISTORY_FILE):
        return {}
    try:
        with open(HISTORY_FILE, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        print(f"[WARNING] {HISTORY_FILE} is empty or corrupted. Initializing new file.")
        return {}

def save_all_chat_data(data):
    """Saves the entire chat data structure to history.json."""
    with open(HISTORY_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def load_chat_sessions(username):
    """Loads all chat sessions for a specific user."""
    all_data = load_all_chat_data()
    return all_data.get(username, [])

def save_chat_session(username, session_id, history):
    """Updates or creates a chat session for a specific user."""
    all_data = load_all_chat_data()
    user_sessions = all_data.get(username, [])
    
    # Simple way to set a title based on the first user message
    title = "New Chat"
    if history and history[0]['role'] == 'user':
        title = history[0]['parts'][0]['text'][:50].strip()
    
    # Find the session to update
    found = False
    for session in user_sessions:
        if session['id'] == session_id:
            session['history'] = history
            session['timestamp'] = datetime.now().isoformat()
            session['title'] = title
            found = True
            break
            
    # If not found, it must be a new session
    if not found:
        user_sessions.append({
            'id': session_id,
            'title': title,
            'timestamp': datetime.now().isoformat(),
            'history': history
        })
    
    all_data[username] = user_sessions
    save_all_chat_data(all_data)
    
    return user_sessions


# --- Database Model (Unchanged) ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# --- Startup and Context Management (Unchanged) ---

@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

@app.before_request
def create_tables():
    if not os.path.exists(INSTANCE_DIR):
        os.makedirs(INSTANCE_DIR, exist_ok=True)
    
    if not os.path.exists(DB_PATH):
        with app.app_context():
            db.create_all()
            
            if User.query.filter_by(username=ADMIN_USER).first() is None:
                admin_user = User(username=ADMIN_USER)
                admin_user.set_password(ADMIN_PASS) 
                db.session.add(admin_user)
                db.session.commit()

# --- Authentication Routes (Unchanged) ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"msg": "Missing username or password"}), 400

    username = data['username']
    password = data['password']
    
    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    
    return jsonify({"msg": "Bad username or password"}), 401

@app.route('/logout')
def logout():
    response = redirect(url_for('login'))
    unset_jwt_cookies(response) 
    flash('You have been logged out.', 'success')
    return response

# --- New/Modified Chat History Routes ---

@app.route('/')
@jwt_required(optional=True)
def home():
    """Renders the main chat interface."""
    return render_template('index.html')

@app.route('/get_chat_sessions', methods=['GET'])
@jwt_required()
def get_chat_sessions():
    """Retrieves the list of chat session titles for the sidebar."""
    username = get_jwt_identity()
    sessions = load_chat_sessions(username)
    
    formatted_sessions = []
    for s in sessions:
        try:
            timestamp_dt = datetime.fromisoformat(s['timestamp'])
            date_str = timestamp_dt.strftime("%b %d, %H:%M")
        except:
            date_str = "Unknown Date"
            
        formatted_sessions.append({
            'id': s['id'],
            'title': s['title'],
            'date': date_str
        })
        
    # Sort by most recent
    formatted_sessions.sort(key=lambda x: datetime.fromisoformat(sessions[[s['id'] for s in sessions].index(x['id'])]['timestamp']), reverse=True)
    
    return jsonify({'sessions': formatted_sessions}), 200

@app.route('/load_session/<session_id>', methods=['GET'])
@jwt_required()
def load_session(session_id):
    """Loads a specific chat session's history."""
    username = get_jwt_identity()
    sessions = load_chat_sessions(username)
    
    for session_data in sessions:
        if session_data['id'] == session_id:
            return jsonify({'history': session_data['history']}), 200
            
    return jsonify({'msg': 'Session not found'}), 404


@app.route('/chat', methods=['POST'])
@jwt_required()
def chat():
    global client
    username = get_jwt_identity()
    data = request.get_json()
    user_message = data.get('message')
    session_id = data.get('sessionId')

    if not user_message or not session_id:
        return jsonify({'msg': 'Missing message or sessionId'}), 400

    try:
        if client is None:
             raise ValueError("Gemini client is not initialized. Check API key.")
        
        # 1. Load Conversation History
        user_sessions = load_chat_sessions(username)
        current_history = []
        is_new_session = True
        
        for session_data in user_sessions:
            if session_data['id'] == session_id:
                current_history = session_data['history']
                is_new_session = False
                break
        
        # 2. Build Contents for API Call
        contents = list(current_history)
        user_part = {"role": "user", "parts": [{"text": user_message}]}
        contents.append(user_part)
        
        # 3. Configuration for the model
        config = genai.types.GenerateContentConfig( 
            system_instruction="You are a helpful and concise AI assistant, running on Flask and powered by Google Gemini.",
        )

        # 4. Call the Gemini API
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=contents, 
            config=config,
        )

        # 5. Process and Update History
        ai_response = response.text
        model_part = {"role": "model", "parts": [{"text": ai_response}]}
        
        # Update the history list
        current_history.append(user_part)
        current_history.append(model_part)
        
        # Save the updated history back to the file
        save_chat_session(username, session_id, current_history)

        return jsonify({'response': ai_response, 'sessionId': session_id, 'isNewSession': is_new_session}), 200

    except APIError as e:
        mock_response = "Gemini API is unavailable or has an error. Please check your key/quota."
        return jsonify({'response': mock_response}), 200 
    
    except ValueError as e:
        mock_response = f"The application is missing a critical configuration: {e}"
        return jsonify({'response': mock_response}), 200 

    except Exception as e:
        return jsonify({'msg': f'An application error occurred: {e}'}), 500

if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc')