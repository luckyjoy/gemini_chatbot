import os
import time
import requests
from datetime import datetime, timedelta, timezone
from functools import wraps
# NOTE: Added 'redirect' import for the root route
from flask import Flask, jsonify, request, render_template, redirect 
from jwt import encode, decode, ExpiredSignatureError, InvalidTokenError
from dotenv import load_dotenv

# --- Load environment variables ---
load_dotenv()

ADMIN_USER = os.getenv("ADMIN_USER")
ADMIN_PASS = os.getenv("ADMIN_PASS")
GEMINI_API_KEY = os.getenv("GOOGLE_API_KEY")
JWT_SECRET = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = "HS256"
JWT_EXP_DELTA_MINUTES = 60

if not all([ADMIN_USER, ADMIN_PASS, GEMINI_API_KEY, JWT_SECRET]):
    # This should be checked in your setup
    print("WARNING: Missing ADMIN_USER, ADMIN_PASS, GEMINI_API_KEY, or JWT_SECRET environment variables.")

GEMINI_API_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-2.5-flash-preview-05-20:generateContent"
)

# CRITICAL FIX: Explicitly set template folder and initialize Flask
app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), 'templates'))
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "supersecretkey")

# --- In-memory user sessions ---
# Key: user_id, Value: {"history": [...], "title": "..."}
user_sessions = {}

# ================= JWT HELPERS =================
def generate_jwt(user_id):
    now = datetime.now(timezone.utc)
    payload = {"user_id": user_id, "iat": now, "exp": now + timedelta(minutes=JWT_EXP_DELTA_MINUTES)}
    return encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def get_user_id_from_token():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return None
    try:
        token = auth_header.split(" ")[1]
        payload = decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload.get('user_id')
    except (ExpiredSignatureError, InvalidTokenError, IndexError):
        return None

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user_id = get_user_id_from_token()
        if not user_id:
            # Return JSON for API calls
            if request.path.startswith('/api/'):
                return jsonify({"msg": "Authentication required"}), 401
            # For non-API routes (like /chat), this logic is now handled client-side.
            return redirect("/login")
        return f(user_id, *args, **kwargs)
    return decorated

# ================= GEMINI API CALL (Simplified for brevity) =================
def sanitize_history(history):
    sanitized = []
    expecting_role = 'user'
    for message in history:
        role = message.get('role')
        if role == expecting_role:
            sanitized.append(message)
            expecting_role = 'model' if role == 'user' else 'user'
    if sanitized and sanitized[-1]['role'] == 'user':
        sanitized.pop()
    if sanitized and sanitized[0]['role'] == 'model':
        sanitized.pop(0)
    return sanitized

def call_gemini_api(history, new_user_message):
    full_history = sanitize_history(history)
    full_history.append({"role": "user", "parts": [{"text": new_user_message}]})
    payload = {
        "contents": full_history,
        "tools": [{"google_search": {} }],
        "system_instruction": {
            "parts": [{"text": "You are a professional Python and C code assistant. Respond clearly and use Markdown formatting for code blocks and explanations. If asked to write code, provide runnable, well-explained code."}]
        }
    }
    api_key = GEMINI_API_KEY
    api_url = f"{GEMINI_API_URL}?key={api_key}"
    max_retries = 3
    base_delay = 1
    
    for i in range(max_retries):
        try:
            response = requests.post(api_url, json=payload, timeout=30)
            response.raise_for_status()
            result = response.json()
            return result.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', 'No response generated.')
        except requests.exceptions.RequestException as e:
            if response is not None and response.status_code == 400:
                return f"Error: Gemini API failed (400). Response: {response.text[:100]}"
            if i == max_retries - 1:
                return f"Error: Failed to connect to Gemini API after {max_retries} attempts."
            time.sleep(base_delay * (2 ** i))

    return "Error: Failed to connect to Gemini API."

# ================= ROUTES =================

@app.route("/")
def index():
    return redirect("/login")

@app.route("/login", methods=["GET"])
def login():
    return render_template("login.html")

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username == ADMIN_USER and password == ADMIN_PASS:
        token = generate_jwt(username)
        return jsonify({"token": token}), 200
    return jsonify({"msg": "Invalid username or password"}), 401


@app.route("/chat")
# --- FIX: Removed @token_required decorator ---
def chat():
    # The client-side JS in chat.html will check localStorage for the token
    return render_template("chat.html")

@app.route("/api/chat", methods=["POST"])
@token_required
def api_chat(user_id):
    data = request.get_json()
    user_message = (data.get("message") or "").strip()
    if not user_message:
        return jsonify({"response": "Please enter a message."})

    user_data = user_sessions.setdefault(user_id, {"history": [], "title": None})
    history = user_data["history"]

    response_text = call_gemini_api(history, user_message)

    history.append({"role": "user", "parts": [{"text": user_message}]})
    history.append({"role": "model", "parts": [
        {"text": response_text}
    ]})

    if not user_data["title"]:
        user_data["title"] = user_message[:50] + ("..." if len(user_message) > 50 else "")

    return jsonify({"response": response_text})

@app.route("/api/history", methods=["GET"])
@token_required
def get_history(user_id):
    user_data = user_sessions.setdefault(user_id, {"history": [], "title": None})
    return jsonify({"history": user_data["history"], "title": user_data["title"]})

@app.route("/api/history/reset", methods=["POST"])
@token_required
def reset_history(user_id):
    user_sessions[user_id] = {"history": [], "title": None}
    return jsonify({"msg": "Chat history cleared."})

# ================= MAIN =================
if __name__ == "__main__":
    if not os.path.exists("cert.pem") or not os.path.exists("key.pem"):
        print("Certificates 'cert.pem' and 'key.pem' not found. Ensure 'setup.sh' created them.")
    
    app.run(host='0.0.0.0', port=5000, ssl_context=('cert.pem', 'key.pem'))
