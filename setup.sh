#!/usr/bin/env bash

# -------------------------
# Detect OS
# -------------------------
OS="$(uname -s)"
echo "Detected OS: $OS"

# -------------------------
# Activate venv
# -------------------------
if [ -d "venv" ]; then
  echo "[SUCCESS] Using existing virtual environment"
else
  echo "[INFO] Creating virtual environment..."
  python -m venv venv
fi

# Activate depending on platform
if [[ "$OS" == "MINGW"* || "$OS" == "CYGWIN"* || "$OS" == "MSYS"* ]]; then
  source venv/Scripts/activate
else
  source venv/bin/activate
fi

# -------------------------
# Upgrade pip + install deps
# -------------------------
echo "Upgrading pip..."
pip install --upgrade pip

echo "Installing dependencies, Werkzeug, and 'cryptography' (Required for SSL)..."
# Ensures all necessary libraries for SSL are installed
pip install -r requirements.txt Werkzeug cryptography

# -------------------------------------
# CLEANUP: Delete old database and sessions (CRITICAL)
# -------------------------------------
echo "🧹 Cleaning up old database and session files..."

# Remove the database file (ignoring lock error)
if [ -f "instance/chatbot.db" ]; then
    rm "instance/chatbot.db" 2>/dev/null || true 
    echo "   - Attempted to delete old instance/chatbot.db"
fi

# Remove the session storage directory
if [ -d "flask_session" ]; then
    rm -rf "flask_session"
    echo "   - Deleted old flask_session directory"
fi

# -------------------------
# Run Flask app
# -------------------------
echo "🚀 Starting Flask app in the background..."
export FLASK_APP=app.py
export FLASK_ENV=development

# 1. Start Flask using the python interpreter
python app.py &
FLASK_PID=$!

# 2. Wait a few seconds for the server to fully spin up
sleep 5

# Open browser cross-platform (Using HTTPS and localhost)
function open_browser() {
# --- UPDATED: Open the login page directly instead of the root '/' ---
LOGIN_URL="https://localhost:5000/login" 

if [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "cygwin"* || "$OSTYPE" == "MSYS"* ]]; then
    start "" "$LOGIN_URL"
elif command -v xdg-open >/dev/null; then
    xdg-open "$LOGIN_URL" &
elif command -v open >/dev/null; then
    open "$LOGIN_URL"
fi
}

# 3. Open the browser
open_browser

echo "=========================================================================="
echo "[SUCCESS] App is running (PID: $FLASK_PID). Use https://localhost:5000."
echo "   NOTE: You MUST click 'Proceed' past the SSL warning in your browser."
echo "   Press Ctrl+C to stop the Flask server."
echo "=========================================================================="

# 4. Use 'trap' to ensure the background process is killed when the script is stopped.
trap "kill $FLASK_PID 2>/dev/null; exit" INT TERM
wait $FLASK_PID
