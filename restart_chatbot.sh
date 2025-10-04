#!/usr/bin/env bash

# ----------------------------------------------------
# Script to stop any existing Flask process and restart the application.
# It uses the same venv activation and HTTPS startup method as setup.sh.
# ----------------------------------------------------

# Define the local project settings
VENV_DIR="venv"
# The app is configured in app.py to use SSL on port 5000 (https://localhost:5000)
LOGIN_URL="https://localhost:5000/login" 

# -------------------------
# 1. Stop Existing Processes
# -------------------------
echo "🛑 Stopping any running Flask server..."

# Use pkill or killall for simpler process management, checking for 'python app.py' command
# The 'kill' command below targets the process started by 'python app.py &'
PIDS=$(ps aux | grep "python app.py" | grep -v "grep" | awk '{print $2}')

if [ -n "$PIDS" ]; then
    echo "   - Killing PIDs: $PIDS"
    kill $PIDS 2>/dev/null || true # Kill processes, ignore errors if already gone
else
    echo "   - No previous Flask process found."
fi

# -------------------------
# 2. Activate Virtual Environment
# -------------------------
echo "🟢 Activating virtual environment..."
OS="$(uname -s)"

if [ ! -d "$VENV_DIR" ]; then
  echo "[ERROR] Virtual environment not found. Please run ./setup.sh first."
  exit 1
fi

# Activate venv depending on platform (Windows vs Linux/Mac)
if [[ "$OS" == "MINGW"* || "$OS" == "CYGWIN"* || "$OS" == "MSYS"* ]]; then
  source "$VENV_DIR/Scripts/activate"
else
  source "$VENV_DIR/bin/activate"
fi

# -------------------------
# 3. Start Flask app
# -------------------------
echo "🚀 Starting Flask app in the background (using HTTPS on port 5000)..."

# Export variables required by Flask and the Python code
export FLASK_APP=app.py
export FLASK_ENV=development

# Start the application using python app.py, which contains app.run(ssl_context='adhoc')
python app.py &
FLASK_PID=$!

# Wait a few seconds for the server to fully spin up
sleep 5

# -------------------------
# 4. Open Browser
# -------------------------
echo "🌐 Opening browser at $LOGIN_URL..."

# Cross-platform browser opening function
function open_browser() {
    if [[ "$OS" == "MINGW"* || "$OS" == "CYGWIN"* || "$OS" == "MSYS"* ]]; then
        start "" "$LOGIN_URL"
    elif command -v xdg-open >/dev/null; then
        xdg-open "$LOGIN_URL" &
    elif command -v open >/dev/null; then
        open "$LOGIN_URL"
    fi
}

open_browser

echo "=========================================================================="
echo "[SUCCESS] App restarted and running (PID: $FLASK_PID). Use $LOGIN_URL."
echo "   NOTE: You MUST click 'Proceed' past the SSL warning in your browser."
echo "   Press Ctrl+C to stop the Flask server."
echo "=========================================================================="

# Use 'trap' to ensure the background process is killed when the script is stopped.
trap "kill $FLASK_PID 2>/dev/null; exit" INT TERM
wait $FLASK_PID
