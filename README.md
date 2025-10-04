
# Chatbot Web App (Flask + OpenAI + JWT Auth)

## Features
- User registration/login with JWT
- Access + Refresh tokens
- Chat with OpenAI API
- Store chat history in SQLite
- Responsive UI with TailwindCSS

## Setup
1. Install dependencies:
   pip install -r requirements.txt
   pip install Flask Flask-SQLAlchemy Flask-JWT-Extended Werkzeug openai python-dotenv

2. Set environment variable:
   export OPENAI_API_KEY='YOUR_KEY'
3. Initialize DB: flask shell -> db.create_all()
4. Run: flask run

## Usage
- Register/Login
- Chat in UI
- Tokens auto-refresh on expiry
