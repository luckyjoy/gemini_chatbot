# Gemini-Powered Flask Chatbot with Persistent History

This project is a secure, authenticated web application built with **Flask** that provides a rich chat interface powered by the **Google Gemini API**. It uses **JWT (JSON Web Tokens)** for stateless authentication, and stores chat history persistently in a local **`history.json`** file.

---

## 🚀 Features

* **Authentication:** User login secured with **JWT**. The default admin user is created on startup.
* **Gemini AI Integration:** Chat functionality is powered by the `google-genai` SDK and the **`gemini-2.5-flash`** model.
* **Persistent Chat History:** Conversations are saved locally to a **`history.json`** file, indexed by user.
* **Dynamic UI:** Features a modern, split-screen interface with a list of past sessions in a **resizable sidebar** (left menu).
* **Security:** Enforces HTTPS with an ad-hoc SSL context for local development and includes essential security headers.
* **Database:** Uses **SQLite** via Flask-SQLAlchemy for user management.
* **Environment Variables:** Configuration and secrets are managed via the `.env` file.

---

## 🛠️ Setup and Installation

### Prerequisites

* **Python 3.11+**
* The `setup.sh` script requires a Unix-like environment (Linux/macOS) or **Git Bash** on Windows.
* **A Google Gemini API Key.**

### 1. Configure the `.env` File

Ensure your `.env` file is in the project root and contains the following necessary variables.

| Variable | Description | Example Value |
| :--- | :--- | :--- |
| **`GOOGLE_API_KEY`** | Your **Gemini API Key**. | `AIzaSy...` |
| `ADMIN_USER` | The default username for the database. | `admin` |
| `ADMIN_PASS` | The password for the default user. | `akj7@v$02f4@` |
| `SECRET_KEY` | Flask session secret key. | `supersecretkey` |
| `JWT_SECRET_KEY` | JWT signing secret key. | `jwt-secret-string` |

### 2. Run the Setup Script

The `setup.sh` script handles virtual environment creation, dependency installation, database cleanup, and starting the Flask server with HTTPS.

```bash
# Make the script executable (if necessary)
chmod +x setup.sh

# Run the setup script
./setup.sh