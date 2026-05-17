# SmartShelf Backend

SmartShelf is a modern web application for managing personal book collections. This repository contains the FastAPI-based backend service.

## 🚀 Features

- **Authentication & Security**: 
  - JWT-based authentication using `OAuth2PasswordBearer`.
  - Password hashing with `pwdlib`.
  - Email verification via SMTP (integrates with MailHog for development).
- **Library Management**:
  - Cataloging books with ISBN, title, cover URL, and description.
  - Tracking reading progress (current page).
  - Personal bookmarks management.
- **Social Features**:
  - Friend system with unique friend codes.
  - Real-time interaction via "Last Seen" tracking.
  - Private messaging between friends.
  - Group chats with multiple participants.
- **Public Forum**:
  - Community feed for sharing book-related posts.
  - Support for image uploads.
- **Database**: 
  - Persistent storage using SQLite.

## 🛠️ Tech Stack

- **Framework**: [FastAPI](https://fastapi.tiangolo.com/)
- **Database**: [SQLite](https://www.sqlite.org/index.html)
- **Validation**: [Pydantic v2](https://docs.pydantic.dev/)
- **Security**: PyJWT, pwdlib
- **Asynchronous I/O**: aiofiles, uvicorn

## ⚙️ Setup & Installation

### 1. Requirements
Ensure you have Python 3.10+ installed.

### 2. Virtual Environment
It is recommended to use a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 3. Dependencies
Install the required packages:
```bash
pip install -r requirements.txt
```

### 4. Environment Variables
Create a `.env` file in the `server` directory and configure the following:
```env
SECRET_KEY=your_secret_key_here
BACKEND_CORS_ORIGINS=["http://localhost:5173"]
SMTP_SERVER=localhost
SMTP_PORT=1025
SENDER_EMAIL=noreply@smartshelf.com
```

## 🏃 Running the Application

Start the development server with uvicorn:
```bash
uvicorn main:app --reload
```
The server will be available at `http://localhost:8000`.

### API Documentation
Once the server is running, you can access the interactive API docs:
- **Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc**: [http://localhost:8000/redoc](http://localhost:8000/redoc)

## 📂 Project Structure

- `main.py`: Entry point, contains all API routes and logic.
- `database.py`: Database connection and schema initialization.
- `static/`: Contains uploaded images and other static assets.
- `requirements.txt`: Python package dependencies.
- `.env`: API configuration and secrets (not tracked in Git).
