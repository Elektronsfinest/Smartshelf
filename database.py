import sqlite3

DATABASE_URL = "smartshelf.db"

def get_db_connection():
    conn = sqlite3.connect(DATABASE_URL)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nickname TEXT NOT NULL,
            email TEXT NOT NULL,
            hashed_password TEXT NOT NULL,
            disabled BOOLEAN NOT NULL DEFAULT 0
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS books (
            id TEXT PRIMARY KEY,
            user_email TEXT NOT NULL,
            isbn TEXT,
            title TEXT NOT NULL,
            cover_url TEXT,
            description TEXT,
            content TEXT,
            current_page INTEGER DEFAULT 1,
            bookmarks TEXT DEFAULT '[]',
            FOREIGN KEY (user_email) REFERENCES users (email)
        )
    ''')
    conn.commit()
    conn.close()

# Initialize DB when this file is imported
init_db()
