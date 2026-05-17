import sqlite3
from database import get_db_connection
from main import get_password_hash, generate_friend_code

def seed_admin():
    conn = get_db_connection()
    email = "adminme@gmail.com"
    existing = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    
    if not existing:
        print("Creating admin account...")
        hashed_pw = get_password_hash("imadmin")
        friend_code = generate_friend_code()
        conn.execute(
            "INSERT INTO users (nickname, email, hashed_password, friend_code) VALUES (?, ?, ?, ?)",
            ("admin", email, hashed_pw, friend_code)
        )
        conn.commit()
        print("Admin account created successfully.")
    else:
        print("Admin account already exists.")
    
    conn.close()

if __name__ == "__main__":
    seed_admin()
