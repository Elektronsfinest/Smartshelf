import os
import sys

# Add the server directory to the python path
server_dir = os.path.join(os.getcwd(), 'server')
sys.path.append(server_dir)

import sqlite3
from database import DATABASE_URL

def check_users():
    print(f"Checking database at: {DATABASE_URL}")
    conn = sqlite3.connect(DATABASE_URL)
    conn.row_factory = sqlite3.Row
    try:
        users = conn.execute("SELECT id, nickname, email FROM users").fetchall()
        print(f"Total users: {len(users)}")
    except Exception as e:
        print(f"Error: {e}")
    conn.close()

if __name__ == "__main__":
    check_users()
