import sqlite3

DATABASE_URL = "smartshelf.db"

def check_users():
    conn = sqlite3.connect(DATABASE_URL)
    conn.row_factory = sqlite3.Row
    users = conn.execute("SELECT id, nickname, email FROM users").fetchall()
    print(f"Total users: {len(users)}")
    for u in users:
        print(f"ID: {u['id']}, Nickname: {u['nickname']}, Email: {u['email']}")
    conn.close()

if __name__ == "__main__":
    check_users()
