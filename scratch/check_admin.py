import sqlite3

DATABASE_URL = "smartshelf.db"

def check_admin():
    conn = sqlite3.connect(DATABASE_URL)
    conn.row_factory = sqlite3.Row
    user = conn.execute("SELECT * FROM users WHERE email = 'adminme@gmail.com'").fetchone()
    if user:
        print(f"Admin found: {dict(user)}")
        print(f"Email type: {type(user['email'])}")
        print(f"Email length: {len(user['email'])}")
        print(f"Email repr: {repr(user['email'])}")
    else:
        print("Admin NOT found by exact email match")
        # Let's try to find it by nickname
        user2 = conn.execute("SELECT * FROM users WHERE nickname = 'admin'").fetchone()
        if user2:
            print(f"User with nickname 'admin' found: {dict(user2)}")
            print(f"Email repr: {repr(user2['email'])}")
    conn.close()

if __name__ == "__main__":
    check_admin()
