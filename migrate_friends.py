import sqlite3

def migrate():
    conn = sqlite3.connect("smartshelf.db")
    cursor = conn.cursor()

    try:
        cursor.execute("ALTER TABLE users ADD COLUMN friend_code TEXT")
        print("Added friend_code")
    except sqlite3.OperationalError as e:
        print(f"friend_code might already exist: {e}")

    try:
        cursor.execute("ALTER TABLE users ADD COLUMN last_seen DATETIME")
        print("Added last_seen")
    except sqlite3.OperationalError as e:
        print(f"last_seen might already exist: {e}")

    conn.commit()
    conn.close()

if __name__ == "__main__":
    migrate()
