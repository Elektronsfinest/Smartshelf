import sqlite3

def migrate():
    conn = sqlite3.connect("smartshelf.db")
    try:
        conn.execute("ALTER TABLE users ADD COLUMN profile_pic TEXT")
    except sqlite3.OperationalError:
        print("Column profile_pic already exists")
    
    try:
        conn.execute("ALTER TABLE users ADD COLUMN last_nickname_change DATETIME")
    except sqlite3.OperationalError:
        print("Column last_nickname_change already exists")
    
    conn.commit()
    conn.close()
    print("Migration successful")

if __name__ == "__main__":
    migrate()
