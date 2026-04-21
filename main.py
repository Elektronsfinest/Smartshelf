from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os
import shutil
import uuid
import json
from dotenv import load_dotenv

load_dotenv()


from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
import random
import string
import smtplib
from email.message import EmailMessage

from fastapi import Depends, FastAPI, HTTPException, status, File, UploadFile
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash
from pydantic import BaseModel

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


from database import get_db_connection
import sqlite3

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: str | None = None


class User(BaseModel):
    id: int | None = None
    nickname: str
    email: str
    disabled: bool = False
    friend_code: str | None = None
    last_seen: str | None = None


class UserInDB(User):
    hashed_password: str

class UserCreate(BaseModel):
    nickname: str
    email: str
    password: str

class VerificationRequest(BaseModel):
    email: str
    code: str

class FriendRequest(BaseModel):
    target: str # either nickname or friend_code

class MessageCreate(BaseModel):
    content: str

class GroupCreate(BaseModel):
    name: str
    friend_ids: list[int]

class GroupMessageCreate(BaseModel):
    content: str

class ForumPostCreate(BaseModel):
    content: str
    image_url: str | None = None

def generate_friend_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

class BookCreate(BaseModel):
    id: str
    isbn: str
    title: str
    coverUrl: str
    description: str
    content: str | None = None
    current_page: int = 1
    bookmarks: str = "[]"

class BookResponse(BookCreate):
    pass


password_hash = PasswordHash.recommended()

DUMMY_HASH = password_hash.hash("dummypassword")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

origins_str = os.getenv("BACKEND_CORS_ORIGINS", '["http://localhost:5173"]')
try:
    origins = json.loads(origins_str)
except json.JSONDecodeError:
    origins = [o.strip() for o in origins_str.strip("[]").split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "static", "uploads", "post_images")
os.makedirs(UPLOAD_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")


def verify_password(plain_password, hashed_password):
    return password_hash.verify(plain_password, hashed_password)


def get_password_hash(password):
    return password_hash.hash(password)


def get_user(email: str):
    conn = get_db_connection()
    user_row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()
    if user_row:
        return UserInDB(**dict(user_row))


def authenticate_user(email: str, password: str):
    user = get_user(email)
    if not user:
        verify_password(password, DUMMY_HASH)
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except InvalidTokenError:
        raise credentials_exception
    user = get_user(email=token_data.email)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")

pending_registrations = {}

def generate_verification_code(length=5):
    return ''.join(random.choices(string.digits, k=length))

# --- SMTP Config ---
SMTP_SERVER = os.getenv("SMTP_SERVER", "localhost")
SMTP_PORT = int(os.getenv("SMTP_PORT", 1026))
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "noreply@smartshelf.com")

def send_verification_email(receiver_email, code):
    msg = EmailMessage()
    msg['Subject'] = 'SmartShelf Email Verification'
    msg['From'] = SENDER_EMAIL
    msg['To'] = receiver_email
    msg.set_content(f"Your verification code is: {code}")
    
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=2) as server:
            # MailHog doesn't typically need starttls or login for local dev
            server.send_message(msg)
        print(f"Email sent to {receiver_email}")
    except (ConnectionRefusedError, smtplib.SMTPConnectError, smtplib.SMTPException, TimeoutError) as e:
        print(f"SMTP error sending email to {receiver_email}: {e}")
        raise e  # Let the caller return the 500 error to the UI
    except Exception as e:
        print(f"Unexpected error sending email: {e}")
        raise e
# ---------------------------------------------

@app.post("/register/request")
async def request_registration(user: UserCreate):
    conn = get_db_connection()
    existing_user = conn.execute("SELECT * FROM users WHERE email = ?", (user.email,)).fetchone()
    conn.close()
    
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
        
    code = generate_verification_code()
    
    pending_registrations[user.email] = {
        "nickname": user.nickname,
        "email": user.email,
        "password": user.password,
        "code": code
    }
    
    # Send actual email via MailHog
    try:
        send_verification_email(user.email, code)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="We are currently having some difficulties, please try again later"
        )
    
    return {"message": "Verification code sent"}

@app.post("/register/verify")
async def verify_and_register(req: VerificationRequest):
    pending_user = pending_registrations.get(req.email)
    
    if not pending_user:
        raise HTTPException(status_code=400, detail="No pending registration found for this email")
        
    if pending_user["code"] != req.code:
        raise HTTPException(status_code=400, detail="Invalid verification code")
        
    conn = get_db_connection()
    hashed_pw = get_password_hash(pending_user["password"])
    new_friend_code = generate_friend_code()
    conn.execute("INSERT INTO users (nickname, email, hashed_password, friend_code) VALUES (?, ?, ?, ?)",
                 (pending_user["nickname"], pending_user["email"], hashed_pw, new_friend_code))
    conn.commit()
    conn.close()
    
    del pending_registrations[req.email]
    
    return {"message": "User registered successfully"}


@app.get("/users/me/")
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> User:
    conn = get_db_connection()
    if not current_user.friend_code:
        new_fc = generate_friend_code()
        conn.execute("UPDATE users SET friend_code = ? WHERE id = ?", (new_fc, current_user.id))
        current_user.friend_code = new_fc
    conn.execute("UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?", (current_user.id,))
    conn.commit()
    conn.close()
    return current_user


@app.get("/users/me/items/")
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return [{"item_id": "Foo", "owner": current_user.nickname}]



@app.get("/books/")
async def get_books(current_user: Annotated[User, Depends(get_current_active_user)]):
    conn = get_db_connection()
    books = conn.execute("SELECT * FROM books WHERE user_email = ?", (current_user.email,)).fetchall()
    conn.close()
    
    return [
        {
            "id": b["id"],
            "isbn": b["isbn"],
            "title": b["title"],
            "coverUrl": b["cover_url"],
            "description": b["description"],
            "content": b["content"],
            "current_page": b["current_page"],
            "bookmarks": b["bookmarks"]
        } for b in books
    ]

@app.post("/books/")
async def add_book(book: BookCreate, current_user: Annotated[User, Depends(get_current_active_user)]):
    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO books (id, user_email, isbn, title, cover_url, description, content, current_page, bookmarks) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (book.id, current_user.email, book.isbn, book.title, book.coverUrl, book.description, book.content, book.current_page, book.bookmarks)
        )
        conn.commit()
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=400, detail="Could not add book")
    conn.close()
    return book

class ProgressUpdate(BaseModel):
    current_page: int

class BookmarksUpdate(BaseModel):
    bookmarks: str

@app.put("/books/{book_id}/progress")
async def update_book_progress(book_id: str, progress: ProgressUpdate, current_user: Annotated[User, Depends(get_current_active_user)]):
    conn = get_db_connection()
    conn.execute(
        "UPDATE books SET current_page = ? WHERE id = ? AND user_email = ?",
        (progress.current_page, book_id, current_user.email)
    )
    conn.commit()
    conn.close()
    return {"status": "success"}

@app.put("/books/{book_id}/bookmarks")
async def update_book_bookmarks(book_id: str, update: BookmarksUpdate, current_user: Annotated[User, Depends(get_current_active_user)]):
    conn = get_db_connection()
    conn.execute(
        "UPDATE books SET bookmarks = ? WHERE id = ? AND user_email = ?",
        (update.bookmarks, book_id, current_user.email)
    )
    conn.commit()
    conn.close()
    return {"status": "success"}


@app.get("/friends/")
async def get_friends(current_user: Annotated[User, Depends(get_current_active_user)]):
    conn = get_db_connection()
    friends = conn.execute('''
        SELECT u.id, u.nickname, u.friend_code, u.last_seen, f.status, f.id as request_id,
               CASE WHEN f.user_id1 = u.id THEN 'received' ELSE 'sent' END as direction
        FROM friendships f
        JOIN users u ON (f.user_id1 = u.id OR f.user_id2 = u.id)
        WHERE (f.user_id1 = ? OR f.user_id2 = ?) AND u.id != ?
    ''', (current_user.id, current_user.id, current_user.id)).fetchall()
    conn.close()
    return [{"id": f["id"], "nickname": f["nickname"], "friend_code": f["friend_code"], "last_seen": f["last_seen"], "status": f["status"], "request_id": f["request_id"], "direction": f["direction"]} for f in friends]

@app.post("/friends/request")
async def send_friend_request(req: FriendRequest, current_user: Annotated[User, Depends(get_current_active_user)]):
    conn = get_db_connection()
    target_user = conn.execute("SELECT id FROM users WHERE nickname = ? OR friend_code = ?", (req.target, req.target)).fetchone()
    if not target_user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")
    if target_user["id"] == current_user.id:
        conn.close()
        raise HTTPException(status_code=400, detail="Cannot add yourself")
    
    existing = conn.execute("SELECT * FROM friendships WHERE (user_id1 = ? AND user_id2 = ?) OR (user_id1 = ? AND user_id2 = ?)",
                            (current_user.id, target_user["id"], target_user["id"], current_user.id)).fetchone()
    if existing:
        conn.close()
        raise HTTPException(status_code=400, detail="Friendship already exists or pending")
        
    conn.execute("INSERT INTO friendships (user_id1, user_id2, status) VALUES (?, ?, ?)",
                 (current_user.id, target_user["id"], 'pending'))
    conn.commit()
    conn.close()
    return {"message": "Friend request sent"}

@app.put("/friends/accept/{request_id}")
async def accept_friend_request(request_id: int, current_user: Annotated[User, Depends(get_current_active_user)]):
    conn = get_db_connection()
    req = conn.execute("SELECT * FROM friendships WHERE id = ? AND status = 'pending'", (request_id,)).fetchone()
    if not req or req["user_id2"] != current_user.id:
        conn.close()
        raise HTTPException(status_code=404, detail="Request not found")
        
    conn.execute("UPDATE friendships SET status = 'accepted' WHERE id = ?", (request_id,))
    conn.commit()
    conn.close()
    return {"message": "Request accepted"}

@app.get("/messages/{friend_id}")
async def get_messages(friend_id: int, current_user: Annotated[User, Depends(get_current_active_user)]):
    conn = get_db_connection()
    messages = conn.execute('''
        SELECT * FROM messages
        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        ORDER BY timestamp ASC
    ''', (current_user.id, friend_id, friend_id, current_user.id)).fetchall()
    conn.close()
    return [{"id": m["id"], "sender_id": m["sender_id"], "receiver_id": m["receiver_id"], "content": m["content"], "timestamp": m["timestamp"]} for m in messages]

@app.post("/messages/{friend_id}")
async def send_message(friend_id: int, req: MessageCreate, current_user: Annotated[User, Depends(get_current_active_user)]):
    conn = get_db_connection()
    conn.execute("INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)",
                 (current_user.id, friend_id, req.content))
    conn.commit()
    conn.close()
    return {"message": "Message sent"}

@app.post("/groups/")
async def create_group(group: GroupCreate, current_user: Annotated[User, Depends(get_current_active_user)]):
    conn = get_db_connection()
    # 1. Create group
    cursor = conn.execute("INSERT INTO chat_groups (name) VALUES (?)", (group.name,))
    group_id = cursor.lastrowid
    
    # 2. Add members
    # Add current user
    conn.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (group_id, current_user.id))
    # Add friends
    for friend_id in group.friend_ids:
        conn.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (group_id, friend_id))
        
    conn.commit()
    conn.close()
    return {"id": group_id, "name": group.name, "message": "Group created successfully"}

@app.get("/groups/")
async def get_groups(current_user: Annotated[User, Depends(get_current_active_user)]):
    conn = get_db_connection()
    groups = conn.execute('''
        SELECT cg.id, cg.name, cg.created_at
        FROM chat_groups cg
        JOIN group_members gm ON cg.id = gm.group_id
        WHERE gm.user_id = ?
    ''', (current_user.id,)).fetchall()
    
    # get members for each group
    result = []
    for g in groups:
        members = conn.execute('''
            SELECT u.id, u.nickname
            FROM users u
            JOIN group_members gm ON u.id = gm.user_id
            WHERE gm.group_id = ?
        ''', (g["id"],)).fetchall()
        
        result.append({
            "id": g["id"],
            "name": g["name"],
            "created_at": g["created_at"],
            "members": [{"id": m["id"], "nickname": m["nickname"]} for m in members]
        })
        
    conn.close()
    return result

@app.get("/groups/{group_id}/messages")
async def get_group_messages(group_id: int, current_user: Annotated[User, Depends(get_current_active_user)]):
    conn = get_db_connection()
    
    # Verify membership
    member = conn.execute("SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?", (group_id, current_user.id)).fetchone()
    if not member:
        conn.close()
        raise HTTPException(status_code=403, detail="Not a member of this group")
        
    messages = conn.execute('''
        SELECT gm.id, gm.group_id, gm.sender_id, gm.content, gm.timestamp, u.nickname as sender_nickname
        FROM group_messages gm
        JOIN users u ON gm.sender_id = u.id
        WHERE gm.group_id = ?
        ORDER BY gm.timestamp ASC
    ''', (group_id,)).fetchall()
    conn.close()
    
    return [{
        "id": m["id"], 
        "group_id": m["group_id"], 
        "sender_id": m["sender_id"], 
        "sender_nickname": m["sender_nickname"],
        "content": m["content"], 
        "timestamp": m["timestamp"]
    } for m in messages]

@app.post("/groups/{group_id}/messages")
async def send_group_message(group_id: int, req: GroupMessageCreate, current_user: Annotated[User, Depends(get_current_active_user)]):
    conn = get_db_connection()
    
    # Verify membership
    member = conn.execute("SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?", (group_id, current_user.id)).fetchone()
    if not member:
        conn.close()
        raise HTTPException(status_code=403, detail="Not a member of this group")
        
    conn.execute("INSERT INTO group_messages (group_id, sender_id, content) VALUES (?, ?, ?)",
                 (group_id, current_user.id, req.content))
    conn.commit()
    conn.close()
    return {"message": "Group message sent"}

# ──────────────────────────  FORUM  ──────────────────────────

@app.get("/forum/posts/")
async def get_forum_posts():
    conn = get_db_connection()
    posts = conn.execute('''
        SELECT fp.id, fp.content, fp.image_url, fp.timestamp, u.id as user_id, u.nickname
        FROM forum_posts fp
        JOIN users u ON fp.user_id = u.id
        ORDER BY fp.timestamp DESC
    ''').fetchall()
    conn.close()
    return [
        {
            "id": p["id"],
            "content": p["content"],
            "image_url": p["image_url"],
            "timestamp": p["timestamp"],
            "user_id": p["user_id"],
            "nickname": p["nickname"]
        }
        for p in posts
    ]

@app.post("/forum/posts/")
async def create_forum_post(
    post: ForumPostCreate,
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    conn = get_db_connection()
    cursor = conn.execute(
        "INSERT INTO forum_posts (user_id, content, image_url) VALUES (?, ?, ?)",
        (current_user.id, post.content, post.image_url)
    )
    post_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return {"id": post_id, "message": "Post created"}

@app.post("/upload/")
async def upload_image(
    current_user: Annotated[User, Depends(get_current_active_user)],
    file: UploadFile = File(...),
):
    allowed_types = {"image/jpeg", "image/jpg", "image/png", "image/gif", "image/webp"}
    content_type = (file.content_type or "").split(";")[0].strip().lower()
    if content_type not in allowed_types:
        raise HTTPException(status_code=400, detail=f"Invalid file type: {content_type}")
    ext = file.filename.rsplit(".", 1)[-1].lower() if file.filename and "." in file.filename else "jpg"
    filename = f"{uuid.uuid4().hex}.{ext}"
    file_path = os.path.join(UPLOAD_DIR, filename)
    data = await file.read()
    with open(file_path, "wb") as f:
        f.write(data)
    return {"url": f"/static/uploads/post_images/{filename}"}