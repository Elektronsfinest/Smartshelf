from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os
from dotenv import load_dotenv

load_dotenv()


from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
import random
import string
import smtplib
from email.message import EmailMessage

from fastapi import Depends, FastAPI, HTTPException, status
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
    nickname: str
    email: str
    disabled: bool = False


class UserInDB(User):
    hashed_password: str

class UserCreate(BaseModel):
    nickname: str
    email: str
    password: str

class VerificationRequest(BaseModel):
    email: str
    code: str

password_hash = PasswordHash.recommended()

DUMMY_HASH = password_hash.hash("dummypassword")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

origins = [
    "http://localhost",
    "http://localhost:5173/",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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

# --- SMTP Config for MailHog ---
SMTP_SERVER = "localhost"
SMTP_PORT = 1026
SENDER_EMAIL = "noreply@smartshelf.com"

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
    conn.execute("INSERT INTO users (nickname, email, hashed_password) VALUES (?, ?, ?)",
                 (pending_user["nickname"], pending_user["email"], hashed_pw))
    conn.commit()
    conn.close()
    
    del pending_registrations[req.email]
    
    return {"message": "User registered successfully"}


@app.get("/users/me/")
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> User:
    return current_user


@app.get("/users/me/items/")
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_active_user)],
):
    return [{"item_id": "Foo", "owner": current_user.nickname}]




@app.get("/{id}")
async def read_root(id: int):
    name = ""
    match id:
         case 1:
            name = "raz"
         case 2:
            name = "dwa"
         case _:
             name = "trzy"
    return {"message": f"hello {name}"}