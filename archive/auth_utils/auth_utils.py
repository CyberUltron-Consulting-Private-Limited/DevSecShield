import asyncio
from email.message import EmailMessage
import smtplib
from backend.auth_utils.html_email import create_verification_email_html
from passlib.context import CryptContext
import os
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Optional, Union, Callable
from jose import jwt
from sqlmodel import Session, select
from sqlalchemy import Engine
from fastapi import Depends, HTTPException, status
from pydantic import ValidationError
from backend.auth_utils.auth_schema import TokenPayload
from backend.models import User, VerificationCode
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
import requests
import msal
load_dotenv()

ACCESS_TOKEN_EXPIRE_MINUTES = 30  # 30 minutes
REFRESH_TOKEN_EXPIRE_MINUTES = 60 * 8 # 8 hours
ALGORITHM = "HS256"
JWT_SECRET_KEY = os.environ['JWT_SECRET_KEY']     # should be kept secret
JWT_REFRESH_SECRET_KEY = os.environ['JWT_REFRESH_SECRET_KEY']      # should be kept secret

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_hashed_password(password: str) -> str:
    return password_context.hash(password)


def verify_password(password: str, hashed_pass: str) -> bool:
    return password_context.verify(password, hashed_pass)


def create_access_token(subject: Union[str, Any], expires_delta: int = None) -> str:
    if expires_delta is not None:
        expires_delta = datetime.now(timezone.utc) + expires_delta
    else:
        expires_delta = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode = {"exp": expires_delta, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, ALGORITHM)
    return encoded_jwt

def create_refresh_token(subject: Union[str, Any], expires_delta: int = None) -> str:
    if expires_delta is not None:
        expires_delta = datetime.now(timezone.utc) + expires_delta
    else:
        expires_delta = datetime.now(timezone.utc) + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)

    to_encode = {"exp": expires_delta, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, JWT_REFRESH_SECRET_KEY, ALGORITHM)
    return encoded_jwt

async def get_current_user_from_access_token(engine: Engine, token: str, ignore_session_active: bool = False) -> User:
        try:
            payload = jwt.decode(
                token, JWT_SECRET_KEY, algorithms=[ALGORITHM]
            )
            token_data = TokenPayload(**payload)
            
            if datetime.fromtimestamp(token_data.exp) < datetime.now():
                print("Token expired 🔴")
                raise HTTPException(
                    status_code = status.HTTP_401_UNAUTHORIZED,
                    detail="Token expired",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
        except(jwt.JWTError, ValidationError) as e:
            print(f"Error: {e} 🔴")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        with Session(engine) as session:
            user = session.exec(select(User).where(User.email == token_data.sub)).first()
        
        if not user.session_active and not ignore_session_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Session not active",
            )
        
        if user is None:
            print("Could not find user 🔴")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Could not find user",
            )
        print("User found 🟩")

        with Session(engine) as session:
            statement = select(User).where(User.id == user.id)
            user = session.exec(statement).first()
            user.last_active = datetime.now(timezone.utc)
            session.add(user)
            session.commit()
            print(f"User {user.email} last active updated to {user.last_active} 🟩")

        return user

async def get_current_user_from_refresh_token(engine: Engine, token: str) -> User:
        try:
            payload = jwt.decode(
                token, JWT_REFRESH_SECRET_KEY, algorithms=[ALGORITHM]
            )
            token_data = TokenPayload(**payload)
            
            if datetime.fromtimestamp(token_data.exp) < datetime.now():
                with Session(engine) as session:
                    statement = select(User).where(User.email == token_data.sub)
                    user = session.exec(statement).first()
                    user.session_active = False
                    session.add(user)
                    session.commit()
                    print(f"User {user.email} session deactivated {datetime.now(timezone.utc)} 🔴")
                raise HTTPException(
                    status_code = status.HTTP_403_FORBIDDEN,
                    detail="Token expired",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        except(jwt.JWTError, ValidationError):
            with Session(engine) as session:
                    statement = select(User).where(User.email == token_data.sub)
                    user = session.exec(statement).first()
                    user.session_active = False
                    session.add(user)
                    session.commit()
                    print(f"User {user.email} session deactivated {datetime.now(timezone.utc)} 🔴")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        with Session(engine) as session:
            user = session.exec(select(User).where(User.email == token_data.sub)).first()
        
        
        if user is None:
            with Session(engine) as session:
                    statement = select(User).where(User.email == token_data.sub)
                    user = session.exec(statement).first()
                    user.session_active = False
                    session.add(user)
                    session.commit()
                    print(f"User {user.email} session deactivated {datetime.now(timezone.utc)} 🔴")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Could not find user",
            )
        
        return user

async def get_user_from_header_or_raise_exception(engine: Engine,Authorization: str | None = None, ignore_session_active: bool = False)->User:
    if not Authorization:
        print("No Authorization header provided 🔴")
        raise HTTPException(status_code=401, detail="Unauthorized")
    access_token = Authorization.split(" ")[1]
    user = await get_current_user_from_access_token(engine, access_token, ignore_session_active)
    return user


async def send_email( recipient_email: str , subject: str , body: Optional[str] = None , html_body:Optional[str] = None ):
    if not html_body and not body:
        raise HTTPException(status_code=400, detail="Body or html_body is required")
    if html_body:
        msg = MIMEText(html_body, 'html')
    else:
        msg = MIMEText(body)
    password = os.environ['EMAIL_PASSWORD']
    sender = os.environ['EMAIL_SENDER']
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = recipient_email
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
            smtp_server.login(sender, password)
            smtp_server.sendmail(sender, recipient_email, msg.as_string())
        print("Message sent! 🟩")
    except Exception as e:
        print(f"Error sending message: {e} 🔴")
        raise HTTPException(status_code=500, detail=str(e))


async def send_outlook_email( recipient_email: str , subject: str , body: Optional[str] = None , html_body:Optional[str] = None , custom_domain:str = "zeroshield.ai" ):
    if not html_body and not body:
        raise HTTPException(status_code=400, detail="Body or html_body is required")
    if html_body:
        msg = MIMEText(html_body, 'html')
    else:
        msg = MIMEText(body)

    try:
        # === CONFIGURATION ===
        TENANT_ID =  os.environ['TENANT_ID']
        CLIENT_ID = os.environ['CLIENT_ID']
        CLIENT_SECRET = os.environ['CLIENT_SECRET']

        SENDER_EMAIL = "support@zeroshield.ai"       # must exist in your Microsoft 365 tenant
        RECIPIENT_EMAIL = recipient_email  # recipient

        # === AUTHENTICATE WITH MICROSOFT GRAPH ===
        AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
        SCOPES = ["https://graph.microsoft.com/.default"]

        app = msal.ConfidentialClientApplication(
            CLIENT_ID,
            authority=AUTHORITY,
            client_credential=CLIENT_SECRET
        )

        token = app.acquire_token_for_client(scopes=SCOPES)
        if "access_token" not in token:
            raise Exception("❌ Authentication failed: " + token.get("error_description", "Unknown error"))

        access_token = token["access_token"]


        email_data = {
            "message": {
                "subject": subject,
                "body": {
                    "contentType": "HTML",
                    "content": html_body
                },
                "toRecipients": [
                    {"emailAddress": {"address": RECIPIENT_EMAIL}}
                ]
            }
        }

        # === SEND THE EMAIL ===
        url = f"https://graph.microsoft.com/v1.0/users/{SENDER_EMAIL}/sendMail"
        headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}

        response = requests.post(url, headers=headers, json=email_data)

        # === RESULT ===
        if response.status_code == 202:
            print("Verfication code sent successfully!")
        else:
            raise Exception(f"❌ Failed: {response.status_code}\n{response.text}")
    
    except Exception as e:
        print(f"Error sending email: {e} 🔴")
        raise HTTPException(status_code=500, detail=str(e))


def generate_verification_code():
    import random
    code = ''.join(random.choices('0123456789', k=6))
    return code

async def send_verification_code_and_save_to_db( recipient_email: str , engine: Engine):
    code = generate_verification_code()
    body = create_verification_email_html(code)
    # await send_email(
    #     recipient_email=recipient_email , 
    #     subject="Verification code", 
    #     html_body=body)
    await send_outlook_email(
        recipient_email=recipient_email , 
        subject="Verification code", 
        html_body=body)
    with Session(engine) as session:
        verification_code = VerificationCode(email=recipient_email, code=code)
        session.add(verification_code)
        session.commit()
    return code


if __name__ == "__main__":
    # print(get_hashed_password("123456"))
    # print(verify_password("123456", get_hashed_password("123456")))
    async def send_outlook():
        await send_outlook_email(recipient_email="nikhil@cyberultron.com", subject="Test Email", html_body="<h1>Hello from Python</h1>")
    asyncio.run(send_outlook())