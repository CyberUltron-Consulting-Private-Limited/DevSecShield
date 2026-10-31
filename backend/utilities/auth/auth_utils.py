import asyncio
from email.message import EmailMessage
import smtplib
from backend.utilities.auth.html_email import create_verification_email_html
from passlib.context import CryptContext
import os
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Optional, Union, Callable
from jose import jwt
from sqlmodel import Session, select, delete
from sqlalchemy import Engine
from fastapi import Depends, HTTPException, status
from pydantic import ValidationError
from backend.utilities.auth.auth_schema import TokenPayload
from backend.new_models import User, VerificationCode
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
            
            if datetime.fromtimestamp(token_data.exp, tz=timezone.utc) < datetime.now(timezone.utc):
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

        if user is None:
            print("Could not find user 🔴")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not user.session_active and not ignore_session_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Session not active",
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
            
            if datetime.fromtimestamp(token_data.exp, tz=timezone.utc) < datetime.now(timezone.utc):
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
        
        if user and not user.session_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Session not active",
            )
        
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
    parts = Authorization.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid Authorization header format")
    access_token = parts[1]
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


def smtp_settings() -> Optional[dict]:
    """The site's own mail relay, for on-prem and air-gapped installs (no Microsoft Graph, no internet).

    Off unless SMTP_HOST is set. SMTP_SECURITY is starttls (default), ssl, or none; none is only allowed without a
    login, so a password never crosses the network in clear text. SMTP_CA_FILE trusts a private CA."""
    host = os.getenv("SMTP_HOST", "").strip()
    if not host:
        return None
    security = os.getenv("SMTP_SECURITY", "starttls").strip().lower()
    if security not in ("starttls", "ssl", "none"):
        raise ValueError("SMTP_SECURITY must be starttls, ssl or none")
    user = os.getenv("SMTP_USERNAME", "").strip()
    if security == "none" and user:
        raise ValueError("SMTP_SECURITY=none cannot be used with SMTP_USERNAME: the password would be sent unencrypted")
    try:
        port = int(os.getenv("SMTP_PORT") or (465 if security == "ssl" else 587))
        timeout = float(os.getenv("SMTP_TIMEOUT_S") or 20)
    except ValueError:
        raise ValueError("SMTP_PORT must be a number and SMTP_TIMEOUT_S a number of seconds") from None
    if not 1 <= port <= 65535 or not 0 < timeout <= 300:  # also rejects NaN
        raise ValueError("SMTP_PORT must be 1-65535 and SMTP_TIMEOUT_S between 0 and 300 seconds")
    return {
        "host": host,
        "port": port,
        "security": security,
        "user": user,
        "password": os.getenv("SMTP_PASSWORD", ""),
        "sender": os.getenv("MAIL_FROM", "").strip() or "no-reply@localhost",
        "ca_file": os.getenv("SMTP_CA_FILE", "").strip() or None,
        "timeout": timeout,
    }


class MailAddressError(ValueError):
    """The recipient address cannot be used (line breaks, no domain, a domain that cannot be encoded)."""


def _smtp_address(address: str) -> str:
    """The address as an SMTP server accepts it: an internationalised domain is sent in its ASCII (punycode) form."""
    local, sep, domain = address.strip().rpartition("@")
    if not sep or not local or not domain or any(c in address for c in "\r\n\x00"):
        raise MailAddressError("invalid email address")
    if not domain.isascii():
        try:
            domain = ".".join(p.encode("idna").decode("ascii") for p in domain.split("."))
        except UnicodeError:
            raise MailAddressError("invalid email domain") from None
    if not local.isascii():
        raise MailAddressError("the mail relay cannot deliver to a non-ASCII mailbox name")
    return f"{local}@{domain}"


def send_smtp_email(cfg: dict, recipient_email: str, subject: str, msg: MIMEText) -> None:
    recipient_email = _smtp_address(recipient_email)
    for value in (subject, cfg["sender"]):
        if "\r" in value or "\n" in value:
            raise MailAddressError("line breaks are not allowed in mail headers")
    msg["Subject"] = subject[:200]
    msg["From"] = cfg["sender"]
    msg["To"] = recipient_email
    import ssl
    context = ssl.create_default_context(cafile=cfg["ca_file"])
    if cfg["security"] == "ssl":
        server = smtplib.SMTP_SSL(cfg["host"], cfg["port"], context=context, timeout=cfg["timeout"])
    else:
        server = smtplib.SMTP(cfg["host"], cfg["port"], timeout=cfg["timeout"])
    with server:
        if cfg["security"] == "starttls":
            server.starttls(context=context)
        if cfg["user"]:
            server.login(cfg["user"], cfg["password"])
        server.send_message(msg, from_addr=cfg["sender"], to_addrs=[recipient_email])


async def send_outlook_email( recipient_email: str , subject: str , body: Optional[str] = None , html_body:Optional[str] = None , custom_domain:str = "zeroshield.ai" ):
    if not html_body and not body:
        raise HTTPException(status_code=400, detail="Body or html_body is required")
    if html_body:
        msg = MIMEText(html_body, 'html')
    else:
        msg = MIMEText(body)

    try:
        smtp = smtp_settings()
    except ValueError as e:
        print(f"Mail relay settings are invalid: {e} 🔴")  # for the operator; the client gets no internals
        raise HTTPException(status_code=500, detail="The mail relay is not configured correctly")
    if smtp is not None:
        try:
            await asyncio.to_thread(send_smtp_email, smtp, recipient_email, subject, msg)
            print("Email sent through the configured SMTP relay")
            return
        except MailAddressError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            print(f"Error sending email through SMTP relay {smtp['host']}:{smtp['port']}: {e} 🔴")
            raise HTTPException(status_code=500, detail="Could not send the email through the configured mail relay")

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


# Local-only: fixed OTP for demo login (set in backend/.env; omit in prod).
LOCAL_DEV_VERIFICATION_EMAIL = os.getenv("LOCAL_DEV_VERIFICATION_EMAIL", "").strip().lower()
LOCAL_DEV_VERIFICATION_CODE = os.getenv("LOCAL_DEV_VERIFICATION_CODE", "").strip()

# Permanent fixed OTPs for specific accounts (prod + local). Only these emails;
# emailed/random codes for them are ignored — only the hardcoded code is accepted.
HARDCODED_VERIFICATION_CODES: dict[str, str] = {
    "shivam@cyberultron.com": "123456",
    "demo@rapipay.com": "123456",
}


def hardcoded_verification_code_for_email(email: str) -> str | None:
    return HARDCODED_VERIFICATION_CODES.get((email or "").strip().lower())


def local_dev_verification_enabled(email: str) -> bool:
    return bool(
        LOCAL_DEV_VERIFICATION_EMAIL
        and LOCAL_DEV_VERIFICATION_CODE
        and email.strip().lower() == LOCAL_DEV_VERIFICATION_EMAIL
    )


def verification_code_is_valid(session: Session, email: str, code: str) -> bool:
    fixed = hardcoded_verification_code_for_email(email)
    if fixed is not None:
        return (code or "").strip() == fixed
    if local_dev_verification_enabled(email) and code == LOCAL_DEV_VERIFICATION_CODE:
        return True
    row = session.exec(
        select(VerificationCode).where(
            VerificationCode.email == email,
            VerificationCode.code == code,
            VerificationCode.expires_at >= datetime.now(timezone.utc),
        )
    ).first()
    return row is not None


def generate_verification_code():
    import secrets
    code = ''.join(secrets.choice('0123456789') for _ in range(6))
    return code

def create_and_store_verification_code(recipient_email: str, engine: Engine) -> str:
    """Fast DB-only insert. Returns 6-digit code."""
    fixed = hardcoded_verification_code_for_email(recipient_email)
    if fixed is not None:
        with Session(engine) as session:
            session.exec(delete(VerificationCode).where(VerificationCode.email == recipient_email))
            session.add(VerificationCode(email=recipient_email, code=fixed))
            session.commit()
        return fixed
    if local_dev_verification_enabled(recipient_email):
        return LOCAL_DEV_VERIFICATION_CODE
    code = generate_verification_code()
    with Session(engine) as session:
        verification_code = VerificationCode(email=recipient_email, code=code)
        session.add(verification_code)
        session.commit()
    return code

def send_verification_email(recipient_email: str, code: str):
    """Synchronous wrapper for background task. Sends email without blocking request."""
    body = create_verification_email_html(code)
    try:
        # Using asyncio.run to wrap the async call in sync context
        import asyncio
        asyncio.run(send_outlook_email(
            recipient_email=recipient_email,
            subject="Verification code",
            html_body=body))
    except Exception as e:
        print(f"Background email send failed for {recipient_email}: {e} 🔴")

async def send_verification_email_async(recipient_email: str, code: str):
    """Async email sender for truly non-blocking background execution."""
    body = create_verification_email_html(code)
    try:
        await send_outlook_email(
            recipient_email=recipient_email,
            subject="Verification code",
            html_body=body)
        print(f"✓ Verification email sent to {recipient_email} in background")
    except Exception as e:
        print(f"Background email send failed for {recipient_email}: {e} 🔴")

async def send_verification_code_and_save_to_db( recipient_email: str , engine: Engine):
    fixed = hardcoded_verification_code_for_email(recipient_email)
    code = fixed if fixed is not None else generate_verification_code()
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
        if fixed is not None:
            session.exec(delete(VerificationCode).where(VerificationCode.email == recipient_email))
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