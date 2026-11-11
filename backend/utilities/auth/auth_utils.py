import asyncio
import hmac
import logging
import os
import re
import secrets
import smtplib
import threading
import unicodedata
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from typing import Any, Optional, Union

import bcrypt as _bcrypt
import msal
import requests
from argon2 import PasswordHasher, Type as _Argon2Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from dotenv import load_dotenv
from fastapi import HTTPException, status
from jose import JWTError, jwt
from sqlalchemy import Engine, case, func, or_
from sqlmodel import Session, delete, select, update

from backend.new_models import AuthCounter, User, VerificationCode
from backend.utilities.auth.html_email import create_verification_email_html

load_dotenv()

log = logging.getLogger("backend.auth")

ACCESS_TOKEN_EXPIRE_MINUTES = 30  # 30 minutes
REFRESH_TOKEN_EXPIRE_MINUTES = 60 * 8 # 8 hours
ALGORITHM = "HS256"
JWT_SECRET_KEY = os.environ['JWT_SECRET_KEY']     # should be kept secret
JWT_REFRESH_SECRET_KEY = os.environ['JWT_REFRESH_SECRET_KEY']      # should be kept secret
MIN_JWT_SECRET_BYTES = 32


def dev_mode() -> bool:
    """DSS_DEV_MODE=1 marks a development server: the fixed local sign-in code works and weak JWT secrets are
    tolerated.  Never set it on a server real users reach."""
    return os.getenv("DSS_DEV_MODE", "").strip() == "1"


def jwt_secret_problems() -> list[str]:
    problems = []
    if hmac.compare_digest(JWT_SECRET_KEY.encode(), JWT_REFRESH_SECRET_KEY.encode()):
        problems.append("JWT_SECRET_KEY and JWT_REFRESH_SECRET_KEY are equal (a refresh token would work as an access token)")
    for name, value in (("JWT_SECRET_KEY", JWT_SECRET_KEY), ("JWT_REFRESH_SECRET_KEY", JWT_REFRESH_SECRET_KEY)):
        if len(value.encode("utf-8")) < MIN_JWT_SECRET_BYTES:
            problems.append(f"{name} is shorter than {MIN_JWT_SECRET_BYTES} bytes")
    return problems


def check_startup_security() -> None:
    """Called once per worker at start-up: refuse weak JWT secrets unless DSS_DEV_MODE=1, and say loudly when
    dev mode is on."""
    problems = jwt_secret_problems()
    if dev_mode():
        log.warning("DSS_DEV_MODE=1: development server. The fixed local sign-in code is accepted for sign-in and "
                    "sign-up (never for password reset) and weak JWT secrets are tolerated. Never use this setting "
                    "on a server real users reach.")
        for problem in problems:
            log.warning("DSS_DEV_MODE=1 tolerates: %s", problem)
        return
    if problems:
        raise RuntimeError("Refusing to start: " + "; ".join(problems)
                           + ". Generate each secret with `openssl rand -hex 32`.")


# ----------------------------------------------------------------------------------------------------- tokens

def _encode(subject: Union[str, Any], typ: str, version: int, expires: timedelta, secret: str) -> str:
    now = datetime.now(timezone.utc)
    claims = {"sub": str(subject), "exp": now + expires, "iat": now, "typ": typ, "ver": int(version)}
    return jwt.encode(claims, secret, ALGORITHM)


def create_access_token(subject: Union[str, Any], expires_delta: Optional[timedelta] = None, version: int = 0) -> str:
    expires = expires_delta if expires_delta is not None else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return _encode(subject, "access", version, expires, JWT_SECRET_KEY)


def create_refresh_token(subject: Union[str, Any], expires_delta: Optional[timedelta] = None, version: int = 0) -> str:
    expires = expires_delta if expires_delta is not None else timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    return _encode(subject, "refresh", version, expires, JWT_REFRESH_SECRET_KEY)


def _verified_claims(token: str, secret: str, typ: str) -> Optional[dict]:
    """Signature, expiry (required), subject and type checked; None when anything is wrong.

    Tokens issued before ``typ``/``ver`` existed carry neither: the secret that verifies them already tells an
    access token from a refresh token, and their version counts as 0."""
    try:
        claims = jwt.decode(token, secret, algorithms=[ALGORITHM], options={"require_exp": True, "require_sub": True})
    except (JWTError, ValueError, TypeError):
        return None
    if claims.get("typ", typ) != typ:
        return None
    subject, version = claims.get("sub"), claims.get("ver", 0)
    if not isinstance(subject, str) or not subject or not isinstance(version, int) or isinstance(version, bool):
        return None
    return claims


PASSWORD_CHANGE_TOKEN_MINUTES = 10


def create_password_change_token(subject: str, version: int) -> str:
    """Issued by sign-in instead of a session when the account must choose a new password (its current one was
    mailed to it by somebody else).  It only works on POST /change_password, once (that bumps the token version)."""
    return _encode(subject, "pwchange", version, timedelta(minutes=PASSWORD_CHANGE_TOKEN_MINUTES), JWT_SECRET_KEY)


def password_change_claims(token: str) -> Optional[dict]:
    """Claims of a valid password-change token; its type must be stated (an old token without one never counts)."""
    claims = _verified_claims(token, JWT_SECRET_KEY, "pwchange")
    return claims if claims is not None and claims.get("typ") == "pwchange" else None


def access_token_subject(token: str) -> Optional[str]:
    """The subject of a validly signed, unexpired access token (no database lookup; used for rate-limit keys)."""
    claims = _verified_claims(token, JWT_SECRET_KEY, "access")
    return claims["sub"] if claims else None


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user_from_access_token(engine: Engine, token: str, ignore_session_active: bool = False) -> User:
    claims = _verified_claims(token, JWT_SECRET_KEY, "access")
    if claims is None:
        raise _unauthorized()
    with Session(engine) as session:
        user = session.exec(select(User).where(User.email == claims["sub"])).first()
        if user is None:
            raise _unauthorized()
        if claims.get("ver", 0) < (user.token_version or 0):
            log.info("access token refused: issued before the account's tokens were revoked (user_id=%s)", user.id)
            raise _unauthorized()
        if not user.session_active and not ignore_session_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Session not active",
            )
        user.last_active = datetime.now(timezone.utc)
        session.add(user)
        session.commit()
        session.refresh(user)
    return user


async def get_current_user_from_refresh_token(engine: Engine, token: str) -> User:
    claims = _verified_claims(token, JWT_REFRESH_SECRET_KEY, "refresh")
    if claims is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    with Session(engine) as session:
        user = session.exec(select(User).where(User.email == claims["sub"])).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Could not find user")
    if claims.get("ver", 0) < (user.token_version or 0):
        log.info("refresh token refused: issued before the account's tokens were revoked (user_id=%s)", user.id)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.session_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Session not active")
    return user


async def get_user_from_header_or_raise_exception(engine: Engine,Authorization: str | None = None, ignore_session_active: bool = False)->User:
    if not Authorization:
        raise HTTPException(status_code=401, detail="Unauthorized")
    parts = Authorization.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="Invalid Authorization header format")
    access_token = parts[1]
    user = await get_current_user_from_access_token(engine, access_token, ignore_session_active)
    return user


# -------------------------------------------------------------------------------------------------- passwords
# Argon2id with the OWASP minimum (19 MiB, 2 passes, 1 lane): ~20 ms per hash on a 2-vCPU host.  passlib is not
# used: its argon2 loader reads the deprecated ``argon2.__version__``.  Legacy bcrypt hashes still verify and
# are replaced by an Argon2id hash at the next successful sign-in.

MIN_NEW_PASSWORD_CHARS = 8
MAX_PASSWORD_CHARS = 128
MAX_PASSWORD_BYTES = 512
# Refused before normalising: NFC composes at most four code points into one, so no password whose NFC form fits
# MAX_PASSWORD_BYTES is longer than this as sent.
MAX_PASSWORD_INPUT_CHARS = 8 * MAX_PASSWORD_BYTES
_BCRYPT_PREFIXES = ("$2a$", "$2b$", "$2y$")
_ARGON2_PREFIX = "$argon2"
_HASHER = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1, hash_len=32, salt_len=16,
                         type=_Argon2Type.ID)
# Each hash holds 19 MiB: cap the concurrent ones per worker (2 vCPUs gain nothing from more).
_HASH_SLOTS = threading.BoundedSemaphore(4)


def normalise_password(password: str) -> str:
    return unicodedata.normalize("NFC", password)


def login_password_problem(password: str) -> Optional[str]:
    """Why a password offered at SIGN-IN is refused before it is hashed, or None: 1 to MAX_PASSWORD_BYTES UTF-8
    bytes after NFC normalisation.  Wider than the new-password rule so every stored password still signs in
    (older rules allowed 5..24 characters, admin-made accounts had no length rule); the byte cap bounds the
    hashing cost."""
    if not password:
        return "Enter your password"
    if len(password) > MAX_PASSWORD_INPUT_CHARS \
            or len(normalise_password(password).encode("utf-8")) > MAX_PASSWORD_BYTES:
        return f"Password must be at most {MAX_PASSWORD_BYTES} bytes long"
    return None


def new_password_problem(password: str) -> Optional[str]:
    """Why a NEW password (sign-up, reset, admin-created) is refused, or None.  Counted in Unicode code
    points after NFC normalisation."""
    if len(password or "") > MAX_PASSWORD_INPUT_CHARS:
        return f"Password must be {MIN_NEW_PASSWORD_CHARS} to {MAX_PASSWORD_CHARS} characters long"
    value = normalise_password(password or "")
    if not MIN_NEW_PASSWORD_CHARS <= len(value) <= MAX_PASSWORD_CHARS:
        return f"Password must be {MIN_NEW_PASSWORD_CHARS} to {MAX_PASSWORD_CHARS} characters long"
    if len(value.encode("utf-8")) > MAX_PASSWORD_BYTES:
        return f"Password must be at most {MAX_PASSWORD_BYTES} bytes long"
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        return "Password must not contain control characters"
    return None


def get_hashed_password(password: str) -> str:
    with _HASH_SLOTS:
        return _HASHER.hash(normalise_password(password))


def _matches(candidate: str, stored: str) -> bool:
    if stored.startswith(_ARGON2_PREFIX):
        try:
            return _HASHER.verify(stored, candidate)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False
    if stored.startswith(_BCRYPT_PREFIXES):
        try:  # bcrypt only ever read the first 72 bytes; bcrypt 5 refuses longer input instead of truncating
            return _bcrypt.checkpw(candidate.encode("utf-8")[:72], stored.encode("ascii"))
        except ValueError:
            return False
    return False


def verify_and_update_password(password: str, stored: str) -> tuple[bool, Optional[str]]:
    """(matches, new_hash).  ``new_hash`` is set when the stored hash is legacy bcrypt or older Argon2 settings.

    The NFC form is tried first; the raw string second (legacy hashes were made without normalisation)."""
    if not password or not stored:
        return False, None
    normalised = normalise_password(password)
    candidates = [normalised] if normalised == password else [normalised, password]
    with _HASH_SLOTS:
        if not any(_matches(candidate, stored) for candidate in candidates):
            return False, None
        if stored.startswith(_ARGON2_PREFIX) and not _HASHER.check_needs_rehash(stored):
            return True, None
        return True, _HASHER.hash(normalised)


def verify_password(password: str, hashed_pass: str) -> bool:
    return verify_and_update_password(password, hashed_pass)[0]


# ------------------------------------------------------------------------------------------------------- mail

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
        log.info("email sent")
    except Exception as e:
        log.error("email could not be sent: %s", type(e).__name__)
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


_MAIL_SECRET_SETTINGS = ("SMTP_PASSWORD", "CLIENT_SECRET")


def mail_failure_cause(exc: BaseException, recipient: str = "") -> str:
    """Why a mail was not sent, for the server log only (the client gets a generic message): the NAME of a missing
    setting, else the error class and its message cut to 200 characters, with the configured mail secrets and the
    recipient's address blanked."""
    if isinstance(exc, KeyError):
        return f"missing setting {exc.args[0]}" if exc.args else "missing setting"
    text = str(exc)
    for name in _MAIL_SECRET_SETTINGS:
        secret = os.environ.get(name) or ""
        if len(secret) >= 4:
            text = text.replace(secret, "***")
    if recipient:
        text = re.sub(re.escape(recipient), "<recipient>", text, flags=re.I)
    text = " ".join(text.split())[:200]
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__


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
        log.error("mail relay settings are invalid: %s", e)  # for the operator; the client gets no internals
        raise HTTPException(status_code=500, detail="The mail relay is not configured correctly")
    if smtp is not None:
        try:
            await asyncio.to_thread(send_smtp_email, smtp, recipient_email, subject, msg)
            log.info("email sent through the configured SMTP relay")
            return
        except MailAddressError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            log.error("email could not be sent through SMTP relay %s:%s: %s", smtp['host'], smtp['port'],
                      mail_failure_cause(e, recipient_email))
            raise HTTPException(status_code=500, detail="Could not send the email through the configured mail relay")

    try:
        await asyncio.to_thread(_send_graph_mail, recipient_email, subject, html_body)
    except Exception as e:
        # The cause (missing TENANT_ID, a Graph error body ...) goes to the log only, never to the client.
        log.error("email could not be sent through Microsoft Graph: %s", mail_failure_cause(e, recipient_email))
        raise HTTPException(status_code=500, detail="Could not send the email") from None


GRAPH_TIMEOUT_S = 20


def _send_graph_mail(recipient_email: str, subject: str, html_body: str) -> None:
    """Microsoft Graph sendMail as the support mailbox. Blocking (msal + requests), so callers run it in a thread."""
    tenant_id = os.environ["TENANT_ID"]
    client_id = os.environ["CLIENT_ID"]
    client_secret = os.environ["CLIENT_SECRET"]
    sender = "support@zeroshield.ai"  # must exist in the Microsoft 365 tenant
    app = msal.ConfidentialClientApplication(
        client_id, authority=f"https://login.microsoftonline.com/{tenant_id}", client_credential=client_secret,
        timeout=GRAPH_TIMEOUT_S,
    )
    token = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    if "access_token" not in token:
        raise RuntimeError("Microsoft Graph authentication failed")
    email_data = {"message": {"subject": subject, "body": {"contentType": "HTML", "content": html_body},
                              "toRecipients": [{"emailAddress": {"address": recipient_email}}]}}
    response = requests.post(f"https://graph.microsoft.com/v1.0/users/{sender}/sendMail",
                             headers={"Authorization": f"Bearer {token['access_token']}", "Content-Type": "application/json"},
                             json=email_data, timeout=GRAPH_TIMEOUT_S)
    if response.status_code != 202:
        raise RuntimeError(f"Microsoft Graph sendMail returned {response.status_code}")
    log.info("email sent through Microsoft Graph")


# ------------------------------------------------------------------------------------------------ sign-in codes
# One live code per email (sending replaces it).  Every guess first charges an attempt to the live code with one
# UPDATE ... WHERE attempts < MAX_CODE_ATTEMPTS RETURNING code, which locks the row; only a guess that got an
# attempt is compared (in constant time), and the right one deletes the code in the same transaction.  So a code
# is compared at most MAX_CODE_ATTEMPTS times and works once, however many guesses arrive at the same moment.
# New codes per email are capped per hour in Postgres (all workers and replicas share the count): at most
# CODE_SENDS_PER_EMAIL x MAX_CODE_ATTEMPTS guesses per email per hour.  Past the cap the LIVE code is mailed again
# (at most once per CODE_RESEND_INTERVAL) instead of refusing, so somebody else requesting codes for an address
# cannot lock its owner out; only when that code is also spent is the request refused until the window ends.

CODE_TTL = timedelta(minutes=10)
MAX_CODE_ATTEMPTS = 5
CODE_SENDS_PER_EMAIL = 5
CODE_SEND_WINDOW = timedelta(hours=1)
CODE_RESEND_INTERVAL = timedelta(seconds=60)
# The fixed code that was once accepted for two named accounts; rows holding it are deleted at start-up.
RETIRED_FIXED_CODES = ("123456",)


def normalise_email(email: Optional[str]) -> str:
    return (email or "").strip().lower()


def normalise_code(code: Optional[str]) -> str:
    """Codes are often pasted with spaces ("123 456") or a trailing newline."""
    return "".join((code or "").split())


def dev_verification_code_for(email: str) -> Optional[str]:
    """The fixed code of the local development account (LOCAL_DEV_VERIFICATION_EMAIL/CODE), only while
    DSS_DEV_MODE=1.  Callers never offer it for password reset."""
    if not dev_mode():
        return None
    dev_email = normalise_email(os.getenv("LOCAL_DEV_VERIFICATION_EMAIL"))
    dev_code = normalise_code(os.getenv("LOCAL_DEV_VERIFICATION_CODE"))
    if dev_email and dev_code and normalise_email(email) == dev_email:
        return dev_code
    return None


class CodeSendLimited(Exception):
    def __init__(self, retry_after: int):
        super().__init__("too many verification codes requested")
        self.retry_after = retry_after


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _naive(moment: datetime) -> datetime:
    return moment.astimezone(timezone.utc).replace(tzinfo=None) if moment.tzinfo else moment


def _insert_for(session: Session):
    """INSERT ... ON CONFLICT for the two databases this runs on (Postgres in production, SQLite in tests)."""
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    elif dialect == "sqlite":
        from sqlalchemy.dialects.sqlite import insert
    else:
        raise RuntimeError(f"unsupported database for auth counters: {dialect}")
    return insert


def charge_auth_counter(session: Session, key: str, window: timedelta, now: datetime) -> tuple[int, datetime]:
    """Fixed window shared by every worker and replica: add one hit to ``key`` and return (hits, window start).
    One atomic upsert, so concurrent requests can neither lose a hit nor both open a new window."""
    expired = AuthCounter.window_start <= now - window
    insert = _insert_for(session)
    statement = (
        insert(AuthCounter)
        .values(key=key, window_start=now, hits=1)
        .on_conflict_do_update(
            index_elements=[AuthCounter.key],
            set_={"hits": case((expired, 1), else_=AuthCounter.hits + 1),
                  "window_start": case((expired, now), else_=AuthCounter.window_start)},
        )
        .returning(AuthCounter.hits, AuthCounter.window_start)
    )
    row = session.exec(statement).first()
    return int(row[0]), row[1]


def _seconds_left(started: datetime, window: timedelta, now: datetime) -> int:
    return max(1, int((_naive(started) + window - _naive(now)).total_seconds()) + 1)


def _resend_live_code(session: Session, email: str, now: datetime, send_window_left: int) -> str:
    """Past the per-email cap: the live code again (attempts kept, expiry renewed), never a new one.  Raises
    CodeSendLimited when there is no live code (the hour's guess budget is spent) or it was re-sent less than
    CODE_RESEND_INTERVAL ago (bounds the mail to the address)."""
    live = session.exec(
        select(VerificationCode)
        .where(VerificationCode.email == email, VerificationCode.expires_at >= now,
               VerificationCode.attempts < MAX_CODE_ATTEMPTS)
        .with_for_update()
    ).first()
    if live is None:
        session.commit()
        raise CodeSendLimited(send_window_left)
    hits, started = charge_auth_counter(session, f"resend_code:{email}", CODE_RESEND_INTERVAL, _naive(now))
    if hits > 1:
        session.commit()
        raise CodeSendLimited(_seconds_left(started, CODE_RESEND_INTERVAL, now))
    live.expires_at = now + CODE_TTL
    session.add(live)
    session.commit()
    return live.code


def issue_verification_code(engine: Engine, email: str) -> Optional[str]:
    """The code to mail to ``email`` (the caller sends it): a fresh code that replaces any earlier one, or, past
    CODE_SENDS_PER_EMAIL new codes within CODE_SEND_WINDOW, the live code again (see _resend_live_code).

    Returns None for the local development account while DSS_DEV_MODE=1 (its fixed code is not stored and no
    mail is sent).  Raises CodeSendLimited when nothing may be sent now."""
    email = normalise_email(email)
    now = _utcnow()
    with Session(engine) as session:
        # counters use naive UTC so the database session's time zone can never shift a window
        hits, started = charge_auth_counter(session, f"send_code:{email}", CODE_SEND_WINDOW, _naive(now))
        if hits > CODE_SENDS_PER_EMAIL:
            if hits == CODE_SENDS_PER_EMAIL + 1:
                log.warning("verification code cap: %d codes already made for this email within %s; "
                            "re-sending the live code from now on", CODE_SENDS_PER_EMAIL, CODE_SEND_WINDOW)
            return _resend_live_code(session, email, now, _seconds_left(started, CODE_SEND_WINDOW, now))
        if dev_verification_code_for(email) is not None:
            session.commit()
            log.warning("DSS_DEV_MODE: no code sent to the local dev account; its fixed code applies")
            return None
        code = "".join(secrets.choice("0123456789") for _ in range(6))
        fresh = dict(code=code, created_at=now, expires_at=now + CODE_TTL, attempts=0)
        insert = _insert_for(session)
        session.exec(  # replaces the email's earlier code (unique email): only the newest code works
            insert(VerificationCode).values(email=email, **fresh)
            .on_conflict_do_update(index_elements=[VerificationCode.email], set_=fresh)
        )
        session.commit()
    return code


def _code_matches(stored: str, guess: str) -> bool:
    return hmac.compare_digest(stored.encode("utf-8"), guess.encode("utf-8"))


def consume_verification_code(engine: Engine, email: str, code: str, *, allow_dev_code: bool) -> bool:
    """True exactly once for the email's live, unexpired code.  Every guess is charged an attempt BEFORE it is
    compared (the charging UPDATE locks the row), so at most MAX_CODE_ATTEMPTS guesses are ever compared with one
    code; a wrong guess that used the last attempt deletes the code.  ``allow_dev_code`` is False for password
    reset."""
    email = normalise_email(email)
    code = normalise_code(code)
    if not email:
        return False
    if allow_dev_code and code:
        dev_code = dev_verification_code_for(email)
        if dev_code is not None and hmac.compare_digest(code.encode(), dev_code.encode()):
            log.warning("DSS_DEV_MODE: the fixed local sign-in code was accepted for the local dev account")
            return True
    now = _utcnow()
    with Session(engine) as session:
        charged = session.exec(
            update(VerificationCode)
            .where(VerificationCode.email == email,
                   VerificationCode.attempts < MAX_CODE_ATTEMPTS,
                   VerificationCode.expires_at >= now)
            .values(attempts=VerificationCode.attempts + 1)
            .returning(VerificationCode.id, VerificationCode.code, VerificationCode.attempts)
        ).first()
        if charged is None:  # no live code: none sent, expired, used, or out of attempts
            session.commit()
            return False
        row_id, live_code, attempts = charged
        if code and _code_matches(live_code, code):
            session.exec(delete(VerificationCode).where(VerificationCode.id == row_id))
            session.commit()
            return True
        if attempts >= MAX_CODE_ATTEMPTS:
            session.exec(delete(VerificationCode).where(VerificationCode.id == row_id))
            log.warning("verification code invalidated after %d wrong attempts", MAX_CODE_ATTEMPTS)
        session.commit()
    return False


def purge_unusable_verification_codes(engine: Engine) -> int:
    """At start-up: delete expired codes and, unless DSS_DEV_MODE=1, rows holding a retired fixed code."""
    conditions = [VerificationCode.expires_at < _utcnow()]
    if not dev_mode():
        conditions.append(VerificationCode.code.in_(RETIRED_FIXED_CODES))
    with Session(engine) as session:
        result = session.exec(delete(VerificationCode).where(or_(*conditions)))
        session.commit()
    return int(result.rowcount or 0)


def send_verification_email(recipient_email: str, code: str) -> None:
    """Send the sign-in code. Synchronous (the router runs it in the threadpool) and RAISES when the mail could not
    be sent, so the user is told instead of waiting for a code that never arrives."""
    body = create_verification_email_html(code)
    asyncio.run(send_outlook_email(recipient_email=recipient_email, subject="Verification code", html_body=body))


def user_by_email(session: Session, email: str) -> Optional[User]:
    """Case-insensitive: accounts created before emails were lower-cased keep their stored spelling."""
    return session.exec(
        select(User).where(func.lower(User.email) == normalise_email(email)).order_by(User.id)
    ).first()
