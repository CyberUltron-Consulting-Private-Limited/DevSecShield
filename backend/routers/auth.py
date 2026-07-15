import datetime
from fastapi import APIRouter, BackgroundTasks
from typing import Annotated
from fastapi import Depends, HTTPException, status , Header
from rich.console import Console
from sqlmodel import Session, delete, select, update
from starlette.concurrency import run_in_threadpool
from backend.new_models import Team
from backend.utilities.auth.auth_utils import (
    create_access_token,
    create_refresh_token,
    get_hashed_password,
    send_verification_code_and_save_to_db,
    verify_password,
    get_current_user_from_refresh_token,
    get_current_user_from_access_token,
    get_user_from_header_or_raise_exception,
    create_and_store_verification_code,
    local_dev_verification_enabled,
    send_verification_email,
    verification_code_is_valid,
)
from backend.new_models import *
from backend.utilities.auth.auth_schema import TokenSchema , ResetPassword ,CodeSend ,RefreshToken, UserLogin, UserSignup
from fastapi_throttle import RateLimiter
import psycopg2
from backend.get_db import get_db , get_mongo_client_db
from rich.console import Console
from starlette.concurrency import run_in_threadpool
console = Console()


router = APIRouter(
    tags=["auth"]
)


# SECURITY: Tiered rate limiting for auth endpoints
limiter = RateLimiter(times=20, seconds=30)  # General: 20 requests per 30 seconds
limiter_strict = RateLimiter(times=5, seconds=60)  # Strict: 5 requests per 60 seconds (login, signup)
limiter_very_strict = RateLimiter(times=3, seconds=120)  # Very strict: 3 requests per 120 seconds (verification codes)

@router.post('/signup', summary="Create new user", dependencies=[Depends(limiter_strict)])
async def create_user(data: UserSignup):
    """
    Request Fields:
    - email: str
    - verification_code: str
    - password: str
    - first_name: str
    - last_name: str
    """
    try:

        engine = get_db()
        mongo_client_db = get_mongo_client_db()

        # STEP 1-------------verifying verification code
        with Session(engine) as session:
            if not verification_code_is_valid(session, data.email, data.verification_code):
                print("invalid verification code 🔴")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid or expired verification code",
                )
            print("code verified and performing cleanup 🟩")
            session.exec(delete(VerificationCode).where(VerificationCode.email == data.email))
            session.commit()

        # STEP 2-------------querying database to check if user already exist
        with Session(engine) as session:
            user = session.exec(select(User).where(User.email == data.email)).first()
        if user is not None:
                raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email already exist"
            )
        with Session(engine) as session:
            new_team = Team(
                name=f"{data.first_name}'s Default Team",
                description=f"Default team for {data.first_name}",
            )
            session.add(new_team)
            session.commit()
            session.refresh(new_team)
            hashed_password = await run_in_threadpool(get_hashed_password, data.password)
            new_user = User(
                email=data.email, 
                password=hashed_password,
                first_name=data.first_name,
                last_name=data.last_name,
                session_active=True, # activating session for new user
                teams =  [ new_team ],
                default_team_id = new_team.id
            )
            team_membership = TeamMembership( team=new_team, user=new_user, role="admin" )
            session.add(team_membership)
            session.commit()
            session.refresh(new_user)

            return {
                "access_token": create_access_token(new_user.email),
                "refresh_token": create_refresh_token(new_user.email),
            }
    except Exception as e:
        Console().print(f"An error has occured : {str(e)}",style="bold red")
        if isinstance(e,psycopg2.Error):
            raise HTTPException(status_code=500, detail="Server is busy, please try again later")
        if isinstance(e,HTTPException):
            raise e
        raise HTTPException(status_code=403, detail="Could not create user, please try again later")

@router.post('/login', summary="Create access and refresh tokens for user. body should be form data", response_model=TokenSchema, dependencies=[Depends(limiter_strict)])
async def login(form_data: UserLogin):
    """
    Request Fields:
    - email: str
    - verification_code: str
    - password: str

    """

    try:
        engine = get_db()
        mongo_client_db = get_mongo_client_db()


        # STEP 1-------------verifying verification code
        with Session(engine) as session:
            if not verification_code_is_valid(session, form_data.email, form_data.verification_code):
                print("invalid verification code 🔴")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid verification code",
                )
            print("code verified and performing cleanup 🟩")
            session.exec(delete(VerificationCode).where(VerificationCode.email == form_data.email))
            session.commit()

        # STEP 2-------------querying database to check if user already exist
        with Session(engine) as session:
            user = session.exec(select(User).where(User.email == form_data.email)).first()
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect email or password"
            )

        hashed_pass = user.password
        is_valid = await run_in_threadpool(verify_password, form_data.password, hashed_pass)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect email or password"
            )


        # STEP 3-------------activating session
        with Session(engine) as session:
            statement = select(User).where(User.id == user.id)
            user = session.exec(statement).first()
            user.session_active = True
            session.add(user)
            session.commit()
            session.refresh(user)
            print(f"user {user.email} logged in and session activated 🟩")

        return {
            "access_token": create_access_token(user.email),
            "refresh_token": create_refresh_token(user.email),
        }
    except Exception as e:
        if isinstance(e,psycopg2.Error):
            raise HTTPException(status_code=500, detail="Server is busy, please try again later")
        if isinstance(e,HTTPException):
            raise e
        raise HTTPException(status_code=403, detail="Could not login user, Check credentials and try again")

@router.post('/refresh', summary="Create new access token from refresh token", dependencies=[Depends(limiter)])
async def refresh(data:RefreshToken,Authorization: Annotated[str | None, Header()] = None, ):
    """
    Request Fields:
    - refresh_token: str
    """
    try:
        engine = get_db()
        mongo_client_db = get_mongo_client_db()


        refresh_token = data.refresh_token
        # checking if refresh token is valid
        user = await get_current_user_from_refresh_token(engine, refresh_token)

        # if refresh token is invalid
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect refresh token"
            )

        # if refresh token is valid
        return {
            "access_token": create_access_token(user.email),
        }
    except Exception as e:
        if isinstance(e,psycopg2.Error):
            raise HTTPException(status_code=500, detail="Server is busy, please try again later")
        if isinstance(e,HTTPException):
            raise e
        raise HTTPException(status_code=403, detail="Could not refresh token, please try again later")

@router.get('/get_user', summary="Get user details", dependencies=[Depends(limiter)])
async def get_user(Authorization: Annotated[str | None, Header()] = None):
    try:
        engine = get_db()
        mongo_client_db = get_mongo_client_db()
        
        if Authorization is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization header is required"
            )


        parts = Authorization.split(" ")
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Authorization header format"
            )
        access_token = parts[1]
        user = await get_current_user_from_access_token(engine, access_token)
        return {
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "profile_photo": user.profile_photo
        }
    except Exception as e:
        Console().print(f"error in get_user: {e} 🔴", style="bold red")
        if isinstance(e,psycopg2.Error):
            raise HTTPException(status_code=500, detail="Server is busy, please try again later")
        if isinstance(e,HTTPException):
            raise e
        raise HTTPException(status_code=403, detail="Could not get user details, please try again later")

@router.post("/send_code", summary="Send verification code to user", dependencies=[Depends(limiter_very_strict)])
async def send_verification_code(data: CodeSend, background_tasks: BackgroundTasks):
    """
    Request Fields:
    - email: str
    
    This endpoint returns immediately after storing the code in DB.
    Email sending happens in background, so response is <50ms.
    """
    try:
        engine = get_db()
        mongo_client_db = get_mongo_client_db()

        # STEP 1: Fast DB insert - returns immediately (fixed code for local demo user)
        code = create_and_store_verification_code(data.email, engine)

        # STEP 2: Queue email (skipped for local fixed-OTP demo account)
        if not local_dev_verification_enabled(data.email):
            background_tasks.add_task(send_verification_email, data.email, code)
        
        return {
            "message": "Verification code sent to user"
        }
    except Exception as e:
        Console().print(f"error in send_verification_code: {e} 🔴", style="bold red")
        if isinstance(e,psycopg2.Error):
            raise HTTPException(status_code=500, detail="Server is busy, please try again later")
        if isinstance(e,HTTPException):
            raise e
        raise HTTPException(status_code=400, detail="Could not send verification code, please try again later")

@router.post("/reset_password", summary="Reset password for user", dependencies=[Depends(limiter)])
async def reset_password(data: ResetPassword):
    """
    Request Fields:
    - email: str
    - verification_code: str
    - password: str
    """
    try:
        engine = get_db()
        mongo_client_db = get_mongo_client_db()

        # STEP 1-------------verifying verification code
        with Session(engine) as session:
            if not verification_code_is_valid(session, data.email, data.verification_code):
                Console().print("invalid verification code 🔴", style="bold red")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid or expired verification code",
                )
            session.exec(delete(VerificationCode).where(VerificationCode.email == data.email))
            session.commit()

        # STEP 2-------------updating password
        with Session(engine) as session:
            hashed_pwd = await run_in_threadpool(get_hashed_password, data.password)
            session.exec(update(User).where(User.email == data.email).values(password=hashed_pwd))
            session.commit()
            user = session.exec(select(User).where(User.email == data.email)).first()
        return {
            "message": f"Password reset successfully for user {user.email}"
        }
    except Exception as e:
        if isinstance(e,psycopg2.Error):
            raise HTTPException(status_code=500, detail="Server is busy, please try again later")
        if isinstance(e,HTTPException):
            raise e
        raise HTTPException(status_code=403, detail="Could not reset password, please try again later")

@router.get("/logout", summary="Logout user", dependencies=[Depends(limiter)])
async def logout(Authorization: Annotated[str | None, Header()] = None):
    """
    Request Fields:
    - Authorization: str
    """
    try:
        engine = get_db()
        mongo_client_db = get_mongo_client_db()

        user = await get_user_from_header_or_raise_exception(engine, Authorization, ignore_session_active=True)
        with Session(engine) as session:
            statement = select(User).where(User.id == user.id)
            user = session.exec(statement).first()

            if user is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User not found"
                )

            user.session_active = False
            session.add(user)
            session.commit()
            session.refresh(user)
            print(f"user {user.email} logged out and session deactivated 🟩")
        return {
            "message": f"User {user.email} logged out and session deactivated 🟩"
        }, 200
    except Exception as e:
        if isinstance(e,psycopg2.Error):
            raise HTTPException(status_code=500, detail="Server is busy, please try again later")
        if isinstance(e,HTTPException):
            raise e
        print(f"error in logout: {e} 🔴")
        raise HTTPException(status_code=403, detail="Could not logout user, please try again later")