from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, Header, status, APIRouter
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.engine import Engine
from sqlmodel import Session, select
from pydantic import BaseModel, field_validator
from backend.utilities.auth.auth_schema import NoEchoValidationRoute, clean_email, clean_new_password
import datetime
from backend.utilities.auth.auth_utils import (
    SET_PASSWORD_LINK_TTL, create_password_change_token, get_user_from_header_or_raise_exception, get_hashed_password,
    user_by_email,
)
from backend.utilities.ratelimit import RateLimiter
from backend.new_models import Team, TeamMembership, User
from backend.utilities.auth.plans import plans
from backend.utilities.auth import email as account_mail
from backend.utilities.auth.email import set_password_link
import psycopg2
from backend.get_db import get_db , get_mongo_client_db
from backend.utilities.db.admin import delete_team_associated_data
from rich.console import Console
console = Console()

class CreateUserData(BaseModel):
    email: str
    password: str
    plan: str
    first_name: str
    last_name: str

class CreateAdminUserData(BaseModel):
    email: str
    password: str  # 8 to 128 characters, the same rules as sign-up
    first_name: str
    last_name: str

    check_email = field_validator("email")(clean_email)
    check_password = field_validator("password")(clean_new_password)

class UpdateUserPlanData(BaseModel):
    user_id: int
    plan: str

class UpdateTeamCreditBalanceData(BaseModel):
    team_id: int
    credit_balance: int

class ToggleAdminAccessData(BaseModel):
    user_id: int

class DeleteUserData(BaseModel):
    user_id: int

router = APIRouter(tags=["Admin"], route_class=NoEchoValidationRoute)  # 422s never echo a password

# Per verified user, per worker (backend/utilities/ratelimit.py).
admin_limiter = RateLimiter("admin", times=60, seconds=60)





@router.get('/admin/check_superuser', summary="Check if current user is a superuser", dependencies=[Depends(admin_limiter)])
async def check_superuser(Authorization: Annotated[str | None, Header()] = None):
    """
    Check if the current authenticated user is a superuser/admin.
    Returns 200 if user is superuser, 403 if not.
    """
    try:
        engine = get_db()
        mongo_db = get_mongo_client_db()

        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        
        if not user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied. Superuser privileges required."
            )
        
        return {
            "message": "User is a superuser",
            "user_id": user.id,
            "email": user.email
        }
    except Exception as e:
        if isinstance(e,psycopg2.Error):
            raise HTTPException(status_code=500, detail="Server is busy, please try again later")
        if isinstance(e,HTTPException):
            raise e
        print(f"Error checking superuser: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get('/admin/teams', summary="Get all teams (admin only)", dependencies=[Depends(admin_limiter)])
async def get_all_teams(Authorization: Annotated[str | None, Header()] = None):
    """
    Get a list of all teams in the system.
    Only accessible by superusers.
    """
    try:
        
        engine = get_db()
        mongo_db = get_mongo_client_db()

        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        
        # Check if user is superuser
        if not user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied. Superuser privileges required."
            )
        
        # Fetch all teams
        with Session(engine) as session:
            teams = session.exec(select(Team)).all()
            
            teams_data = []
            for team in teams:
                teams_data.append({
                    "team_id": team.id,
                    "team_name": team.name,
                    "team_description": team.description,
                    "team_members": [member.user.email for member in team.team_memberships],
                    "team_created_at": team.created_at,
                    "team_credit_balance": team.credit_balance,
                    "scans_count": len(team.scans),
                    "guardrails_integrations_count": len(team.guardrails_integrations),
                    "cicd_integrations_count": len(team.cicd_integrations),
                    "sast_scans_count": len([scan for scan in team.scans if scan.scan_type == "sast"]),
                    "iac_scans_count": len([scan for scan in team.scans if scan.scan_type == "iac"]),
                    "sbom_sca_scans_count": len([scan for scan in team.scans if scan.scan_type == "sbom_sca"]),
                    "cbom_scans_count": len([scan for scan in team.scans if scan.scan_type == "cbom"]),
                    "ai_bom_scans_count": len([scan for scan in team.scans if scan.scan_type == "ai_bom"]),
                })
            
            return teams_data
            
    except Exception as e:
        if isinstance(e,psycopg2.Error):
            raise HTTPException(status_code=500, detail="Server is busy, please try again later")
        if isinstance(e,HTTPException):
            raise e
        print(f"Error fetching teams: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@router.get('/admin/users', summary="Get all users (admin only)", dependencies=[Depends(admin_limiter)])
async def get_all_users(Authorization: Annotated[str | None, Header()] = None):
    """
    Get a list of all users in the system.
    Only accessible by superusers.
    """
    try:
        engine = get_db()
        mongo_db = get_mongo_client_db()

        user = await get_user_from_header_or_raise_exception(engine, Authorization)
        
        if not user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied. Superuser privileges required."
            )

        with Session(engine) as session:
            users = session.exec(select(User)).all()
            
            users_data = []
            for user in users:
                users_data.append({
                    "user_id": user.id,
                    "user_email": user.email,
                    "user_first_name": user.first_name,
                    "user_last_name": user.last_name,
                    "user_team_memberships": [(membership.team.id, membership.team.name) for membership in user.team_memberships],
                    "user_is_superuser": user.is_superuser,
                    "user_default_team_id": user.default_team_id
                })
            
            return users_data
            
    except Exception as e:
        if isinstance(e,psycopg2.Error):
            raise HTTPException(status_code=500, detail="Server is busy, please try again later")
        if isinstance(e,HTTPException):
            raise e
        print(f"Error fetching users: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@router.post('/admin/create_admin_user', summary="Create a new admin user (admin only)", dependencies=[Depends(admin_limiter)])
async def create_admin_user(data: CreateAdminUserData, Authorization: Annotated[str | None, Header()] = None):

    try:
        engine = get_db()
        mongo_db = get_mongo_client_db()

        # Check if user is superuser
        admin_user = await get_user_from_header_or_raise_exception(engine, Authorization)
        
        if not admin_user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied. Superuser privileges required."
            )
        
        
        
        # Check if user already exists
        # The administrator's password is only a temporary one: the account must choose its own at the first
        # sign-in, and the mail carries a single-use "choose your password" link, never a password.
        hashed_password = await run_in_threadpool(get_hashed_password, data.password)
        with Session(engine) as session:
            existing_user = user_by_email(session, data.email)
            
            if existing_user:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User with this email already exists"
                )
            
            new_team = Team(
                name=f"{data.first_name}'s Default Team",
                description=f"Default team for {data.first_name}",
            )
            session.add(new_team)
            session.flush()

            # Create new user
            new_user = User(
                email=data.email,
                password=hashed_password,
                first_name=data.first_name,
                last_name=data.last_name,
                is_superuser=True,  # New users are not superusers by default
                default_team_id=new_team.id,
                must_change_password=True,
                teams =  [ new_team ],
            )

            team_membership = TeamMembership( team=new_team, user=new_user, role="admin" )

            session.add(team_membership)
            session.flush()

            # the account exists only once its "choose your password" link went out (a failed mail keeps nothing)
            link_token = create_password_change_token(new_user.email, new_user.token_version or 0,
                                                      expires=SET_PASSWORD_LINK_TTL)
            expires_on = (datetime.datetime.now(datetime.timezone.utc) + SET_PASSWORD_LINK_TTL).strftime("%d %b %Y %H:%M UTC")
            try:
                await account_mail.send_account_created_email(new_user.email, set_password_link(link_token), expires_on)
            except Exception:
                session.rollback()
                raise
            session.commit()
            session.refresh(new_user)

            return {
                "message": "Admin user created successfully",
                "user": {
                    "id": new_user.id,
                    "email": new_user.email,
                    "first_name": new_user.first_name,
                    "last_name": new_user.last_name,
                    "is_superuser": new_user.is_superuser,
                    "default_team_id": new_user.default_team_id
                }
            }
            
    except Exception as e:
        if isinstance(e,psycopg2.Error):
            raise HTTPException(status_code=500, detail="Server is busy, please try again later")
        if isinstance(e,HTTPException):
            raise e
        print(f"Error creating admin user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@router.post("/admin/update", summary="Update team credit balance (admin only)", dependencies=[Depends(admin_limiter)])
async def update_team_credit_balance(
    data: UpdateTeamCreditBalanceData,
    Authorization: Annotated[str | None, Header()] = None
):
    """
    Update a team's credit balance.
    Only accessible by superusers.
    """
    try:
        engine = get_db()
        mongo_db = get_mongo_client_db()

        # Check if user is superuser
        admin_user = await get_user_from_header_or_raise_exception(engine, Authorization)
        
        if not admin_user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied. Superuser privileges required."
            )
        
        # Update user total scans
        with Session(engine) as session:
            team = session.exec(select(Team).where(Team.id == data.team_id)).first()
            
            if not team:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Team not found"
                )
            
            if data.credit_balance < 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Credit balance cannot be negative"
                )
            
            team.credit_balance = data.credit_balance
            session.add(team)
            session.commit()
            session.refresh(team)
            
            return {
                "message": "Team credit balance updated successfully",
                "user": {
                "id": team.id,
                "name": team.name,
                "credit_balance": team.credit_balance
            }
        }
    except Exception as e:
        if isinstance(e,psycopg2.Error):
            raise HTTPException(status_code=500, detail="Server is busy, please try again later")
        if isinstance(e,HTTPException):
            raise e
        print(f"Error updating user total scans: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )



@router.post('/admin/toggle_admin_access', summary="Toggle admin access for a user (admin only)", dependencies=[Depends(admin_limiter)])
async def toggle_admin_access(
    data: ToggleAdminAccessData,
    Authorization: Annotated[str | None, Header()] = None
):
    """
    Toggle admin/superuser access for a user.
    Only accessible by superusers.
    
    Request Body:
    - user_id: int
    """
    try:
        engine = get_db()
        mongo_db = get_mongo_client_db()

        # Check if user is superuser
        admin_user = await get_user_from_header_or_raise_exception(engine, Authorization)
        
        if not admin_user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied. Superuser privileges required."
            )
        
        # Prevent admin from removing their own admin access
        if admin_user.id == data.user_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot modify your own admin privileges"
            )
        
        # Toggle user admin access
        with Session(engine) as session:
            user = session.exec(select(User).where(User.id == data.user_id)).first()
            
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            
            # Toggle the is_superuser status
            user.is_superuser = not user.is_superuser
            session.add(user)
            session.commit()
            session.refresh(user)
            
            return {
                "message": f"User admin access {'granted' if user.is_superuser else 'revoked'} successfully",
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "is_superuser": user.is_superuser
                }
            }
            
    except Exception as e:
        if isinstance(e,psycopg2.Error):
            raise HTTPException(status_code=500, detail="Server is busy, please try again later")
        if isinstance(e,HTTPException):
            print(f"Error toggling admin access: {str(e)}")
            raise e
        print(f"Error toggling admin access: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )


@router.delete('/admin/delete_user', summary="Delete a user (admin only)", dependencies=[Depends(admin_limiter)])
async def delete_user(
    data: DeleteUserData,
    Authorization: Annotated[str | None, Header()] = None
):
    """
    Delete a user from the system.
    Only accessible by superusers.
    """
    try:
        engine = get_db()
        mongo_db = get_mongo_client_db()

        # Check if user is superuser
        admin_user = await get_user_from_header_or_raise_exception(engine, Authorization)
        
        if not admin_user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied. Superuser privileges required."
            )
        
        # Delete team that user is a part of :
        with Session(engine) as session:
            user = session.exec(select(User).where(User.id == data.user_id)).first()
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="User not found"
                )
            for membership in user.team_memberships:
                console.print(f"Membership: {membership}", style="bold green")
                if membership.team_id != user.default_team_id:
                    session.delete(membership) # removing as a member of all other teams except the default team
                else:
                    default_team_id = user.default_team_id
                    delete_team_associated_data(membership.team_id)
                    session.delete(membership)
                    default_team = session.exec(select(Team).where(Team.id == default_team_id)).first()

                    session.delete(default_team)
            
            session.commit()

            # delete user
            session.delete(user) # deleting the user
            session.commit()
        
        return {
            "message": "User deleted successfully",
            "user": {
                "id": user.id,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
            }
        }
    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error deleting user: {str(e)}", style="bold red")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )