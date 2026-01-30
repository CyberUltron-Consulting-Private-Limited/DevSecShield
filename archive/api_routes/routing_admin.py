from typing import Annotated
from fastapi import FastAPI, HTTPException, Header, status
from sqlalchemy.engine import Engine
from sqlmodel import Session, select
from pydantic import BaseModel
from backend.auth_utils.auth_utils import get_user_from_header_or_raise_exception, get_hashed_password , send_email
from backend.models import User
from backend.auth_utils.plans import plans
from backend.auth_utils.html_email import create_user_password_email_html
import psycopg2

class CreateUserData(BaseModel):
    email: str
    password: str
    plan: str
    first_name: str
    last_name: str

class CreateAdminData(BaseModel):
    email: str
    password: str
    plan: str
    first_name: str
    last_name: str

class UpdateUserPlanData(BaseModel):
    user_id: int
    plan: str

class UpdateUserTotalScansData(BaseModel):
    user_id: int
    total_scans: int

class ToggleAdminAccessData(BaseModel):
    user_id: int

def admin_routes(app: FastAPI, engine: Engine):
    
    @app.get('/admin/check_superuser', summary="Check if current user is a superuser")
    async def check_superuser(Authorization: Annotated[str | None, Header()] = None):
        """
        Check if the current authenticated user is a superuser/admin.
        Returns 200 if user is superuser, 403 if not.
        """
        try:
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

    @app.get('/admin/users', summary="Get all users (admin only)")
    async def get_all_users(Authorization: Annotated[str | None, Header()] = None):
        """
        Get a list of all users in the system.
        Only accessible by superusers.
        """
        try:
            # Check if user is superuser
            user = await get_user_from_header_or_raise_exception(engine, Authorization)
            
            if not user.is_superuser:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied. Superuser privileges required."
                )
            
            # Fetch all users
            with Session(engine) as session:
                users = session.exec(select(User)).all()
                
                users_data = []
                for user in users:
                    users_data.append({
                        "id": user.id,
                        "email": user.email,
                        "first_name": user.first_name,
                        "last_name": user.last_name,
                        "plan": user.plan,
                        "is_superuser": user.is_superuser,
                        "total_scans": user.total_scans
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

    @app.post('/admin/create_user', summary="Create a new user (admin only)")
    async def create_user(data: CreateUserData, Authorization: Annotated[str | None, Header()] = None):
        """
        Create a new user account.
        Only accessible by superusers.
        
        Request Fields:
        - email: str
        - password: str
        - plan: str (free, basic, standard, pro, enterprise)
        - first_name: str
        - last_name: str
        """
        try:
            # Check if user is superuser
            admin_user = await get_user_from_header_or_raise_exception(engine, Authorization)
            
            if not admin_user.is_superuser:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied. Superuser privileges required."
                )
            
            # Validate plan
            if data.plan not in plans:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid plan. Available plans: {list(plans.keys())}"
                )
            
            # Check if user already exists
            with Session(engine) as session:
                existing_user = session.exec(
                    select(User).where(User.email == data.email)
                ).first()
                
                if existing_user:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="User with this email already exists"
                    )
                
                # Create new user
                new_user = User(
                    email=data.email,
                    password=get_hashed_password(data.password),
                    first_name=data.first_name,
                    last_name=data.last_name,
                    plan=data.plan,
                    is_superuser=False,  # New users are not superusers by default
                    total_scans=0
                )
                
                session.add(new_user)
                session.commit()
                session.refresh(new_user)

                # send email to user
                await send_email(new_user.email, "User Created", html_body=create_user_password_email_html(data.password, new_user.email))
                
                return {
                    "message": "User created successfully",
                    "user": {
                        "id": new_user.id,
                        "email": new_user.email,
                        "first_name": new_user.first_name,
                        "last_name": new_user.last_name,
                        "plan": new_user.plan,
                        "is_superuser": new_user.is_superuser,
                        "total_scans": new_user.total_scans
                    }
                }
                
        except Exception as e:
            if isinstance(e,psycopg2.Error):
                raise HTTPException(status_code=500, detail="Server is busy, please try again later")
            if isinstance(e,HTTPException):
                raise e
            print(f"Error creating user: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error"
            )

    @app.post('/admin/create_admin', summary="Create a new admin user (admin only)")
    async def create_admin(data: CreateAdminData, Authorization: Annotated[str | None, Header()] = None):
        """
        Create a new admin/superuser account.
        Only accessible by superusers.
        
        Request Fields:
        - email: str
        - password: str
        - plan: str (free, basic, standard, pro, enterprise)
        - first_name: str
        - last_name: str
        """
        try:
            # Check if user is superuser
            admin_user = await get_user_from_header_or_raise_exception(engine, Authorization)
            
            if not admin_user.is_superuser:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied. Superuser privileges required."
                )
            
            # Validate plan
            if data.plan not in plans:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid plan. Available plans: {list(plans.keys())}"
                )
            
            # Check if user already exists
            with Session(engine) as session:
                existing_user = session.exec(
                    select(User).where(User.email == data.email)
                ).first()
                
                if existing_user:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="User with this email already exists"
                    )
                
                # Create new admin user
                new_admin = User(
                    email=data.email,
                    password=get_hashed_password(data.password),
                    first_name=data.first_name,
                    last_name=data.last_name,
                    plan=data.plan,
                    is_superuser=True,  # This user will be an admin
                    total_scans=0
                )
                
                session.add(new_admin)
                session.commit()
                session.refresh(new_admin)

                # send email to admin user
                await send_email(new_admin.email, "Admin Account Created", html_body=create_user_password_email_html(data.password, new_admin.email))
                
                return {
                    "message": "Admin user created successfully",
                    "user": {
                        "id": new_admin.id,
                        "email": new_admin.email,
                        "first_name": new_admin.first_name,
                        "last_name": new_admin.last_name,
                        "plan": new_admin.plan,
                        "is_superuser": new_admin.is_superuser,
                        "total_scans": new_admin.total_scans
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
    
    
    @app.post("/admin/update_user_total_scans", summary="Update user total scans (admin only)")
    async def update_user_total_scans(
        data: UpdateUserTotalScansData,
        Authorization: Annotated[str | None, Header()] = None
    ):
        """
        Update a user's total scans.
        Only accessible by superusers.
        """
        try:
            # Check if user is superuser
            admin_user = await get_user_from_header_or_raise_exception(engine, Authorization)
            
            if not admin_user.is_superuser:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied. Superuser privileges required."
                )
            
            # Update user total scans
            with Session(engine) as session:
                user = session.exec(select(User).where(User.id == data.user_id)).first()
                
                if not user:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="User not found"
                    )
                
                user.total_scans = data.total_scans
                session.add(user)
                session.commit()
                session.refresh(user)
                
                return {
                    "message": "User total scans updated successfully",
                    "user": {
                    "id": user.id,
                    "email": user.email,
                    "total_scans": user.total_scans
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

    
    
    
    @app.post('/admin/update_user_plan', summary="Update user plan (admin only)")
    async def update_user_plan(
        data: UpdateUserPlanData, 
        Authorization: Annotated[str | None, Header()] = None
    ):
        """
        Update a user's plan.
        Only accessible by superusers.
        
        Request Body:
        - user_id: int
        - plan: str (free, basic, standard, pro, enterprise)
        """
        try:
            # Check if user is superuser
            admin_user = await get_user_from_header_or_raise_exception(engine, Authorization)
            
            if not admin_user.is_superuser:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied. Superuser privileges required."
                )
            
            # Validate plan
            if data.plan not in plans:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid plan. Available plans: {list(plans.keys())}"
                )
            
            # Update user plan
            with Session(engine) as session:
                user = session.exec(select(User).where(User.id == data.user_id)).first()
                
                if not user:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="User not found"
                    )
                
                user.plan = data.plan
                session.add(user)
                session.commit()
                session.refresh(user)
                
                return {
                    "message": "User plan updated successfully",
                    "user": {
                        "id": user.id,
                        "email": user.email,
                        "plan": user.plan
                    }
                }
                
        except Exception as e:
            if isinstance(e,psycopg2.Error):
                raise HTTPException(status_code=500, detail="Server is busy, please try again later")
            if isinstance(e,HTTPException):
                raise e
            print(f"Error updating user plan: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error"
            )

    @app.post('/admin/toggle_admin_access', summary="Toggle admin access for a user (admin only)")
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

    @app.delete('/admin/users/{user_id}', summary="Delete a user (admin only)")
    async def delete_user(user_id: int, Authorization: Annotated[str | None, Header()] = None):
        """
        Delete a user account.
        Only accessible by superusers.
        """
        try:
            # Check if user is superuser
            admin_user = await get_user_from_header_or_raise_exception(engine, Authorization)
            
            if not admin_user.is_superuser:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied. Superuser privileges required."
                )
            
            # Prevent admin from deleting themselves
            if admin_user.id == user_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Cannot delete your own account"
                )
            
            # Delete user
            with Session(engine) as session:
                user = session.exec(select(User).where(User.id == user_id)).first()
                
                if not user:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="User not found"
                    )
                
                session.delete(user)
                session.commit()
                
                return {
                    "message": f"User {user.email} deleted successfully"
                }
                
        except Exception as e:
            if isinstance(e,psycopg2.Error):
                raise HTTPException(status_code=500, detail="Server is busy, please try again later")
            if isinstance(e,HTTPException):
                raise e
            print(f"Error deleting user: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error"
            )

    @app.get('/admin/stats', summary="Get system statistics (admin only)")
    async def get_system_stats(Authorization: Annotated[str | None, Header()] = None):
        """
        Get system statistics including user counts, plan distribution, etc.
        Only accessible by superusers.
        """
        try:
            # Check if user is superuser
            admin_user = await get_user_from_header_or_raise_exception(engine, Authorization)
            
            if not admin_user.is_superuser:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied. Superuser privileges required."
                )
            
            # Get statistics
            with Session(engine) as session:
                # Total users
                total_users = len(session.exec(select(User)).all())
                
                # Superusers count
                superusers = len(session.exec(select(User).where(User.is_superuser == True)).all())
                
                # Plan distribution
                plan_distribution = {}
                for plan_name in plans.keys():
                    count = len(session.exec(select(User).where(User.plan == plan_name)).all())
                    plan_distribution[plan_name] = count
                
                # Total scans across all users
                total_scans = sum(user.total_scans for user in session.exec(select(User)).all())
                
                return {
                    "total_users": total_users,
                    "superusers": superusers,
                    "regular_users": total_users - superusers,
                    "plan_distribution": plan_distribution,
                    "total_scans": total_scans
                }
                
        except Exception as e:
            if isinstance(e,psycopg2.Error):
                raise HTTPException(status_code=500, detail="Server is busy, please try again later")
            if isinstance(e,HTTPException):
                raise e
            print(f"Error fetching system stats: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error"
            )
