from sqlalchemy import Engine
from rich.console import Console
from fastapi import HTTPException, status
from sqlmodel import Session, select
from backend.new_models import TeamMember
console = Console()

def check_if_user_is_in_team(user_id: int, team_id: int, engine: Engine) -> None:
    """
    Check if a user is in a team. ( checks is a membership record exists for given user_id and team_id )
    Raises an HTTPException if the user is not in the team.
    """
    try:
        with Session(engine) as session:
            team_member = session.exec(select(TeamMember).where(TeamMember.user_id == user_id, TeamMember.team_id == team_id)).first()
            if team_member is None:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is not in team")
    
    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error in check_if_user_is_in_team: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in checking if user is in team, please try again later")

def check_if_user_is_admin_of_team(user_id: int, team_id: int, engine: Engine) -> None:
    """
    Check if a user is an admin of a team. ( checks is a membership record exists for given user_id and team_id and the role is admin ) 
    Raises an HTTPException if the user is not in the team or is not an admin.
    """
    try:
        with Session(engine) as session:
            team_member = session.exec(select(TeamMember).where(TeamMember.user_id == user_id, TeamMember.team_id == team_id)).first()
            if team_member is None:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is not in team")
            if team_member.role != "admin":
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is not admin of team")
    except HTTPException as e:
        raise e
    except Exception as e:
        console.print(f"Error in check_if_user_is_admin_of_team: {e}",style="bold red")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error in checking if user is in team, please try again later")

