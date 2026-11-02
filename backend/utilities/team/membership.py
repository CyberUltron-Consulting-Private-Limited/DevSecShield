from sqlmodel import  Session , select
from sqlalchemy.engine import Engine
from sqlalchemy import func, or_
from backend.new_models import User , Team , TeamMembership
from rich.console import Console
import secrets
import string
from starlette.concurrency import run_in_threadpool
from backend.utilities.auth.email import send_email_with_credentials
from backend.utilities.auth.auth_utils import get_hashed_password, normalise_email
from fastapi import HTTPException , status

console = Console()

INVITE_PASSWORD_CHARS = 20


def generate_random_password() -> str:
    """First password of an invited user (mailed to them): 20 characters from a CSPRNG (~119 bits)."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(INVITE_PASSWORD_CHARS))

async def add_emails_to_team(email_ids: list[str], team_id: int, engine: Engine) -> None:
    email_ids = list(dict.fromkeys(normalise_email(email) for email in email_ids if normalise_email(email)))
    
    with Session(engine) as session:
        team = session.exec(select(Team).where(Team.id == team_id)).first()


        # STEP [ 1 ] : =============================== create users if they dont exist ================================================= 
        for email in email_ids:
            # ---------------------------> creating a new user and send them an email with credentials 
            user = session.exec(select(User).where(func.lower(User.email) == email)).first()
            if not user:
                # ---------------------------> creating a new default team for this new user 
                default_team_for_new_user = Team(
                    name=f"{email.split('@')[0]}'s Default Team",
                    description=f"Default team for {email.split('@')[0]}",
                )
                session.add(default_team_for_new_user)
                session.commit()
                session.refresh(default_team_for_new_user)

                # ---------------------------> create user model 
                generated_password = generate_random_password()
                user = User(
                    email=email, 
                    password=await run_in_threadpool(get_hashed_password, generated_password),
                    first_name=email.split("@")[0],
                    last_name="user",
                    default_team_id=default_team_for_new_user.id
                    )
                session.add(user)


                # ---------------------------> add the user to the team 
                team_membership = TeamMembership(user=user, team=default_team_for_new_user , role="admin")
                session.add(team_membership)


                session.commit()
                await send_email_with_credentials(email=email, password=generated_password,team_name=team.name)
                console.print(f"Email {email} does not exist for any user , creating a new user and sending email with credentials 📧", style="bold orange1")
        
        
        
        # STEP [ 2 ] : =============================== get all the users and add them to the team  ================================================= 
        
        # ----------------------------> get all users by their email ids 
        or_statements = []
        for email in email_ids:
            or_statements.append(func.lower(User.email) == email)
        users = session.exec(select(User).where(or_(*or_statements))).all()

        # ----------------------------> add them to the team 
        for user in users:
            for membership in user.team_memberships:
                if membership.team_id == team_id:
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in team")
            team_membership = TeamMembership(user=user, team=team)
            session.add(team_membership)
        session.commit()
        console.print(f"Emails {email_ids} added to team {team_id}", style="bold green")


async def remove_emails_from_team(email_ids: list[str], team_id: int, engine: Engine) -> None:
    with Session(engine) as session:
        or_statements = []
        for email in email_ids:
            or_statements.append(func.lower(User.email) == normalise_email(email))
        users = session.exec(select(User).where(or_(*or_statements))).all()

        for user in users:
            team_membership = session.exec(select(TeamMembership).where(TeamMembership.user_id == user.id , TeamMembership.team_id == team_id)).first()
            console.print(f"Team membership: {team_membership} removed ! ", style="bold yellow")
            if not team_membership:
                console.print(f"Email {user.email} not found in team {team_id}", style="bold red")
                continue
            session.delete(team_membership)
            session.commit()
            
        

        session.commit()
        console.print(f"Emails {email_ids} removed from team {team_id}", style="bold orange1")