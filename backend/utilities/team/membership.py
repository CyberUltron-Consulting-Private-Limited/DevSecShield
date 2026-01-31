from sqlmodel import Engine , Session , select
from backend.new_models import User , Team , TeamMembership
from rich import Console

from backend.utilities.auth.email import send_email_with_credentials

console = Console()


def add_emails_to_team(email_ids: list[str], team_id: int, engine: Engine) -> None:
    
    with Session(engine) as session:
        team = session.exec(select(Team).where(Team.id == team_id)).first()


        # if email doesnt exist for any user , create a new user and send email with credentials 
        for email in email_ids:
            user = session.exec(select(User).where(User.email == email)).first()
            if not user:
                user = User(email=email)
                session.add(user)
                session.commit()
                send_email_with_credentials(email, user.password)
                console.print(f"Email {email} does not exist for any user , creating a new user and sending email with credentials", style="bold orange1")
        
        query_statement = select(User)
        for email in email_ids:
            query_statement = query_statement.where(User.email == email)
        users = session.exec(query_statement).all()
        for user in users:
            team_membership = TeamMembership(user=user, team=team)
            user.team_memberships.append(team_membership)
            session.add(user)
        session.commit()
        console.print(f"Emails {email_ids} added to team {team_id}", style="bold green")


def remove_emails_from_team(email_ids: list[str], team_id: int, engine: Engine) -> None:
    with Session(engine) as session:
        query_statement = select(User)
        for email in email_ids:
            query_statement = query_statement.where(User.email == email)
        users = session.exec(query_statement).all()

        for user in users:
            team_membership = session.exec(select(TeamMembership).where(TeamMembership.user_id == user.id and TeamMembership.team_id == team_id)).first()
            if not team_membership:
                console.print(f"Email {user.email} not found in team {team_id}", style="bold red")
                continue
            user.team_memberships.remove(team_membership)
            session.add(user)
        

        session.commit()
        console.print(f"Emails {email_ids} removed from team {team_id}", style="bold orange1")