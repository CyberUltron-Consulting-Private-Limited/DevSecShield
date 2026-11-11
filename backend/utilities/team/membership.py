from sqlmodel import  Session , select
from sqlalchemy.engine import Engine
from sqlalchemy import func, or_
from backend.new_models import User , TeamMembership
from rich.console import Console
from backend.utilities.auth.auth_utils import normalise_email
from backend.utilities.auth.auth_schema import clean_email
from backend.utilities.team import invitations
from fastapi import HTTPException , status

console = Console()


def _valid_invite_emails(email_ids: list[str]) -> list[str]:
    """The addresses, cleaned as on sign-up (lower case, trimmed, one '@', no spaces), duplicates dropped. One address
    that is not an email refuses the whole request before anything is stored: before, "bad email" became a user
    account with its own default team, and only the invitation mail then failed (400)."""
    cleaned: list[str] = []
    for raw in email_ids:
        if not (raw or "").strip():
            continue
        try:
            email = clean_email(raw)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail=f"Enter a valid email address ({str(raw).strip()[:80]!r} is not one)") from None
        local, _, domain = email.rpartition("@")
        if not local or "." not in domain or domain.startswith(".") or domain.endswith(".") or any(c in email for c in "\r\n\x00"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail=f"Enter a valid email address ({email[:80]!r} is not one)")
        cleaned.append(email)
    return list(dict.fromkeys(cleaned))


async def add_emails_to_team(email_ids: list[str], team_id: int, engine: Engine, invited_by_user_id: int | None = None) -> list[str]:
    """Invite the addresses to the team (utilities/team/invitations.py): each gets a single-use link and joins only
    when it accepts.  No account is created and no password is generated or mailed here."""
    email_ids = _valid_invite_emails(email_ids)
    if not email_ids:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Enter at least one email address")
    return await invitations.invite_emails(email_ids, team_id, invited_by_user_id, engine)


async def remove_emails_from_team(email_ids: list[str], team_id: int, engine: Engine) -> None:
    with Session(engine) as session:
        # every account with the address, however it is spelled: removing an address from a team removes its access,
        # including a duplicate account's (docs/security/email-case-duplicates.md)
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