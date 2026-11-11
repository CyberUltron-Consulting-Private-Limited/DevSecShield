import logging

from backend.utilities.auth.auth_utils import send_outlook_email
from backend.utilities.auth.html_email import create_team_invitation_email_html

log = logging.getLogger("backend.team")

# A fixed subject: team names are chosen by any user, and a subject line is a mail header.
TEAM_INVITATION_SUBJECT = "You have been invited to join a team on DevSecShield"


async def send_team_invitation_email(email: str, team_name: str, inviter: str, link: str, expires_on: str) -> None:
    """Mail the invitation link. Raises when the mail could not be sent (the caller then keeps nothing).
    No password is ever generated for, or mailed to, the invitee."""
    body = create_team_invitation_email_html(team_name, inviter, link, expires_on)
    await send_outlook_email(recipient_email=email, subject=TEAM_INVITATION_SUBJECT, html_body=body)
    log.info("team invitation mailed")
