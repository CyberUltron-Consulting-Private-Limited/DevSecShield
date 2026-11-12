import logging
import os

from backend.utilities.auth.auth_utils import send_outlook_email
from backend.utilities.auth.html_email import create_account_created_email_html, create_team_invitation_email_html

log = logging.getLogger("backend.team")

# A fixed subject: team names are chosen by any user, and a subject line is a mail header.
TEAM_INVITATION_SUBJECT = "You have been invited to join a team on DevSecShield"


async def send_team_invitation_email(email: str, team_name: str, inviter: str, link: str, expires_on: str) -> None:
    """Mail the invitation link. Raises when the mail could not be sent (the caller then keeps nothing).
    No password is ever generated for, or mailed to, the invitee."""
    body = create_team_invitation_email_html(team_name, inviter, link, expires_on)
    await send_outlook_email(recipient_email=email, subject=TEAM_INVITATION_SUBJECT, html_body=body)
    log.info("team invitation mailed")


ACCOUNT_CREATED_SUBJECT = "Your DevSecShield account: choose your password"


def set_password_link(token: str) -> str:
    """The page /set_password with the token in the fragment: a fragment is never sent to a server (no access log,
    no Referer), only the page reads it."""
    base = (os.environ.get("CBOM_PUBLIC_APP_URL") or "https://devsecshield.zeroshield.ai").rstrip("/")
    return f"{base}/set_password#{token}"


async def send_account_created_email(email: str, link: str, expires_on: str) -> None:
    """Mail the single-use "choose your password" link of an account an administrator created.  Raises when the
    mail could not be sent.  Never carries a password."""
    body = create_account_created_email_html(email, link, expires_on)
    await send_outlook_email(recipient_email=email, subject=ACCOUNT_CREATED_SUBJECT, html_body=body)
    log.info("account-created mail sent")


BREAK_GLASS_SUBJECT = "DevSecShield: an owner signed in with a password while single sign-on is required"


async def send_break_glass_email(recipients: list[str], owner_email: str, ip: str | None, at_iso: str) -> None:
    """Tell every owner of a team that requires SSO that one of them used the password break-glass sign-in.  The
    subject is fixed; the body escapes every value (an address and an IP are all it says)."""
    import html as _html

    owner, where, when = (_html.escape(str(v or "unknown"), quote=True) for v in (owner_email, ip, at_iso))
    body = (f"<p>{owner} signed in to DevSecShield with a password and a mailed code at {when} (UTC) from {where}, "
            "although your team requires single sign-on for that address.</p>"
            "<p>Owners keep this break-glass sign-in so that a broken identity provider never locks a team out. "
            "If this was not expected, change that owner's password and review the team's audit log.</p>")
    for recipient in recipients:
        try:
            await send_outlook_email(recipient_email=recipient, subject=BREAK_GLASS_SUBJECT, html_body=body)
        except Exception as exc:  # one recipient's failure never stops the others; the audit row is the record
            log.error("break-glass notice not mailed (%s)", type(exc).__name__)
    log.info("break-glass notice mailed to %s owner(s)", len(recipients))
