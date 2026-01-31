from rich import Console
from backend.utilities.auth.html_email import create_user_password_email_html_for_team_membership
from backend.utilities.auth.auth_utils import send_outlook_email
console = Console()

async def send_email_with_credentials(email: str, password: str, team_name: str):
    body = create_user_password_email_html_for_team_membership(password, email, team_name)
    await send_outlook_email(
        recipient_email=email,
        subject="Credentials for team membership",
        html_body=body)
    console.print(f"Email with credentials sent to {email} for team {team_name}", style="bold green")