"""SMTP login check of the Chola production kit: connect, STARTTLS, AUTH, QUIT. Sends no mail.

Runs inside the backend image with the backend's own environment (remote.sh smtp-test:
`docker compose run --rm --no-deps -T --entrypoint /backend/.venv/bin/python backend - < smtp_check.py`), so it tests
exactly the settings the API uses (SMTP_HOST, SMTP_PORT, SMTP_SECURITY, SMTP_USERNAME, SMTP_PASSWORD) from the network
the API uses. Prints one verdict line; never prints the password or the mailbox address.

Exit: 0 login works; 2 SMTP AUTH is disabled (tenant, mailbox or basic authentication); 3 credentials refused;
4 network / TLS; 5 settings missing or invalid.
"""
import os
import smtplib
import ssl
import sys

# Office 365 answers (535 5.7.139 / 5.7.3 ...): substring -> (exit code, verdict)
DISABLED = [
    ("smtpclientauthentication is disabled for the tenant",
     ("SMTP AUTH is disabled for the whole tenant (Exchange admin center > Settings > Mail flow: 'Turn off SMTP AUTH "
      "protocol for your organization' is on)")),
    ("smtpclientauthentication is disabled for the mailbox",
     ("SMTP AUTH is disabled for this mailbox (Microsoft 365 admin center > Users > the mailbox > Mail > Manage email "
      "apps: tick 'Authenticated SMTP', or Set-CASMailbox -SmtpClientAuthenticationDisabled $false)")),
    ("basic authentication is disabled",
     ("Basic authentication for SMTP AUTH is disabled for the tenant (Microsoft's retirement of Basic auth for "
      "Client Submission, or an authentication policy): re-enable it for this mailbox or move mail to another relay")),
    ("did not meet the criteria to be authenticated",
     "the sign-in was blocked by tenant policy (Security defaults, Conditional Access or MFA on the mailbox)"),
]
BAD_CREDENTIALS = ["credentials were incorrect", "5.7.3 authentication unsuccessful", "535 5.7.8",
                   "authentication unsuccessful"]


def scrub(text, *secrets):
    for s in secrets:
        if s and len(s) >= 4:
            text = text.replace(s, "***")
    return " ".join(text.split())[:300]


def main():
    host = os.getenv("SMTP_HOST", "").strip()
    user = os.getenv("SMTP_USERNAME", "").strip()
    password = os.getenv("SMTP_PASSWORD", "")
    security = os.getenv("SMTP_SECURITY", "starttls").strip().lower()
    try:
        port = int(os.getenv("SMTP_PORT") or (465 if security == "ssl" else 587))
    except ValueError:
        print("SMTP check: SMTP_PORT is not a number")
        return 5
    if not host or not user or not password:
        print("SMTP check: SMTP_HOST, SMTP_USERNAME or SMTP_PASSWORD is not set in backend.env")
        return 5
    if security not in ("starttls", "ssl"):
        print("SMTP check: SMTP_SECURITY must be starttls or ssl for a login")
        return 5
    where = f"{host}:{port} ({security})"
    ctx = ssl.create_default_context()
    try:
        if security == "ssl":
            server = smtplib.SMTP_SSL(host, port, context=ctx, timeout=20)
        else:
            server = smtplib.SMTP(host, port, timeout=20)
        with server:
            server.ehlo()
            if security == "starttls":
                if not server.has_extn("starttls"):
                    print(f"SMTP check: {where} does not offer STARTTLS; refusing to send the password")
                    return 4
                server.starttls(context=ctx)
                server.ehlo()
            if not server.has_extn("auth"):
                print(f"SMTP check: FAILED - {where} offers no AUTH after STARTTLS: SMTP AUTH is disabled "
                      "(tenant or mailbox)")
                return 2
            server.login(user, password)
            print(f"SMTP check: OK - logged in to {where} as the configured mailbox (no mail sent)")
            try:
                server.quit()
            except smtplib.SMTPException:
                pass
            return 0
    except smtplib.SMTPAuthenticationError as e:
        raw = e.smtp_error.decode("utf-8", "replace") if isinstance(e.smtp_error, bytes) else str(e.smtp_error)
        msg = scrub(f"{e.smtp_code} {raw}", password, user)
        low = msg.lower()
        for needle, verdict in DISABLED:
            if needle in low:
                print(f"SMTP check: FAILED - {verdict}. Server said: {msg}")
                return 2
        if any(n in low for n in BAD_CREDENTIALS):
            print(f"SMTP check: FAILED - the mailbox password was refused (wrong or expired password, or an app "
                  f"password is required). Server said: {msg}")
            return 3
        print(f"SMTP check: FAILED - login refused. Server said: {msg}")
        return 3
    except (TimeoutError, OSError, ssl.SSLError, smtplib.SMTPException) as e:
        print(f"SMTP check: FAILED - cannot talk to {where}: {type(e).__name__}: {scrub(str(e), password, user)} "
              "(is outbound TCP 587 open from the instance?)")
        return 4


if __name__ == "__main__":
    sys.exit(main())
