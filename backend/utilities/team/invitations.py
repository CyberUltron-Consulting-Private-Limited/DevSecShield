"""Team invitations: adding an address to a team mails it a single-use link; nobody joins until the invitee accepts.

* No password is ever generated for, or mailed to, the invitee.  A new address chooses its own password on the
  invitation page (the link proves the mailbox, as a sign-up code would); an existing account signs in as that
  address and then accepts or declines.
* The token (256 bits, hex so it survives the login page's ``redirect_url`` encoding) is stored only as its
  SHA-256 and works once: accept, decline, revoke and resend clear or replace it, each with a compare-and-swap on
  the hash, so two concurrent uses of one link cannot both succeed.  Links expire after ``INVITE_TTL``.
* One row per (team, address) (unique): inviting the address again reuses the row.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import logging
import os
import re
import secrets

from fastapi import HTTPException, status
from sqlalchemy import update
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select
from starlette.concurrency import run_in_threadpool

from backend.new_models import Team, TeamInvitation, TeamMembership, User
from backend.utilities.auth import email as invite_mail
from backend.utilities.auth.auth_utils import get_hashed_password, normalise_email, user_by_email

log = logging.getLogger("backend.team")

INVITE_TTL = dt.timedelta(days=7)
_TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")

GONE = "This invitation link is not valid any more: it was used, declined, revoked or replaced by a newer one. " \
       "Ask a team admin to invite you again."
EXPIRED = "This invitation has expired. Ask a team admin to send a new one."


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token() -> tuple[str, str]:
    token = secrets.token_hex(32)
    return token, token_hash(token)


def invite_link(token: str) -> str:
    base = (os.environ.get("CBOM_PUBLIC_APP_URL") or "https://devsecshield.zeroshield.ai").rstrip("/")
    return f"{base}/invite/{token}"


def iso_z(moment: dt.datetime | None) -> str | None:
    return moment.replace(microsecond=0).isoformat() + "Z" if moment else None


def is_expired(row: TeamInvitation, now: dt.datetime) -> bool:
    return row.expires_at <= now


def _inviter_label(session: Session, user_id: int | None) -> str:
    user = session.get(User, user_id) if user_id else None
    return user.email if user else "A team admin"


def _member_ids(session: Session, team_id: int) -> set[int]:
    return {m.user_id for m in session.exec(select(TeamMembership).where(TeamMembership.team_id == team_id)).all()}


async def _issue_and_mail(session: Session, row: TeamInvitation, team: Team, inviter_id: int | None,
                          now: dt.datetime) -> None:
    """Give ``row`` a new token and expiry, flush, mail the link, commit.  If the mail fails nothing is kept (the
    previous token, if any, stays valid)."""
    token, hashed = new_token()
    row.token_hash, row.status, row.created_at = hashed, "pending", now
    row.expires_at, row.responded_at, row.invited_by_user_id = now + INVITE_TTL, None, inviter_id
    session.add(row)
    try:
        session.flush()  # a concurrent invitation of the same address waits here, then fails the unique index
    except IntegrityError:
        session.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail=f"{row.email} already has a pending invitation") from None
    try:
        await invite_mail.send_team_invitation_email(
            email=row.email, team_name=team.name, inviter=_inviter_label(session, inviter_id),
            link=invite_link(token), expires_on=row.expires_at.strftime("%d %b %Y %H:%M UTC"))
    except Exception:
        session.rollback()
        raise
    session.commit()


async def invite_emails(emails: list[str], team_id: int, inviter_id: int | None, engine: Engine) -> list[str]:
    """Invite already-validated, lower-cased addresses.  Refuses (before anything is stored or sent) an address
    whose account is already a member, or that has a live invitation (Resend replaces it)."""
    now = utcnow()
    with Session(engine) as session:
        team = session.get(Team, team_id)
        if team is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found")
        members = _member_ids(session, team_id)
        rows: dict[str, TeamInvitation | None] = {}
        for email in emails:
            account = user_by_email(session, email)
            if account is not None and account.id in members:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{email} is already in the team")
            row = session.exec(select(TeamInvitation).where(TeamInvitation.team_id == team_id,
                                                            TeamInvitation.email == email)).first()
            if row is not None and row.status == "pending" and not is_expired(row, now):
                raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                    detail=f"{email} already has a pending invitation (Resend sends a new link)")
            rows[email] = row
        for email, row in rows.items():
            await _issue_and_mail(session, row or TeamInvitation(team_id=team_id, email=email, created_at=now,
                                                                 expires_at=now), team, inviter_id, now)
        log.info("team invitations sent team_id=%s count=%s by=%s", team_id, len(rows), inviter_id)
        return list(rows)


def _team_row(session: Session, team_id: int, invitation_id: int) -> TeamInvitation:
    row = session.get(TeamInvitation, invitation_id)
    if row is None or row.team_id != team_id or row.status not in ("pending", "declined"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invitation not found")
    return row


def list_invitations(team_id: int, engine: Engine) -> list[dict]:
    """The team's open invitations (pending, expired or declined), newest first, for its admins."""
    now = utcnow()
    with Session(engine) as session:
        rows = session.exec(select(TeamInvitation).where(TeamInvitation.team_id == team_id,
                                                         TeamInvitation.status.in_(("pending", "declined")))  # type: ignore[attr-defined]
                            .order_by(TeamInvitation.created_at.desc(), TeamInvitation.id.desc())).all()  # type: ignore[attr-defined]
        return [{
            "id": row.id,
            "email": row.email,
            "status": "expired" if row.status == "pending" and is_expired(row, now) else row.status,
            "invited_by": _inviter_label(session, row.invited_by_user_id),
            "created_at": iso_z(row.created_at),
            "expires_at": iso_z(row.expires_at),
            "responded_at": iso_z(row.responded_at),
        } for row in rows]


async def resend_invitation(team_id: int, invitation_id: int, inviter_id: int | None, engine: Engine) -> None:
    """A new link (new token, a fresh 7 days); the old link stops working."""
    now = utcnow()
    with Session(engine) as session:
        row = _team_row(session, team_id, invitation_id)
        team = session.get(Team, team_id)
        account = user_by_email(session, row.email)
        if account is not None and account.id in _member_ids(session, team_id):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{row.email} is already in the team")
        await _issue_and_mail(session, row, team, inviter_id, now)
        log.info("team invitation re-sent team_id=%s invitation_id=%s by=%s", team_id, invitation_id, inviter_id)


def revoke_invitation(team_id: int, invitation_id: int, engine: Engine) -> None:
    with Session(engine) as session:
        row = _team_row(session, team_id, invitation_id)
        row.status, row.token_hash, row.responded_at = "revoked", None, utcnow()
        session.add(row)
        session.commit()
        log.info("team invitation revoked team_id=%s invitation_id=%s", team_id, invitation_id)


# ------------------------------------------------------------------------------------------------ the invitee

def live_invitation(session: Session, token: str, now: dt.datetime) -> TeamInvitation:
    """The pending, unexpired invitation behind ``token``, or 404 / 410."""
    if not _TOKEN_RE.match(token or ""):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=GONE)
    row = session.exec(select(TeamInvitation).where(TeamInvitation.token_hash == token_hash(token))).first()
    if row is None or row.status != "pending":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=GONE)
    if is_expired(row, now):
        raise HTTPException(status_code=status.HTTP_410_GONE, detail=EXPIRED)
    return row


def describe(token: str, engine: Engine) -> dict:
    now = utcnow()
    with Session(engine) as session:
        row = live_invitation(session, token, now)
        team = session.get(Team, row.team_id)
        return {
            "email": row.email,
            "team_name": team.name if team else "",
            "invited_by": _inviter_label(session, row.invited_by_user_id),
            "expires_at": iso_z(row.expires_at),
            "account_exists": user_by_email(session, row.email) is not None,
        }


def _close(session: Session, row: TeamInvitation, token: str, new_status: str, now: dt.datetime) -> None:
    """Compare-and-swap the invitation out of "pending": exactly one concurrent use of a link wins."""
    done = session.exec(
        update(TeamInvitation)
        .where(TeamInvitation.id == row.id, TeamInvitation.token_hash == token_hash(token),
               TeamInvitation.status == "pending", TeamInvitation.expires_at > now)
        .values(status=new_status, token_hash=None, responded_at=now)
    ).rowcount
    if done != 1:
        session.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=GONE)


def _join(session: Session, team_id: int, user_id: int) -> None:
    exists = session.exec(select(TeamMembership).where(TeamMembership.team_id == team_id,
                                                       TeamMembership.user_id == user_id)).first()
    if exists is None:
        session.add(TeamMembership(team_id=team_id, user_id=user_id, role="member"))


def _require_invitee(session: Session, row: TeamInvitation, user: User | None) -> User:
    """The signed-in account must be the one the invited address signs in to."""
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=f"Sign in as {row.email} to answer this invitation")
    account = user_by_email(session, row.email)
    if account is None or account.id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"This invitation is for {row.email}. You are signed in as {normalise_email(user.email)}: "
                                   f"sign out and sign in as {row.email} to answer it.")
    return account


def accept(token: str, user: User, engine: Engine) -> int:
    now = utcnow()
    with Session(engine) as session:
        row = live_invitation(session, token, now)
        account = _require_invitee(session, row, user)
        _close(session, row, token, "accepted", now)
        _join(session, row.team_id, account.id)
        session.commit()
        log.info("team invitation accepted team_id=%s user_id=%s", row.team_id, account.id)
        return row.team_id


def decline(token: str, user: User | None, engine: Engine) -> None:
    """An existing account declines signed in as the address; a new address declines with the link alone (it proves
    the mailbox, and declining grants nothing)."""
    now = utcnow()
    with Session(engine) as session:
        row = live_invitation(session, token, now)
        if user is not None or user_by_email(session, row.email) is not None:
            _require_invitee(session, row, user)
        _close(session, row, token, "declined", now)
        session.commit()
        log.info("team invitation declined team_id=%s", row.team_id)


async def register(token: str, password: str, first_name: str, last_name: str, engine: Engine) -> tuple[User, int]:
    """A new address accepts: the account is created with the password the invitee chose (and its own default team,
    as on sign-up) and joins the team."""
    hashed = await run_in_threadpool(get_hashed_password, password)
    now = utcnow()
    with Session(engine) as session:
        row = live_invitation(session, token, now)
        if user_by_email(session, row.email) is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail=f"An account already uses {row.email}: sign in as {row.email} to accept")
        _close(session, row, token, "accepted", now)
        default_team = Team(name=f"{first_name}'s Default Team", description=f"Default team for {first_name}")
        session.add(default_team)
        session.flush()
        user = User(email=row.email, password=hashed, first_name=first_name, last_name=last_name,
                    profile_photo=None, session_active=True, default_team_id=default_team.id)
        session.add(user)
        session.flush()
        session.add(TeamMembership(team_id=default_team.id, user_id=user.id, role="admin"))
        _join(session, row.team_id, user.id)
        session.commit()
        session.refresh(user)
        log.info("account created from a team invitation team_id=%s user_id=%s", row.team_id, user.id)
        return user, row.team_id
