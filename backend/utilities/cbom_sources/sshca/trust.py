"""The trust bundle servers fetch without a person (sec M4 / arch "machine read path", PR #65 review round 7).

What a server needs for the ``zs-cbom`` login: the CA keys to trust (``TrustedUserCAKeys``), the revocation list
(``RevokedKeys``, an OpenSSH KRL) and the principals of its server group (``AuthorizedPrincipalsFile``).  All of it is
public by nature (public keys, serials, group names), so a server reads it with a per-team, read-only, revocable
distribution token (``zst_…``, shown once, stored as SHA-256) instead of a 30-minute user session.  The token reads
this team's three files and nothing else.

* Generations (``cbomsshcatrust``, one row per team): ``trust_generation`` moves on every change of what servers must
  trust (CA created, rotated, promoted, revoked; certificate revoked), ``revocation_generation`` on both revokes.  The
  KRL's bytes are a pure function of the revocation generation (its version is the generation, its "generated" time
  the generation's time), cached per worker under it, so 10,000 servers polling cost one build per revocation.
* Each answer carries a strong ``ETag`` (SHA-256 of the body) and ``X-ZS-Trust-Generation``; ``If-None-Match`` gets
  a 304 with no body.
* Fetchers (``cbomsshcatrustfetch``): the ``X-ZS-Fetcher`` header (the server's name; default ``token-<id>``) and the
  generation it last received, written when it changes or every ``FETCH_WRITE_EVERY``.  A ``next`` CA records the
  generation that added it, so ``promote`` shows how many active fetchers (seen in the last 24 h) already have it.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import os
import re
import secrets
import threading
from typing import Any

from fastapi import HTTPException
from sqlalchemy import func, update
from sqlalchemy.dialects import postgresql, sqlite
from sqlmodel import Session, select

from backend.utilities.cbom_sources.common import audit, iso_z, log
from backend.utilities.cbom_sources.sshca import certs as C
from backend.utilities.cbom_sources.sshca.models import (
    CbomSshCa,
    CbomSshCaTrust,
    CbomSshCaTrustFetch,
    CbomSshCaTrustToken,
    CbomSshCertIssued,
)

TOKEN_PREFIX = "zst_"
TOKEN_RE = re.compile(r"^zst_[A-Za-z0-9_-]{40}$")
MAX_TOKENS_PER_TEAM = 20
MAX_FETCHERS_PER_TEAM = 20_000
FETCH_WRITE_EVERY = _dt.timedelta(minutes=15)
TOKEN_TOUCH_EVERY = _dt.timedelta(minutes=1)
ACTIVE_FETCHER = _dt.timedelta(hours=24)
PROMOTE_MIN_AGE_ENV = "CBOM_SSHCA_PROMOTE_MIN_AGE_S"
PROMOTE_MIN_AGE_S = 900
MAX_GROUPS = 16
_GROUP = re.compile(r"^[a-z0-9][a-z0-9._-]{0,47}$")
_FETCHER_BAD = re.compile(r"[^A-Za-z0-9._:@-]")
KRL_KEEP_EXPIRED = _dt.timedelta(hours=1)  # a revoked certificate stays listed this long after it expired (skew)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def etag_of(body: bytes) -> str:
    return '"' + hashlib.sha256(body).hexdigest()[:32] + '"'


def etag_matches(header: str | None, etag: str) -> bool:
    """``If-None-Match`` (weak comparison, RFC 9110 13.1.2): ``*`` or any listed tag equal to ours."""
    if not header:
        return False
    for part in header.split(","):
        tag = part.strip()
        if tag == "*" or (tag[2:] if tag.startswith("W/") else tag) == etag:
            return True
    return False


# ----------------------------------------------------------------------------- generations
def generations(session: Session, team_id: int) -> tuple[int, int, _dt.datetime | None]:
    """(trust generation, revocation generation, when the revocation generation last moved)."""
    row = session.exec(select(CbomSshCaTrust).where(CbomSshCaTrust.team_id == team_id)).first()
    if row is None:
        return 0, 0, None
    return int(row.trust_generation), int(row.revocation_generation), row.revocation_changed_at


def bump(session: Session, team_id: int, now: _dt.datetime, *, revocation: bool = False) -> int:
    """Move the team's trust generation (and the revocation generation for a revoke) in the caller's transaction;
    returns the new trust generation.  One upsert, safe against two first bumps at once."""
    table = CbomSshCaTrust.__table__  # type: ignore[attr-defined]
    dialect = session.get_bind().dialect.name
    insert = postgresql.insert if dialect == "postgresql" else sqlite.insert
    values: dict[str, Any] = {"team_id": team_id, "trust_generation": 1, "trust_changed_at": now,
                              "revocation_generation": 1 if revocation else 0,
                              "revocation_changed_at": now if revocation else None,
                              "row_version": 1, "created_at": now, "last_updated": now}
    changes: dict[str, Any] = {"trust_generation": table.c.trust_generation + 1, "trust_changed_at": now,
                               "row_version": table.c.row_version + 1, "last_updated": now}
    if revocation:
        changes.update(revocation_generation=table.c.revocation_generation + 1, revocation_changed_at=now)
    stmt = insert(table).values(**values).on_conflict_do_update(index_elements=["team_id"], set_=changes) \
        .returning(table.c.trust_generation)
    return int(session.execute(stmt).scalar_one())


# ----------------------------------------------------------------------------- the three files
def trusted(row: CbomSshCa, now: _dt.datetime, overlap: _dt.timedelta) -> bool:
    if row.revoked_at is not None or row.state == "revoked":
        return False
    if row.state in ("next", "active"):
        return True
    return row.state == "retired" and row.retired_at is not None and now - row.retired_at < overlap


def trusted_keys_text(session: Session, team_id: int, now: _dt.datetime, overlap: _dt.timedelta) -> str:
    """TrustedUserCAKeys: next, active and recently retired keys.  No clock in the text (it would change the ETag
    every second); the generation names the version."""
    generation = generations(session, team_id)[0]
    rows = session.exec(select(CbomSshCa).where(CbomSshCa.team_id == team_id).order_by(CbomSshCa.id)).all()
    lines = [f"# ZeroShield SSH CA keys for TrustedUserCAKeys (team {team_id}, trust generation {generation}).",
             "# Keep this file current with the trust-fetch script (rotate, promote and revoke change it)."]
    lines += [f"{r.public_key.strip()} zs-ca-{r.id}-{r.state}" for r in rows if trusted(r, now, overlap)]
    return "\n".join(lines) + "\n"


_krl_cache: dict[int, tuple[int, bytes]] = {}
_krl_lock = threading.Lock()
MAX_KRL_CACHE = 10_000


def krl_bytes(session: Session, team_id: int) -> tuple[bytes, int]:
    """(the team's KRL, its revocation generation).  Every revoked CA key, and the serials of revoked certificates that
    were still (nearly) valid when the generation moved.  Built once per generation and worker."""
    from backend.utilities.cbom_sources.sshca import krl
    from backend.utilities.cbom_sources.sshca.ca import from_db_serial

    _trust, generation, changed_at = generations(session, team_id)
    with _krl_lock:
        hit = _krl_cache.get(team_id)
        if hit and hit[0] == generation:
            return hit[1], generation
    cas = {row.id: row for row in session.exec(select(CbomSshCa).where(CbomSshCa.team_id == team_id)).all()}
    revoked_cas = [C.public_blob(row.public_key) for row in cas.values() if row.revoked_at is not None]
    serials: dict[bytes, list[int]] = {}
    if changed_at is not None:
        certs = session.exec(select(CbomSshCertIssued.ca_id, CbomSshCertIssued.serial).where(  # partial index
            CbomSshCertIssued.team_id == team_id, CbomSshCertIssued.revoked_at.is_not(None),  # type: ignore[union-attr]
            CbomSshCertIssued.valid_before > changed_at - KRL_KEEP_EXPIRED)).all()
        for ca_id, serial in certs:
            ca = cas.get(ca_id)
            if ca is not None:
                serials.setdefault(C.public_blob(ca.public_key), []).append(from_db_serial(int(serial)))
    stamp = int(changed_at.replace(tzinfo=_dt.timezone.utc).timestamp()) if changed_at else 0
    data = krl.build(revoked_ca_blobs=revoked_cas, revoked_serials=serials, krl_version=generation, generated=stamp,
                     comment=f"ZeroShield SSH CA revocations, team {team_id}, generation {generation}")
    with _krl_lock:
        if len(_krl_cache) >= MAX_KRL_CACHE:
            _krl_cache.clear()
        _krl_cache[team_id] = (generation, data)
    return data, generation


def check_groups(groups: list[str]) -> list[str]:
    out = list(dict.fromkeys(g.strip() for g in groups if g and g.strip()))
    if len(out) > MAX_GROUPS or any(not _GROUP.match(g) for g in out):
        raise HTTPException(status_code=400, detail=f"group: up to {MAX_GROUPS} server groups, lowercase letters, "
                                                    "digits and . _ -")
    return out


def principals_text(team_id: int, groups: list[str]) -> str:
    lines = ["# /etc/ssh/zs-cbom/principals/zs-cbom: the certificate principals this server accepts for zs-cbom",
             f"# (team {team_id}): one per server group this server belongs to."]
    if not groups:
        lines.append(f"# No group given (?group=<name>); principals look like zs-{team_id}-<group>.")
    return "\n".join(lines + [f"zs-{team_id}-{g}" for g in groups]) + "\n"


# ----------------------------------------------------------------------------- tokens
def public_token(row: CbomSshCaTrustToken, fetchers: int = 0) -> dict[str, Any]:
    return {"id": row.id, "name": row.name, "prefix": row.prefix, "created_by_user_id": row.created_by_user_id,
            "created_at": iso_z(row.created_at), "last_used_at": iso_z(row.last_used_at),
            "revoked_at": iso_z(row.revoked_at), "fetchers": fetchers, "row_version": row.row_version}


def create_token(session: Session, team_id: int, user_id: int, name: str,
                 now: _dt.datetime) -> tuple[CbomSshCaTrustToken, str]:
    live = session.exec(select(func.count()).select_from(CbomSshCaTrustToken).where(
        CbomSshCaTrustToken.team_id == team_id, CbomSshCaTrustToken.revoked_at.is_(None))).one()  # type: ignore[union-attr]
    if live >= MAX_TOKENS_PER_TEAM:
        raise HTTPException(status_code=400, detail=f"A team can have at most {MAX_TOKENS_PER_TEAM} trust tokens; "
                                                    "revoke one first")
    secret = TOKEN_PREFIX + secrets.token_urlsafe(30)[:40]
    row = CbomSshCaTrustToken(team_id=team_id, name=name, token_hash=sha256_hex(secret), prefix=secret[:8],
                              created_by_user_id=user_id, created_at=now, last_updated=now)
    session.add(row)
    session.flush()
    audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="sshca.trust_token.create",
          object_type="ssh_trust_token", object_id=row.id, changed_fields=["name"])
    log("ssh ca trust token created", team=team_id, token=row.id, by=user_id)
    return row, secret


def list_tokens(session: Session, team_id: int, now: _dt.datetime) -> list[dict[str, Any]]:
    rows = session.exec(select(CbomSshCaTrustToken).where(CbomSshCaTrustToken.team_id == team_id)
                        .order_by(CbomSshCaTrustToken.id)).all()
    counts = dict(session.exec(select(CbomSshCaTrustFetch.token_id, func.count()).where(
        CbomSshCaTrustFetch.team_id == team_id, CbomSshCaTrustFetch.last_fetch_at >= now - ACTIVE_FETCHER)
        .group_by(CbomSshCaTrustFetch.token_id)).all())
    return [public_token(r, int(counts.get(r.id, 0))) for r in rows]


def revoke_token(session: Session, team_id: int, token_id: int, user_id: int, now: _dt.datetime) -> CbomSshCaTrustToken:
    row = session.get(CbomSshCaTrustToken, token_id)
    if row is None or row.team_id != team_id:
        raise HTTPException(status_code=404, detail="Trust token not found")
    if row.revoked_at is not None:
        raise HTTPException(status_code=400, detail="This trust token is already revoked")
    changed = session.exec(update(CbomSshCaTrustToken)  # type: ignore[call-overload]
                           .where(CbomSshCaTrustToken.id == row.id, CbomSshCaTrustToken.revoked_at.is_(None))  # type: ignore[union-attr]
                           .values(revoked_at=now, revoked_by_user_id=user_id, last_updated=now,
                                   row_version=CbomSshCaTrustToken.row_version + 1)
                           .execution_options(synchronize_session=False)).rowcount
    if changed != 1:
        raise HTTPException(status_code=409, detail="This was changed elsewhere. Reload to see the latest version.")
    session.expire(row)
    audit(session, team_id=team_id, actor_type="user", actor_id=user_id, action="sshca.trust_token.revoke",
          object_type="ssh_trust_token", object_id=row.id, changed_fields=["revoked_at"])
    log("ssh ca trust token revoked", team=team_id, token=row.id, by=user_id)
    return row


def authenticate(session: Session, secret: str | None) -> CbomSshCaTrustToken | None:
    """The live token for this secret, or None (unknown, malformed or revoked)."""
    if not secret or not TOKEN_RE.match(secret):
        return None
    row = session.exec(select(CbomSshCaTrustToken).where(CbomSshCaTrustToken.token_hash == sha256_hex(secret))).first()
    if row is None or row.revoked_at is not None:
        return None
    return row


def fetcher_name(header: str | None, token: CbomSshCaTrustToken) -> str:
    name = _FETCHER_BAD.sub("", (header or "").strip())[:128]
    return name or f"token-{token.id}"


def record_fetch(session: Session, token: CbomSshCaTrustToken, fetcher: str, ip: str, now: _dt.datetime, *,
                 trust_generation: int | None = None, revocation_generation: int | None = None) -> None:
    """Remember what this fetcher received (and touch the token), in the caller's transaction.  Written only when a
    generation changed or the last write is older than ``FETCH_WRITE_EVERY`` (10,000 servers polling every few
    minutes would otherwise write on every request)."""
    if token.last_used_at is None or now - token.last_used_at >= TOKEN_TOUCH_EVERY:
        session.exec(update(CbomSshCaTrustToken).where(CbomSshCaTrustToken.id == token.id)  # type: ignore[call-overload]
                     .values(last_used_at=now).execution_options(synchronize_session=False))
    row = session.exec(select(CbomSshCaTrustFetch).where(CbomSshCaTrustFetch.token_id == token.id,
                                                         CbomSshCaTrustFetch.fetcher == fetcher)).first()
    if row is not None:
        same = ((trust_generation is None or row.trust_generation == trust_generation)
                and (revocation_generation is None or row.revocation_generation == revocation_generation))
        if same and now - row.last_fetch_at < FETCH_WRITE_EVERY:
            return
        values: dict[str, Any] = {"last_fetch_at": now, "last_ip": ip[:64], "last_updated": now,
                                  "row_version": CbomSshCaTrustFetch.row_version + 1}
        if trust_generation is not None:
            values["trust_generation"] = trust_generation
        if revocation_generation is not None:
            values["revocation_generation"] = revocation_generation
        session.exec(update(CbomSshCaTrustFetch).where(CbomSshCaTrustFetch.id == row.id)  # type: ignore[call-overload]
                     .values(**values).execution_options(synchronize_session=False))
        return
    known = session.exec(select(func.count()).select_from(CbomSshCaTrustFetch)
                         .where(CbomSshCaTrustFetch.team_id == token.team_id)).one()
    if known >= MAX_FETCHERS_PER_TEAM:
        return  # served, not tracked (the readiness counts say "of the tracked fetchers")
    table = CbomSshCaTrustFetch.__table__  # type: ignore[attr-defined]
    insert = postgresql.insert if session.get_bind().dialect.name == "postgresql" else sqlite.insert
    values = {"team_id": token.team_id, "token_id": token.id, "fetcher": fetcher, "trust_generation": trust_generation,
              "revocation_generation": revocation_generation, "first_fetch_at": now, "last_fetch_at": now,
              "last_ip": ip[:64], "row_version": 1, "created_at": now, "last_updated": now}
    session.execute(insert(table).values(**values).on_conflict_do_nothing(index_elements=["token_id", "fetcher"]))


# ----------------------------------------------------------------------------- promote readiness
def promote_min_age_s() -> int:
    try:
        return max(0, int(os.environ.get(PROMOTE_MIN_AGE_ENV, PROMOTE_MIN_AGE_S)))
    except ValueError:
        return PROMOTE_MIN_AGE_S


def readiness(session: Session, row: CbomSshCa, now: _dt.datetime) -> dict[str, Any] | None:
    """For a ``next`` CA: its age against the minimum, and how many active fetchers already have the generation that
    added it."""
    if row.state != "next":
        return None
    since = now - ACTIVE_FETCHER
    base = select(func.count()).select_from(CbomSshCaTrustFetch).where(
        CbomSshCaTrustFetch.team_id == row.team_id, CbomSshCaTrustFetch.last_fetch_at >= since)
    total = int(session.exec(base).one())
    ready = int(session.exec(base.where(CbomSshCaTrustFetch.trust_generation >= int(row.trust_generation or 0))).one()) \
        if row.trust_generation else 0
    created = row.created_at or now
    min_age = promote_min_age_s()
    return {"age_s": max(0, int((now - created).total_seconds())), "min_age_s": min_age,
            "promote_after": iso_z(created + _dt.timedelta(seconds=min_age)), "fetchers_total": total,
            "fetchers_ready": ready}


def purge_fetchers(session: Session, now: _dt.datetime, older_than: _dt.timedelta = _dt.timedelta(days=30)) -> int:
    from sqlalchemy import delete

    return int(session.exec(delete(CbomSshCaTrustFetch).where(  # type: ignore[call-overload]
        CbomSshCaTrustFetch.last_fetch_at < now - older_than)).rowcount or 0)
