"""Single sign-on per team (F4 PR 2): configuration, verified domains, the browser round trip, JIT, enforcement.

Round trip (the SPA and the API are different origins; the API is never called with a cookie except here):

1. The SPA makes a random ``client_nonce``, keeps it in sessionStorage, and sends the browser (top-level) to
   ``GET /sso/{team}/start?redirect=/path&cn=<sha256(client_nonce)>``.
2. ``start`` stores a ``SsoLoginState`` (10 min, single use: OIDC state / SAML RelayState, PKCE verifier, nonce or
   SAML request id, the redirect path, the client-nonce hash) and sets a random HttpOnly cookie on the API origin
   whose SHA-256 is in the row, then redirects to the IdP.
3. The IdP returns the browser to the OIDC callback (GET) or the SAML ACS (cross-site POST).  The callback refuses
   unless the cookie matches the state row (login CSRF, session fixation), verifies the IdP's answer (``oidc.py`` /
   ``saml.py``), applies the team's rules (verified domain, JIT, superusers never), and stores a ``SsoHandoff``
   (60 s, single use, bound to the client-nonce hash).  It redirects to ``APP/sso/complete#code=...``: the code
   travels in the fragment (never sent to a server, never in a log), tokens never travel in a URL.
4. The SPA posts the code with its ``client_nonce`` to ``POST /sso/exchange`` and gets the usual tokens.  A code
   planted in another browser is useless there: that browser has no matching ``client_nonce``.

Redirect paths are relative paths on the SPA only (``safe_redirect_path``): no open redirect.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import logging
import os
import re
import secrets
from dataclasses import dataclass
from typing import Callable, Optional

from fastapi import HTTPException, status
from sqlalchemy import delete, func, update
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from backend.access_models import SsoAssertionSeen, SsoHandoff, SsoLoginState, TeamSsoConfig, TeamSsoDomain
from backend.new_models import Team, TeamMembership, User
from backend.utilities.auth.auth_utils import normalise_email, user_by_email
from backend.utilities.rbac import audit

log = logging.getLogger("backend.sso")

STATE_TTL = dt.timedelta(minutes=10)
HANDOFF_TTL = dt.timedelta(seconds=60)
COOKIE = "zs_sso"
JIT_ROLES = ("viewer", "member")
TXT_PREFIX = "devsecshield-verification="
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


class SsoRefused(Exception):
    """A sign-in the team's rules refuse; ``str(err)`` is shown to the person."""


class SsoUnavailable(Exception):
    pass


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------------------------- server addresses

def public_api_url() -> str:
    """The API's public base URL (redirect URI, ACS, SP entity id).  Configured, never taken from the request's Host
    header (which a client chooses)."""
    url = (os.getenv("SSO_PUBLIC_API_URL") or "").strip().rstrip("/")
    if not url.startswith(("https://", "http://")):
        raise SsoUnavailable("Single sign-on is not set up on this server (SSO_PUBLIC_API_URL)")
    return url


def app_url() -> str:
    return (os.environ.get("CBOM_PUBLIC_APP_URL") or "https://devsecshield.zeroshield.ai").strip().rstrip("/")


def oidc_redirect_uri(team_id: int) -> str:
    return f"{public_api_url()}/sso/{team_id}/oidc/callback"


def saml_acs_url(team_id: int) -> str:
    return f"{public_api_url()}/sso/{team_id}/saml/acs"


def saml_sp_entity_id(team_id: int) -> str:
    return f"{public_api_url()}/sso/{team_id}/saml"


def cookie_secure() -> bool:
    return public_api_url().startswith("https://")


def safe_redirect_path(value: Optional[str]) -> str:
    """A path on the SPA, or "/home".  Never a URL, a scheme-relative ``//host``, a backslash or a control char."""
    value = (value or "").strip()
    if (not value.startswith("/") or value.startswith("//") or value.startswith("/\\") or "\\" in value
            or len(value) > 512 or any(ord(c) < 0x20 or ord(c) == 0x7F for c in value) or "://" in value):
        return "/home"
    return value


def domain_of(email: str) -> str:
    return normalise_email(email).rpartition("@")[2]


def clean_domain(value: str) -> str:
    domain = (value or "").strip().lower().rstrip(".")
    if domain.startswith("@"):
        domain = domain[1:]
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        raise HTTPException(status_code=400, detail="domain: not a valid domain name") from None
    if not _DOMAIN_RE.match(domain):
        raise HTTPException(status_code=400, detail="domain: not a valid domain name (e.g. example.com)")
    return domain


# --------------------------------------------------------------------------------------------- configuration

def config_of(session: Session, team_id: int) -> Optional[TeamSsoConfig]:
    return session.exec(select(TeamSsoConfig).where(TeamSsoConfig.team_id == team_id)).first()


def verified_domains(session: Session, team_id: int) -> list[str]:
    rows = session.exec(select(TeamSsoDomain.domain).where(TeamSsoDomain.team_id == team_id,
                                                           TeamSsoDomain.verified_at.isnot(None))).all()  # type: ignore[union-attr]
    return sorted(rows)


def public_config(session: Session, team_id: int) -> dict:
    cfg = config_of(session, team_id)
    domains = session.exec(select(TeamSsoDomain).where(TeamSsoDomain.team_id == team_id)
                           .order_by(TeamSsoDomain.domain)).all()
    try:
        sp = {"oidc_redirect_uri": oidc_redirect_uri(team_id), "saml_acs_url": saml_acs_url(team_id),
              "saml_sp_entity_id": saml_sp_entity_id(team_id),
              "saml_metadata_url": f"{public_api_url()}/sso/{team_id}/saml/metadata",
              "login_url": f"{app_url()}/login?sso={team_id}", "available": True}
    except SsoUnavailable as exc:
        sp = {"available": False, "reason": str(exc)}
    return {
        "config": None if cfg is None else {
            "protocol": cfg.protocol, "enabled": cfg.enabled, "enforced": cfg.enforced, "jit": cfg.jit,
            "default_role": cfg.default_role, "oidc_issuer": cfg.oidc_issuer, "oidc_client_id": cfg.oidc_client_id,
            "oidc_client_secret_set": bool(cfg.oidc_secret_encrypted), "oidc_scopes": cfg.oidc_scopes,
            "saml_idp_entity_id": cfg.saml_idp_entity_id, "saml_idp_sso_url": cfg.saml_idp_sso_url,
            "saml_idp_cert_count": len(cfg.saml_idp_certs or []), "row_version": cfg.row_version,
        },
        "domains": [{"id": d.id, "domain": d.domain, "verified": d.verified_at is not None,
                     "verified_at": d.verified_at.replace(microsecond=0).isoformat() + "Z" if d.verified_at else None,
                     "verify_method": d.verify_method,
                     "txt_record": {"name": d.domain, "value": TXT_PREFIX + d.verification_token}} for d in domains],
        "sp": sp,
    }


def _pem_certs(values: list[str]) -> list[str]:
    from cryptography import x509

    out = []
    for value in values:
        text = (value or "").strip()
        if not text:
            continue
        if "BEGIN CERTIFICATE" not in text:  # a bare base64 certificate, as IdP metadata shows it
            body = re.sub(r"\s+", "", text)
            text = "-----BEGIN CERTIFICATE-----\n" + "\n".join(body[i:i + 64] for i in range(0, len(body), 64)) \
                   + "\n-----END CERTIFICATE-----\n"
        try:
            x509.load_pem_x509_certificate(text.encode("ascii"))
        except (ValueError, UnicodeEncodeError):
            raise HTTPException(status_code=400, detail="saml_idp_certs: not an X.509 certificate") from None
        out.append(text)
    if len(out) > 4:
        raise HTTPException(status_code=400, detail="saml_idp_certs: at most 4 certificates (current and next)")
    return out


@dataclass
class ConfigInput:
    protocol: str
    enabled: bool
    enforced: bool
    jit: bool
    default_role: str
    oidc_issuer: Optional[str] = None
    oidc_client_id: Optional[str] = None
    oidc_client_secret: Optional[str] = None  # None or "": keep the stored secret
    oidc_scopes: Optional[str] = None
    saml_idp_entity_id: Optional[str] = None
    saml_idp_sso_url: Optional[str] = None
    saml_idp_certs: Optional[list[str]] = None
    expected_version: Optional[int] = None


def save_config(engine: Engine, team_id: int, data: ConfigInput, actor, meta: dict) -> dict:
    from backend.utilities.cbom_sources.crypto import encrypt_secrets
    from backend.utilities.sso import http as sso_http

    if data.protocol not in ("oidc", "saml"):
        raise HTTPException(status_code=400, detail="protocol: choose oidc or saml")
    if data.default_role not in JIT_ROLES:
        raise HTTPException(status_code=400, detail="default_role: new members join as viewer or member")
    with Session(engine) as session:
        session.exec(select(Team).where(Team.id == team_id).with_for_update()).first()
        cfg = config_of(session, team_id) or TeamSsoConfig(team_id=team_id)
        if data.expected_version is not None and cfg.id is not None and cfg.row_version != data.expected_version:
            raise HTTPException(status_code=409, detail="This was changed elsewhere. Reload to see the latest version.")
        changed = []
        for name in ("protocol", "enabled", "enforced", "jit", "default_role"):
            if getattr(cfg, name) != getattr(data, name):
                changed.append(name)
                setattr(cfg, name, getattr(data, name))
        if data.protocol == "oidc":
            for name in ("oidc_issuer", "oidc_client_id", "oidc_scopes"):
                value = (getattr(data, name) or "").strip() or None
                if name == "oidc_scopes":
                    value = value or "openid email profile"
                    if "openid" not in value.split() or "email" not in value.split():
                        raise HTTPException(status_code=400, detail="oidc_scopes: include openid and email")
                if value != getattr(cfg, name):
                    changed.append(name)
                    setattr(cfg, name, value)
            if cfg.oidc_issuer:
                try:
                    sso_http.check_url(cfg.oidc_issuer)
                except sso_http.SsoHttpError as exc:
                    raise HTTPException(status_code=400, detail=f"oidc_issuer: {exc}") from None
            if data.oidc_client_secret:
                if len(data.oidc_client_secret) > 512:
                    raise HTTPException(status_code=400, detail="oidc_client_secret: at most 512 characters")
                cfg.oidc_secret_encrypted = encrypt_secrets({"client_secret": data.oidc_client_secret})
                changed.append("oidc_client_secret")
            if data.enabled and not (cfg.oidc_issuer and cfg.oidc_client_id):
                raise HTTPException(status_code=400, detail="Enter the issuer and client id before turning SSO on")
        else:
            for name in ("saml_idp_entity_id", "saml_idp_sso_url"):
                value = (getattr(data, name) or "").strip() or None
                if value != getattr(cfg, name):
                    changed.append(name)
                    setattr(cfg, name, value)
            if cfg.saml_idp_sso_url:
                try:
                    sso_http.check_url(cfg.saml_idp_sso_url)
                except sso_http.SsoHttpError as exc:
                    raise HTTPException(status_code=400, detail=f"saml_idp_sso_url: {exc}") from None
            if data.saml_idp_certs is not None:
                certs = _pem_certs(data.saml_idp_certs)
                if certs != (cfg.saml_idp_certs or []):
                    cfg.saml_idp_certs = certs
                    changed.append("saml_idp_certs")
            if data.enabled and not (cfg.saml_idp_entity_id and cfg.saml_idp_sso_url and cfg.saml_idp_certs):
                raise HTTPException(status_code=400,
                                    detail="Enter the IdP entity id, sign-in URL and signing certificate before turning SSO on")
        if data.enforced and not data.enabled:
            raise HTTPException(status_code=400, detail="Turn SSO on before requiring it")
        if data.enforced and not verified_domains(session, team_id):
            raise HTTPException(status_code=400, detail="Verify at least one email domain before requiring SSO")
        cfg.updated_by_user_id = actor.user_id
        cfg.last_updated = utcnow()
        if cfg.id is not None:
            cfg.row_version += 1
        session.add(cfg)
        session.flush()
        audit.record(session, action="team.sso.config", team_id=team_id, object_type="sso", object_id=cfg.id,
                     ip=meta.get("ip"), user_agent=meta.get("user_agent"),
                     details={"changed": sorted(set(changed)), "protocol": cfg.protocol, "enabled": cfg.enabled,
                              "enforced": cfg.enforced}, **audit.actor_fields(actor))
        session.commit()
        return public_config(session, team_id)


def add_domain(engine: Engine, team_id: int, raw: str, actor, meta: dict) -> dict:
    domain = clean_domain(raw)
    with Session(engine) as session:
        count = session.exec(select(func.count()).select_from(TeamSsoDomain).where(TeamSsoDomain.team_id == team_id)).one()
        if int(count) >= 20:
            raise HTTPException(status_code=400, detail="A team can claim at most 20 domains")
        row = TeamSsoDomain(team_id=team_id, domain=domain, verification_token=secrets.token_hex(16))
        session.add(row)
        try:
            session.flush()
        except IntegrityError:
            session.rollback()
            raise HTTPException(status_code=409, detail=f"{domain} is already on this team's list") from None
        audit.record(session, action="team.sso.domain.add", team_id=team_id, object_type="sso_domain",
                     object_id=domain, ip=meta.get("ip"), user_agent=meta.get("user_agent"), details={"domain": domain},
                     **audit.actor_fields(actor))
        session.commit()
        return public_config(session, team_id)


def dns_txt_values(name: str) -> list[str]:
    import dns.exception
    import dns.resolver

    try:
        answer = dns.resolver.resolve(name, "TXT", lifetime=8.0)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        raise HTTPException(status_code=503, detail="The DNS lookup timed out: try again") from None
    values = []
    for record in answer:
        values.append(b"".join(record.strings).decode("utf-8", "replace"))
    return values


def verify_domain(engine: Engine, team_id: int, domain_id: int, actor, meta: dict, *,
                  method: str = "dns", txt_lookup: Callable[[str], list[str]] = None) -> dict:
    """DNS: the TXT record ``devsecshield-verification=<token>`` on the domain itself.  ``method="superuser"``: a
    platform operator vouches (air-gapped installs, audited)."""
    with Session(engine) as session:
        row = session.get(TeamSsoDomain, domain_id)
        if row is None or row.team_id != team_id:
            raise HTTPException(status_code=404, detail="Domain not found")
        if row.verified_at is None:
            if method == "dns":
                expected = TXT_PREFIX + row.verification_token
                values = (txt_lookup or dns_txt_values)(row.domain)
                if not any(hmac.compare_digest(v.strip(), expected) for v in values):
                    raise HTTPException(status_code=400,
                                        detail=f"No TXT record {expected!r} on {row.domain} yet (DNS changes can take a while)")
            row.verified_at, row.verified_by_user_id, row.verify_method = utcnow(), actor.user_id, method
            session.add(row)
            try:
                session.flush()
            except IntegrityError:
                session.rollback()
                raise HTTPException(status_code=409,
                                    detail=f"{row.domain} is already verified by another team") from None
            audit.record(session, action="team.sso.domain.verify", team_id=team_id, object_type="sso_domain",
                         object_id=row.domain, ip=meta.get("ip"), user_agent=meta.get("user_agent"),
                         details={"domain": row.domain, "method": method}, **audit.actor_fields(actor))
            session.commit()
        return public_config(session, team_id)


def delete_domain(engine: Engine, team_id: int, domain_id: int, actor, meta: dict) -> dict:
    with Session(engine) as session:
        row = session.get(TeamSsoDomain, domain_id)
        if row is None or row.team_id != team_id:
            raise HTTPException(status_code=404, detail="Domain not found")
        cfg = config_of(session, team_id)
        if cfg is not None and cfg.enforced and row.verified_at is not None and \
                verified_domains(session, team_id) == [row.domain]:
            raise HTTPException(status_code=400, detail="Stop requiring SSO before removing its last verified domain")
        audit.record(session, action="team.sso.domain.remove", team_id=team_id, object_type="sso_domain",
                     object_id=row.domain, ip=meta.get("ip"), user_agent=meta.get("user_agent"),
                     details={"domain": row.domain}, **audit.actor_fields(actor))
        session.delete(row)
        session.commit()
        return public_config(session, team_id)


# --------------------------------------------------------------------------------------------- discovery

def team_for_email(session: Session, email: str) -> Optional[TeamSsoConfig]:
    """The enabled SSO configuration of the team that verified the address's domain (domain capture)."""
    domain = domain_of(email)
    if not domain:
        return None
    row = session.exec(select(TeamSsoDomain).where(TeamSsoDomain.domain == domain,
                                                   TeamSsoDomain.verified_at.isnot(None))).first()  # type: ignore[union-attr]
    if row is None:
        return None
    cfg = config_of(session, row.team_id)
    return cfg if cfg is not None and cfg.enabled else None


def discover(engine: Engine, email: str) -> dict:
    with Session(engine) as session:
        cfg = team_for_email(session, email)
        if cfg is None:
            return {"sso": False}
        return {"sso": True, "team_id": cfg.team_id, "protocol": cfg.protocol, "enforced": cfg.enforced}


def enforced_for(session: Session, email: str) -> Optional[TeamSsoConfig]:
    cfg = team_for_email(session, email)
    return cfg if cfg is not None and cfg.enforced else None


def is_owner(session: Session, team_id: int, user_id: int) -> bool:
    return session.exec(select(TeamMembership.role).where(TeamMembership.team_id == team_id,
                                                          TeamMembership.user_id == user_id)).first() == "owner"


# --------------------------------------------------------------------------------------------- round trip

def _active_config(session: Session, team_id: int) -> TeamSsoConfig:
    cfg = config_of(session, team_id)
    if cfg is None or not cfg.enabled:
        raise SsoRefused("Single sign-on is not turned on for this team")
    return cfg


def start(engine: Engine, team_id: int, *, redirect: Optional[str], client_nonce_hash: str,
          login_hint: Optional[str] = None) -> tuple[str, str]:
    """(IdP URL, cookie value).  ``client_nonce_hash`` is the SHA-256 (hex) of the SPA's sessionStorage nonce."""
    from backend.utilities.sso import oidc, saml

    if not _SHA256_HEX.match(client_nonce_hash or ""):
        raise SsoRefused("Start single sign-on from the sign-in page")
    now = utcnow()
    with Session(engine) as session:
        cfg = _active_config(session, team_id)
        cookie = secrets.token_urlsafe(32)
        state = SsoLoginState(id=secrets.token_urlsafe(32), team_id=team_id, protocol=cfg.protocol,
                              binding_hash=sha256_hex(cookie), client_nonce_hash=client_nonce_hash,
                              redirect_path=safe_redirect_path(redirect), created_at=now, expires_at=now + STATE_TTL)
        hint = normalise_email(login_hint) if login_hint and "@" in login_hint else None
        if cfg.protocol == "oidc":
            verifier, challenge = oidc.pkce_pair()
            state.pkce_verifier, state.nonce = verifier, secrets.token_urlsafe(32)
            try:
                doc = oidc.discovery(cfg.oidc_issuer or "")
            except Exception as exc:
                log.warning("sso start: discovery failed for team %s (%s)", team_id, type(exc).__name__)
                raise SsoRefused(f"The identity provider cannot be reached: {exc}") from None
            url = oidc.authorization_url(doc, client_id=cfg.oidc_client_id or "", redirect_uri=oidc_redirect_uri(team_id),
                                         state=state.id, nonce=state.nonce, challenge=challenge,
                                         scopes=cfg.oidc_scopes, login_hint=hint)
        else:
            state.saml_request_id = saml.new_request_id()
            url = saml.authn_request_url(idp_sso_url=cfg.saml_idp_sso_url or "", sp_entity_id=saml_sp_entity_id(team_id),
                                         acs_url=saml_acs_url(team_id), request_id=state.saml_request_id,
                                         relay_state=state.id, now=now)
        session.add(state)
        session.commit()
        return url, cookie


def _take_state(session: Session, team_id: int, state_id: str, cookie: Optional[str], protocol: str,
                now: dt.datetime) -> SsoLoginState:
    """The state row, consumed (compare-and-set: once), if this browser holds its cookie."""
    row = session.get(SsoLoginState, (state_id or "")[:64])
    if row is None or row.team_id != team_id or row.protocol != protocol:
        raise SsoRefused("This sign-in was not started here, or it was already used: start again")
    if row.used_at is not None or row.expires_at <= now:
        raise SsoRefused("This sign-in has expired or was already used: start again")
    if not cookie or not hmac.compare_digest(sha256_hex(cookie), row.binding_hash):
        raise SsoRefused("This sign-in was started in another browser: start again here")
    done = session.exec(update(SsoLoginState).where(SsoLoginState.id == row.id, SsoLoginState.used_at.is_(None))
                        .values(used_at=now)).rowcount  # type: ignore[union-attr]
    if done != 1:
        raise SsoRefused("This sign-in was already used: start again")
    return row


def _remember_assertion(session: Session, team_id: int, issuer: str, assertion_id: str, expires: dt.datetime) -> None:
    key = sha256_hex(f"{team_id}\n{issuer}\n{assertion_id}")
    session.add(SsoAssertionSeen(key=key, team_id=team_id, expires_at=expires))
    try:
        session.flush()
    except IntegrityError:
        session.rollback()
        raise SsoRefused("This SAML assertion was already used (replay)") from None


def _sign_in(session: Session, cfg: TeamSsoConfig, email: str, display_name: Optional[str], protocol: str,
             meta: dict, now: dt.datetime) -> tuple[User, dict]:
    email = normalise_email(email)
    domain = domain_of(email)
    if domain not in verified_domains(session, cfg.team_id):
        raise SsoRefused(f"{domain} is not a verified domain of this team, so its single sign-on cannot sign you in")
    user = user_by_email(session, email)
    created = joined = False
    if user is not None and user.is_superuser:
        raise SsoRefused("Platform administrators sign in with their password and code, not through a team's SSO")
    if user is None:
        if not cfg.jit:
            raise SsoRefused("No account uses this address yet: ask a team admin to invite you")
        first, _, last = (display_name or email.split("@")[0]).partition(" ")
        default = Team(name=f"{first[:40]}'s Default Team", description=f"Default team for {first[:40]}")
        session.add(default)
        session.flush()
        user = User(email=email, password="!sso-only:" + secrets.token_hex(16), first_name=first[:64] or None,
                    last_name=last[:64] or None, profile_photo=None, session_active=True, default_team_id=default.id)
        session.add(user)
        session.flush()
        session.add(TeamMembership(team_id=default.id, user_id=user.id, role="owner"))
        created = True
    membership = session.get(TeamMembership, (cfg.team_id, user.id))
    if membership is None:
        if not cfg.jit:
            raise SsoRefused("You are not a member of this team yet: ask a team admin to invite you")
        session.add(TeamMembership(team_id=cfg.team_id, user_id=user.id, role=cfg.default_role))
        joined = True
    user.session_active = True
    user.last_active = now
    session.add(user)
    session.flush()
    details = {"protocol": protocol, "account_created": created, "joined_with_role": cfg.default_role if joined else None}
    audit.record(session, action="auth.login.sso", team_id=cfg.team_id, actor_user_id=user.id, actor_email=email,
                 actor_type="sso", object_type="account", object_id=user.id, ip=meta.get("ip"),
                 user_agent=meta.get("user_agent"), details={k: v for k, v in details.items() if v is not None})
    return user, details


def _handoff(session: Session, state: SsoLoginState, user: User, now: dt.datetime) -> str:
    code = secrets.token_urlsafe(32)
    session.add(SsoHandoff(code_hash=sha256_hex(code), user_id=user.id, team_id=state.team_id,
                           client_nonce_hash=state.client_nonce_hash, redirect_path=state.redirect_path,
                           protocol=state.protocol, expires_at=now + HANDOFF_TTL))
    return code


def refused_event(engine: Engine, team_id: int, protocol: str, reason: str, meta: dict, email: Optional[str] = None) -> None:
    try:
        audit.record_now(engine, action="auth.login.sso", outcome="denied", team_id=team_id, actor_type="sso",
                         actor_email=normalise_email(email) if email else None, ip=meta.get("ip"),
                         user_agent=meta.get("user_agent"), details={"protocol": protocol, "reason": reason[:200]})
    except Exception as exc:
        log.error("audit: refused SSO sign-in not recorded (%s)", type(exc).__name__)


def finish_oidc(engine: Engine, team_id: int, *, state_id: str, cookie: Optional[str], code: str, meta: dict) -> str:
    from backend.utilities.cbom_sources.crypto import decrypt_secrets
    from backend.utilities.sso import oidc

    now = utcnow()
    with Session(engine) as session:
        state = _take_state(session, team_id, state_id, cookie, "oidc", now)
        session.commit()  # the state is spent whatever happens next
        cfg = _active_config(session, team_id)
        if cfg.protocol != "oidc":
            raise SsoRefused("This team signs in with SAML now: start again")
        try:
            doc = oidc.discovery(cfg.oidc_issuer or "")
            tokens = oidc.exchange_code(doc, client_id=cfg.oidc_client_id or "",
                                        client_secret=decrypt_secrets(cfg.oidc_secret_encrypted).get("client_secret"),
                                        code=code, redirect_uri=oidc_redirect_uri(team_id), verifier=state.pkce_verifier or "")
            identity = oidc.verify_id_token(doc, tokens["id_token"], issuer=cfg.oidc_issuer or "",
                                            client_id=cfg.oidc_client_id or "", nonce=state.nonce or "", now=now)
        except oidc.OidcError as exc:
            raise SsoRefused(str(exc)) from None
        except Exception as exc:  # the IdP unreachable or answering nonsense
            from backend.utilities.sso.http import SsoHttpError
            if isinstance(exc, SsoHttpError):
                raise SsoRefused(str(exc)) from None
            raise
        user, _ = _sign_in(session, cfg, identity.email, identity.name, "oidc", meta, now)
        result = _handoff(session, state, user, now)
        session.commit()
        return result


def finish_saml(engine: Engine, team_id: int, *, relay_state: str, cookie: Optional[str], saml_response: str,
                meta: dict) -> str:
    from backend.utilities.sso import saml

    now = utcnow()
    with Session(engine) as session:
        state = _take_state(session, team_id, relay_state, cookie, "saml", now)
        session.commit()
        cfg = _active_config(session, team_id)
        if cfg.protocol != "saml":
            raise SsoRefused("This team signs in with OIDC now: start again")
        try:
            identity = saml.parse_response(saml_response, idp_certs=list(cfg.saml_idp_certs or []),
                                           idp_entity_id=cfg.saml_idp_entity_id or "",
                                           sp_entity_id=saml_sp_entity_id(team_id), acs_url=saml_acs_url(team_id),
                                           request_id=state.saml_request_id or "", now=now)
        except saml.SamlError as exc:
            raise SsoRefused(str(exc)) from None
        _remember_assertion(session, team_id, cfg.saml_idp_entity_id or "", identity.assertion_id, identity.expires_at)
        display = " ".join(filter(None, [(identity.attributes.get("firstName") or [None])[0],
                                         (identity.attributes.get("lastName") or [None])[0]])) or None
        user, _ = _sign_in(session, cfg, identity.email, display, "saml", meta, now)
        result = _handoff(session, state, user, now)
        session.commit()
        return result


def exchange(engine: Engine, code: str, client_nonce: str) -> tuple[User, str, int]:
    """(user, redirect path, team id) for a valid, unused, unexpired code shown with its client nonce."""
    now = utcnow()
    with Session(engine) as session:
        row = session.get(SsoHandoff, sha256_hex(code or ""))
        if row is None or row.used_at is not None or row.expires_at <= now:
            raise SsoRefused("This sign-in link has expired or was already used: sign in again")
        if not client_nonce or not hmac.compare_digest(sha256_hex(client_nonce), row.client_nonce_hash):
            raise SsoRefused("This sign-in was started in another browser tab or browser: sign in again here")
        done = session.exec(update(SsoHandoff).where(SsoHandoff.code_hash == row.code_hash, SsoHandoff.used_at.is_(None))
                            .values(used_at=now)).rowcount  # type: ignore[union-attr]
        if done != 1:
            raise SsoRefused("This sign-in link was already used: sign in again")
        user = session.get(User, row.user_id)
        if user is None:
            raise SsoRefused("The account no longer exists")
        session.commit()
        session.refresh(user)
        return user, row.redirect_path, row.team_id


def purge_expired(engine: Engine) -> int:
    """Old round-trip rows (states, hand-offs, assertion ids past their expiry)."""
    now = utcnow()
    removed = 0
    with Session(engine) as session:
        for model in (SsoLoginState, SsoHandoff, SsoAssertionSeen):
            removed += session.exec(  # type: ignore[call-overload]
                delete(model).where(model.expires_at < now - dt.timedelta(hours=1))).rowcount or 0
        session.commit()
    return removed
