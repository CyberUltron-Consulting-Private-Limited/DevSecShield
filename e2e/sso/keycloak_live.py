"""Live single sign-on against a real Keycloak (F4 SSO): a scripted browser signs in through Keycloak's own login
pages, over OIDC and SAML, against a running DevSecShield API.  Browser-less: ``requests`` keeps the cookies a
browser would, follows Keycloak's forms and the SAML POST binding page, and never runs JavaScript.

    # 1. API database: tables + a team, its owner, an existing member and the SSO settings (prints the team id)
    python e2e/sso/keycloak_live.py seed --db-url postgresql+psycopg2://... --lab lab.json
    # 2. API: uvicorn backend.main:app with SSO_PUBLIC_API_URL / SSO_ALLOWED_IDP_ORIGINS / CBOM_PUBLIC_APP_URL
    # 3. the sign-ins (the lab file comes from keycloak_lab.py setup --team-id <id>)
    python e2e/sso/keycloak_live.py run --api http://127.0.0.1:8099 --app http://127.0.0.1:3999 \
        --db-url ... --lab lab.json --team <id> --out evidence.json

``run`` writes an evidence file: every step's HTTP status and outcome, the audit rows written, never a token, a
password, a code or a client secret.  Exit 0 when every expectation held.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import sys
from html import unescape
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import requests

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

DOMAIN = "acme-sso.test"
OWNER = f"olivia@{DOMAIN}"


def _engine(url: str):
    from sqlmodel import create_engine
    return create_engine(url)


# ------------------------------------------------------------------------------------------------ seed

def seed(args) -> int:
    from sqlmodel import Session, SQLModel

    import backend.access_models  # noqa: F401  (registers the F4 tables)
    from backend.access_models import TeamSsoConfig, TeamSsoDomain
    from backend.new_models import Team, TeamMembership, User
    from backend.utilities.auth.auth_utils import get_hashed_password
    from backend.utilities.cbom_sources.crypto import encrypt_secrets

    lab = json.loads(Path(args.lab).read_text()) if args.lab else None
    engine = _engine(args.db_url)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        team = Team(name="Acme (SSO lab)", description="F4 Keycloak lab")
        s.add(team)
        s.flush()
        for email, role in ((OWNER, "owner"), (f"alice@{DOMAIN}", "viewer")):
            own = Team(name=f"{email} default", description="default")
            s.add(own)
            s.flush()
            user = User(email=email, password=get_hashed_password(secrets.token_urlsafe(18)), first_name="Lab",
                        last_name="User", profile_photo=None, session_active=email == OWNER,
                        default_team_id=own.id)  # the owner is "signed in": run() mints its token
            s.add(user)
            s.flush()
            s.add(TeamMembership(team_id=own.id, user_id=user.id, role="owner"))
            s.add(TeamMembership(team_id=team.id, user_id=user.id, role=role))
        cfg = TeamSsoConfig(team_id=team.id, protocol="oidc", enabled=True, jit=True, default_role="member")
        if lab:
            cfg.oidc_issuer, cfg.oidc_client_id = lab["oidc"]["issuer"], lab["oidc"]["client_id"]
            cfg.oidc_secret_encrypted = encrypt_secrets({"client_secret": lab["oidc"]["client_secret"]})
        s.add(cfg)
        s.add(TeamSsoDomain(team_id=team.id, domain=DOMAIN, verification_token=secrets.token_hex(16),
                            verified_at=dt.datetime.now(dt.timezone.utc).replace(tzinfo=None),
                            verify_method="superuser"))
        s.commit()
        print(team.id)
    return 0


def configure(args) -> int:
    """Point the seeded team at the lab's realms (after keycloak_lab.py setup, which needs the team id)."""
    from sqlmodel import Session, select

    from backend.access_models import TeamSsoConfig
    from backend.utilities.cbom_sources.crypto import encrypt_secrets

    lab = json.loads(Path(args.lab).read_text())
    with Session(_engine(args.db_url)) as s:
        cfg = s.exec(select(TeamSsoConfig).where(TeamSsoConfig.team_id == args.team)).one()
        cfg.oidc_issuer, cfg.oidc_client_id = lab["oidc"]["issuer"], lab["oidc"]["client_id"]
        cfg.oidc_secret_encrypted = encrypt_secrets({"client_secret": lab["oidc"]["client_secret"]})
        s.add(cfg)
        s.commit()
    print("configured")
    return 0


# ------------------------------------------------------------------------------------------------ browser

class _LoopbackSession(requests.Session):
    """Browsers treat http://127.0.0.1 and http://localhost as secure contexts ("potentially trustworthy" origins),
    so they keep and send ``Secure`` cookies there; Keycloak marks its login cookies Secure even over http.  The
    stdlib cookie jar would never send them back over http (Keycloak: "Cookie not found"), so after each request
    loopback cookies are made sendable over http, as a browser would."""

    LOOPBACK = ("127.0.0.1", "localhost", "::1", "localhost.local")

    def request(self, *args, **kwargs):
        response = super().request(*args, **kwargs)
        for cookie in self.cookies:
            if cookie.domain.lstrip(".") in self.LOOPBACK:
                cookie.secure = False
        return response


class Browser:
    """Cookies and redirects as a browser keeps them; the proxy from the environment is never used (loopback)."""

    def __init__(self):
        self.s = _LoopbackSession()
        self.s.trust_env = False
        self.nonce = secrets.token_urlsafe(32)

    @property
    def cn(self) -> str:
        return hashlib.sha256(self.nonce.encode()).hexdigest()


def _form(html: str, form_id: str | None = None) -> tuple[str, dict]:
    from lxml import html as lhtml

    doc = lhtml.fromstring(html)
    forms = doc.xpath(f"//form[@id='{form_id}']") if form_id else doc.xpath("//form")
    if not forms:
        raise AssertionError("no form on the page")
    form = forms[0]
    fields = {i.get("name"): i.get("value") or "" for i in form.xpath(".//input[@name]")}
    return unescape(form.get("action")), fields


def _fragment(location: str, app: str) -> dict:
    assert location.startswith(app + "/sso/complete#"), location
    return {k: v[0] for k, v in parse_qs(location.split("#", 1)[1]).items()}


def keycloak_login(b: Browser, idp_url: str, username: str, password: str) -> requests.Response:
    page = b.s.get(idp_url, timeout=30)
    assert page.status_code == 200, (page.status_code, page.text[:200])
    action, fields = _form(page.text, "kc-form-login")
    fields.update({"username": username, "password": password})
    return b.s.post(action, data=fields, allow_redirects=False, timeout=30)


def start(b: Browser, api: str, team: int) -> requests.Response:
    r = b.s.get(f"{api}/sso/{team}/start", params={"cn": b.cn, "redirect": "/home"}, allow_redirects=False,
                timeout=30)
    assert r.status_code == 303, (r.status_code, r.text[:200])
    return r


def exchange(b: Browser, api: str, code: str) -> requests.Response:
    return b.s.post(f"{api}/sso/exchange", json={"code": code, "client_nonce": b.nonce}, timeout=30)


def whoami(b: Browser, api: str, tokens: dict) -> str:
    r = b.s.get(f"{api}/get_user", headers={"Authorization": f"Bearer {tokens['access_token']}"}, timeout=30)
    assert r.status_code == 200, r.text[:200]
    return r.json()["email"]


# ------------------------------------------------------------------------------------------------ run

def run(args) -> int:
    lab = json.loads(Path(args.lab).read_text())
    api, app, team = args.api.rstrip("/"), args.app.rstrip("/"), args.team
    steps: list[dict] = []
    ok = True

    def step(name: str, passed: bool, **facts):
        nonlocal ok
        ok = ok and passed
        steps.append({"step": name, "passed": passed, **facts})
        print(("PASS " if passed else "FAIL ") + name + " " + json.dumps(facts))

    def oidc_attempt(user: str, *, deliver_to: Browser | None = None):
        b = Browser()
        r = start(b, api, team)
        q = {k: v[0] for k, v in parse_qs(urlsplit(r.headers["location"]).query).items()}
        cookie = "zs_sso" in r.headers.get("set-cookie", "")
        back = keycloak_login(b, r.headers["location"], user, lab["users"][user])
        assert back.status_code in (302, 303), (back.status_code, back.text[:300])
        callback = back.headers["location"]
        target = deliver_to or b
        result = target.s.get(callback, allow_redirects=False, timeout=30)
        return b, q, cookie, callback, result

    # ---- OIDC: an existing member signs in
    b, q, cookie, callback, result = oidc_attempt("alice")
    frag = _fragment(result.headers["location"], app)
    tokens = exchange(b, api, frag.get("code", "")) if "code" in frag else None
    step("oidc: alice (existing viewer) signs in through Keycloak's login page", bool(tokens is not None and tokens.status_code == 200
         and whoami(b, api, tokens.json()) == f"alice@{DOMAIN}"),
         authorize_endpoint=urlsplit(lab["oidc"]["issuer"]).netloc, pkce=q.get("code_challenge_method"),
         challenge_len=len(q.get("code_challenge", "")), state_sent=bool(q.get("state")), nonce_sent=bool(q.get("nonce")),
         binding_cookie=cookie, callback_status=result.status_code, exchange_status=tokens.status_code if tokens else None)
    again = b.s.get(callback, allow_redirects=False, timeout=30)
    step("oidc: the same callback URL again is refused (state single use)",
         "already used" in _fragment(again.headers["location"], app).get("error", ""),
         error=_fragment(again.headers["location"], app).get("error"))
    replay = exchange(b, api, frag["code"])
    step("oidc: the hand-off code works once", replay.status_code == 400, status=replay.status_code)

    # ---- OIDC: JIT
    b, _q, _c, _cb, result = oidc_attempt("bob")
    frag = _fragment(result.headers["location"], app)
    tokens = exchange(b, api, frag.get("code", "")) if "code" in frag else None
    step("oidc: bob (no account) is created just in time", bool(tokens is not None and tokens.status_code == 200
         and whoami(b, api, tokens.json()) == f"bob@{DOMAIN}"), error=frag.get("error"))

    # ---- OIDC: refusals
    _b, _q, _c, _cb, result = oidc_attempt("mallory")
    err = _fragment(result.headers["location"], app).get("error", "")
    step("oidc: mallory (verified email, another domain) is refused", "not a verified domain" in err, error=err)
    _b, _q, _c, _cb, result = oidc_attempt("unverified")
    err = _fragment(result.headers["location"], app).get("error", "")
    step("oidc: an email Keycloak has not verified is refused", "not verified" in err, error=err)
    victim = Browser()
    _b, _q, _c, _cb, result = oidc_attempt("alice", deliver_to=victim)
    err = _fragment(result.headers["location"], app).get("error", "")
    step("oidc: login CSRF - a valid callback delivered to another browser is refused", "another browser" in err,
         error=err)

    # ---- SAML: switch the team to the SAML realm through the owners' API
    from backend.utilities.auth.auth_utils import create_access_token
    owner = {"Authorization": f"Bearer {create_access_token(OWNER, version=0)}"}
    s = requests.Session()
    s.trust_env = False
    current = s.get(f"{api}/team/{team}/sso", headers=owner, timeout=30)
    put = s.put(f"{api}/team/{team}/sso", headers=owner, timeout=30, json={
        "protocol": "saml", "enabled": True, "enforced": False, "jit": True, "default_role": "member",
        "saml_idp_entity_id": lab["saml"]["idp_entity_id"], "saml_idp_sso_url": lab["saml"]["idp_sso_url"],
        "saml_idp_certs": [lab["saml"]["idp_cert_pem"]], "expected_version": current.json()["config"]["row_version"]})
    sp = put.json().get("sp", {}) if put.status_code == 200 else {}
    step("saml: the owner switches the team to SAML (PUT /team/{id}/sso)", put.status_code == 200,
         status=put.status_code, sp_entity_id=sp.get("saml_sp_entity_id"), acs=sp.get("saml_acs_url"),
         lab_sp_entity_id=lab["saml"]["sp_entity_id"])

    def saml_attempt(user: str):
        b = Browser()
        r = start(b, api, team)
        page = keycloak_login(b, r.headers["location"], user, lab["users"][user])
        assert page.status_code == 200, (page.status_code, page.headers.get("location"), page.text[:300])
        action, fields = _form(page.text)
        return b, action, fields

    b, action, fields = saml_attempt("alice")
    result = b.s.post(action, data=fields, allow_redirects=False, timeout=30)
    frag = _fragment(result.headers["location"], app)
    tokens = exchange(b, api, frag.get("code", "")) if "code" in frag else None
    xml = base64.b64decode(fields["SAMLResponse"]).decode("utf-8", "replace")
    step("saml: alice signs in through Keycloak's login page and the POST binding", bool(
         tokens is not None and tokens.status_code == 200 and whoami(b, api, tokens.json()) == f"alice@{DOMAIN}"),
         acs=action, acs_status=result.status_code, error=frag.get("error"),
         signature_elements=len(re.findall(r"<(?:\w+:)?Signature[\s>]", xml)),
         assertion_signed=bool(re.search(r"<(?:\w+:)?Assertion\b.*?<(?:\w+:)?Signature[\s>]", xml, re.S)),
         has_in_response_to="InResponseTo=" in xml, has_not_on_or_after="NotOnOrAfter=" in xml)
    again = b.s.post(action, data=fields, allow_redirects=False, timeout=30)
    err = _fragment(again.headers["location"], app).get("error", "")
    step("saml: the same POST again (replay) is refused", "already used" in err, error=err)
    b2 = Browser()
    start_again = start(b2, api, team)
    relay = parse_qs(urlsplit(start_again.headers["location"]).query)["RelayState"][0]
    replayed = b2.s.post(action, data={"SAMLResponse": fields["SAMLResponse"], "RelayState": relay},
                         allow_redirects=False, timeout=30)
    err = _fragment(replayed.headers["location"], app).get("error", "")
    step("saml: the captured response replayed into a fresh sign-in is refused", "another sign-in" in err
         or "replay" in err or "not confirmed" in err, error=err)
    b3, action3, fields3 = saml_attempt("alice")
    tampered = base64.b64decode(fields3["SAMLResponse"]).replace(f"alice@{DOMAIN}".encode(), f"ceo@{DOMAIN}".encode())
    fields3["SAMLResponse"] = base64.b64encode(tampered).decode()
    forged = b3.s.post(action3, data=fields3, allow_redirects=False, timeout=30)
    err = _fragment(forged.headers["location"], app).get("error", "")
    step("saml: a response whose NameID was changed is refused (signature)", "not signed" in err, error=err)
    b4, action4, fields4 = saml_attempt("mallory")
    refused = b4.s.post(action4, data=fields4, allow_redirects=False, timeout=30)
    err = _fragment(refused.headers["location"], app).get("error", "")
    step("saml: mallory (another domain) is refused", "not a verified domain" in err, error=err)

    # ---- the audit log
    from sqlmodel import Session, select

    from backend.access_models import AuditEvent
    with Session(_engine(args.db_url)) as session:
        rows = session.exec(select(AuditEvent).where(AuditEvent.action.in_(  # type: ignore[union-attr]
            ["auth.login.sso", "team.sso.config"])).order_by(AuditEvent.id)).all()
    audit_rows = [{"action": r.action, "outcome": r.outcome, "actor": r.actor_email,
                   "protocol": (r.details or {}).get("protocol"), "reason": (r.details or {}).get("reason")}
                  for r in rows]
    step("audit: every SSO sign-in and refusal is in the audit log",
         sum(1 for r in audit_rows if r["action"] == "auth.login.sso") >= 10, rows=len(audit_rows))

    out = {"at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(), "api": api,
           "keycloak": lab["keycloak"], "team_id": team, "passed": ok, "steps": steps, "audit": audit_rows}
    Path(args.out).write_text(json.dumps(out, indent=2))
    print(("ALL PASSED" if ok else "SOME FAILED") + f": {sum(s['passed'] for s in steps)}/{len(steps)}; {args.out}")
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("seed", "configure", "run"))
    parser.add_argument("--db-url", default=os.environ.get("LAB_DB_URL", ""))
    parser.add_argument("--lab", default="")
    parser.add_argument("--api", default="http://127.0.0.1:8099")
    parser.add_argument("--app", default="http://127.0.0.1:3999")
    parser.add_argument("--team", type=int, default=0)
    parser.add_argument("--out", default="keycloak-live-evidence.json")
    args = parser.parse_args()
    return {"seed": seed, "configure": configure, "run": run}[args.action](args)


if __name__ == "__main__":
    sys.exit(main())
