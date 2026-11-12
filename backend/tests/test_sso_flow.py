"""Single sign-on end to end through the real app (F4 SSO), with an in-process OIDC provider and SAML IdP.

The OIDC provider is a test RSA key behind faked discovery / JWKS / token endpoints (utilities/sso/http.py is the
only network path, and it is replaced); the SAML IdP signs with signxml.  Covered:

* the round trip: start (cookie + state + PKCE S256 + nonce) -> callback -> hand-off -> exchange -> tokens;
* login CSRF / session fixation: no cookie, another browser's cookie, a used or expired state, another team's
  state; a hand-off code planted in another browser (no matching client nonce), used twice, or expired;
* ID token: wrong nonce, audience, issuer, alg "none", HS256 with the public key as secret (algorithm confusion),
  expired, email not verified;
* SAML: a signed response signs in; the same assertion again (with a fresh state) is a replay; an unsolicited
  response (no state) is refused;
* open redirect: //evil, https://evil, /\\evil, javascript: all become /home;
* JIT and the team's rules: new account with the default role, existing members keep their role, another domain
  refused, superusers refused, JIT off refused;
* enforced SSO: password sign-in refused for the captured domain, the owner's break-glass sign-in allowed and
  audited, sign-up refused;
* configuration: owners only (403 for admins), the client secret is write-only, an http issuer is refused unless the
  operator listed its origin, domain verification by TXT record, one team per verified domain.
"""
import base64
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "sso-flow-test-access-secret-0123456789")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "sso-flow-test-refresh-secret-0123456789")

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from jose import jwk, jwt  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from backend.access_models import AuditEvent, SsoLoginState, TeamSsoConfig, TeamSsoDomain  # noqa: E402
from backend.main import app  # noqa: E402
from backend.new_models import Team, TeamMembership, User  # noqa: E402
from backend.routers import auth as auth_router  # noqa: E402
from backend.tests.support.rbac import bearer, join, make_user, patch_all_get_db  # noqa: E402
from backend.utilities import ratelimit  # noqa: E402
from backend.utilities.auth.auth_utils import get_hashed_password  # noqa: E402
from backend.utilities.sso import http as sso_http  # noqa: E402
from backend.utilities.sso import service as SSO  # noqa: E402

API = "https://api.devsec.test"
APP = "https://app.devsec.test"
ISSUER = "https://idp.acme-sso.test/realms/acme"
CLIENT_ID = "devsecshield"
DOMAIN = "acme-sso.test"
OWNER, ADMIN, MEMBER = f"olivia@{DOMAIN}", f"adam@{DOMAIN}", f"max@{DOMAIN}"
PASSWORD = "Correct-Horse-Battery-9"


class FakeIdp:
    """Discovery, JWKS and token endpoint of an OIDC provider, in process."""

    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pem = self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption())
        public = self.key.public_key().public_bytes(serialization.Encoding.PEM,
                                                     serialization.PublicFormat.SubjectPublicKeyInfo)
        self.public_pem = public
        self.jwk = {**jwk.construct(public, "RS256").to_dict(), "kid": "k1", "use": "sig", "alg": "RS256"}
        self.codes: dict[str, dict] = {}
        self.next_claims: dict = {}
        self.next_header: dict = {}
        self.next_key = None

    def discovery(self):
        return {"issuer": ISSUER, "authorization_endpoint": ISSUER + "/protocol/openid-connect/auth",
                "token_endpoint": ISSUER + "/protocol/openid-connect/token",
                "jwks_uri": ISSUER + "/protocol/openid-connect/certs", "code_challenge_methods_supported": ["S256"]}

    def get_json(self, url):
        if url.endswith("/.well-known/openid-configuration"):
            return self.discovery()
        if url.endswith("/certs"):
            return {"keys": [{k: (v.decode() if isinstance(v, bytes) else v) for k, v in self.jwk.items()}]}
        raise AssertionError(url)

    def authorize(self, url, email, **claims):
        """What the IdP does when the person signs in: a code bound to the request's nonce and PKCE challenge."""
        q = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
        assert q["code_challenge_method"] == "S256" and q["response_type"] == "code" and q["client_id"] == CLIENT_ID
        code = secrets.token_urlsafe(16)
        self.codes[code] = {"nonce": q["nonce"], "challenge": q["code_challenge"], "redirect_uri": q["redirect_uri"],
                            "email": email, **claims}
        return q, code

    def post_form(self, url, form):
        grant = self.codes.pop(form["code"], None)
        if grant is None:
            raise sso_http.SsoHttpError("The identity provider refused the request (invalid_grant)")
        challenge = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest()).rstrip(b"=").decode()
        if challenge != grant["challenge"] or form["redirect_uri"] != grant["redirect_uri"]:
            raise sso_http.SsoHttpError("The identity provider refused the request (invalid_grant)")
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": CLIENT_ID, "sub": "sub-" + grant["email"], "iat": now, "exp": now + 300,
                  "nonce": grant["nonce"], "email": grant["email"], "email_verified": True, "name": "Test Person"}
        claims.update({k: v for k, v in grant.items() if k not in ("nonce", "challenge", "redirect_uri", "email")})
        claims.update(self.next_claims)
        header = {"kid": "k1", **self.next_header}
        key = self.next_key or self.pem
        alg = header.pop("alg", "RS256")
        token = jwt.encode(claims, key, algorithm=alg, headers=header)
        return {"access_token": "at", "id_token": token, "token_type": "Bearer"}


@pytest.fixture()
def world(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'sso.db'}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    patch_all_get_db(monkeypatch, engine)
    monkeypatch.setenv("SSO_PUBLIC_API_URL", API)
    monkeypatch.setenv("CBOM_PUBLIC_APP_URL", APP)
    idp = FakeIdp()
    monkeypatch.setattr(sso_http, "get_json", idp.get_json)
    monkeypatch.setattr(sso_http, "post_form", idp.post_form)
    codes: dict[str, str] = {}
    monkeypatch.setattr(auth_router, "send_verification_email", lambda email, code: codes.__setitem__(email, code))
    ratelimit.reset_all()
    ids = {}
    with Session(engine) as s:
        team = Team(name="Acme")
        s.add(team)
        s.commit()
        s.refresh(team)
        ids["team"] = team.id
        for email, role in ((OWNER, "owner"), (ADMIN, "admin"), (MEMBER, "viewer")):
            u = make_user(s, email, password_hash=get_hashed_password(PASSWORD))
            ids[email] = u.id
            join(s, team.id, u.id, role)
        root = make_user(s, f"root@{DOMAIN}", superuser=True)
        ids["root"] = root.id
        s.add(TeamSsoConfig(team_id=team.id, protocol="oidc", enabled=True, jit=True, default_role="member",
                            oidc_issuer=ISSUER, oidc_client_id=CLIENT_ID))
        s.add(TeamSsoDomain(team_id=team.id, domain=DOMAIN, verification_token="t", verified_at=dt.datetime(2026, 1, 1),
                            verify_method="dns"))
        s.commit()
    yield engine, ids, idp, codes
    ratelimit.reset_all()


@pytest.fixture()
def client(world):
    return TestClient(app, base_url=API, follow_redirects=False)


def nonce_pair():
    nonce = secrets.token_urlsafe(32)
    return nonce, hashlib.sha256(nonce.encode()).hexdigest()


def begin(client, team, redirect="/home"):
    ratelimit.reset_all()
    nonce, cn = nonce_pair()
    r = client.get(f"/sso/{team}/start", params={"cn": cn, "redirect": redirect})
    assert r.status_code == 303, r.text
    return nonce, r


def fragment(response) -> dict:
    location = response.headers["location"]
    assert location.startswith(APP + "/sso/complete#"), location
    return {k: v[0] for k, v in parse_qs(location.split("#", 1)[1]).items()}


def oidc_login(client, idp, team, email, **claims):
    nonce, start = begin(client, team)
    q, code = idp.authorize(start.headers["location"], email, **claims)
    ratelimit.reset_all()
    back = client.get(f"/sso/{team}/oidc/callback", params={"state": q["state"], "code": code})
    return nonce, back


def exchange(client, code, nonce):
    ratelimit.reset_all()
    return client.post("/sso/exchange", json={"code": code, "client_nonce": nonce})


# ------------------------------------------------------------------------------------------------ OIDC round trip

def test_oidc_round_trip_signs_in_and_hands_tokens_to_the_spa_that_started_it(world, client):
    engine, ids, idp, _ = world
    nonce, back = oidc_login(client, idp, ids["team"], OWNER)
    assert back.status_code == 303
    code = fragment(back)["code"]
    tokens = exchange(client, code, nonce)
    assert tokens.status_code == 200, tokens.text
    body = tokens.json()
    assert body["redirect"] == "/home" and body["team_id"] == ids["team"]
    me = client.get("/get_user", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.status_code == 200 and me.json()["email"] == OWNER
    assert exchange(client, code, nonce).status_code == 400  # once
    with Session(engine) as s:
        event = s.exec(select(AuditEvent).where(AuditEvent.action == "auth.login.sso")).all()[-1]
    assert event.outcome == "success" and event.actor_user_id == ids[OWNER] and event.details["protocol"] == "oidc"
    assert "set-cookie" in {k.lower() for k in back.headers.keys()}  # the binding cookie is cleared


def test_the_start_sets_a_binding_cookie_and_asks_for_pkce(world, client):
    _, ids, _, _ = world
    _, start = begin(client, ids["team"])
    cookie = start.headers["set-cookie"]
    assert SSO.COOKIE + "=" in cookie and "HttpOnly" in cookie and "Path=/sso/" in cookie
    assert "Secure" in cookie and "SameSite=none" in cookie.replace("None", "none")
    q = {k: v[0] for k, v in parse_qs(urlsplit(start.headers["location"]).query).items()}
    assert q["code_challenge_method"] == "S256" and len(q["code_challenge"]) == 43 and q["nonce"] and q["state"]


def test_a_callback_without_this_browsers_cookie_is_refused(world, client):
    """Login CSRF: an attacker's own (valid) code and state, delivered to the victim's browser."""
    _, ids, idp, _ = world
    _, start = begin(client, ids["team"])
    q, code = idp.authorize(start.headers["location"], OWNER)
    victim = TestClient(app, base_url=API, follow_redirects=False)  # no cookie
    back = victim.get(f"/sso/{ids['team']}/oidc/callback", params={"state": q["state"], "code": code})
    assert "another browser" in fragment(back)["error"]
    other = TestClient(app, base_url=API, follow_redirects=False)
    other.cookies.set(SSO.COOKIE, "someone-elses-cookie", domain=urlsplit(API).hostname, path="/sso/")
    back = other.get(f"/sso/{ids['team']}/oidc/callback", params={"state": q["state"], "code": code})
    assert "error" in fragment(back)


def test_a_state_works_once_and_not_for_another_team_or_after_it_expires(world, client):
    engine, ids, idp, _ = world
    nonce, back = oidc_login(client, idp, ids["team"], OWNER)
    with Session(engine) as s:
        state = s.exec(select(SsoLoginState)).one()
    again = client.get(f"/sso/{ids['team']}/oidc/callback", params={"state": state.id, "code": "x"})
    assert "already used" in fragment(again)["error"]
    _, start = begin(client, ids["team"])
    q, code = idp.authorize(start.headers["location"], OWNER)
    wrong_team = client.get(f"/sso/{ids['team'] + 999}/oidc/callback", params={"state": q["state"], "code": code})
    assert "error" in fragment(wrong_team)
    with Session(engine) as s:
        row = s.get(SsoLoginState, q["state"])
        row.expires_at = dt.datetime(2000, 1, 1)
        s.add(row)
        s.commit()
    expired = client.get(f"/sso/{ids['team']}/oidc/callback", params={"state": q["state"], "code": code})
    assert "expired" in fragment(expired)["error"]


def test_a_hand_off_code_is_useless_in_another_browser(world, client):
    """A code planted in the victim's browser (session fixation): the victim's SPA has no matching nonce."""
    _, ids, idp, _ = world
    _, back = oidc_login(client, idp, ids["team"], OWNER)
    code = fragment(back)["code"]
    victims_nonce, _ = nonce_pair()
    refused = exchange(client, code, victims_nonce)
    assert refused.status_code == 400 and "another browser" in refused.json()["detail"]


@pytest.mark.parametrize("claims,header,message", [
    ({"nonce": "not-the-one"}, {}, "nonce"),
    ({"aud": "someone-else"}, {}, "signature, issuer, audience"),
    ({"iss": "https://evil.test"}, {}, "signature, issuer, audience"),
    ({"exp": int(time.time()) - 3600}, {}, "signature, issuer, audience"),
    ({"email_verified": False}, {}, "not verified"),
    ({"email": None}, {}, "email address"),
    ({"iat": int(time.time()) + 3600}, {}, "issue time"),
])
def test_id_token_checks(world, client, claims, header, message):
    _, ids, idp, _ = world
    idp.next_claims = claims
    _, back = oidc_login(client, idp, ids["team"], OWNER)
    assert message in fragment(back)["error"]


def test_alg_none_and_hs256_with_the_public_key_are_refused(world, client):
    _, ids, idp, _ = world
    idp.next_header = {"alg": "HS256"}
    idp.next_key = idp.public_pem.decode()  # the classic algorithm-confusion forgery
    _, back = oidc_login(client, idp, ids["team"], OWNER)
    assert "accepted algorithm" in fragment(back)["error"]
    idp.next_header, idp.next_key = {}, None
    unsigned_header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "kid": "k1"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({"iss": ISSUER}).encode()).rstrip(b"=").decode()
    from backend.utilities.sso import oidc
    with pytest.raises(oidc.OidcError, match="accepted algorithm"):
        oidc.verify_id_token(idp.discovery(), f"{unsigned_header}.{payload}.", issuer=ISSUER, client_id=CLIENT_ID,
                             nonce="n", now=dt.datetime.now(dt.timezone.utc).replace(tzinfo=None))


@pytest.mark.parametrize("target", ["//evil.test/x", "https://evil.test", "/\\evil.test", "javascript:alert(1)",
                                    "/ok\nSet-Cookie: x", "", "evil.test"])
def test_redirects_stay_on_the_app(world, client, target):
    _, ids, idp, _ = world
    nonce, start = begin(client, ids["team"], redirect=target)
    q, code = idp.authorize(start.headers["location"], OWNER)
    back = client.get(f"/sso/{ids['team']}/oidc/callback", params={"state": q["state"], "code": code})
    assert exchange(client, fragment(back)["code"], nonce).json()["redirect"] == "/home"


def test_a_safe_path_is_kept(world, client):
    _, ids, idp, _ = world
    nonce, start = begin(client, ids["team"], redirect=f"/{ids['team']}/sast?tab=1")
    q, code = idp.authorize(start.headers["location"], OWNER)
    back = client.get(f"/sso/{ids['team']}/oidc/callback", params={"state": q["state"], "code": code})
    assert exchange(client, fragment(back)["code"], nonce).json()["redirect"] == f"/{ids['team']}/sast?tab=1"


# ------------------------------------------------------------------------------------------------ JIT and rules

def test_jit_creates_the_account_with_the_default_role_and_keeps_existing_roles(world, client):
    engine, ids, idp, _ = world
    nonce, back = oidc_login(client, idp, ids["team"], f"newbie@{DOMAIN}")
    assert exchange(client, fragment(back)["code"], nonce).status_code == 200
    nonce, back = oidc_login(client, idp, ids["team"], MEMBER)  # a viewer stays a viewer
    assert exchange(client, fragment(back)["code"], nonce).status_code == 200
    with Session(engine) as s:
        newbie = s.exec(select(User).where(User.email == f"newbie@{DOMAIN}")).one()
        assert s.get(TeamMembership, (ids["team"], newbie.id)).role == "member"
        assert s.get(TeamMembership, (newbie.default_team_id, newbie.id)).role == "owner"
        assert newbie.password.startswith("!sso-only:")  # no password can ever match
        assert s.get(TeamMembership, (ids["team"], ids[MEMBER])).role == "viewer"


@pytest.mark.parametrize("email,message", [
    ("mallory@evil-sso.test", "not a verified domain"),
    (f"root@{DOMAIN}", "Platform administrators"),
])
def test_addresses_the_team_may_not_sign_in(world, client, email, message):
    engine, ids, idp, _ = world
    _, back = oidc_login(client, idp, ids["team"], email)
    assert message in fragment(back)["error"]
    with Session(engine) as s:
        denied = s.exec(select(AuditEvent).where(AuditEvent.outcome == "denied")).all()
    assert any(e.action == "auth.login.sso" for e in denied)


def test_jit_off_refuses_unknown_people(world, client):
    engine, ids, idp, _ = world
    with Session(engine) as s:
        cfg = s.exec(select(TeamSsoConfig)).one()
        cfg.jit = False
        s.add(cfg)
        s.commit()
    _, back = oidc_login(client, idp, ids["team"], f"stranger@{DOMAIN}")
    assert "ask a team admin" in fragment(back)["error"]


# ------------------------------------------------------------------------------------------------ enforcement

def _password_login(client, codes, email):
    ratelimit.reset_all()
    assert client.post("/send_code", json={"email": email}).status_code == 200
    ratelimit.reset_all()
    return client.post("/login", json={"email": email, "verification_code": codes[email], "password": PASSWORD})


def test_enforced_sso_refuses_passwords_except_the_owners_break_glass(world, client):
    engine, ids, _, codes = world
    with Session(engine) as s:
        cfg = s.exec(select(TeamSsoConfig)).one()
        cfg.enforced = True
        s.add(cfg)
        s.commit()
    refused = _password_login(client, codes, ADMIN)
    assert refused.status_code == 403 and "single sign-on" in refused.json()["detail"]
    owner = _password_login(client, codes, OWNER)
    assert owner.status_code == 200 and owner.json()["access_token"]
    with Session(engine) as s:
        glass = s.exec(select(AuditEvent).where(AuditEvent.action == "auth.login.break_glass")).all()
    assert len(glass) == 1 and glass[0].actor_user_id == ids[OWNER]
    ratelimit.reset_all()
    assert client.post("/send_code", json={"email": f"new@{DOMAIN}"}).status_code == 200
    ratelimit.reset_all()
    signup = client.post("/signup", json={"email": f"new@{DOMAIN}", "verification_code": codes[f"new@{DOMAIN}"],
                                          "password": PASSWORD, "first_name": "N", "last_name": "P"})
    assert signup.status_code == 403 and "single sign-on" in signup.json()["detail"]
    other = _password_login(client, codes, f"root@{DOMAIN}")  # superusers keep password sign-in
    assert other.status_code == 200


# ------------------------------------------------------------------------------------------------ configuration

def test_only_owners_manage_sso_and_the_secret_is_write_only(world, client):
    _, ids, _, _ = world
    team = ids["team"]
    assert client.get(f"/team/{team}/sso", headers=bearer(ADMIN)).status_code == 403
    body = {"protocol": "oidc", "enabled": True, "enforced": False, "jit": True, "default_role": "member",
            "oidc_issuer": ISSUER, "oidc_client_id": CLIENT_ID, "oidc_client_secret": "Canary-Client-Secret-123"}
    ratelimit.reset_all()
    assert client.put(f"/team/{team}/sso", headers=bearer(ADMIN), json=body).status_code == 403
    ratelimit.reset_all()
    saved = client.put(f"/team/{team}/sso", headers=bearer(OWNER), json=body)
    assert saved.status_code == 200, saved.text
    assert "Canary-Client-Secret-123" not in saved.text and saved.json()["config"]["oidc_client_secret_set"] is True
    assert "Canary-Client-Secret-123" not in client.get(f"/team/{team}/sso", headers=bearer(OWNER)).text
    sp = saved.json()["sp"]
    assert sp["oidc_redirect_uri"] == f"{API}/sso/{team}/oidc/callback"
    assert sp["saml_acs_url"] == f"{API}/sso/{team}/saml/acs"


def test_an_http_issuer_needs_the_operator(world, client, monkeypatch):
    _, ids, _, _ = world
    body = {"protocol": "oidc", "enabled": True, "oidc_issuer": "http://10.0.0.5:8080/realms/x", "oidc_client_id": "c"}
    refused = client.put(f"/team/{ids['team']}/sso", headers=bearer(OWNER), json=body)
    assert refused.status_code == 400 and "https" in refused.json()["detail"]
    monkeypatch.setenv("SSO_ALLOWED_IDP_ORIGINS", "http://10.0.0.5:8080")
    ratelimit.reset_all()
    assert client.put(f"/team/{ids['team']}/sso", headers=bearer(OWNER), json=body).status_code == 200


def test_domains_are_verified_by_txt_record_and_belong_to_one_team(world, client, monkeypatch):
    engine, ids, _, _ = world
    team = ids["team"]
    added = client.post(f"/team/{team}/sso/domains", headers=bearer(OWNER), json={"domain": "Corp-Example.TEST."})
    assert added.status_code == 200, added.text
    row = next(d for d in added.json()["domains"] if d["domain"] == "corp-example.test")
    assert row["verified"] is False and row["txt_record"]["value"].startswith(SSO.TXT_PREFIX)
    monkeypatch.setattr(SSO, "dns_txt_values", lambda name: ["something-else"])
    ratelimit.reset_all()
    assert client.post(f"/team/{team}/sso/domains/{row['id']}/verify", headers=bearer(OWNER)).status_code == 400
    monkeypatch.setattr(SSO, "dns_txt_values", lambda name: [row["txt_record"]["value"]])
    ratelimit.reset_all()
    assert client.post(f"/team/{team}/sso/domains/{row['id']}/verify", headers=bearer(OWNER)).json()["domains"]
    # another team claims and proves the same domain: refused, the first team keeps it
    with Session(engine) as s:
        other = Team(name="Other")
        s.add(other)
        s.commit()
        s.refresh(other)
        join(s, other.id, ids[ADMIN], "owner")
        other_id = other.id
    ratelimit.reset_all()
    theirs = client.post(f"/team/{other_id}/sso/domains", headers=bearer(ADMIN), json={"domain": "corp-example.test"})
    their_row = next(d for d in theirs.json()["domains"] if d["domain"] == "corp-example.test")
    monkeypatch.setattr(SSO, "dns_txt_values", lambda name: [their_row["txt_record"]["value"]])
    ratelimit.reset_all()
    clash = client.post(f"/team/{other_id}/sso/domains/{their_row['id']}/verify", headers=bearer(ADMIN))
    assert clash.status_code == 409 and "another team" in clash.json()["detail"]
    for bad in ("localhost", "-x.test", "a" * 70 + ".test", "exa mple.test", "http://x.test"):
        ratelimit.reset_all()
        assert client.post(f"/team/{team}/sso/domains", headers=bearer(OWNER), json={"domain": bad}).status_code == 400


def test_discover_tells_the_sign_in_page_where_to_go(world, client):
    _, ids, _, _ = world
    assert client.get("/sso/discover", params={"email": OWNER}).json() == {
        "sso": True, "team_id": ids["team"], "protocol": "oidc", "enforced": False}
    assert client.get("/sso/discover", params={"email": "x@elsewhere.test"}).json() == {"sso": False}
