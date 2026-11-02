"""Sign-in codes, tokens and passwords, end to end through the real auth routers on SQLite.

Run (no .env is read):

    cd backend && PYTHON_DOTENV_DISABLED=1 PYTHONPATH=.. JWT_SECRET_KEY=t JWT_REFRESH_SECRET_KEY=r \
      AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=y AWS_DEFAULT_REGION=us-east-1 \
      python -m pytest tests/test_auth_hardening.py -q -p no:cacheprovider
"""
import concurrent.futures
import datetime as dt
import os
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "auth-hardening-test-access-secret")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "auth-hardening-test-refresh-secret")

import bcrypt  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from jose import jwt as jose_jwt  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from backend.main import app  # noqa: E402
from backend.new_models import AuthCounter, Team, TeamMembership, User, VerificationCode  # noqa: E402
from backend.routers import admin as admin_router  # noqa: E402
from backend.routers import auth as auth_router  # noqa: E402
from backend.utilities.auth import auth_utils  # noqa: E402
from backend.utilities.team import membership  # noqa: E402

DEV_EMAIL = "dev@local.test"
DEV_CODE = "246810"
PASSWORD = "Correct-Horse-Battery-9"


@pytest.fixture()
def world(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'auth.db'}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    for module in (auth_router, admin_router):
        monkeypatch.setattr(module, "get_db", lambda: engine)
    sent: dict[str, list[str]] = {}
    monkeypatch.setattr(auth_router, "send_verification_email",
                        lambda email, code: sent.setdefault(email, []).append(code))
    monkeypatch.delenv("DSS_DEV_MODE", raising=False)
    monkeypatch.setenv("LOCAL_DEV_VERIFICATION_EMAIL", DEV_EMAIL)
    monkeypatch.setenv("LOCAL_DEV_VERIFICATION_CODE", DEV_CODE)
    return engine, sent


@pytest.fixture()
def client(world):
    return TestClient(app)


def add_user(engine, email: str, password_hash: str, *, superuser: bool = False) -> int:
    with Session(engine) as s:
        team = Team(name=f"{email} team")
        s.add(team)
        s.commit()
        s.refresh(team)
        user = User(email=email, password=password_hash, first_name="T", last_name="U", profile_photo=None,
                    session_active=True, default_team_id=team.id, is_superuser=superuser)
        s.add(user)
        s.commit()
        s.refresh(user)
        s.add(TeamMembership(team_id=team.id, user_id=user.id, role="admin"))
        s.commit()
        return user.id


def stored(engine, user_id: int) -> User:
    with Session(engine) as s:
        return s.get(User, user_id)


def send_code(client, sent, email: str) -> str:
    r = client.post("/send_code", json={"email": email})
    assert r.status_code == 200, r.text
    return sent[email.strip().lower()][-1]


def login(client, email: str, password: str, code: str):
    return client.post("/login", json={"email": email, "password": password, "verification_code": code})


def legacy_bcrypt(password: str, prefix: str = "$2b$") -> str:
    """What passlib's bcrypt handler stored: bcrypt over the first 72 UTF-8 bytes, 12 rounds."""
    hashed = bcrypt.hashpw(password.encode("utf-8")[:72], bcrypt.gensalt(rounds=4)).decode()
    return prefix + hashed[4:]


# ---------------------------------------------------------------------------------------------- sign-up


def test_signup_accepts_a_128_character_password_and_stores_argon2id(client, world):
    engine, sent = world
    password = "pässwörd-" + "\U0001F600" * 100 + "x" * 19  # 128 code points, NFC
    assert len(password) == 128
    code = send_code(client, sent, "New.User@Example.TEST ")
    r = client.post("/signup", json={"email": " new.user@example.test", "password": password,
                                     "verification_code": code, "first_name": "N", "last_name": "U"})
    assert r.status_code == 200, r.text
    with Session(engine) as s:
        user = s.exec(select(User).where(User.email == "new.user@example.test")).one()
    assert user.password.startswith("$argon2id$v=19$m=19456,t=2,p=1$")
    assert user.token_version == 0
    claims = jose_jwt.decode(r.json()["access_token"], auth_utils.JWT_SECRET_KEY, algorithms=["HS256"])
    assert claims["typ"] == "access" and claims["ver"] == 0 and "iat" in claims
    assert login(client, "NEW.USER@example.test", password, send_code(client, sent, "new.user@example.test")).status_code == 200


@pytest.mark.parametrize("password, message", [
    ("short7!", "8 to 128 characters"),
    ("x" * 129, "8 to 128 characters"),
    ("tab\there-ok-length", "control characters"),
    ("nul\x00inside-long", "control characters"),
])
def test_signup_refuses_passwords_outside_the_rules_with_a_clear_422(client, world, password, message):
    _engine, sent = world
    code = send_code(client, sent, "rules@example.test")
    r = client.post("/signup", json={"email": "rules@example.test", "password": password,
                                     "verification_code": code, "first_name": "R", "last_name": "U"})
    assert r.status_code == 422
    assert message in r.text
    assert password not in r.text, "a refused password is never echoed back"
    assert all(set(e) <= {"type", "loc", "msg"} for e in r.json()["detail"])


def test_new_password_rules_count_code_points_after_nfc():
    decomposed = "é" * 64  # 128 code points raw, 64 after NFC
    assert auth_utils.new_password_problem(decomposed) is None
    assert auth_utils.new_password_problem("\U0001F600" * 128) is None  # 512 UTF-8 bytes
    assert "8 to 128" in auth_utils.new_password_problem("\U0001F600" * 129)


# -------------------------------------------------------------------------------------------- passwords


@pytest.mark.parametrize("prefix", ["$2a$", "$2b$", "$2y$"])
def test_login_upgrades_a_legacy_bcrypt_hash_to_argon2id_once(client, world, prefix):
    engine, sent = world
    user_id = add_user(engine, "legacy@example.test", legacy_bcrypt("old-pass-5", prefix))
    assert login(client, "legacy@example.test", "old-pass-5", send_code(client, sent, "legacy@example.test")).status_code == 200
    upgraded = stored(engine, user_id).password
    assert upgraded.startswith("$argon2id$")
    assert login(client, "legacy@example.test", "old-pass-5", send_code(client, sent, "legacy@example.test")).status_code == 200
    assert stored(engine, user_id).password == upgraded, "a current argon2 hash is not rewritten"
    r = login(client, "legacy@example.test", "wrong-pass", send_code(client, sent, "legacy@example.test"))
    assert r.status_code == 400 and r.json()["detail"] == "Incorrect email or password"


def test_a_24_emoji_legacy_password_truncated_by_bcrypt_still_logs_in(client, world):
    engine, sent = world
    password = "\U0001F510" * 24  # 96 UTF-8 bytes: bcrypt only ever saw the first 72
    user_id = add_user(engine, "emoji@example.test", legacy_bcrypt(password))
    assert login(client, "emoji@example.test", password, send_code(client, sent, "emoji@example.test")).status_code == 200
    assert stored(engine, user_id).password.startswith("$argon2id$")
    # after the upgrade the WHOLE password is checked
    assert login(client, "emoji@example.test", password, send_code(client, sent, "emoji@example.test")).status_code == 200
    assert not auth_utils.verify_password("\U0001F510" * 18, stored(engine, user_id).password)


def test_a_legacy_non_nfc_password_matches_raw_and_is_rehashed_as_nfc():
    raw = "café-secret"  # decomposed, as some keyboards send it
    ok, new_hash = auth_utils.verify_and_update_password(raw, legacy_bcrypt(raw))
    assert ok and new_hash.startswith("$argon2id$")
    assert auth_utils.verify_password("café-secret", new_hash)  # composed form now works too


def test_the_hash_upgrade_is_compare_and_swap(client, world, monkeypatch):
    """A reset that lands between verify and store wins: the login does not overwrite the new hash."""
    engine, sent = world
    user_id = add_user(engine, "race@example.test", legacy_bcrypt("old-pass-5"))
    real = auth_router.verify_and_update_password

    def verify_then_reset(password, old):
        result = real(password, old)
        with Session(engine) as s:
            user = s.get(User, user_id)
            user.password = auth_utils.get_hashed_password("reset-in-between-1")
            s.add(user)
            s.commit()
        return result

    monkeypatch.setattr(auth_router, "verify_and_update_password", verify_then_reset)
    assert login(client, "race@example.test", "old-pass-5", send_code(client, sent, "race@example.test")).status_code == 200
    assert auth_utils.verify_password("reset-in-between-1", stored(engine, user_id).password)


def test_login_accepts_every_old_length_but_not_more_than_128(client, world):
    engine, sent = world
    add_user(engine, "five@example.test", legacy_bcrypt("abcde"))
    assert login(client, "five@example.test", "abcde", send_code(client, sent, "five@example.test")).status_code == 200
    assert login(client, "five@example.test", "x" * 129, "123456").status_code == 422


def test_hash_and_verify_raise_no_deprecation_warning():
    """passlib's argon2 loader reads the deprecated ``argon2.__version__``; the direct argon2-cffi path does not."""
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        new = auth_utils.get_hashed_password("warning-free-1")
        assert auth_utils.verify_and_update_password("warning-free-1", new) == (True, None)
        ok, upgraded = auth_utils.verify_and_update_password("warning-free-1", legacy_bcrypt("warning-free-1"))
        assert ok and upgraded.startswith("$argon2id$")


def test_hashing_is_off_the_event_loop_and_invites_get_strong_passwords(monkeypatch):
    passwords = {membership.generate_random_password() for _ in range(50)}
    assert len(passwords) == 50
    assert all(len(p) == 20 and p.isalnum() for p in passwords)
    import inspect

    assert "run_in_threadpool(get_hashed_password" in inspect.getsource(membership.add_emails_to_team)
    assert "run_in_threadpool(get_hashed_password" in inspect.getsource(admin_router.create_admin_user)


# ------------------------------------------------------------------------------------------------ codes


def test_a_code_works_once_and_only_the_newest_code_is_live(client, world):
    engine, sent = world
    add_user(engine, "once@example.test", auth_utils.get_hashed_password(PASSWORD))
    first = send_code(client, sent, "once@example.test")
    second = send_code(client, sent, "once@example.test")
    with Session(engine) as s:
        assert len(s.exec(select(VerificationCode).where(VerificationCode.email == "once@example.test")).all()) == 1
    if first != second:
        assert login(client, "once@example.test", PASSWORD, first).status_code == 400
    assert login(client, "once@example.test", PASSWORD, f" {second[:3]} {second[3:]}\n").status_code == 200
    assert login(client, "once@example.test", PASSWORD, second).status_code == 400, "single use"


def test_five_wrong_codes_invalidate_the_live_code(client, world):
    engine, sent = world
    add_user(engine, "guess@example.test", auth_utils.get_hashed_password(PASSWORD))
    code = send_code(client, sent, "guess@example.test")
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(auth_utils.MAX_CODE_ATTEMPTS):
        assert login(client, "guess@example.test", PASSWORD, wrong).status_code == 400
    assert login(client, "guess@example.test", PASSWORD, code).status_code == 400, "the right code no longer works"
    fresh = send_code(client, sent, "guess@example.test")
    assert login(client, "guess@example.test", PASSWORD, fresh).status_code == 200


def test_four_wrong_codes_still_leave_the_code_usable(client, world):
    engine, sent = world
    add_user(engine, "four@example.test", auth_utils.get_hashed_password(PASSWORD))
    code = send_code(client, sent, "four@example.test")
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(auth_utils.MAX_CODE_ATTEMPTS - 1):
        assert login(client, "four@example.test", PASSWORD, wrong).status_code == 400
    assert login(client, "four@example.test", PASSWORD, code).status_code == 200


def test_an_expired_code_is_refused(client, world):
    engine, sent = world
    add_user(engine, "late@example.test", auth_utils.get_hashed_password(PASSWORD))
    code = send_code(client, sent, "late@example.test")
    with Session(engine) as s:
        row = s.exec(select(VerificationCode).where(VerificationCode.email == "late@example.test")).one()
        row.expires_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)
        s.add(row)
        s.commit()
    assert login(client, "late@example.test", PASSWORD, code).status_code == 400


def test_concurrent_use_of_one_code_succeeds_exactly_once(world):
    engine, _sent = world
    code = auth_utils.issue_verification_code(engine, "race-code@example.test")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: auth_utils.consume_verification_code(
            engine, "race-code@example.test", code, allow_dev_code=True), range(8)))
    assert results.count(True) == 1


def test_codes_per_email_are_capped_per_hour_with_retry_after(client, world, monkeypatch):
    engine, sent = world
    monkeypatch.setattr(auth_router.send_code_ip_limiter, "times", 100)  # isolate the per-email cap
    for _ in range(auth_utils.CODE_SENDS_PER_EMAIL):
        send_code(client, sent, "flood@example.test")
    r = client.post("/send_code", json={"email": "FLOOD@example.test"})
    assert r.status_code == 429
    assert 3500 < int(r.headers["retry-after"]) <= 3601
    assert len(sent["flood@example.test"]) == auth_utils.CODE_SENDS_PER_EMAIL, "no mail for a refused request"
    with Session(engine) as s:  # the window is shared through the database, not this process
        counter = s.get(AuthCounter, "send_code:flood@example.test")
        counter.window_start = counter.window_start - dt.timedelta(hours=1, seconds=1)
        s.add(counter)
        s.commit()
    assert client.post("/send_code", json={"email": "flood@example.test"}).status_code == 200


def test_the_retired_fixed_code_no_longer_signs_anyone_in(client, world):
    engine, sent = world
    assert not hasattr(auth_utils, "HARDCODED_VERIFICATION_CODES")
    for email in ("shivam@cyberultron.com", "demo@rapipay.com"):
        user_id = add_user(engine, email, auth_utils.get_hashed_password(PASSWORD))
        if send_code(client, sent, email) == "123456":
            pytest.skip("the random code happened to be 123456")
        assert login(client, email, PASSWORD, "123456").status_code == 400
        r = client.post("/reset_password", json={"email": email, "password": "Taken-Over-123", "verification_code": "123456"})
        assert r.status_code == 400
        assert auth_utils.verify_password(PASSWORD, stored(engine, user_id).password)


def test_the_dev_code_needs_dev_mode_and_never_resets_a_password(client, world, monkeypatch):
    engine, _sent = world
    user_id = add_user(engine, DEV_EMAIL, auth_utils.get_hashed_password(PASSWORD))
    # without DSS_DEV_MODE the fixed code is an ordinary wrong code
    assert login(client, DEV_EMAIL, PASSWORD, DEV_CODE).status_code == 400
    monkeypatch.setenv("DSS_DEV_MODE", "1")
    assert login(client, DEV_EMAIL, PASSWORD, DEV_CODE).status_code == 200
    assert login(client, DEV_EMAIL.upper(), PASSWORD, DEV_CODE).status_code == 200, "repeatable in dev mode"
    r = client.post("/reset_password", json={"email": DEV_EMAIL, "password": "Taken-Over-123", "verification_code": DEV_CODE})
    assert r.status_code == 400
    assert auth_utils.verify_password(PASSWORD, stored(engine, user_id).password)
    # the dev code is only for the dev email
    add_user(engine, "other@example.test", auth_utils.get_hashed_password(PASSWORD))
    assert login(client, "other@example.test", PASSWORD, DEV_CODE).status_code == 400


def test_dev_mode_acceptance_is_logged_as_a_warning(world, monkeypatch, caplog):
    engine, _sent = world
    monkeypatch.setenv("DSS_DEV_MODE", "1")
    with caplog.at_level("WARNING", logger="backend.auth"):
        assert auth_utils.consume_verification_code(engine, DEV_EMAIL, DEV_CODE, allow_dev_code=True)
    assert any("DSS_DEV_MODE" in r.getMessage() for r in caplog.records)
    assert DEV_EMAIL not in caplog.text


def test_start_up_purge_removes_retired_fixed_and_expired_codes(world, monkeypatch):
    engine, _sent = world
    now = dt.datetime.now(dt.timezone.utc)
    with Session(engine) as s:
        s.add(VerificationCode(email="a@example.test", code="123456", expires_at=now + dt.timedelta(minutes=5)))
        s.add(VerificationCode(email="b@example.test", code="654321", expires_at=now - dt.timedelta(minutes=1)))
        s.add(VerificationCode(email="c@example.test", code="777777", expires_at=now + dt.timedelta(minutes=5)))
        s.commit()
    monkeypatch.setenv("DSS_DEV_MODE", "1")
    assert auth_utils.purge_unusable_verification_codes(engine) == 1  # dev mode keeps fixed codes
    monkeypatch.delenv("DSS_DEV_MODE")
    assert auth_utils.purge_unusable_verification_codes(engine) == 1
    with Session(engine) as s:
        assert [r.email for r in s.exec(select(VerificationCode)).all()] == ["c@example.test"]


# ----------------------------------------------------------------------------------------------- tokens


def test_reset_revokes_every_earlier_token(client, world):
    engine, sent = world
    user_id = add_user(engine, "reset@example.test", auth_utils.get_hashed_password(PASSWORD))
    tokens = login(client, "reset@example.test", PASSWORD, send_code(client, sent, "reset@example.test")).json()
    assert client.post("/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 200
    r = client.post("/reset_password", json={"email": "Reset@Example.test", "password": "Brand-New-Pass-1",
                                             "verification_code": send_code(client, sent, "reset@example.test")})
    assert r.status_code == 200, r.text
    assert stored(engine, user_id).token_version == 1
    assert client.post("/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 403
    assert client.get("/get_user", headers={"Authorization": f"Bearer {tokens['access_token']}"}).status_code == 401
    assert login(client, "reset@example.test", PASSWORD, send_code(client, sent, "reset@example.test")).status_code == 400
    fresh = login(client, "reset@example.test", "Brand-New-Pass-1", send_code(client, sent, "reset@example.test")).json()
    assert jose_jwt.get_unverified_claims(fresh["access_token"])["ver"] == 1
    assert client.get("/get_user", headers={"Authorization": f"Bearer {fresh['access_token']}"}).status_code == 200
    refreshed = client.post("/refresh", json={"refresh_token": fresh["refresh_token"]})
    assert jose_jwt.get_unverified_claims(refreshed.json()["access_token"])["ver"] == 1


def test_token_types_are_not_interchangeable(client, world):
    engine, _sent = world
    add_user(engine, "typ@example.test", auth_utils.get_hashed_password(PASSWORD))
    exp = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)
    refresh_shaped = jose_jwt.encode({"sub": "typ@example.test", "exp": exp, "typ": "refresh", "ver": 0},
                                     auth_utils.JWT_SECRET_KEY, "HS256")
    access_shaped = jose_jwt.encode({"sub": "typ@example.test", "exp": exp, "typ": "access", "ver": 0},
                                    auth_utils.JWT_REFRESH_SECRET_KEY, "HS256")
    assert client.get("/get_user", headers={"Authorization": f"Bearer {refresh_shaped}"}).status_code == 401
    assert client.post("/refresh", json={"refresh_token": access_shaped}).status_code == 403
    real_refresh = auth_utils.create_refresh_token("typ@example.test")
    assert client.get("/get_user", headers={"Authorization": f"Bearer {real_refresh}"}).status_code == 401


def test_tokens_from_before_typ_and_ver_count_as_version_zero(client, world):
    engine, _sent = world
    user_id = add_user(engine, "old-token@example.test", auth_utils.get_hashed_password(PASSWORD))
    exp = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)
    legacy = jose_jwt.encode({"sub": "old-token@example.test", "exp": exp}, auth_utils.JWT_SECRET_KEY, "HS256")
    assert client.get("/get_user", headers={"Authorization": f"Bearer {legacy}"}).status_code == 200
    with Session(engine) as s:
        user = s.get(User, user_id)
        user.token_version = 1
        s.add(user)
        s.commit()
    assert client.get("/get_user", headers={"Authorization": f"Bearer {legacy}"}).status_code == 401
    no_exp = jose_jwt.encode({"sub": "old-token@example.test"}, auth_utils.JWT_SECRET_KEY, "HS256")
    assert client.get("/get_user", headers={"Authorization": f"Bearer {no_exp}"}).status_code == 401


@pytest.mark.parametrize("access, refresh, dev, refused", [
    ("a" * 32, "a" * 32, False, "are equal"),
    ("a" * 31, "b" * 40, False, "JWT_SECRET_KEY is shorter"),
    ("a" * 40, "b" * 8, False, "JWT_REFRESH_SECRET_KEY is shorter"),
    ("a" * 32, "a" * 32, True, None),
    ("a" * 32, "b" * 32, False, None),
])
def test_start_up_refuses_weak_jwt_secrets_unless_dev_mode(monkeypatch, access, refresh, dev, refused):
    monkeypatch.setattr(auth_utils, "JWT_SECRET_KEY", access)
    monkeypatch.setattr(auth_utils, "JWT_REFRESH_SECRET_KEY", refresh)
    if dev:
        monkeypatch.setenv("DSS_DEV_MODE", "1")
    else:
        monkeypatch.delenv("DSS_DEV_MODE", raising=False)
    if refused:
        with pytest.raises(RuntimeError, match=refused):
            auth_utils.check_startup_security()
    else:
        auth_utils.check_startup_security()


def test_the_app_does_not_boot_with_weak_secrets(monkeypatch, world):
    monkeypatch.setattr(auth_utils, "JWT_SECRET_KEY", "same-secret")
    monkeypatch.setattr(auth_utils, "JWT_REFRESH_SECRET_KEY", "same-secret")
    monkeypatch.delenv("DSS_DEV_MODE", raising=False)
    with pytest.raises(RuntimeError, match="Refusing to start"):
        with TestClient(app):  # runs the lifespan
            pass


# ------------------------------------------------------------------------------------------- emails / admin


def test_accounts_created_with_mixed_case_emails_still_sign_in(client, world):
    engine, sent = world
    add_user(engine, "Mixed.Case@Example.test", auth_utils.get_hashed_password(PASSWORD))
    r = login(client, "mixed.case@example.test", PASSWORD, send_code(client, sent, "MIXED.case@example.test"))
    assert r.status_code == 200
    assert client.get("/get_user", headers={"Authorization": f"Bearer {r.json()['access_token']}"}).json()["email"] == "Mixed.Case@Example.test"
    code = send_code(client, sent, "mixed.case@example.test")
    r = client.post("/signup", json={"email": "MIXED.CASE@example.test", "password": PASSWORD, "verification_code": code,
                                     "first_name": "D", "last_name": "U"})
    assert r.status_code == 400 and "already exist" in r.json()["detail"]


def test_admin_created_users_follow_the_new_password_rules(client, world, monkeypatch):
    engine, _sent = world
    add_user(engine, "root@example.test", auth_utils.get_hashed_password(PASSWORD), superuser=True)
    mails = []

    async def fake_send(email, subject, html_body=None, body=None):
        mails.append(email)

    monkeypatch.setattr(admin_router, "send_email", fake_send)
    token = auth_utils.create_access_token("root@example.test")
    headers = {"Authorization": f"Bearer {token}"}
    body = {"email": " Ops@Example.test ", "first_name": "O", "last_name": "P"}
    assert client.post("/admin/create_admin_user", json={**body, "password": "short"}, headers=headers).status_code == 422
    long_ok = "L" * 128
    r = client.post("/admin/create_admin_user", json={**body, "password": long_ok}, headers=headers)
    assert r.status_code == 200, r.text
    with Session(engine) as s:
        user = s.exec(select(User).where(User.email == "ops@example.test")).one()
    assert user.password.startswith("$argon2id$") and auth_utils.verify_password(long_ok, user.password)


def test_send_code_tells_the_user_when_the_mail_cannot_be_sent(client, world, monkeypatch):
    """Follow-up from the staging proof: /send_code answered 200 while the backend logged
    "Error sending email: 'TENANT_ID'", so the user waited for a code that never came. The send now happens before
    the answer; a failed send is a 503 with a generic message (the cause stays in the log)."""
    from backend.routers import auth as auth_router_module

    def broken(email, code):
        raise KeyError("TENANT_ID")

    monkeypatch.setattr(auth_router_module, "send_verification_email", broken)
    r = client.post("/send_code", json={"email": "mail.down@example.test"})
    assert r.status_code == 503
    assert "TENANT_ID" not in r.text and "KeyError" not in r.text
    assert "could not send the verification code" in r.json()["detail"]


def test_send_code_passes_through_an_address_the_mailer_refuses(client, world, monkeypatch):
    from fastapi import HTTPException

    from backend.routers import auth as auth_router_module

    def refused(email, code):
        raise HTTPException(status_code=400, detail="Invalid recipient address")

    monkeypatch.setattr(auth_router_module, "send_verification_email", refused)
    r = client.post("/send_code", json={"email": "odd@example.test"})
    assert r.status_code == 400 and r.json()["detail"] == "Invalid recipient address"
