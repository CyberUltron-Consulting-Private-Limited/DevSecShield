"""Sign-in codes, tokens and passwords, end to end through the real auth routers on SQLite.

Run (no .env is read):

    cd backend && PYTHON_DOTENV_DISABLED=1 PYTHONPATH=.. JWT_SECRET_KEY=t JWT_REFRESH_SECRET_KEY=r \
      AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=y AWS_DEFAULT_REGION=us-east-1 \
      python -m pytest tests/test_auth_hardening.py -q -p no:cacheprovider
"""
import concurrent.futures
import datetime as dt
import os
import re
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
from sqlmodel import delete as sa_delete  # noqa: E402

from backend.main import app  # noqa: E402
from backend.new_models import AuthCounter, Team, TeamMembership, User, VerificationCode  # noqa: E402
from backend.routers import admin as admin_router  # noqa: E402
from backend.routers import auth as auth_router  # noqa: E402
from backend.utilities import ratelimit  # noqa: E402
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


def test_login_accepts_every_old_length_up_to_the_byte_cap(client, world):
    engine, sent = world
    add_user(engine, "five@example.test", legacy_bcrypt("abcde"))
    assert login(client, "five@example.test", "abcde", send_code(client, sent, "five@example.test")).status_code == 200
    r = login(client, "five@example.test", "x" * (auth_utils.MAX_PASSWORD_BYTES + 1), "123456")
    assert r.status_code == 422 and "at most 512 bytes" in r.text
    assert login(client, "five@example.test", "", "123456").status_code == 422


def test_a_legacy_password_longer_than_128_characters_still_signs_in(client, world):
    """Admin-created accounts once had no length rule: such a password signs in (and is upgraded to Argon2id)
    as long as it fits the 512-byte cap that bounds the hashing cost; new passwords stay capped at 128."""
    engine, sent = world
    password = "A" * 130
    user_id = add_user(engine, "longadmin@example.test", legacy_bcrypt(password))
    r = login(client, "longadmin@example.test", password, send_code(client, sent, "longadmin@example.test"))
    assert r.status_code == 200, r.text
    assert stored(engine, user_id).password.startswith("$argon2id$")
    assert login(client, "longadmin@example.test", password,
                 send_code(client, sent, "longadmin@example.test")).status_code == 200, "and again after the upgrade"
    longest = "B" * auth_utils.MAX_PASSWORD_BYTES
    other = add_user(engine, "longest@example.test", legacy_bcrypt(longest))
    assert login(client, "longest@example.test", longest, send_code(client, sent, "longest@example.test")).status_code == 200
    assert stored(engine, other).password.startswith("$argon2id$")
    r = client.post("/reset_password", json={"email": "longadmin@example.test", "password": password,
                                             "verification_code": send_code(client, sent, "longadmin@example.test")})
    assert r.status_code == 422 and "8 to 128 characters" in r.text, "a NEW password is still capped at 128"


def test_a_decomposed_password_that_signed_up_also_signs_in(client, world):
    """Sign-up counts after NFC; sign-in must too (70 x 'e' + combining acute is 140 code points as sent)."""
    import unicodedata

    engine, sent = world
    password = unicodedata.normalize("NFD", "é" * 70)
    assert len(password) == 140
    r = client.post("/signup", json={"email": "nfd@example.test", "password": password, "first_name": "N",
                                     "last_name": "F", "verification_code": send_code(client, sent, "nfd@example.test")})
    assert r.status_code == 200, r.text
    r = login(client, "nfd@example.test", password, send_code(client, sent, "nfd@example.test"))
    assert r.status_code == 200, r.text
    # the 128-character sign-up maximum, decomposed: 256 code points as sent, still one valid password
    longest = unicodedata.normalize("NFD", "é" * 128)
    r = client.post("/reset_password", json={"email": "nfd@example.test", "password": longest,
                                             "verification_code": send_code(client, sent, "nfd@example.test")})
    assert r.status_code == 200, r.text
    assert login(client, "nfd@example.test", longest, send_code(client, sent, "nfd@example.test")).status_code == 200


@pytest.mark.parametrize("password, refused", [
    ("", True),
    ("a", False),
    ("x" * 512, False),
    ("x" * 513, True),
    ("\U0001F600" * 128, False),   # 512 bytes
    ("\U0001F600" * 129, True),
    ("é" * 256, False),      # 768 bytes as sent, 512 after NFC
    ("é" * 257, True),
    ("x" * 100_000, True),         # refused before it is normalised or hashed
])
def test_the_sign_in_password_rule_is_bytes_after_nfc(password, refused):
    assert (auth_utils.login_password_problem(password) is not None) is refused


def test_hash_and_verify_raise_no_deprecation_warning():
    """passlib's argon2 loader reads the deprecated ``argon2.__version__``; the direct argon2-cffi path does not."""
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        new = auth_utils.get_hashed_password("warning-free-1")
        assert auth_utils.verify_and_update_password("warning-free-1", new) == (True, None)
        ok, upgraded = auth_utils.verify_and_update_password("warning-free-1", legacy_bcrypt("warning-free-1"))
        assert ok and upgraded.startswith("$argon2id$")


def test_hashing_is_off_the_event_loop_and_invites_never_generate_passwords(monkeypatch):
    import inspect

    from backend.utilities.team import invitations

    # an invitation never makes a password for somebody else (S2, round 5): the invitee chooses one
    assert not hasattr(membership, "generate_random_password")
    assert "get_hashed_password" not in inspect.getsource(membership)
    assert "run_in_threadpool(get_hashed_password" in inspect.getsource(invitations.register)
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


def _statements_of(engine):
    from sqlalchemy import event

    seen: list[str] = []

    def record(conn, cursor, statement, parameters, context, executemany):
        seen.append(" ".join(statement.split()))

    event.listen(engine, "before_cursor_execute", record)
    return seen


def _wrong(code: str, i: int = 1) -> str:
    return f"{(int(code) + i) % 1_000_000:06d}"


def test_every_guess_is_charged_to_the_live_code_before_it_is_compared(world, monkeypatch):
    """A guess must lock and charge the live code BEFORE it is compared: a ``DELETE ... WHERE code = :guess``
    that matches nothing takes no lock, so concurrent wrong guesses were all compared before any was counted
    (21-30 per code on Postgres instead of five)."""
    engine, _sent = world
    code = auth_utils.issue_verification_code(engine, "order@example.test")
    seen = _statements_of(engine)
    assert not auth_utils.consume_verification_code(engine, "order@example.test", _wrong(code), allow_dev_code=False)
    assert auth_utils.consume_verification_code(engine, "order@example.test", code, allow_dev_code=False)
    touching = [s for s in seen if "verificationcode" in s.lower()]
    assert touching, seen
    assert not any(re.search(r"verificationcode\.code\s*=", s, re.I) for s in touching), \
        "the guess is never compared in SQL (that comparison takes no row lock)"
    first = touching[0]
    assert first.upper().startswith("UPDATE VERIFICATIONCODE SET ATTEMPTS"), first
    assert re.search(r"verificationcode\.attempts\s*<", first) and "RETURNING" in first.upper(), first

    # at most MAX_CODE_ATTEMPTS comparisons per live code, however many guesses arrive at once
    code = auth_utils.issue_verification_code(engine, "burst@example.test")
    compared: list[str] = []
    real = auth_utils._code_matches

    def counting(stored_code, guess):
        compared.append(stored_code)
        return real(stored_code, guess)

    monkeypatch.setattr(auth_utils, "_code_matches", counting)
    guesses = [_wrong(code, i) for i in range(1, 31)] + [code]
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda g: auth_utils.consume_verification_code(
            engine, "burst@example.test", g, allow_dev_code=False), guesses))
    assert len(compared) <= auth_utils.MAX_CODE_ATTEMPTS
    assert results.count(True) <= 1
    if not results[-1]:
        with Session(engine) as s:
            assert s.exec(select(VerificationCode).where(VerificationCode.email == "burst@example.test")).first() is None


PG_URL = os.environ.get("AUTH_TEST_PG_URL")


@pytest.mark.skipif(not PG_URL, reason="set AUTH_TEST_PG_URL (an empty PostgreSQL database) to run")
def test_a_burst_of_wrong_codes_is_compared_at_most_five_times_on_postgres(monkeypatch):
    """The reviewer's race on PostgreSQL: 30 wrong codes and the right one at the same moment.  Counts every
    comparison made against the live code (in Python, or as a SQL ``code = :guess`` that ran before the right
    code was accepted); the design bound is MAX_CODE_ATTEMPTS per code."""
    import threading
    import time

    from sqlalchemy import event

    engine = create_engine(PG_URL, pool_size=40, max_overflow=0)
    SQLModel.metadata.create_all(engine, tables=[VerificationCode.__table__, AuthCounter.__table__])
    sql_compared: list[tuple[float, str, int]] = []
    py_compared: list[str] = []
    lock = threading.Lock()

    @event.listens_for(engine, "after_cursor_execute")
    def _after(conn, cursor, statement, parameters, context, executemany):
        if re.search(r"verificationcode\.code\s*=", statement) and isinstance(parameters, dict):
            guess = next((v for k, v in parameters.items() if k.startswith("code")), None)
            with lock:
                sql_compared.append((time.perf_counter(), guess, cursor.rowcount))

    real = getattr(auth_utils, "_code_matches", None)

    def counting(stored_code, guess):
        with lock:
            py_compared.append(guess)
        return real(stored_code, guess)

    monkeypatch.setattr(auth_utils, "_code_matches", counting, raising=False)
    emails = []
    try:
        for trial in range(4):
            email = f"pg-burst-{trial}-{time.time_ns()}@example.test"
            emails.append(email)
            code = auth_utils.issue_verification_code(engine, email)
            guesses = [_wrong(code, i) for i in range(1, 31)] + [code]
            barrier = threading.Barrier(len(guesses))
            results: dict[str, bool] = {}
            sql_compared.clear()
            py_compared.clear()

            def guess(g):
                barrier.wait()
                if g == code:
                    time.sleep(0.002)
                results[g] = auth_utils.consume_verification_code(engine, email, g, allow_dev_code=False)

            threads = [threading.Thread(target=guess, args=(g,)) for g in guesses]
            for t in threads:
                t.start()
            for t in threads:
                t.join(60)
            compared = len(py_compared)
            if results[code] and sql_compared:
                accepted_at = next(ts for ts, g, _rc in sql_compared if g == code)
                compared += 1 + sum(1 for ts, g, _rc in sql_compared if g != code and ts < accepted_at)
            assert compared <= auth_utils.MAX_CODE_ATTEMPTS, (trial, compared, results[code])
            assert sum(results.values()) <= 1
    finally:
        with Session(engine) as s:
            for email in emails:
                s.exec(sa_delete(VerificationCode).where(VerificationCode.email == email))
                s.exec(sa_delete(AuthCounter).where(AuthCounter.key.like(f"%{email}")))
            s.commit()
        engine.dispose()


def test_codes_per_email_are_capped_per_hour_and_the_cap_resends_the_live_code(client, world, monkeypatch):
    """Past the per-email cap no NEW code is made (the guess budget stays bounded); the live code is mailed
    again instead, so requests from somebody else cannot lock the owner out of sign-in."""
    engine, sent = world
    monkeypatch.setattr(auth_router.send_code_ip_limiter, "times", 100)  # isolate the per-email cap
    for _ in range(auth_utils.CODE_SENDS_PER_EMAIL):
        send_code(client, sent, "flood@example.test")
    live = sent["flood@example.test"][-1]
    r = client.post("/send_code", json={"email": "FLOOD@example.test"})
    assert r.status_code == 200, r.text
    assert sent["flood@example.test"][-1] == live, "the live code again, not a new one"
    with Session(engine) as s:
        rows = s.exec(select(VerificationCode).where(VerificationCode.email == "flood@example.test")).all()
        assert [row.code for row in rows] == [live]
    # at most one re-send per CODE_RESEND_INTERVAL: mail to the address stays bounded
    r = client.post("/send_code", json={"email": "flood@example.test"})
    assert r.status_code == 429
    assert 0 < int(r.headers["retry-after"]) <= auth_utils.CODE_RESEND_INTERVAL.total_seconds() + 1
    assert len(sent["flood@example.test"]) == auth_utils.CODE_SENDS_PER_EMAIL + 1, "no mail for a refused request"
    with Session(engine) as s:  # the window is shared through the database, not this process
        counter = s.get(AuthCounter, "send_code:flood@example.test")
        counter.window_start = counter.window_start - dt.timedelta(hours=1, seconds=1)
        s.add(counter)
        s.commit()
    assert client.post("/send_code", json={"email": "flood@example.test"}).status_code == 200  # a new window
    assert len(sent["flood@example.test"]) == auth_utils.CODE_SENDS_PER_EMAIL + 2


def test_anyone_requesting_codes_cannot_lock_the_owner_out(client, world):
    """Reviewer repro: five unauthenticated /send_code calls (from rotating addresses) used to refuse the owner's
    own request for an hour.  The owner now gets the live code and signs in."""
    engine, sent = world
    add_user(engine, "ceo@example.test", auth_utils.get_hashed_password(PASSWORD))
    for _ in range(auth_utils.CODE_SENDS_PER_EMAIL):
        ratelimit.reset_all()  # stands in for rotating client addresses
        assert client.post("/send_code", json={"email": "ceo@example.test"}).status_code == 200
    ratelimit.reset_all()
    r = client.post("/send_code", json={"email": "CEO@example.test"})  # the owner, from another address
    assert r.status_code == 200, r.text
    assert login(client, "ceo@example.test", PASSWORD, sent["ceo@example.test"][-1]).status_code == 200


def test_past_the_cap_a_burned_code_is_not_replaced(client, world, monkeypatch):
    """Once the hour's codes are used up and the live one is spent (five wrong guesses), no new code exists until
    the window ends: the per-email guess budget (codes x MAX_CODE_ATTEMPTS) is never exceeded."""
    engine, sent = world
    monkeypatch.setattr(auth_router.send_code_ip_limiter, "times", 100)
    add_user(engine, "spent@example.test", auth_utils.get_hashed_password(PASSWORD))
    for _ in range(auth_utils.CODE_SENDS_PER_EMAIL):
        send_code(client, sent, "spent@example.test")
    live = sent["spent@example.test"][-1]
    for i in range(auth_utils.MAX_CODE_ATTEMPTS):
        assert not auth_utils.consume_verification_code(engine, "spent@example.test", _wrong(live, i + 1),
                                                        allow_dev_code=False)
    r = client.post("/send_code", json={"email": "spent@example.test"})
    assert r.status_code == 429 and 3500 < int(r.headers["retry-after"]) <= 3601
    with Session(engine) as s:
        assert s.exec(select(VerificationCode).where(VerificationCode.email == "spent@example.test")).first() is None


def test_a_resent_code_keeps_its_attempt_count_and_gets_a_fresh_expiry(world):
    engine, _sent = world
    for _ in range(auth_utils.CODE_SENDS_PER_EMAIL):
        code = auth_utils.issue_verification_code(engine, "keep@example.test")
    assert not auth_utils.consume_verification_code(engine, "keep@example.test", _wrong(code), allow_dev_code=False)
    with Session(engine) as s:
        row = s.exec(select(VerificationCode).where(VerificationCode.email == "keep@example.test")).one()
        row.expires_at = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=30)
        s.add(row)
        s.commit()
    assert auth_utils.issue_verification_code(engine, "keep@example.test") == code
    with Session(engine) as s:
        row = s.exec(select(VerificationCode).where(VerificationCode.email == "keep@example.test")).one()
        assert row.attempts == 1, "re-sending never hands out more guesses"
        expires = row.expires_at.replace(tzinfo=dt.timezone.utc) if row.expires_at.tzinfo is None else row.expires_at
        assert expires > dt.datetime.now(dt.timezone.utc) + auth_utils.CODE_TTL - dt.timedelta(minutes=1)


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


def test_logout_revokes_the_tokens_for_good(client, world):
    """Reviewer repro: logout only cleared session_active, and the next sign-in set it again, so a stolen
    access or refresh token from before the logout worked again.  Logout now bumps token_version."""
    engine, sent = world
    user_id = add_user(engine, "victim@example.test", auth_utils.get_hashed_password(PASSWORD))
    stolen = login(client, "victim@example.test", PASSWORD, send_code(client, sent, "victim@example.test")).json()
    old = {"Authorization": f"Bearer {stolen['access_token']}"}
    assert client.get("/logout", headers=old).status_code == 200
    assert stored(engine, user_id).token_version == 1
    assert client.get("/get_user", headers=old).status_code == 401
    assert client.post("/refresh", json={"refresh_token": stolen["refresh_token"]}).status_code == 403
    assert client.get("/logout", headers=old).status_code == 401, "a revoked token cannot log out again"
    fresh = login(client, "victim@example.test", PASSWORD, send_code(client, sent, "victim@example.test")).json()
    assert client.get("/get_user", headers=old).status_code == 401, "signing in again does not revive old tokens"
    assert client.post("/refresh", json={"refresh_token": stolen["refresh_token"]}).status_code == 403
    assert client.get("/get_user", headers={"Authorization": f"Bearer {fresh['access_token']}"}).status_code == 200
    assert client.post("/refresh", json={"refresh_token": fresh["refresh_token"]}).status_code == 200


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


def test_no_credential_debug_trace_is_left_in_the_backend():
    """A developer trace (DSS_AGENT_DEBUG_LOG) logged an access-key suffix, the secret's length and the dotenv path,
    and compared the key against the endings of a real key pair.  It is gone, with the trace file that was
    committed from it."""
    markers = re.compile(r"DSS_AGENT_DEBUG_LOG|#region agent log|_agent_debug_log|key_matches_(?:in)?valid_pair")
    offenders = []
    for path in (_REPO_ROOT / "backend").rglob("*.py"):
        if ".venv" in path.parts or "tests" in path.parts:
            continue
        if markers.search(path.read_text(encoding="utf-8", errors="replace")):
            offenders.append(str(path.relative_to(_REPO_ROOT)))
    assert offenders == []
    import subprocess

    tracked = subprocess.run(["git", "-C", str(_REPO_ROOT), "ls-files", "--", ".cursor"], capture_output=True, text=True)
    if tracked.returncode == 0:  # a source checkout (not an image without .git)
        assert not [p for p in tracked.stdout.splitlines() if re.fullmatch(r"\.cursor/debug-[^/]*\.log", p)]
    ignored = subprocess.run(["git", "-C", str(_REPO_ROOT), "check-ignore", "-q", ".cursor/debug-abc123.log"])
    assert ignored.returncode in (0, 128), "Cursor debug traces are git-ignored"


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

    async def fake_send(email, link, expires_on):
        mails.append(email)

    monkeypatch.setattr(admin_router.account_mail, "send_account_created_email", fake_send)
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
