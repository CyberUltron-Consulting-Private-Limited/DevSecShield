"""CB-10: collection never locks out a customer's account or HSM partition.

* PKCS#11 (issue #211): with more than one token and no token label the source is refused (no ``C_Login`` at all);
  only the named token is logged in to; a token whose user PIN is ``COUNT_LOW`` / ``FINAL_TRY`` / ``LOCKED`` gets no
  ``C_Login`` (public objects only) and a coverage row says why.
* A credential breaker in ``jobctx``: after K (3) consecutive ``auth_failed`` for the job's credential the remaining
  targets are ``skipped_credential_refused``, and until the credential has worked once at most K logins are in flight,
  so 10 targets with a wrong password make at most 3 attempts.  The job result carries ``credential_refused`` for the
  server, which pauses the source's runs and schedules until the credential is edited.  Linux password logins, WinRM,
  the database collectors and KMIP use it.
"""
from __future__ import annotations

import threading
import time

import pytest

from zs_scan_node import jobctx
from zs_scan_node.collectors import ConfigError
from zs_scan_node.collectors import database as D
from zs_scan_node.collectors import hsm_pkcs11 as H
from zs_scan_node.collectors import kmip as K
from zs_scan_node.collectors import linux_ssh as L
from zs_scan_node.collectors import windows_winrm as W
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan, Target
from zs_scan_node.scrub import Scrubber

TARGETS = [f"10.0.0.{i}" for i in range(1, 11)]


def _ctx(kind: str = "collect") -> JobContext:
    return JobContext(job_id=7, attempt=1, run_id=None, kind=kind, source_kind="linux_servers",
                      scrubber=Scrubber(["Wrong-Pass-1"]), never_scan=NeverScan(), deadline=time.monotonic() + 60)


class _Attempts:
    """A fake login: records every attempt and how many were in flight at once."""

    def __init__(self, fail, ok_targets=()):
        self.lock = threading.Lock()
        self.tried: list[str] = []
        self.in_flight = 0
        self.peak = 0
        self.fail = fail
        self.ok_targets = set(ok_targets)

    def __call__(self, label: str):
        with self.lock:
            self.tried.append(label)
            self.in_flight += 1
            self.peak = max(self.peak, self.in_flight)
        try:
            time.sleep(0.05)
            if label in self.ok_targets:
                return 1
            raise self.fail
        finally:
            with self.lock:
                self.in_flight -= 1


def _statuses(ctx: JobContext) -> dict[str, int]:
    out: dict[str, int] = {}
    for o in ctx.outcomes:
        out[o.status] = out.get(o.status, 0) + 1
    return out


# ----------------------------------------------------------------------------- the breaker
def test_ten_linux_targets_with_a_wrong_password_make_at_most_three_attempts(monkeypatch):
    attempts = _Attempts(L.TargetFail("auth_failed", "login as zs-cbom was refused"))
    monkeypatch.setattr(L, "collect_target", lambda ctx, target, config, creds: attempts(target.label))
    ctx = _ctx()
    L.collect(ctx, {"credential_type": "password", "parallel": 8}, {"password": "Wrong-Pass-1"}, {"targets": TARGETS})
    assert len(attempts.tried) == 3
    assert _statuses(ctx) == {"auth_failed": 3, "skipped_credential_refused": 7}
    skipped = [o for o in ctx.outcomes if o.status == "skipped_credential_refused"]
    assert "3 logins in a row were refused" in skipped[0].error
    result = ctx.result()
    assert result["credential_refused"] == {"failures": 3, "skipped": 7, "limit": 3}
    assert result["counts"]["skipped"] == 7 and result["counts"]["failed"] == 3


def test_once_the_credential_has_worked_logins_run_in_parallel_again(monkeypatch):
    attempts = _Attempts(L.TargetFail("unreachable", "no route"), ok_targets=TARGETS)
    monkeypatch.setattr(L, "collect_target", lambda ctx, target, config, creds: ("ok", None, attempts(target.label)))
    ctx = _ctx()
    L.collect(ctx, {"credential_type": "password", "parallel": 8}, {"password": "Wrong-Pass-1"}, {"targets": TARGETS})
    assert _statuses(ctx) == {"ok": 10} and attempts.peak > 3
    assert "credential_refused" not in ctx.result()


def test_failures_that_are_not_refused_logins_never_trip_the_breaker(monkeypatch):
    attempts = _Attempts(L.TargetFail("unreachable", "no route to host"))
    monkeypatch.setattr(L, "collect_target", lambda ctx, target, config, creds: attempts(target.label))
    ctx = _ctx()
    L.collect(ctx, {"credential_type": "password", "parallel": 8}, {"password": "Wrong-Pass-1"}, {"targets": TARGETS})
    assert _statuses(ctx) == {"unreachable": 10} and len(attempts.tried) == 10
    assert "credential_refused" not in ctx.result()


def test_a_refused_streak_after_the_credential_worked_still_trips(monkeypatch):
    calls = {"n": 0}

    def login(ctx, target, config, creds):
        calls["n"] += 1
        if calls["n"] == 1:
            return "ok", None, 1
        raise L.TargetFail("auth_failed", "refused")

    monkeypatch.setattr(L, "collect_target", login)
    ctx = _ctx()
    L.collect(ctx, {"credential_type": "password", "parallel": 1}, {"password": "Wrong-Pass-1"}, {"targets": TARGETS})
    assert _statuses(ctx) == {"ok": 1, "auth_failed": 3, "skipped_credential_refused": 6}


def test_key_logins_do_not_use_the_breaker(monkeypatch):
    """The plan's scope is password logins: an SSH key or certificate refused by a host does not count toward an
    account lockout, so a key not yet deployed on some hosts never skips the others."""
    monkeypatch.setattr(L, "_credentials", lambda ctx, config, secrets: {"key": object()})
    attempts = _Attempts(L.TargetFail("auth_failed", "refused"))
    monkeypatch.setattr(L, "collect_target", lambda ctx, target, config, creds: attempts(target.label))
    ctx = _ctx()
    L.collect(ctx, {"credential_type": "node_key", "parallel": 8}, {}, {"targets": TARGETS})
    assert _statuses(ctx) == {"auth_failed": 10}


def test_the_connection_test_uses_the_breaker_too(monkeypatch):
    def refuse(ctx, target, config, creds):
        raise L.TargetFail("auth_failed", "login as zs-cbom was refused")

    monkeypatch.setattr(L, "open_session", refuse)
    ctx = _ctx("test_connection")
    L.test(ctx, {"credential_type": "password"}, {"password": "Wrong-Pass-1"}, {"targets": TARGETS[:5]})
    assert [s["status"] for s in ctx.samples] == ["auth_failed"] * 3 + ["skipped_credential_refused"] * 2


def test_winrm_stops_after_three_refused_logins(monkeypatch):
    attempts = _Attempts(W._Fail("auth_failed", "WinRM refused the login"))
    monkeypatch.setattr(W, "collect_target", lambda ctx, target, config, password, ca_path=None: attempts(target.label))
    monkeypatch.setattr(W, "_password", lambda ctx, config, secrets: "Wrong-Pass-1")
    ctx = _ctx()
    W.collect(ctx, {"parallel": 8}, {"password": "Wrong-Pass-1"}, {"targets": TARGETS})
    assert len(attempts.tried) == 3
    assert _statuses(ctx) == {"auth_failed": 3, "skipped_credential_refused": 7}
    assert ctx.result()["credential_refused"]["failures"] == 3


def test_a_database_login_refused_marks_the_credential_refused(monkeypatch):
    monkeypatch.setattr(D, "_one", lambda ctx, config, secrets, scope=None: (
        Target("db.bank.local", "10.0.0.5"), "auth_failed", "PostgreSQL refused the login", 0))
    ctx = _ctx()
    D.collect(ctx, {"engine": "postgresql", "host": "db.bank.local"}, {"password": "Wrong-Pass-1"}, {})
    assert ctx.result()["credential_refused"] == {"failures": 1, "skipped": 0, "limit": 3}


def test_a_kmip_login_refused_marks_the_credential_refused(monkeypatch):
    monkeypatch.setattr(K, "run", lambda ctx, config, secrets, test_only=False: (
        Target("kmip.bank.local", "10.0.0.6"), "auth_failed", "the KMIP server refused the request", 0))
    ctx = _ctx()
    K.collect(ctx, {"host": "kmip.bank.local"}, {}, {})
    assert ctx.result()["credential_refused"]["failures"] == 1


def test_a_waiting_login_gives_up_when_the_job_stops():
    breaker = jobctx.CredentialBreaker(limit=1)
    assert breaker.acquire(lambda: None) is None  # one login in flight, the credential not proven yet
    stop = {"why": None}
    got: list = []
    waiter = threading.Thread(target=lambda: got.append(breaker.acquire(lambda: stop["why"])))
    waiter.start()
    time.sleep(0.2)
    assert waiter.is_alive()  # waits for the first login's answer
    stop["why"] = "skipped_cancelled"
    waiter.join(2)
    assert got == ["skipped_cancelled"]


# ----------------------------------------------------------------------------- PKCS#11
class _Flags(int):
    pass


class _Token:
    def __init__(self, label: str, flags: int, log: list):
        self.label, self.flags, self._log = label, flags, log
        self.manufacturer_id = self.model = self.serial = ""

    def open(self, rw=False, user_pin=None):
        self._log.append((self.label, user_pin))
        return _Session()


class _Session:
    def get_objects(self):
        return iter(())

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Slot:
    def __init__(self, token, slot_id):
        self._token, self.slot_id = token, slot_id
        self.slot_description = self.manufacturer_id = ""

    def get_token(self):
        return self._token


class _Lib:
    manufacturer_id = library_description = ""

    def __init__(self, tokens):
        self._slots = [_Slot(t, i) for i, t in enumerate(tokens)]

    def get_slots(self, token_present=True):
        return self._slots


def _hsm(monkeypatch, *tokens):
    monkeypatch.setattr(H, "_open", lambda config: ("softhsm", _Lib(list(tokens))))


def _flags(*names: str) -> int:
    from pkcs11 import TokenFlag

    value = TokenFlag.TOKEN_INITIALIZED | TokenFlag.LOGIN_REQUIRED | TokenFlag.USER_PIN_INITIALIZED
    for name in names:
        value |= getattr(TokenFlag, name)
    return value


def test_two_tokens_and_no_label_is_refused_without_any_login(monkeypatch):
    log: list = []
    _hsm(monkeypatch, _Token("lab-a", _flags(), log), _Token("lab-b", _flags(), log))
    ctx = _ctx()
    with pytest.raises(ConfigError, match="2 tokens.*token label"):
        H.collect(ctx, {"module": "softhsm"}, {"pin": "1234"}, {})
    assert log == []
    ctx = _ctx("test_connection")
    H.test(ctx, {"module": "softhsm"}, {"pin": "1234"}, {})
    assert log == [] and ctx.samples[0]["status"] == "error" and "token label" in ctx.samples[0]["note"]


def test_only_the_labelled_token_is_logged_in_to(monkeypatch):
    log: list = []
    _hsm(monkeypatch, _Token("lab-a", _flags(), log), _Token("lab-b", _flags(), log))
    ctx = _ctx()
    H.collect(ctx, {"module": "softhsm", "token_label": "lab-a"}, {"pin": "1234"}, {})
    assert log == [("lab-a", "1234")]
    assert [(o.target, o.status) for o in ctx.outcomes] == [("lab-a", "ok")]


def test_two_tokens_with_the_same_label_are_refused(monkeypatch):
    log: list = []
    _hsm(monkeypatch, _Token("lab-a", _flags(), log), _Token("lab-a", _flags(), log))
    with pytest.raises(ConfigError, match="2 tokens are labelled"):
        H.collect(_ctx(), {"module": "softhsm", "token_label": "lab-a"}, {"pin": "1234"}, {})
    assert log == []


@pytest.mark.parametrize("flag", ["USER_PIN_COUNT_LOW", "USER_PIN_FINAL_TRY", "USER_PIN_LOCKED"])
def test_a_token_near_its_pin_lockout_gets_no_login(monkeypatch, flag):
    log: list = []
    _hsm(monkeypatch, _Token("lab-a", _flags(flag), log))
    ctx = _ctx()
    H.collect(ctx, {"module": "softhsm", "token_label": "lab-a"}, {"pin": "1234"}, {})
    ctx.flush()
    assert log == [("lab-a", None)]  # a session without C_Login: public objects only
    gaps = [a for a in ctx.collected if a["type"] == "coverage"]
    assert len(gaps) == 1 and gaps[0]["facts"]["status"] == "denied"
    assert flag.replace("USER_", "").lower().replace("_", " ")[4:] in gaps[0]["facts"]["detail"].lower()
    ctx = _ctx("test_connection")
    H.test(ctx, {"module": "softhsm", "token_label": "lab-a"}, {"pin": "1234"}, {})
    assert log[-1] == ("lab-a", None) and ctx.samples[0]["status"] == "skipped_credential_refused"


def test_one_token_and_no_label_still_logs_in(monkeypatch):
    log: list = []
    _hsm(monkeypatch, _Token("only", _flags(), log))
    ctx = _ctx()
    H.collect(ctx, {"module": "softhsm"}, {"pin": "1234"}, {})
    assert log == [("only", "1234")]


# ----------------------------------------------------------------------------- PKCS#11 on a real SoftHSM2
# Each check runs in its own process: python-pkcs11 keeps one initialised library per process, and SoftHSM reads its
# token directory once, at C_Initialize (test_hsm_softhsm_live.py relies on initialising it first).
_LIB = next((p for p in ("/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so")
             if __import__("os").path.isfile(p)), None)
_UTIL = __import__("shutil").which("softhsm2-util")
_CHILD = """
import json, sys, time
from zs_scan_node.collectors import ConfigError, hsm_pkcs11 as H
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan
from zs_scan_node.scrub import Scrubber
kind, config = sys.argv[1], json.loads(sys.argv[2])
ctx = JobContext(job_id=1, attempt=1, run_id=None, kind=kind, source_kind="key_manager", scrubber=Scrubber([]),
                 never_scan=NeverScan(), deadline=time.monotonic() + 60)
try:
    (H.test if kind == "test_connection" else H.collect)(ctx, config, {"pin": "11112222"}, {})
    error = None
except ConfigError as exc:
    error = str(exc)
print(json.dumps({"error": error, "outcomes": [[o.target, o.status] for o in ctx.outcomes],
                  "samples": [[s["target"], s["status"], s["note"]] for s in ctx.samples]}))
"""


@pytest.fixture()
def two_tokens(tmp_path):
    """Issue #211's setup: tokens lab-a and lab-b with different PINs on one module."""
    import json
    import os
    import subprocess
    import sys

    if not (_LIB and _UTIL):
        pytest.skip("SoftHSM2 not available")
    pytest.importorskip("pkcs11")
    (tmp_path / "tokens").mkdir()
    conf = tmp_path / "softhsm2.conf"
    conf.write_text(f"directories.tokendir = {tmp_path / 'tokens'}\nobjectstore.backend = file\nlog.level = ERROR\n")
    env = {**os.environ, "SOFTHSM2_CONF": str(conf), "ZS_PKCS11_MODULES": f"softhsm={_LIB}"}
    for label, pin in (("lab-a", "11112222"), ("lab-b", "33334444")):
        subprocess.run([_UTIL, "--module", _LIB, "--init-token", "--free", "--label", label, "--so-pin", "99990000",
                        "--pin", pin], check=True, capture_output=True, env=env)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def run(kind: str, config: dict) -> dict:
        proc = subprocess.run([sys.executable, "-c", _CHILD, kind, json.dumps(config)], capture_output=True, text=True,
                              env={**env, "PYTHONPATH": root}, timeout=60)
        assert proc.returncode == 0, proc.stderr
        return json.loads(proc.stdout.strip().splitlines()[-1])

    return run


def test_softhsm_a_blank_label_with_two_tokens_tries_no_pin(two_tokens):
    tested = two_tokens("test_connection", {"module": "softhsm"})
    assert [s[1] for s in tested["samples"]] == ["error"] and "2 tokens" in tested["samples"][0][2]
    collected = two_tokens("collect", {"module": "softhsm"})
    assert "token label" in collected["error"] and collected["outcomes"] == []


def test_softhsm_only_the_labelled_token_is_read_and_the_other_sees_no_login(two_tokens):
    collected = two_tokens("collect", {"module": "softhsm", "token_label": "lab-a"})
    assert collected["outcomes"] == [["lab-a", "ok"]]  # before CB-10, a blank label gave lab-b auth_failed
    tested = two_tokens("test_connection", {"module": "softhsm", "token_label": "lab-a"})
    assert [s[:2] for s in tested["samples"]] == [["lab-a", "ready"]]
