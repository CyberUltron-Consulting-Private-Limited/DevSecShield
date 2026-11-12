"""Canary grep, 5xx <-> log ref, the strict ledger, checksums and redaction (DA CB-01 failing-first list)."""
from __future__ import annotations

import base64
import json
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from fakerun import FakeRun
from harness import canary, gate, ledger, logs, manifest, redact
from harness.checks import Checks


def _ids(checks: Checks, verdict: str) -> dict[str, str]:
    return {c.id: c.reason for c in checks if c.verdict == verdict}


# ------------------------------------------------------------------------------------------------------- canary
def test_planted_base64_canary_is_found_as_a_leak(tmp_path):
    fr = FakeRun(tmp_path)
    run = fr.write()
    # the canary leaks inside a base64 blob in an API response, at an odd offset
    blob = base64.b64encode(b"xy" + fr.canary_value.encode() + b"tail").decode()
    (run / "api" / "nodes.json").write_text(json.dumps({"blob": blob}), encoding="utf-8")
    checks = Checks()
    canary.judge(run, checks)
    fails = _ids(checks, "FAIL")
    assert fails == {"G15/canary/ssh-pass/leaks": "leak"}
    leak = next(c for c in checks if c.id == "G15/canary/ssh-pass/leaks")
    assert leak.observed == ["api/nodes.json [base64]"]
    assert fr.canary_value not in (run / "canaries.txt").read_text()


@pytest.mark.parametrize("encode, label", [
    (lambda v: v, "raw"),
    (lambda v: json.dumps({"a": v + '"'})[7:-2], "raw"),
    (lambda v: __import__("urllib.parse").parse.quote("p=" + v + "&x", safe=""), "url"),
])
def test_canary_encodings(tmp_path, encode, label):
    fr = FakeRun(tmp_path)
    fr.canary_value = "zs-canary/7f3a 9c1e+5b2d"  # characters that URL-encode
    run = fr.write()
    (run / "logs" / "node.log").write_text("2026-11-12T09:00:00Z x " + encode(fr.canary_value) + "\n", encoding="utf-8")
    checks = Checks()
    canary.judge(run, checks)
    leak = next(c for c in checks if c.id == "G15/canary/ssh-pass/leaks")
    assert leak.verdict == "FAIL" and any(f"[{label}]" in o for o in leak.observed)


def test_canary_inside_a_trace_zip_is_found(tmp_path):
    fr = FakeRun(tmp_path)
    run = fr.write()
    (run / "steps" / "G4").mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(run / "steps" / "G4" / "trace.zip", "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("resources/body.json", json.dumps({"password": fr.canary_value}))
    checks = Checks()
    canary.judge(run, checks)
    leak = next(c for c in checks if c.id == "G15/canary/ssh-pass/leaks")
    assert leak.observed == ["steps/G4/trace.zip!resources/body.json [raw]"]


def test_canary_fails_when_its_control_location_is_absent(tmp_path):
    fr = FakeRun(tmp_path)
    run = fr.write()
    (run / "lab" / "ubuntu" / "zs-canary").unlink()
    checks = Checks()
    canary.judge(run, checks)
    assert _ids(checks, "FAIL") == {"G15/canary/ssh-pass/control": "control-missing"}


def test_clean_run_canary_passes(tmp_path):
    run = FakeRun(tmp_path).write()
    checks = Checks()
    canary.judge(run, checks)
    assert _ids(checks, "FAIL") == {} and len(_ids(checks, "PASS")) == 2


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl needed to make a key")
def test_private_key_canary_found_as_der_hex_and_spki(tmp_path):
    fr = FakeRun(tmp_path)
    run = fr.write()
    key = run / "lab" / "ubuntu" / "rsa1024.key"
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:1024", "-out", str(key)],
                   check=True, capture_output=True)
    fr.edit_json("oracle/canaries.json", lambda d: d["canaries"].append(
        {"id": "rsa1024", "kind": "private_key", "pem_path": "lab/ubuntu/rsa1024.key",
         "allowed": ["oracle/canaries.json"], "control": "lab/ubuntu/rsa1024.key"}))
    pem = key.read_text()
    der = base64.b64decode("".join(ln for ln in pem.splitlines() if ln and not ln.startswith("-----")))
    spki = subprocess.run(["openssl", "pkey", "-pubout", "-outform", "DER"], input=pem.encode(),
                          capture_output=True, check=True).stdout
    import hashlib
    (run / "db" / "dump.sql").write_text("x\\x" + der.hex() + "\n", encoding="utf-8")
    (run / "exports" / "run1.cdx.json").write_text(
        (run / "exports" / "run1.cdx.json").read_text() + " " + hashlib.sha256(spki).hexdigest(), encoding="utf-8")
    manifest.freeze_oracle(run)
    checks = Checks()
    canary.judge(run, checks)
    leak = next(c for c in checks if c.id == "G15/canary/rsa1024/leaks")
    assert leak.verdict == "FAIL"
    assert set(leak.observed) == {"db/dump.sql [der-hex]", "exports/run1.cdx.json [spki-sha256]"}
    assert next(c for c in checks if c.id == "G15/canary/rsa1024/control").verdict == "PASS"


# --------------------------------------------------------------------------------------------------------- logs
def _har(run: Path, status: int, body: str, started="2026-11-12T09:00:05.000Z", path="/9/cbom/sources/runs"):
    har = {"log": {"entries": [{"startedDateTime": started,
                                "request": {"method": "POST", "url": f"https://api.dss.test{path}", "headers": []},
                                "response": {"status": status, "headers": [],
                                             "content": {"mimeType": "application/json", "text": body}}}]}}
    (run / "har" / "G9.har").write_text(json.dumps(har), encoding="utf-8")


def test_5xx_without_a_log_ref_fails(tmp_path):
    run = FakeRun(tmp_path).write()
    _har(run, 500, json.dumps({"detail": "Internal Server Error"}))
    checks = Checks()
    logs.judge(run, checks, [9])
    assert list(_ids(checks, "FAIL").values()) == ["5xx-without-log-ref"]


def test_5xx_with_a_ref_the_backend_logged_passes(tmp_path):
    run = FakeRun(tmp_path).write()
    _har(run, 500, json.dumps({"detail": "Something went wrong; please try again (ref 0a1b2c3d)"}))
    with open(run / "logs" / "backend.log", "a", encoding="utf-8") as fh:
        fh.write("2026-11-12T09:00:05.2Z cbom sources start run FAILED ref=0a1b2c3d error=KeyError team=9\n")
    checks = Checks()
    logs.judge(run, checks, [9])
    assert _ids(checks, "FAIL") == {}


def test_5xx_ref_not_in_any_log_fails(tmp_path):
    run = FakeRun(tmp_path).write()
    _har(run, 500, json.dumps({"detail": "Something went wrong; please try again (ref 0a1b2c3d)"}))
    checks = Checks()
    logs.judge(run, checks, [9])
    assert list(_ids(checks, "FAIL").values()) == ["5xx-ref-not-logged"]


def test_proxy_5xx_explained_by_nginx_line_within_5s(tmp_path):
    run = FakeRun(tmp_path).write()
    _har(run, 502, "<html>bad gateway</html>")
    (run / "logs" / "nginx.log").write_text(
        '2026-11-12T09:00:07Z 172.18.0.1 - - [12/Nov/2026:09:00:07 +0000] "POST /9/cbom/sources/runs HTTP/1.1" 502 157\n',
        encoding="utf-8")
    checks = Checks()
    logs.judge(run, checks, [9])
    assert _ids(checks, "FAIL") == {}


def test_assets_stored_with_rejections_and_unexplained_failed_line(tmp_path):
    run = FakeRun(tmp_path).write()
    (run / "logs" / "backend.log").write_text(
        "2026-11-12T09:00:01Z cbom sources assets stored team=9 run=55 job=900 attempt=1 accepted=2 duplicate=0 "
        "rejected=1 dropped=0 total=2 cap_reached=False\n"
        "2026-11-12T09:00:02Z cbom sources collect FAILED ref=ffff0000 error=ValueError team=9\n"
        "2026-11-12T09:00:03Z cbom sources collect FAILED ref=eeee0000 error=ValueError team=77\n", encoding="utf-8")
    checks = Checks()
    logs.judge(run, checks, [9])
    assert sorted(_ids(checks, "FAIL").values()) == ["assets-rejected-or-dropped", "unexplained-failed-line"]


# ------------------------------------------------------------------------------------------------------- ledger
def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_a_ledger_row_that_passes_makes_the_runner_exit_non_zero(tmp_path, capsys):
    """DA CB-01 failing-first: a stale row (its checks pass) fails the gate until the PR removes it."""
    run = FakeRun(tmp_path).write()  # complete export: key sizes present, so KF-9 passes
    led = _write(tmp_path / "l.yaml",
                 "- row: KF-9\n  gate: [G11]\n  match: {kind: join, view: export, field: key_size}\n  issue: '#1'\n"
                 "  owner: CB-06\n  why: export lacks key size\n"
                 "- row: POSTURE\n  gate: [G11]\n  match: {kind: derived, field: posture}\n  issue: '#1'\n"
                 "  owner: CB-05\n  why: x\n  not_run_ok: CB-05\n")
    assert gate.main(["judge", str(run), "--ledger", str(led)]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["ledger"]["KF-9"] == "stale" and out["blocking"] == 0


def test_ledger_row_matching_nothing_fails_unless_not_run_ok(tmp_path):
    run = FakeRun(tmp_path).write()
    base = ("- row: POSTURE\n  gate: [G11]\n  match: {kind: derived, field: posture}\n  issue: '#1'\n  owner: CB-05\n"
            "  why: x\n  not_run_ok: CB-05\n")
    led = _write(tmp_path / "l.yaml", base + "- row: KF-X\n  gate: [G7]\n  match: {check: zeek}\n  issue: '#1'\n"
                 "  owner: CB-08\n  why: zeek option\n")
    passed, report = gate.judge(run, led)
    assert not passed and {r["row"]: r["status"] for r in report["ledger"]}["KF-X"] == "not-run"
    _write(led, base + "- row: KF-X\n  gate: [G7]\n  match: {check: zeek}\n  issue: '#1'\n  owner: CB-08\n"
           "  why: zeek option\n  not_run_ok: the G7 spec is CB-05's\n")
    passed, report = gate.judge(run, led)
    assert passed


def test_ledger_rows_need_issue_and_owner(tmp_path):
    led = _write(tmp_path / "l.yaml", "- row: KF-1\n  gate: [G3]\n  match: {check: x}\n  owner: CB-03\n  why: y\n")
    with pytest.raises(ledger.LedgerError, match="issue"):
        ledger.load(led)


def test_the_repository_ledger_is_valid():
    rows = ledger.load(gate.DEFAULT_LEDGER)
    assert rows, "e2e/cbom/known-fail.yaml is empty"
    for row in rows:
        assert set(row["gate"]) <= set(gate.GATES), row["row"]
        assert str(row["issue"]).startswith(("#", "cbom/issues/")), row["row"]
        assert str(row["owner"]).startswith(("CB-", "#")), row["row"]


# ------------------------------------------------------------------------------------------ manifest and redaction
def test_sums_verify_and_detect_tampering(tmp_path):
    run = FakeRun(tmp_path).write()
    digest = manifest.write_sums(run)
    assert len(digest) == 64 and manifest.verify(run) == []
    if shutil.which("sha256sum"):
        subprocess.run(["sha256sum", "-c", "--quiet", "SHA256SUMS"], cwd=run, check=True)
    (run / "exports" / "run1.cdx.json").write_text("{}", encoding="utf-8")
    (run / "late.txt").write_text("x", encoding="utf-8")
    assert sorted(manifest.verify(run)) == ["changed exports/run1.cdx.json", "unlisted late.txt"]


def test_har_tokens_are_scrubbed_and_none_left(tmp_path):
    run = FakeRun(tmp_path).write()
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlc2lnbmF0dXJl"
    reg = "zsr_" + "A" * 40
    vendor = "zsv_" + "b" * 32
    har = {"log": {"entries": [{
        "startedDateTime": "2026-11-12T09:00:00Z",
        "request": {"method": "POST", "url": f"https://api.dss.test/q/{vendor}?token=abc12345678",
                    "headers": [{"name": "Authorization", "value": f"Bearer {jwt}"},
                                {"name": "Cookie", "value": "s=1"}],
                    "cookies": [{"name": "s", "value": "1"}],
                    "postData": {"mimeType": "application/json",
                                 "text": json.dumps({"email": "a@b", "password": "Hunter2-very-secret",
                                                     "verification_code": "123456"})}},
        "response": {"status": 200, "headers": [{"name": "Set-Cookie", "value": "s=2"}],
                     "content": {"mimeType": "application/json",
                                 "text": json.dumps({"access_token": jwt, "registration_token": reg,
                                                     "command": f"-e ZS_REGISTRATION_TOKEN='{reg}' \\",
                                                     "finding_codes": ["CERT_EXPIRED"], "code": "PROTO_TLS10"})}}}]}}
    (run / "har" / "G1.har").write_text(json.dumps(har), encoding="utf-8")
    (run / "steps" / "G3" / "command.txt").write_text(f"docker run -e ZS_REGISTRATION_TOKEN='{reg}' img\n",
                                                      encoding="utf-8")
    problems = gate.redact_run(run, ["Hunter2-very-secret"])
    assert problems == []
    text = (run / "har" / "G1.har").read_text()
    for secret in (jwt, reg, vendor, "Hunter2-very-secret", "123456", "abc12345678"):
        assert secret not in text, secret
    assert "CERT_EXPIRED" in text and "PROTO_TLS10" in text  # evidence values survive
    assert reg not in (run / "steps" / "G3" / "command.txt").read_text()
    # the same token gets the same hash in every mark, whatever file it was in (comparable without revealing it)
    digest = redact.mark("x", reg).split(":")[-1].rstrip("]")
    assert f":{digest}]" in text and f":{digest}]" in (run / "steps" / "G3" / "command.txt").read_text()


def test_residual_secret_in_an_export_is_reported_not_rewritten(tmp_path):
    run = FakeRun(tmp_path).write()
    path = run / "exports" / "run1.cdx.json"
    before = path.read_bytes()
    path.write_bytes(before + b" zsn_" + b"x" * 30)
    after = path.read_bytes()
    problems = gate.redact_run(run, [])
    assert problems == ["exports/run1.cdx.json: zs-token"] and path.read_bytes() == after
