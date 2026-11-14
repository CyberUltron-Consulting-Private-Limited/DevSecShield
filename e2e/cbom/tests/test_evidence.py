"""Canary grep, 5xx <-> log ref, the strict ledger, checksums and redaction (DA CB-01 failing-first list)."""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

import ledgers
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
def test_private_key_canary_found_as_pem_line_and_der_hex_but_not_by_its_public_fingerprint(tmp_path):
    fr = FakeRun(tmp_path)
    run = fr.write()
    key = run / "lab" / "ubuntu" / "rsa1024.key"
    other = run / "lab" / "ubuntu" / "other.key"
    for k in (key, other):
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:1024", "-out", str(k)],
                       check=True, capture_output=True)
    fr.edit_json("oracle/canaries.json", lambda d: d["canaries"].extend([
        {"id": "rsa1024", "kind": "private_key", "pem_path": "lab/ubuntu/rsa1024.key",
         "allowed": ["oracle/canaries.json"], "control": "lab/ubuntu/rsa1024.key"},
        {"id": "other", "kind": "private_key", "pem_path": "lab/ubuntu/other.key",
         "allowed": ["oracle/canaries.json"], "control": "lab/ubuntu/other.key"}]))
    pem = key.read_text()
    lines = [ln for ln in pem.splitlines() if ln and not ln.startswith("-----")]
    der = base64.b64decode("".join(lines))
    spki = subprocess.run(["openssl", "pkey", "-pubout", "-outform", "DER"], input=pem.encode(),
                          capture_output=True, check=True).stdout
    (run / "db" / "dump.sql").write_text("x\\x" + der.hex() + "\n", encoding="utf-8")
    (run / "logs" / "node.log").write_text("2026-11-12T09:00:00Z " + lines[5] + "\n", encoding="utf-8")
    # what a CBOM is supposed to report: the public key's fingerprint, and the shared first PEM line
    (run / "exports" / "fp.txt").write_text(hashlib.sha256(spki).hexdigest() + "\n" + lines[0] + "\n", encoding="utf-8")
    manifest.freeze_oracle(run)
    checks = Checks()
    canary.judge(run, checks)
    leak = next(c for c in checks if c.id == "G15/canary/rsa1024/leaks")
    assert leak.verdict == "FAIL"
    assert set(leak.observed) == {"db/dump.sql [der-hex]", "logs/node.log [pem-line]"}
    assert next(c for c in checks if c.id == "G15/canary/rsa1024/control").verdict == "PASS"
    assert next(c for c in checks if c.id == "G15/canary/other/leaks").verdict == "PASS"


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
    pin = {"id": "G11/join/run1/asset/certificate@10.231.0.17:443/key_size/export", "expected": 256, "observed": "<absent>"}
    led = ledgers.write(tmp_path / "l.yaml",
                        ledgers.row("KF-9", ["G11"], {"kind": "join", "view": "export", "field": "key_size"}, [pin],
                                    owner="CB-06"), ledgers.POSTURE)
    assert gate.main(["judge", str(run), "--ledger", str(led)]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["ledger"]["KF-9"] == "stale" and out["blocking"] == 0


def test_ledger_row_matching_nothing_fails_as_stale(tmp_path):
    run = FakeRun(tmp_path).write()
    led = ledgers.write(tmp_path / "l.yaml", ledgers.POSTURE,
                        ledgers.row("KF-X", ["G7"], {"check": "zeek"}, [{"id": "G7/zeek"}], owner="CB-08"))
    passed, report = gate.judge(run, led)
    assert not passed and {r["row"]: r["status"] for r in report["ledger"]}["KF-X"] == "stale"


ROW = "- row: KF-1\n  gate: [G3]\n  match: {check: x}\n  owner: CB-03\n  why: y\n"


def test_ledger_rows_need_issue_owner_and_pinned_identities(tmp_path):
    led = _write(tmp_path / "l.yaml", ROW + "  expect: [{id: G3/x}]\n")
    with pytest.raises(ledger.LedgerError, match="issue"):
        ledger.load(led)
    _write(led, ROW + "  issue: '#1'\n")
    with pytest.raises(ledger.LedgerError, match="expect"):
        ledger.load(led)
    # v2 counts alone pin nothing; a NOT-RUN pin needs its reason; a reason needs a NOT-RUN pin; counts that disagree
    # with the pins; malformed pins (kills L8, L11, L12 and the v3 pin rules)
    for extra, error in (("  expect_failing: 2\n", "lacks expect"),
                         ("  expect: []\n", "lacks expect"),
                         ("  expect: [{id: G3/x, verdict: NOT-RUN}]\n", "needs not_run_ok"),
                         ("  expect: [{id: G3/x}]\n  not_run_ok: z\n", "without a pinned NOT-RUN"),
                         ("  expect: [{id: G3/x}]\n  expect_failing: 2\n", "expect pins 1"),
                         ("  expect: [{id: G3/x, verdict: KNOWN-FAIL}]\n", "verdict must be"),
                         ("  expect: [{id: G3/x, bogus: 1}]\n", "unknown keys"),
                         ("  expect: [{verdict: FAIL}]\n", "string id"),
                         ("  expect: [{id: G3/x, verdict: NOT-RUN, expected: 1}]\n  not_run_ok: z\n", "no expected")):
        _write(led, ROW + "  issue: '#1'\n" + extra)
        with pytest.raises(ledger.LedgerError, match=error):
            ledger.load(led)
    _write(led, ROW + "  issue: '#1'\n  expect: [{id: G3/x}]\n  expect_failing: 1\n")
    assert ledger.load(led)[0]["expect"] == [{"id": "G3/x", "verdict": "FAIL", "expected": None, "observed": None}]


@pytest.mark.parametrize("match, error", [
    ({"verdict": "FAIL"}, "not allowed"),
    ({"id_prefix": "G11/"}, "not allowed"),
    ({"id": "G11/x"}, "not allowed"),
    ({"kind": "join"}, "must name one of"),
    ({"check": "x", "bogus": 1}, "not allowed"),
    ({"check": []}, "a value or a list"),
])
def test_ledger_refuses_wide_or_unknown_match_keys(tmp_path, match, error):
    """Review 5874859738 major 6: a row can only be narrowed; `{verdict: FAIL}` used to absorb every failure."""
    led = ledgers.write(tmp_path / "l.yaml", ledgers.row("WIDE", ["G11"], match, [{"id": "G11/x"}]))
    with pytest.raises(ledger.LedgerError, match=error):
        ledger.load(led)


def _check(id_, gate_, verdict, **subject):
    from harness.checks import Check
    expected, observed = subject.pop("expected", None), subject.pop("observed", None)
    return Check(id=id_, gate=gate_, kind=subject.pop("kind", "oracle"), verdict=verdict, subject=subject,
                 reason=subject.pop("reason", ""), expected=expected, observed=observed)


def _rows(tmp_path, text):
    return ledger.load(_write(tmp_path / "rows.yaml", text))


def test_ledger_matching_semantics_gate_scope_lists_and_exact_values(tmp_path):
    """Kills mutants L5 (gate ignored), L6 (lists as wildcards), L7 (prefix/substring), L9 (NOT-JUDGED ledgerable)."""
    from harness.checks import Checks
    rows = _rows(tmp_path, "- {row: R, gate: [G11], match: {field: [key_size, curve]}, issue: '#1', owner: CB-1, why: x, "
                           "expect: [{id: a}, {id: b, verdict: NOT-JUDGED}]}")
    checks = Checks()
    checks.add(_check("a", "G11", "FAIL", field="key_size"))      # matched
    checks.add(_check("b", "G11", "NOT-JUDGED", field="curve"))   # matched (NOT-JUDGED can be ledgered)
    checks.add(_check("c", "G12", "FAIL", field="key_size"))      # other gate: not matched
    checks.add(_check("d", "G11", "FAIL", field="key_size_x"))    # neither a prefix nor a substring match
    checks.add(_check("e", "G11", "FAIL", field="groups"))        # a value not in the list
    checks.add(_check("f", "G11", "FAIL"))                        # no field at all: never matched (L13)
    results, blocking = ledger.apply(rows, checks)
    assert results[0].failing == 2 and results[0].status == "holds", results[0]
    assert sorted(c.id for c in blocking) == ["c", "d", "e", "f"]


@pytest.mark.parametrize("verdict, observed, status", [
    ("FAIL", 1024, "holds"),         # as pinned
    ("FAIL", 512, "moved"),          # the same check, a different wrong value (a worse regression)
    ("NOT-JUDGED", 1024, "moved"),   # the same value, another verdict
])
def test_ledger_pins_compare_verdict_and_values_not_counts(tmp_path, verdict, observed, status):
    """Review 5878413538 major 3: the identity is (id, verdict, expected, observed); a count would see none of this."""
    from harness.checks import Checks
    rows = _rows(tmp_path, "- {row: R, gate: [G11], match: {field: key_size}, issue: '#1', owner: CB-1, why: x, "
                           "expect: [{id: a, expected: 2048, observed: 1024}]}")
    checks = Checks()
    checks.add(_check("a", "G11", verdict, field="key_size", expected=2048, observed=observed))
    results, blocking = ledger.apply(rows, checks)
    assert results[0].status == status and not blocking
    if status == "moved":
        assert results[0].unexpected and results[0].missing == [{"id": "a", "verdict": "FAIL", "expected": 2048,
                                                                  "observed": 1024}]


def test_ledger_not_run_needs_a_not_run_row(tmp_path):
    """Kills L3: a NOT-RUN check is covered only by a row that pins it with not_run_ok, not by any matching row."""
    from harness.checks import Checks
    plain = _rows(tmp_path, "- {row: F, gate: [G7], match: {check: x}, issue: '#1', owner: CB-1, why: y, expect: [{id: x}]}")
    checks = Checks()
    checks.add(_check("x", "G7", "NOT-RUN", check="x"))
    results, blocking = ledger.apply(plain, checks)
    assert [c.id for c in blocking] == ["x"] and results[0].status == "moved"
    checks = Checks()
    checks.add(_check("x", "G7", "NOT-RUN", check="x"))
    ok = _rows(tmp_path, "- {row: F, gate: [G7], match: {check: x}, issue: '#1', owner: CB-1, why: y, "
                         "not_run_ok: by design, expect: [{id: x, verdict: NOT-RUN}]}")
    results, blocking = ledger.apply(ok, checks)
    assert not blocking and results[0].status == "not-run-ok"


def test_pin_tool_rewrites_only_the_expect_blocks():
    """`python3 -m harness.ledger pin <run> --write` keeps comments and other keys and replaces counts by identities."""
    text = ("# a comment kept\n- row: A\n  gate: [G11]\n  match: {check: x}\n  expect_failing: 3\n  issue: '#1'\n"
            "  owner: CB-1\n  why: \"two\n    lines\"\n  expect:\n    - {\"id\": \"old\"}\n# between\n- row: B\n"
            "  gate: [G7]\n  match: {check: y}\n  issue: '#2'\n  owner: CB-2\n  why: z\n")
    out = ledger.rewrite(text, {"A": [{"id": "G11/x", "verdict": "FAIL", "expected": 1, "observed": 2}]})
    assert "# a comment kept" in out and "# between" in out and '"id": "old"' not in out and "expect_failing" not in out
    rows = ledger.load.__globals__["yaml"].safe_load(out)
    assert rows[0]["expect"] == [{"id": "G11/x", "expected": 1, "observed": 2}] and rows[0]["why"] == "two lines"
    assert "expect" not in rows[1]


def test_the_repository_ledger_is_valid():
    rows = ledger.load(gate.DEFAULT_LEDGER)  # v3 schema: allowlisted keys, narrowing key, pinned identities
    assert rows, "e2e/cbom/known-fail.yaml is empty"
    for row in rows:
        assert set(row["gate"]) <= set(gate.GATES + gate.WAVES), row["row"]
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
    jwt = ".".join(base64.urlsafe_b64encode(part).decode().rstrip("=") for part in (
        json.dumps({"alg": "HS256"}).encode(), json.dumps({"sub": secrets.token_hex(8)}).encode(), secrets.token_bytes(24)))
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


def test_a_missing_core_log_fails_g16(tmp_path):
    run = FakeRun(tmp_path).write()
    (run / "logs" / "nginx.log").unlink()
    checks = Checks()
    logs.judge(run, checks, [9])
    assert _ids(checks, "FAIL") == {"G16/collected/nginx": "log-missing"}


def test_deferred_lab_parts_become_not_run_checks_the_ledger_must_name(tmp_path):
    fr = FakeRun(tmp_path)
    run = fr.write()
    deferred = [{"part": "idp", "address": "10.231.0.42", "gate": ["G7"], "reason": "IdP target not built",
                 "deferred": True, "issue_draft": "round6/cbom/cb-02/issue-deferred.md"},
                {"part": "k8s", "address": None, "gate": ["W-HOST"], "reason": "disk", "deferred": True}]
    fr.edit_json("oracle/run1.json", lambda d: d.__setitem__("deferred", deferred))
    (run / "lab" / "lab.json").write_text(json.dumps({"deferred": deferred}), encoding="utf-8")
    manifest.freeze_oracle(run)
    led = ledgers.write(tmp_path / "l.yaml", ledgers.POSTURE)
    passed, report = gate.judge(run, led)
    ids = {c["id"]: c for c in report["checks"]}
    assert ids["G7/deferred_idp"]["verdict"] == "NOT-RUN" and ids["G7/deferred_idp"]["reason"] == "IdP target not built"
    assert ids["W-HOST/deferred_k8s"]["subject"]["part"] == "k8s"
    assert not passed  # unlisted NOT-RUN blocks
    ledgers.write(led, ledgers.POSTURE, ledgers.row("LAB", ["G7", "W-HOST"], {"check": "deferred", "part": ["idp", "k8s"]},
                                                    [ledgers.nr("G7/deferred_idp"), ledgers.nr("W-HOST/deferred_k8s")],
                                                    not_run_ok="deferred by the lab", owner="CB-02", issue="#93"))
    passed, report = gate.judge(run, led)
    assert passed, [c["id"] for c in report["blocking"]]


def test_judging_a_hard_linked_copy_never_rewrites_the_sealed_bundle(tmp_path):
    """Run 5 incident: `cp -al` + judge rewrote the bundle's diff/oracle-run1.csv through the shared inode."""
    import os
    import shutil
    run = FakeRun(tmp_path / "a").write()
    gate.judge(run, ledgers.write(tmp_path / "l.yaml", ledgers.POSTURE))
    sealed = {p: p.read_bytes() for p in run.rglob("*") if p.is_file()}
    copy = tmp_path / "copy"
    shutil.copytree(run, copy, copy_function=os.link)
    api = copy / "api" / "assets-run1.json"  # a different judgement must not leak back into the original
    doc = json.loads(api.read_text(encoding="utf-8"))
    doc["items"][0]["algorithm"] = "DSA"
    api.unlink()
    api.write_text(json.dumps(doc), encoding="utf-8")
    gate.judge(copy, ledgers.write(tmp_path / "l.yaml", ledgers.POSTURE))
    assert {p: p.read_bytes() for p in run.rglob("*") if p.is_file()} == sealed
