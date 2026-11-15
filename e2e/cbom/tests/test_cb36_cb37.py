"""CB-36 Tier V replica runs and CB-37 Tier S acceptance.

The judges read evidence only. They do not launch a sandbox, a browser, or a deploy.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from harness import tier_s as Ts
from harness import tier_v as Tv
from harness.gate import FLOW_STEPS
from harness.rundir import write_json

SHA = "a" * 40
OTHER = "b" * 40
DIGEST = "sha256:" + "ab" * 32
STARTED = "2026-11-15T00:00:00Z"


def _check(report: dict, cid: str) -> dict:
    return next(c for c in report["checks"] if c["id"] == cid)


def _edit(path: Path, fn) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    fn(data)
    write_json(path, data)


def _ssm(chunks) -> dict:
    if chunks and isinstance(chunks[0], dict):
        text = "".join(part["text"] for part in sorted(chunks, key=lambda part: part["index"]))
    else:
        text = "".join(chunks)
    return {"sha256": hashlib.sha256(text.encode()).hexdigest(), "chunks": chunks}


def _ready_v(tmp_path: Path) -> Path:
    run = Tv.plan(tmp_path, SHA)
    facts = dict(Tv.WINDOWS_REQUIRED)
    facts["lockout_counter"] = 1
    describe = {"engine": "postgres", "engine_version": "16.4", "storage_encrypted": True,
                "publicly_accessible": False}
    write_json(run / "tier-v" / "sandbox.json", {
        "build": SHA, "tags": {"Project": "DevSecShield"}, "shutdown_behavior": "terminate",
        "started": STARTED, "deadline": "2026-11-15T03:00:00Z", "destroyed_at": "2026-11-15T02:30:00Z"})
    write_json(run / "tier-v" / "playwright.json", {"headless": True})
    write_json(run / "tier-v" / "teardown.json", {"checked": ["eks", "ec2", "rds", "alb"], "remaining": []})
    write_json(run / "tier-v" / "targets" / "windows.json", {"oracle": facts, "observed": dict(facts)})
    write_json(run / "tier-v" / "targets" / "rds.json", {"oracle": {"describe": describe},
                                                        "observed": {"describe": dict(describe)}})
    write_json(run / "tier-v" / "targets" / "alb.json", {
        "oracle": {"describe": {"scheme": "internal", "dns_name": "internal-cb36.lab"}},
        "observed": {"describe": {"scheme": "internal", "dns_name": "internal-cb36.lab"}}})
    write_json(run / "tier-v" / "targets" / "fips.json", {
        "oracle": {"name": "Rocky Linux", "version_id": "9.3", "fips_enabled": "1"},
        "observed": {"name": "Rocky Linux", "version_id": "9.3", "fips_enabled": 1}})
    write_json(run / "tier-v" / "ssm" / "evidence.json", _ssm([
        {"index": 1, "text": "-evidence"}, {"index": 0, "text": "tier-v"}]))
    return run


def _steps(run: Path, fail_step: str | None = None, include_dropped: bool = False) -> None:
    steps = list(FLOW_STEPS) if include_dropped else [s for s in FLOW_STEPS if s not in Ts.DROPPED_STEPS]
    for step in steps:
        write_json(run / "steps" / step / "step.json", {
            "gate": step, "status": "ran",
            "checks": [{"id": f"{step}/ok", "verdict": "FAIL" if step == fail_step else "PASS"}]})


def _preflight(**over) -> dict:
    doc = {
        "sha": SHA,
        "builds": {"health": SHA[:12], "header": SHA, "frontend": SHA, "node": SHA},
        "alembic_current": "cb37head", "alembic_head": "cb37head",
        "workers": {"cloud_worker": True, "scheduler": True, "dispatcher": True},
        "canary_idp": {"ran": True, "seconds": 300},
        "canary_schedule": {"fired": True, "in_slot": True},
        "node_image": {"digest": DIGEST, "published": True},
        "allowed_diff": False, "topup": False, "oa7": False,
        "g13_public_receiver_approved": False, "inherited_from_l_sha": SHA,
    }
    doc.update(over)
    return doc


def _ready_s(tmp_path: Path, **over) -> Path:
    run = Ts.plan(tmp_path, SHA)
    write_json(run / "tier-s" / "preflight.json", _preflight(**over))
    _steps(run, include_dropped=bool(over.get("g13_public_receiver_approved")))
    return run


# ----------------------------------------------------------------------------- CB-36
def test_plan_names_a_tier_v_run_and_states_the_contract(tmp_path):
    run = Tv.plan(tmp_path, SHA)
    assert run.name.startswith(f"V-{SHA[:12]}-")
    contract = json.loads((run / "tier-v" / "contract.json").read_text(encoding="utf-8"))
    assert contract["track"] == "CB-36" and contract["sha"] == SHA
    assert contract["max_lifetime_min"] == 180 and contract["ssm_inline_cap"] == 24000
    assert contract["windows"]["rdp_nla"] is False and contract["windows"]["lockout_threshold"] == 3
    assert contract["rds_engine"] == "postgres" and contract["alb_scheme"] == "internal"
    assert Tv.main(["plan", "--root", str(tmp_path), "--sha", "abc"]) == 2


def test_a_complete_replica_passes_and_judges_again(tmp_path):
    run = _ready_v(tmp_path)
    ok, report = Tv.judge(run)
    assert ok and report["schema"] == "zs-cbom-tier-v/1" and report["sha"] == SHA
    assert Tv.judge(run)[0] is True
    assert Tv.main(["judge", str(run)]) == 0
    assert Tv.main(["judge", str(tmp_path / "missing")]) == 2


def test_ssm_chunks_reassemble_in_order_under_the_character_cap():
    body, reason = Tv.reassemble_ssm(_ssm([{"index": 1, "text": "b"}, {"index": 0, "text": "a"}]))
    assert reason == "" and body == b"ab"
    exact, reason = Tv.reassemble_ssm(_ssm(["é" * 24000]))
    assert reason == "" and exact == ("é" * 24000).encode()
    over, reason = Tv.reassemble_ssm(_ssm(["é" * 24001]))
    assert over is None and "24001" in reason and "24000" in reason
    gap, reason = Tv.reassemble_ssm(_ssm([{"index": 0, "text": "a"}, {"index": 2, "text": "c"}]))
    assert gap is None and "indexes" in reason
    mixed, reason = Tv.reassemble_ssm({"sha256": "ab" * 32, "chunks": ["a", {"index": 1, "text": "b"}]})
    assert mixed is None and "mix" in reason
    bad = _ssm(["evidence"])
    bad["sha256"] = "0" * 64
    mismatch, reason = Tv.reassemble_ssm(bad)
    assert mismatch is None and reason == "sha256 does not match the reassembled download"
    empty, reason = Tv.reassemble_ssm(_ssm([""]))
    assert empty is None and "empty" in reason
    huge, reason = Tv.reassemble_ssm(_ssm(["x"] * (Tv.MAX_SSM_CHUNKS + 1)))
    assert huge is None and "chunks" in reason


def test_lifetime_boundary_shutdown_tag_and_build(tmp_path):
    run = _ready_v(tmp_path)
    _edit(run / "tier-v" / "sandbox.json", lambda d: d.update(destroyed_at="2026-11-15T03:00:00Z"))
    assert Tv.judge(run)[0] is True  # destroyed on the 180-minute deadline

    _edit(run / "tier-v" / "sandbox.json", lambda d: d.update(deadline="2026-11-15T03:01:00Z",
                                                             destroyed_at="2026-11-15T03:01:00Z"))
    ok, report = Tv.judge(run)
    assert not ok and _check(report, "V/lifetime")["verdict"] == "FAIL"

    _edit(run / "tier-v" / "sandbox.json", lambda d: d.update(deadline="2026-11-15T02:00:00Z",
                                                             destroyed_at="2026-11-15T02:30:00Z"))
    assert _check(Tv.judge(run)[1], "V/lifetime")["verdict"] == "FAIL"  # destroyed after the declared deadline

    _edit(run / "tier-v" / "sandbox.json", lambda d: d.update(
        started=STARTED, deadline="2026-11-15T02:00:00Z", destroyed_at="2026-11-15T01:00:00Z",
        shutdown_behavior="stop", tags={"Project": "other"}, build=OTHER))
    report = Tv.judge(run)[1]
    assert _check(report, "V/shutdown")["verdict"] == "FAIL"
    assert _check(report, "V/tags")["verdict"] == "FAIL"
    assert _check(report, "V/build")["verdict"] == "FAIL"
    assert _check(report, "V/lifetime")["verdict"] == "PASS"


def test_windows_rds_alb_and_fips_rows(tmp_path):
    run = _ready_v(tmp_path)
    _edit(run / "tier-v" / "targets" / "windows.json", lambda d: d["observed"].update(ecc_p256=False))
    report = Tv.judge(run)[1]
    assert _check(report, "V/windows/ecc_p256")["reason"] == "mismatch"
    _edit(run / "tier-v" / "targets" / "windows.json", lambda d: (
        d["oracle"].pop("ecc_p256"), d["observed"].pop("ecc_p256")))
    assert _check(Tv.judge(run)[1], "V/windows/ecc_p256")["verdict"] == "NOT-JUDGED"
    _edit(run / "tier-v" / "targets" / "windows.json", lambda d: d["oracle"].update(ecc_p256=True, rdp_nla=True))
    assert _check(Tv.judge(run)[1], "V/windows/rdp_nla")["reason"] == "oracle"
    _edit(run / "tier-v" / "targets" / "windows.json", lambda d: d["oracle"].update(rdp_nla=False, lockout_counter=3))
    assert _check(Tv.judge(run)[1], "V/windows/lockout_counter")["reason"] == "oracle"

    _edit(run / "tier-v" / "targets" / "rds.json", lambda d: d["oracle"]["describe"].update(engine="mysql"))
    assert _check(Tv.judge(run)[1], "V/rds/describe")["reason"] == "not-postgres"
    _edit(run / "tier-v" / "targets" / "rds.json", lambda d: d["oracle"]["describe"].update(engine="postgres"))
    _edit(run / "tier-v" / "targets" / "rds.json", lambda d: d["observed"]["describe"].update(engine_version="16.3"))
    assert _check(Tv.judge(run)[1], "V/rds/describe")["reason"] == "mismatch"

    _edit(run / "tier-v" / "targets" / "alb.json", lambda d: d["observed"]["describe"].update(scheme="internet-facing"))
    assert _check(Tv.judge(run)[1], "V/alb/scheme")["verdict"] == "FAIL"
    _edit(run / "tier-v" / "targets" / "alb.json", lambda d: d["oracle"]["describe"].pop("scheme"))
    assert _check(Tv.judge(run)[1], "V/alb/scheme")["verdict"] == "NOT-JUDGED"

    _edit(run / "tier-v" / "targets" / "fips.json", lambda d: d["observed"].update(name="Ubuntu"))
    assert _check(Tv.judge(run)[1], "V/fips/host")["reason"] == "mismatch"
    _edit(run / "tier-v" / "targets" / "fips.json", lambda d: d["oracle"].pop("version_id"))
    assert _check(Tv.judge(run)[1], "V/fips/host")["verdict"] == "NOT-JUDGED"


def test_missing_evidence_does_not_pass(tmp_path):
    run = _ready_v(tmp_path)
    (run / "tier-v" / "playwright.json").unlink()
    (run / "tier-v" / "ssm").rename(tmp_path / "ssm-aside")
    ok, report = Tv.judge(run)
    assert not ok
    assert _check(report, "V/playwright")["verdict"] == "NOT-RUN"
    assert _check(report, "V/ssm")["verdict"] == "NOT-RUN"
    _edit(run / "tier-v" / "teardown.json", lambda d: d.update(remaining=["i-0cb36"], checked=["ec2"]))
    assert _check(Tv.judge(run)[1], "V/teardown")["verdict"] == "FAIL"
    (run / "tier-v" / "sandbox.json").unlink()
    assert _check(Tv.judge(run)[1], "V/sandbox")["verdict"] == "NOT-RUN"


def test_a_headless_flag_must_be_boolean_true(tmp_path):
    run = _ready_v(tmp_path)
    _edit(run / "tier-v" / "playwright.json", lambda d: d.update(headless="true"))
    assert _check(Tv.judge(run)[1], "V/playwright")["verdict"] == "FAIL"


def test_tier_modules_do_not_call_the_network():
    root = Path(__file__).resolve().parents[1] / "harness"
    for name in ("tier_v.py", "tier_s.py"):
        text = (root / name).read_text(encoding="utf-8")
        for banned in ("boto", "requests", "urllib", "http.client", "socket", "subprocess"):
            assert banned not in text


# ----------------------------------------------------------------------------- CB-37
def test_plan_names_a_tier_s_acceptance(tmp_path):
    run = Ts.plan(tmp_path, SHA)
    assert run.name.startswith(f"S-{SHA[:12]}-")
    contract = json.loads((run / "tier-s" / "contract.json").read_text(encoding="utf-8"))
    assert contract["track"] == "CB-37" and contract["canary_idp_max_s"] == 300
    assert contract["dropped_unless_public_receiver"] == ["G13", "G13b"]
    assert Ts.main(["plan", "--root", str(tmp_path), "--sha", "nope"]) == 2


def test_a_recorded_acceptance_signs_off(tmp_path):
    run = _ready_s(tmp_path)
    assert Ts.main(["accept", str(run), "--date", "2026-11-15"]) == 0
    ok, report = Ts.accept(run, "2026-11-15")
    assert ok and report["schema"] == "zs-cbom-tier-s/1"
    text = (run / "sign-off" / "staging-acceptance-2026-11-15.md").read_text(encoding="utf-8")
    assert text.startswith("# CBOM Tier S acceptance 2026-11-15")
    assert "**Verdict: PASS**" in text
    saved = json.loads((run / "tier-s" / "report.json").read_text(encoding="utf-8"))
    assert saved["signoff"] == "sign-off/staging-acceptance-2026-11-15.md"
    assert f"DB and log rows are inherited from Tier L at the same SHA {SHA}." in text
    assert _check(report, "S/step/G13")["verdict"] == "NOT-RUN"
    assert _check(report, "S/step/G13")["subject"]["accepted_skip"] is True
    assert _check(report, "S/step/G13b")["subject"]["accepted_skip"] is True
    assert _check(report, "S/canary/idp")["verdict"] == "PASS"  # 300 seconds is the limit
    assert Ts.main(["accept", str(tmp_path / "missing"), "--date", "2026-11-15"]) == 2
    assert Ts.main(["accept", str(run), "--date", "15 Nov 2026"]) == 2


def test_preflight_disagreements_fail(tmp_path):
    run = _ready_s(tmp_path)
    _edit(run / "tier-s" / "preflight.json", lambda d: d["builds"].update(header=OTHER))
    assert _check(Ts.accept(run, "2026-11-15")[1], "S/build/header")["verdict"] == "FAIL"
    _edit(run / "tier-s" / "preflight.json", lambda d: d["builds"].update(header=SHA))
    _edit(run / "tier-s" / "preflight.json", lambda d: d["canary_idp"].update(seconds=300.1))
    assert _check(Ts.accept(run, "2026-11-15")[1], "S/canary/idp")["verdict"] == "FAIL"
    _edit(run / "tier-s" / "preflight.json", lambda d: d["canary_idp"].update(seconds=True))
    assert _check(Ts.accept(run, "2026-11-15")[1], "S/canary/idp")["verdict"] == "FAIL"
    _edit(run / "tier-s" / "preflight.json", lambda d: d["canary_idp"].update(seconds=120))
    _edit(run / "tier-s" / "preflight.json", lambda d: d["canary_schedule"].update(in_slot=False))
    assert _check(Ts.accept(run, "2026-11-15")[1], "S/canary/schedule")["verdict"] == "FAIL"
    _edit(run / "tier-s" / "preflight.json", lambda d: d.update(
        canary_schedule={"fired": True, "in_slot": True}, allowed_diff=True, topup=True,
        alembic_current="other-head", workers={"cloud_worker": True, "scheduler": False, "dispatcher": True},
        node_image={"digest": "ghcr.io/example/node:1.0.2", "published": True},
        inherited_from_l_sha=OTHER))
    report = Ts.accept(run, "2026-11-15")[1]
    for cid in ("S/allowed-diff", "S/topup", "S/alembic", "S/worker/scheduler", "S/node-image",
                "S/evidence/inherited"):
        assert _check(report, cid)["verdict"] == "FAIL", cid


def test_oa7_collects_db_and_logs_and_a_dropped_receiver_stays_dropped(tmp_path):
    run = _ready_s(tmp_path, oa7=True, inherited_from_l_sha=None)
    ok, report = Ts.accept(run, "2026-11-15")
    assert not ok
    assert _check(report, "S/evidence/db")["verdict"] == "FAIL"
    assert _check(report, "S/evidence/logs")["verdict"] == "FAIL"
    (run / "db" / "assets.csv").write_text("id\n1\n", encoding="utf-8")
    (run / "logs" / "backend.log").write_text("cloud worker started\n", encoding="utf-8")
    ok, report = Ts.accept(run, "2026-11-15")
    text = (run / report["signoff"]).read_text(encoding="utf-8")
    assert ok and "DB and log rows were collected for this acceptance." in text
    assert "inherited from Tier L" not in text

    refused = _ready_s(tmp_path / "public", g13_public_receiver_approved=True)
    (refused / "steps" / "G13" / "step.json").unlink()
    assert _check(Ts.accept(refused, "2026-11-15")[1], "S/step/G13")["verdict"] == "NOT-RUN"
    assert "accepted_skip" not in _check(Ts.accept(refused, "2026-11-15")[1], "S/step/G13")["subject"]


def test_a_failed_gate_step_and_a_missing_preflight_do_not_sign_off_as_pass(tmp_path):
    run = _ready_s(tmp_path)
    _steps(run, fail_step="G0")
    ok, report = Ts.accept(run, "2026-11-15")
    assert not ok and _check(report, "S/step/G0")["verdict"] == "FAIL"
    (run / "tier-s" / "preflight.json").write_text("{", encoding="utf-8")
    ok, report = Ts.accept(run, "2026-11-15")
    assert not ok and _check(report, "S/preflight")["verdict"] == "FAIL"
    (run / "tier-s" / "preflight.json").unlink()
    ok, report = Ts.accept(run, "2026-11-15")
    assert not ok and _check(report, "S/preflight")["verdict"] == "NOT-RUN"
    assert "**Verdict: FAIL**" in (run / report["signoff"]).read_text(encoding="utf-8")


def test_the_signoff_scrubs_a_bearer_token(tmp_path):
    token = "Bearer " + "a" * 20
    run = _ready_s(tmp_path, alembic_current=token, alembic_head=token)
    ok, report = Ts.accept(run, "2026-11-15")
    text = (run / report["signoff"]).read_text(encoding="utf-8")
    assert ok and token not in text and "[REDACTED:bearer:" in text


def test_modules_stay_under_the_file_cap():
    root = Path(__file__).resolve().parents[1] / "harness"
    for name in ("tier_v.py", "tier_s.py"):
        assert len((root / name).read_text(encoding="utf-8").splitlines()) < 500
