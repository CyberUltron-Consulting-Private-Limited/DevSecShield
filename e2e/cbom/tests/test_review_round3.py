"""Controls added for review 5878413538 (#75 round 3): each test fails on a wrong CBOM the reviewer showed the gate let
through (round6/rv-75-r2/wrong6.json) or on one of the reviewer's mutants of the judge that the earlier suite did not
kill (round6/rv-75-r2/mymutants.txt)."""
from __future__ import annotations

import csv
import datetime as dt
import json
from pathlib import Path

import pytest

import ledgers
from fakerun import FakeRun
from harness import gate, identity, join, logs, manifest, neverscan, rundir, timing
from harness import standards as STD
from harness.checks import Checks


def judge(run: Path, tmp_path: Path):
    led = ledgers.write(tmp_path / "l.yaml", ledgers.POSTURE)
    passed, report = gate.judge(run, led)
    return passed, {c["id"]: c for c in report["blocking"]}, report


def _edit(path: Path, fn) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    fn(data)
    path.write_text(json.dumps(data), encoding="utf-8")


def _all_checks(report) -> dict:
    return {c["id"]: c for c in report["checks"]}


# ------------------------------------------------------------------------------- major 1: compare before NOT-JUDGED
def _unverify(fr: FakeRun, keys: list[str], oid: str = "z01/certificate") -> None:
    _edit(fr.dir / "lab/selfcheck.json", lambda d: d["targets"][0].__setitem__("unverified_keys", {oid: keys}))


def test_unverified_key_agreeing_is_not_judged_with_the_products_value(tmp_path):
    fr = FakeRun(tmp_path)
    fr.write()
    _unverify(fr, ["algorithm", "key_size"])
    _, blocking, _ = judge(fr.dir, tmp_path)
    for key, value in (("algorithm", "EC"), ("key_size", 256)):  # R15: every listed key, not only the first
        check = blocking[f"G11/oracle/run1/z01/certificate/{key}"]
        assert (check["verdict"], check["reason"], check["observed"]) == ("NOT-JUDGED", "lab-not-independent", value)


def test_unverified_key_disagreeing_fails(tmp_path):
    """5c / N4: the product's value differs from the lab's (unverified) value in every view -> FAIL, never NOT-JUDGED."""
    fr = FakeRun(tmp_path)
    fr.write()
    _unverify(fr, ["not_after"])
    for view in ("api/assets-run1.json",):
        _edit(fr.dir / view, lambda d: d["items"][0]["facts"].__setitem__("not_after", "2026-11-12T08:00:00Z"))
    _, blocking, _ = judge(fr.dir, tmp_path)
    check = blocking["G11/oracle/run1/z01/certificate/not_after"]
    assert (check["verdict"], check["reason"]) == ("FAIL", "disagrees-with-unverified-lab")
    assert check["observed"] == "2026-11-12T08:00:00Z"


def test_unverified_sampled_key_fails_on_a_suite_the_lab_never_listed(tmp_path):
    fr = FakeRun(tmp_path)
    fr.write()
    _unverify(fr, ["cipher_suites"], "z01/tls_endpoint")
    _, blocking, _ = judge(fr.dir, tmp_path)
    assert blocking["G11/oracle/run1/z01/tls_endpoint/cipher_suites"]["verdict"] == "NOT-JUDGED"
    _edit(fr.dir / "api/assets-run1.json", lambda d: d["items"][1]["facts"].__setitem__(
        "ciphers", ["TLS_RSA_WITH_RC4_128_MD5"]))
    _, blocking, _ = judge(fr.dir, tmp_path)
    assert blocking["G11/oracle/run1/z01/tls_endpoint/cipher_suites"]["reason"] == "disagrees-with-unverified-lab"


def test_derived_suite_from_unverified_list_is_compared_and_tls13_still_judged(tmp_path):
    """N3: the suite list is unverified, but the endpoint's TLSv1.3-only versions are: the negotiated suite must be one
    of RFC 8446's five whatever the lab listed."""
    fr = FakeRun(tmp_path)
    fr.write()
    _edit(fr.dir / "oracle/run1.json", lambda d: (d["targets"][0]["assets"][1]["expect"].pop("algorithm", None),
                                                  d["targets"][0]["assets"][1]["expect"].__setitem__(
                                                      "cipher_suites", ["TLS_AES_256_GCM_SHA384",
                                                                        "TLS_RSA_WITH_AES_128_CBC_SHA"])))
    manifest.freeze_oracle(fr.dir)
    _unverify(fr, ["cipher_suites"], "z01/tls_endpoint")
    _, blocking, report = judge(fr.dir, tmp_path)
    checks = _all_checks(report)
    assert checks["G11/oracle/run1/z01/tls_endpoint/algorithm"]["verdict"] == "NOT-JUDGED"
    assert checks["G11/oracle/run1/z01/tls_endpoint/algorithm/tls13_suite"]["verdict"] == "PASS"
    # the product reports a suite the (wrong) lab list holds but TLS 1.3 cannot negotiate
    _edit(fr.dir / "api/assets-run1.json", lambda d: d["items"][1].__setitem__("algorithm", "TLS_RSA_WITH_AES_128_CBC_SHA"))
    _, blocking, _ = judge(fr.dir, tmp_path)
    assert blocking["G11/oracle/run1/z01/tls_endpoint/algorithm/tls13_suite"]["reason"] == "wrong-value"
    assert "G11/oracle/run1/z01/tls_endpoint/algorithm" in blocking  # NOT-JUDGED, still blocking unless ledgered
    # and a suite the lab never listed fails the derived check itself
    _edit(fr.dir / "api/assets-run1.json", lambda d: d["items"][1].__setitem__("algorithm", "TLS_RSA_WITH_RC4_128_MD5"))
    _, blocking, _ = judge(fr.dir, tmp_path)
    assert blocking["G11/oracle/run1/z01/tls_endpoint/algorithm"]["reason"] == "disagrees-with-unverified-lab"


# ------------------------------------------------------------------------- major 2: codes and impact on weaknesses
def test_codes_and_impact_are_judged_where_the_lab_states_them(tmp_path):
    """N12 / N12b: an expired certificate or a TLS 1.0 endpoint that is no longer flagged fails."""
    fr = FakeRun(tmp_path)
    fr.write()
    _, blocking, _ = judge(fr.dir, tmp_path)
    assert not [b for b in blocking if "/oracle/" in b]
    _edit(fr.dir / "api/assets-run1.json", lambda d: d["items"][2].update(impact="Low", finding_codes=["QUANTUM_VULNERABLE"]))
    _, blocking, _ = judge(fr.dir, tmp_path)
    assert blocking["G11/oracle/run1/z02/certificate/code/CERT_SELF_SIGNED"]["reason"] == "code-missing"
    assert blocking["G11/oracle/run1/z02/certificate/impact_min"]["reason"] == "impact-too-low"
    assert blocking["G11/oracle/run1/z02/certificate/impact_min"]["observed"] == "Low"


def test_unstated_codes_and_impact_are_not_run_with_the_shown_value(tmp_path):
    """The lab's silence is named (NOT-RUN no-expectation) and carries what the customer was shown, so a pinned row
    moves when the product stops flagging a weakness the lab did not name."""
    fr = FakeRun(tmp_path)
    fr.write()
    _edit(fr.dir / "oracle/run1.json", lambda d: [a.update(codes_include=[], impact_min=None, impact_max=None)
                                                  for a in d["targets"][1]["assets"]])
    manifest.freeze_oracle(fr.dir)
    _, blocking, _ = judge(fr.dir, tmp_path)
    codes, impact = blocking["G11/oracle/run1/z02/certificate/finding_codes"], blocking["G11/oracle/run1/z02/certificate/impact"]
    assert (codes["verdict"], codes["reason"], codes["observed"]) == ("NOT-RUN", "no-expectation",
                                                                      ["CERT_SELF_SIGNED", "QUANTUM_VULNERABLE"])
    assert (impact["verdict"], impact["observed"]) == ("NOT-RUN", "High")
    led = ledgers.pinned(fr.dir, tmp_path / "p.yaml", ledgers.POSTURE, ledgers.NOVERDICT)
    assert gate.judge(fr.dir, led)[0]
    _edit(fr.dir / "api/assets-run1.json", lambda d: d["items"][2].update(impact=None, finding_codes=["QUANTUM_VULNERABLE"]))
    passed, report = gate.judge(fr.dir, led)
    row = {r["row"]: r for r in report["ledger"]}["NOVERDICT"]
    assert not passed and row["status"] == "moved" and len(row["unexpected"]) == 2


@pytest.mark.parametrize("impact, ok", [("Critical", True), ("High", True), ("Medium", False), (None, False)])
def test_impact_min(tmp_path, impact, ok):
    fr = FakeRun(tmp_path)
    fr.write()
    _edit(fr.dir / "api/assets-run1.json", lambda d: d["items"][2].__setitem__("impact", impact))
    _, _, report = judge(fr.dir, tmp_path)
    assert _all_checks(report)["G11/oracle/run1/z02/certificate/impact_min"]["verdict"] == ("PASS" if ok else "FAIL")


# ------------------------------------------------------------------------------- major 3: identities, not counts
def test_identity_normalises_run_specific_values_and_keeps_the_rest(tmp_path):
    run = FakeRun(tmp_path).write()
    maps = identity.id_maps(run)
    assert maps["asset"]["101"] == "certificate@10.231.0.17:443"
    assert identity.normalise_id("G11/join/run1/asset/101/key_size/export", maps) == \
        "G11/join/run1/asset/certificate@10.231.0.17:443/key_size/export"
    assert identity.normalise_id("G11/oracle/run1/z01/extra/103", maps) == "G11/oracle/run1/z01/extra/certificate@10.231.0.18:443"
    # lab dates relative to the oracle's generated_at (2026-11-12T08:59:00Z), digests, fingerprints, lab run ids
    assert identity.normalise_value("2027-11-12T08:59:00Z", maps) == "gen+365d"
    assert identity.normalise_value("2026-11-11T08:59:30Z", maps) == "gen-0d86370s"
    assert identity.normalise_value("expired on 2025-10-08", maps) == "expired on gen-400d32340s"
    assert identity.normalise_value({"fp": "ab" * 32, "ssh": "SHA256:" + "A" * 43}, maps) == {"fp": "<hex:64>",
                                                                                             "ssh": "<ssh-fp>"}
    assert identity.normalise_value("CN=CA lab-20261112T152145Z", maps) == "CN=CA lab-<run>"
    assert identity.normalise_value(["TLSv1.2", 1024, None, True], maps) == ["TLSv1.2", 1024, None, True]
    assert identity.normalise_value(900, maps, "job_id") == "job?"


# ------------------------------------------------------------------------------- standards (minor; R10, R11)
@pytest.mark.parametrize("group", sorted(STD.TLS_GROUPS_PQ))
def test_every_iana_pq_group_is_pq(group):
    assert STD.tls_group_class(group) == "pq" and STD.kex_quantum_vulnerable([group], "tls") is False


@pytest.mark.parametrize("group", sorted(STD.TLS_GROUPS_CLASSICAL))
def test_every_iana_classical_group_is_classical(group):
    assert STD.tls_group_class(group) == "classical" and STD.kex_quantum_vulnerable([group], "tls") is True


@pytest.mark.parametrize("kex", sorted(STD.SSH_KEX_PQ))
def test_every_pq_ssh_kex_is_pq(kex):
    assert STD.ssh_kex_class(kex) == "pq" and STD.kex_quantum_vulnerable([kex], "ssh") is False


@pytest.mark.parametrize("kex", sorted(STD.SSH_KEX_CLASSICAL) + ["ecdh-sha2-1.3.132.0.10", "gss-group14-sha256-toWM5Slw5Ew8Mqkay+al2g=="])
def test_every_classical_ssh_kex_is_classical(kex):
    assert STD.ssh_kex_class(kex) == "classical" and STD.kex_quantum_vulnerable([kex], "ssh") is True


def test_the_tables_are_closed_and_transcribed_in_full():
    """N1b: MLKEM1024X448 (IANA 4591) used to read as classical; an unknown name is now 'not derived'."""
    assert len(STD.TLS_GROUPS_PQ) == 12 and len(STD.TLS_GROUPS_CLASSICAL) == 51
    assert {"SecP256r1MLKEM512", "MLKEM512X25519", "curveSM2MLKEM768", "MLKEM1024X448",
            "SecP256r1Kyber768Draft00"} <= STD.TLS_GROUPS_PQ
    assert {"mlkem768nistp256-sha256", "mlkem1024nistp384-sha384"} <= STD.SSH_KEX_PQ
    assert STD.kex_quantum_vulnerable(["x25519", "made-up-group"], "tls") is None
    assert STD.kex_quantum_vulnerable(["made-up-kex"], "ssh") is None
    assert STD.tls_group_class("X25519Kyber768Draft00 (OBSOLETE)") == "pq" and STD.tls_group_class("X25519") == "classical"
    assert STD.tls_group_class("<NULL>") is None


@pytest.mark.parametrize("suite, cls", [("TLS_RSA_WITH_AES_128_CBC_SHA", {"static-rsa", "cbc"}),
                                        ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", {"static-rsa", "cbc", "3des"}),
                                        ("TLS_RSA_WITH_RC4_128_MD5", {"static-rsa", "rc4"}),
                                        ("TLS_RSA_WITH_NULL_SHA", {"static-rsa", "null"}),
                                        ("TLS_RSA_EXPORT_WITH_RC4_40_MD5", {"rc4", "export"}),
                                        ("TLS_AES_128_GCM_SHA256", set())])
def test_weak_suite_class_per_entry(suite, cls):
    assert STD.classes_present([suite], STD.WEAK_SUITE_CLASSES) == cls


def test_rfc8446_suites():
    assert STD.TLS13_SUITES == {"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
                                "TLS_AES_128_CCM_SHA256", "TLS_AES_128_CCM_8_SHA256"}


# ------------------------------------------------------------------------------- never-scan re-derived (minor)
def _scoped(fr: FakeRun, canary_lines: list[dict] | None, control_lines: list[dict] | None):
    run = fr.dir
    (run / "flow-state.json").write_text(json.dumps({
        "scope": {"sources": ["S-zoo"], "ranges": ["10.231.0.16/28", "10.231.0.32/30"]},
        "node": {"addresses": ["10.231.0.2"]}, "g9_start": "2026-11-12T08:59:00Z"}))
    (run / "lab").mkdir(exist_ok=True)
    (run / "lab" / "lab.json").write_text(json.dumps({"listeners": [
        {"name": "canary", "role": "canary", "address": "10.231.0.33", "log": "lab/listeners/canary.jsonl"},
        {"name": "control", "role": "control", "address": "10.231.0.34", "log": "lab/listeners/control.jsonl"},
        {"name": "idn-fass", "role": "canary", "address": "10.231.0.44", "log": "lab/listeners/idn-fass.jsonl"}]}))
    (run / "lab" / "listeners").mkdir(exist_ok=True)
    for name, lines in (("canary", canary_lines), ("control", control_lines)):
        if lines is not None:
            (run / "lab" / "listeners" / f"{name}.jsonl").write_text("".join(json.dumps(x) + "\n" for x in lines))


def _nv(run: Path) -> dict:
    checks = Checks()
    neverscan.judge(run, checks)
    return {c.id: c for c in checks}


PROBE = {"ts": "2026-11-12T09:00:40Z", "peer": "10.231.0.1:40618", "local": "10.231.0.33:443"}
NODE_CTL = {"ts": "2026-11-12T08:59:20Z", "peer": "10.231.0.2:43426", "local": "10.231.0.34:443"}


def test_neverscan_is_rederived_from_the_whole_sealed_log(tmp_path):
    fr = FakeRun(tmp_path)
    fr.write()
    _scoped(fr, [PROBE], [NODE_CTL])
    got = _nv(fr.dir)
    assert {k: v.verdict for k, v in got.items()} == {"G10/sealed/canary_accepts/canary": "PASS",
                                                      "G10/sealed/canary_log_path/canary": "PASS",
                                                      "G10/sealed/control_accepts/control": "PASS"}
    # N11: a node connection after the flow's G10 count, in the sealed file
    late = {"ts": "2026-11-12T09:05:00Z", "peer": "10.231.0.2:40100", "local": "10.231.0.33:443"}
    _scoped(fr, [PROBE, late], [NODE_CTL])
    assert _nv(fr.dir)["G10/sealed/canary_accepts/canary"].reason == "never-scan-reached"
    # a node connection before Start is not the scan's (CB-05's G4 test), another peer is not the node's
    _scoped(fr, [PROBE, {**late, "ts": "2026-11-12T08:50:00Z"}, {**late, "peer": "10.231.0.9:1"}], [NODE_CTL])
    assert _nv(fr.dir)["G10/sealed/canary_accepts/canary"].verdict == "PASS"


def test_neverscan_missing_listener_log_fails(tmp_path):
    """N11b: a canary log missing from the bundle is FAIL(listener-log-missing), never zero."""
    fr = FakeRun(tmp_path)
    fr.write()
    _scoped(fr, None, None)
    got = _nv(fr.dir)
    assert {got[k].reason for k in got} == {"listener-log-missing"} and len(got) == 3
    _scoped(fr, [], [NODE_CTL])  # present but no probe line: the log path is not proven
    assert _nv(fr.dir)["G10/sealed/canary_log_path/canary"].reason == "log-path"
    _scoped(fr, [PROBE], [])  # the control never reached: the zero proves nothing
    assert _nv(fr.dir)["G10/sealed/control_accepts/control"].reason == "control-not-reached"


# ------------------------------------------------------------------------------- timing (minor; R1-R4)
def _db_created(fr: FakeRun, value: str) -> None:
    path = fr.dir / "db" / "assets.csv"
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    rows[0]["created_at"] = value
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


@pytest.mark.parametrize("created, ok", [
    ("2026-11-12 08:58:01", True),    # inside the 120 s slack before G9 start (08:59:00)
    ("2026-11-12 08:56:59", False),   # R2: 121 s before Start
    ("2026-11-12 08:49:00", False),   # N9: ten minutes before Start
    ("2026-11-12 09:02:30", True),    # G10 end 09:00:30 + 120 s
    ("2026-11-12 09:10:30", False),   # R1: after G10 end + slack
])
def test_db_rows_window_bounds(tmp_path, created, ok):
    fr = FakeRun(tmp_path)
    fr.write()
    _db_created(fr, created)
    _, _, report = judge(fr.dir, tmp_path)
    assert _all_checks(report)["G11/db_created_in_run_window/run1"]["verdict"] == ("PASS" if ok else "FAIL")


def test_db_window_without_rows_is_not_run(tmp_path):
    fr = FakeRun(tmp_path)
    fr.write()
    path = fr.dir / "db" / "assets.csv"
    path.write_text(path.read_text().splitlines()[0] + "\n")
    checks = Checks()
    timing.judge(fr.dir, "1", checks)
    assert checks.get("G11/db_created_in_run_window/run1").verdict == "NOT-RUN"


@pytest.mark.parametrize("ts, ok", [("2026-11-12T09:01:00Z", True), ("2026-11-12T09:13:00Z", False),
                                    ("2026-11-12T08:40:00Z", False)])
def test_export_timestamp_has_an_upper_bound(tmp_path, ts, ok):
    """R3: an export stamped after the run (same UTC day) used to pass."""
    fr = FakeRun(tmp_path)
    fr.write()
    _edit(fr.dir / "exports/run1.cdx.json", lambda d: d["metadata"].__setitem__("timestamp", ts))
    _, _, report = judge(fr.dir, tmp_path)
    assert _all_checks(report)["G12/timestamps_on_run_day/run1"]["verdict"] == ("PASS" if ok else "FAIL")


@pytest.mark.parametrize("serial, ok", [
    ("urn:uuid:3f6c2a1e-8b4d-4c7a-9e21-5d0b7a6c4f13", True),
    ("urn:uuid:00000000-0000-0000-0000-000000000000", False),   # N9c
    ("urn:uuid:abc", False),                                     # R4
    ("urn:uuid:3f6c2a1e-8b4d-0c7a-9e21-5d0b7a6c4f13", False),   # version 0
    ("urn:uuid:3f6c2a1e-8b4d-4c7a-7e21-5d0b7a6c4f13", False),   # not the RFC 4122 variant
    ("3f6c2a1e-8b4d-4c7a-9e21-5d0b7a6c4f13", False),
])
def test_serial_number_is_an_rfc4122_urn(tmp_path, serial, ok):
    fr = FakeRun(tmp_path)
    fr.write()
    _edit(fr.dir / "exports/run1.cdx.json", lambda d: d.__setitem__("serialNumber", serial))
    _, _, report = judge(fr.dir, tmp_path)
    assert _all_checks(report)["G12/serial_number/run1"]["verdict"] == ("PASS" if ok else "FAIL")


def test_serial_number_differs_between_runs_and_from_sibling_bundles_of_the_team(tmp_path):
    fr = FakeRun(tmp_path / "a")
    run = fr.write()
    (run / "exports" / "run2.cdx.json").write_text((run / "exports" / "run1.cdx.json").read_text())
    checks = Checks()
    timing.judge(run, "1", checks)
    assert checks.get("G12/serial_number/run1").reason == "serial-not-unique"
    (run / "exports" / "run2.cdx.json").unlink()
    other = tmp_path / "a" / "L-other"
    other.mkdir()
    serial = json.loads((run / "exports/run1.cdx.json").read_text())["serialNumber"]
    (other / "MANIFEST.json").write_text(json.dumps({"teams": {"A": fr.team}, "runs": [77], "serialNumbers": {"1": serial}}))
    checks = Checks()
    timing.judge(run, "1", checks)
    assert "bundle L-other" in str(checks.get("G12/serial_number/run1").observed)
    # the same product run downloaded again (same run id) is the same BOM, not a duplicate
    (other / "MANIFEST.json").write_text(json.dumps({"teams": {"A": fr.team}, "runs": [fr.run_id], "serialNumbers": {"1": serial}}))
    checks = Checks()
    timing.judge(run, "1", checks)
    assert checks.get("G12/serial_number/run1").verdict == "PASS"


def test_run_record_dates_are_judged(tmp_path):
    """N9b: the run's own record (API run document, DB runs/jobs) dated a year back used to pass."""
    fr = FakeRun(tmp_path)
    fr.write()
    _, _, report = judge(fr.dir, tmp_path)
    assert _all_checks(report)["G11/run_record_in_run_window/run1"]["verdict"] == "PASS"
    _edit(fr.dir / f"api/run-{fr.run_id}.json", lambda d: d["run"].__setitem__("finished_at", "2025-11-12T09:00:20Z"))
    _, blocking, _ = judge(fr.dir, tmp_path)
    assert list(blocking["G11/run_record_in_run_window/run1"]["observed"]) == ["api.run.finished_at"]


# ------------------------------------------------------------------------------- logs, join, rundir (R5-R8, N10)
def test_a_job_that_stored_one_asset_needs_its_stored_line(tmp_path):
    """R5: the positive control holds for a job with exactly one asset (run 6's R-canary job)."""
    fr = FakeRun(tmp_path)
    fr.write()
    path = fr.dir / "db" / "jobs.csv"
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    rows.append({**rows[0], "id": "901", "asset_count": "1"})
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    checks = Checks()
    logs.judge(fr.dir, checks, [fr.team])
    assert checks.get("G16/assets-stored/job-901-logged").reason == "assets-stored-line-missing"


def test_ui_total_compares_the_db_row_count(tmp_path):
    """R6: the header equals the API's total, but the DB holds a row more for the run."""
    fr = FakeRun(tmp_path)
    fr.write()
    path = fr.dir / "db" / "assets.csv"
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    rows.append({**rows[0], "id": "999"})
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    _, blocking, _ = judge(fr.dir, tmp_path)
    assert blocking["G11/join/run1/ui_total"]["expected"]["db_rows"] == 4


@pytest.mark.parametrize("text, total", [("3 assets found", 3), ("1,204 assets found", 1204), ("3 of 4 assets found", None),
                                         ("no assets", None)])
def test_ui_header_needs_exactly_one_number(tmp_path, text, total):
    """N10: '25 of 26 assets found' claims an asset the table does not show."""
    fr = FakeRun(tmp_path)
    fr.write()
    _edit(fr.dir / "ui/assets-run1.json", lambda d: d.__setitem__("total_text", text))
    assert join.ui_header_total(fr.dir, "1") == total


def test_db_rows_of_other_runs_never_join_this_run(tmp_path):
    """R8: the DB export holds every run of the team; only this run's rows are its DB view."""
    fr = FakeRun(tmp_path)
    fr.write()
    path = fr.dir / "db" / "assets.csv"
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    rows.append({**rows[0], "id": "777", "run_id": str(fr.run_id - 1)})
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    assert 777 not in join.load_views(fr.dir, "1")["db"]
    passed, blocking, _ = judge(fr.dir, tmp_path)
    assert passed, sorted(blocking)


def test_runs_the_flow_started_are_judged_even_without_files(tmp_path):
    """R7 (m4's flow-state branch): a second run the flow started with no oracle or API capture is still a run."""
    fr = FakeRun(tmp_path)
    run = fr.write()
    (run / "flow-state.json").write_text(json.dumps({"runs": [55, 56]}))
    assert rundir.run_steps(run) == ["1", "2"]


def test_negative_cases_name_their_intended_check():
    from harness import negative
    assert set(negative.INTENDED) == set(negative.WRONG) and len(negative.WRONG) == 47
    report = {"blocking": [{"id": "G11/oracle/run1/z04/cert[0]/code/CERT_EXPIRED", "reason": "code-missing"}], "ledger": []}
    assert negative.intended_hit("N12_expired_cert_not_flagged", report)
    report = {"blocking": [{"id": "G11/join/run1/ui", "reason": "x"}],
              "ledger": [{"row": "R", "status": "moved", "unexpected": [{"id": "G11/oracle/run1/z04/cert[0]/finding_codes"}],
                          "missing": []}]}
    assert negative.intended_hit("N12_expired_cert_not_flagged", report).startswith("row R moved")
    assert negative.intended_hit("N11_canary_hit_after_g10", report) is None
