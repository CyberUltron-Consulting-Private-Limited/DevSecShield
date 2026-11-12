"""Controls added for review 5874859738: each test fails on a defect the reviewer showed the gate let through, or on
a one-line mutant of the judge that the earlier suite did not kill (round6/rv-75-notes/mutants.txt)."""
from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

import ledgers
from fakerun import FakeRun
from harness import derived, gate, join, logs, manifest, oracle
from harness.checks import Checks


def judge(run: Path, tmp_path: Path):
    led = ledgers.write(tmp_path / "l.yaml", ledgers.POSTURE)
    passed, report = gate.judge(run, led)
    return passed, {c["id"]: c for c in report["blocking"]}, report


def _edit(path: Path, fn) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    fn(data)
    path.write_text(json.dumps(data), encoding="utf-8")


def _db_rows(run: Path):
    path = run / "db" / "assets.csv"
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    return path, rows


def _write_db(path: Path, rows) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def _add_everywhere(fr: FakeRun, spec: dict) -> None:
    run = fr.dir
    _edit(run / "api/assets-run1.json", lambda d: (d["items"].append(fr.api_item(spec)),
                                                    d.__setitem__("all_total", d["all_total"] + 1)))
    path, rows = _db_rows(run)
    rows.append({k: str(v) for k, v in fr.db_row(spec).items()})
    _write_db(path, rows)
    _edit(run / "exports/run1.cdx.json", lambda d: d["components"].append(fr.component(spec)))
    _edit(run / "ui/assets-run1.json", lambda d: (d["rows"].append(fr.ui_row(spec)),
                                                   d.__setitem__("total_text", f"{len(d['rows'])} assets")))


# ------------------------------------------------------------------------------------------- oracle (majors 1-3)
def test_an_asset_no_target_claims_fails_unattributed(tmp_path):
    """major 1 / wrong CBOMs 4, 4b: a fabricated asset outside every target used to pass."""
    fr = FakeRun(tmp_path)
    fr.write()
    _add_everywhere(fr, dict(fr.assets[1], id=104, target="203.0.113.7", location="203.0.113.7:443"))
    passed, blocking, _ = judge(fr.dir, tmp_path)
    assert not passed and blocking["G11/oracle/run1/unattributed/104"]["reason"] == "unattributed"


def test_declared_empty_address_claims_exactly_one_coverage_row(tmp_path):
    """v7 §A.1: an address the lab declares empty must carry one coverage row and nothing else."""
    fr = FakeRun(tmp_path)
    fr.write()
    cov = dict(fr.assets[1], id=105, type="coverage", cdx="algorithm", target="10.231.0.27",
               location="10.231.0.27#no answer", algorithm=None, protocol=None, qv=None, impact=None, codes=[],
               finding="no answer", facts={"check": "no answer"})
    _add_everywhere(fr, cov)
    _edit(fr.dir / "oracle/run1.json", lambda d: d.__setitem__("ranges", [
        {"source": "S-zoo", "cidr": "10.231.0.16/28", "empty_addresses": ["10.231.0.27"]}]))
    manifest.freeze_oracle(fr.dir)
    passed, blocking, report = judge(fr.dir, tmp_path)
    ids = {c["id"]: c["verdict"] for c in report["checks"]}
    assert ids["G11/oracle/run1/empty/10.231.0.27"] == "PASS" and "G11/oracle/run1/unattributed/105" not in ids
    # a second, fabricated asset at the empty address fails the declaration
    _add_everywhere(fr, dict(fr.assets[1], id=106, target="10.231.0.27", location="10.231.0.27:443"))
    passed, blocking, _ = judge(fr.dir, tmp_path)
    assert blocking["G11/oracle/run1/empty/10.231.0.27"]["reason"] == "empty-address"


def test_closed_world_extra_fails(tmp_path):
    """kills mutant O1 (closed-world extras never fail)."""
    fr = FakeRun(tmp_path)
    fr.write()
    _add_everywhere(fr, dict(fr.assets[1], id=107, location="10.231.0.17:8443"))
    passed, blocking, _ = judge(fr.dir, tmp_path)
    assert blocking["G11/oracle/run1/z01/extra/107"]["reason"] == "extra"


def test_asset_type_is_part_of_the_match(tmp_path):
    """kills mutant O6: a TLS endpoint must not stand in for the certificate at the same location."""
    fr = FakeRun(tmp_path)
    fr.write()
    _edit(fr.dir / "oracle/run1.json", lambda d: d["targets"][0]["assets"].reverse())
    manifest.freeze_oracle(fr.dir)
    path, rows = _db_rows(fr.dir)
    passed, blocking, report = judge(fr.dir, tmp_path)
    present = {c["id"]: c["subject"].get("asset_id") for c in report["checks"] if c["id"].endswith("/present")}
    assert present["G11/oracle/run1/z01/certificate/present"] == 101
    assert present["G11/oracle/run1/z01/tls_endpoint/present"] == 102


@pytest.mark.parametrize("flip, oid", [("tls", "z01/tls_endpoint")])
def test_endpoint_quantum_verdict_is_derived_from_the_oracles_groups(tmp_path, flip, oid):
    """major 2 / wrong CBOMs 3b, 3c: the oracle states groups but no verdict; a flipped verdict must fail."""
    fr = FakeRun(tmp_path)
    fr.write()
    _edit(fr.dir / "oracle/run1.json",
          lambda d: d["targets"][0]["assets"][1]["expect"].pop("quantum_vulnerable"))
    manifest.freeze_oracle(fr.dir)
    passed, _, report = judge(fr.dir, tmp_path)
    check = next(c for c in report["checks"] if c["id"] == f"G11/oracle/run1/{oid}/quantum_vulnerable")
    assert check["verdict"] == "PASS" and check["subject"]["expectation"] == "derived"
    _edit(fr.dir / "api/assets-run1.json", lambda d: d["items"][1].__setitem__("quantum_vulnerable", False))
    passed, blocking, _ = judge(fr.dir, tmp_path)
    assert blocking[f"G11/oracle/run1/{oid}/quantum_vulnerable"]["reason"] == "wrong-value"


def test_unstated_visible_field_is_not_run_no_expectation(tmp_path):
    """major 2: a field the customer sees and the oracle does not state is named, so the ledger must list it."""
    fr = FakeRun(tmp_path)
    fr.write()
    _edit(fr.dir / "oracle/run1.json", lambda d: d["targets"][1]["assets"][0]["expect"].pop("algorithm"))
    manifest.freeze_oracle(fr.dir)
    passed, blocking, _ = judge(fr.dir, tmp_path)
    assert blocking["G11/oracle/run1/z02/certificate/algorithm"]["verdict"] == "NOT-RUN"
    assert blocking["G11/oracle/run1/z02/certificate/algorithm"]["reason"] == "no-expectation"


def test_sampled_suites_need_must_report_and_are_judged_exactly(tmp_path):
    """major 3 / wrong CBOM 8 / mutant O3: reporting only the negotiated suite drops the planted weak classes."""
    fr = FakeRun(tmp_path)
    fr.write()
    accepted = ["TLS_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_128_CBC_SHA"]
    _edit(fr.dir / "oracle/run1.json",
          lambda d: d["targets"][0]["assets"][1]["expect"].__setitem__("cipher_suites", accepted))
    manifest.freeze_oracle(fr.dir)
    passed, blocking, _ = judge(fr.dir, tmp_path)
    assert blocking["G11/oracle/run1/z01/tls_endpoint/cipher_suites/must_report"]["reason"] == "must-report-missing"
    assert blocking["G11/oracle/run1/z01/tls_endpoint/cipher_suites/complete"]["reason"] == "sample-not-enumeration"
    assert "G11/oracle/run1/z01/tls_endpoint/cipher_suites" not in blocking  # what it reports is accepted
    # a suite the server does not accept fails the subset rule (O3)
    _edit(fr.dir / "api/assets-run1.json", lambda d: d["items"][1]["facts"].__setitem__("ciphers", ["RC4-MD5"]))
    passed, blocking, _ = judge(fr.dir, tmp_path)
    assert blocking["G11/oracle/run1/z01/tls_endpoint/cipher_suites"]["reason"] == "not-accepted-by-server"


def test_lab_must_report_list_wins_over_the_class_rule(tmp_path):
    fr = FakeRun(tmp_path)
    fr.write()
    _edit(fr.dir / "oracle/run1.json", lambda d: d["targets"][0]["assets"][1].__setitem__(
        "must_report", {"groups": ["secp256r1", "X25519"]}))
    manifest.freeze_oracle(fr.dir)
    passed, _, report = judge(fr.dir, tmp_path)
    assert next(c for c in report["checks"]
                if c["id"] == "G11/oracle/run1/z01/tls_endpoint/groups/must_report")["verdict"] == "PASS"


def test_not_independent_selfcheck_key_is_not_judged(tmp_path):
    """m5: a key whose only self-check shares code with the prober is NOT-JUDGED, never a product pass."""
    fr = FakeRun(tmp_path)
    fr.write()
    _edit(fr.dir / "lab/selfcheck.json", lambda d: d["targets"][0].__setitem__("checks", [
        {"oracle_id": "z01/certificate", "key": "fingerprint_sha256 (served chain)", "agree": True,
         "independent": False}, {"oracle_id": "z01/certificate", "key": "algorithm", "agree": True,
                                 "independent": False}]))
    passed, blocking, _ = judge(fr.dir, tmp_path)
    assert blocking["G11/oracle/run1/z01/certificate/algorithm"]["verdict"] == "NOT-JUDGED"
    assert blocking["G11/oracle/run1/z01/certificate/algorithm"]["reason"] == "lab-not-independent"


def test_contradicting_discriminator_is_reported_missing(tmp_path):
    """nit: a candidate whose fingerprint contradicts the oracle is not paired (diagnosis: missing, not wrong-value)."""
    fr = FakeRun(tmp_path)
    fr.write()
    _edit(fr.dir / "oracle/run1.json", lambda d: d["targets"][1]["assets"][0]["expect"].__setitem__(
        "fingerprint_sha256", "cc" * 32))
    _edit(fr.dir / "api/assets-run1.json", lambda d: d["items"][2]["facts"].__setitem__("fingerprint_sha256", "dd" * 32))
    manifest.freeze_oracle(fr.dir)
    passed, blocking, _ = judge(fr.dir, tmp_path)
    assert blocking["G11/oracle/run1/z02/certificate/present"]["reason"] == "missing"


# --------------------------------------------------------------------------------------------------- join (m1)
def test_ui_total_and_duplicates_are_judged(tmp_path):
    """m1 / wrong CBOMs 6, 6b, 7 / mutant J2."""
    fr = FakeRun(tmp_path)
    fr.write()
    _edit(fr.dir / "ui/assets-run1.json", lambda d: d.__setitem__("total_text", "4 assets"))
    passed, blocking, _ = judge(fr.dir, tmp_path)
    assert blocking["G11/join/run1/ui_total"]["reason"] == "count-mismatch"
    fr.write()
    _edit(fr.dir / "ui/assets-run1.json", lambda d: d["rows"].append(dict(d["rows"][0])))
    passed, blocking, _ = judge(fr.dir, tmp_path)
    assert blocking["G11/join/run1/duplicates/ui"]["reason"] == "duplicate-in-ui"
    assert blocking["G11/join/run1/count/ui"]["reason"] == "count-mismatch"


def test_extra_row_only_in_the_export_is_counted(tmp_path):
    """mutant J2: a row only the export has fails presence and the count."""
    fr = FakeRun(tmp_path)
    fr.write()
    _edit(fr.dir / "exports/run1.cdx.json", lambda d: d["components"].append({**d["components"][0],
                                                                              "bom-ref": "zs-asset-999"}))
    passed, blocking, _ = judge(fr.dir, tmp_path)
    assert blocking["G11/join/run1/count/export"]["reason"] == "count-mismatch"
    assert blocking["G11/join/run1/asset/999/presence/export"]["reason"] == "extra-in-export"


def test_key_size_and_protocol_versions_are_compared_exactly_across_views(tmp_path):
    """kills F1 (key_size equal everywhere) and F2 (protocol versions judged as a sample)."""
    fr = FakeRun(tmp_path)
    fr.write()
    path, rows = _db_rows(fr.dir)
    rows[2]["key_size"] = "2048"
    _write_db(path, rows)
    passed, blocking, _ = judge(fr.dir, tmp_path)
    assert blocking["G11/join/run1/asset/103/key_size/db"]["reason"] == "mismatch"
    fr.write()
    _edit(fr.dir / "oracle/run1.json", lambda d: d["targets"][0]["assets"][1]["expect"].__setitem__(
        "protocol_versions", ["TLSv1.2", "TLSv1.3"]))
    manifest.freeze_oracle(fr.dir)
    passed, blocking, _ = judge(fr.dir, tmp_path)
    assert blocking["G11/oracle/run1/z01/tls_endpoint/protocol_versions"]["reason"] == "wrong-value"


def test_coverage_row_exported_as_a_gap_counts_as_present(tmp_path):
    """CB-06 v1 §4: coverage rows move from components to metadata zs:coverage_gap."""
    fr = FakeRun(tmp_path)
    fr.write()
    run = fr.dir
    cov = dict(fr.assets[1], id=108, type="coverage", cdx="algorithm", target="10.231.0.17",
               location="10.231.0.17#no answer", algorithm=None, protocol=None, qv=None, impact=None, codes=[],
               finding="no answer", facts={"check": "no answer"})
    _add_everywhere(fr, cov)

    def to_gap(d):
        d["components"] = [c for c in d["components"] if c["bom-ref"] != "zs-asset-108"]
        d["metadata"]["properties"].append({"name": "zs:coverage_gap", "value": json.dumps(
            {"ref": "zs-asset-108", "location": "10.231.0.17#no answer", "target": "10.231.0.17"})})
    _edit(run / "exports/run1.cdx.json", to_gap)
    views = join.load_views(run, "1")
    assert 108 in views["export"]
    checks = Checks()
    join.join(run, "1", checks)
    assert not [c.id for c in checks if c.verdict == "FAIL" and "/108/" in c.id]


# -------------------------------------------------------------------------------------------- derived (D1-D3)
@pytest.mark.parametrize("edit, cid", [
    (lambda d: d["facets"]["type"].__setitem__("certificate", 9), "G11/derived/run1/by_type"),
    (lambda d: d.__setitem__("all_total", 9), "G11/derived/run1/total"),
])
def test_derived_facets_are_checked(tmp_path, edit, cid):
    fr = FakeRun(tmp_path)
    fr.write()
    _edit(fr.dir / "api/assets-run1.json", edit)
    checks = Checks()
    derived.judge(fr.dir, "1", checks)
    assert {c.id: c.verdict for c in checks}[cid] == "FAIL"


def test_derived_closed_world_quantum_count_follows_the_oracle(tmp_path):
    """kills D3: the product's matched assets must carry the oracle's quantum verdicts."""
    fr = FakeRun(tmp_path)
    fr.write()
    _edit(fr.dir / "api/assets-run1.json", lambda d: d["items"][0].__setitem__("quantum_vulnerable", False))
    pairs: dict[str, int] = {}
    views = join.load_views(fr.dir, "1")
    oracle.match(fr.dir, "1", Checks(), views["api"], views["export"], None, pairs)
    checks = Checks()
    derived.judge(fr.dir, "1", checks, pairs, None)
    assert {c.id: c.verdict for c in checks}["G11/derived/run1/oracle/quantum"] == "FAIL"


# ---------------------------------------------------------------------------------------------- logs (m3, G1, G2)
def test_dropped_assets_fail_g16(tmp_path):
    """kills G1 (dropped ignored)."""
    run = FakeRun(tmp_path).write()
    (run / "logs" / "backend.log").write_text(
        "2026-11-12T09:00:01Z cbom sources assets stored team=9 run=55 job=900 attempt=1 accepted=2 duplicate=0 "
        "rejected=0 dropped=1 total=2 cap_reached=False\n", encoding="utf-8")
    checks = Checks()
    logs.judge(run, checks, [9])
    assert [c.reason for c in checks if c.verdict == "FAIL"] == ["assets-rejected-or-dropped"]


def test_nginx_line_must_match_path_and_time(tmp_path):
    """kills G2 (any nginx line explains any 5xx): another path, or 30 s away, explains nothing."""
    run = FakeRun(tmp_path).write()
    har = {"log": {"entries": [{"startedDateTime": "2026-11-12T09:00:05Z",
                                "request": {"method": "POST", "url": "https://api.dss.test/9/cbom/sources/runs"},
                                "response": {"status": 502, "content": {"text": "bad gateway"}}}]}}
    (run / "har" / "G9.har").write_text(json.dumps(har), encoding="utf-8")
    for line in ('2026-11-12T09:00:06Z x "POST /9/other HTTP/1.1" 502 1\n',
                 '2026-11-12T09:00:40Z x "POST /9/cbom/sources/runs HTTP/1.1" 502 1\n'):
        (run / "logs" / "nginx.log").write_text(line, encoding="utf-8")
        checks = Checks()
        logs.judge(run, checks, [9])
        assert [c.reason for c in checks if c.verdict == "FAIL"] == ["5xx-without-log-ref"]


def test_g16_is_not_vacuous(tmp_path):
    """m3 / wrong CBOMs 11, 12: no HAR is NOT-RUN; a job that stored assets must have its 'assets stored' line."""
    run = FakeRun(tmp_path).write()
    for f in (run / "har").glob("*.har"):
        f.unlink()
    (run / "logs" / "backend.log").write_text("", encoding="utf-8")
    checks = Checks()
    logs.judge(run, checks, [9])
    by = {c.id: (c.verdict, c.reason) for c in checks}
    assert by["G16/har"][0] == "NOT-RUN"
    assert by["G16/assets-stored/job-900-logged"] == ("FAIL", "assets-stored-line-missing")


def test_g16_requires_node_and_lab_logs(tmp_path):
    run = FakeRun(tmp_path).write()
    (run / "lab" / "lab.json").write_text(json.dumps({"targets": [{"container": "cb02-z01"}],
                                                      "listeners": [{"container": "cb02-canary"}]}))
    (run / "flow-state.json").write_text(json.dumps({"node": {"container": "zs-scan-node-e2e-node-1"}}))
    checks = Checks()
    logs.judge(run, checks, [9])
    fails = {c.id for c in checks if c.verdict == "FAIL"}
    assert {"G16/collected/cb02-z01", "G16/collected/cb02-canary", "G16/collected/zs-scan-node-*"} <= fails


# ------------------------------------------------------------------------------------------- gate (X2, m4, O-10)
def test_every_flow_step_is_required(tmp_path):
    """kills X2: each step the flow or runner writes is required (a missing step.json is NOT-RUN and blocks)."""
    expected = ["G0", "G1", "G2", "G3", "G4", "G5", "G5b", "G6", "G7", "G8", "G9", "G10", "G11", "G12", "G13", "G13b",
                "G14", "G17"]
    assert gate.FLOW_STEPS == expected
    fr = FakeRun(tmp_path)
    run = fr.write()
    (run / "steps" / "G9" / "step.json").unlink()
    passed, blocking, _ = judge(run, tmp_path)
    assert blocking["G9/step"]["verdict"] == "NOT-RUN"


def test_a_run_with_an_oracle_but_no_api_capture_is_not_skipped(tmp_path):
    """m4: run 2's oracle exists, its API lane does not -> NOT-RUN, which blocks."""
    fr = FakeRun(tmp_path)
    run = fr.write()
    (run / "oracle" / "run2.json").write_text((run / "oracle" / "run1.json").read_text())
    manifest.freeze_oracle(run)
    passed, blocking, _ = judge(run, tmp_path)
    assert blocking["G11/join/run2/api"]["verdict"] == "NOT-RUN"


def test_export_timestamp_and_db_rows_must_be_on_the_run_day(tmp_path):
    """m2 / O-10 / wrong CBOM 5."""
    fr = FakeRun(tmp_path)
    run = fr.write()
    _edit(run / "exports/run1.cdx.json", lambda d: d["metadata"].__setitem__("timestamp", "2025-11-12T09:01:00Z"))
    path, rows = _db_rows(run)
    for r in rows:
        r["created_at"] = "2025-11-12 09:00:00"
    _write_db(path, rows)
    passed, blocking, _ = judge(run, tmp_path)
    assert blocking["G12/timestamps_on_run_day/run1"]["reason"] == "outside-run-window"
    assert blocking["G11/db_created_in_run_window/run1"]["reason"] == "outside-run-window"


def test_ledger_error_exits_2_not_1(tmp_path, capsys):
    """nit: a broken ledger is an error, not a gate verdict."""
    run = FakeRun(tmp_path).write()
    bad = tmp_path / "bad.yaml"
    bad.write_text("- row: X\n  gate: [G11]\n  match: {verdict: FAIL}\n  expect_failing: 1\n  issue: '#1'\n"
                   "  owner: CB-1\n  why: x\n", encoding="utf-8")
    assert gate.main(["judge", str(run), "--ledger", str(bad)]) == 2


def test_trace_zip_is_redacted_and_scanned(tmp_path):
    """m6: a bearer token inside a trace.zip member is scrubbed, and an unscrubbable one is reported."""
    import zipfile
    run = FakeRun(tmp_path).write()
    jwt = "eyJ" + "a" * 20 + ".eyJ" + "b" * 20 + "." + "c" * 24
    z = run / "steps" / "G3" / "trace.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("trace.network", json.dumps({"headers": [{"name": "Authorization", "value": f"Bearer {jwt}"}]}))
        zf.writestr("shot.png", b"\x89PNG")
    assert gate.redact_run(run, []) == []
    with zipfile.ZipFile(z) as zf:
        assert jwt not in zf.read("trace.network").decode() and zf.read("shot.png") == b"\x89PNG"


def test_export_serial_number_and_run_verdict_are_judged(tmp_path):
    """m2 / O-10: the export names its run (urn:uuid serial), and a re-judged row keeps the DB's run verdict."""
    fr = FakeRun(tmp_path)
    run = fr.write()
    _edit(run / "exports/run1.cdx.json", lambda d: (d.__setitem__("serialNumber", ""),
                                                     d["components"][0]["properties"].append(
                                                         {"name": "zs:run_impact", "value": "Critical"})))
    passed, blocking, _ = judge(run, tmp_path)
    assert blocking["G12/serial_number/run1"]["reason"] == "serial-missing"
    assert blocking["G12/run_verdict_eq_db/run1"]["reason"] == "mismatch"


@pytest.mark.parametrize("accepted, want", [
    (["X25519MLKEM768"], False), (["x25519", "secp256r1"], True), (["X25519MLKEM768", "x25519"], None), ([], None)])
def test_kex_verdict_table(accepted, want):
    from harness import standards as STD
    assert STD.kex_quantum_vulnerable(accepted, STD.PQ_TLS_GROUPS) is want


def test_ssh_pseudo_methods_do_not_count_as_kex():
    from harness import standards as STD
    assert STD.kex_quantum_vulnerable(["mlkem768x25519-sha256", "ext-info-s", "kex-strict-s-v00@openssh.com"],
                                      STD.PQ_SSH_KEX) is False


def test_weak_suite_classes():
    from harness import standards as STD
    got = STD.classes_present(["TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_AES_128_GCM_SHA256"], STD.WEAK_SUITE_CLASSES)
    assert got == {"static-rsa", "cbc"}


def test_derived_algorithm_must_be_an_accepted_suite(tmp_path):
    """D-rule: with no stated algorithm, the negotiated suite the product shows must be one the server accepts."""
    fr = FakeRun(tmp_path)
    fr.write()
    _edit(fr.dir / "oracle/run1.json",
          lambda d: d["targets"][0]["assets"][1]["expect"].pop("algorithm", None))
    manifest.freeze_oracle(fr.dir)
    passed, _, report = judge(fr.dir, tmp_path)
    check = next(c for c in report["checks"] if c["id"] == "G11/oracle/run1/z01/tls_endpoint/algorithm")
    assert check["verdict"] == "PASS" and check["subject"]["expectation"] == "derived"
    for view in ("api/assets-run1.json",):
        _edit(fr.dir / view, lambda d: d["items"][1].__setitem__("algorithm", "TLS_CHACHA20_POLY1305_SHA256"))
    passed, blocking, _ = judge(fr.dir, tmp_path)
    assert blocking["G11/oracle/run1/z01/tls_endpoint/algorithm"]["reason"] == "wrong-value"


def test_target_outside_scope_with_product_assets_fails(tmp_path):
    """The customer did not configure the target, yet the product reports assets there."""
    fr = FakeRun(tmp_path)
    run = fr.write()
    (run / "flow-state.json").write_text(json.dumps({"scope": {"sources": [], "ranges": ["10.231.0.0/31"]}}))
    passed, blocking, _ = judge(run, tmp_path)
    assert blocking["G11/oracle/run1/z01/out-of-scope/101"]["reason"] == "out-of-scope-asset"


def test_unverified_keys_named_by_the_lab_are_not_judged(tmp_path):
    """INTERFACES v7.1 #5: a key in selfcheck ``unverified_keys`` has no independent proof -> NOT-JUDGED."""
    fr = FakeRun(tmp_path)
    fr.write()
    _edit(fr.dir / "lab/selfcheck.json",
          lambda d: d["targets"][0].__setitem__("unverified_keys", {"z01/tls_endpoint": ["cipher_suites"]}))
    passed, blocking, _ = judge(fr.dir, tmp_path)
    assert blocking["G11/oracle/run1/z01/tls_endpoint/cipher_suites"]["reason"] == "lab-not-independent"


def test_lab_stated_verdict_must_agree_with_its_own_groups(tmp_path):
    """v7 §A.2: the lab's stated endpoint verdict wins, but contradicting its own accepted groups is a lab bug."""
    fr = FakeRun(tmp_path)
    fr.write()
    _edit(fr.dir / "oracle/run1.json", lambda d: d["targets"][0]["assets"][1]["expect"].update(
        {"quantum_vulnerable": False, "groups": ["x25519", "secp256r1"]}))
    manifest.freeze_oracle(fr.dir)
    passed, blocking, _ = judge(fr.dir, tmp_path)
    assert blocking["G11/oracle/run1/z01/tls_endpoint/quantum_vulnerable/lab_vs_derivation"]["reason"] == \
        "lab-vs-derivation"
