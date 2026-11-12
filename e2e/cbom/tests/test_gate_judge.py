"""The gate judges a correct CBOM PASS and every deliberately wrong one FAIL (the positive controls of the gate)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

import ledgers
from fakerun import FakeRun
from harness import gate, manifest

@pytest.fixture
def empty_ledger(tmp_path: Path) -> Path:
    path = tmp_path / "ledger.yaml"
    path.write_text("[]\n", encoding="utf-8")
    return path


def judge(run: Path, ledger: Path):
    passed, report = gate.judge(run, ledger)
    blocking = {c["id"]: c for c in report["blocking"]}
    return passed, blocking, report


def test_correct_cbom_passes(tmp_path, empty_ledger):
    run = FakeRun(tmp_path).write()
    passed, blocking, report = judge(run, empty_ledger)
    # the only non-PASS checks a complete, correct run may have are the posture numbers no oracle defines yet
    assert set(blocking) == {"G11/derived/run1/posture"}, blocking
    assert report["counts"]["FAIL"] == 0
    assert report["counts"]["PASS"] > 60


def test_correct_cbom_passes_with_posture_ledgered(tmp_path):
    run = FakeRun(tmp_path).write()
    ledger = ledgers.write(tmp_path / "l.yaml", ledgers.POSTURE)
    passed, blocking, _ = judge(run, ledger)
    assert passed and not blocking


@pytest.mark.parametrize("mutate, expect_id, reason", [
    # the export says ECDSA, the API (and the DB) say EC
    (lambda fr: _set_prop_file(fr, 101, "zs:algorithm", "ECDSA"), "G11/join/run1/asset/101/algorithm/export",
     "mismatch"),
    # the export invents an asset the API never served
    (lambda fr: fr.edit_json("exports/run1.cdx.json", lambda d: d["components"].append(
        {**d["components"][0], "bom-ref": "zs-asset-999"})),
     "G11/join/run1/asset/999/presence/export", "extra-in-export"),
    # the UI lost a row
    (lambda fr: fr.edit_json("ui/assets-run1.json", lambda d: d["rows"].pop()),
     "G11/join/run1/asset/103/presence/ui", "missing-in-ui"),
    # the UI shows another key size than the API
    (lambda fr: fr.edit_json("ui/assets-run1.json", lambda d: d["rows"][2].__setitem__("algorithm", "RSA 2048")),
     "G11/join/run1/asset/103/algorithm_cell/ui", "mismatch"),
    # the product (API, DB, export, UI all agree) stored RSA-2048 where the lab served RSA-3072: only the oracle sees it
    (lambda fr: _all_views_key_size(fr, 103, 2048), "G11/oracle/run1/z02/certificate/key_size", "wrong-value"),
    # the product missed a finding the lab planted
    (lambda fr: fr.edit_json("api/assets-run1.json", lambda d: d["items"][2].__setitem__(
        "finding_codes", ["QUANTUM_VULNERABLE"])),
     "G11/oracle/run1/z02/certificate/code/CERT_SELF_SIGNED", "code-missing"),
    # the DB holds a different impact than the API serves (and no date rule explains it)
    (lambda fr: _db_cell(fr, 102, "impact", "Critical"), "G11/join/run1/asset/102/impact/db", "mismatch"),
    # an asset fabricated at the never-scan canary
    (lambda fr: _add_everywhere(fr, 104, "10.231.0.33", "10.231.0.33:443"),
     "G11/oracle/run1/z01/must-not-appear/0", "fabricated"),
    # facets that do not add up
    (lambda fr: fr.edit_json("api/assets-run1.json", lambda d: d["facets"].__setitem__("quantum_vulnerable", 0)),
     "G11/derived/run1/quantum", "mismatch"),
])
def test_wrong_cbom_fails(tmp_path, empty_ledger, mutate, expect_id, reason):
    fr = FakeRun(tmp_path)
    fr.write()
    mutate(fr)
    manifest.freeze_oracle(fr.dir)  # an oracle the test itself changed is re-frozen; O-5 has its own test
    passed, blocking, _ = judge(fr.dir, empty_ledger)
    assert not passed
    assert expect_id in blocking, sorted(blocking)
    assert blocking[expect_id]["reason"] == reason


def test_differ_fails_rsa3072_against_export_without_key_size(tmp_path, empty_ledger):
    """DA CB-01 failing-first: RSA-3072 vs an export without a key size is FAIL(export-missing), never a skip."""
    fr = FakeRun(tmp_path, legacy_export=True)
    fr.write()
    passed, blocking, _ = judge(fr.dir, empty_ledger)
    assert not passed
    check = blocking["G11/join/run1/asset/103/key_size/export"]
    assert check["reason"] == "export-missing" and check["expected"] == 3072
    for field in ("curve", "signature_algorithm"):
        assert blocking[f"G11/join/run1/asset/101/{field}/export"]["reason"] == "export-missing"
    assert blocking["G11/join/run1/asset/102/groups/export"]["reason"] == "export-missing"
    assert blocking["G11/join/run1/asset/101/pqc_class/export"]["reason"] == "export-missing"
    assert blocking["G11/join/run1/asset/101/provenance/export"]["reason"] == "export-missing"
    # the oracle still judges the product on the API value (O-7): key size 3072 is right
    assert "G11/oracle/run1/z02/certificate/key_size" not in blocking


KF9_MATCH = {"kind": "join", "view": "export", "reason": "export-missing",
             "field": ["key_size", "curve", "signature_algorithm", "groups", "pqc_class", "provenance", "job_id"]}


def test_legacy_export_is_known_fail_under_kf9(tmp_path):
    fr = FakeRun(tmp_path, legacy_export=True)
    fr.write()
    ledger = ledgers.pinned(fr.dir, tmp_path / "l.yaml", ledgers.row("KF-9", ["G11"], KF9_MATCH, owner="CB-06"),
                            ledgers.row("KF-9o", ["G11"], {"kind": "oracle", "field": "pqc_class", "reason": "export-missing"},
                                        owner="CB-06"), ledgers.POSTURE)
    passed, blocking, report = judge(fr.dir, ledger)
    assert passed, sorted(blocking)
    rows = {r["row"]: r for r in report["ledger"]}
    assert rows["KF-9"]["status"] == "holds" and rows["KF-9"]["failing"] == 15
    pins = yaml.safe_load(ledger.read_text(encoding="utf-8"))[0]["expect"]
    # identities, not a count: the asset id is replaced by type@location, values are kept
    assert {"id": "G11/join/run1/asset/certificate@10.231.0.17:443/key_size/export", "verdict": "FAIL", "expected": 256,
            "observed": "<absent>"} in pins


@pytest.mark.parametrize("change", ["fixed", "worse", "swap", "other-value"])
def test_a_ledger_row_whose_identities_move_fails_the_gate(tmp_path, change):
    """Review 5878413538 major 3: a pinned row fails the gate on a fix (fewer), a new defect under it (more), a fix plus
    a new defect that keep the count (swap: N8/N8b), and the same check failing with another value (N6)."""
    fr = FakeRun(tmp_path, legacy_export=True)
    fr.write()
    ledger = ledgers.pinned(fr.dir, tmp_path / "l.yaml", ledgers.row("KF-9", ["G11"], KF9_MATCH, owner="CB-06"),
                            ledgers.row("KF-9o", ["G11"], {"kind": "oracle", "field": "pqc_class"}), ledgers.POSTURE)
    assert judge(fr.dir, ledger)[0]
    if change in ("fixed", "swap"):  # the export gains the leaf's key size
        _set_prop_file(fr, 101, "zs:key_size", "256")
    if change in ("worse", "swap"):  # the API invents a curve the export lacks on the RSA certificate
        fr.edit_json("api/assets-run1.json", lambda d: d["items"][2]["facts"].__setitem__("curve", "P-384"))
        fr.edit_csv("db/assets.csv", lambda rows: [r.__setitem__("facts", json.dumps({**json.loads(r["facts"]), "curve": "P-384"}))
                                                   for r in rows if r["id"] == "103"])
    if change == "other-value":  # the same export-missing check, another API value
        fr.edit_json("api/assets-run1.json", lambda d: d["items"][0]["facts"].__setitem__("sig_alg", "ecdsa-with-SHA384"))
        fr.edit_csv("db/assets.csv", lambda rows: [r.__setitem__("facts", json.dumps({**json.loads(r["facts"]), "sig_alg": "ecdsa-with-SHA384"}))
                                                   for r in rows if r["id"] == "101"])
        fr.edit_json("oracle/run1.json", lambda d: d["targets"][0]["assets"][0]["expect"].__setitem__(
            "signature_algorithm", "ecdsa-with-SHA384"))
        manifest.freeze_oracle(fr.dir)
    passed, _, report = judge(fr.dir, ledger)
    row = {x["row"]: x for x in report["ledger"]}["KF-9"]
    assert not passed and row["status"] == "moved", row
    if change == "swap":
        assert row["failing"] == 15 and row["unexpected"] and row["missing"]


def test_oracle_changed_after_start_fails(tmp_path, empty_ledger):
    fr = FakeRun(tmp_path)
    fr.write()
    fr.edit_json("oracle/run1.json", lambda d: d["targets"][0]["assets"][0]["expect"].__setitem__("key_size", 384))
    passed, blocking, _ = judge(fr.dir, empty_ledger)
    assert not passed and blocking["G0/oracle-frozen"]["reason"] == "oracle-changed"


def test_lab_selfcheck_disagreement_is_not_judged_never_pass(tmp_path, empty_ledger):
    fr = FakeRun(tmp_path)
    fr.write()
    fr.edit_json("lab/selfcheck.json", lambda d: d["targets"][1].update(
        agree=False, checks=[{"oracle_id": "z02/certificate", "key": "key_size", "agree": False}]))
    passed, blocking, report = judge(fr.dir, empty_ledger)
    assert not passed
    assert blocking["G11/oracle/run1/z02/certificate"]["verdict"] == "NOT-JUDGED"
    assert not [c for c in report["checks"] if c["id"].startswith("G11/oracle/run1/z02/") and c["verdict"] == "PASS"]


def test_missing_selfcheck_fails(tmp_path, empty_ledger):
    fr = FakeRun(tmp_path)
    fr.write()
    (fr.dir / "lab" / "selfcheck.json").unlink()
    passed, blocking, _ = judge(fr.dir, empty_ledger)
    assert blocking["G11/oracle/run1/selfcheck"]["reason"] == "selfcheck-missing"


def test_missing_step_is_not_run_and_blocks(tmp_path, empty_ledger):
    fr = FakeRun(tmp_path)
    fr.write()
    (fr.dir / "steps" / "G14" / "step.json").unlink()
    passed, blocking, _ = judge(fr.dir, empty_ledger)
    assert not passed and blocking["G14/step"]["verdict"] == "NOT-RUN"


def test_db_compares_with_run_verdict_when_a_date_rule_changed_it(tmp_path, empty_ledger):
    """API shows today's impact with the run's kept in as_of_run; the DB holds the run's: that is consistent."""
    fr = FakeRun(tmp_path)
    fr.write()

    def today(d):
        item = d["items"][0]
        item["as_of_run"] = {"date": "2026-11-12", "judged_on": "2026-11-13", "impact": "Medium",
                             "finding_codes": ["QUANTUM_VULNERABLE"], "finding": "Quantum-vulnerable key"}
        item["impact"] = "High"
        d["facets"]["impact"] = {"High": 2, "Low": 1}
    fr.edit_json("api/assets-run1.json", today)
    _set_prop_file(fr, 101, "zs:impact", "High")
    fr.edit_json("ui/assets-run1.json", lambda d: d["rows"][0].__setitem__("impact", "High"))
    passed, blocking, _ = judge(fr.dir, empty_ledger)
    assert "G11/join/run1/asset/101/impact/db" not in blocking
    assert "G11/join/run1/asset/101/impact/export" not in blocking


def test_cli_exit_codes(tmp_path, empty_ledger, capsys):
    fr = FakeRun(tmp_path)
    fr.write()
    assert gate.main(["judge", str(fr.dir), "--ledger", str(empty_ledger)]) == 1  # posture NOT-RUN unledgered
    out = json.loads(capsys.readouterr().out)
    assert out["passed"] is False
    assert gate.main(["judge", str(tmp_path / "nope")]) == 2


# ----------------------------------------------------------------------------------------------------- helpers
def _set_prop(doc, aid, name, value):
    for comp in doc["components"]:
        if comp["bom-ref"] == f"zs-asset-{aid}":
            for prop in comp["properties"]:
                if prop["name"] == name:
                    prop["value"] = value
                    return
            comp["properties"].append({"name": name, "value": value})


def _set_prop_file(fr, aid, name, value):
    fr.edit_json("exports/run1.cdx.json", lambda d: _set_prop(d, aid, name, value))


def _db_cell(fr, aid, column, value):
    import csv
    path = fr.dir / "db" / "assets.csv"
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    for row in rows:
        if row["id"] == str(aid):
            row[column] = value
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def _all_views_key_size(fr, aid, size):
    fr.edit_json("api/assets-run1.json", lambda d: [i.__setitem__("key_size", size) for i in d["items"] if i["id"] == aid])
    _db_cell(fr, aid, "key_size", str(size))
    _set_prop_file(fr, aid, "zs:key_size", str(size))
    fr.edit_json("ui/assets-run1.json", lambda d: [r.__setitem__("algorithm", f"RSA {size}") for r in d["rows"]
                                                   if r["id"] == aid])


def _add_everywhere(fr, aid, target, location):
    spec = dict(fr.assets[1], id=aid, target=target, location=location)
    fr.edit_json("api/assets-run1.json", lambda d: (d["items"].append(fr.api_item(spec)),
                                                    d.__setitem__("all_total", d["all_total"] + 1),
                                                    d["facets"]["type"].__setitem__("tls_endpoint", 2),
                                                    d["facets"]["impact"].__setitem__("Low", 2),
                                                    d["facets"].__setitem__("quantum_vulnerable", 4)))
    import csv
    path = fr.dir / "db" / "assets.csv"
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    rows.append({k: str(v) for k, v in fr.db_row(spec).items()})
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    fr.edit_json("exports/run1.cdx.json", lambda d: d["components"].append(fr.component(spec)))
    fr.edit_json("ui/assets-run1.json", lambda d: d["rows"].append(fr.ui_row(spec)))


@pytest.mark.parametrize("ca_id", [99, 120])
def test_chain_certificates_at_one_location_are_told_apart_by_fingerprint(tmp_path, empty_ledger, ca_id):
    """A leaf and its CA share the endpoint's location; the product may store them in either order (both orders are
    tried, so matching by id order alone fails one of them: mutant O9)."""
    fr = FakeRun(tmp_path)
    leaf = fr.assets[0]
    ca = dict(leaf, id=ca_id, name="CN=lab CA", algorithm="RSA", key_size=2048, impact="Low", codes=["QUANTUM_VULNERABLE"],
              finding="Quantum-vulnerable key", pqc="vulnerable",
              facts={**leaf["facts"], "key_alg": "RSA", "curve": None, "subject": "CN=lab CA", "issuer": "CN=lab CA",
                     "fingerprint_sha256": "bb" * 32, "serial": "ca"},
              oracle={"target": "z01", "expect": {"algorithm": "RSA", "subject": "CN=lab CA", "key_size": 2048,
                                                   "quantum_vulnerable": True, "fingerprint_sha256": "BB:" * 31 + "BB"},
                      "codes_include": ["QUANTUM_VULNERABLE"], "impact_min": "Low"})
    leaf["facts"]["fingerprint_sha256"] = "aa" * 32
    leaf["oracle"]["expect"]["fingerprint_sha256"] = "aa" * 32
    ca["facts"] = {k: v for k, v in ca["facts"].items() if v is not None}
    fr.assets.insert(0, ca)  # the CA is listed first in the oracle, whatever its id
    fr.write()
    fr.edit_json("oracle/run1.json", lambda d: [a.__setitem__("oracle_id", f"z01/cert{i}") for i, a in
                                                enumerate(x for x in d["targets"][0]["assets"] if x["asset_type"] == "certificate")])
    manifest.freeze_oracle(fr.dir)
    passed, blocking, report = judge(fr.dir, empty_ledger)
    assert not [b for b in blocking if "/oracle/" in b], sorted(blocking)
    by_id = {c["id"]: c for c in report["checks"]}
    assert by_id["G11/oracle/run1/z01/cert0/present"]["subject"]["asset_id"] == ca_id
    assert by_id["G11/oracle/run1/z01/cert1/present"]["subject"]["asset_id"] == 101


def test_target_outside_the_runs_scope_is_not_run_not_missing(tmp_path, empty_ledger):
    fr = FakeRun(tmp_path)
    fr.write()
    (fr.dir / "flow-state.json").write_text(json.dumps({"scope": {"sources": [], "ranges": ["10.231.0.0/31"]}}))
    passed, blocking, _ = judge(fr.dir, empty_ledger)
    assert blocking["G11/oracle/run1/z01/certificate"]["verdict"] == "NOT-RUN"
    assert blocking["G11/oracle/run1/z02/certificate"]["verdict"] == "NOT-RUN"
    (fr.dir / "flow-state.json").write_text(json.dumps({"scope": {"sources": ["S-zoo"], "ranges": []}}))
    passed, blocking, _ = judge(fr.dir, empty_ledger)
    assert set(blocking) == {"G11/derived/run1/posture"}


def test_ssh_oracle_keys_compare_sets_without_pseudo_algorithms():
    from harness import fieldmap as F
    product = {"facts": {"kex": ["curve25519-sha256", "ext-info-s", "kex-strict-s-v00@openssh.com"],
                         "macs_s2c": ["hmac-sha2-256"], "macs_c2s": ["hmac-sha1"],
                         "host_key": {"key_type": "ssh-ed25519", "bits": 256, "fingerprint_sha256": "2e01" + "0" * 60}}}
    assert F.norm_ssh_list(F.ORACLE_ONLY["kex_algorithms"](product)) == ["curve25519-sha256"]
    assert F.norm_ssh_list(F.ORACLE_ONLY["macs"](product)) == ["hmac-sha1", "hmac-sha2-256"]
    want = [{"type": "ssh-ed25519", "bits": 256, "fingerprint_sha256": "2e01" + "0" * 60},
            {"type": "ssh-rsa", "bits": 1024, "fingerprint_sha256": "SHA256:AAAA"}]
    assert F.norm_host_keys(F.ORACLE_ONLY["host_keys"](product)) != F.norm_host_keys(want)  # one of two keys read
    assert F.norm_host_keys(F.ORACLE_ONLY["host_keys"](product)) == F.norm_host_keys(want[:1])
