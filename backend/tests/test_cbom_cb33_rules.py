"""CB-33 PR-B: the KMS rotation and unattached-certificate rules follow what AWS supports.

Before this change (dev with PR-A):
* B1: ``KMS_NO_ROTATION`` was raised for every Enabled customer key with imported material (origin EXTERNAL): AWS
  answers ``KeyRotationEnabled: false`` for them (on-demand rotation page, DA-4), but they cannot rotate
  automatically at all;
* B7: ``CERT_UNUSED`` ("orphaned") was raised for AWS Private CA (PRIVATE) certificates, certificates whose key was
  exported, ACME certificates and certificates never issued (HF-7), all used or managed outside what ACM sees;
* never-issued ACM requests were judged quantum-vulnerable although they hold no certificate (HF-7);
* a multi-Region replica's text named the replica, whose rotation is set on its primary (FP-5), and a Disabled key's
  text did not say it must be enabled first (OQ-1: the finding stays).

Withdrawn findings are rule changes: drift re-judges both sides and lists them under "rule changes", with no event
(OQ-3: no close event).  A certificate whose new ``exported`` fact hides the finding is a collector change (PR-0).

    /home/claude/work/bt.sh <worktree> -q tests/test_cbom_cb33_rules.py
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_cbom_aws_cb33 import ACM_PREFIX, Plan, _cert_detail, _cert_summary, arn, keys_of, meta, rotation, run  # noqa: E402
from test_cbom_drift_last_known import OLD, Chain, cert, emitted, engine, key  # noqa: E402,F401  (fixtures)

from backend.utilities.cbom_sources import classify as C  # noqa: E402
from backend.utilities.cbom_sources import crypto_kb  # noqa: E402

NOW = dt.datetime(2026, 11, 14, 6, 0, 0)


def codes(asset: dict) -> list[str]:
    return C.classify(asset["type"], asset.get("algorithm"), asset.get("key_size"), asset.get("protocol"),
                      asset.get("facts") or {}, NOW)["finding_codes"]


def verdict(asset: dict) -> dict:
    return C.classify(asset["type"], asset.get("algorithm"), asset.get("key_size"), asset.get("protocol"),
                      asset.get("facts") or {}, NOW)


# ============================================================================ T1 imported key material
def test_t1_an_imported_material_key_is_never_kms_no_rotation():
    """B1 (live: AWS answers false for EXTERNAL keys). dev: KMS_NO_ROTATION on every Enabled EXTERNAL key."""
    plan = (Plan().keys(1, 2, 3)
            .describe(1, meta(1, origin="EXTERNAL")).rotation(1, rotation(False)).materials(1, [])
            .describe(2, meta(2, origin="EXTERNAL")).rotation(2, "UnsupportedOperationException").materials(2, [])
            .describe(3, meta(3)).rotation(3, rotation(False)))  # control: AWS_KMS keeps it
    _services, found, _rows = run(plan)
    keys = keys_of(found)
    assert "KMS_NO_ROTATION" not in codes(keys[arn(1)]) and "KMS_NO_ROTATION" not in codes(keys[arn(2)])
    assert "KMS_NO_ROTATION" in codes(keys[arn(3)])


def test_t1b_rows_without_origin_keep_todays_verdict():
    """GCP / Azure keys (no ``origin`` fact) are judged exactly as before."""
    gcp = {"type": "kms_key", "algorithm": "SYMMETRIC_DEFAULT", "key_size": 256,
           "facts": {"key_spec": "SYMMETRIC_DEFAULT", "key_manager": "CUSTOMER", "rotation_enabled": False,
                     "provider": "gcp"}}
    assert "KMS_NO_ROTATION" in codes(gcp)


def test_t_repl_a_replica_names_its_primary():
    primary = "arn:aws:kms:us-east-1:123456789012:key/mrk-1"
    replica = key("r1", multi_region_type="REPLICA", primary_key_arn=primary)
    out = verdict(replica)
    assert "KMS_NO_ROTATION" in out["finding_codes"] and f"--key-id {primary}" in out["finding"]


def test_t_dis_a_disabled_key_keeps_the_finding_and_says_enable_it_first():
    """OQ-1 default: keep; suppressing it would make disabling a key read as a fix."""
    out = verdict(key("d1", key_state="Disabled"))
    assert "KMS_NO_ROTATION" in out["finding_codes"] and "enable the key first" in out["finding"]


# ============================================================================ T12 unattached certificates
@pytest.mark.parametrize("facts,kept", [
    ({"aws_type": "PRIVATE"}, False),
    ({"exported": True}, False),
    ({"key_pair_origin": "ACME"}, False),
    ({"status": "PENDING_VALIDATION"}, False),
    ({"status": "FAILED"}, False),
    ({"status": "VALIDATION_TIMED_OUT"}, False),
    ({"aws_type": "IMPORTED"}, True),  # controls: an orphaned certificate is still one
    ({"aws_type": "IMPORTED", "status": "EXPIRED"}, True),  # issued, then expired / revoked: still an orphan
    ({"aws_type": "IMPORTED", "status": "REVOKED"}, True),
    ({"status": "INACTIVE"}, True),
    ({"aws_type": "AMAZON_ISSUED", "exported": False, "export_option": "DISABLED"}, True),  # c6c669ef's shape (L-3)
    ({}, True),
])
def test_t12_cert_unused_only_where_the_certificate_is_really_orphaned(facts, kept):
    assert ("CERT_UNUSED" in codes(cert("x1", **facts))) is kept


def test_t12_end_to_end_through_the_collector():
    plan = Plan()
    plan.acm = [("list_certificates", {"CertificateSummaryList": [
        _cert_summary(1, Exported=True, ExportOption="ENABLED"), _cert_summary(2, type="PRIVATE"),
        _cert_summary(3, ExportOption="DISABLED", Exported=False)]}, None),
        ("describe_certificate", _cert_detail(1), {"CertificateArn": f"{ACM_PREFIX}c1"}),
        ("describe_certificate", _cert_detail(2, Type="PRIVATE"), {"CertificateArn": f"{ACM_PREFIX}c2"}),
        ("describe_certificate", _cert_detail(3), {"CertificateArn": f"{ACM_PREFIX}c3"})]
    _services, found, _rows = run(plan)
    certs = {a["location"].rsplit("/", 1)[-1]: codes(a) for a in found if a["type"] == "certificate"}
    assert "CERT_UNUSED" not in certs["c1"] and "CERT_UNUSED" not in certs["c2"] and "CERT_UNUSED" in certs["c3"]


@pytest.mark.parametrize("status,judged", [("PENDING_VALIDATION", False), ("FAILED", False),
                                           ("VALIDATION_TIMED_OUT", False), ("ISSUED", True), ("EXPIRED", True),
                                           ("REVOKED", True), ("INACTIVE", True)])
def test_t12b_a_never_issued_request_is_not_judged_quantum_vulnerable(status, judged):
    out = verdict(cert("x1", status=status, in_use=True))
    assert (out["quantum_vulnerable"] is not None) is judged


# ============================================================================ T17 drift: rule changes, not drift
def _dev_rules(monkeypatch):
    """The rules as they were before this PR, for the stored baseline."""
    real = C.classify

    def before(asset_type, algorithm, key_size, protocol, facts, now=None):
        out = real(asset_type, algorithm, key_size, protocol, facts, now)
        f = facts or {}
        extra = []
        if asset_type == "kms_key" and f.get("rotation_enabled") is False and f.get("key_manager") == "CUSTOMER" \
                and f.get("key_spec") == "SYMMETRIC_DEFAULT":
            extra.append("KMS_NO_ROTATION")
        if asset_type == "certificate" and f.get("in_use") is False:
            extra.append("CERT_UNUSED")
        codes_ = sorted(set(out["finding_codes"]) | set(extra))
        return {**out, "finding_codes": codes_, "finding": out["finding"] or ("old rule" if codes_ else None),
                "impact": out["impact"] or ("Medium" if codes_ else None)}

    monkeypatch.setattr(C, "classify", before)
    return real


def test_t17_withdrawn_findings_are_rule_changes_with_no_event(engine, emitted, monkeypatch):  # noqa: F811
    """dev: a straddle-free deploy still re-judges (ST-1); without it these would be ``resolved`` events that close
    the customer's tickets as fixed."""
    estate = [key("e1", origin="EXTERNAL"), cert("p1", aws_type="PRIVATE"), key("a1")]
    ch = Chain(engine)
    real = _dev_rules(monkeypatch)
    r1 = ch.run(estate, versions=OLD)
    ch.record(r1)
    monkeypatch.setattr(C, "classify", real)
    r2 = ch.run(estate)
    assert ch.record(r2) == []
    diff = ch.diff(r2, r1)
    assert diff["resolved"] == [] and diff["versions"]["rules_changed"] is True
    assert sorted((r["code"], r["direction"], r["label_change"]) for r in diff["rule_changes"]) == [
        ("CERT_UNUSED", "resolved", "rule change"), ("KMS_NO_ROTATION", "resolved", "rule change")]


def test_the_first_run_with_exported_is_a_collector_change_with_the_real_rule(engine, emitted):  # noqa: F811
    """DA-1 X1 with PR-B's rule: the stored row predates the ``exported`` fact (PR-A)."""
    ch = Chain(engine)
    ch.record(ch.run([cert("x1")]))
    r2 = ch.run([cert("x1", exported=True)])
    assert ch.record(r2) == []
    assert [(d["code"], d["label_change"]) for d in ch.diff(r2)["collector_changes"]] == [
        ("CERT_UNUSED", "collector change")]


def test_the_knowledge_base_was_rebuilt_past_the_shipped_version():
    assert crypto_kb.version() > "2026.11.14.2"
    findings = crypto_kb.load()["findings"]["node"]
    assert "imported material" in findings["KMS_NO_ROTATION"]["description"]
    assert "never issued" in findings["CERT_UNUSED"]["description"]
