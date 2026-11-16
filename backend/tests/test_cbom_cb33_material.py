"""CB-33 PR-C: imported KMS key material (B3) and HMAC keys (B9).

Before this change (dev with PR-A/PR-B):
* a key with imported material (origin EXTERNAL) whose material expires raised nothing, and neither did a key in
  PendingImport, which cannot encrypt or decrypt at all (B3; observed live in the CB-A1 run: a PendingImport key got
  no finding);
* an HMAC KMS key (HMAC_224..512) had no quantum verdict (B9; observed live in the CB-A1 run).

Owner decision (OQ-2): two Medium codes, a 30-day window.  ``KMS_KEY_MATERIAL_EXPIRES`` is date-based (judged today
in every view, like certificate expiry); it is never raised while the key is in PendingImport, which is
``KMS_KEY_NO_MATERIAL``.  Facts come from the collector (PR-A): ``valid_to``, ``expiration_model``,
``key_materials``.

    /home/claude/work/bt.sh <worktree> -q tests/test_cbom_cb33_material.py
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_cbom_aws_cb33 import MAT1, MAT2, Plan, _enum, _KMS_MODEL, arn, keys_of, meta, rotation, run  # noqa: E402
from test_cbom_drift_last_known import key  # noqa: E402

from backend.utilities.cbom_sources import classify as C  # noqa: E402
from backend.utilities.cbom_sources import crypto_kb, exploit_demo  # noqa: E402

NOW = dt.datetime(2026, 11, 14, 6, 0, 0)


def iso(when: dt.datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def external(valid_to: dt.datetime | None, *, state="Enabled", model="KEY_MATERIAL_EXPIRES", materials=None):
    facts = {"origin": "EXTERNAL", "key_state": state, "expiration_model": model,
             "valid_to": iso(valid_to) if valid_to else None, "current_key_material_id": MAT1}
    if materials is not None:
        facts["key_materials"] = materials
    return key("x1", rotation=None, **facts)


def verdict(asset, now=NOW):
    return C.classify(asset["type"], asset.get("algorithm"), asset.get("key_size"), None, asset["facts"], now)


# ============================================================================ T4 the 30-day window
@pytest.mark.parametrize("ahead,raised", [
    (dt.timedelta(days=10), True), (dt.timedelta(days=30), True), (dt.timedelta(days=30, seconds=1), False),
    (dt.timedelta(days=-2), True),  # expired but not yet PendingImport (the state lags): still raised, "expired on"
])
def test_t4_material_expiring_within_30_days(ahead, raised):
    out = verdict(external(NOW + ahead))
    assert ("KMS_KEY_MATERIAL_EXPIRES" in out["finding_codes"]) is raised
    if raised:
        assert out["impacts"]["KMS_KEY_MATERIAL_EXPIRES"] == "Medium"
        assert (NOW + ahead).date().isoformat() in out["finding"]


def test_t4_material_that_does_not_expire_and_aws_kms_keys_raise_nothing():
    assert "KMS_KEY_MATERIAL_EXPIRES" not in verdict(external(None, model="KEY_MATERIAL_DOES_NOT_EXPIRE"))[
        "finding_codes"]
    aws_kms = key("a1", valid_to=iso(NOW + dt.timedelta(days=3)), expiration_model="KEY_MATERIAL_EXPIRES")
    assert not {"KMS_KEY_MATERIAL_EXPIRES", "KMS_KEY_NO_MATERIAL"} & set(verdict(aws_kms)["finding_codes"])


def test_t4_shown_judges_the_expiry_today_not_on_the_run_date():
    """A run 25 days ago saw material 40 days ahead (no finding); today it is 15 days ahead."""
    then = NOW - dt.timedelta(days=25)
    asset = external(then + dt.timedelta(days=40))
    stored = verdict(asset, then)
    assert "KMS_KEY_MATERIAL_EXPIRES" not in stored["finding_codes"]
    row = SimpleNamespace(asset_type="kms_key", algorithm=asset["algorithm"], key_size=asset["key_size"],
                          protocol=None, facts=asset["facts"], created_at=then, impact=stored["impact"],
                          finding_codes=stored["finding_codes"], finding=stored["finding"])
    today = C.shown(row, NOW)
    assert "KMS_KEY_MATERIAL_EXPIRES" in today["finding_codes"] and today["as_of_run"] is not None
    assert "KMS_KEY_MATERIAL_EXPIRES" in C.DATE_CODES and "kms_key" in C.DATED_TYPES


# ============================================================================ T5 PendingImport
def test_t5_pending_import_is_no_material_and_never_also_expiring():
    pending = [{"id": MAT2, "state": "PENDING_ROTATION", "import_state": "PENDING_IMPORT",
                "expiration_model": "KEY_MATERIAL_EXPIRES", "valid_to": None}]
    out = verdict(external(NOW - dt.timedelta(days=1), state="PendingImport", materials=pending))
    assert [c for c in out["finding_codes"] if c.startswith("KMS_")] == ["KMS_KEY_NO_MATERIAL"]
    assert f"--key-material-id {MAT2}" in out["finding"]


def test_t5b_several_materials_are_named():
    materials = [{"id": MAT1, "state": "NON_CURRENT", "import_state": "IMPORTED", "expiration_model":
                  "KEY_MATERIAL_EXPIRES", "valid_to": iso(NOW + dt.timedelta(days=5))},
                 {"id": MAT2, "state": "CURRENT", "import_state": "IMPORTED", "expiration_model":
                  "KEY_MATERIAL_EXPIRES", "valid_to": iso(NOW + dt.timedelta(days=20))}]
    out = verdict(external(NOW + dt.timedelta(days=20), materials=materials))
    assert MAT1[:16] in out["finding"] and MAT2[:16] in out["finding"]
    assert (NOW + dt.timedelta(days=5)).date().isoformat() in out["finding"]  # the earliest date


def test_end_to_end_from_the_collector_facts():
    soon = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None, microsecond=0) + dt.timedelta(days=7)
    plan = (Plan().keys(1, 2)
            .describe(1, meta(1, origin="EXTERNAL", valid_to=soon)).rotation(1, rotation(False))
            .materials(1, [{"KeyId": "k", "KeyMaterialId": MAT1,
                            "KeyMaterialState": _enum(_KMS_MODEL, "KeyMaterialState", "CURRENT"),
                            "ImportState": "IMPORTED", "ExpirationModel": "KEY_MATERIAL_EXPIRES", "ValidTo": soon}])
            .describe(2, meta(2, origin="EXTERNAL", state="PendingImport")).materials(2, []))
    _services, found, _rows = run(plan)
    keys = keys_of(found)
    one = C.classify("kms_key", "SYMMETRIC_DEFAULT", 256, None, keys[arn(1)]["facts"])["finding_codes"]
    two = C.classify("kms_key", "SYMMETRIC_DEFAULT", 256, None, keys[arn(2)]["facts"])["finding_codes"]
    assert "KMS_KEY_MATERIAL_EXPIRES" in one and "KMS_NO_ROTATION" not in one
    assert "KMS_KEY_NO_MATERIAL" in two


# ============================================================================ T11 HMAC keys
@pytest.mark.parametrize("spec", ["HMAC_224", "HMAC_256", "HMAC_384", "HMAC_512"])
def test_t11_hmac_keys_are_symmetric_not_quantum_vulnerable(spec):
    out = C.classify("kms_key", spec, None, None, {"key_spec": _enum(_KMS_MODEL, "KeySpec", spec),
                                                    "key_manager": "CUSTOMER", "key_usage": "GENERATE_VERIFY_MAC",
                                                    "origin": "AWS_KMS", "key_state": "Enabled"}, NOW)
    assert out["quantum_vulnerable"] is False and "QUANTUM_VULNERABLE" not in out["finding_codes"]


def test_t11_asymmetric_keys_keep_their_verdict():
    out = C.classify("kms_key", "RSA_2048", 2048, None, {"key_spec": "RSA_2048", "key_manager": "CUSTOMER"}, NOW)
    assert out["quantum_vulnerable"] is True


# ============================================================================ T-KB
@pytest.mark.parametrize("code", ["KMS_KEY_MATERIAL_EXPIRES", "KMS_KEY_NO_MATERIAL"])
def test_t_kb_every_new_code_has_an_entry_a_fix_class_and_a_read_only_proof(code):
    entry = crypto_kb.load()["findings"]["node"][code]
    assert entry["default_impact"] == "Medium" and entry["remediation"]["steps"]
    assert entry["fix_class"]["class"] == "configurable"
    assert code in exploit_demo._BY_CODE
    assert crypto_kb.version() > "2026.11.14.3"
