"""CB-24 PR-4b, PKCS#11 half, backend side: the token class the scan node now reports (hsm_pkcs11.token_classification)
decides the fix class of a PKCS#11 key's capability codes (plan §3.2, T4 / AG-4b):

* hardware token (slot CKF_HW_SLOT: HSM or smart card) -> R-HW, hardware-fixed (observed);
* software token (SoftHSM v2, as recorded from a real token) -> R-TYPE, vendor-fixed;
* class not read -> R-HW-UNREAD, unknown ("PKCS#11 token type ... not read").

The facts come from the node's own classifier on recorded token info, then classify and agility.evaluate."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.utilities.cbom_sources import agility as AG  # noqa: E402
from backend.utilities.cbom_sources.classify import classify  # noqa: E402

NODE = {"lane": "node", "source_kind": "key_manager", "provider": "pkcs11", "operated_by": None, "application": None}
# SoftHSM 2.6.1 (Ubuntu softhsm2 2.6.1-2.2ubuntu3), recorded 2026-11-14 with python-pkcs11 on a fresh token
SOFTHSM = {"token_manufacturer": "SoftHSM project", "token_model": "SoftHSM v2", "library_manufacturer": "SoftHSM",
           "slot_manufacturer": "SoftHSM project", "slot_flags": ["TOKEN_PRESENT"]}


@pytest.fixture(scope="module")
def classify_token():
    sys.path.insert(0, str(ROOT / "scan_node"))
    from zs_scan_node.collectors.hsm_pkcs11 import token_classification

    return token_classification


def _key(token_facts):
    facts = {"store": "pkcs11", "key_class": "private", "key_type": "RSA", **token_facts}
    verdict = classify("managed_key", "RSA", 2048, None, facts, None)
    assert "QUANTUM_VULNERABLE" in verdict["finding_codes"], verdict
    result = AG.evaluate("node", "managed_key", verdict["finding_codes"], facts, NODE)
    return result, {p["code"]: p for p in result["by_code"]}["QUANTUM_VULNERABLE"]


@pytest.mark.parametrize("info,flags,cls,rule", [
    (SOFTHSM, ["TOKEN_PRESENT"], "vendor-fixed", "R-TYPE"),
    ({"token_manufacturer": "Acme HSM Inc.", "token_model": "A9"}, ["TOKEN_PRESENT", "HW_SLOT"], "hardware-fixed", "R-HW"),
    ({"token_manufacturer": "Card Co", "token_model": "PIV"}, ["TOKEN_PRESENT", "REMOVABLE_DEVICE", "HW_SLOT"],
     "hardware-fixed", "R-HW"),
    ({"token_manufacturer": "Acme HSM Inc.", "token_model": "A9"}, ["TOKEN_PRESENT"], "unknown", "R-HW-UNREAD"),
])
def test_the_token_class_decides_the_fix_class(classify_token, info, flags, cls, rule):
    token = classify_token(info, flags)
    facts = {k: token[k] for k in ("token_class", "token_kind", "token_class_basis")}
    result, qv = _key(facts)
    assert (qv["class"], qv["rule"]) == (cls, rule), qv
    if cls == "hardware-fixed":
        assert qv["confidence"] == "observed" and result["fix_class"] == "hardware-fixed"
    if cls == "unknown":
        assert qv["unknown_reason"] == "token_type_not_read"


def test_a_key_from_an_older_node_without_a_token_class_stays_unknown():
    _result, qv = _key({})
    assert (qv["class"], qv["unknown_reason"]) == ("unknown", "token_type_not_read")
