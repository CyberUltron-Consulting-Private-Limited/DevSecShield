"""CB-24 PR-4b, backend side: the Windows key provider the scan node now reads (KEY_PROV_INFO, no key opened) decides
the fix class of a Windows certificate's capability codes (plan §3.2):

* tpm / smartcard / hsm provider -> R-HW, hardware-fixed (observed);
* software provider (Microsoft Software KSP, the CAPI providers) -> no hardware rule: the table class (vendor-fixed,
  R-INFERRED), so the certificate is no longer "unknown";
* a provider outside the reviewed list -> R-HW-UNREAD, unknown ("key provider not in the reviewed list");
* provider not read (older node, registry value unreadable) -> R-HW-UNREAD, unknown ("key provider ... not read").

The facts come from the real node parser (scan_node windows_winrm.parse_certificates) on the C6 lab's recorded
providers (see scan_node/tests/test_windows_key_provider.py), then classify and agility.evaluate, as a run does."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.utilities.cbom_sources import agility as AG  # noqa: E402
from backend.utilities.cbom_sources.classify import classify  # noqa: E402

NODE = {"lane": "node", "source_kind": "windows_servers", "provider": None, "operated_by": None, "application": None}


@pytest.fixture(scope="module")
def node():
    sys.path.insert(0, str(ROOT / "scan_node"))
    sys.path.insert(0, str(ROOT / "scan_node" / "tests"))
    try:
        from zs_scan_node.collectors import windows_winrm as W
        import test_windows_key_provider as T
    finally:
        sys.path.remove(str(ROOT / "scan_node" / "tests"))
    return W, T


def _fix(row):
    verdict = classify("certificate", row["key_alg"], row["key_size"], None, row, None)
    assert "QUANTUM_VULNERABLE" in verdict["finding_codes"], verdict
    result = AG.evaluate("node", "certificate", verdict["finding_codes"], row, NODE)
    return result, {p["code"]: p for p in result["by_code"]}["QUANTUM_VULNERABLE"]


@pytest.mark.parametrize("provider,cls,rule", [
    ("Microsoft Platform Crypto Provider", "hardware-fixed", "R-HW"),
    ("Microsoft Smart Card Key Storage Provider", "hardware-fixed", "R-HW"),
    ("nCipher Security World Key Storage Provider", "hardware-fixed", "R-HW"),
    ("Microsoft Software Key Storage Provider", "vendor-fixed", "R-INFERRED"),
    ("Microsoft RSA SChannel Cryptographic Provider", "vendor-fixed", "R-INFERRED"),
    ("Contoso Quantum HSM Key Storage Provider", "unknown", "R-HW-UNREAD"),
])
def test_the_provider_decides_the_fix_class(node, provider, cls, rule):
    W, T = node
    (row,) = W.parse_certificates(json.dumps([T._synthetic("AB12", provider)]))
    result, qv = _fix(row)
    assert (qv["class"], qv["rule"]) == (cls, rule), qv
    if cls == "hardware-fixed":
        assert qv["confidence"] == "observed" and provider.split()[0] not in ("",) and "key provider" in qv["fact"]
        assert result["fix_class"] == "hardware-fixed"
    if cls == "unknown":
        assert qv["unknown_reason"] == "key_provider_unlisted"


def test_the_lab_certificates_are_no_longer_unknown(node):
    """C6 lab (oracle): every key is software. Before PR-4b every one was unknown (provider not read)."""
    W, T = node
    rows = W.parse_certificates(json.dumps(T.lab_rows()))
    for row in rows:
        _result, qv = _fix(row)
        assert qv["class"] == "vendor-fixed" and qv["rule"] == "R-INFERRED", (row["thumbprint"], qv)
    old = W.parse_certificates(T.CERTS_JSON)  # the same certificates from a node before PR-4b
    for row in old:
        _result, qv = _fix(row)
        assert (qv["class"], qv["unknown_reason"]) == ("unknown", "key_provider_not_read"), qv


def test_a_provider_that_could_not_be_read_stays_unknown(node):
    W, T = node
    row_in = dict(T.ZSLABDC[1], KeyProv=None, KeyProvError="UnauthorizedAccessException")
    (row,) = W.parse_certificates(json.dumps([row_in]))
    _result, qv = _fix(row)
    assert (qv["class"], qv["rule"], qv["unknown_reason"]) == ("unknown", "R-HW-UNREAD", "key_provider_not_read")
