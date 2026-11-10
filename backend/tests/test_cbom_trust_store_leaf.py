"""The backend half of round 5 / G3 item 4: the node now reports a leaf certificate kept in a trust-store directory as
its own certificate row (scan_node tests/test_trust_store_leaf_certs.py). That row gets the normal certificate
findings; the CA-only "Trust store directory" summary row stays inventory."""
import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.utilities.cbom_sources.classify import classify  # noqa: E402


def test_leaf_row_from_a_trust_store_directory_has_findings():
    leaf = {"path": "/etc/ssl/certs/www.pem", "index": 0, "is_ca": False, "self_signed": False, "key_alg": "RSA",
            "key_size": 1024, "sig_alg": "sha1WithRSAEncryption", "not_after": "2026-01-01T00:00:00Z",
            "subject": "CN=www.example.internal", "source": "file"}
    out = classify("certificate", "RSA", 1024, None, leaf)
    assert {"CERT_EXPIRED", "SIG_SHA1", "RSA_LT_2048"} <= set(out["finding_codes"])
    assert out["impact"] == "High"


def test_ca_only_summary_row_stays_inventory():
    summary = {"path": "/etc/ssl/certs", "trust_store": True, "count": 140, "files": 140, "expired": 2,
               "rsa_under_2048": 0, "sha1_signed": 3, "md5_signed": 0}
    out = classify("certificate", None, None, None, summary)
    assert out["finding_codes"] == [] and out["impact"] is None
