"""Staging QA round 2 on D3, takeover review (PR #500): what the round-2 fixes left.

* G-D3-6 (CycloneDX): an algorithm broken without a quantum computer (MD5, SHA-1, DES,
  3DES, RC4 ...) meets no NIST security strength category, so its
  ``nistQuantumSecurityLevel`` is 0 (CycloneDX 1.6: "A value of 0 indicates that none
  of the categories are met"; NIST SP 800-131A Rev 2 disallows them), while it stays
  ``quantumVulnerable`` false ("Broken today"). HMAC-SHA1 is not broken (SP 800-131A
  keeps HMAC-SHA-1 acceptable) and is not graded 0.
* G-D3-6 (distributions): the engine's PQC readiness counts a broken-today algorithm
  as judged and not quantum-safe, as the results page, the PDF and the scan list do
  (frontend quantumFilter.quantumCounts, backend cbom_metrics).
* Q2-04: MAC and KDF algorithms whose identity the scan knows carry their registered
  OID (HMAC-SHA*: RFC 8018 / RFC 4231 ids, PBKDF2: RFC 8018, scrypt: RFC 7914), so
  CERT-In Table 9's OID check does not report them missing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aibom.emit.crypto_oid import algorithm_oid
from aibom.integrations.cbom_devsecshield import scan_crypto_to_devsecshield


def _scan(tmp_path: Path, files: dict[str, str]) -> dict:
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return scan_crypto_to_devsecshield(str(tmp_path), level=4)


_BROKEN = '''import hashlib
from Crypto.Cipher import DES, ARC4
def password_digest(password):
    return hashlib.md5(password.encode()).hexdigest()
def legacy_sig(data):
    return hashlib.sha1(data).hexdigest()
def enc(key, data):
    return DES.new(key, DES.MODE_CBC).encrypt(data)
def stream(key, data):
    return ARC4.new(key).encrypt(data)
def good(data):
    return hashlib.sha256(data).hexdigest()
'''


def _algos(out: dict) -> dict[str, list[dict]]:
    by: dict[str, list[dict]] = {}
    for c in out["cbom_json"]["components"]:
        cp = c.get("cryptoProperties") or {}
        if cp.get("assetType") == "algorithm":
            by.setdefault(c["name"].upper(), []).append(cp)
    return by


def test_broken_algorithms_are_nist_quantum_level_zero(tmp_path):
    out = _scan(tmp_path, {"app.py": _BROKEN})
    algos = _algos(out)
    broken = [n for n in algos if n.startswith(("MD5", "SHA-1", "DES", "RC4"))]
    assert {"MD5", "SHA-1"} <= set(broken), sorted(algos)
    assert any(n.startswith("DES") for n in broken), sorted(algos)
    assert any(n.startswith("RC4") for n in broken), sorted(algos)
    for name in broken:
        for cp in algos[name]:
            level = cp["algorithmProperties"].get("nistQuantumSecurityLevel")
            assert level == 0, (name, cp)
    assert algos["SHA-256"][0]["algorithmProperties"]["nistQuantumSecurityLevel"] == 2
    rows = {r["title"].upper(): r for r in out["results"]}
    md5 = rows["MD5"]
    assert md5["nist_quantum_security_level"] == 0
    assert md5["quantum_vulnerable"] is False and md5["quantum_safe"] is False


def test_engine_pqc_readiness_counts_broken_today_as_not_safe(tmp_path):
    out = _scan(tmp_path, {"app.py": _BROKEN})
    pqc = out["cbom_distributions"]["pqc"]
    rows = [r for r in out["results"] if r.get("asset_type") == "algorithm"]
    broken = [r for r in rows if r.get("weak") and not r.get("quantum_vulnerable")]
    safe = [r for r in rows if r.get("quantum_safe") is True]
    assert broken, rows
    assert pqc["broken_today"] == len(broken)
    assert pqc["quantum_safe"] == len(safe)
    judged = pqc["quantum_safe"] + pqc["quantum_vulnerable"] + pqc["broken_today"]
    assert pqc["readiness_pct"] == round(100.0 * pqc["quantum_safe"] / judged, 1)
    assert pqc["readiness_pct"] < 100.0


@pytest.mark.parametrize(
    ("name", "primitive", "oid"),
    [
        ("HMAC-SHA1", "mac", "1.2.840.113549.2.7"),
        ("HMAC-SHA224", "mac", "1.2.840.113549.2.8"),
        ("HMAC-SHA256", "mac", "1.2.840.113549.2.9"),
        ("HMAC-SHA384", "mac", "1.2.840.113549.2.10"),
        ("HMAC-SHA512", "mac", "1.2.840.113549.2.11"),
        ("PBKDF2", "kdf", "1.2.840.113549.1.5.12"),
        ("PBKDF2-HMAC-SHA256", "kdf", "1.2.840.113549.1.5.12"),
        ("scrypt", "kdf", "1.3.6.1.4.1.11591.4.11"),
    ],
)
def test_mac_and_kdf_oids(name, primitive, oid):
    assert algorithm_oid(name, primitive) == oid


@pytest.mark.parametrize("name", ["HMAC", "Argon2", "Fernet", "AES", "HKDF"])
def test_no_oid_without_a_pinned_identity(name):
    assert algorithm_oid(name, "mac" if name == "HMAC" else None) is None


def test_hmac_sha1_is_not_graded_broken(tmp_path):
    src = (
        "import hmac, hashlib\n"
        "def tag(k, m):\n    return hmac.new(k, m, hashlib.sha1).digest()\n"
    )
    out = _scan(tmp_path, {"m.py": src})
    for name, cps in _algos(out).items():
        if name.startswith("HMAC"):
            for cp in cps:
                level = cp["algorithmProperties"].get("nistQuantumSecurityLevel")
                assert level != 0, (name, cp)


def test_cert_in_oid_check_counts_mac_and_kdf_oids(tmp_path):
    out = _scan(tmp_path, {"k.py": '''import hashlib, hmac
def derive(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw, salt, 600000)
def tag(k, m):
    return hmac.new(k, m, hashlib.sha256).digest()
'''})
    no_oid = [c["name"] for c in out["cbom_json"]["components"]
              if (c.get("cryptoProperties") or {}).get("assetType") == "algorithm"
              and not c["cryptoProperties"].get("oid")]
    assert not any(n.upper().startswith(("PBKDF2", "HMAC-SHA")) for n in no_oid), no_oid
