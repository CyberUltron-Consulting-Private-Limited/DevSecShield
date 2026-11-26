"""Staging QA round 2 on D3 (code-scan CBOM): Q2-01, Q2-02, Q2-04, Q2-09, Q2-11, G-D3-6,
N2, N7.

Fixtures are small trees written here: the false positives of the reviewer's EncDec-Pro
repro (a Kotlin memory tier
read as AES-512, UI labels and settings keys read as scrypt) and real Kotlin / JS /
Python crypto calls that must
still be found.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aibom.cbom.detect import detect_crypto
from aibom.integrations.cbom_devsecshield import scan_crypto_to_devsecshield
from aibom.score.posture import posture_risk


def _keys(text: str, lang: str) -> dict[str, list]:
    out: dict[str, list] = {}
    for det in detect_crypto(text, lang):
        out.setdefault(det.key, []).append(det)
    return out


def _scan(tmp_path: Path, files: dict[str, str]) -> dict:
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return scan_crypto_to_devsecshield(str(tmp_path), level=4)


_FERNET_APP = (
    "from cryptography.fernet import Fernet\nf = Fernet(Fernet.generate_key())\n"
)


def _titles(out: dict) -> list[str]:
    return [r["title"] for r in out["results"]]


# ----------------------------------------------------------------------------- Q2-02
# false inventory
KOTLIN_PROFILE = '''package com.example.crypto
data class KeyProfile(val name: String, val keyBytes: Int, val memoryMb: Int, \
val scryptN: Int, val cipher: String)
object Profiles {
    val all = listOf(
        KeyProfile("Key 9", 32, 256, 262144, "AES-256-GCM"),
        KeyProfile("Key 10", 32, 512, 524288, "AES-256-GCM")
    )
}
'''


def test_kotlin_memory_tier_is_no_aes_key_size():
    dets = _keys(KOTLIN_PROFILE, "java")
    sizes = {d.key_size for d in dets.get("aes", [])} | {
        d.key_size for d in dets.get("aes-256", [])
    }
    assert 512 not in sizes, "a 512 MB memory tier is not an AES-512 key"
    assert sizes <= {256, None}


def test_bare_modulus_still_sizes_rsa():
    dets = _keys(
        'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); '
        "kpg.initialize(1024);",
        "java",
    )
    assert any(d.key_size == 1024 for d in dets.get("rsa", []))


KOTLIN_LABELS = '''package com.example.ui
@Composable fun Bar() {
    Text(text = "Scrypt Tier (GPU-Proof)", fontSize = 9.sp)
    Text(text = "AES-256-GCM", fontSize = 9.sp)
    val status: String = "Drag or pick files to encrypt with ENC5F \
(AES-256-GCM & Scrypt)"
    val cipherEngine: String = "AES-256-GCM (scrypt)"
}
'''


def test_kotlin_ui_labels_are_not_algorithm_use():
    assert _keys(KOTLIN_LABELS, "java") == {}


JS_CONFIG = '''const KEY_CONFIGS = {
  "Key 1": { kdf: "scrypt", scryptN: 16384, scryptR: 8, scryptP: 1 },
};
el.kdfLabelBadge.textContent = `Scrypt (${memMb}MB RAM) + AES-256-GCM AEAD`;
updateStatus(`Text Encrypted (${conf.alias})`, "success", \
`AES-256-GCM AEAD | Scrypt Memory-Hard`);
'''


def test_js_settings_and_labels_are_not_algorithm_use():
    assert "scrypt" not in _keys(JS_CONFIG, "javascript")
    assert "aes" not in _keys(JS_CONFIG, "javascript")


JS_REAL = '''const nodeCrypto = require("crypto");
async function deriveScrypt(pw, salt, N, r, p) {
  return nodeCrypto.scryptSync(pw, salt, 32, { N, r, p, maxmem: 1 << 30 });
}
const c = nodeCrypto.createCipheriv('aes-256-gcm', key, iv);
const k = await crypto.subtle.importKey("raw", raw, \
{ name: "AES-GCM", length: 256 }, false, ["encrypt"]);
'''


def test_real_js_crypto_calls_are_found():
    keys = _keys(JS_REAL, "javascript")
    assert "scrypt" in keys, "crypto.scryptSync is a scrypt call"
    assert "aes-256" in keys or any(d.key_size == 256 for d in keys.get("aes", []))
    assert "aes" in keys  # WebCrypto AES-GCM


KOTLIN_REAL = '''package com.example.crypto
import javax.crypto.Cipher
object Fernet {
    fun seal(key: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val md = java.security.MessageDigest.getInstance("SHA-256")
        return Scrypt.scrypt(password, salt, N = 16384, r = 8, p = 1, dkLen = 32)
    }
}
'''


def test_real_kotlin_crypto_calls_are_found():
    keys = _keys(KOTLIN_REAL, "java")
    assert "scrypt" in keys
    assert "aes" in keys
    assert "sha256" in keys


PY_CONFIG = '''HAS_ARGON2 = True
KEY_CONFIGS = {"Key 1": {"kdf": "argon2id" if HAS_ARGON2 else "scrypt", \
"cipher": "AES-256-GCM"}}
'''
PY_REAL = '''import hashlib
from passlib.context import CryptContext
ctx = CryptContext(schemes=["bcrypt"])
def derive(material, salt):
    return hashlib.scrypt(material, salt=salt, n=2**17, r=8, p=1, dklen=32)
'''


def test_python_settings_value_is_not_scrypt_but_calls_are():
    assert "scrypt" not in _keys(PY_CONFIG, "python")
    keys = _keys(PY_REAL, "python")
    assert "scrypt" in keys and "bcrypt" in keys


def test_encdec_repro_counts(tmp_path):
    """The reviewer's EncDec-Pro shape: labels and settings no longer add scrypt /
    AES-512 rows, the real scrypt
    calls stay, and no row is quantum-safe only because a label named it."""
    out = _scan(tmp_path, {
        "android/KeyProfile.kt": KOTLIN_PROFILE,
        "android/Bar.kt": KOTLIN_LABELS,
        "android/Fernet.kt": KOTLIN_REAL,
        "web/crypto.js": JS_CONFIG + JS_REAL,
        "server.py": PY_CONFIG,
        "cli.py": PY_REAL,
    })
    titles = _titles(out)
    assert not any("512" in t and t.upper().startswith("AES") for t in titles), titles
    scrypt_files = sorted(
        r["location"] for r in out["results"] if r["title"] == "scrypt"
    )
    assert scrypt_files == ["android/Fernet.kt", "cli.py", "web/crypto.js"], (
        scrypt_files
    )
    assert not any(r["location"] == "android/Bar.kt" for r in out["results"]), (
        "labels are no inventory"
    )


# ----------------------------------------------------------------------------- Q2-01
# one risk score
def test_cbom_scores_is_the_posture_score_of_the_findings(tmp_path):
    out = _scan(tmp_path, {"app.py": '''import hashlib
def password_digest(password):
    return hashlib.md5(password.encode()).hexdigest()
from cryptography.hazmat.primitives.asymmetric import rsa
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
'''})
    scores = out["cbom_scores"]
    counts = scores["severity_counts"]
    assert sum(counts.values()) >= 2
    score, grade, label = posture_risk(
        counts["critical"], counts["high"], counts["medium"], counts["low"]
    )
    assert (scores["risk_normalized"], scores["risk_grade"], scores["risk_label"]) == (
        float(score),
        grade,
        label,
    )
    assert scores["risk_band"] == label.split()[0].lower()
    # the counts are the result rows' findings (impact, Low when none), as every D3
    # surface counts them
    rows = [
        r
        for r in out["results"]
        if r.get("finding_codes") or r.get("weak") or r.get("quantum_vulnerable")
    ]
    assert sum(counts.values()) == len(rows)


def test_worst_severity_cap_applies(tmp_path):
    out = _scan(
        tmp_path,
        {
            f"m{i}.py": "import hashlib\n"
            f"def checksum_{i}(path):\n"
            "    return hashlib.md5(open(path,'rb').read()).hexdigest()\n"
            for i in range(12)
        },
    )
    scores = out["cbom_scores"]
    assert scores["severity_counts"]["critical"] == 0
    assert scores["severity_counts"]["high"] == 0
    assert scores["risk_normalized"] <= 49  # no Critical or High: at most C


# ----------------------------------------------------------------------------- G-D3-6
# MD5
def test_md5_cache_key_is_low_without_the_certificate_cve(tmp_path):
    out = _scan(tmp_path, {"router.py": '''import hashlib
_PROMPT_ANALYSIS_CACHE = {}
def route(prompt):
    prompt_hash = hashlib.md5(prompt.encode()).hexdigest()
    if prompt_hash in _PROMPT_ANALYSIS_CACHE:
        return _PROMPT_ANALYSIS_CACHE[prompt_hash]
'''})
    md5 = [r for r in out["results"] if r["title"] == "MD5"]
    assert md5, "the broken hash stays in the inventory with its weak-hash finding"
    row = md5[0]
    assert row["finding_codes"] == ["WEAK_ALGORITHM"]
    assert row["impact"] == "Low"
    assert "CVE-2004-2761" not in row["cves"]
    assert row["quantum_safe"] is not True


def test_md5_security_use_is_high_and_never_quantum_safe(tmp_path):
    out = _scan(tmp_path, {"auth.py": '''import hashlib
def store(password):
    return hashlib.md5(password.encode()).hexdigest()
'''})
    row = next(r for r in out["results"] if r["title"] == "MD5")
    assert row["impact"] == "High"
    assert (
        row["quantum_safe"] is False and row["quantum_vulnerable"] is False
    )  # "Broken today"
    assert "CVE-2004-2761" not in row["cves"], (
        "CVE-2004-2761 is MD5 in a certificate signature"
    )


# ----------------------------------------------------------------------------- Q2-11
# scrypt
def test_scrypt_is_graded_by_cost_without_a_prf(tmp_path):
    out = _scan(tmp_path, {"kdf.py": "from cryptography.hazmat.primitives.kdf.scrypt "
                           + '''import Scrypt
from cryptography.hazmat.primitives import hashes
def derive(salt):
    return Scrypt(algorithm=hashes.SHA256(), length=32, salt=salt, n=2**14, r=8, p=1)
'''})
    row = next(r for r in out["results"] if r["title"] == "scrypt")
    assert row["finding_codes"] == ["WEAK_KDF_COST"]
    assert "WEAK_KDF_ITERATIONS" not in row["finding_codes"]
    comp = next(
        c for c in out["cbom_json"]["components"] if c["bom-ref"] == row["bom_ref"]
    )
    props = {p["name"]: p["value"] for p in comp.get("properties", [])}
    assert "crypto:kdfPrf" not in props
    assert props["crypto:scryptN"] == "16384"


# ----------------------------------------------------------------------------- Q2-09
# one library row
def test_range_lower_bound_is_unverified_not_a_finding(tmp_path):
    out = _scan(
        tmp_path,
        {
            "requirements.txt": "cryptography>=38.0.0\n",
            "app.py": _FERNET_APP,
        },
    )
    libs = [
        c
        for c in out["cbom_json"]["components"]
        if c["type"] == "library" and "cryptography" in c["name"]
    ]
    assert len(libs) == 1, [c["name"] for c in libs]
    lib = libs[0]
    assert "@" not in lib["name"], "a range is never part of the name"
    assert lib.get("purl") == "pkg:pypi/cryptography"
    props = {p["name"]: p["value"] for p in lib.get("properties", [])}
    assert props["crypto:versionVerified"] == "false"
    assert int(props["crypto:unverifiedAdvisoryCount"]) > 0
    assert not [
        r
        for r in out["results"]
        if "VULNERABLE_CRYPTO_LIBRARY" in (r.get("finding_codes") or [])
    ]


def test_a_lockfile_version_wins_over_the_range(tmp_path):
    """``cryptography>=41.0`` with uv.lock at 43.0.1: the row has a real version, so it
    is not called unverified and the range's lower-bound advisories are not listed
    (the bank fixture said "no lockfile resolves it" next to uv.lock's 43.0.1)."""
    out = _scan(
        tmp_path,
        {
            "requirements.txt": "cryptography>=41.0\n",
            "uv.lock": 'version = 1\n\n[[package]]\nname = "cryptography"\n'
            'version = "43.0.1"\nsource = { registry = "https://pypi.org/simple" }\n',
            "app.py": _FERNET_APP,
        },
    )
    libs = [
        c
        for c in out["cbom_json"]["components"]
        if c["type"] == "library" and "cryptography" in c["name"]
    ]
    assert [c["name"] for c in libs] == ["pyca/cryptography"]
    assert libs[0]["version"] == "43.0.1"
    props = {p["name"]: p["value"] for p in libs[0].get("properties", [])}
    assert "crypto:versionVerified" not in props
    assert "crypto:unverifiedAdvisories" not in props


def test_exact_pin_is_its_own_flagged_row_linked_to_the_library(tmp_path):
    """An exact pin keeps origin/dev's shape: the D1 lane judges the manifest row
    "cryptography@38.0.0" (bench/cbom/d1 NR-LIB-detected); it links to the code lane's
    pyca/cryptography row, which the PDF and served BOM list as one library."""
    out = _scan(
        tmp_path,
        {
            "requirements.txt": "cryptography==38.0.0\n",
            "app.py": _FERNET_APP,
        },
    )
    comps = {c["name"]: c for c in out["cbom_json"]["components"]}
    pin = comps["cryptography@38.0.0"]
    props = {p["name"]: p["value"] for p in pin.get("properties", [])}
    assert props["crypto:libraryRef"] == comps["pyca/cryptography"]["bom-ref"]
    assert props["discovery:source"] == "requirements.txt"
    flagged = [
        r
        for r in out["results"]
        if "VULNERABLE_CRYPTO_LIBRARY" in (r.get("finding_codes") or [])
    ]
    assert len(flagged) == 1 and flagged[0]["bom_ref"] == pin["bom-ref"]


# ----------------------------------------------------------------------------- Q2-04 /
# N7 CERT-In
def _cert_in(out: dict) -> dict:
    return {r["id"]: r for r in out["cbom_compliance"]["cert_in_cbom"]["requirements"]}


def test_cert_in_oid_reads_the_algorithms_oids(tmp_path):
    out = _scan(tmp_path, {"a.py": '''import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
hashlib.sha256(b"x").hexdigest()
rsa.generate_private_key(public_exponent=65537, key_size=3072)
'''})
    algos = [c for c in out["cbom_json"]["components"]
             if (c.get("cryptoProperties") or {}).get("assetType") == "algorithm"]
    with_oid = [c for c in algos if c["cryptoProperties"].get("oid")]
    assert with_oid
    req = _cert_in(out)["T9-Algorithms-OID"]
    if len(with_oid) == len(algos):
        assert req["verdict"] == "pass"
    assert "not present" not in req["evidence"]
    for c in with_oid:  # the graph fact the check reads is the CycloneDX oid
        props = {p["name"]: p["value"] for p in c.get("properties", [])}
        assert props["crypto:oid"] == c["cryptoProperties"]["oid"]


def test_cert_in_mode_only_judges_block_ciphers(tmp_path):
    out = _scan(
        tmp_path, {"h.py": "import hashlib\nhashlib.sha256(b'x').hexdigest()\n"}
    )
    req = _cert_in(out)["T9-Algorithms-Mode"]
    # a hash has no mode of operation: nothing is missing
    assert req["verdict"] == "pass", req


def test_cert_in_cbom_and_vex_emission_are_evidenced_by_the_scan(tmp_path):
    out = _scan(
        tmp_path, {"h.py": "import hashlib\nhashlib.sha256(b'x').hexdigest()\n"}
    )
    reqs = _cert_in(out)
    assert reqs["8.4.1.5"]["verdict"] == "pass"
    assert reqs["8.4.1.6"]["verdict"] == "pass"


# ----------------------------------------------------------------------------- N2 weak-
# crypto chart by impact
def test_weakness_impacts_split_the_chart_by_severity(tmp_path):
    out = _scan(tmp_path, {"kdf.py": '''import hashlib
def derive(material, salt):
    return hashlib.scrypt(material, salt=salt, n=2**14, r=8, p=1, dklen=32)
def store(password):
    return hashlib.md5(password.encode()).hexdigest()
'''})
    impacts = out["cbom_distributions"]["weakness_impacts"]
    assert impacts["WEAK_KDF_COST"] == {"Low": 1}
    assert impacts["WEAK_ALGORITHM"] == {"High": 1}
    assert {k: sum(v.values()) for k, v in impacts.items()} == out[
        "cbom_distributions"
    ]["weakness"]


@pytest.mark.parametrize("line", ['"AES/CBC/PKCS5Padding"', "'aes-128-cbc'"])
def test_api_strings_without_spaces_are_kept(line):
    lang = "java" if "/" in line else "javascript"
    call = (
        f"Cipher.getInstance({line})"
        if lang == "java"
        else f"crypto.createCipheriv({line}, k, iv)"
    )
    assert _keys(call, lang), call
