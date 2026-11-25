"""PR #500 takeover, round 2: what the first takeover left open.

* Configuration literals: a string literal is algorithm USE only when it flows into
  a crypto call (an argument, a name or key a crypto call reads) or is the value of
  a key a crypto library reads. App settings (``"cipher": "AES-256-GCM"``), display
  labels and Kotlin data-class defaults are low-confidence ``config_evidence``,
  not inventoried and not counted (IBM sonar-cryptography / CBOMkit detect API
  calls, not bare strings).
* Test code: a finding in test, fixture or example code is Low and labelled
  ``test code``, still listed.
* MD5 / SHA-1 ``classicalSecurityLevel``: their collision strength as attacked
  today (MD5 18, RFC 6151; SHA-1 63, SHAttered / Shambles), the same number in the
  CycloneDX file and in the result row the UI and the PDF read.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aibom.cbom.code_context import is_test_path
from aibom.cbom.detect import detect_crypto
from aibom.integrations.cbom_devsecshield import scan_crypto_to_devsecshield


def _scan(tmp_path: Path, files: dict[str, str]) -> dict:
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return scan_crypto_to_devsecshield(str(tmp_path), level=4)


def _keys(text: str, lang: str) -> tuple[set[str], list[dict]]:
    ev: list[dict] = []
    return {d.key for d in detect_crypto(text, lang, config_evidence=ev)}, ev


# -----------------------------------------------------------------------------
# configuration literals
@pytest.mark.parametrize(
    ("lang", "text"),
    [
        (
            "python",
            'KEY_CONFIGS = {"Key 1": {"kdf": "scrypt", "cipher": "AES-256-GCM"}}\n',
        ),
        ("python", 'CONF = {\n    "cipher": "AES-256-GCM",\n}\n'),
        (
            "python",
            'INFO = {"kdf_engines": ["Argon2id" if HAS else "Scrypt (Memory-Hard)", '
            '"PBKDF2-HMAC-SHA256 (Legacy Decrypt)"]}\n',
        ),
        (
            "java",
            "data class KeyProfile(\n    val name: String,\n"
            '    val cipher: String = "AES-256-GCM",\n)\n',
        ),
        ("javascript", 'const KEY_CONFIGS = {\n  cipher: "AES-256-GCM",\n};\n'),
    ],
)
def test_settings_and_labels_are_configuration_evidence_not_assets(lang, text):
    keys, ev = _keys(text, lang)
    assert keys == set(), keys
    assert ev and all(e["binding"] for e in ev), ev


@pytest.mark.parametrize(
    ("lang", "text", "key"),
    [
        # the constant flows into the crypto call
        (
            "java",
            'private static final String ALGO = "AES/CBC/PKCS5Padding";\n'
            "Cipher c = Cipher.getInstance(ALGO);\n",
            "aes",
        ),
        # the settings key is read by a crypto call
        (
            "python",
            'CONF = {"cipher": "AES-256-GCM"}\nc = make_cipher(CONF["cipher"])\n',
            "aes",
        ),
        # an argument of a call
        ("python", 'h = hashlib.new("md5")\n', "md5"),
        ("java", 'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");\n', "aes"),
        # a key the crypto library itself reads
        ("python", 'SETTINGS = {"ALGORITHM": "MD5"}\n', "md5"),
        # WebCrypto algorithm objects (name / hash read by crypto.subtle)
        ("javascript", 'const alg = { name: "AES-GCM", length: 256 };\n', "aes"),
        (
            "javascript",
            'await crypto.subtle.encrypt(\n  { name: "AES-GCM", iv },\n  key, data);\n',
            "aes",
        ),
        # no binding at all: left to the existing rules
        ("python", 'if alg == "MD5":\n    pass\n', "md5"),
        (
            "javascript",
            "function f() {\n  const alg = 'md5';\n  return run(alg);\n}\n",
            "md5",
        ),
    ],
)
def test_literals_that_flow_into_crypto_stay(lang, text, key):
    keys, _ev = _keys(text, lang)
    assert key in keys, keys


@pytest.mark.parametrize("lang", ["java", "javascript"])
def test_locals_in_a_method_body_are_statements_not_settings(lang):
    """A brace after a signature opens a block: its bindings are statements that
    may reach a crypto call in another method (CryptoAPI-Bench interprocedural and
    multiple-class cases, a D1 floor), never object-literal settings."""
    from aibom.cbom.detect import _ConfigLiterals

    lines = [
        "class A {",
        "  void m() {",
        '    String c = "DES/ECB/PKCS5Padding";',
        "    go(c);",
        "  }",
        "}",
    ]
    assert _ConfigLiterals(lines, lang).unused_spans(2, lines[2]) == []


def test_a_call_spelled_inside_a_string_is_no_call():
    keys, _ev = _keys('X = ["Scrypt (Memory-Hard)"]\n', "python")
    assert "scrypt" not in keys


def test_scan_reports_configuration_evidence_outside_the_totals(tmp_path):
    out = _scan(
        tmp_path,
        {
            "server.py": "import hashlib\n"
            'KEY_CONFIGS = {"Key 1": {"cipher": "AES-256-GCM"}}\n'
            "def digest(b):\n    return hashlib.sha256(b).hexdigest()\n",
            "app/KeyProfile.kt": "data class KeyProfile(\n"
            '    val cipher: String = "AES-256-GCM",\n)\n',
        },
    )
    titles = {r["title"] for r in out["results"]}
    assert titles == {"SHA-256"}, titles
    ev = out["config_evidence"]
    assert {(e["location"], e["binding"]) for e in ev} == {
        ("server.py", "cipher"),
        ("app/KeyProfile.kt", "cipher"),
    }
    assert all(e["confidence"] == "low" and e["kind"] == "configuration" for e in ev)
    props = {
        p["name"]: p["value"]
        for p in out["cbom_json"]["metadata"].get("properties", [])
    }
    assert props.get("crypto:configEvidenceCount") == "2"
    assert "crypto:configEvidence" not in props
    assert not any("AES" in c["name"] for c in out["cbom_json"]["components"])


# ----------------------------------------------------------------------------- test
# code
@pytest.mark.parametrize(
    ("path", "test"),
    [
        ("tests/test_backend_contract.py", True),
        ("test_app.py", True),
        ("pkg/x_test.go", True),
        ("src/test/java/CryptoTest.java", True),
        ("web/a.spec.ts", True),
        ("examples/demo.py", True),
        ("spec/fixtures/key.pem", True),
        ("src/app.py", False),
        ("contest/app.py", False),
        ("latest/app.py", False),
        ("testimony.py", False),
        ("app/specification.py", False),
    ],
)
def test_test_paths(path, test):
    assert is_test_path(path) is test


def test_a_finding_in_test_code_is_low_labelled_and_listed(tmp_path):
    src = "import hashlib\ndef f(pw):\n    return hashlib.md5(pw).hexdigest()\n"
    out = _scan(tmp_path, {"app.py": src, "tests/test_app.py": src})
    md5 = {r["location"]: r for r in out["results"] if r["title"] == "MD5"}
    assert md5["app.py"]["impact"] == "High" and md5["app.py"]["code_context"] is None
    t = md5["tests/test_app.py"]
    assert t["impact"] == "Low" and t["code_context"] == "test"
    assert t["finding_codes"] == md5["app.py"]["finding_codes"], (
        "kept visible with its code"
    )
    assert "test code" in t["description"].lower()
    # the risk score counts it at Low
    assert out["cbom_scores"]["severity_counts"]["high"] == 1


# -----------------------------------------------------------------------------
# classical strength
def test_md5_and_sha1_classical_level_is_their_collision_strength(tmp_path):
    out = _scan(
        tmp_path,
        {
            "h.py": "import hashlib\nhashlib.md5(b'x')\nhashlib.sha1(b'x')\n"
            "hashlib.sha256(b'x')\n"
        },
    )
    cdx = {
        c["name"]: c["cryptoProperties"]["algorithmProperties"].get(
            "classicalSecurityLevel"
        )
        for c in out["cbom_json"]["components"]
        if (c.get("cryptoProperties") or {}).get("assetType") == "algorithm"
    }
    rows = {r["title"]: r["security_strength_bits"] for r in out["results"]}
    assert cdx["MD5"] == rows["MD5"] == 18
    assert cdx["SHA-1"] == rows["SHA-1"] == 63
    assert cdx["SHA-256"] == rows["SHA-256"] == 128
