"""PR #500 re-review 6063599094 (round 5): the reviewer's probes as tests.

1. A setting no crypto call is proven to read is listed as "unconfirmed (configuration
   only)", Low, and weighs nothing in the score.
2. A read in another file proves a setting only through a real link: the reader
   imports the declaring module, or names the setting's owner symbol.
3. A Python Enum member read in another file is found again.
4. ``Object.assign(target, {...})`` and inline deny-list membership checks are
   mentions.
5. The CBOM's ``crypto:configMention`` carries no source text.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

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


# ----------------------------------------------------------------------------- 1
def test_an_unconfirmed_setting_is_listed_low_outside_the_confirmed_score(tmp_path):
    out = _scan(
        tmp_path, {"app/conf.py": "EXPORT = {'format': 'csv', 'checksum': 'md5'}\n"}
    )
    rows = [r for r in out["results"] if r["title"] == "MD5"]
    assert rows, out["results"]
    row = rows[0]
    assert row["config_status"] == "unconfirmed" and row["confidence"] == "low"
    assert row["impact"] == "Low"
    assert "unconfirmed (configuration only)" in row["description"].lower()
    scores = out["cbom_scores"]
    # round 7 (re-review 6066152368, #505's rule): never a clean A; the confirmed
    # score has nothing, so the headline is the setting's worst case, "unverified"
    assert scores["risk_posture_status"] == "unverified" and scores["risk_grade"] != "A"
    assert scores["severity_counts"] == dict.fromkeys(
        ("critical", "high", "medium", "low"), 0
    )
    comp = next(c for c in out["cbom_json"]["components"] if c["name"] == "MD5")
    props = {p["name"]: p["value"] for p in comp.get("properties", [])}
    assert props["crypto:configStatus"] == "unconfirmed"
    assert props["crypto:configStatusLabel"] == "unconfirmed (configuration only)"


def test_test_code_only_scan_is_zero_a(tmp_path):
    out = _scan(tmp_path, {"tests/test_h.py": "import hashlib\nhashlib.md5(b'x')\n"})
    scores = out["cbom_scores"]
    assert (scores["risk_normalized"], scores["risk_grade"]) == (0.0, "A")


# ----------------------------------------------------------------------------- 2
def test_a_leaf_name_read_in_an_unrelated_file_proves_nothing(tmp_path):
    out = _scan(
        tmp_path,
        {
            "src/ui/options.js": "export const exportOptions = "
            "{ digest: 'md5', cipher: 'none' };\n",
            "src/mail/digest.js": "export const mail = { digest: 'weekly' };\n",
            "src/sec/h.js": "const crypto = require('crypto');\n"
            "function h(o, d) { return crypto.createHash(o.digest).update(d); }\n",
        },
    )
    md5 = [r for r in out["results"] if r["title"] == "MD5"]
    assert md5 and all(r["config_status"] == "unconfirmed" for r in md5), md5
    assert all(not r["config_read_at"] for r in md5)


def test_an_import_or_owner_symbol_proves_a_setting(tmp_path):
    out = _scan(
        tmp_path,
        {
            "src/ui/options.js": "export const cryptoConfig = { digest: 'md5' };\n",
            "src/sec/h.js": "const crypto = require('crypto');\n"
            "import { cryptoConfig } from '../ui/options';\n"
            "function h(d) {\n"
            "  return crypto.createHash(cryptoConfig.digest).update(d); }\n",
        },
    )
    md5 = [r for r in out["results"] if r["title"] == "MD5"]
    assert md5 and md5[0]["config_read_at"] == "src/sec/h.js:4", md5
    assert md5[0]["config_status"] != "unconfirmed"


# ----------------------------------------------------------------------------- 3
def test_a_python_enum_member_read_in_another_file_is_found(tmp_path):
    out = _scan(
        tmp_path,
        {
            "app/algs.py": "from enum import Enum\n"
            "class Hash(str, Enum):\n    WEAK = 'md5'\n    OK = 'sha256'\n",
            "app/use.py": "import hashlib\nfrom app.algs import Hash\n"
            "def h(d):\n    return hashlib.new(Hash.WEAK.value, d)\n",
        },
    )
    titles = {r["title"] for r in out["results"]}
    assert "MD5" in titles, titles


# ----------------------------------------------------------------------------- 4
@pytest.mark.parametrize(
    ("lang", "text"),
    [
        ("javascript", "Object.assign(settings, { cipher: 'AES-256-GCM' });\n"),
        (
            "javascript",
            "function f(alg) {\n"
            "  if (['md5', 'sha1'].includes(alg)) throw new Error(alg);\n}\n",
        ),
        (
            "python",
            "def f(alg):\n    if alg in ('md5', 'sha1'):\n        raise ValueError\n",
        ),
        (
            "java",
            "class A {\n  void f(String alg) {\n"
            '    if (List.of("MD5", "SHA-1").contains(alg)) throw new X();\n  }\n}\n',
        ),
    ],
)
def test_merges_and_membership_checks_are_mentions(lang, text):
    keys, ev = _keys(text, lang)
    assert not keys & {"aes", "aes-256", "md5", "sha1"}, keys
    assert ev


def test_object_assign_target_read_by_a_crypto_call_is_an_asset():
    text = (
        "const crypto = require('crypto');\n"
        "Object.assign(settings, { cipher: 'aes-256-gcm' });\n"
        "const c = crypto.createCipheriv(settings.cipher, k, iv);\n"
    )
    keys, _ev = _keys(text, "javascript")
    assert keys & {"aes", "aes-256"}, keys


# ----------------------------------------------------------------------------- 5
def test_bom_mentions_carry_no_source_text(tmp_path):
    out = _scan(
        tmp_path,
        {
            "a.py": "def f(algo):\n"
            "    if algo == 'md5':  # TOKEN=s3cr3t\n"
            "        return 1\n"
        },
    )
    props = out["cbom_json"]["metadata"]["properties"]
    mentions = [
        json.loads(p["value"]) for p in props if p["name"] == "crypto:configMention"
    ]
    assert mentions == [{"algorithm": "md5", "line": 2, "location": "a.py"}]
    assert out["config_evidence"][0]["value"], "the API keeps the text for the team"
