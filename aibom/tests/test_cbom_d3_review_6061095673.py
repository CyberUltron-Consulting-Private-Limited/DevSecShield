"""PR #500 review 6061095673 (round 4): the reviewer's probes as tests.

1. A settings value declared in one file and read by a crypto call in another is an
   asset that names both places; a setting no read is proven for stays an asset at
   low confidence (recall never below the literal lane's). Spring ``@Value`` defaults
   and ``self.ALG`` into ``jwt.encode`` are found.
2. Test code is labelled and listed but never counted in the risk score.
4. A line continuation with escaped quotes inside a literal keeps the real call.
5. Crypto calls are matched by identifier tokens; comparisons, argparse choices,
   case / when labels, TS unions and Enum members are configuration mentions.
6. The configuration mentions are listed in the CycloneDX metadata (valid 1.6).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aibom.cbom.detect import _is_crypto_callee, detect_crypto
from aibom.integrations.cbom_devsecshield import scan_crypto_to_devsecshield


def _scan(tmp_path: Path, files: dict[str, str]) -> dict:
    for name, text in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return scan_crypto_to_devsecshield(str(tmp_path), level=4)


def _rows(out: dict) -> dict[tuple[str, str], dict]:
    return {(r["title"], r["location"]): r for r in out["results"]}


def _keys(text: str, lang: str) -> tuple[set[str], list[dict]]:
    ev: list[dict] = []
    return {d.key for d in detect_crypto(text, lang, config_evidence=ev)}, ev


# ----------------------------------------------------------------------------- 1
CROSS_FILE = {
    "kotlin": (
        {
            "k/Cfg.kt": "package x\ndata class CryptoCfg(val spec: String = "
            '"DESede/ECB/PKCS5Padding", val digest: String = "MD5")\n',
            "k/Enc.kt": "package x\nimport javax.crypto.Cipher\n"
            "import java.security.MessageDigest\nfun enc(cfg: CryptoCfg) {\n"
            "    val c = Cipher.getInstance(cfg.spec)\n"
            "    val d = MessageDigest.getInstance(cfg.digest)\n}\n",
        },
        {("MD5", "k/Cfg.kt"): "k/Enc.kt:6"},
        ("3DES", "k/Cfg.kt"),
    ),
    "pydantic": (
        {
            "settings.py": "from pydantic_settings import BaseSettings\n"
            "class Settings(BaseSettings):\n    hash_name: str = 'md5'\n"
            "settings = Settings()\n",
            "crypto.py": "import hashlib\nfrom settings import settings\n"
            "def h(d):\n    return hashlib.new(settings.hash_name, d).hexdigest()\n",
        },
        {("MD5", "settings.py"): "crypto.py:4"},
        None,
    ),
    "dict": (
        {
            "config.py": "CONFIG = {'digest': 'sha1', 'rounds': 3}\n",
            "use.py": "import hashlib\nfrom config import CONFIG\n"
            "def h(d):\n    return hashlib.new(CONFIG['digest'], d).hexdigest()\n",
        },
        {("SHA-1", "config.py"): "use.py:4"},
        None,
    ),
    "node": (
        {
            "config.js": "module.exports = "
            "{ cipher: 'des-ede3-cbc', digest: 'md5' };\n",
            "use.js": "const crypto = require('crypto');\n"
            "const cfg = require('./config');\n"
            "function enc(k, iv, d) {\n"
            "  return crypto.createCipheriv(cfg.cipher, k, iv); }\n"
            "function h(d) { return crypto.createHash(cfg.digest).update(d); }\n",
        },
        {("MD5", "config.js"): "use.js:5"},
        ("3DES", "config.js"),
    ),
}


@pytest.mark.parametrize("case", sorted(CROSS_FILE))
def test_a_setting_read_by_a_crypto_call_in_another_file_is_a_proven_asset(
    tmp_path, case
):
    files, proven, prefixed = CROSS_FILE[case]
    out = _scan(tmp_path, files)
    rows = _rows(out)
    for key, read_at in proven.items():
        assert key in rows, sorted(rows)
        row = rows[key]
        assert row["config_read_at"] == read_at, row
        assert row["confidence"] != "low"
    if prefixed:
        title, loc = prefixed
        hit = [r for (t, ll), r in rows.items() if t.startswith(title) and ll == loc]
        assert hit and hit[0]["config_read_at"], sorted(rows)


def test_an_unread_setting_is_a_low_confidence_asset_not_dropped(tmp_path):
    out = _scan(tmp_path, {"conf.py": "CONF = {'digest': 'md5', 'rounds': 3}\n"})
    rows = _rows(out)
    row = rows[("MD5", "conf.py")]
    assert row["confidence"] == "low" and row["config_binding"] == "digest"
    assert not row["config_read_at"]


def test_spring_value_default_into_cipher_get_instance(tmp_path):
    out = _scan(
        tmp_path,
        {
            "Svc.java": (
                "import javax.crypto.Cipher;\n"
                "import org.springframework.beans.factory.annotation.Value;\n"
                "class Svc {\n"
                '    @Value("${crypto.alg:DES/ECB/PKCS5Padding}")\n'
                "    private String alg;\n"
                "    byte[] enc(byte[] d) throws Exception {\n"
                "        Cipher c = Cipher.getInstance(alg);\n"
                "        return c.doFinal(d);\n    }\n}\n"
            )
        },
    )
    titles = {r["title"] for r in out["results"]}
    assert any(t.startswith("DES") for t in titles), titles


def test_self_class_attribute_into_jwt_encode(tmp_path):
    out = _scan(
        tmp_path,
        {
            "tok.py": (
                "import jwt\nclass Tokens:\n    ALG = 'none'\n"
                "    def make(self, p, k):\n"
                "        return jwt.encode(p, k, algorithm=self.ALG)\n"
            )
        },
    )
    rows = [r for r in out["results"] if r["location"] == "tok.py" and r["line"] == 5]
    assert rows, [(r["title"], r["line"]) for r in out["results"]]


# ----------------------------------------------------------------------------- 2
def test_test_files_never_raise_the_grade(tmp_path):
    app = {
        "app/crypto.py": "import hashlib\n"
        "def h(b):\n    return hashlib.md5(b).hexdigest()\n"
    }
    base = _scan(tmp_path / "a", app)["cbom_scores"]
    tests = {
        f"tests/test_{n}.py": "import hashlib\nfrom Crypto.Cipher import DES\n"
        "def t(b, k):\n    hashlib.md5(b)\n    hashlib.sha1(b)\n"
        "    return DES.new(k, DES.MODE_ECB)\n"
        for n in range(6)
    }
    with_tests = _scan(tmp_path / "b", {**app, **tests})
    scores = with_tests["cbom_scores"]
    assert (scores["risk_normalized"], scores["risk_grade"]) == (
        base["risk_normalized"],
        base["risk_grade"],
    )
    assert scores["risk_total"] == base["risk_total"]
    listed = [r for r in with_tests["results"] if r.get("code_context") == "test"]
    assert listed and all(r["impact"] == "Low" for r in listed if r["impact"])


# ----------------------------------------------------------------------------- 4
def test_continuation_with_escaped_quotes_in_a_literal_keeps_the_call():
    text = (
        'import hashlib\nsig = hashlib.md5(b"k=\\"v\\"" + body).hexdigest() + \\\n'
        "    x\n"
    )
    keys, _ev = _keys(text, "python")
    assert "md5" in keys


def test_escaped_text_outside_strings_keeps_a_real_call_on_the_line():
    text = (
        "import hashlib\n"
        'h = hashlib.md5(b).hexdigest(); x = {\\"c\\": \\"AES-256-GCM\\"}\n'
    )
    keys, ev = _keys(text, "python")
    assert "md5" in keys and "aes" not in keys and ev


# ----------------------------------------------------------------------------- 5
@pytest.mark.parametrize(
    ("chain", "crypto"),
    [
        ("Object.assign", False),
        ("conversation.send", False),
        ("universal.load", False),
        ("assignRole", False),
        ("CryptoCfg", False),
        ("crypto.createCipheriv", True),
        ("crypto.createHash", True),
        ("hashlib.new", True),
        ("Cipher.getInstance", True),
        ("MessageDigest.getInstance", True),
        ("jwt.encode", True),
        ("signer.sign", True),
        ("RSA.generate", True),
        ("SecretKeySpec", True),
    ],
)
def test_crypto_callees_are_matched_by_identifier_tokens(chain, crypto):
    assert _is_crypto_callee(chain) is crypto


@pytest.mark.parametrize(
    ("lang", "text"),
    [
        (
            "python",
            "def f(algo):\n    if algo == 'md5':\n        raise ValueError(algo)\n",
        ),
        (
            "java",
            'class A {\n  boolean f(String n) {\n    return "MD5".equals(n);\n  }\n}\n',
        ),
        (
            "python",
            "import argparse\np = argparse.ArgumentParser()\n"
            "p.add_argument('--checksum', choices=['md5', 'sha1'])\n",
        ),
        (
            "javascript",
            "function f(a) {\n  switch (a) {\n"
            "    case 'md5':\n      return 1;\n  }\n}\n",
        ),
        (
            "java",
            'class A {\n  int f(String a) {\n    return when (a) {\n      "MD5" -> 1\n'
            "      else -> 0\n    }\n  }\n}\n",
        ),
        ("javascript", "type Hash = 'md5' | 'sha1';\n"),
        (
            "python",
            "from enum import Enum\n"
            "class Algo(Enum):\n    MD5 = 'md5'\n    SHA1 = 'sha1'\n",
        ),
    ],
)
def test_mentions_are_configuration_evidence(lang, text):
    keys, ev = _keys(text, lang)
    assert not keys & {"md5", "sha1"}, keys
    assert ev


def test_an_enum_member_read_by_a_crypto_call_is_an_asset():
    text = (
        "import hashlib\nfrom enum import Enum\nclass Algo(Enum):\n    MD5 = 'md5'\n"
        "def h(b):\n    return hashlib.new(Algo.MD5.value, b)\n"
    )
    keys, _ev = _keys(text, "python")
    assert "md5" in keys


def test_object_assign_is_a_mention_and_a_const_object_an_unconfirmed_setting(tmp_path):
    """Re-review 6063599094: an object handed to ``Object.assign`` is a mention (no
    crypto call reads its target); a declared settings object no crypto call reads is
    an unconfirmed setting, listed and not scored."""
    a = _scan(
        tmp_path / "a",
        {"a.js": "Object.assign(settings, { cipher: 'AES-256-GCM' });\n"},
    )
    b = _scan(tmp_path / "b", {"b.js": "const settings = { cipher: 'AES-256-GCM' };\n"})
    assert a["results"] == [] and a["config_evidence"]
    rb = [(r["title"], r.get("config_status")) for r in b["results"]]
    assert rb and all(status == "unconfirmed" for _t, status in rb)


# ----------------------------------------------------------------------------- 6
def test_mentions_are_listed_in_the_bom_metadata_and_it_stays_valid(tmp_path):
    out = _scan(
        tmp_path, {"a.py": "def f(algo):\n    if algo == 'md5':\n        return 1\n"}
    )
    assert out["config_evidence"] and out["config_evidence_total"] == len(
        out["config_evidence"]
    )
    props = out["cbom_json"]["metadata"]["properties"]
    mentions = [
        json.loads(p["value"]) for p in props if p["name"] == "crypto:configMention"
    ]
    assert mentions and mentions[0]["location"] == "a.py" and mentions[0]["line"] == 2
    count = [p["value"] for p in props if p["name"] == "crypto:configEvidenceCount"]
    assert count == [str(len(out["config_evidence"]))]
    from aibom.emit.validate import validate_cyclonedx

    assert validate_cyclonedx(out["cbom_json"]) == []
