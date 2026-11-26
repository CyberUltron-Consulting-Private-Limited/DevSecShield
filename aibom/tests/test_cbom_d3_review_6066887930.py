"""PR #500 re-review 6066887930 (round 8): the reviewer's probes as tests.

1. Contract with #505: ``risk_unverified`` carries ``kind: "unconfirmed_setting"``.
2. ``Object.assign`` layouts that lost 3DES: ``module.exports = Object.assign({},
   require('./base'), {...})`` read from another file; a member target
   ``app.settings = Object.assign(...)``; a function returning ``Object.assign(...)``.
3. Partials: node-config JSON parsed structurally (nested, minified) and
   ``config.get('x').y``; a top-level deny-list is a mention; a typed getter proof
   never falls back to a name-only match; a Spring getter feeding
   ``Cipher.getInstance`` in another file gives a row; ``reg.HASHERS.get()``
   confirms a registry; an RSA-1024 setting row; Blowfish everywhere.
"""

from __future__ import annotations

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


def _rows(out: dict) -> dict[str, tuple[str | None, str | None]]:
    return {
        r["title"]: (r.get("config_status"), r.get("config_read_at"))
        for r in out["results"]
    }


def _confirmed(rows: dict, prefix: str) -> bool:
    hits = [v for t, v in rows.items() if t.startswith(prefix)]
    return bool(hits) and all(status != "unconfirmed" for status, _r in hits)


CRYPTO = "const crypto = require('crypto');\n"


# ----------------------------------------------------------------------------- 1
def test_risk_unverified_names_its_kind(tmp_path):
    out = _scan(tmp_path, {"app/conf.py": "EXPORT = {'checksum': 'md5'}\n"})
    assert out["cbom_scores"]["risk_unverified"]["kind"] == "unconfirmed_setting"


# ----------------------------------------------------------------------------- 2
@pytest.mark.parametrize(
    "files",
    [
        {
            "src/base.js": "module.exports = { mode: 'x' };\n",
            "src/settings.js": "module.exports = "
            "Object.assign({}, require('./base'), {\n"
            "  cipher: 'des-ede3-cbc',\n});\n",
            "src/use.js": CRYPTO + "const settings = require('./settings');\n"
            "const c = crypto.createCipheriv(settings.cipher, key, iv);\n",
        },
        {
            "src/a.js": CRYPTO + "const app = {};\n"
            "app.settings = Object.assign({}, defaults, { cipher: 'des-ede3-cbc' });\n"
            "const c = crypto.createCipheriv(app.settings.cipher, key, iv);\n",
        },
        {
            "src/a.js": CRYPTO + "function load() {\n"
            "  return Object.assign({}, defaults, {\n"
            "    cipher: 'des-ede3-cbc',\n  });\n"
            "}\nconst settings = load();\n"
            "const c = crypto.createCipheriv(settings.cipher, key, iv);\n",
        },
    ],
    ids=["module-exports", "member-target", "function-return"],
)
def test_object_assign_layouts_confirm_3des(tmp_path, files):
    rows = _rows(_scan(tmp_path, files))
    assert _confirmed(rows, "3DES"), rows


# ----------------------------------------------------------------------------- 3
_HASHER = (
    "const config = require('config');\n" + CRYPTO + "const h = crypto.createHash("
)


@pytest.mark.parametrize(
    ("config", "read"),
    [
        (  # minified
            '{"app":{"security":{"hashAlgorithm":"md5","rounds":3}},"port":80}',
            "config.get('app.security.hashAlgorithm')",
        ),
        (  # nested, inline objects on one line
            '{\n  "app": {\n'
            '    "security": { "hashAlgorithm": "md5", "x": {"y": 1} },\n'
            '    "z": 2\n  }\n}\n',
            "config.get('app.security.hashAlgorithm')",
        ),
        (  # config.get('x').y
            '{\n  "security": {\n    "hashAlgorithm": "md5"\n  }\n}\n',
            "config.get('security').hashAlgorithm",
        ),
    ],
    ids=["minified", "nested", "get-then-attribute"],
)
def test_node_config_json_is_parsed_structurally(tmp_path, config, read):
    out = _scan(
        tmp_path, {"config/default.json": config, "src/h.js": _HASHER + read + ");\n"}
    )
    rows = [r for r in out["results"] if r["title"] == "MD5"]
    assert rows and rows[0]["location"] == "config/default.json", out["results"]
    assert rows[0].get("config_status") is None
    assert rows[0].get("config_read_at") == "src/h.js:3"


@pytest.mark.parametrize(
    "use",
    [
        "if (WEAK.has(alg)) throw new Error(alg);\n",
        "if (WEAK.has(alg)) {\n  throw new Error(alg);\n}\n",
        "if (WEAK.has(alg)) {\n  res.status(400).send('weak hash');\n  return;\n}\n",
        "if (WEAK.has(alg)) return res.status(400).end();\n",
    ],
)
def test_a_top_level_deny_list_is_a_mention(use):
    """A list only warned about stays a finding (test_cbom_review5_detector_fps):
    the work goes on with the name. A rejecting guard makes it a deny-list."""
    text = "const WEAK = new Set(['md5', 'sha1']);\n" + use
    ev: list[dict] = []
    keys = {d.key for d in detect_crypto(text, "javascript", config_evidence=ev)}
    assert not keys & {"md5", "sha1"}, keys
    assert {e["line"] for e in ev} == {1}, ev


_SEC_PROPS = (
    "package com.x;\n"
    "import org.springframework.boot.context.properties.ConfigurationProperties;\n"
    '@ConfigurationProperties(prefix = "app.security")\n'
    "public class SecProps {\n"
    '  private String hashAlgorithm = "MD5";\n'
    "  public String getHashAlgorithm() { return hashAlgorithm; }\n"
    "}\n"
)


@pytest.mark.parametrize(
    "decl",
    ["var props = loader.load();", "private Object props;", "Props props;"],
)
def test_an_untyped_getter_never_proves_by_name(tmp_path, decl):
    """The reader names SecProps (it imports it) but reads ``props`` whose type is
    not SecProps or not known: no proof by the name alone."""
    hasher = (
        "package com.y;\nimport com.x.SecProps;\nimport java.security.MessageDigest;\n"
        "class Hasher {\n  SecProps unused;\n"
        "  byte[] h(byte[] d) throws Exception {\n"
        f"    {decl}\n"
        "    return MessageDigest.getInstance(props.getHashAlgorithm()).digest(d);\n"
        "  }\n}\n"
    )
    rows = _rows(
        _scan(tmp_path, {"src/SecProps.java": _SEC_PROPS, "src/Hasher.java": hasher})
    )
    assert rows.get("MD5", ("missing",))[0] == "unconfirmed", rows


def test_a_spring_getter_feeding_cipher_in_another_file_gives_a_row(tmp_path):
    props = (
        "import org.springframework.boot.context.properties.ConfigurationProperties;\n"
        '@ConfigurationProperties(prefix = "app")\npublic class CryptoProps {\n'
        '  private String transformation = "DES/ECB/PKCS5Padding";\n'
        "  public String getTransformation() { return transformation; }\n}\n"
    )
    enc = (
        "import javax.crypto.Cipher;\nclass Enc {\n  private CryptoProps props;\n"
        "  byte[] e(byte[] d, java.security.Key k) throws Exception {\n"
        "    Cipher c = Cipher.getInstance(props.getTransformation());\n"
        "    c.init(Cipher.ENCRYPT_MODE, k);\n    return c.doFinal(d);\n  }\n}\n"
    )
    rows = _rows(
        _scan(tmp_path, {"src/CryptoProps.java": props, "src/Enc.java": enc})
    )
    des = {t: v for t, v in rows.items() if t.startswith("DES")}
    assert des and all(v == (None, "src/Enc.java:5") for v in des.values()), rows


def test_a_registry_reached_through_its_module_confirms(tmp_path):
    rows = _rows(
        _scan(
            tmp_path,
            {
                "lib/reg.py": "import hashlib\nHASHERS = {'md5': hashlib.md5}\n",
                "app.py": "from lib import reg\n\ndef digest(name, data):\n"
                "    return reg.HASHERS.get(name)(data).hexdigest()\n",
            },
        )
    )
    assert rows.get("MD5") == (None, "app.py:4"), rows


@pytest.mark.parametrize(
    ("lang", "text"),
    [
        ("python", "KEY = {'algorithm': 'RSA', 'key_size': 1024}\n"),
        ("python", "KEY = {\n    'algorithm': 'RSA',\n    'key_size': 1024,\n}\n"),
        ("javascript", "const cfg = { alg: 'rsa', modulusLength: 1024 };\n"),
    ],
)
def test_an_rsa_1024_setting_is_a_row(lang, text):
    dets = detect_crypto(text, lang)
    assert [(d.key, d.key_size) for d in dets if d.key.startswith("rsa")] == [
        ("rsa", 1024)
    ], dets


@pytest.mark.parametrize(
    ("lang", "text"),
    [
        ("javascript", "const c = crypto.createCipheriv('bf-cbc', key, iv);\n"),
        ("javascript", "const c = crypto.createCipheriv('bf', key, iv);\n"),
        ("csharp", "var engine = new BlowfishEngine();\n"),
        ("java", "BlockCipher e = new BlowfishEngine();\n"),
    ],
)
def test_blowfish_is_detected(lang, text):
    assert "blowfish" in {d.key for d in detect_crypto(text, lang)}
