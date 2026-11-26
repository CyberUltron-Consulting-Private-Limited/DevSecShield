"""PR #500 re-review 6064703319 (round 6): the reviewer's probes as tests.

1. (Blocking) ``Object.assign(settings, {cipher: 'des-ede3-cbc'})`` read by
   ``createCipheriv(settings.cipher, ...)`` is a confirmed 3DES asset, also when the
   object spans lines: the assign target is the owner, an owner-qualified read
   proves it.
2. Common indirection resolves to confirmed: node-config
   (``config.get('security.hashAlgorithm')`` -> ``config/default.js`` and the
   env-specific files), Python package re-exports (``from .base import Cfg as
   AppCfg``), Spring ``@ConfigurationProperties`` getters.
3. Membership checks are mentions: Java ``WEAK.contains("MD5")``, JS ``new
   Set([...]).has(...)``, Kotlin ``in listOf(...)``.
6. One rule for algorithm registries: a dict whose values are crypto constructors
   or algorithm objects is a real capability, reported as an asset, unconfirmed
   unless the registry is used.
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
    """title -> (config_status, config_read_at)."""
    return {
        r["title"]: (r.get("config_status"), r.get("config_read_at"))
        for r in out["results"]
    }


def _keys(text: str, lang: str) -> tuple[set[str], list[dict]]:
    ev: list[dict] = []
    return {d.key for d in detect_crypto(text, lang, config_evidence=ev)}, ev


# ----------------------------------------------------------------------------- 1
@pytest.mark.parametrize(
    "assign",
    [
        "Object.assign(settings, {cipher:'des-ede3-cbc'});\n",
        "Object.assign(settings, {\n  cipher: 'des-ede3-cbc',\n});\n",
        "Object.assign(\n  settings,\n  { cipher: 'des-ede3-cbc' },\n);\n",
    ],
)
def test_object_assign_read_by_a_crypto_call_is_a_confirmed_3des(tmp_path, assign):
    src = (
        "const crypto = require('crypto');\n"
        "const settings = {};\n"
        + assign
        + "const c = crypto.createCipheriv(settings.cipher, key, iv);\n"
    )
    rows = _rows(_scan(tmp_path, {"src/a.js": src}))
    tdes = [t for t in rows if t.startswith("3DES")]
    assert tdes, rows
    status, read_at = rows[tdes[0]]
    assert status != "unconfirmed" and read_at, rows


def test_object_assign_read_in_another_file_through_its_target(tmp_path):
    rows = _rows(
        _scan(
            tmp_path,
            {
                "src/settings.js": "const settings = {};\n"
                "Object.assign(settings, {\n  cipher: 'des-ede3-cbc',\n});\n"
                "module.exports = settings;\n",
                "src/use.js": "const crypto = require('crypto');\n"
                "const settings = require('./settings');\n"
                "const c = crypto.createCipheriv(settings.cipher, key, iv);\n",
            },
        )
    )
    tdes = [t for t in rows if t.startswith("3DES")]
    assert tdes and rows[tdes[0]] == (None, "src/use.js:3"), rows


# ----------------------------------------------------------------------------- 2
_NODE_CONFIG = {
    "config/default.js": "module.exports = {\n"
    "  security: { hashAlgorithm: 'md5' },\n};\n",
    "config/production.js": "module.exports = {\n"
    "  security: {\n    hashAlgorithm: 'sha1',\n  },\n};\n",
}


@pytest.mark.parametrize(
    "use",
    [
        "const config = require('config');\nconst crypto = require('crypto');\n"
        "const h = crypto.createHash(config.get('security.hashAlgorithm'));\n",
        "const config = require('config');\nconst crypto = require('crypto');\n"
        "const alg = config.get('security.hashAlgorithm');\n"
        "const h = crypto.createHash(alg);\n",
    ],
)
def test_node_config_reads_confirm_the_default_and_env_files(tmp_path, use):
    rows = _rows(_scan(tmp_path, {**_NODE_CONFIG, "src/h.js": use}))
    for title in ("MD5", "SHA-1"):
        assert title in rows, rows
        status, read_at = rows[title]
        assert status != "unconfirmed" and (read_at or "").startswith("src/h.js:"), rows


def test_node_config_key_alone_does_not_confirm_another_owner(tmp_path):
    rows = _rows(
        _scan(
            tmp_path,
            {
                **_NODE_CONFIG,
                "src/h.js": "const config = require('config');\n"
                "const crypto = require('crypto');\n"
                "const h = crypto.createHash(config.get('legacy.hashAlgorithm'));\n",
            },
        )
    )
    assert rows["MD5"][0] == "unconfirmed", rows


def test_python_package_re_export_confirms_the_class_setting(tmp_path):
    rows = _rows(
        _scan(
            tmp_path,
            {
                "pkg/base.py": "class Cfg:\n    HASH = 'md5'\n",
                "pkg/__init__.py": "from .base import Cfg as AppCfg\n",
                "app.py": "import hashlib\nfrom pkg import AppCfg\n"
                "d = hashlib.new(AppCfg.HASH)\n",
            },
        )
    )
    assert rows.get("MD5") == (None, "app.py:3"), rows


def test_spring_configuration_properties_getter_confirms_the_field(tmp_path):
    rows = _rows(
        _scan(
            tmp_path,
            {
                "src/SecProps.java": "import org.springframework.boot.context."
                "properties.ConfigurationProperties;\n"
                '@ConfigurationProperties(prefix = "app.security")\n'
                "public class SecProps {\n"
                '  private String hashAlgorithm = "MD5";\n'
                "  public String getHashAlgorithm() { return hashAlgorithm; }\n"
                "}\n",
                "src/Hasher.java": "import java.security.MessageDigest;\n"
                "class Hasher {\n  SecProps props;\n"
                "  byte[] h(byte[] d) throws Exception {\n"
                "    return MessageDigest.getInstance(props.getHashAlgorithm())"
                ".digest(d);\n  }\n}\n",
            },
        )
    )
    assert "MD5" in rows and rows["MD5"][0] != "unconfirmed", rows


# ----------------------------------------------------------------------------- 3
@pytest.mark.parametrize(
    ("lang", "text"),
    [
        (
            "java",
            "import java.util.Set;\nclass A {\n"
            '  static final Set<String> WEAK = Set.of("MD5", "SHA-1");\n'
            '  boolean md5Banned() { return WEAK.contains("MD5"); }\n}\n',
        ),
        (
            "javascript",
            "function f(alg) {\n"
            "  if (new Set(['md5', 'sha1']).has(alg)) throw new Error(alg);\n}\n",
        ),
        (
            "java",  # Kotlin (.kt) runs in the java lane
            "fun weak(alg: String) = alg in listOf(\"MD5\", \"SHA-1\")\n",
        ),
        ("java", 'fun ok(alg: String) = alg !in setOf("MD5", "SHA-1")\n'),
    ],
)
def test_membership_checks_are_mentions(lang, text):
    keys, ev = _keys(text, lang)
    assert not keys & {"md5", "sha1"}, keys
    assert ev or "WEAK =" in text  # the deny-list declaration is skipped as before


# ----------------------------------------------------------------------------- 6
_REGISTRIES = {
    "hashes": "import hashlib\n"
    "HASHES = {'md5': hashlib.md5, 'sha1': hashlib.sha1}\n",
    "pyjwt": "class NoneAlgorithm:\n    pass\n\n"
    "_algorithms = {\n    'none': NoneAlgorithm(),\n}\n",
}


@pytest.mark.parametrize("name", sorted(_REGISTRIES))
def test_an_unused_algorithm_registry_is_an_unconfirmed_asset(tmp_path, name):
    rows = _rows(_scan(tmp_path, {"reg.py": _REGISTRIES[name]}))
    assert rows, rows
    assert all(status == "unconfirmed" for status, _r in rows.values()), rows


@pytest.mark.parametrize(
    ("name", "use"),
    [
        (
            "hashes",
            "def digest(name, data):\n    return HASHES[name](data).hexdigest()\n",
        ),
        ("pyjwt", "def get(alg):\n    return _algorithms[alg]\n"),
    ],
)
def test_a_used_algorithm_registry_is_a_confirmed_asset(tmp_path, name, use):
    rows = _rows(_scan(tmp_path, {"reg.py": _REGISTRIES[name] + use}))
    assert rows, rows
    assert all(
        status != "unconfirmed" and read_at for status, read_at in rows.values()
    ), rows
    if name == "pyjwt":
        assert any("none" in t.lower() for t in rows), rows


def test_a_multi_line_object_in_a_key_constructor_stays_an_asset():
    """A brace that opens its own line inside a call's arguments is an object
    literal, judged like a one-line one; a JWK constructor is a crypto API, so its
    ``alg`` flows into it (pyjwt tests/test_api_jws.py)."""
    text = (
        "import jwt\n"
        "jwk = PyJWK(\n"
        "    {\n"
        '        "kty": "oct",\n'
        '        "alg": "HS512",\n'
        "    }\n"
        ")\n"
    )
    keys, _ev = _keys(text, "python")
    assert keys & {"hmac", "sha512"}, keys
