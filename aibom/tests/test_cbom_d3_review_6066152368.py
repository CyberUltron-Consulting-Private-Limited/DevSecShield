"""PR #500 re-review 6066152368 (round 7): the reviewer's probes as tests.

1. (Blocking) ``const settings = Object.assign({}, defaults, {cipher: ...})`` read by
   ``createCipheriv(settings.cipher)`` confirms 3DES: with a fresh literal (or any
   target) the assigned variable owns the merged settings; ``let`` / ``var`` and a
   later reassignment too.
2. #505's semantics: a scan whose only weak crypto is unconfirmed gets the worst-case
   score with status "unverified" (never a clean A); confirmed plus unconfirmed shows
   the confirmed score with ``risk_unverified`` (note, worst, worst case); test code
   stays unscored.
3. Partials: a destructured rename from ``require`` confirms; a named ``Set`` used as
   a deny-list is a mention; a Java field assigned a transformation in the
   constructor and used in ``Cipher.getInstance`` is inventoried; a Spring getter
   proves only its own owner type; node-config JSON / YAML files; a registry used
   from another file that imports it.
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


def _confirmed(rows: dict, title_prefix: str) -> bool:
    hits = [v for t, v in rows.items() if t.startswith(title_prefix)]
    return bool(hits) and all(s != "unconfirmed" and r for s, r in hits)


# ----------------------------------------------------------------------------- 1
_READ = "const c = crypto.createCipheriv(settings.cipher, key, iv);\n"


@pytest.mark.parametrize(
    "decl",
    [
        "const settings = Object.assign({}, defaults, {cipher:'des-ede3-cbc'});\n",
        "let settings = Object.assign({}, defaults, { cipher: 'des-ede3-cbc' });\n",
        "var settings = Object.assign({}, {\n  cipher: 'des-ede3-cbc',\n});\n",
        "const settings = Object.assign({ cipher: 'des-ede3-cbc' }, defaults);\n",
        "let settings = {};\n"
        "settings = Object.assign({}, settings, {\n  cipher: 'des-ede3-cbc',\n});\n",
    ],
)
def test_object_assign_into_a_fresh_object_is_owned_by_the_variable(tmp_path, decl):
    src = "const crypto = require('crypto');\nconst defaults = {};\n" + decl + _READ
    rows = _rows(_scan(tmp_path, {"src/a.js": src}))
    assert _confirmed(rows, "3DES"), rows


# ----------------------------------------------------------------------------- 2
def test_unconfirmed_only_is_the_worst_case_marked_unverified(tmp_path):
    out = _scan(tmp_path, {"app/conf.py": "EXPORT = {'checksum': 'md5'}\n"})
    scores = out["cbom_scores"]
    assert scores["risk_posture_status"] == "unverified"
    assert scores["risk_grade"] != "A" and scores["risk_normalized"] > 0
    unverified = scores["risk_unverified"]
    assert unverified["count"] == 1 and unverified["worst"] in ("critical", "high")
    assert unverified["note"].startswith("unverified: 1 unconfirmed setting (worst: ")
    assert unverified["worst_case"]["score"] == scores["risk_normalized"]
    row = next(r for r in out["results"] if r["title"] == "MD5")
    assert row["config_status"] == "unconfirmed" and row["impact"] == "Low"
    assert row["unverified_severity"] == unverified["worst"]


def test_confirmed_plus_unconfirmed_shows_the_confirmed_score_and_a_note(tmp_path):
    out = _scan(
        tmp_path,
        {
            "app/conf.py": "EXPORT = {'checksum': 'md5'}\n",
            "app/tls.py": "import hashlib\nh = hashlib.sha256(b'x')\n"
            "k = hashlib.sha1(b'y')\n",
        },
    )
    scores = out["cbom_scores"]
    assert scores["risk_posture_status"] == "scored"
    unverified = scores["risk_unverified"]
    assert unverified["count"] == 1
    assert unverified["worst_case"]["score"] >= scores["risk_normalized"]
    assert unverified["note"].startswith("unverified: 1 unconfirmed setting")


def test_test_code_only_stays_unscored(tmp_path):
    out = _scan(tmp_path, {"tests/test_h.py": "import hashlib\nhashlib.md5(b'x')\n"})
    scores = out["cbom_scores"]
    assert (scores["risk_normalized"], scores["risk_grade"]) == (0.0, "A")
    assert scores["risk_posture_status"] == "scored"
    assert scores.get("risk_unverified") is None


# ----------------------------------------------------------------------------- 3
def test_destructured_rename_from_require_confirms(tmp_path):
    rows = _rows(
        _scan(
            tmp_path,
            {
                "src/config.js": "module.exports = { digest: 'md5' };\n",
                "src/h.js": "const crypto = require('crypto');\n"
                "const { digest: alg } = require('./config');\n"
                "const h = crypto.createHash(alg);\n",
            },
        )
    )
    assert rows.get("MD5") == (None, "src/h.js:3"), rows


def test_a_named_set_used_as_a_deny_list_is_a_mention():
    text = (
        "const WEAK = new Set(['md5', 'sha1']);\n"
        "function ok(alg) {\n  if (WEAK.has(alg)) throw new Error(alg);\n}\n"
    )
    ev: list[dict] = []
    keys = {d.key for d in detect_crypto(text, "javascript", config_evidence=ev)}
    assert not keys & {"md5", "sha1"}, keys
    assert {e["line"] for e in ev} == {1} and len(ev) == 2, ev


def test_a_java_field_set_in_the_constructor_and_used_by_get_instance(tmp_path):
    src = (
        "import javax.crypto.Cipher;\nclass A {\n"
        "  private final String transformation;\n"
        '  A() { this.transformation = "DES/ECB/PKCS5Padding"; }\n'
        "  byte[] e(byte[] d, java.security.Key k) throws Exception {\n"
        "    Cipher c = Cipher.getInstance(this.transformation);\n"
        "    c.init(Cipher.ENCRYPT_MODE, k);\n    return c.doFinal(d);\n  }\n}\n"
    )
    rows = _rows(_scan(tmp_path, {"src/A.java": src}))
    assert any(t.startswith("DES") for t in rows), rows


_SEC_PROPS = (
    "import org.springframework.boot.context.properties.ConfigurationProperties;\n"
    '@ConfigurationProperties(prefix = "app.security")\n'
    "public class SecProps {\n"
    '  private String hashAlgorithm = "MD5";\n'
    "  public String getHashAlgorithm() { return hashAlgorithm; }\n"
    "}\n"
)


def _hasher(owner_type: str) -> str:
    return (
        "import java.security.MessageDigest;\n"
        f"class Hasher {{\n  private {owner_type} props;\n"
        "  byte[] h(byte[] d) throws Exception {\n"
        "    return MessageDigest.getInstance(props.getHashAlgorithm())"
        ".digest(d);\n  }\n}\n"
    )


def test_a_spring_getter_proves_its_own_owner_type(tmp_path):
    rows = _rows(
        _scan(
            tmp_path,
            {"src/SecProps.java": _SEC_PROPS, "src/Hasher.java": _hasher("SecProps")},
        )
    )
    assert rows.get("MD5") == (None, "src/Hasher.java:5"), rows


def test_a_spring_getter_on_another_type_does_not_prove_it(tmp_path):
    rows = _rows(
        _scan(
            tmp_path,
            {
                "src/SecProps.java": _SEC_PROPS,
                "src/OtherProps.java": "public class OtherProps {\n"
                "  public String getHashAlgorithm() { return null; }\n}\n",
                "src/Hasher.java": _hasher("OtherProps"),
            },
        )
    )
    assert rows.get("MD5", ("missing",))[0] == "unconfirmed", rows


_READER = (
    "const config = require('config');\nconst crypto = require('crypto');\n"
    "const h = crypto.createHash(config.get('security.hashAlgorithm'));\n"
)


@pytest.mark.parametrize(
    ("name", "text"),
    [
        (
            "config/default.json",
            '{\n  "security": {\n    "hashAlgorithm": "md5"\n  }\n}\n',
        ),
        ("config/production.yaml", "security:\n  hashAlgorithm: md5\n"),
        ("config/test.yml", "security:\n  hashAlgorithm: 'md5'\n"),
    ],
)
def test_node_config_json_and_yaml_files(tmp_path, name, text):
    out = _scan(tmp_path, {name: text, "src/h.js": _READER})
    rows = [r for r in out["results"] if r["title"] == "MD5"]
    assert rows and rows[0]["location"] == name, out["results"]
    assert (rows[0].get("config_status"), rows[0].get("config_read_at")) == (
        None,
        "src/h.js:3",
    )


def test_node_config_value_no_one_reads_is_unconfirmed(tmp_path):
    out = _scan(
        tmp_path,
        {
            "config/default.json": '{\n  "legacy": {\n'
            '    "hashAlgorithm": "md5"\n  }\n}\n'
        },
    )
    rows = [r for r in out["results"] if r["title"] == "MD5"]
    assert rows and rows[0]["config_status"] == "unconfirmed", out["results"]


def test_a_registry_used_from_another_file_is_confirmed(tmp_path):
    rows = _rows(
        _scan(
            tmp_path,
            {
                "lib/reg.py": "import hashlib\n"
                "HASHES = {'md5': hashlib.md5, 'sha1': hashlib.sha1}\n",
                "app.py": "from lib.reg import HASHES\n\n"
                "def digest(name, data):\n    return HASHES[name](data).hexdigest()\n",
            },
        )
    )
    assert rows and all(s != "unconfirmed" and r for s, r in rows.values()), rows
    assert all(r == "app.py:4" for _s, r in rows.values()), rows


def test_an_unconfirmed_strong_setting_is_no_unverified_finding(tmp_path):
    """Only weak crypto counts: an unconfirmed ``AES-256-GCM`` setting is clean
    inventory, so the scan stays 0 / A, scored (EncDec-Pro's seven settings)."""
    out = _scan(tmp_path, {"app/conf.py": "EXPORT = {'cipher': 'AES-256-GCM'}\n"})
    scores = out["cbom_scores"]
    assert (scores["risk_normalized"], scores["risk_posture_status"]) == (0.0, "scored")
    assert scores["risk_unverified"] is None
