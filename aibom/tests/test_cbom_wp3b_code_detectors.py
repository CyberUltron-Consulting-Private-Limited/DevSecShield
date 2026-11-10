"""Code-level detectors closing the round-5 lab gaps (WP3b): constants and helpers across files, key material proven
by its value, notebooks, archives inside the tree, git history, private XOR / Feistel constructions, Fernet,
non-security hashing, inner hashes of composites, vendored output and minified lines.

Each case mirrors a planted crypto-zoo item (named in the test) and has a negative twin.
"""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from aibom.cbom.custom_crypto import detect_custom_constructions
from aibom.cbom.detect import detect_crypto
from aibom.cbom.misuse import detect_material_misuse
from aibom.cbom.notebook import OUTPUT_PREFIX, virtual_source
from aibom.cbom.pipeline import scan_crypto
from aibom.cbom.purpose import hash_purpose
from aibom.emit.cyclonedx import emit_cyclonedx
from aibom.emit.validate import validate_cyclonedx

_HEX = "00112233445566778899aabbccddeeff"


def _write(root: Path, files: dict[str, str | bytes]) -> None:
    for rel, body in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(body, bytes):
            p.write_bytes(body)
        else:
            p.write_text(body, encoding="utf-8")


def _rows(tmp_path: Path, files: dict[str, str | bytes], **kw) -> tuple[list[dict], object]:
    """Every crypto asset as {name, refs, codes, props} plus the result."""
    _write(tmp_path, files)
    result = scan_crypto(tmp_path, **kw)
    out = []
    for c in result.components:
        if c.kind != "crypto_asset":
            continue
        out.append({"name": c.name, "ref": c.bom_ref, "props": dict(c.properties or {}),
                    "codes": sorted({f.code for f in result.flags_for(c.bom_ref)})})
    return out, result


def _at(rows: list[dict], path: str) -> dict[str, dict]:
    return {r["name"]: r for r in rows if r["props"].get("discovery:source") == path}


# --------------------------------------------------------------------------- #
# Constants and helpers defined in another file (COD-105/106/108, COD-098)
# --------------------------------------------------------------------------- #


def test_java_constant_of_another_class_names_the_cipher(tmp_path: Path) -> None:
    rows, result = _rows(tmp_path, {
        "src/eva/Algs.java": 'package eva;\npublic final class Algs {\n  public static final String CIPHER = "DES";\n}\n',
        "src/eva/Prop2.java": "package eva;\nimport javax.crypto.Cipher;\npublic class Prop2 {\n"
                              "  Cipher c() throws Exception {\n    return Cipher.getInstance(Algs.CIPHER);\n  }\n}\n",
        "src/eva/Stat.java": "package eva;\nimport javax.crypto.Cipher;\nimport static eva.Algs.CIPHER;\n"
                             "class Stat { Cipher c() throws Exception { return Cipher.getInstance(CIPHER); } }\n",
    })
    des = _at(rows, "src/eva/Prop2.java")["DES"]
    assert des["props"]["crypto:line"] == "5"
    assert des["props"]["crypto:definedAt"] == "src/eva/Algs.java:3"
    assert "WEAK_ALGORITHM" in des["codes"]
    assert _at(rows, "src/eva/Stat.java")["DES"]["props"]["crypto:definedAt"] == "src/eva/Algs.java:3"
    # the export lists the constant as a second occurrence of the use-site row (schema-valid)
    bom = emit_cyclonedx(result)
    assert validate_cyclonedx(bom) == []
    comp = next(c for c in bom["components"] if c["bom-ref"] == des["ref"])
    assert {"location": "src/eva/Algs.java", "line": 3,
            "additionalContext": "value defined here"} in comp["evidence"]["occurrences"]


def test_java_constant_that_differs_between_two_classes_of_one_name_is_not_used(tmp_path: Path) -> None:
    rows, _ = _rows(tmp_path, {
        "a/Algs.java": 'class Algs { static final String CIPHER = "DES"; }\n',
        "b/Algs.java": 'class Algs { static final String CIPHER = "AES/GCM/NoPadding"; }\n',
        "c/Use.java": "import javax.crypto.Cipher;\nclass Use { Object c() throws Exception "
                      "{ return Cipher.getInstance(Algs.CIPHER); } }\n",
    })
    assert _at(rows, "c/Use.java") == {}


def test_python_constant_imported_from_a_project_module(tmp_path: Path) -> None:
    rows, _ = _rows(tmp_path, {
        "svc/eva/consts.py": "ALG = 'md5'\n",
        "svc/eva/prop2.py": "import hashlib\nfrom .consts import ALG\ndef h(pw):\n"
                            "    return hashlib.new(ALG, pw).hexdigest()\n",
        "svc/other.py": "import hashlib\nfrom elsewhere import ALG\ndef h(pw):\n    return hashlib.new(ALG, pw)\n",
    })
    md5 = _at(rows, "svc/eva/prop2.py")["MD5"]
    assert md5["props"]["crypto:line"] == "4"
    assert md5["props"]["crypto:definedAt"] == "svc/eva/consts.py:1"
    assert _at(rows, "svc/other.py") == {}  # a module outside the project resolves to nothing


def test_helper_imported_by_name_lists_its_callers(tmp_path: Path) -> None:
    rows, result = _rows(tmp_path, {
        "services/crypto_svc/pycryptodome_des.py": "from Crypto.Cipher import DES\ndef c(key):\n"
                                                    "    return DES.new(key, DES.MODE_ECB)\n",
        "test/test_crypto.py": "from services.crypto_svc.pycryptodome_des import c\ndef test_des_roundtrip():\n"
                               "    key = b'0123456701234567'\n    assert c(key[:8]) is not None\n",
    })
    des = _at(rows, "services/crypto_svc/pycryptodome_des.py")["DES-ECB"]
    assert des["props"]["crypto:calledFrom"] == "test/test_crypto.py:4"
    comp = next(c for c in emit_cyclonedx(result)["components"] if c["bom-ref"] == des["ref"])
    assert {"location": "test/test_crypto.py", "line": 4, "additionalContext": "called from here"} in \
        comp["evidence"]["occurrences"]
    assert _at(rows, "test/test_crypto.py") == {}  # no second inventory row at the call site


# --------------------------------------------------------------------------- #
# Key material proven by its value (COD-067/068/125/126/127/128/160)
# --------------------------------------------------------------------------- #


def _keys(text: str, lang: str, lookup=None) -> list[tuple[str | None, int, bool, str | None]]:
    return [(f.var, f.line, f.hardcoded, f.derived_with)
            for f in detect_material_misuse(text, lang, lookup) if f.kind == "secret-key"]


def test_hex_key_constant_without_any_crypto_import() -> None:
    java = f'package p;\npublic class KeyConst {{\n  public static final String K = "{_HEX}";\n}}\n'
    assert _keys(java, "java") == [("K", 3, True, None)]
    # a 128-bit hex digest named for what it is (a checksum / cache key) is not key material
    assert _keys(f'class C {{ static final String CACHE_KEY = "{_HEX}"; }}\n', "java") == []
    assert _keys(f'CHECKSUM = "{_HEX}"\n', "python") == []
    assert _keys('KEY = "0000000000000000000000000000000a"\n', "python") == []  # not a key: one repeated digit


def test_decoded_and_split_key_literals() -> None:
    assert _keys('import base64\nKEY = base64.b64decode("c3VwZXJzZWNyZXRhZXNrZXkxMjM0NTY3OA==")\n', "python") == \
        [("KEY", 2, True, None)]
    split = "KEY = (\n    b'001122'\n    b'334455'\n    b'66778899aabbccddeeff'\n)\ndef k(): return KEY\n"
    assert _keys(split, "python") == [("KEY", 2, True, None)]
    assert _keys("def k():\n    return bytes.fromhex('00112233445566778899aabbccddeeff')\n", "python") == \
        [("k()", 2, True, None)]
    java = ('class KeySplit9 {\n  static final String P1 = "00112233";\n'
            '  static final String P2 = "445566778899aabbccddeeff";\n'
            "  public static String key() { return P1 + P2; }\n}\n")
    assert ("key()", 4, True, None) in _keys(java, "java")
    # negatives: a short decode, a one-letter function returning random bytes, a key read from the environment
    assert _keys('KEY = base64.b64decode("c2hvcnQ=")\n', "python") == []
    assert _keys("import random\ndef k():\n    return random.randbytes(16)\n", "python") == []
    assert _keys("import os\nKEY = os.environ['K']\n", "python") == []


def test_key_derived_from_a_constant_through_md5(tmp_path: Path) -> None:
    src = "import hashlib\ndef k():\n    return hashlib.md5(b'corporate-master-pass').digest()\n"
    assert _keys(src, "python") == [("k()", 3, True, "MD5")]
    rows, _ = _rows(tmp_path, {"key_md5const9.py": src})
    found = _at(rows, "key_md5const9.py")
    key = found["secret-key (k(), key_md5const9.py)"]
    assert key["codes"] == ["HARDCODED_KEY"] and key["props"]["crypto:derivedWith"] == "MD5"
    md5 = found["MD5"]  # the derivation step: listed, derived from the key row, no finding of its own
    assert md5["props"]["crypto:derived"] == "true" and md5["props"]["crypto:derivedFrom"] == key["ref"]
    assert md5["codes"] == []


def test_md5_used_elsewhere_in_the_file_stays_a_finding(tmp_path: Path) -> None:
    src = ("import hashlib\ndef k():\n    return hashlib.md5(b'corporate-master-pass').digest()\n"
           "def sig(pw):\n    return hashlib.md5(pw).hexdigest()\n")
    rows, _ = _rows(tmp_path, {"two.py": src})
    md5 = _at(rows, "two.py")["MD5"]
    assert "crypto:derived" not in md5["props"] and "WEAK_ALGORITHM" in md5["codes"]


def test_key_read_from_a_properties_file(tmp_path: Path) -> None:
    code = ("def load():\n    with open('keys.properties') as fh:\n        for line in fh:\n"
            "            if line.startswith('aes.key='): return bytes.fromhex(line.split('=')[1].strip())\n")
    rows, _ = _rows(tmp_path, {
        "eva/keys.properties": f"db.user=app\naes.key={_HEX}\ndb.pool=10\n",
        "eva/key_res9.py": code,
        "eva/name.py": "def load(cfg):\n    return cfg['db.user=']\n",
        "eva/weak.properties": "app.key=short\n",
        "eva/short.py": "def load():\n    open('weak.properties')\n    return 'app.key='\n",
    })
    key = _at(rows, "eva/key_res9.py")["secret-key (aes.key, key_res9.py)"]
    assert key["codes"] == ["HARDCODED_KEY"]
    assert key["props"]["crypto:line"] == "4" and key["props"]["crypto:definedAt"] == "eva/keys.properties:2"
    assert _at(rows, "eva/name.py") == {} and _at(rows, "eva/short.py") == {}


# --------------------------------------------------------------------------- #
# Jupyter notebooks (COD-130)
# --------------------------------------------------------------------------- #


def _nb(cells: list[dict], v4: bool = True) -> bytes:
    if v4:
        return json.dumps({"cells": cells, "metadata": {}, "nbformat": 4, "nbformat_minor": 5}).encode()
    v3 = [dict(c, input=c.pop("source")) for c in cells]
    return json.dumps({"worksheets": [{"cells": v3}], "metadata": {}, "nbformat": 3}).encode()


def test_notebook_virtual_source_code_and_outputs() -> None:
    raw = _nb([
        {"cell_type": "markdown", "source": ["# AES notes"]},
        {"cell_type": "code", "source": ["%matplotlib inline\n", "import hashlib\n", "h = hashlib.md5(b'x')\n"],
         "outputs": [{"output_type": "display_data", "data": {"image/png": "iVBORw0KGgo=" * 50}},
                     {"output_type": "stream", "text": ["done\n"]}]},
    ])
    text, origin = virtual_source(raw)
    assert text.split("\n") == ["", "import hashlib", "h = hashlib.md5(b'x')", OUTPUT_PREFIX + "done"]
    assert origin == [(2, "code"), (2, "code"), (2, "code"), (2, "output")]
    assert virtual_source(b"not json") is None


@pytest.mark.parametrize("v4", [True, False])
def test_notebook_key_in_output_and_algorithm_in_code(tmp_path: Path, v4: bool) -> None:
    raw = _nb([{"cell_type": "code", "source": ["import hashlib\n", "print('AES key =', key.hex())\n",
                                                "d = hashlib.sha1(b'x')\n"],
                "outputs": [{"output_type": "stream", "name": "stdout", "text": [f"AES key = {_HEX}\n"]}]}], v4)
    rows, _ = _rows(tmp_path, {"notebooks/explore.ipynb": raw})
    found = _at(rows, "notebooks/explore.ipynb")
    key = found["secret-key (notebook output, explore.ipynb)"]
    assert key["codes"] == ["HARDCODED_KEY"] and key["props"]["crypto:line"] == "4"
    assert key["props"]["crypto:notebookCell"] == "1 (output)"
    assert found["SHA-1"]["props"]["crypto:line"] == "3"
    assert found["SHA-1"]["props"]["crypto:notebookCell"] == "1 (code)"
    assert found["SHA-1"]["props"]["crypto:language"] == "jupyter"


def test_notebook_prose_output_is_not_an_algorithm(tmp_path: Path) -> None:
    raw = _nb([{"cell_type": "code", "source": ["x = 1\n"],
                "outputs": [{"output_type": "stream", "text": ["We use AES-256 and SHA-256 here\n"]}]}])
    rows, _ = _rows(tmp_path, {"n.ipynb": raw})
    assert _at(rows, "n.ipynb") == {}


# --------------------------------------------------------------------------- #
# Archives in the tree (COD-131)
# --------------------------------------------------------------------------- #


def _zip(members: dict[str, bytes], *, encrypted: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    raw = bytearray(buf.getvalue())
    if encrypted:  # set the "encrypted" flag bit in the local and central headers (zipfile cannot write one)
        for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            pos = raw.find(sig)
            while pos >= 0:
                raw[pos + off] |= 0x1
                pos = raw.find(sig, pos + 4)
    return bytes(raw)


def test_key_inside_a_nested_zip(tmp_path: Path) -> None:
    inner = _zip({"secret.key": (_HEX + "\n").encode(), "readme.txt": b"hello"})
    rows, result = _rows(tmp_path, {
        "assets/bundle.zip": _zip({"secret.key": (_HEX + "\n").encode()}),
        "assets/outer.zip": _zip({"lib/inner.jar": inner}),
        "assets/locked.zip": _zip({"locked.key": (_HEX + "\n").encode()}, encrypted=True),
    })
    key = _at(rows, "assets/bundle.zip!secret.key")["secret-key (bundle.zip!secret.key)"]
    assert key["props"]["crypto:keySize"] == "128" and key["props"]["crypto:line"] == "1"
    assert key["props"]["crypto:archive"] == "assets/bundle.zip"
    assert _at(rows, "assets/outer.zip!lib/inner.jar!secret.key")
    assert result.properties["crypto:coverage:archiveEncrypted"] == "1"
    assert result.properties["crypto:coverage:archiveMembersNotScanned"] == "1"  # readme.txt
    assert validate_cyclonedx(emit_cyclonedx(result)) == []


def test_archive_nesting_depth_is_bounded(tmp_path: Path) -> None:
    data = _zip({"k.key": (_HEX + "\n").encode()})
    for level in range(4):
        data = _zip({f"l{level}.zip": data})
    rows, result = _rows(tmp_path, {"deep.zip": data})
    assert not [r for r in rows if r["props"].get("discovery:source", "").startswith("deep.zip")]
    assert result.properties["crypto:coverage:archiveTooDeep"] == "1"


def test_member_larger_than_its_header_claims_is_not_read(tmp_path: Path) -> None:
    from aibom.cbom.archives import ArchiveBudget, _read_member

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.key", b"A" * 100_000)
    with zipfile.ZipFile(io.BytesIO(buf.getvalue())) as zf:
        info = zf.getinfo("big.key")
        info.file_size = 10  # a lying header
        budget = ArchiveBudget()
        assert _read_member(zf, info, 2_000_000, budget) is None  # cut at the declared size, then refused
        assert budget.skipped_budget + budget.skipped_unsupported == 1 and budget.bytes_read == 0


# --------------------------------------------------------------------------- #
# Git history (COD-191)
# --------------------------------------------------------------------------- #

_GIT = shutil.which("git")


def _git(root: Path, *args: str) -> None:
    subprocess.run([_GIT, "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                    "-c", "commit.gpgsign=false", *args], check=True, capture_output=True)


def _repo_with_deleted_key(root: Path, pack: bool) -> None:
    root.mkdir()
    _git(root, "init", "-q")
    (root / "config").mkdir()
    (root / "config" / "old_deploy.key").write_text(f"{_HEX}\n")
    (root / "app.py").write_text("x = 1\n")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "add")
    _git(root, "rm", "-q", "config/old_deploy.key")
    _git(root, "commit", "-q", "-m", "remove")
    if pack:
        _git(root, "gc", "-q", "--aggressive")


@pytest.mark.skipif(_GIT is None, reason="git is needed to build the fixture repository")
@pytest.mark.parametrize("pack", [False, True])
def test_key_deleted_from_the_tree_is_found_in_history(tmp_path: Path, pack: bool) -> None:
    root = tmp_path / "repo"
    _repo_with_deleted_key(root, pack)
    result = scan_crypto(root)
    rows = [c for c in result.components if (c.properties or {}).get("discovery:source") == "config/old_deploy.key"]
    assert len(rows) == 1
    props = rows[0].properties
    assert props["crypto:historyOnly"] == "true" and len(props["crypto:gitCommit"]) == 40
    assert props["crypto:keySize"] == "128"
    assert result.properties["crypto:coverage:gitHistoryCommits"] == "2"
    # the deleted key is a finding (it was "Info" inventory, invisible on the results page: lab UI run u2, round 5)
    flags = [f for f in result.flags if f.target == rows[0].bom_ref]
    assert [f.code for f in flags] == ["HARDCODED_KEY"]
    assert "Key in git history" in flags[0].message and props["crypto:gitCommit"][:12] in flags[0].message
    # opted out, or a shallow clone: history is not read
    assert not [c for c in scan_crypto(root, scan_history=False).components
                if (c.properties or {}).get("discovery:source") == "config/old_deploy.key"]
    (root / ".git" / "shallow").write_text("0" * 40 + "\n")
    shallow = scan_crypto(root)
    assert not [c for c in shallow.components if (c.properties or {}).get("discovery:source") == "config/old_deploy.key"]
    assert shallow.properties["crypto:coverage:gitHistory"] == "shallow clone: history not read"


@pytest.mark.skipif(_GIT is None, reason="git is needed to build the fixture repository")
def test_history_reader_never_opens_git_config_and_skips_a_linked_git_dir(tmp_path: Path, monkeypatch) -> None:
    from aibom.cbom import githistory

    root = tmp_path / "repo"
    _repo_with_deleted_key(root, pack=False)
    opened: list[str] = []
    real = githistory._read
    monkeypatch.setattr(githistory, "_read", lambda p, limit: (opened.append(str(p)), real(p, limit))[1])
    files, _ = githistory.history_key_files(root)
    assert [f.rel for f in files] == ["config/old_deploy.key"]
    assert not [p for p in opened if p.endswith("/config") or "/hooks/" in p]
    linked = tmp_path / "linked"
    linked.mkdir()
    (linked / ".git").symlink_to(root / ".git")
    assert githistory.history_key_files(linked) == ([], {})


# --------------------------------------------------------------------------- #
# Private constructions (COD-069/070), Fernet (COD-129)
# --------------------------------------------------------------------------- #


def test_repeating_key_xor_and_feistel_round() -> None:
    xor = ("def transform(data, key):\n    out = bytearray(len(data))\n    for i in range(len(data)):\n"
           "        out[i] = data[i] ^ key[i % len(key)]\n    return bytes(out)\n")
    assert detect_custom_constructions(xor) == [("xor", "XOR cipher (custom implementation)", "stream-cipher", [4])]
    feistel = ("class Feistel {\n  public int round(int l, int r, int k) {\n    int t = r;\n"
               "    r = l ^ ((r << 3 | r >>> 29) + k);\n    l = t;\n    return l;\n  }\n}\n")
    assert detect_custom_constructions(feistel) == [
        ("feistel", "Feistel cipher (custom implementation)", "block-cipher", [4])]
    assert detect_custom_constructions("def f(L, R, k):\n    for i in range(16):\n        L, R = R, L ^ F(R, k[i])\n")
    # negatives: a table lookup (constant modulus), a plain swap, an XOR outside a loop, a checksum
    assert detect_custom_constructions("for i in range(n):\n    crc = crc ^ table[i % 256]\n") == []
    assert detect_custom_constructions("t = a\na = b\nb = t\n") == []
    assert detect_custom_constructions("x = data[0] ^ key[0 % len(key)]\n") == []


def test_fernet_is_inventoried_and_only_a_literal_key_is_a_finding(tmp_path: Path) -> None:
    rows, _ = _rows(tmp_path, {
        "env9.py": "import os\nfrom cryptography.fernet import Fernet\ndef f():\n"
                   "    return Fernet(os.environ['FERNET_KEY'])\n",
        "lit.py": 'from cryptography.fernet import Fernet\nKEY = b"Zb3JvU2hpZWxkRmVybmV0S2V5MDAwMTIzNDU2Nzg5MDEyMzQ="\n'
                  "def f():\n    return Fernet(KEY)\n",
    })
    env = _at(rows, "env9.py")
    assert set(env) == {"Fernet"} and env["Fernet"]["codes"] == []
    assert env["Fernet"]["props"]["crypto:primitive"] == "ae" and env["Fernet"]["props"]["crypto:keySize"] == "256"
    assert "HARDCODED_KEY" in _at(rows, "lit.py")["secret-key (KEY, lit.py)"]["codes"]


# --------------------------------------------------------------------------- #
# Purpose of a hash (trap COD-089) and inner hashes of composites
# --------------------------------------------------------------------------- #


def test_hash_purpose_lines() -> None:
    def purpose(src: str, line: int) -> str | None:
        return hash_purpose(src.split("\n"), line, "python")

    assert purpose("def cache_key(url):\n    return hashlib.md5(url.encode()).hexdigest()\n", 2) == "cache-key"
    assert purpose("h = hashlib.md5(data, usedforsecurity=False)\n", 1) == "usedforsecurity=False"
    assert purpose("etag = hashlib.sha1(body).hexdigest()\n", 1) == "etag"
    # evasion: a cache-key name fed a secret, an explicit flag on a password, a pinning fingerprint
    assert purpose("def cache_key(password):\n    return hashlib.md5(password.encode()).hexdigest()\n", 2) is None
    assert purpose("cache_key = hashlib.md5(user_password).hexdigest()\n", 1) is None
    assert purpose("h = hashlib.md5(password, usedforsecurity=False)\n", 1) is None
    assert purpose("def fingerprint(cert):\n    return hashlib.md5(cert).hexdigest()\n", 2) is None
    assert purpose("def digest(data):\n    return hashlib.md5(data).hexdigest()\n", 2) is None


def test_cache_key_md5_is_inventory_not_a_weakness(tmp_path: Path) -> None:
    rows, _ = _rows(tmp_path, {
        "services/cache/key.py": "import hashlib\ndef cache_key(url):\n"
                                 "    # content-addressing for the on-disk render cache\n"
                                 "    return hashlib.md5(url.encode()).hexdigest()\n",
        "services/auth/pw.py": "import hashlib\ndef cache_key(password):\n"
                               "    return hashlib.md5(password.encode()).hexdigest()\n",
    })
    cache = _at(rows, "services/cache/key.py")["MD5"]
    assert cache["codes"] == [] and cache["props"]["crypto:purpose"] == "cache-key"
    assert "WEAK_ALGORITHM" in _at(rows, "services/auth/pw.py")["MD5"]["codes"]


def test_inner_hashes_are_derived_rows_and_the_composite_keeps_the_finding(tmp_path: Path) -> None:
    rows, result = _rows(tmp_path, {
        "Sha1Rsa.java": "import java.security.Signature;\nclass Sha1Rsa {\n"
                        '  Object s() throws Exception { return Signature.getInstance("SHA1withRSA"); }\n}\n',
        "Mac.java": "import javax.crypto.Mac;\nclass M {\n"
                    '  Object m() throws Exception { return Mac.getInstance("HmacSHA256"); }\n}\n',
        "pbkdf2_weak.py": "from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC\n"
                          "from cryptography.hazmat.primitives import hashes\ndef kdf(salt):\n"
                          "    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=1000)\n",
        "both.py": "import hashlib, hmac\ndef m(k, d):\n    return hmac.new(k, d, hashlib.sha256)\n"
                   "def h(d):\n    return hashlib.sha256(d).digest()\n",
    })
    rsa = _at(rows, "Sha1Rsa.java")
    assert "WEAK_ALGORITHM" in rsa["RSA"]["codes"] and rsa["RSA"]["props"]["crypto:innerDigest"] == "SHA-1"
    assert rsa["SHA-1"]["codes"] == [] and rsa["SHA-1"]["props"]["crypto:derivedFrom"] == rsa["RSA"]["ref"]
    mac = _at(rows, "Mac.java")
    assert mac["SHA-256"]["props"]["crypto:derived"] == "true" and mac["SHA-256"]["props"]["crypto:line"] == "3"
    kdf = _at(rows, "pbkdf2_weak.py")
    assert kdf["SHA-256"]["props"]["crypto:derived"] == "true"
    assert "crypto:derived" not in _at(rows, "both.py")["SHA-256"]["props"]  # also hashed on its own
    assert validate_cyclonedx(emit_cyclonedx(result)) == []


# --------------------------------------------------------------------------- #
# Vendored / build output and minified lines (COD-138..141)
# --------------------------------------------------------------------------- #

_LEGACY = "const crypto = require('crypto');\nfunction h(x) {\n  return crypto.createHash('md5').update(x).digest('hex');\n}\n"


def test_vendored_dirs_opt_in_labelled_third_party(tmp_path: Path) -> None:
    files = {"vendor/legacy_crypto.js": _LEGACY, "build/legacy_crypto.js": _LEGACY,
             "node_modules/legacy_crypto.js": _LEGACY, "node_modules/pkg/index.js": _LEGACY,
             "app.js": _LEGACY}
    rows, _ = _rows(tmp_path, files)
    assert {r["props"]["discovery:source"] for r in rows} == {"app.js"}
    rows, result = _rows(tmp_path, {}, include_vendored=True)
    seen = {r["props"]["discovery:source"]: r["props"].get("crypto:thirdParty") for r in rows if r["name"] == "MD5"}
    assert seen == {"app.js": None, "vendor/legacy_crypto.js": "true", "build/legacy_crypto.js": "true",
                    "node_modules/legacy_crypto.js": "true"}  # packages under node_modules/<pkg>/ stay out
    assert result.properties["crypto:coverage:skippedVendoredDirs"] == "1"


def test_minified_line_longer_than_the_string_window_still_folds() -> None:
    line = "var a=1;" * 1200 + "var c=require('crypto').createCipheriv('aes-'+'128-ecb',k,null);" + "var b=2;" * 10
    assert len(line) > 8000
    found = {(d.key, d.mode) for d in detect_crypto(line, "javascript")}
    assert ("aes-128", "ECB") in found


# --------------------------------------------------------------------------- #
# A transformation supplied by configuration (COD-169), Spring @Value
# --------------------------------------------------------------------------- #

_FROM_PROPS = ("package eva;\nimport javax.crypto.Cipher;\npublic class FromProps3 {\n"
               "  public Cipher c(String fromProps) throws Exception {\n    return Cipher.getInstance(fromProps);\n"
               "  }\n}\n")


def test_parameter_cipher_bound_to_the_only_configured_transformation(tmp_path: Path) -> None:
    rows, _ = _rows(tmp_path, {
        "pay/src/main/java/eva/FromProps3.java": _FROM_PROPS,
        "pay/src/main/resources/application.properties": "server.port=8443\napp.cipher=AES/ECB/PKCS5Padding\n",
        "svc/app.properties": "crypto.cipher=DES/CBC/PKCS5Padding\n",  # another module's: not a candidate
    })
    aes = _at(rows, "pay/src/main/java/eva/FromProps3.java")["AES-ECB"]
    assert aes["props"]["crypto:confidence"] == "medium"
    assert aes["props"]["crypto:definedAt"] == "pay/src/main/resources/application.properties:2"


def test_parameter_cipher_not_bound_when_the_module_configures_two(tmp_path: Path) -> None:
    rows, _ = _rows(tmp_path, {
        "pay/src/main/java/eva/FromProps3.java": _FROM_PROPS,
        "pay/src/main/resources/application.properties": "a.cipher=AES/ECB/PKCS5Padding\n"
                                                         "b.cipher=AES/GCM/NoPadding\n",
    })
    assert _at(rows, "pay/src/main/java/eva/FromProps3.java") == {}


def test_secret_key_spec_field_default_overridden_only_by_a_setter(tmp_path: Path) -> None:
    src = ("import javax.crypto.spec.SecretKeySpec;\nclass B {\n  protected String encryptionAlgorithm = \"AES\";\n"
           "  void setEncryptionAlgorithm(String encryptionAlgorithm) {\n"
           "    this.encryptionAlgorithm = encryptionAlgorithm;\n  }\n"
           "  Object k(byte[] s) { return new SecretKeySpec(s, encryptionAlgorithm); }\n}\n")
    rows, _ = _rows(tmp_path, {"B.java": src, "C.java": src.replace("class B", "class C").replace(
        "this.encryptionAlgorithm = encryptionAlgorithm;", 'this.encryptionAlgorithm = "DES";')})
    aes = _at(rows, "B.java")["AES"]
    assert aes["props"]["crypto:confidence"] == "medium" and aes["props"]["crypto:line"] == "7"
    assert _at(rows, "C.java") == {}  # a second literal value: which one reaches the call is not provable


def test_spring_value_field_resolves_its_property(tmp_path: Path) -> None:
    rows, _ = _rows(tmp_path, {
        "m/src/main/java/S.java": "import javax.crypto.Cipher;\nclass S {\n"
                                  '  @Value("${app.transformation}") private String tr;\n'
                                  "  Cipher c() throws Exception { return Cipher.getInstance(tr); }\n}\n",
        "m/src/main/resources/application.yml": "app:\n  transformation: DESede/CBC/PKCS5Padding\n",
    })
    row = _at(rows, "m/src/main/java/S.java")["3DES-CBC"]
    assert row["props"]["crypto:definedAt"] == "m/src/main/resources/application.yml:2"
    assert "crypto:confidence" not in row["props"]  # read from the code's own reference, not inferred


# --------------------------------------------------------------------------- #
# Binary OpenPGP keyring
# --------------------------------------------------------------------------- #


def test_binary_openpgp_public_key_packet(tmp_path: Path) -> None:
    body = bytes([4]) + b"\x00\x00\x00\x00" + bytes([1]) + (2048).to_bytes(2, "big") + b"\x01" * 256 + \
        (17).to_bytes(2, "big") + b"\x01\x00\x01"
    packet = bytes([0xC0 | 6, 0xFF]) + len(body).to_bytes(4, "big") + body  # new-format public key packet
    rows, _ = _rows(tmp_path, {"keys/release.gpg": packet + bytes([0xC0 | 13, 3]) + b"abc"})
    key = _at(rows, "keys/release.gpg")["public-key (release.gpg)"]
    assert key["props"]["crypto:algorithm"] == "RSA" and key["props"]["crypto:keySize"] == "2048"
    rows, _ = _rows(tmp_path / "other", {"keys/noise.gpg": b"\x89PNG\r\n\x1a\n" + b"\x00" * 40})
    assert _at(rows, "keys/noise.gpg") == {}


def test_package_declaration_is_not_a_usage() -> None:
    """bisq: ``package ...crypto.ed25519.arithmetic;`` made an Ed25519 row (and its inner SHA-512) per file."""
    java = "package org.nem.core.crypto.ed25519.arithmetic;\nclass Ed25519Field {}\n"
    assert detect_crypto(java, "java") == []
    assert detect_crypto("package ed25519\n\nfunc f() {}\n", "go") == []
    used = ("package p.ed25519;\nimport java.security.Signature;\nclass S { Object s() throws Exception "
            '{ return Signature.getInstance("Ed25519"); } }\n')
    assert {(d.key, d.line_no) for d in detect_crypto(used, "java")} == {("ed25519", 3)}
