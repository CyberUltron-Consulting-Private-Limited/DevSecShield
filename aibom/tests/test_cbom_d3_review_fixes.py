"""Review of #491 (D3 code-scan CBOM): the major and the engine-side minors.

Each test reproduces a finding of review 6027777683 on a small repository written to
``tmp_path`` (the reviewer's fixtures under ``qa/491/fx``). Salt literals below are
test values; the CBOM must never carry them.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from aibom.emit.validate import validate_cyclonedx
from aibom.integrations.cbom_devsecshield import scan_crypto_to_devsecshield

_PBKDF2 = (
    "from cryptography.hazmat.primitives import hashes\n"
    "from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC\n"
    "import os\n"
)


def _write(root: pathlib.Path, files: dict[str, str]) -> pathlib.Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _scan(root: pathlib.Path) -> dict:
    out = scan_crypto_to_devsecshield(root, level=4)
    assert validate_cyclonedx(out["cbom_json"]) == []
    return out


def _props(comp: dict) -> dict[str, str]:
    return {p["name"]: p["value"] for p in comp.get("properties") or []}


def _named(out: dict, name: str, source: str | None = None) -> list[dict]:
    return [
        c
        for c in out["cbom_json"]["components"]
        if c["name"] == name
        and (source is None or _props(c).get("discovery:source") == source)
    ]


def _findings(out: dict, code: str) -> list[dict]:
    return [r for r in out["results"] if code in (r.get("finding_codes") or [])]


# --------------------------------------------------------------------------- M1
def test_weak_then_strong_pbkdf2_reports_the_weak_call(tmp_path: pathlib.Path) -> None:
    _write(
        tmp_path,
        {
            "a.py": _PBKDF2 + "def legacy(pw):\n"
            "    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, "
            "salt=os.urandom(16), iterations=500).derive(pw)\n"
            "def modern(pw):\n"
            "    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, "
            "salt=os.urandom(16), iterations=600000).derive(pw)\n"
        },
    )
    out = _scan(tmp_path)
    (pbkdf2,) = _named(out, "PBKDF2", "a.py")
    props = _props(pbkdf2)
    assert props["crypto:iterations"] == "500"  # was 600000: the last call won
    assert props["crypto:kdfWeakestLine"] == "5"
    assert "L5 iterations=500" in props["crypto:kdfCalls"]
    assert "L7 iterations=600000" in props["crypto:kdfCalls"]
    (row,) = _findings(out, "WEAK_KDF_ITERATIONS")
    assert row["impact"] == "Medium" and row["line"] == 5  # below NIST SP 800-132


def test_static_salt_file_keeps_its_weaker_stdlib_call(tmp_path: pathlib.Path) -> None:
    _write(
        tmp_path,
        {
            "app/static_salt.py": "import hashlib\n"
            + _PBKDF2
            + 'SALT = b"org-wide-fixed-salt-v1"\n'
            "def module_const(pw):\n"
            "    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, "
            "salt=SALT, iterations=480000).derive(pw)\n"
            "def stdlib(pw):\n"
            '    return hashlib.pbkdf2_hmac("sha256", pw, b"stdlib-fixed-salt", '
            "100_000, 32)\n"
        },
    )
    out = _scan(tmp_path)
    props = _props(_named(out, "PBKDF2", "app/static_salt.py")[0])
    assert props["crypto:iterations"] == "100000"
    assert "iterations=480000" in props["crypto:kdfCalls"]  # the 480000 is not lost
    blob = json.dumps(out)
    assert "org-wide-fixed-salt-v1" not in blob and "stdlib-fixed-salt" not in blob


def test_argon2_password_hasher_then_raw_keeps_every_call(
    tmp_path: pathlib.Path,
) -> None:
    _write(
        tmp_path,
        {
            "argon.py": "import os\n"
            "from argon2 import PasswordHasher, Type\n"
            "from argon2.low_level import hash_secret_raw\n"
            "ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, "
            "type=Type.ID)\n"
            "def raw_i(pw):\n"
            "    return hash_secret_raw(pw, os.urandom(16), time_cost=1, "
            "memory_cost=8, parallelism=1, hash_len=32, type=Type.I)\n"
            "def raw_id(pw):\n"
            "    return hash_secret_raw(pw, os.urandom(16), time_cost=2, "
            "memory_cost=19456, parallelism=1, hash_len=32, type=Type.ID)\n"
        },
    )
    out = _scan(tmp_path)
    props = _props(_named(out, "Argon2", "argon.py")[0])
    # the weakest call's own set, never a mix: Type.I with t=1, m=8
    assert (props["crypto:argon2TimeCost"], props["crypto:argon2MemoryCost"]) == (
        "1",
        "8",
    )
    assert props["crypto:argon2Variant"] == "Argon2i"
    assert (
        "L4 argon2MemoryCost=65536" in props["crypto:kdfCalls"]
    )  # PasswordHasher kept
    assert _findings(out, "WEAK_KDF_ITERATIONS")


# --------------------------------------------------------------------------- m3
def test_scrypt_cost_written_as_a_power_is_read(tmp_path: pathlib.Path) -> None:
    _write(
        tmp_path,
        {
            "y.py": "import hashlib, os\n"
            "def k(pw):\n"
            "    return hashlib.scrypt(pw, salt=os.urandom(16), n=2**14, r=8, "
            "p=1, dklen=32)\n"
            "def k2(pw):\n"
            "    return hashlib.scrypt(pw, salt=os.urandom(16), n=1 << 15, r=8, "
            "p=1, dklen=32)\n"
        },
    )
    props = _props(_named(_scan(tmp_path), "scrypt", "y.py")[0])
    assert props["crypto:scryptN"] == "16384"
    assert "scryptN=32768" in props["crypto:kdfCalls"]


def test_a_huge_power_is_not_folded(tmp_path: pathlib.Path) -> None:
    _write(
        tmp_path,
        {
            "y.py": "import hashlib, os\n"
            "def k(pw):\n"
            "    return hashlib.scrypt(pw, salt=os.urandom(16), n=99999**999, "
            "r=8, p=1)\n"
        },
    )
    assert "crypto:scryptN" not in _props(_named(_scan(tmp_path), "scrypt", "y.py")[0])


# --------------------------------------------------------------------------- m7 / m8
@pytest.mark.parametrize(
    ("call", "impact"),
    [
        (
            "PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=os.urandom(16), "
            "iterations=480000)",
            "Low",
        ),  # below OWASP 600,000
        (
            "PBKDF2HMAC(algorithm=hashes.SHA512(), length=64, salt=os.urandom(16), "
            "iterations=210000)",
            None,
        ),  # OWASP's PBKDF2-HMAC-SHA512 minimum
        (
            "PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=os.urandom(16), "
            "iterations=999)",
            "Medium",
        ),  # below NIST SP 800-132
    ],
)
def test_pbkdf2_iterations_are_graded(
    tmp_path: pathlib.Path, call: str, impact
) -> None:
    _write(tmp_path, {"k.py": _PBKDF2 + f"kdf = {call}\n"})
    rows = _findings(_scan(tmp_path), "WEAK_KDF_ITERATIONS")
    assert [r["impact"] for r in rows] == ([impact] if impact else [])


def test_argon2_below_owasp_memory_is_graded(tmp_path: pathlib.Path) -> None:
    _write(
        tmp_path,
        {
            "a.py": "from argon2 import PasswordHasher\n"
            "weak = PasswordHasher(time_cost=2, memory_cost=8192, parallelism=1)\n"
            "ok = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)\n"
        },
    )
    (row,) = _findings(_scan(tmp_path), "WEAK_KDF_ITERATIONS")
    assert row["impact"] == "Low" and row["line"] == 2


def test_pbkdf2_location_is_the_call_not_the_import_fallback(
    tmp_path: pathlib.Path,
) -> None:
    _write(
        tmp_path,
        {
            "router/encryption.py": "import os\n"
            "from cryptography.hazmat.primitives import hashes\n"
            "try:\n"
            "    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC\n"
            "except ImportError:\n"
            "    PBKDF2HMAC = None\n"
            "\n"
            "def derive(pw):\n"
            "    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, "
            "salt=os.urandom(16), iterations=600000)\n"
            "    return kdf.derive(pw)\n"
        },
    )
    props = _props(_named(_scan(tmp_path), "PBKDF2", "router/encryption.py")[0])
    assert props["crypto:line"] == "9" and props["crypto:occurrences"] == "9"


# --------------------------------------------------------------------------- m2
def test_pyca_digest_is_provided_by_pyca_not_hashlib(tmp_path: pathlib.Path) -> None:
    _write(
        tmp_path,
        {
            "requirements.txt": "cryptography==43.0.1\n",
            "app/env_salt.py": _PBKDF2 + "def f(pw):\n"
            "    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, "
            'salt=os.environ["KDF_SALT"].encode(), iterations=600000).derive(pw)\n',
            "app/digest.py": "import hashlib\nh = hashlib.sha256(b'x').hexdigest()\n",
        },
    )
    out = _scan(tmp_path)
    sha = _named(out, "SHA-256", "app/env_salt.py")[0]
    assert _props(sha)["crypto:detectedBy"] == "pyca/cryptography"
    provides = {
        d["ref"]: d.get("provides", []) for d in out["cbom_json"]["dependencies"]
    }
    assert sha["bom-ref"] not in provides.get("crypto-lib-hashlib-stdlib", [])
    assert sha["bom-ref"] in provides["crypto-lib-pyca-cryptography"]
    stdlib_sha = _named(out, "SHA-256", "app/digest.py")[0]
    assert _props(stdlib_sha)["crypto:detectedBy"] == "hashlib (stdlib)"


# --------------------------------------------------------------------------- m6
def test_one_salt_row_per_literal_with_its_line(tmp_path: pathlib.Path) -> None:
    _write(
        tmp_path,
        {
            "app/static_salt.py": "import hashlib\n"
            + _PBKDF2
            + 'SALT = b"org-wide-fixed-salt-v1"\n'
            "def a(pw):\n"
            "    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, "
            "salt=SALT, iterations=600000).derive(pw)\n"
            "def b(pw):\n"
            '    return hashlib.pbkdf2_hmac("sha256", pw, b"stdlib-fixed-salt", '
            "600_000, 32)\n"
        },
    )
    out = _scan(tmp_path)
    salts = [
        c
        for c in out["cbom_json"]["components"]
        if _props(c).get("crypto:materialKind") == "salt"
    ]
    lines = sorted(int(_props(c)["crypto:line"]) for c in salts)
    assert lines == [5, 9]  # one row per literal: the constant and the call
    by_line = {_props(c)["crypto:line"]: _props(c) for c in salts}
    assert by_line["5"]["crypto:literalLength"] == "22"
    assert by_line["9"]["crypto:literalLength"] == "17"
    rows = _findings(out, "STATIC_SALT")
    assert sorted(r["line"] for r in rows) == [5, 9]


def test_vulnerable_pin_is_linked_to_its_library_row(tmp_path: pathlib.Path) -> None:
    """``cryptography>=42`` is one library row, the code lane's ``pyca/cryptography``
    (m6; staging QA Q2-09: the
    advisory lane no longer adds a ``cryptography@>=42`` component): a range's lower
    bound is no installed version, so
    its advisories are listed on that row as unverified and raise no finding."""
    _write(
        tmp_path,
        {
            "requirements.txt": "cryptography>=42\n",
            "k.py": _PBKDF2 + "kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), "
            "length=32, salt=os.urandom(16), iterations=600000)\n",
        },
    )
    out = _scan(tmp_path)
    libs = {
        c["name"]: c for c in out["cbom_json"]["components"] if c["type"] == "library"
    }
    assert "cryptography@>=42" not in libs and "pyca/cryptography" in libs
    props = _props(libs["pyca/cryptography"])
    assert props["crypto:versionConstraint"] == ">=42"
    assert (
        props["crypto:versionVerified"] == "false"
        and int(props["crypto:unverifiedAdvisoryCount"]) > 0
    )
    assert not _findings(out, "VULNERABLE_CRYPTO_LIBRARY")


# --------------------------------------------------------------------------- m4
def test_images_behind_nested_or_unset_args_are_kept(tmp_path: pathlib.Path) -> None:
    _write(
        tmp_path,
        {
            "Dockerfile": "ARG PY=3.12\nARG BASE=python:${PY}-slim\nFROM ${BASE}\n"
            "ARG NODE_VERSION\nFROM node:${NODE_VERSION}-alpine\nFROM ${UNSET_IMAGE}\n",
            "k.py": "import hashlib\nh = hashlib.sha256(b'x')\n",
        },
    )
    images = {
        c["name"]: (c.get("version"), _props(c))
        for c in _scan(tmp_path)["cbom_json"]["components"]
        if c["type"] == "container"
    }
    assert images["python"][0] == "3.12-slim"
    assert images["node"][1]["image:tag"] == "unresolved (${NODE_VERSION})"
    assert images["${UNSET_IMAGE}"][1]["image:unresolved"] == "${UNSET_IMAGE}"
