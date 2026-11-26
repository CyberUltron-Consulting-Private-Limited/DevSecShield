"""Second review of #491 (D3 code-scan CBOM, review 6030339160).

M-A: constant folding is bounded by its result (ints below 2**64, str / bytes at 4096
characters) and by its depth, and a Python file too deep to parse or walk is skipped
with a coverage note: one pathological file never fails or exhausts the scan.
M-B: the weakest KDF call is the worst-graded one (iterations against the OWASP
minimum of that call's own PRF), not the one with the fewest raw iterations.
M-C: a crypto library "provides" only the algorithms whose ``crypto:detectedBy`` names
it, in ``dependencies`` and in the crypto graph alike.
Minors: ``crypto:line`` is the weakest call; two literals on one line are two rows;
OWASP's scrypt alternatives (N, p) are compliant; the row's library is the weakest
call's.

Every hostile fold runs in a child process with a 2 GB address-space limit, so a
regression fails the test instead of the machine. Salt literals below are test values.
"""

from __future__ import annotations

import json
import os
import pathlib
import resource
import subprocess
import sys
import textwrap

import pytest

import aibom
from aibom.cbom.normalize import normalize_crypto
from aibom.cbom.pipeline import scan_crypto
from aibom.emit.validate import validate_cyclonedx
from aibom.integrations.cbom_devsecshield import scan_crypto_to_devsecshield

_SRC = str(pathlib.Path(aibom.__file__).resolve().parents[1])
_HEADER = (
    "from cryptography.hazmat.primitives import hashes\n"
    "from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC\n"
    "import hashlib, os\n"
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


# --------------------------------------------------------------------------- M-A
_CHILD = textwrap.dedent(
    """
    import json, pathlib, resource, sys
    from aibom.cbom.scanners import ast_crypto_scan as s
    text = pathlib.Path(sys.argv[1]).read_text()
    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    assets, materials = s._scan_file(pathlib.Path(sys.argv[1]), "app.py", text)
    after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    print(json.dumps({
        "growth_mb": (after - before) // 1024,
        "assets": [[a.name, a.params] for a in assets],
        "salts": [[m.kind, m.props.get("crypto:literalLength")] for m in materials],
    }))
    """
)


def _limit_memory() -> None:  # the child's whole address space
    resource.setrlimit(resource.RLIMIT_AS, (2 << 30, 2 << 30))


def _scan_in_child(tmp_path: pathlib.Path, body: str) -> dict:
    app = tmp_path / "app.py"
    app.write_text(_HEADER + body, encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-c", _CHILD, str(app)],
        capture_output=True,
        text=True,
        timeout=120,
        preexec_fn=_limit_memory,
        env={**os.environ, "PYTHONPATH": _SRC},
        cwd=tmp_path,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    return json.loads(proc.stdout.strip().splitlines()[-1])


_SQUARING = "A0 = 65536**64\n" + "".join(
    f"A{i} = A{i - 1} * A{i - 1}\n" for i in range(1, 41)
)


@pytest.mark.parametrize(
    "body",
    [
        'SALT = b"a" * 10**10\n'
        "k = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=SALT, "
        "iterations=600000)\n",
        'PAD = "x" * (1 << 33)\n',
        _SQUARING,
        'X = b"a" * 65536\nY = X * 65536\nZ = Y * 65536\n',
        'S = b"s" * 4000\nT = S + S\nU = T * 1000\n',
        "M = 2**64\nN = M * M * M * M\n",
    ],
    ids=["bytes-times-power", "str-times-shift", "repeated-squaring",
         "chained-names", "sum-then-product", "int-products"],
)
def test_hostile_folds_stay_small(tmp_path: pathlib.Path, body: str) -> None:
    out = _scan_in_child(tmp_path, body)
    assert out["growth_mb"] < 64, out
    # nothing larger than the caps was folded: no salt row of a giant literal
    assert all(int(n or 0) <= 4096 for _, n in out["salts"]), out


def test_folding_caps_are_exact() -> None:
    import ast

    from aibom.cbom.scanners.ast_crypto_scan import _literal_value

    def fold(expr: str):
        return _literal_value(ast.parse(expr, mode="eval").body, {})

    assert fold('b"a" * 4096') == b"a" * 4096
    assert fold('b"a" * 4097') is None
    assert fold('4096 * "x"') == "x" * 4096
    assert fold('"ab" * 2049') is None
    assert fold('b"a" * 2048 + b"b" * 2048') == b"a" * 2048 + b"b" * 2048
    assert fold('b"a" * 2048 + b"b" * 2049') is None
    assert fold("2**63") == 2**63
    assert fold("2**64") is None
    assert fold("(1 << 32) * (1 << 32)") is None
    assert fold("(1 << 32) * ((1 << 32) - 1)") is None  # Sub is not folded
    assert fold("18446744073709551615 + 0") == 2**64 - 1
    assert fold("18446744073709551615 + 1") is None
    assert fold("2**14") == 16384 and fold("1 << 14") == 16384
    assert fold("True << 3") is None and fold("2.5 * 3") is None
    assert fold('b"a" * True') is None


def test_fold_depth_is_bounded() -> None:
    import ast

    from aibom.cbom.scanners.ast_crypto_scan import _literal_value

    shallow = "+".join(["1"] * 20)
    deep = "+".join(["1"] * 500)
    assert _literal_value(ast.parse(shallow, mode="eval").body, {}) == 20
    assert _literal_value(ast.parse(deep, mode="eval").body, {}) is None


@pytest.mark.parametrize("terms", [2_000, 50_000])
def test_a_long_expression_never_fails_the_scan(
    tmp_path: pathlib.Path, terms: int
) -> None:
    """2,000 terms parse but overflow a recursive walk; 50,000 terms overflow the
    parser itself. Either way the file is skipped or read without its fold, the
    other files are scanned, and the skip is reported."""
    _write(
        tmp_path,
        {
            "deep.py": "import hashlib\nN = " + "+".join(["1"] * terms) + "\n"
            'k = hashlib.pbkdf2_hmac("sha256", b"pw", os.urandom(16), 600000)\n',
            "ok.py": _HEADER
            + "k = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, "
            "salt=os.urandom(16), iterations=1000)\n",
        },
    )
    result = scan_crypto(str(tmp_path))
    sources = {
        (c.properties or {}).get("discovery:source")
        for c in result.components
        if c.kind == "crypto_asset"
    }
    assert "ok.py" in sources
    if terms == 50_000:
        assert result.properties.get("crypto:coverage:skippedPythonTooDeep") == "1"
    else:  # parsed: its call is inventoried, the over-deep fold is not
        assert "deep.py" in sources


# --------------------------------------------------------------------------- M-B
def test_sha256_below_owasp_is_not_hidden_by_compliant_sha512(
    tmp_path: pathlib.Path,
) -> None:
    _write(
        tmp_path,
        {
            "app.py": _HEADER
            + "legacy = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, "
            "salt=os.urandom(16), iterations=300_000)\n"
            "modern = PBKDF2HMAC(algorithm=hashes.SHA512(), length=64, "
            "salt=os.urandom(16), iterations=210_000)\n"
        },
    )
    out = _scan(tmp_path)
    props = _props(_named(out, "PBKDF2", "app.py")[0])
    assert props["crypto:iterations"] == "300000"
    assert props["crypto:kdfPrf"] == "HMAC-SHA256"
    assert props["crypto:kdfWeakestLine"] == "4"
    (row,) = _findings(out, "WEAK_KDF_ITERATIONS")
    assert row["impact"] == "Low" and row["line"] == 4


def test_sha1_below_owasp_is_not_hidden_by_compliant_sha256(
    tmp_path: pathlib.Path,
) -> None:
    _write(
        tmp_path,
        {
            "app.py": "import hashlib, os\n"
            'def legacy(pw): return hashlib.pbkdf2_hmac("sha1", pw, '
            "os.urandom(16), 1_000_000)\n"
            'def modern(pw): return hashlib.pbkdf2_hmac("sha256", pw, '
            "os.urandom(16), 600_000)\n"
        },
    )
    out = _scan(tmp_path)
    props = _props(_named(out, "PBKDF2", "app.py")[0])
    assert props["crypto:iterations"] == "1000000"
    assert props["crypto:kdfPrf"] == "HMAC-SHA1"
    (row,) = _findings(out, "WEAK_KDF_ITERATIONS")
    assert row["impact"] == "Low" and row["line"] == 2
    assert "1,300,000" in json.dumps(row)  # graded against SHA-1's own minimum


def test_below_nist_outranks_below_owasp(tmp_path: pathlib.Path) -> None:
    """999 SHA-512 iterations (below NIST's 1,000: Medium) are worse than 1,000 SHA-1
    iterations (below OWASP only: Low), although 999 / 210,000 is a larger fraction
    of its OWASP minimum than 1,000 / 1,300,000: the grade decides first, the ratio
    only within a grade."""
    _write(
        tmp_path,
        {
            "app.py": "import hashlib, os\n"
            'a = hashlib.pbkdf2_hmac("sha1", b"pw", os.urandom(16), 1_000)\n'
            'b = hashlib.pbkdf2_hmac("sha512", b"pw", os.urandom(16), 999)\n'
        },
    )
    out = _scan(tmp_path)
    assert _props(_named(out, "PBKDF2", "app.py")[0])["crypto:iterations"] == "999"
    (row,) = _findings(out, "WEAK_KDF_ITERATIONS")
    assert row["impact"] == "Medium" and row["line"] == 3


def test_kdf_grade_is_one_table() -> None:
    from aibom.cbom.weakness import kdf_call_grade

    assert kdf_call_grade("pbkdf2", {"crypto:iterations": "1300000",
                                     "crypto:kdfPrf": "HMAC-SHA1"}) == (0, 1.0)
    assert kdf_call_grade("pbkdf2", {"crypto:iterations": "300000",
                                     "crypto:kdfPrf": "HMAC-SHA256"}) == (1, 0.5)
    assert kdf_call_grade("pbkdf2", {"crypto:iterations": "999"})[0] == 2
    assert kdf_call_grade("pbkdf2", {}) is None
    assert kdf_call_grade("argon2", {"crypto:argon2MemoryCost": "19456",
                                     "crypto:argon2TimeCost": "2"}) == (0, 1.0)


# --------------------------------------------------------------------------- M-C
def test_graph_provides_only_what_the_library_implements(
    tmp_path: pathlib.Path,
) -> None:
    """One file imports pyca, hashlib and argon2-cffi. pyca provides only its own
    calls' algorithms, never hashlib's scrypt, argon2-cffi's Argon2 or a salt; the
    crypto graph and ``dependencies`` agree edge for edge."""
    _write(
        tmp_path,
        {
            "requirements.txt": "cryptography==43.0.1\nargon2-cffi==23.1.0\n",
            "app.py": _HEADER
            + "from argon2 import PasswordHasher\n"
            'SALT = b"org-wide-fixed-salt-v1"\n'
            "k = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=SALT, "
            "iterations=600000)\n"
            "s = hashlib.scrypt(b'pw', salt=os.urandom(16), n=2**17, r=8, p=1)\n"
            "h = PasswordHasher(time_cost=2, memory_cost=19456)\n",
        },
    )
    run = normalize_crypto(scan_crypto(str(tmp_path)), duration_of_scan=0.0)
    bom, graph = run["cbom_json"], run["cbom_graph"]
    by_ref = {c["bom-ref"]: c for c in bom["components"]}
    deps = {d["ref"]: set(d.get("provides") or []) for d in bom["dependencies"]}
    graph_provides: dict[str, set[str]] = {}
    for e in graph["edges"]:
        if e["rel"] == "provides":
            graph_provides.setdefault(e["source"], set()).add(e["target"])
    assert graph_provides, "the libraries provide their algorithms"
    assert graph_provides == {k: v for k, v in deps.items() if v}
    for lib, targets in graph_provides.items():
        label = by_ref[lib]["name"].lower()
        for t in targets:
            comp = by_ref[t]
            assert comp["cryptoProperties"]["assetType"] == "algorithm", comp["name"]
            assert _props(comp)["crypto:detectedBy"].lower() == label, (
                by_ref[lib]["name"], comp["name"])


# --------------------------------------------------------------------------- minors
def test_crypto_line_is_the_weakest_call(tmp_path: pathlib.Path) -> None:
    _write(
        tmp_path,
        {
            "app.py": _HEADER
            + "a = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, "
            "salt=os.urandom(16), iterations=600000)\n"
            "b = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, "
            "salt=os.urandom(16), iterations=500)\n"
        },
    )
    out = _scan(tmp_path)
    props = _props(_named(out, "PBKDF2", "app.py")[0])
    assert props["crypto:line"] == "5"
    assert props["crypto:occurrences"] == "4,5"
    (row,) = _findings(out, "WEAK_KDF_ITERATIONS")
    assert row["line"] == 5


def test_two_literals_on_one_line_are_two_rows(tmp_path: pathlib.Path) -> None:
    _write(
        tmp_path,
        {
            "app.py": "import hashlib\n"
            'a = hashlib.pbkdf2_hmac("sha256", b"pw", b"first-literal-salt", '
            '600_000); b = hashlib.pbkdf2_hmac("sha256", b"pw", '
            'b"second-different-salt-xx", 600_000)\n'
        },
    )
    out = _scan(tmp_path)
    salts = [
        _props(c)
        for c in out["cbom_json"]["components"]
        if _props(c).get("crypto:materialKind") == "salt"
    ]
    assert sorted(p["crypto:literalLength"] for p in salts) == ["18", "24"]
    assert {p["crypto:line"] for p in salts} == {"2"}
    assert len(_findings(out, "STATIC_SALT")) == 2
    blob = json.dumps(out, default=str)
    assert "first-literal-salt" not in blob and "second-different-salt" not in blob


@pytest.mark.parametrize(
    ("n", "r", "p", "graded"),
    [
        ("2**17", 8, 1, False),
        ("2**16", 8, 2, False),
        ("2**15", 8, 3, False),
        ("2**14", 8, 5, False),
        ("2**13", 8, 10, False),
        ("2**16", 8, 1, True),
        ("2**13", 8, 9, True),
        ("2**17", 4, 1, True),  # r below 8 halves the memory
    ],
)
def test_owasp_scrypt_alternatives_are_compliant(
    tmp_path: pathlib.Path, n: str, r: int, p: int, graded: bool
) -> None:
    _write(
        tmp_path,
        {
            "app.py": "import hashlib, os\n"
            f"def a(pw): return hashlib.scrypt(pw, salt=os.urandom(16), n={n}, "
            f"r={r}, p={p}, dklen=32)\n"
        },
    )
    # scrypt is graded by its cost (N, r, p): WEAK_KDF_COST, never an iteration count
    # (staging QA Q2-11)
    out = _scan(tmp_path)
    assert not _findings(out, "WEAK_KDF_ITERATIONS")
    rows = _findings(out, "WEAK_KDF_COST")
    assert [r_["impact"] for r_ in rows] == (["Low"] if graded else [])


def test_row_library_is_the_weakest_calls(tmp_path: pathlib.Path) -> None:
    _write(
        tmp_path,
        {
            "app.py": _HEADER
            + "a = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, "
            "salt=os.urandom(16), iterations=600000)\n"
            'b = hashlib.pbkdf2_hmac("sha256", b"pw", os.urandom(16), 100_000)\n'
        },
    )
    props = _props(_named(_scan(tmp_path), "PBKDF2", "app.py")[0])
    assert props["crypto:line"] == "5"
    assert props["crypto:detectedBy"] == "hashlib (stdlib)"
