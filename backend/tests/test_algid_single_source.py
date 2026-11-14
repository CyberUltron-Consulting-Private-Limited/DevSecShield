"""Single-source guard for algorithm identity (CB-04, T-B15).

Post-quantum identifiers (FIPS names, OIDs, IANA codepoints, round-3 names) belong in algid.py / algid_tables.py,
which are generated from scripts/algid/sources. The pattern is built from algid itself: its PQ markers (the
substrings resolve() reads as post-quantum, letters with or without separators), the PQ TLS group and signature-scheme
codepoints (hex, and decimal where the number is not a common one), the OIDs of every post-quantum row, and the
prototype/OQS arcs. Any other product file that matches is listed here with its number of MATCHES (not lines), so:
* a new file that starts naming PQ algorithms fails (route it through algid instead);
* a listed file whose count changes fails, also when a second name lands on a line that already matched, so the list
  shrinks as each CB-04 consumer PR moves a site to algid (and nobody adds a table to a listed file by accident).
Only the three vendored copies are exempt, by path, plus tests. Files that only TALK about PQ (report text, KB
remediation advice, schemas) stay listed for good; CB-16 owns rules.py/strength.py.

    cd backend && PYTHONPATH=.. .venv/bin/python -m pytest tests/test_algid_single_source.py -q
"""
from __future__ import annotations

import re
import subprocess
import sys
import unicodedata
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from backend.utilities.cbom_sources import algid as A  # noqa: E402

ROOTS = ("backend", "scan_node", "aibom/src", "frontend/components/cbom")
COPIES = {f"{folder}/{name}" for folder in ("backend/utilities/cbom_sources", "scan_node/zs_scan_node",
                                           "aibom/src/aibom/cbom") for name in ("algid.py", "algid_tables.py")}
# tests, and dependency lock files (package hashes, never an algorithm table)
NOT_PRODUCT = re.compile(r"(^|/)(tests?|__tests__)/|\.test\.tsx?$|(^|/)(uv\.lock|requirements[^/]*\.lock|package-lock\.json)$")


def _marker_pattern() -> re.Pattern[str]:
    """algid's PQ markers as algid reads them (on NFKC text). A marker of five letters or more may have any
    non-alphanumeric characters between its letters (ML-KEM, ml_kem, ML.KEM, ML/DSA) and may follow digits
    (X25519MLKEM768, rsa3072_dilithium2); XMSS may also follow letters (SHA256withXMSS), as algid matches it anywhere.
    LMS, HSS, HQC and BIKE (algid's _TOKEN_MARKERS) must start a token and be followed only by digits or a level
    (hqc128, p256_bikel1), as in algid's _marker, so "bikes", "LMSYS" and "realms" do not count."""
    parts = []
    for marker in sorted(A._PQ_MARKERS, key=len, reverse=True):
        if marker in A._TOKEN_MARKERS:
            parts.append(rf"(?<![^\W_]){re.escape(marker)}(?:(?![^\W\d_])|(?=L\d))")
        else:
            head = "" if marker == "XMSS" else "(?<![a-z])"
            parts.append(head + r"[\W_]*".join(re.escape(ch) for ch in marker))
    return re.compile("|".join(parts), re.IGNORECASE)


def _pq_codepoints() -> set[int]:
    """PQ TLS group and signature-scheme codepoints. 0x0200-0x0202 (MLKEM512/768/1024) are left out of the hex set,
    as 512-514 are left out of the decimal set: they are common constants (a MySQL capability flag, the legacy
    dsa_sha1 sigscheme 0x0202), and the markers catch those groups' names anyway."""
    out: set[int] = set()
    for table, other in ((A._TLS_GROUPS, A._TLS_SIGSCHEMES), (A._TLS_SIGSCHEMES, A._TLS_GROUPS)):
        out |= {cp for cp, name in table.items() if A._ALGS[name][0] == "PQ" and cp not in other}
    return {cp for cp in out if not 0x0200 <= cp <= 0x0202}


MARKERS = _marker_pattern()
CODEPOINTS = _pq_codepoints()
DECIMAL_CODEPOINTS = {cp for cp in CODEPOINTS if cp >= 2300}  # 512-514 are common numbers
PQ_OIDS = {oid for oid, name in A._OIDS.items() if A._ALGS[name][0] == "PQ"}
OID_ARCS = tuple(prefix for prefix, _hint, _primitive in A._OID_PREFIXES)
HEX = re.compile(r"(?<![0-9a-z])0x([0-9a-f]{4})(?![0-9a-z])", re.IGNORECASE)
DECIMAL = re.compile(r"(?<![0-9a-z.])(\d{4,5})(?![0-9a-z])", re.IGNORECASE)
DOTTED = re.compile(r"(?<![\d.])([0-2](?:\.\d+){3,})")


def count(text: str) -> int:
    """Matches of every way algid itself recognises a post-quantum identifier: a marker, a PQ codepoint (hex, or
    decimal), the OID of a PQ row, or an OID under a prototype/OQS arc."""
    n = sum(1 for _ in MARKERS.finditer(unicodedata.normalize("NFKC", text)))
    n += sum(1 for m in HEX.finditer(text) if int(m.group(1), 16) in CODEPOINTS)
    n += sum(1 for m in DECIMAL.finditer(text) if int(m.group(1)) in DECIMAL_CODEPOINTS)
    n += sum(1 for m in DOTTED.finditer(text) if m.group(1) in PQ_OIDS or m.group(1).startswith(OID_ARCS))
    return n


# path -> number of matches (strict: a listed file must match exactly this many times)
ALLOWED = {
    "aibom/src/aibom/cbom/compliance.py": 55,
    "aibom/src/aibom/cbom/data/crypto_kb.json": 71,
    "aibom/src/aibom/cbom/data/named_groups.json": 10,
    "aibom/src/aibom/cbom/detect.py": 60,
    "aibom/src/aibom/cbom/ingest.py": 29,
    "aibom/src/aibom/cbom/normalize.py": 4,
    "aibom/src/aibom/cbom/pqc.py": 45,
    "aibom/src/aibom/cbom/redact.py": 18,
    "aibom/src/aibom/cbom/rules.py": 63,
    "aibom/src/aibom/cbom/scanners/algorithm_scan.py": 6,
    "aibom/src/aibom/cbom/scanners/protocol_scan.py": 1,
    "aibom/src/aibom/cbom/strength.py": 40,
    "aibom/src/aibom/cbom/weakness.py": 18,
    "aibom/src/aibom/emit/crypto_oid.py": 27,
    "aibom/src/aibom/emit/cyclonedx.py": 15,
    "aibom/src/aibom/integrations/cbom_devsecshield.py": 1,
    "aibom/src/aibom/schemas/bom-1.6.schema.json": 2,
    "aibom/src/aibom/schemas/spdx-3.0.1.schema.json": 3,
    "backend/utilities/ai/remediation.py": 1,
    "backend/utilities/cbom_sources/classify_ext/node_net.py": 5,
    "backend/utilities/cbom_sources/data/crypto_kb.json": 71,
    "backend/utilities/cbom_sources/data/cyclonedx/bom-1.6.xsd": 2,
    "backend/utilities/cbom_sources/exploit_demo.py": 6,
    "backend/utilities/cbom_sources/fixgen.py": 2,
    "backend/utilities/cbom_sources/gcp_collect.py": 3,
    "backend/utilities/dashboard/cbom_team_rollup.py": 2,
    "backend/utilities/pdf/cbom_deliverable_text.py": 9,
    "frontend/components/cbom/CbomCryptoCharts.tsx": 3,
    "frontend/components/cbom/heatmapLogic.ts": 12,
    "frontend/components/cbom/pqcMigrationGroup.ts": 4,
    "frontend/components/cbom/quantumFilter.ts": 1,
    "frontend/components/cbom/sources/RunPosture.tsx": 1,
    "scan_node/Dockerfile": 1,
    "scan_node/README.md": 2,
    "scan_node/zs_scan_node/certparse.py": 1,
    "scan_node/zs_scan_node/collectors/network.py": 1,
    "scan_node/zs_scan_node/ikeprobe.py": 5,
    "scan_node/zs_scan_node/kmip_ttlv.py": 5,
    "scan_node/zs_scan_node/tlsprobe.py": 15,
}


def _matches() -> dict[str, int]:
    try:
        files = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "--", *ROOTS],
                               cwd=REPO, capture_output=True, text=True, check=True).stdout.split()
    except (OSError, subprocess.CalledProcessError):  # no git (a source tarball): walk the tree instead
        skip = ("node_modules", ".venv", ".next", "__pycache__")
        files = [str(p.relative_to(REPO)) for root in ROOTS for p in (REPO / root).rglob("*")
                 if p.is_file() and not any(part in skip for part in p.parts)]
    out: dict[str, int] = {}
    for rel in files:
        if rel in COPIES or NOT_PRODUCT.search(rel):
            continue
        try:
            text = (REPO / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue
        n = count(text)
        if n:
            out[rel] = n
    return out


def test_pq_identifiers_live_in_algid_only():
    found = _matches()
    new = {p: n for p, n in found.items() if p not in ALLOWED}
    assert not new, f"PQ identifiers outside algid.py: {new}. Resolve them through algid instead"
    changed = {p: (ALLOWED[p], found.get(p, 0)) for p in ALLOWED if found.get(p, 0) != ALLOWED[p]}
    assert not changed, f"(allowed, now) per listed file: {changed}. Update ALLOWED (it may only shrink)"


def test_the_guard_catches_what_algid_recognises():
    """Each way a PQ identifier can be written counts, once per occurrence (not per line)."""
    for text in ("XMSS", "LMS_SHA256_M32_H10", "HSS", "HQC-128", "FrodoKEM-640", "Classic-McEliece", "BIKE-L1",
                 "0x0905", "0x0906", "4588", "1.2.840.113549.1.9.16.3.17", "1.3.6.1.4.1.2.267.12.6.5", "X25519MLKEM768",
                 "ml_dsa_65", "2.16.840.1.114027.80.8.1.4", "0x11EC", "SecP256r1MLKEM768", "rsa3072_dilithium2"):
        assert count(text) >= 1, text
    assert count("PQ_GROUPS = (0x11EC, 0x11EB)  # X25519MLKEM768, MLKEM1024, ML-DSA-87") == 5
    for text in ("ML.KEM-768", "ML/DSA/44", "ML\u2011DSA\u201165", "SLH\u2010DSA"):  # every spelling algid resolves
        assert count(text) == 1 and A.family_label(text) == "PQ", text
    for text in ("realms", "bikes", "0x0200", "0x0201", "0x0202", "512", "sha256:0a4588ff", "2.16.840.1.101.3.4.3.2",
                 "helms 2310ms", "SHA1 with SSH", "client_caps = 0x0800 | 0x0200", "LMSYS", "Bikeshed", "HSSI"):
        assert count(text) == 0, text
    # The short-marker rule is algid's own: the guard counts a string exactly when algid reads it as PQ.
    for text in ("bikel1", "p256_bikel1", "HQC128", "SHA256withXMSS", "SHA512WITHXMSSMT", "ＬＭＳ_SHA256",
                 "bikes", "LMSYS", "hqcfoo", "HSSI", "realms", "HELMS", "bikes2", "HSSB1"):
        assert (count(text) == 1) == (A.family_label(text) == "PQ"), text
