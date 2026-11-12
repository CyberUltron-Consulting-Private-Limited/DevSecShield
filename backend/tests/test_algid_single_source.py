"""Single-source guard for algorithm identity (CB-04, T-B15).

Post-quantum identifiers (FIPS names, OIDs, IANA codepoints, round-3 names) belong in algid.py, which is generated
from scripts/algid/sources. Any other product file that mentions them is listed here with the number of lines that
match, so that:
* a new file that starts naming PQ algorithms fails (route it through algid instead);
* a listed file whose count changes fails, so the list shrinks as each CB-04 consumer PR moves a site to algid (and
  nobody adds a second table to a listed file by accident).
Tests, the algid copies and the generator are not product sites. Files that only TALK about PQ (report text, KB
remediation advice, schemas) stay listed for good; CB-16 owns rules.py/strength.py.

    cd backend && PYTHONPATH=.. .venv/bin/python -m pytest tests/test_algid_single_source.py -q
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ROOTS = ("backend", "scan_node", "aibom/src", "frontend/components/cbom")
PATTERN = re.compile(
    r"ML[-_ ]?DSA|ML[-_ ]?KEM|SLH[-_ ]?DSA|FN[-_]?DSA|KYBER|DILITHIUM|SPHINCS|FALCON|SNTRUP|XWING|X-WING"
    r"|2\.16\.840\.1\.101\.3\.4\.[34]\.|1\.3\.6\.1\.5\.5\.7\.6\.|0x0904|0x11E[9A-F]|0x6399",
    re.IGNORECASE,
)
NOT_PRODUCT = re.compile(r"(^|/)(tests?|__tests__|fixtures)/|\.test\.tsx?$|(^|/)algid\.py$")

# path -> number of matching lines (strict: a listed file must match exactly this many lines)
ALLOWED = {
    "aibom/src/aibom/cbom/compliance.py": 21,
    "aibom/src/aibom/cbom/data/crypto_kb.json": 41,
    "aibom/src/aibom/cbom/data/named_groups.json": 3,
    "aibom/src/aibom/cbom/detect.py": 26,
    "aibom/src/aibom/cbom/ingest.py": 12,
    "aibom/src/aibom/cbom/normalize.py": 2,
    "aibom/src/aibom/cbom/pqc.py": 28,
    "aibom/src/aibom/cbom/redact.py": 3,
    "aibom/src/aibom/cbom/rules.py": 25,
    "aibom/src/aibom/cbom/scanners/algorithm_scan.py": 4,
    "aibom/src/aibom/cbom/scanners/protocol_scan.py": 1,
    "aibom/src/aibom/cbom/strength.py": 10,
    "aibom/src/aibom/cbom/weakness.py": 6,
    "aibom/src/aibom/cbom/x509.py": 1,
    "aibom/src/aibom/emit/crypto_oid.py": 16,
    "aibom/src/aibom/emit/cyclonedx.py": 6,
    "aibom/src/aibom/integrations/cbom_devsecshield.py": 1,
    "aibom/src/aibom/schemas/bom-1.6.schema.json": 2,
    "aibom/src/aibom/schemas/spdx-3.0.1.schema.json": 9,
    "backend/utilities/ai/remediation.py": 1,
    "backend/utilities/cbom_sources/classify.py": 1,
    "backend/utilities/cbom_sources/classify_ext/node_net.py": 5,
    "backend/utilities/cbom_sources/data/crypto_kb.json": 41,
    "backend/utilities/cbom_sources/data/cyclonedx/bom-1.6.xsd": 2,
    "backend/utilities/cbom_sources/exploit_demo.py": 3,
    "backend/utilities/cbom_sources/fixgen.py": 2,
    "backend/utilities/cbom_sources/gcp_collect.py": 1,
    "backend/utilities/cbom_sources/heatmap.py": 3,
    "backend/utilities/dashboard/cbom_team_rollup.py": 1,
    "backend/utilities/pdf/cbom_deliverable_text.py": 4,
    "frontend/components/cbom/CbomCryptoCharts.tsx": 2,
    "frontend/components/cbom/heatmapLogic.ts": 1,
    "frontend/components/cbom/pqcMigrationGroup.ts": 2,
    "frontend/components/cbom/quantumFilter.ts": 1,
    "frontend/components/cbom/sources/RunPosture.tsx": 1,
    "scan_node/Dockerfile": 1,
    "scan_node/README.md": 2,
    "scan_node/zs_scan_node/certparse.py": 1,
    "scan_node/zs_scan_node/collectors/network.py": 1,
    "scan_node/zs_scan_node/ikeprobe.py": 4,
    "scan_node/zs_scan_node/kmip_ttlv.py": 1,
    "scan_node/zs_scan_node/tlsprobe.py": 3,
}


def _matches() -> dict[str, int]:
    try:
        files = subprocess.run(["git", "ls-files", "--", *ROOTS], cwd=REPO, capture_output=True, text=True,
                               check=True).stdout.split()
    except (OSError, subprocess.CalledProcessError):  # no git (a source tarball): walk the tree instead
        skip = ("node_modules", ".venv", ".next", "__pycache__")
        files = [str(p.relative_to(REPO)) for root in ROOTS for p in (REPO / root).rglob("*")
                 if p.is_file() and not any(part in skip for part in p.parts)]
    out: dict[str, int] = {}
    for rel in files:
        if NOT_PRODUCT.search(rel):
            continue
        try:
            text = (REPO / rel).read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError):
            continue
        n = sum(1 for line in text.splitlines() if PATTERN.search(line))
        if n:
            out[rel] = n
    return out


def test_pq_identifiers_live_in_algid_only():
    found = _matches()
    new = {p: n for p, n in found.items() if p not in ALLOWED}
    assert not new, f"PQ identifiers outside algid.py: {new}. Resolve them through algid instead"
    changed = {p: (ALLOWED[p], found.get(p, 0)) for p in ALLOWED if found.get(p, 0) != ALLOWED[p]}
    assert not changed, f"(allowed, now) per listed file: {changed}. Update ALLOWED (it may only shrink)"
