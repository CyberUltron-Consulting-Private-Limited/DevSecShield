"""CNSA 2.0 and FIPS 140-3 framework verdicts over a CBOM Sources collection (CB-16 AC 4).

The code lane judges each code scan against its compliance frameworks (``aibom.cbom.compliance``; the verdicts are in
the scan's ``cbom_compliance``) and the team roll-up pools them (``cbom_team_rollup._pool_compliance``).  A Sources
collection is a CBOM result too (``collections_view``), so it is judged against the two frameworks whose requirements
the inventory can evidence, with the SAME predicates the code lane's checks call (``standards.framework_checks``, one
module in two byte-identical copies): an algorithm gets one verdict whichever lane saw it.

* ``fips_140_3``: FIPS-1 (only approved security functions), FIPS-2 (RSA / DH / DSA keys of at least 2048 bits),
  FIPS-3 (no SP 800-131A disallowed algorithm; a Sources asset never says its cipher mode, so ECB is the code lane's).
* ``cnsa_2_0``: CNSA-1 (symmetric ciphers and hashes are AES-256 / SHA-384/512), CNSA-2 (post-quantum algorithms are
  a CNSA 2.0 parameter set).

A requirement fails when any judged part of any asset fails it and passes otherwise, as the code lane's checks do (a
collection with nothing post-quantum passes CNSA-2).  A collection none of whose assets names an algorithm the
standards can judge is ``out_of_scope`` for both frameworks (the code lane's "no cryptographic assets" rule).  The
requirements the inventory cannot evidence (FIPS-4 CMVP certificate, CNSA-3 migration targets, CNSA-4 timeline) get
no Sources verdict: an attestation is a code-scan upload, and a Sources asset carries no migration target.
"""
from __future__ import annotations

from typing import Any, Iterable

from backend.utilities.cbom_sources import standards as STD

FRAMEWORKS: tuple[str, ...] = ("fips_140_3", "cnsa_2_0")
SOURCES: dict[str, str] = {  # the code lane's citations (compliance._S_FIPS / _S_CNSA)
    "fips_140_3": "FIPS 140-3 / SP 800-140C / SP 800-131A",
    "cnsa_2_0": "NSA CNSA 2.0",
}
VERDICT_PASS, VERDICT_FAIL, VERDICT_OUT_OF_SCOPE = "pass", "fail", "out_of_scope"

Part = tuple[str, Any, Any]


def collection_compliance(assets_parts: Iterable[Iterable[Part]]) -> dict[str, dict[str, Any]]:
    """One collection's ``cbom_compliance``-shaped blocks: per framework, the verdict counts and its requirements
    (``id``, ``title``, ``source``, ``verdict``, ``failing``: how many assets fail it)."""
    judged = False
    failing: dict[str, int] = {req: 0 for req in STD.REQUIREMENTS}
    for parts in assets_parts:
        fails: set[str] = set()
        for role, ident, size in parts:
            if STD.judge(role, ident, size) is None:
                continue
            judged = True
            for req, result in STD.framework_checks(role, ident, size).items():
                if result:
                    fails.add(req)
        for req in fails:
            failing[req] += 1
    out: dict[str, dict[str, Any]] = {}
    for framework in FRAMEWORKS:
        reqs = []
        for req, (fw, title) in STD.REQUIREMENTS.items():
            if fw != framework:
                continue
            verdict = VERDICT_OUT_OF_SCOPE if not judged else (VERDICT_FAIL if failing[req] else VERDICT_PASS)
            reqs.append({"id": req, "title": title, "source": SOURCES[framework], "verdict": verdict,
                         "failing": failing[req] if judged else 0})
        counts = {state: sum(1 for r in reqs if r["verdict"] == state)
                  for state in (VERDICT_PASS, VERDICT_FAIL, VERDICT_OUT_OF_SCOPE)}
        out[framework] = {**counts, "pass_with_evidence": 0, "not_bom_evidenceable": 0, "na": 0,
                          "requirements": reqs}
    return out


__all__ = ["FRAMEWORKS", "collection_compliance"]
