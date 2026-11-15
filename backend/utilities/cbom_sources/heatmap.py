"""Heat-map (algorithm family x source or asset type, counted by worst impact) and the certificate-expiry list of a
collection run. Code scans build the same views in the browser from the rows and ``cbom_distributions`` they already
load; ``algorithm_family`` here and ``algorithmFamily`` in ``frontend/components/cbom/heatmapLogic.ts`` follow the
same table.
"""
from __future__ import annotations

import datetime as _dt
import re
from typing import Any

from sqlmodel import Session, select

from backend.new_models import CbomCollectedAsset, CbomCollectionJob, CbomCollectionSource
from backend.utilities.cbom_sources import algid
from backend.utilities.cbom_sources import identity as ID

IMPACTS = ("Critical", "High", "Medium", "Low", "none")
_RANK = {name: i for i, name in enumerate(IMPACTS)}
CERT_CAP = 2_000
# (family, tokens or prefixes): first match wins, so a certificate's key algorithm wins over its signature hash.
# Post-quantum names are algid's (algorithm_family asks algid first, so a hybrid group is never read as ECC): the one
# post-quantum token left is NTRU, which is no algid marker (algid only knows its NTRU Prime variant).
FAMILY_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Post-quantum", ("ntru",)),
    ("EdDSA", ("ed25519", "ed448", "eddsa")),
    ("RSA", ("rsa",)),
    ("Elliptic curve", ("ecdsa", "ecdh", "ecdhe", "ec", "secp", "prime256", "p256", "p384", "p521", "nistp", "x25519",
                        "x448", "curve25519", "brainpool")),
    ("Diffie-Hellman", ("dh", "dhe", "ffdhe", "modp", "diffie")),
    ("DSA", ("dsa", "dss")),
    ("AES", ("aes",)),
    ("ChaCha20", ("chacha", "chacha20")),
    ("DES / 3DES", ("des", "3des", "tripledes", "desede", "cbc3")),
    ("RC4", ("rc4", "arcfour")),
    ("Blowfish", ("blowfish", "bf")),
    ("MD5", ("md5",)),
    ("SHA-1", ("sha1",)),
    ("SHA-2 / SHA-3", ("sha2", "sha224", "sha256", "sha384", "sha512", "sha3")),
    ("HMAC", ("hmac",)),
)
FAMILIES = tuple(f for f, _ in FAMILY_RULES) + ("Protocol (no key data)", "Library", "Other")
_PROTOCOL_TYPES = {"tls_endpoint", "ssh_endpoint", "ssh_server_config", "database_tls", "load_balancer_tls", "cdn_tls",
                   "api_tls", "k8s_ingress_tls"}


def _tokens(text: str) -> list[str]:
    raw = re.sub(r"[^a-z0-9-]+", " ", text.lower()).split()
    out = []
    for tok in raw:
        out.append(tok)
        out.append(tok.replace("-", ""))
        out.extend(p for p in tok.split("-") if p)
    return out


def _match(text: str) -> str | None:
    tokens = _tokens(text)
    if not tokens:
        return None
    for family, words in FAMILY_RULES:
        for word in words:
            w = word.replace("-", "")
            for tok in tokens:
                # whole tokens for short words ("ec", "dh", "des", "bf"), substrings for long ones ("sha256withrsa")
                if (len(w) <= 3 and tok == w) or (len(w) > 3 and w in tok) or (w == "rsa" and "rsa" in tok):
                    return family
    return None


# algid's public-key family labels as heat-map families
_ALGID_FAMILY = {"PQ": "Post-quantum", "RSA": "RSA", "EC": "Elliptic curve", "ECDSA": "Elliptic curve",
                 "ECDH": "Elliptic curve", "X25519": "Elliptic curve", "X448": "Elliptic curve",
                 "SM2": "Elliptic curve", "ED25519": "EdDSA", "ED448": "EdDSA", "EDDSA": "EdDSA",
                 "DH": "Diffie-Hellman", "DSA": "DSA"}


def _algid_family(text: str) -> str | None:
    """The family of an identifier algid knows by OID, registry or cloud name, alias or post-quantum marker
    (a KMS post-quantum signing enum is post-quantum, not DSA; a post-quantum OID is not "Other"). Its classical name
    fallback is left to the token rules below, which read cipher-suite names the way they always have."""
    found = algid.resolve(algid.compare_key(text))
    if found is None or found.matched_by == "fallback":
        return None
    return _ALGID_FAMILY.get(found.family_label or "")


def algorithm_family(algorithm: str | None, asset_type: str | None, facts: dict[str, Any] | None = None) -> str:
    facts = facts or {}
    for text in (algorithm, facts.get("key_alg"), facts.get("group"), facts.get("kex"), facts.get("cipher"),
                 facts.get("sig_alg"), facts.get("method")):
        if text:
            # then the token rules on the text as written, then on the algorithm a cloud enum names
            # (SYMMETRIC_DEFAULT is AES-256-GCM)
            found = _algid_family(str(text)) or _match(str(text)) or _match(str(algid.compare_key(str(text))))
            if found:
                return found
    if asset_type in ("crypto_library", "process_library", "library"):
        return "Library"
    if asset_type in _PROTOCOL_TYPES or asset_type == "protocol":
        return "Protocol (no key data)"
    return "Other"


def _worst(a: str, b: str) -> str:
    return a if _RANK[a] <= _RANK[b] else b


METRICS = ("impact", "grade")
GRADES = ("Q0", "Q1", "Q2", "Q3", "Q4", "none")
_KNOWN = ("Q1", "Q2", "Q3", "Q4")  # worst first; Q0 (unknown) is counted apart and never hides a known grade
CELL_PAGE_MAX = 200


def worst_grade(by_grade: dict[str, int]) -> str | None:
    """A cell's worst known grade (Q1 < Q2 < Q3 < Q4); "Q0" only when it has no known grade but an unknown one."""
    known = next((g for g in _KNOWN if by_grade.get(g)), None)
    return known or ("Q0" if by_grade.get("Q0") else None)


def _rows(session: Session, team_id: int, run_id: int, *, by: str, metric: str):
    """The run's non-coverage rows with what the map counts them by: (row, family, column, impact today, PQC class,
    grade or None, source name, job). The map and a cell's drill-down both read this one loop."""
    from backend.utilities.cbom_sources import qgrade as QG
    from backend.utilities.cbom_sources.classify import shown
    from backend.utilities.cbom_sources.posture import JudgedElsewhere, classify_pqc

    jobs = {j.id: j for j in session.exec(select(CbomCollectionJob).where(
        CbomCollectionJob.team_id == team_id, CbomCollectionJob.run_id == run_id)).all()}
    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id)).all()}
    rows = session.exec(select(CbomCollectedAsset).where(
        CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.run_id == run_id)
        .order_by(CbomCollectedAsset.id)).all()
    elsewhere = JudgedElsewhere(rows)
    grading = None
    if metric == "grade":  # CB-19 PR-3: the grade the run's list shows (one context loader, the run's record inputs)
        from dataclasses import replace

        grading = replace(QG.load_context(session, team_id=team_id, run_id=run_id), elsewhere=elsewhere)
    today = _dt.datetime.utcnow()
    for row in rows:
        if row.asset_type == "coverage":
            continue
        view = shown(row, today)  # date-based findings (expiry, end of life) judged today
        codes = list(view["finding_codes"])
        job = jobs.get(row.job_id)
        src = sources.get((job.source_id if job else None) or 0)
        name = ID.job_source_name(job, src) if job else None
        column = (name if job else "Unknown source") if by == "source" else row.asset_type
        cls = classify_pqc(row, codes, elsewhere=elsewhere)[0]  # the one class function (CB-18)
        graded = grading.grade_row(row, codes, explain=False, cls=cls) if grading is not None else None
        yield (row, algorithm_family(row.algorithm, row.asset_type, row.facts), column, view["impact"], cls, graded,
               name, today)


def run_heatmap(session: Session, team_id: int, run_id: int, *, by: str = "source",
                metric: str = "impact") -> dict[str, Any]:
    """``metric="grade"`` (CB-19 PR-3) adds each cell's assets per quantum risk grade (``by_grade``, "none" = no
    grade) and its ``worst_grade``; the impact counts are there either way."""
    from backend.utilities.cbom_sources.posture import PQC_CLASSES

    if metric not in METRICS:
        raise ValueError(f"metric: {metric}")
    cells: dict[tuple[str, str], dict[str, Any]] = {}
    columns: dict[str, int] = {}
    certs: list[dict[str, Any]] = []
    for row, family, column, shown_impact, cls, graded, source_name, today in _rows(
            session, team_id, run_id, by=by, metric=metric):
        impact = shown_impact if shown_impact in _RANK else "none"
        cell = cells.setdefault((family, column), {"count": 0, "worst": "none", "by_impact": {k: 0 for k in IMPACTS},
                                                   "pqc_classes": {c: 0 for c in PQC_CLASSES}})
        cell["count"] += 1
        # the one class function (CB-18): a cell can say how many of its assets the scan could not identify
        cell["pqc_classes"][cls] += 1
        cell["by_impact"][impact] += 1
        cell["worst"] = _worst(cell["worst"], impact)
        if graded is not None:
            by_grade = cell.setdefault("by_grade", {g: 0 for g in GRADES})
            by_grade[graded.q_grade or "none"] += 1
        columns[column] = columns.get(column, 0) + 1
        facts = row.facts or {}
        if ID.is_certificate(row) and facts.get("not_after") and len(certs) < CERT_CAP:
            from backend.utilities.cbom_sources.drift import parse_time

            when = parse_time(facts.get("not_after"))
            if when is None:
                continue
            certs.append({"asset_id": row.id, "not_after": when.replace(microsecond=0).isoformat() + "Z",
                          "days_left": (when - today).days, "subject": facts.get("subject"),
                          "issuer": facts.get("issuer"), "target": row.target, "location": row.location,
                          "name": row.name, "impact": shown_impact, "source_name": source_name})
    if metric == "grade":
        for cell in cells.values():
            cell["worst_grade"] = worst_grade(cell["by_grade"])
    families = [f for f in FAMILIES if any(k[0] == f for k in cells)]
    cols = sorted(columns, key=lambda c: (-columns[c], c))
    certs.sort(key=lambda c: c["not_after"])
    return {"by": by, "metric": metric, "rows": families, "columns": cols,
            "cells": [{"row": f, "column": c, **cells[(f, c)]} for f in families for c in cols if (f, c) in cells],
            "certificates": certs, "certificates_truncated": len(certs) >= CERT_CAP}


def heatmap_cell(session: Session, team_id: int, run_id: int, *, by: str, row: str, column: str,
                 metric: str = "impact", page: int = 1, page_size: int = 50) -> dict[str, Any]:
    """The assets of one cell (CB-19 PR-3 drill-down), from the same loop as the map, so ``total`` is the cell's
    ``count`` and the grades are the cell's ``by_grade``. Worst first (grade or impact, by ``metric``), then id."""
    if metric not in METRICS:
        raise ValueError(f"metric: {metric}")
    page_size = max(1, min(int(page_size), CELL_PAGE_MAX))
    found = []
    for asset, family, col, impact, cls, graded, source_name, _today in _rows(
            session, team_id, run_id, by=by, metric="grade"):
        if family != row or col != column:
            continue
        found.append({"id": asset.id, "type": asset.asset_type, "target": asset.target, "location": asset.location,
                      "name": asset.name, "algorithm": asset.algorithm, "key_size": asset.key_size,
                      "impact": impact, "pqc_class": cls, "source_name": source_name,
                      **(graded.fields() if graded is not None else {})})
    grade_rank = {g: i for i, g in enumerate((*_KNOWN, "Q0"))}
    if metric == "grade":
        found.sort(key=lambda a: (grade_rank.get(a.get("q_grade") or "", 9), a["id"] or 0))
    else:
        found.sort(key=lambda a: (_RANK.get(a["impact"] or "none", 9), a["id"] or 0))
    start = (max(1, int(page)) - 1) * page_size
    return {"by": by, "metric": metric, "row": row, "column": column, "total": len(found), "page": page,
            "page_size": page_size, "items": found[start:start + page_size]}


__all__ = ["FAMILIES", "GRADES", "METRICS", "algorithm_family", "heatmap_cell", "run_heatmap", "worst_grade"]
