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


def run_heatmap(session: Session, team_id: int, run_id: int, *, by: str = "source") -> dict[str, Any]:
    jobs = {j.id: j for j in session.exec(select(CbomCollectionJob).where(
        CbomCollectionJob.team_id == team_id, CbomCollectionJob.run_id == run_id)).all()}
    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id)).all()}
    rows = session.exec(select(CbomCollectedAsset).where(
        CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.run_id == run_id)).all()
    from backend.utilities.cbom_sources.classify import shown

    cells: dict[tuple[str, str], dict[str, Any]] = {}
    columns: dict[str, int] = {}
    certs: list[dict[str, Any]] = []
    today = _dt.datetime.utcnow()
    for row in rows:
        if row.asset_type == "coverage":
            continue
        shown_impact = shown(row, today)["impact"]  # date-based findings (expiry, end of life) judged today
        job = jobs.get(row.job_id)
        src = sources.get((job.source_id if job else None) or 0)
        column = (ID.job_source_name(job, src) if job else "Unknown source") if by == "source" else row.asset_type
        family = algorithm_family(row.algorithm, row.asset_type, row.facts)
        impact = shown_impact if shown_impact in _RANK else "none"
        cell = cells.setdefault((family, column), {"count": 0, "worst": "none", "by_impact": {k: 0 for k in IMPACTS}})
        cell["count"] += 1
        cell["by_impact"][impact] += 1
        cell["worst"] = _worst(cell["worst"], impact)
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
                          "name": row.name, "impact": shown_impact,
                          "source_name": ID.job_source_name(job, src) if job else None})
    families = [f for f in FAMILIES if any(k[0] == f for k in cells)]
    cols = sorted(columns, key=lambda c: (-columns[c], c))
    certs.sort(key=lambda c: c["not_after"])
    return {"by": by, "rows": families, "columns": cols,
            "cells": [{"row": f, "column": c, **cells[(f, c)]} for f in families for c in cols if (f, c) in cells],
            "certificates": certs, "certificates_truncated": len(certs) >= CERT_CAP}


__all__ = ["FAMILIES", "algorithm_family", "run_heatmap"]
