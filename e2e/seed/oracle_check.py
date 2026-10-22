#!/usr/bin/env python3
"""Independent oracle: re-derive the plan's Appendix-B quantities with plain code (stdlib only).

``derive()`` shares no code with the product aggregator (``backend/utilities/dashboard/
cbom_team_rollup.py``).  It reads the persisted run-objects as plain JSON, applies the DOCUMENTED
formulas of plan sections 4.1 - 4.5, and returns the same structure as ``fixtures/expected.json``
(``appendix_b`` and ``per_source``).  ``compare()`` then reports every quantity that differs.

Two worlds use it:

* the E2E world - ``seed_team.py`` calls ``verify()`` on the scans it is about to store (scanned
  live in the ``aibom-scan`` container) and aborts when Appendix B is not reproduced, so a drifting
  scanner or fixture is caught at seed time instead of as a confusing PDF mismatch;
* the pinned fixture world - ``python3 oracle_check.py`` (no arguments) re-derives everything from
  the committed ``backend/tests/fixtures/cbom_team_rollup_scans.json`` at its frozen date and proves
  that the literals in ``fixtures/expected.json`` are right.  Run it whenever the scanner, the
  fixture trees or the expected file change.

Independent evidence on top of the formulas: when ``file_fps`` is supplied, the unique-certificate
count is also derived from the DER SHA-256 of the certificate FILES (``openssl x509 -fingerprint
-sha256`` equivalent) and must agree with the ``crypto:*`` tuple identity.

Formulas (all from the plan, none from product code):

* eligible = team ``cbom`` scans with status ``success`` (case-insensitive); included = eligible with
  a list ``results`` or a dict ``cbom_json``; a source is a repo URL + branch (userinfo and ``.git``
  and trailing ``/`` removed, lower case) or a zip title; current scan = newest included scan of the
  source by ``(created_at, id)``;
* certificate identity = SHA-256 of the 8 ``crypto:*`` certificate properties joined by ``\\x1f``;
* validity band from ``notAfter`` against ``as_of``: < 0 days EXPIRED, <= 30 LE_30, <= 90 LE_90, VALID;
* grade input = current rows with at least one finding code, weighted 10/5/2/1 by impact;
  score = min(100, 4 x weighted); bands F >= 70, D >= 50, C >= 30, B >= 15, A below;
* readiness = safe / (safe + vulnerable) over current ``algorithm`` rows, in percent, one decimal;
* compliance pooling = sums of the per-framework verdict counts of the current full-fidelity scans;
  coverage = (pass + pass_with_evidence) / (pass + pass_with_evidence + fail), three decimals.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

IMPACT_ORDER = ("Critical", "High", "Medium", "Low")
IMPACT_POINTS = {"Critical": 10, "High": 5, "Medium": 2, "Low": 1}
GRADE_FLOORS = ((70, "F"), (50, "D"), (30, "C"), (15, "B"), (0, "A"))
NOT_COMPLETED = {"pending", "started", "retry", "not_started"}
STATES = ("pass", "pass_with_evidence", "fail", "not_bom_evidenceable", "out_of_scope")
ATTESTABLE = ("not_bom_evidenceable", "pass_with_evidence")


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def parse_iso(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def source_of(scan: dict[str, Any]) -> tuple[str, str, str]:
    """``(key, label, kind)`` of a scan's source (plan 4.3, re-implemented here)."""
    meta = scan.get("scan_metadata") or {}
    title = str(scan.get("title") or "")
    if meta.get("repo_url"):
        parts = urlsplit(str(meta["repo_url"]).strip())
        path = parts.path.rstrip("/")
        path = path[: -len(".git")] if path.endswith(".git") else path
        branch = meta.get("branch") or "default"
        host = parts.hostname or ""
        return (f"repo:{host}{path}@{branch}".lower(), f"{host}{path} ({branch})".lower(), "repo")
    if meta.get("zip_file_used"):
        return f"zip:{slug(title)}", f"Zip upload: {title}", "zip"
    if meta.get("cbom_file_used"):
        return f"file:{slug(title)}", f"Uploaded CBOM: {title}", "file"
    return f"scan:{scan.get('id')}", f"Scan #{scan.get('id')}", "scan"


def asset_class(row: dict[str, Any]) -> str:
    """alg | cert | proto | mat - from ``asset_type``, else the legacy ``algorithm_type`` (plan 3.1)."""
    kind = row.get("asset_type")
    if kind:
        return {"certificate": "cert", "protocol": "proto", "related-crypto-material": "mat"}.get(
            str(kind), "alg"
        )
    return {"certificate": "cert", "key": "mat", "protocol": "proto"}.get(
        str(row.get("algorithm_type")), "alg"
    )


def _props(component: dict[str, Any]) -> dict[str, str]:
    return {p["name"]: p["value"] for p in component.get("properties") or [] if isinstance(p, dict)}


def _components(scan: dict[str, Any]) -> list[dict[str, Any]]:
    bom = scan["scan_data"].get("cbom_json")
    return [c for c in (bom or {}).get("components", []) if isinstance(c, dict)]


def cert_key(props: dict[str, str]) -> str:
    parts = [
        (props.get("crypto:subjectName") or "").strip().casefold(),
        (props.get("crypto:issuerName") or "").strip().casefold(),
        props.get("crypto:notValidBefore", ""),
        props.get("crypto:notValidAfter", ""),
        (props.get("crypto:signatureAlgorithm") or "").casefold(),
        (props.get("crypto:publicKeyAlgorithm") or "").casefold(),
        str(props.get("crypto:keySize", "")),
        (props.get("crypto:curve") or "").casefold(),
    ]
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:16]


def der_sha256(pem: str) -> str:
    body = "".join(line for line in pem.splitlines() if line and not line.startswith("-----"))
    return hashlib.sha256(base64.b64decode(body)).hexdigest()


def tree_cert_fingerprints(tree: Path) -> dict[str, str]:
    """``{repo-relative path: DER sha256}`` of every certificate FILE below ``tree``."""
    found: dict[str, str] = {}
    for current, _dirs, files in os.walk(tree):
        for name in sorted(files):
            if not name.endswith((".pem", ".crt", ".cer")):
                continue
            path = Path(current) / name
            text = path.read_text(encoding="ascii", errors="replace")
            if "BEGIN CERTIFICATE" in text:
                found[path.relative_to(tree).as_posix()] = der_sha256(text)
    return dict(sorted(found.items()))


def band_of(not_after_iso: str, as_of: date) -> str:
    days = (date.fromisoformat(not_after_iso[:10]) - as_of).days
    if days < 0:
        return "EXPIRED"
    if days <= 30:
        return "LE_30"
    if days <= 90:
        return "LE_90"
    return "VALID"


def grade_of(score: int) -> str:
    return next(grade for floor, grade in GRADE_FLOORS if score >= floor)


def _usable(scan: dict[str, Any]) -> bool:
    data = scan.get("scan_data")
    return isinstance(data, dict) and (
        isinstance(data.get("results"), list) or isinstance(data.get("cbom_json"), dict)
    )


def derive(
    scans: list[dict[str, Any]],
    as_of: date,
    *,
    team_id: int = 1,
    file_fps: dict[int, dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Appendix-B quantities of ``team_id`` as plain data (see the module docstring)."""
    out: dict[str, Any] = {}
    team = [s for s in scans if s["team_id"] == team_id and s["scan_type"] == "cbom"]
    status = {s["id"]: str(s["status"]).strip().lower() for s in team}
    eligible = [s for s in team if status[s["id"]] == "success"]
    included = [s for s in eligible if _usable(s)]
    out["scans_total"] = len(team)
    out["eligible"] = len(eligible)
    out["included"] = len(included)
    out["excluded"] = {
        "failure": sum(v == "failure" for v in status.values()),
        "not_completed": sum(v in NOT_COMPLETED for v in status.values()),
        "no_data": len(eligible) - len(included),
    }

    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for scan in included:
        groups[source_of(scan)[0]].append(scan)
    newest = {k: max(g, key=lambda s: (s["created_at"], s["id"])) for k, g in groups.items()}
    out["sources"] = len(groups)

    # --- certificates -------------------------------------------------------------------------
    occurrences: list[dict[str, Any]] = []
    for scan in included:
        for comp in _components(scan):
            if (comp.get("cryptoProperties") or {}).get("assetType") == "certificate":
                props = _props(comp)
                occurrences.append(
                    {"scan": scan["id"], "source": source_of(scan)[0], "path": props.get("discovery:source"),
                     "key": cert_key(props), "props": props}
                )  # fmt: skip
    by_key: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for occ in occurrences:
        by_key[occ["key"]].append(occ)
    out["cert_raw"] = len(occurrences)
    out["cert_unique"] = len(by_key)
    out["bands"] = dict(
        Counter(band_of(g[0]["props"]["crypto:notValidAfter"], as_of) for g in by_key.values())
    )
    for band in ("EXPIRED", "LE_30", "LE_90", "VALID"):
        out["bands"].setdefault(band, 0)
    if file_fps is not None:
        ids = {s["id"] for s in included}
        files = {sid: paths for sid, paths in file_fps.items() if sid in ids}
        out["cert_files"] = sum(len(paths) for paths in files.values())
        unique_files = {fp for paths in files.values() for fp in paths.values()}
        out["cert_unique_by_file_fingerprint"] = len(unique_files)
        fp_to_keys: dict[str, set[str]] = defaultdict(set)
        key_to_fps: dict[str, set[str]] = defaultdict(set)
        for occ in occurrences:
            fingerprint = files.get(occ["scan"], {}).get(occ["path"] or "")
            if fingerprint is not None:  # the legacy scan has no files: tuple identity only
                fp_to_keys[fingerprint].add(occ["key"])
                key_to_fps[occ["key"]].add(fingerprint)
        out["cert_partitions_agree"] = all(len(v) == 1 for v in fp_to_keys.values()) and all(
            len(v) == 1 for v in key_to_fps.values()
        )

    def group_of(cn: str) -> list[dict[str, Any]]:
        return next((g for g in by_key.values() if g[0]["props"].get("crypto:subjectName") == cn), [])

    created = {s["id"]: s["created_at"] for s in included}
    for name, cn in (("dup_app", "synthetic-crypto-app.test"), ("dup_leaf", "chain.leaf.test")):
        group = group_of(cn)
        if group:
            out[name] = {
                "scans": sorted({o["scan"] for o in group}),
                "sources": len({o["source"] for o in group}),
                "locations": len({(o["source"], o["path"]) for o in group}),
                "first_scan": min(group, key=lambda o: (created[o["scan"]], o["scan"]))["scan"],
                "last_scan": max(group, key=lambda o: (created[o["scan"]], o["scan"]))["scan"],
            }

    # --- current state ------------------------------------------------------------------------
    rows = [r for scan in newest.values() for r in scan["scan_data"].get("results", []) if isinstance(r, dict)]
    out["occurrences"] = len(rows)
    out["impact"] = {k: v for k, v in Counter(r.get("impact") for r in rows).items() if k}
    issues = [r for r in rows if r.get("finding_codes")]
    out["issue"] = {k: v for k, v in Counter(r.get("impact") for r in issues).items() if k}
    weighted = sum(IMPACT_POINTS.get(r.get("impact"), 0) for r in issues)
    score = min(100, weighted * 4)
    out["risk"] = {"score": score, "grade": grade_of(score), "weighted_points": weighted}
    codes: Counter[str] = Counter()
    for row in rows:
        codes.update(row.get("finding_codes") or [])
    out["codes"] = dict(codes)
    out["top_critical"] = [r.get("title") for r in rows if r.get("impact") == "Critical"]
    algorithms = [r for r in rows if asset_class(r) == "alg"]

    def is_vulnerable(row: dict[str, Any]) -> bool:
        return bool(row.get("quantum_vulnerable")) or row.get("quantum_safe") is False

    def has_quantum_status(row: dict[str, Any]) -> bool:
        return row.get("quantum_vulnerable") is not None or row.get("quantum_safe") is not None

    # Safe = algorithm rows that are not vulnerable and carry a quantum fact; rows with no quantum
    # fact at all are "not gradeable" and stay out of the readiness fraction.
    vulnerable = sum(1 for r in algorithms if is_vulnerable(r))
    safe = sum(1 for r in algorithms if not is_vulnerable(r) and has_quantum_status(r))
    out["qv"] = vulnerable
    out["safe"] = safe
    out["not_gradeable"] = len(algorithms) - vulnerable - safe
    out["readiness"] = round(100 * safe / (safe + vulnerable), 1) if (safe + vulnerable) else None
    # NIST quantum security level of the quantum-safe rows ("none" = not recorded) and hybrids.
    qsl: dict[str, dict[str, int]] = {}
    for row in algorithms:
        if is_vulnerable(row) or not has_quantum_status(row):
            continue
        level = row.get("nist_quantum_security_level")
        bucket = qsl.setdefault("none" if level is None else str(level), {"occurrences": 0, "hybrid": 0})
        bucket["occurrences"] += 1
        bucket["hybrid"] += 1 if row.get("hybrid") else 0
    out["qsl"] = dict(sorted(qsl.items()))
    by_class: dict[str, dict[str, int]] = {}
    for klass in ("alg", "cert", "proto", "mat"):
        group = [r for r in rows if asset_class(r) == klass]
        counts = Counter(r.get("impact") for r in group)
        by_class[klass] = {**{name: counts[name] for name in IMPACT_ORDER}, "total": len(group)}
    out["by_type_impact"] = by_class
    misuse = {"WEAK_RNG", "STATIC_IV", "REUSED_NONCE", "HARDCODED_KEY"}
    out["material_with_misuse"] = sum(
        1 for r in rows if asset_class(r) == "mat" and misuse & set(r.get("finding_codes") or [])
    )

    # --- libraries ----------------------------------------------------------------------------
    libs: dict[str, set[str]] = defaultdict(set)
    for scan in newest.values():
        for comp in _components(scan):
            if comp.get("type") == "library":
                libs[str(comp["name"]).casefold()].add(source_of(scan)[0])
    out["libs"] = len(libs)
    out["libs_multi"] = sorted(name for name, srcs in libs.items() if len(srcs) > 1)
    out["libs_source_level"] = sum(len(v) for v in libs.values())

    # --- compliance pooling + attestation ledger -------------------------------------------------
    pool: dict[str, Counter[str]] = defaultdict(Counter)
    pooled = 0
    pairs: dict[tuple[str, str], int] = defaultdict(int)  # sources that need an attestation (NBE / PWE)
    in_scope: dict[tuple[str, str], int] = defaultdict(int)  # sources where the control applies at all
    attested: dict[tuple[str, str], int] = defaultdict(int)
    for scan in newest.values():
        compliance = scan["scan_data"].get("cbom_compliance")
        if not isinstance(compliance, dict) or not compliance:
            continue
        pooled += 1
        for framework, block in compliance.items():
            if not isinstance(block, dict):
                continue
            for state in STATES:
                pool[framework][state] += int(block.get(state, 0))
            for req in block.get("requirements") or []:
                if not isinstance(req, dict):
                    continue
                key = (framework, str(req.get("id")))
                if req.get("verdict") not in ("out_of_scope", "na"):
                    in_scope[key] += 1
                if req.get("verdict") in ATTESTABLE:
                    pairs[key] += 1
                    if req.get("verdict") == "pass_with_evidence":
                        attested[key] += 1
    out["pooled"] = pooled
    out["legacy"] = len(newest) - pooled
    distinct_requirements: set[tuple[str, str]] = set()
    for scan in newest.values():
        compliance = scan["scan_data"].get("cbom_compliance")
        for framework, block in (compliance.items() if isinstance(compliance, dict) else []):
            if isinstance(block, dict):
                for req in block.get("requirements") or []:
                    if isinstance(req, dict):
                        distinct_requirements.add((framework, str(req.get("id"))))
    out["requirements_distinct"] = len(distinct_requirements)
    compliance_out: dict[str, Any] = {}
    for framework, c in sorted(pool.items()):
        passed = c["pass"] + c["pass_with_evidence"]
        denominator = passed + c["fail"]
        compliance_out[framework] = {
            "pass": c["pass"],
            "pass_with_evidence": c["pass_with_evidence"],
            "fail": c["fail"],
            "nbe": c["not_bom_evidenceable"],
            "oos": c["out_of_scope"],
            "coverage": round(passed / denominator, 3) if denominator else None,
        }
    out["compliance"] = compliance_out
    out["ledger"] = {
        "pairs": len(pairs),
        "source_level": sum(pairs.values()),
        "attested_source_level": sum(attested.values()),
        # "<framework>/<requirement>" -> sources where the control applies, and sources that need evidence
        "per_requirement": {
            f"{fw}/{rid}": {"in_scope": in_scope[(fw, rid)], "needing": n} for (fw, rid), n in sorted(pairs.items())
        },
    }

    # --- per source -------------------------------------------------------------------------
    per_source: dict[str, Any] = {}
    for key, scan in sorted(newest.items(), key=lambda kv: source_of(kv[1])[1].lower()):
        _key, label, kind = source_of(scan)
        data_rows = [r for r in scan["scan_data"].get("results", []) if isinstance(r, dict)]
        klass = Counter(asset_class(r) for r in data_rows)
        impact = Counter(r.get("impact") for r in data_rows)
        libraries = [c for c in _components(scan) if c.get("type") == "library"]
        compliance_present = isinstance(scan["scan_data"].get("cbom_compliance"), dict) and bool(
            scan["scan_data"].get("cbom_compliance")
        )
        per_source[label] = {
            "kind": kind,
            "current_scan": scan["id"],
            "scans": sorted(s["id"] for s in groups[key]),
            "fidelity": "full" if compliance_present and scan["scan_data"].get("cbom_distributions") else "legacy",
            "alg": klass["alg"],
            "cert": klass["cert"],
            "proto": klass["proto"],
            "mat": klass["mat"],
            "libs": len(libraries),
            "total": len(data_rows),
            "impact": {name: impact[name] for name in IMPACT_ORDER},
        }  # fmt: skip
    out["per_source"] = per_source
    return out


def _close(a: Any, b: Any) -> bool:
    if isinstance(a, float) or isinstance(b, float):
        return a is not None and b is not None and abs(float(a) - float(b)) <= 0.0006
    return bool(a == b)


def compare(derived: Any, expected: Any, path: str = "") -> list[str]:
    """Differences where ``expected`` is not a subset of ``derived`` (dict keys, lists, scalars)."""
    problems: list[str] = []
    if isinstance(expected, dict):
        if not isinstance(derived, dict):
            return [f"{path or '/'}: expected an object, derived {derived!r}"]
        for key, want in expected.items():
            if key.startswith("_"):  # provenance notes
                continue
            if key not in derived:
                problems.append(f"{path}/{key}: not derived")
            else:
                problems.extend(compare(derived[key], want, f"{path}/{key}"))
    elif isinstance(expected, list):
        if derived != expected:
            problems.append(f"{path}: derived {derived!r}, expected {expected!r}")
    elif not _close(derived, expected):
        problems.append(f"{path}: derived {derived!r}, expected {expected!r}")
    return problems


def verify(
    scans: list[dict[str, Any]],
    as_of: date,
    expected: dict[str, Any],
    *,
    file_fps: dict[int, dict[str, str]] | None = None,
) -> list[str]:
    """Problems found when comparing ``derive(scans)`` with ``expected['appendix_b'/'per_source']``."""
    derived = derive(scans, as_of, file_fps=file_fps)
    problems = compare(derived, expected["appendix_b"], "appendix_b")
    problems += compare(derived["per_source"], expected["per_source"], "per_source")
    if file_fps is not None and derived.get("cert_unique") != derived.get("cert_unique_by_file_fingerprint"):
        problems.append(
            f"certificate identity: tuple hash says {derived.get('cert_unique')}, "
            f"DER fingerprints say {derived.get('cert_unique_by_file_fingerprint')}"
        )
    if file_fps is not None and not derived.get("cert_partitions_agree"):
        problems.append("certificate identity: tuple-hash and DER-fingerprint partitions disagree")
    return problems


def canary_confinement(scans: list[dict[str, Any]], canaries: dict[str, int]) -> list[str]:
    """Each canary string must occur in the blob of exactly its own scan and in no other."""
    blobs = {s["id"]: json.dumps(s["scan_data"], sort_keys=True) for s in scans}
    problems = []
    for token, owner in canaries.items():
        seen_in = sorted(sid for sid, blob in blobs.items() if token in blob)
        if seen_in != [owner]:
            problems.append(f"canary {token!r} occurs in scans {seen_in}, expected only [{owner}]")
    return problems


# ---------------------------------------------------------------------------------------------
# CLI: verify expected.json against the pinned fixture world
# ---------------------------------------------------------------------------------------------
def _fixture_world(path: Path) -> tuple[list[dict[str, Any]], date]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return raw["scans"], date.fromisoformat(raw["as_of"])


def main() -> int:
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--fixture",
        type=Path,
        default=root / "backend" / "tests" / "fixtures" / "cbom_team_rollup_scans.json",
    )
    parser.add_argument("--expected", type=Path, default=root / "e2e" / "fixtures" / "expected.json")
    parser.add_argument(
        "--trees",
        type=Path,
        default=root / "e2e" / ".work" / "trees",
        help="trees built by fixtures/build_trees.sh; adds the certificate-FILE fingerprint evidence",
    )
    parser.add_argument("--print", action="store_true", help="print the derived quantities as JSON")
    args = parser.parse_args()

    scans, as_of = _fixture_world(args.fixture)
    file_fps: dict[int, dict[str, str]] | None = None
    if args.trees.is_dir():
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import plan

        file_fps = {
            item.key: tree_cert_fingerprints(args.trees / item.payload[1])
            for item in plan.SEED
            if item.payload[0] == "tree" and (args.trees / item.payload[1]).is_dir()
        }
    derived = derive(scans, as_of, file_fps=file_fps)
    if args.print:
        print(json.dumps(derived, indent=2, sort_keys=True))
        if not args.expected.is_file() or args.expected.stat().st_size == 0:
            return 0
    expected = json.loads(args.expected.read_text(encoding="utf-8"))
    if file_fps is None:
        print(f"note: {args.trees} not found; certificate-file evidence (cert_files) not checked")
        expected["appendix_b"].pop("cert_files", None)
    problems = compare(derived, expected["appendix_b"], "appendix_b")
    problems += compare(derived["per_source"], expected["per_source"], "per_source")
    problems += canary_confinement(scans, expected.get("canary_owner_scan", {}))
    if problems:
        print(f"expected.json does NOT match the pinned fixture world ({as_of}):", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print(f"OK: expected.json (appendix_b, per_source) reproduced from {args.fixture.name} at {as_of}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
