"""The code-scan results page's ``scan_metadata`` sections for one CBOM Sources run (CB-38 W2b, one results template).

``GET /{team_id}/cbom/sources/runs/{run_id}/parity`` serves this. The code page (``CbomResults.tsx``) reads these keys
from a code scan's ``scan_metadata``; a run gets the same keys in the same shapes, so the page renders both:

* ``cbom_compliance``: per-framework tri-state verdicts (pass / pass_with_evidence / fail / out_of_scope /
  not_bom_evidenceable / na per requirement; NIST SP 1800-38B / 800-57 / 1800-38C, OMB M-23-02, EU CRA / DORA, PCI-DSS,
  FIPS 140-3, BSI TR-02102, CNSA 2.0, RBI FREE-AI protection, CERT-In CBOM, SEBI CSCRF). Computed by the code lane's
  own engine, ``aibom.cbom.compliance.run_cbom_compliance``, unchanged: this module only builds its input graph (one
  ``crypto_asset`` component per collected asset, with the ``crypto:`` properties the checks read) from what the run
  API already decided for that asset: the PQC class from ``posture.classify_pqc`` (the one class function, so a
  quantum verdict never disagrees with ``/posture``), classical strength from ``run_results.strength`` (the strength
  chart's rule), primitive / NIST level from ``algid``. Requirement ``refs`` are the run's ``zs-asset-<id>`` bom-refs
  (the same refs as ``/results`` distributions and the ``/assets`` items' ``bom_ref``).
* ``rbi_csf_rollup`` / ``certin_posture``: the backend's own roll-up functions (``dashboard.rbi_posture``,
  ``dashboard.certin_posture``) over that compliance blob, exactly as ``scan_metadata.py`` calls them for a code scan.
* ``cbom_graph`` (+ ``_compact`` / ``_expanded``): the crypto dependency graph. Full graph: one node per collected
  asset (``zs-asset-<id>``), libraries as ``framework`` nodes, certificate chain ``signed_by`` edges. The compact (40)
  and expanded (120 node) views are the code lane's ``aibom.cbom.graph_detail.build_detailed`` with the same budgets;
  its "folder" layer is the run's source / target (host, account, cluster) here.
* ``cbom_coverage``: "What this scan covered" in ``CbomCoverageReport`` shape: jobs that failed / were cancelled /
  collected only part, targets not reached, and the ``coverage`` ("not collected") assets grouped by source and reason.

Rule P: nothing here is a posture number (readiness, PQC counts, severity totals stay in ``/results`` and
``/posture``). The aibom engine is imported lazily (``engine()``); without it the three compliance keys are ``None``
and ``engine.compliance`` says ``unavailable`` (the page then hides those sections, as for a legacy scan).

Cached in-process like ``/results``: keyed by (run id, ``run.last_updated``, UTC day, KB version) plus the same inputs
digest; an active run's entry is reused for ``run_results.LIVE_TTL_S`` seconds; bounded by summed assets
(``CACHE_ROWS``, ``CBOM_RUN_PARITY_CACHE_ROWS``, default ``/results``' bound), least recently used out first. An
engine error at run time degrades like a missing engine (null compliance keys, logged once), never a 500.
"""
from __future__ import annotations

import datetime as _dt
import os
import sys
import threading
import time
from collections import Counter, OrderedDict
from itertools import pairwise
from pathlib import Path
from typing import Any

from sqlmodel import Session, select

from backend.new_models import CbomCollectedAsset, CbomCollectionRun
from backend.utilities.cbom_sources import crypto_kb
from backend.utilities.cbom_sources import identity as ID
from backend.utilities.cbom_sources import posture as POSTURE
from backend.utilities.cbom_sources import run_results as RR
from backend.utilities.cbom_sources.common import iso_z, utcnow

GRAPH_CAP = 50_000  # assets judged / drawn (the run CycloneDX export cap)
COVERAGE_NOTES_CAP = 50
# the cache holds at most this many summed assets (each entry weighs its assets_total), like /results
CACHE_ROWS = int(os.environ.get("CBOM_RUN_PARITY_CACHE_ROWS") or RR.CACHE_ROWS)
COMPACT_MAX_NODES = 40  # dashboard.bom_graph_view.COMPACT_MAX_NODES / aibom normalize
EXPANDED_MAX_NODES = 120
_KEY_KINDS = {"private_key": "private-key", "public_key": "public-key", "keystore": "keystore",
              "ssh_host_key": "public-key", "ssh_user_key": "public-key", "kms_key": "secret-key",
              "cloud_secret": "secret-key", "signing_key": "private-key", "host_secret": "secret-key"}
_LIBRARY_TYPES = frozenset({"crypto_library", "process_library"})
_ALG_SUFFIX = "-alg"
_JOB_GAPS = {"failed": "failed", "cancelled": "was cancelled", "expired": "timed out"}


# ----------------------------------------------------------------------------- the code lane's engine
_ENGINE_LOCK = threading.Lock()
_ENGINE: dict[str, Any] = {}


def _aibom_paths() -> list[Path]:
    """Where the aibom package's ``src`` may be: ``CBOM_AIBOM_SRC``, the backend image (``/opt/aibom/src``), the
    repository checkout (tests, local runs)."""
    out = []
    if os.environ.get("CBOM_AIBOM_SRC"):
        out.append(Path(os.environ["CBOM_AIBOM_SRC"]))
    out.append(Path("/opt/aibom/src"))
    out.append(Path(__file__).resolve().parents[3] / "aibom" / "src")
    return out


def engine() -> dict[str, Any]:
    """``{"compliance": module|None, "graph": module|None, "reason": str|None}``; imported once per process."""
    with _ENGINE_LOCK:
        if _ENGINE:
            return _ENGINE
        try:
            import aibom.cbom.compliance  # noqa: F401
        except ImportError:
            for path in _aibom_paths():
                if (path / "aibom" / "__init__.py").is_file():
                    # a namespace package named aibom (the repository's top-level folder) may shadow the real one
                    for name in [m for m in sys.modules if m == "aibom" or m.startswith("aibom.")]:
                        sys.modules.pop(name, None)
                    if str(path) not in sys.path:
                        sys.path.insert(0, str(path))
                    break
        try:
            from aibom.cbom import compliance as compliance_mod
            from aibom.cbom import graph_detail as graph_mod
            from aibom.model import component as component_mod
            from aibom.model import result as result_mod

            _ENGINE.update({"compliance": compliance_mod, "graph": graph_mod, "component": component_mod,
                            "result": result_mod, "reason": None})
        except Exception as exc:  # noqa: BLE001 - any import failure: the backend still serves the rest of the page
            _ENGINE.update({"compliance": None, "graph": None, "component": None, "result": None,
                            "reason": f"crypto compliance engine not installed in this backend ({type(exc).__name__})"})
        return _ENGINE


_ERRORS_LOGGED: set[tuple[str, str]] = set()


def _engine_error(part: str, exc: BaseException) -> None:
    """``cbom run parity engine error part= error=``: logged once per process per part and exception type."""
    key = (part, type(exc).__name__)
    with _ENGINE_LOCK:
        if key in _ERRORS_LOGGED:
            return
        _ERRORS_LOGGED.add(key)
    line = f"{RR.utc_timestamp()} cbom run parity engine error part={part} error={type(exc).__name__}"
    request_id = RR.current_request_id()
    try:
        # the exception text is not logged: it can carry customer asset names
        RR.console.print(line + (f" request_id={request_id}" if request_id else ""),
                         markup=False, highlight=False, soft_wrap=True)
    except Exception:  # noqa: BLE001, S110 - logging must never fail a request
        pass


def _reset_engine() -> None:  # tests
    with _ENGINE_LOCK:
        _ENGINE.clear()
        _ERRORS_LOGGED.clear()


# ----------------------------------------------------------------------------- one asset -> graph facts
def _bom_ref(asset_id: int | None) -> str:
    return f"zs-asset-{asset_id}"


def _cdx_asset_type(row: CbomCollectedAsset) -> str | None:
    if row.asset_type in _LIBRARY_TYPES:
        return None
    if ID.is_certificate(row):
        return "certificate"
    if row.cdx_type in ("algorithm", "protocol", "related-crypto-material", "certificate"):
        return row.cdx_type
    if row.asset_type in _KEY_KINDS:
        return "related-crypto-material"
    return "algorithm"


def _protocol(row: CbomCollectedAsset, facts: dict[str, Any]) -> tuple[str | None, str | None]:
    """(protocolType, the lowest version offered) of a network asset."""
    offered = facts.get("protocols") if isinstance(facts.get("protocols"), list) else []
    labels = [RR._proto_label(p) for p in offered] or [RR._proto_label(row.protocol)]
    labels = [lb for lb in labels if lb]
    if not labels:
        kind = {"ssh_endpoint": "ssh", "tls_endpoint": "tls"}.get(row.asset_type)
        return kind, None
    first = min(labels)
    kind, _, version = first.partition(" ")
    return kind.lower(), version or None


def _facts_of(row: CbomCollectedAsset, view: dict[str, Any], memo: Any) -> dict[str, Any]:
    """What the run API decided for one asset, in the graph vocabulary (shared by the compliance input and the graph
    nodes, so the two never disagree)."""
    facts = row.facts if isinstance(row.facts, dict) else {}
    leaf = facts.get("leaf") if isinstance(facts.get("leaf"), dict) else {}
    codes = tuple(c for c in view.get("finding_codes") or [] if isinstance(c, str) and not c.startswith("COVERAGE_"))
    klass = POSTURE.classify_pqc(row, list(codes))[0]
    level = RR.strength(klass, codes, memo)
    texts = [t for t in (row.algorithm, facts.get("key_alg") or leaf.get("key_alg"), facts.get("group"),
                         facts.get("kex"), facts.get("sig_alg") or leaf.get("sig_alg")) if t]
    idents = [i for i in (memo.identity(t) for t in texts) if i is not None]
    primitive = next((i.primitive for i in idents if i.primitive), None)
    nist = next((i.nist_category for i in idents if i.nist_category), None)
    impact = view.get("impact") if view.get("impact") in RR._IMPACT_RANK else None
    return {"codes": codes, "klass": klass, "strength": level, "primitive": primitive, "nist": nist,
            "impact": impact, "facts": facts, "leaf": leaf, "idents": idents,
            "weak": level == "weak", "quantum_vulnerable": klass == "quantum-vulnerable"}


def _component_properties(row: CbomCollectedAsset, f: dict[str, Any], source_name: str,
                          as_algorithm: bool = False) -> dict[str, str]:
    """``crypto:`` properties of the asset's component; ``as_algorithm``: of the algorithm component a certificate,
    key or protocol carries (its public-key / key-exchange algorithm), as the code lane's emitter derives one."""
    facts, leaf = f["facts"], f["leaf"]
    asset_type = "algorithm" if as_algorithm else (_cdx_asset_type(row) or "algorithm")
    props: dict[str, str] = {"crypto:assetType": asset_type, "discovery:source": str(row.location or "")[:512],
                             "zs:source": source_name, "zs:target": str(row.target or "")}
    if f["strength"] in ("weak", "moderate", "strong"):
        props["crypto:strength"] = f["strength"]
    if f["klass"] == "quantum-vulnerable":
        props["crypto:quantumVulnerable"] = "true"
        props["crypto:nistQuantumSecurityLevel"] = "0"
        migration = next((c for c in f["codes"] if (crypto_kb.entry("node", c) or {}).get("pqc") == "quantum-broken"),
                         None)
        target = crypto_kb.summary_fix("node", [migration]) if migration else None
        if target:
            props["crypto:pqcMigrationTarget"] = str(target)[:200]
    elif f["klass"] in ("quantum-safe", "hybrid", "grover-weakened"):
        props["crypto:quantumVulnerable"] = "false"
        if f["nist"]:
            props["crypto:nistQuantumSecurityLevel"] = str(f["nist"])
        if f["klass"] == "hybrid":
            props["crypto:hybrid"] = "true"
    if f["primitive"]:
        props["crypto:primitive"] = str(f["primitive"])
    elif asset_type == "algorithm":
        props["crypto:primitive"] = "unknown"
    key_size = row.key_size or facts.get("key_size") or leaf.get("key_size") or facts.get("bits")
    if isinstance(key_size, int) and not isinstance(key_size, bool) and key_size > 0:
        props["crypto:keySize"] = str(key_size)
    if asset_type == "protocol":
        kind, version = _protocol(row, facts)
        if kind:
            props["crypto:protocolType"] = kind
        if version:
            props["crypto:protocolVersion"] = version
    elif asset_type == "certificate":
        for prop, key in (("crypto:subjectName", "subject"), ("crypto:issuerName", "issuer"),
                          ("crypto:notValidBefore", "not_before"), ("crypto:notValidAfter", "not_after"),
                          ("crypto:signatureAlgorithm", "sig_alg"), ("crypto:publicKeyAlgorithm", "key_alg")):
            value = facts.get(key) or leaf.get(key)
            if value:
                props[prop] = str(value)[:255]
        props["crypto:selfSigned"] = "true" if facts.get("self_signed") or leaf.get("self_signed") else "false"
        if RR._is_ca(row):
            props["crypto:isCertificateAuthority"] = "true"
    elif asset_type == "related-crypto-material":
        props["crypto:materialKind"] = _KEY_KINDS.get(row.asset_type, "key")
    curve = facts.get("curve") or facts.get("group")
    if curve:
        props["crypto:curve"] = str(curve)[:64]
    return props


def _display_name(row: CbomCollectedAsset) -> str:
    facts = row.facts if isinstance(row.facts, dict) else {}
    leaf = facts.get("leaf") if isinstance(facts.get("leaf"), dict) else {}
    subject = (facts.get("subject") or leaf.get("subject")) if ID.is_certificate(row) else None
    return str(subject or row.algorithm or row.name or row.location or f"asset {row.id}")[:255]


# ----------------------------------------------------------------------------- the pass
def _gather(session: Session, run: CbomCollectionRun, team_id: int, now: _dt.datetime) -> dict[str, Any]:
    from backend.utilities.cbom_sources.classify import shown

    jobs, sources, _nodes = RR._job_context(session, team_id, int(run.id or 0))
    names: dict[int, str] = {}
    memo = RR._Memo()
    assets: list[tuple[CbomCollectedAsset, dict[str, Any], str]] = []
    libraries: list[tuple[CbomCollectedAsset, dict[str, Any], str]] = []
    coverage: Counter = Counter()
    coverage_targets: dict[tuple[str, str], set] = {}
    total = 0
    truncated = False
    from backend.utilities.cbom_sources import resource_identity as RI

    # one graph node / compliance component per resource, as the run's assets API (review 6039899144 B1)
    fold = RI.run_fold(session, team_id, int(run.id or 0))
    query = (select(CbomCollectedAsset)
             .where(CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.run_id == run.id, RI.kept_clause(fold))
             .order_by(CbomCollectedAsset.id)  # type: ignore[arg-type]
             .execution_options(yield_per=RR.YIELD_PER))
    for row in session.exec(query):
        name = names.get(row.job_id)
        if name is None:
            job = jobs.get(row.job_id)
            name = names[row.job_id] = RR._source_ref(job, sources.get((job.source_id if job else row.source_id) or 0),
                                                      row.source_id)[1]
        if row.asset_type == "coverage":
            facts = row.facts if isinstance(row.facts, dict) else {}
            what = str(facts.get("what") or "part of the source")[:120]
            reason = str(facts.get("reason") or "not collected")[:200]
            coverage[(name, what, reason)] += 1
            coverage_targets.setdefault((name, what, reason), set()).add(str(row.target or ""))
            continue
        total += 1
        if total > GRAPH_CAP:
            truncated = True
            continue
        f = _facts_of(row, shown(row, now), memo)
        (libraries if row.asset_type in _LIBRARY_TYPES else assets).append((row, f, name))
    return {"jobs": jobs, "sources": sources, "assets": assets, "libraries": libraries, "coverage": coverage,
            "coverage_targets": coverage_targets, "total": total, "truncated": truncated}


def _compliance(g: dict[str, Any], run: CbomCollectionRun) -> dict[str, Any] | None:
    eng = engine()
    if eng["compliance"] is None:
        return None
    Crypto = eng["component"].CryptoAssetComponent
    Framework = eng["component"].FrameworkComponent if hasattr(eng["component"], "FrameworkComponent") else None
    Meta = eng["component"].MetadataComponent
    comps = []
    for row, f, name in g["assets"]:
        comps.append(Crypto(bom_ref=_bom_ref(row.id), name=_display_name(row),
                            properties=_component_properties(row, f, name)))
        if _cdx_asset_type(row) != "algorithm" and (f["idents"] or f["quantum_vulnerable"]):
            # the algorithm a certificate / key / endpoint uses, as its own algorithm component (the checks judge
            # algorithms): quantum verdict and strength are the asset's (posture class, strength rule)
            alg = f["idents"][0].name if f["idents"] else _display_name(row)
            comps.append(Crypto(bom_ref=_bom_ref(row.id) + _ALG_SUFFIX, name=str(alg)[:255],
                                properties=_component_properties(row, f, name, as_algorithm=True)))
    if Framework is not None:
        for row, f, name in g["libraries"]:
            try:
                comps.append(Framework(bom_ref=_bom_ref(row.id), name=_display_name(row),
                                       properties={"crypto:role": "library", "discovery:source": str(row.location)}))
            except ValueError:  # a library node is optional for every check (pydantic rejects odd properties)
                continue
    result = eng["result"].ScanResult(subject=Meta(name=f"Sources run #{run.id}"),
                                      components=sorted(comps, key=lambda c: (c.kind, c.bom_ref)))
    report = eng["compliance"].run_cbom_compliance(result)
    for block in report.values():  # refs name the run's assets: zs-asset-<id> (a derived algorithm -> its asset)
        for req in (block.get("requirements") or []) if isinstance(block, dict) else []:
            if isinstance(req.get("refs"), list):
                req["refs"] = list(dict.fromkeys(str(r).removesuffix(_ALG_SUFFIX) for r in req["refs"]))
    return report


def _graph(g: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, Any] | None]:
    nodes: list[dict[str, Any]] = []
    folder_key: dict[str, str] = {}
    chains: dict[tuple[str, str], list[tuple[int, str]]] = {}
    for row, f, name in g["assets"]:
        ref = _bom_ref(row.id)
        nodes.append({"id": ref, "label": _display_name(row), "kind": "crypto_asset",
                      "asset_type": _cdx_asset_type(row), "primitive": f["primitive"], "impact": f["impact"],
                      "quantum_vulnerable": f["quantum_vulnerable"], "weak": f["weak"], "location": row.location,
                      "source": name, "target": row.target, "asset_id": row.id})
        folder_key[ref] = _folder_location(name, row.target, ref)
        index = RR._chain_index(row)
        if index is not None and ID.is_certificate(row):
            chains.setdefault((str(row.job_id), str(row.target or "")), []).append((index, ref))
    for row, f, name in g["libraries"]:
        ref = _bom_ref(row.id)
        nodes.append({"id": ref, "label": _display_name(row), "kind": "framework", "asset_type": None,
                      "primitive": None, "impact": f["impact"], "quantum_vulnerable": False,
                      # a library is "weak" when it carries a finding (end of life, a CVE, a weak default), as
                      # the code lane flags a vulnerable crypto library; the strength rule judges algorithms only
                      "weak": bool(f["codes"]), "location": row.location, "source": name,
                      "target": row.target, "asset_id": row.id})
        folder_key[ref] = _folder_location(name, row.target, ref)
    edges: list[dict[str, Any]] = []
    for members in chains.values():
        members.sort()
        for (_i, child), (_j, parent) in pairwise(members):
            if child != parent:
                edges.append({"source": child, "target": parent, "rel": "signed_by"})
    nodes.sort(key=lambda n: str(n["id"]))
    edges.sort(key=lambda e: (e["source"], e["rel"], e["target"]))
    full = {"nodes": nodes, "edges": edges,
            "meta": {"raw_node_count": len(nodes), "raw_edge_count": len(edges), "lane": "cbom_run",
                     "truncated": bool(g["truncated"]), "assets_total": g["total"]}}
    eng = engine()
    if eng["graph"] is None or not nodes:
        empty = {"nodes": [], "edges": [], "meta": {"assets": 0, "shown_assets": 0}}
        return full, (empty if not nodes else None), (empty if not nodes else None)
    real = {n["id"]: n.get("location") for n in nodes}
    # build_detailed groups assets by the folder of ``location``: give it source / target as the folder
    shaped = {"nodes": [{**n, "location": folder_key[n["id"]]} for n in nodes], "edges": edges}

    def view(max_nodes: int) -> dict[str, Any]:
        out = eng["graph"].build_detailed(shaped, max_nodes=max_nodes)
        for n in out["nodes"]:
            if n.get("id") in real:
                n["location"] = real[n["id"]]
            elif n.get("kind") == "location" and isinstance(n.get("label"), str):
                n["label"] = _unescape(n["label"])
        out.setdefault("meta", {})["truncated"] = bool(g["truncated"])
        return out

    try:
        return full, view(COMPACT_MAX_NODES), view(EXPANDED_MAX_NODES)
    except Exception as exc:  # noqa: BLE001 - an engine bug must not cost the page its graph and banner
        _engine_error("graph", exc)
        return full, None, None


_ESC = {"/": "∕", ":": "∶"}  # build_detailed splits a location on "/" and ":"


def _folder_location(source: str, target: Any, ref: str) -> str:
    def esc(text: str) -> str:
        for a, b in _ESC.items():
            text = text.replace(a, b)
        return text.strip() or "-"
    return f"{esc(str(source))}/{esc(str(target or 'no target'))}/{ref}"


def _unescape(text: str) -> str:
    for a, b in _ESC.items():
        text = text.replace(b, a)
    return text.replace("/ (", " (").rstrip("/").replace("//", " / ")


def _coverage(g: dict[str, Any]) -> dict[str, Any] | None:
    """``CbomCoverageReport``: ``notes`` (``kind`` skipped|info) and ``skipped`` (how many notes say something was
    not read)."""
    notes: list[dict[str, str]] = []
    for job in g["jobs"].values():
        if job.kind != "collect" and job.kind != "discover":
            continue
        name = ID.job_source_name(job, g["sources"].get(job.source_id or 0))
        gap = _JOB_GAPS.get(job.status)
        if gap:
            reason = f": {job.error[:200]}" if job.error else ""
            notes.append({"key": f"job-{job.id}", "kind": "skipped",
                          "text": f"{name}: the collection {gap}{reason}; nothing from it is in these results"})
            continue
        targets = (job.result or {}).get("targets") if isinstance(job.result, dict) else None
        missed = [t for t in targets or [] if isinstance(t, dict) and str(t.get("status") or "ok") != "ok"]
        if missed:
            by_status = Counter(str(t.get("status")) for t in missed)
            detail = ", ".join(f"{n} {s.replace('_', ' ')}" for s, n in sorted(by_status.items()))
            shown_targets = ", ".join(str(t.get("target")) for t in missed[:5])
            more = f" and {len(missed) - 5} more" if len(missed) > 5 else ""
            notes.append({"key": f"job-{job.id}-targets", "kind": "skipped",
                          "text": f"{name}: {len(missed)} target(s) not collected ({detail}): {shown_targets}{more}"})
    for (name, what, reason), count in sorted(g["coverage"].items()):
        targets = sorted(t for t in g["coverage_targets"].get((name, what, reason), set()) if t)
        on = f" on {len(targets)} target(s)" if targets else ""
        notes.append({"key": f"coverage-{len(notes)}", "kind": "skipped",
                      "text": f"{name}: {what} not collected{on} ({reason})"})
    if g["truncated"]:
        notes.append({"key": "truncated", "kind": "info",
                      "text": f"The dependency graph and the compliance verdicts judge the first {GRAPH_CAP:,} of "
                              f"{g['total']:,} assets; every count elsewhere on this page covers all of them."})
    if not notes:
        return None
    skipped = sum(1 for n in notes if n["kind"] == "skipped")
    notes = notes[:COVERAGE_NOTES_CAP]
    return {"notes": notes, "skipped": skipped}


def _compute(session: Session, run: CbomCollectionRun, team_id: int, now: _dt.datetime) -> dict[str, Any]:
    from backend.utilities.dashboard.certin_posture import build_certin_posture
    from backend.utilities.dashboard.rbi_posture import build_rbi_csf_rollup

    g = _gather(session, run, team_id, now)
    reason = None
    try:
        compliance = _compliance(g, run)
        rbi = build_rbi_csf_rollup(cbom_compliance=compliance) if compliance else None
        certin = build_certin_posture(cbom_compliance=compliance) if compliance else None
    except Exception as exc:  # noqa: BLE001 - degrade like a missing engine instead of a 500 for the whole page
        _engine_error("compliance", exc)
        compliance = rbi = certin = None
        reason = f"crypto compliance engine error ({type(exc).__name__})"
    full, compact, expanded = _graph(g)
    return {
        "scan_metadata": {
            "cbom_compliance": compliance,
            "rbi_csf_rollup": rbi,
            "certin_posture": certin,
            "cbom_graph": full, "cbom_graph_compact": compact, "cbom_graph_expanded": expanded,
            "cbom_coverage": _coverage(g),
            "cbom_input": None, "repo_url": None, "branch": None, "zip_file_used": None, "cbom_file_used": False,
            "scan_binaries": False,
        },
        "engine": ({"compliance": "available"} if compliance is not None
                   else {"compliance": "unavailable", "reason": reason or engine()["reason"]}),
        "assets_judged": len(g["assets"]) + len(g["libraries"]),
        "assets_total": g["total"],
        "computed_at": iso_z(now),
    }


# ----------------------------------------------------------------------------- cache
_CACHE: OrderedDict[int, tuple[tuple[Any, ...], str, bool, float, dict[str, Any]]] = OrderedDict()
_CACHE_LOCK = threading.Lock()
_LOCKS: dict[int, threading.Lock] = {}
COMPUTE_COUNT: Counter[int] = Counter()


def clear_cache() -> None:
    with _CACHE_LOCK:
        _CACHE.clear()
        _LOCKS.clear()
        COMPUTE_COUNT.clear()


def _lock(run_id: int) -> threading.Lock:
    with _CACHE_LOCK:
        return _LOCKS.setdefault(run_id, threading.Lock())


def _degraded(computed: dict[str, Any]) -> bool:
    """True when an engine error (not a missing engine) shaped this result: it is retried after LIVE_TTL_S."""
    return "engine error" in str(computed.get("engine", {}).get("reason") or "")


def run_parity(session: Session, run: CbomCollectionRun, *, team_id: int, risk_model: dict[str, Any] | None,
               now: _dt.datetime | None = None) -> dict[str, Any]:
    now = now or utcnow()
    judged_on = now.date().isoformat()
    kb_version = crypto_kb.version()
    key, digest, _count = RR._inputs(session, team_id, run, judged_on, kb_version, risk_model)
    rid = int(run.id or 0)
    active = run.status in RR.ACTIVE_STATUSES
    with _lock(rid):
        with _CACHE_LOCK:
            hit = _CACHE.get(rid)
        # a live run, or a result degraded by an engine error, is only reused for LIVE_TTL_S
        short = hit is not None and (active or _degraded(hit[4]))
        fresh = hit is not None and hit[0] == key and hit[1] == digest and hit[2] == active and (
            not short or time.monotonic() - hit[3] < RR.LIVE_TTL_S)
        if fresh:
            computed = hit[4]  # type: ignore[index]
            with _CACHE_LOCK:
                if rid in _CACHE:
                    _CACHE.move_to_end(rid)  # least recently *used*: a read keeps the run in the cache
        else:
            started = time.perf_counter()
            computed = _compute(session, run, team_id, now)
            with _CACHE_LOCK:
                COMPUTE_COUNT[rid] += 1
                _CACHE[rid] = (key, digest, active, time.monotonic(), computed)
                _CACHE.move_to_end(rid)
                total = sum(max(int(e[4]["assets_total"]), 1) for e in _CACHE.values())
                while total > CACHE_ROWS and len(_CACHE) > 1:  # least recently used out; the newest stays
                    old, entry = _CACHE.popitem(last=False)
                    total -= max(int(entry[4]["assets_total"]), 1)
                    lock = _LOCKS.get(old)
                    if lock is not None and not lock.locked():  # a request computing that run keeps its lock
                        _LOCKS.pop(old, None)
                    COMPUTE_COUNT.pop(old, None)
            RR._log_summary(run=rid, team=team_id, rows=computed["assets_total"], what="parity",
                            ms=int((time.perf_counter() - started) * 1000), digest=digest,
                            engine=computed["engine"]["compliance"])
    return {"run_id": rid, **computed, "kb_version": kb_version, "judged_on": judged_on, "inputs_digest": digest,
            "state": "live" if active else "ready", "stale": False}


__all__ = ["COMPACT_MAX_NODES", "EXPANDED_MAX_NODES", "GRAPH_CAP", "clear_cache", "engine", "run_parity"]
