"""VEX semantics for every CBOM surface (CB-22, KF-11): one rule for which CycloneDX 1.6 ``analysis`` a finding gets.

Used by the Sources run export (``inventory.vulnerabilities``) and the code-scan VEX (``routers/certin.py``); the run
VEX deliverable of CB-38 (``run_deliverables``, PR #124) can import ``code_basis`` / ``analysis_for`` /
``affects_cut`` from here so the three documents cannot disagree.

CycloneDX 1.6 ``analysis.state`` (published schema 1.6.2, ``impactAnalysisState``): ``resolved``,
``resolved_with_pedigree``, ``exploitable``, ``in_triage``, ``false_positive``, ``not_affected`` (``not_affected``
"should" carry a ``justification``). ``response``: ``can_not_fix``, ``will_not_fix``, ``update``, ``rollback``,
``workaround_available``.

Rules (``zs:vex_rules`` = ``VEX_RULES``; DA default OA-10c; each entry also says its ``zs:vex_basis``)
------------------------------------------------------------------------------------------------------
==============================================================  ===============  =============  =========================
Finding                                                         basis            state          detail / response
==============================================================  ===============  =============  =========================
weak algorithm or setting a collector observed on the asset     observed         exploitable    observed; a classical
(Sources run, KB namespace ``node``: TLS 1.0 accepted, RSA <                                    attack is known today
2048, expired certificate, plain-text secret ...)
quantum-future only: KB category ``pqc`` (QUANTUM_VULNERABLE,   quantum_only     in_triage      harvest-now-decrypt-later
NO_PQ_KEX, SSH_NO_PQ_KEX, IKE_NO_PQ) or ``pqc:                                                  (key exchange) or future
grover-weakened`` (DISK_XTS_128); no classical attack today                                     forgery; the assets'
                                                                                                Q-grade (``qgrade``)
inferred from a version or date, not behaviour (LIB_KNOWN_CVE,  inferred         in_triage      a version is not proof
LIB_EOL, DB_EOL_VERSION; code: EOL_* / *_CRYPTO_LIBRARY /
LIBRARY_CVE_RANGE / KNOWN_TLS_VULNERABILITY)
weakness seen in source code or configuration (code scan, KB    static           in_triage      in use in the code; that it
namespace ``code``)                                                                             protects something
                                                                                                reachable is not proven
CVE matched from the evidence or a library version              cve              in_triage      a match is not proof
finding of an earlier complete collection of the same source    drift_resolved   resolved       not found again (drift
(or scan of the same repository) that this one no longer has                                    event ``resolved``)
remediation plan ``done`` (run VEX deliverable)                 (any)            resolved
remediation plan ``accepted_risk``                              (any)            (unchanged)    response will_not_fix
remediation plan ``in_progress``                                (any)            (unchanged)    response update
==============================================================  ===============  =============  =========================

Never emitted from evidence: ``not_affected`` (CycloneDX: the component is not affected, with a justification; only a
customer's triage can say that, a follow-up of CB-22), ``false_positive``, ``resolved_with_pedigree``. Unread scope is
never resolved: drift lists a finding under a coverage gap as ``not_read``, records no ``resolved`` event for it, so it
gets no ``resolved`` entry here; coverage rows are never components and never affected.
"""
from __future__ import annotations

import json
from collections import Counter
from typing import Any, Iterable, Mapping

from backend.utilities.cbom_sources import crypto_kb

VEX_RULES = "cb22-1"
AFFECTS_CAP = 5_000  # affected assets listed per entry; the rest are counted (``affects_cut``)
REMOVED_KEYS_CAP = 200

OBSERVED, STATIC, QUANTUM_ONLY, INFERRED, CVE, DRIFT_RESOLVED = (
    "observed", "static", "quantum_only", "inferred", "cve", "drift_resolved")
BASES = (OBSERVED, STATIC, QUANTUM_ONLY, INFERRED, CVE, DRIFT_RESOLVED)
DEFAULT_STATE = {OBSERVED: "exploitable", STATIC: "in_triage", QUANTUM_ONLY: "in_triage", INFERRED: "in_triage",
                 CVE: "in_triage", DRIFT_RESOLVED: "resolved"}

# judged from a version or a date, never from behaviour seen on the asset
INFERRED_CODES = {
    "node": frozenset({"LIB_KNOWN_CVE", "LIB_EOL", "DB_EOL_VERSION"}),
    "code": frozenset({"EOL_CRYPTO_LIBRARY", "EOL_BASE_IMAGE", "VULNERABLE_CRYPTO_LIBRARY", "LIBRARY_CVE_RANGE",
                       "KNOWN_TLS_VULNERABILITY"}),
}
# quantum-only codes about a key exchange: what is recorded today is decrypted later
HNDL_CODES = frozenset({"NO_PQ_KEX", "SSH_NO_PQ_KEX", "IKE_NO_PQ"})

DETAIL_OBSERVED = ("Observed directly by the collector on each listed asset: the weak algorithm or setting is in use "
                   "where it was collected, and a classical attack on it is known today.")
DETAIL_STATIC = ("Seen in the source code or configuration of each listed asset: the weak use is real, but whether it "
                 "protects data or a path an attacker can reach is not proven by a code scan; confirm, then fix or "
                 "record the exception.")
DETAIL_HNDL = ("Quantum-only exposure, no classical attack known today: the key exchange is quantum-vulnerable, so "
               "traffic recorded now can be decrypted once a cryptographically relevant quantum computer exists "
               "(harvest now, decrypt later). Plan the post-quantum migration (Mosca X + Y > Z).")
DETAIL_QUANTUM = ("Quantum-only exposure, no classical attack known today: a future cryptographically relevant "
                  "quantum computer could forge these signatures or recover these keys (or, for 128-bit symmetric "
                  "keys, halve their strength). Plan the post-quantum migration (Mosca X + Y > Z).")
DETAIL_QUANTUM_ANY = ("Quantum-only exposure, no classical attack known today: a future cryptographically relevant "
                      "quantum computer could decrypt what this algorithm protects (data recorded now: harvest now, "
                      "decrypt later) or forge what it signs. Plan the post-quantum migration (Mosca X + Y > Z).")
DETAIL_INFERRED = ("Inferred from a version or date, not from observed behaviour: confirm whether the affected code "
                   "path or release is in use before treating it as exploitable.")
DETAIL_CVE = "A version or configuration match is not proof of exposure."
DETAIL_DRIFT_RESOLVED = ("Not found again by a complete collection of the same source: the finding was present in the "
                         "baseline run and is gone from the listed assets (drift event \"resolved\"; findings under a "
                         "coverage gap are \"not read\", never resolved).")
DETAIL_DRIFT_RESOLVED_CODE = ("Not found again by a complete scan of the same repository and branch with the same scope "
                              "and engine: the finding was in the baseline scan and is gone (drift event "
                              "\"resolved\").")
DETAIL_DONE = ("Marked done in the team's remediation plan; this run collected the asset before the fix or the next "
               "run confirms it.")
DETAIL_ACCEPTED = "The team accepted this risk in the remediation plan and will not fix it."
DETAIL_IN_PROGRESS = "Remediation is in progress in the team's remediation plan."
GRADE_NONE = "not graded"
CODE_SCAN_GRADE = ("Q-grade: code scans are not graded (a grade needs the exposure and Mosca inputs of a Sources run); "
                   "grade this use through a Sources run of the system that runs the code.")


# ----------------------------------------------------------------------------- basis and analysis
def code_basis(code: str, namespace: str = "node") -> str:
    """``observed`` | ``static`` | ``quantum_only`` | ``inferred`` for a KB finding code (module docstring table).
    ``namespace``: ``node`` (Sources runs: observed by a collector) or ``code`` (code and CBOM-file scans)."""
    if code in INFERRED_CODES.get(namespace, frozenset()):
        return INFERRED
    entry = crypto_kb.entry(namespace, code) or {}
    if entry.get("category") == "pqc" or entry.get("pqc") == "grover-weakened":
        return QUANTUM_ONLY
    return OBSERVED if namespace == "node" else STATIC


def default_state(basis: str) -> str:
    return DEFAULT_STATE[basis]


def quantum_detail(code: str | None, hndl: bool | None) -> str:
    """Harvest-now-decrypt-later for a key exchange, future forgery / key recovery otherwise; ``hndl`` None: by code."""
    if hndl is None:
        if code in HNDL_CODES:
            return DETAIL_HNDL
        return DETAIL_QUANTUM if code and (crypto_kb.entry("node", code) or {}).get("pqc") == "grover-weakened" \
            else DETAIL_QUANTUM_ANY
    return DETAIL_HNDL if hndl else DETAIL_QUANTUM


def grade_note(q_grades: Mapping[str | None, int] | None) -> str | None:
    """The Q-grade sentence of a quantum-only entry: how many listed assets carry each grade (``qgrade``)."""
    if not q_grades:
        return None
    from backend.utilities.cbom_sources.qgrade import GRADE_MODEL, LABELS

    parts = [f"{g} {LABELS.get(g, '')} {n}".replace("  ", " ") for g, n in sorted(
        ((g, n) for g, n in q_grades.items() if g), key=lambda x: x[0])]
    if q_grades.get(None):
        parts.append(f"{GRADE_NONE} {q_grades[None]}")
    return (f"Q-grade of the listed assets ({GRADE_MODEL}; Q1 = migrate first): {', '.join(parts)}. "
            "In triage until the post-quantum migration of these assets is planned.")


def analysis_for(basis: str, *, status: str | None = None, hndl: bool | None = None, cve_detail: str | None = None,
                 code: str | None = None, q_grades: Mapping[str | None, int] | None = None,
                 grade_text: str | None = None) -> dict[str, Any]:
    """The CycloneDX ``analysis`` of one finding (code or CVE) on one asset or one group of assets.

    ``status``: the remediation-plan status of the asset (``done`` / ``accepted_risk`` / ``in_progress``), when the
    caller reads the plan (the run VEX deliverable; the export does not, so its bytes do not change with the plan).
    ``hndl`` / ``code``: pick the quantum-only detail. ``q_grades``: grade -> count of the listed assets (quantum-only
    entries); ``grade_text`` replaces the grade sentence (code scans: not graded)."""
    if basis not in DEFAULT_STATE:
        raise ValueError(f"unknown VEX basis {basis!r}")
    if status == "done":
        return {"state": "resolved", "detail": DETAIL_DONE}
    state = DEFAULT_STATE[basis]
    if basis == OBSERVED:
        detail = DETAIL_OBSERVED
    elif basis == STATIC:
        detail = DETAIL_STATIC
    elif basis == QUANTUM_ONLY:
        detail = quantum_detail(code, hndl)
        extra = grade_text or grade_note(q_grades)
        if extra:
            detail = f"{detail} {extra}"
    elif basis == CVE:
        detail = cve_detail or DETAIL_CVE
    elif basis == DRIFT_RESOLVED:
        detail = DETAIL_DRIFT_RESOLVED
    else:
        detail = DETAIL_INFERRED
    out: dict[str, Any] = {"state": state, "detail": detail}
    if state == "resolved":
        return out
    if status == "accepted_risk":
        out["response"] = ["will_not_fix"]
        out["detail"] = f"{DETAIL_ACCEPTED} {detail}"
    elif status == "in_progress":
        out["response"] = ["update"]
        out["detail"] = f"{DETAIL_IN_PROGRESS} {detail}"
    return out


# ----------------------------------------------------------------------------- properties
def prop(name: str, value: Any) -> dict[str, str]:
    return {"name": name, "value": str(value)}


def affects_cut(listed: int, total: int, cap: int | None = None, *, lower_bound: bool = False
                ) -> list[dict[str, str]]:
    """Properties of an entry whose ``affects`` lists fewer assets than have the finding: ``zs:affected_truncated``,
    ``zs:affected_total`` (the true count, or a stated lower bound), ``zs:affects_cap``. Empty when nothing is cut."""
    cap = AFFECTS_CAP if cap is None else cap
    if total <= listed and not (lower_bound and listed >= cap):
        return []
    value = f"at least {total} (matches past the cap are not counted)" if lower_bound else str(total)
    return [prop("zs:affected_truncated", "true"), prop("zs:affected_total", value), prop("zs:affects_cap", cap)]


def grade_props(q_grades: Mapping[str | None, int], *, model_version: str | None = None,
                inputs_digest: str | None = None) -> list[dict[str, str]]:
    """``zs:q_grades`` (compact JSON grade -> count; ``none`` = not graded) and the grade model / inputs it came from."""
    counts = {(g or "none"): n for g, n in sorted(q_grades.items(), key=lambda x: (x[0] is None, x[0] or ""))}
    out = [prop("zs:q_grades", json.dumps(counts, separators=(",", ":")))]
    if model_version:
        out.append(prop("zs:grade_model_version", model_version))
    if inputs_digest:
        out.append(prop("zs:grade_inputs_digest", inputs_digest))
    return out


# ----------------------------------------------------------------------------- drift-resolved findings
def drift_resolved(session: Any, *, team_id: int, run_id: int | None = None, scan_id: int | None = None
                   ) -> list[dict[str, Any]]:
    """The ``resolved`` drift events of one run (``scope`` node) or one code scan (``scope`` code): code, the stable
    asset key, whether the asset itself is gone, and the baseline it was compared with. At most ``drift.EVENT_CAP``
    are ever recorded per run or scan."""
    from sqlmodel import select

    from backend.new_models import CbomDriftEvent

    if (run_id is None) == (scan_id is None):
        raise ValueError("give run_id or scan_id")
    query = select(CbomDriftEvent).where(CbomDriftEvent.team_id == team_id, CbomDriftEvent.kind == "resolved")
    query = query.where(CbomDriftEvent.scope == "node", CbomDriftEvent.run_id == run_id) if run_id is not None else \
        query.where(CbomDriftEvent.scope == "code", CbomDriftEvent.scan_id == scan_id)
    out = []
    for e in session.exec(query.order_by(CbomDriftEvent.id)).all():
        if not e.code:
            continue
        detail = e.detail if isinstance(e.detail, dict) else {}
        out.append({"code": e.code, "asset_key": e.asset_key, "asset_removed": bool(detail.get("asset_removed")),
                    "baseline": e.baseline_run_id if run_id is not None else e.baseline_scan_id,
                    "severity": e.severity})
    return out


def resolved_entries(events: Iterable[Mapping[str, Any]], ref_of: Mapping[str, str], *, namespace: str,
                     baseline_name: str, taken: set[str] | None = None) -> list[dict[str, Any]]:
    """One ``resolved`` vulnerability per finding code from ``drift_resolved`` events. ``ref_of``: stable asset key ->
    the bom-ref of that asset in THIS document (the asset is still listed, the finding is gone); an asset that is
    itself gone, or not in this document, is counted (``zs:resolved_assets_not_listed``) and its stable key listed
    (``zs:resolved_asset_key``, first ``REMOVED_KEYS_CAP``) instead of a reference that would not resolve.
    ``baseline_name``: ``run`` or ``scan``. ``taken``: bom-refs already used (a resolved entry never reuses one)."""
    by_code: dict[str, dict[str, Any]] = {}
    for e in events:
        hit = by_code.setdefault(e["code"], {"refs": [], "gone": [], "baselines": set()})
        ref = ref_of.get(str(e.get("asset_key") or "")) if not e.get("asset_removed") else None
        if ref:
            hit["refs"].append(ref)
        else:
            hit["gone"].append(str(e.get("asset_key") or ""))
        if e.get("baseline") is not None:
            hit["baselines"].add(int(e["baseline"]))
    taken = taken if taken is not None else set()
    out: list[dict[str, Any]] = []
    for code, hit in sorted(by_code.items()):
        entry_kb = crypto_kb.entry(namespace, code) or {}
        refs = list(dict.fromkeys(hit["refs"]))
        gone = list(dict.fromkeys(k for k in hit["gone"] if k))
        bom_ref = f"zs-vuln-{code.lower()}-resolved"
        while bom_ref in taken:
            bom_ref += "-1"
        taken.add(bom_ref)
        analysis = analysis_for(DRIFT_RESOLVED)
        if namespace == "code":
            analysis["detail"] = DETAIL_DRIFT_RESOLVED_CODE
        entry: dict[str, Any] = {
            "bom-ref": bom_ref, "id": f"ZS-CBOM-{code}",
            "source": {"name": "ZeroShield crypto knowledge base", "url": "https://cwe.mitre.org/"},
            "cwes": [int(c[4:]) for c in entry_kb.get("cwe") or [] if str(c)[4:].isdigit()],
            "description": entry_kb.get("description"),
            "analysis": analysis,
        }
        if refs:
            entry["affects"] = [{"ref": r} for r in refs[:AFFECTS_CAP]]  # module value at call time (tests patch it)
        entry["properties"] = [
            prop("zs:vex_basis", DRIFT_RESOLVED),
            *[prop(f"zs:baseline_{baseline_name}_id", b) for b in sorted(hit["baselines"])],
            *affects_cut(min(len(refs), AFFECTS_CAP), len(refs)),
            *([prop("zs:resolved_assets_not_listed", len(gone))] if gone else []),
            *[prop("zs:resolved_asset_key", k) for k in gone[:REMOVED_KEYS_CAP]],
            prop("zs:kb_version", crypto_kb.version()),
        ]
        out.append(entry)
    return out


# ----------------------------------------------------------------------------- code-scan VEX
def _cve_ids(row: Mapping[str, Any]) -> list[str]:
    cves = row.get("cves")
    out: list[str] = []
    if isinstance(cves, dict):
        out = [str(k).strip() for k in cves if str(k).strip()]
    elif isinstance(cves, list):
        for item in cves:
            if isinstance(item, str) and item.strip():
                out.append(item.strip())
            elif isinstance(item, dict) and str(item.get("id") or item.get("cve") or "").strip():
                out.append(str(item.get("id") or item.get("cve")).strip())
    return out


def code_scan_vulnerabilities(findings: list[Any], *, resolved: Iterable[Mapping[str, Any]] = (),
                              ref_of: Mapping[str, str] | None = None) -> list[dict[str, Any]]:
    """A CBOM code scan's VEX entries: one per finding code (state by ``code_basis(code, "code")``), one per CVE
    (``in_triage``), one ``resolved`` per code its drift resolved, and the CERT-In F5 ``not-affected:<ref>`` stub for
    each component with no finding and no CVE (kept from rules 2: "no weakness found", not a triage verdict)."""
    by_code: dict[str, list[str]] = {}
    by_cve: dict[str, list[str]] = {}
    clean: list[str] = []
    for i, row in enumerate(findings):
        if not isinstance(row, dict):
            continue
        ref = str(row.get("bom_ref") or row.get("bom-ref") or f"component-{i}")
        codes = [c for c in row.get("finding_codes") or [] if isinstance(c, str) and c]
        for code in codes:
            by_code.setdefault(code, []).append(ref)
        cves = _cve_ids(row)
        for cid in cves:
            by_cve.setdefault(cid, []).append(ref)
        if not codes and not cves:
            clean.append(ref)
    out: list[dict[str, Any]] = []
    taken: set[str] = set()
    for code, refs in sorted(by_code.items()):
        basis = code_basis(code, "code")
        analysis = analysis_for(basis, code=code, grade_text=CODE_SCAN_GRADE if basis == QUANTUM_ONLY else None)
        bom_ref = f"zs-vuln-{code.lower()}"
        taken.add(bom_ref)
        unique = list(dict.fromkeys(refs))
        out.append({"bom-ref": bom_ref, "id": f"ZS-CBOM-{code}",
                    "source": {"name": "DevSecShield CERT-In VEX", "url": ""},
                    "analysis": analysis, "affects": [{"ref": r} for r in unique[:AFFECTS_CAP]],
                    "properties": [prop("zs:vex_basis", basis), *affects_cut(min(len(unique), AFFECTS_CAP), len(unique))]})
    for cid, refs in sorted(by_cve.items()):
        unique = list(dict.fromkeys(refs))
        bom_ref = f"zs-vuln-{cid.lower()}"
        taken.add(bom_ref)
        out.append({"bom-ref": bom_ref, "id": cid,
                    "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cid}"},
                    "analysis": analysis_for(CVE, cve_detail="Matched from the algorithm or protocol the code uses; a "
                                                             "match is not proof of exposure."),
                    "affects": [{"ref": r} for r in unique[:AFFECTS_CAP]],
                    "properties": [prop("zs:vex_basis", CVE), *affects_cut(min(len(unique), AFFECTS_CAP), len(unique))]})
    out += resolved_entries(resolved, ref_of or {}, namespace="code", baseline_name="scan", taken=taken)
    for ref in dict.fromkeys(clean):
        out.append({"id": f"not-affected:{ref}", "source": {"name": "DevSecShield CERT-In VEX", "url": ""},
                    "analysis": {"state": "not_affected", "detail": "No weakness or CVE found for this asset (CERT-In F5)"},
                    "affects": [{"ref": ref}], "properties": [prop("zs:vex_basis", "no_finding")]})
    return out


def code_scan_vex(findings: list[Any], *, resolved: Iterable[Mapping[str, Any]] = (),
                  ref_of: Mapping[str, str] | None = None) -> dict[str, Any]:
    """The CycloneDX 1.6 VEX document of a CBOM code scan (what ``GET /{team}/cbom/scan/{id}/vex`` serves)."""
    vulns = code_scan_vulnerabilities(findings, resolved=resolved, ref_of=ref_of)
    states = Counter(v["analysis"]["state"] for v in vulns)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {
            "tools": {"components": [{"type": "application", "name": "DevSecShield CERT-In VEX", "version": VEX_RULES}]},
            "properties": [
                prop("zs:vex_rules", VEX_RULES),
                *[prop(f"zs:entries_{state}", n) for state, n in sorted(states.items())],
                prop("certin:disclaimer", "Advisory VEX alignment to CERT-In TG v2.0; observed weaknesses are "
                                          "exploitable, code findings and quantum-only risks in triage, drift-fixed "
                                          "findings resolved. Does not constitute CERT-In certification."),
            ],
        },
        "vulnerabilities": vulns,
    }


def is_current(scan_type: str, vex: Any) -> bool:
    """A stored CBOM code-scan VEX written by older rules is rebuilt (other scan types keep theirs)."""
    if scan_type != "cbom":
        return True
    props = ((vex.get("metadata") or {}).get("properties") or []) if isinstance(vex, dict) else []
    return any(isinstance(p, dict) and p.get("name") == "zs:vex_rules" and p.get("value") == VEX_RULES for p in props)
