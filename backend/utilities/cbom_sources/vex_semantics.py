"""VEX semantics for every CBOM surface (CB-22, KF-11): one rule for which CycloneDX 1.6 ``analysis`` a finding gets.

Used by the Sources run export (``inventory.vulnerabilities``) and the code-scan VEX (``routers/certin.py``). A run VEX
built on top of the export (CB-38's ``run_deliverables``, PR #124) must take each export entry's ``analysis`` and
``zs:vex_basis`` as they are and only overlay the remediation plan with ``apply_plan_status``; it must never re-judge
an entry by its code (a ``drift_resolved`` entry would turn back into ``exploitable``) or add a second
``zs:vex_basis`` / ``zs:affected_*`` set (``tests/test_cbom_cb22_vex.py`` holds the contract).

CycloneDX 1.6 ``analysis.state`` (published schema 1.6.2, ``impactAnalysisState``): ``resolved``,
``resolved_with_pedigree``, ``exploitable``, ``in_triage``, ``false_positive``, ``not_affected`` (``not_affected``
"should" carry a ``justification``). ``response``: ``can_not_fix``, ``will_not_fix``, ``update``, ``rollback``,
``workaround_available``.

The reviewed default per code
-----------------------------
Each KB finding code carries ``vex_default`` (``basis``, ``reason``), built into the KB by
``scripts/crypto_kb/build_kb.py`` from the reviewed table ``scripts/crypto_kb/sources/vex_default.json`` (one row per
code with a reason and sources; the build fails on a missing row). A code without a reviewed row (a KB bundle older
than rules cb22-1) is ``unreviewed`` -> ``in_triage``, never ``exploitable``.

================  =============  =============================================================================
basis             state          meaning
================  =============  =============================================================================
observed          exploitable    a collector observed the weak setting on the asset and a classical attack on it
                                 is known (Sources runs only: TLS 1.0 accepted, RSA < 2048, expired ...)
posture           in_triage      configuration or hygiene risk with no direct attack on the asset as observed
                                 (rotation off, expires in 30 days, unused certificate, informational SHA-1 ...)
quantum_only      in_triage      no classical attack today (KB category pqc, or grover-weakened); detail: harvest
                                 now, decrypt later or future forgery, and the listed assets' Q-grades
inferred          in_triage      judged from a version or a date, not from behaviour
static            in_triage      seen in source code or configuration by a code scan; reachability not proven
cve               in_triage      a CVE matched from a version range, from an implementation-specific flaw, or
                                 from a finding that is itself not observed
drift_resolved    resolved       an earlier complete collection (scan) of the same source had it; this one does
                                 not (drift event ``resolved``); unread scope is never resolved
unreviewed        in_triage      no reviewed default for the code
================  =============  =============================================================================

A CVE matched from an ``observed`` code is ``observed`` (``exploitable``) when the KB marks it ``vex_inherent`` (a flaw
of the algorithm or protocol itself: SWEET32, RC4 biases, POODLE, DROWN, Logjam, MD5/SHA-1 collisions). The collector
negotiated that algorithm or protocol with the reachable service, and that is the exposure. An implementation-specific
CVE (Lucky13, Terrapin, BEAST, Heartbleed ...) and every library-range CVE stay ``in_triage``.

The remediation plan (``apply_plan_status``)
--------------------------------------------
* ``done``: ``resolved`` only when the plan was marked done after the asset was collected (the run predates the fix;
  the next run confirms it). Marked done but collected afterwards (still observed), or times unknown: the state is
  kept and the detail says the plan's "done" is not confirmed by this evidence, with response ``update``.
* ``accepted_risk``: the state is kept and the response is ``will_not_fix``. On an ``in_triage`` finding this pairing
  is deliberate: the team decided not to fix, but the evidence still does not show a classical attack, so the state
  cannot become ``exploitable``, and ``not_affected`` would need a justification the evidence does not give.
* ``in_progress``: the state is kept, response ``update``.

Never emitted from evidence: ``not_affected`` for a finding (only a customer's triage can say that: a CB-22
follow-up), ``false_positive``, ``resolved_with_pedigree``. The code-scan VEX keeps the CERT-In F5
``not-affected:<ref>`` stub for a component with no finding (``zs:vex_basis`` ``no_finding``).
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import uuid
from collections import Counter
from typing import Any, Callable, Iterable, Mapping

from backend.utilities.cbom_sources import crypto_kb

VEX_RULES = "cb22-1"
AFFECTS_CAP = 5_000  # affected assets listed per entry; the rest are counted (``affects_cut``)
REMOVED_KEYS_CAP = 200
_CODE_VEX_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://zeroshield.ai/cbom/code-scan/vex")

OBSERVED, POSTURE, STATIC, QUANTUM_ONLY, INFERRED, CVE, DRIFT_RESOLVED, UNREVIEWED = (
    "observed", "posture", "static", "quantum_only", "inferred", "cve", "drift_resolved", "unreviewed")
BASES = (OBSERVED, POSTURE, STATIC, QUANTUM_ONLY, INFERRED, CVE, DRIFT_RESOLVED, UNREVIEWED)
KB_BASES = (OBSERVED, POSTURE, QUANTUM_ONLY, INFERRED, STATIC)  # what a reviewed KB row may say
DEFAULT_STATE = {OBSERVED: "exploitable", POSTURE: "in_triage", STATIC: "in_triage", QUANTUM_ONLY: "in_triage",
                 INFERRED: "in_triage", CVE: "in_triage", DRIFT_RESOLVED: "resolved", UNREVIEWED: "in_triage"}

# quantum-only codes about a key exchange: what is recorded today is decrypted later
HNDL_CODES = frozenset({"NO_PQ_KEX", "SSH_NO_PQ_KEX", "IKE_NO_PQ"})

DETAIL_OBSERVED = ("Observed directly by the collector on each listed asset: the weak algorithm or setting is in use "
                   "where it was collected, and a classical attack on it is known today.")
DETAIL_POSTURE = "Configuration or hygiene risk, no direct attack on the asset as observed"
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
DETAIL_UNREVIEWED = ("No reviewed VEX default for this finding code in the knowledge base in force; in triage until "
                     "it is reviewed.")
DETAIL_CVE = "A version or configuration match is not proof of exposure."
DETAIL_CVE_IMPLEMENTATION = ("An implementation-specific flaw: whether the product on the asset has it (version, "
                             "mode, patch) is not checked.")
DETAIL_CVE_INHERENT = ("{code} was observed on the asset by the collector and {cve} is a flaw of that algorithm or "
                       "protocol itself, so the observation is the exposure.")
DETAIL_DRIFT_RESOLVED = ("Not found again by a complete collection of the same source: the finding was present in the "
                         "baseline run and is gone from the listed assets (drift event \"resolved\"; findings under a "
                         "coverage gap are \"not read\", never resolved).")
DETAIL_DRIFT_RESOLVED_CODE = ("Not found again by a complete scan of the same repository and branch with the same scope "
                              "and engine: the finding was in the baseline scan and is gone (drift event "
                              "\"resolved\").")
DETAIL_DRIFT_TRUNCATED = (" Drift stores at most {cap} events per run or scan and this one reached it, so this list "
                          "may be incomplete.")
DETAIL_DONE = ("Marked done in the team's remediation plan after this run collected the asset; the next run "
               "confirms the fix.")
DETAIL_DONE_UNCONFIRMED = ("Marked done in the team's remediation plan{when}, but this run{collected} still observes "
                           "the finding, so the fix is not confirmed.")
DETAIL_ACCEPTED = "The team accepted this risk in the remediation plan and will not fix it."
DETAIL_IN_PROGRESS = "Remediation is in progress in the team's remediation plan."
GRADE_NONE = "not graded"
CODE_SCAN_GRADE = ("Q-grade: code scans are not graded (a grade needs the exposure and Mosca inputs of a Sources run); "
                   "grade this use through a Sources run of the system that runs the code.")
CODE_CVE_ALGORITHM = "Matched from the algorithm or protocol the code uses; a match is not proof of exposure."
CODE_CVE_LIBRARY = ("Named by a library advisory for the version the scan found; distributions and vendors back-port "
                    "fixes, so a version match is not proof of exposure.")


# ----------------------------------------------------------------------------- basis
def kb_default(code: str, namespace: str = "node") -> dict[str, Any] | None:
    """The reviewed ``vex_default`` row of a KB code (``basis``, ``reason``), or None."""
    row = (crypto_kb.entry(namespace, code) or {}).get("vex_default")
    return row if isinstance(row, dict) and row.get("basis") in KB_BASES else None


def code_basis(code: str, namespace: str = "node") -> str:
    """The reviewed basis of a KB finding code (module docstring); ``unreviewed`` when the KB in force has none.
    ``namespace``: ``node`` (Sources runs) or ``code`` (code and CBOM-file scans: never ``observed``)."""
    row = kb_default(code, namespace)
    if row is None:
        return UNREVIEWED
    if namespace != "node" and row["basis"] == OBSERVED:  # a code scan does not observe the running system
        return STATIC
    return row["basis"]


def default_state(basis: str) -> str:
    return DEFAULT_STATE[basis]


def cve_inherent(cve_id: str) -> bool:
    """True when the KB marks the CVE a flaw of the algorithm or protocol itself (``vex_inherent``)."""
    return (crypto_kb.cve(cve_id) or {}).get("vex_inherent") is True


def cve_basis(cve_id: str, from_codes: Iterable[str], namespace: str = "node") -> tuple[str, str | None]:
    """(basis, the observed code it rests on) of a CVE matched from ``from_codes`` on one asset: ``observed`` when one
    of them is observed and the CVE is inherent to that algorithm or protocol, else ``cve``."""
    if cve_inherent(cve_id):
        for code in sorted(set(from_codes)):
            if code_basis(code, namespace) == OBSERVED:
                return OBSERVED, code
    return CVE, None


# ----------------------------------------------------------------------------- analysis
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


def _naive(value: Any) -> _dt.datetime | None:
    if isinstance(value, _dt.datetime):
        return value if value.tzinfo is None else value.astimezone(_dt.timezone.utc).replace(tzinfo=None)
    if isinstance(value, str) and value:
        try:
            return _naive(_dt.datetime.fromisoformat(value.replace("Z", "+00:00")))
        except ValueError:
            return None
    return None


def _iso(value: Any) -> str | None:
    moment = _naive(value)
    return moment.replace(microsecond=0).isoformat() + "Z" if moment else None


def apply_plan_status(analysis: Mapping[str, Any], status: str | None, *, plan_changed_at: Any = None,
                      collected_at: Any = None) -> dict[str, Any]:
    """Overlay the remediation-plan status of one asset on the evidence ``analysis`` of a finding (module docstring).
    ``plan_changed_at``: when the plan entry last changed; ``collected_at``: when this run collected the asset."""
    out = dict(analysis)
    if not status or out.get("state") == "resolved":
        return out
    detail = str(out.get("detail") or "")
    if status == "done":
        changed, collected = _naive(plan_changed_at), _naive(collected_at)
        if changed is not None and collected is not None and changed > collected:
            return {"state": "resolved", "detail": f"{DETAIL_DONE} {detail}".strip()}
        note = DETAIL_DONE_UNCONFIRMED.format(when=f" ({_iso(changed)})" if changed else "",
                                              collected=f" (collected {_iso(collected)})" if collected else "")
        out["response"] = ["update"]
        out["detail"] = f"{note} {detail}".strip()
    elif status == "accepted_risk":
        out["response"] = ["will_not_fix"]
        out["detail"] = f"{DETAIL_ACCEPTED} {detail}".strip()
    elif status == "in_progress":
        out["response"] = ["update"]
        out["detail"] = f"{DETAIL_IN_PROGRESS} {detail}".strip()
    return out


def analysis_for(basis: str, *, status: str | None = None, hndl: bool | None = None, cve_detail: str | None = None,
                 code: str | None = None, q_grades: Mapping[str | None, int] | None = None,
                 grade_text: str | None = None, namespace: str = "node", plan_changed_at: Any = None,
                 collected_at: Any = None) -> dict[str, Any]:
    """The CycloneDX ``analysis`` of one finding (code or CVE) on one asset or one group of assets: the evidence
    analysis for ``basis``, then the remediation plan (``apply_plan_status``) when ``status`` is given.
    ``hndl`` / ``code``: pick the quantum-only detail and the posture reason. ``q_grades``: grade -> count of the
    listed assets (quantum-only entries); ``grade_text`` replaces the grade sentence (code scans: not graded)."""
    if basis not in DEFAULT_STATE:
        raise ValueError(f"unknown VEX basis {basis!r}")
    state = DEFAULT_STATE[basis]
    if basis == OBSERVED:
        detail = cve_detail or DETAIL_OBSERVED
    elif basis == POSTURE:
        reason = (kb_default(code, namespace) or {}).get("reason") if code else None
        detail = f"{DETAIL_POSTURE}: {reason}." if reason else f"{DETAIL_POSTURE}."
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
    elif basis == UNREVIEWED:
        detail = DETAIL_UNREVIEWED
    else:
        detail = DETAIL_INFERRED
    return apply_plan_status({"state": state, "detail": detail}, status, plan_changed_at=plan_changed_at,
                             collected_at=collected_at)


# ----------------------------------------------------------------------------- properties
def prop(name: str, value: Any) -> dict[str, str]:
    return {"name": name, "value": str(value)}


def props_of(entry: Mapping[str, Any]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for p in entry.get("properties") or []:
        if isinstance(p, dict):
            out.setdefault(str(p.get("name")), []).append(str(p.get("value")))
    return out


def entry_basis(entry: Mapping[str, Any]) -> str | None:
    """The ``zs:vex_basis`` an entry was judged on (one per entry)."""
    values = props_of(entry).get("zs:vex_basis") or []
    return values[0] if values else None


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


def bom_link(serial: str, version: int | str, ref: str) -> str:
    """A CycloneDX 1.6 BOM-Link to ``ref`` in another BOM: ``urn:cdx:<serial uuid>/<version>#<ref>``."""
    return f"urn:cdx:{str(serial).removeprefix('urn:uuid:')}/{version}#{ref}"


# ----------------------------------------------------------------------------- drift-resolved findings
def drift_resolved(session: Any, *, team_id: int, run_id: int | None = None, scan_id: int | None = None
                   ) -> list[dict[str, Any]]:
    """The ``resolved`` drift events of one run (``scope`` node) or one code scan (``scope`` code): code, the stable
    asset key, whether the asset itself is gone, the baseline it was compared with and the baseline's asset id /
    bom-ref."""
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
                    "baseline_asset_id": detail.get("asset_id"), "baseline_bom_ref": detail.get("bom_ref"),
                    "severity": e.severity})
    return out


def drift_truncated(session: Any, *, team_id: int, run_id: int | None = None, scan_id: int | None = None) -> bool:
    """True when the run's (scan's) drift reached ``drift.EVENT_CAP`` stored events, so its resolutions may be cut."""
    from sqlalchemy import func
    from sqlmodel import select

    from backend.new_models import CbomDriftEvent
    from backend.utilities.cbom_sources.drift import EVENT_CAP

    query = select(func.count()).select_from(CbomDriftEvent).where(CbomDriftEvent.team_id == team_id)
    query = query.where(CbomDriftEvent.run_id == run_id, CbomDriftEvent.scope == "node") if run_id is not None else \
        query.where(CbomDriftEvent.scan_id == scan_id, CbomDriftEvent.scope == "code")
    return int(session.exec(query).one() or 0) >= EVENT_CAP


def resolved_entries(events: Iterable[Mapping[str, Any]], ref_of: Mapping[str, str], *, namespace: str,
                     baseline_name: str, taken: set[str] | None = None,
                     link_of: Callable[[Mapping[str, Any]], str | None] | None = None,
                     truncated: bool = False) -> list[dict[str, Any]]:
    """One ``resolved`` vulnerability per finding code from ``drift_resolved`` events. ``ref_of``: stable asset key ->
    bom-ref of that asset in THIS document (still listed, the finding gone). An asset that is itself gone is
    referenced in the baseline document with a BOM-Link (``link_of``) and named by its stable key
    (``zs:resolved_asset_key``, first ``REMOVED_KEYS_CAP``); ``zs:resolved_assets_not_listed`` counts them.
    ``baseline_name``: ``run`` or ``scan``. ``truncated``: drift reached its event cap (``zs:resolved_truncated``)."""
    by_code: dict[str, dict[str, Any]] = {}
    for e in events:
        hit = by_code.setdefault(e["code"], {"refs": [], "gone": [], "baselines": set()})
        ref = ref_of.get(str(e.get("asset_key") or "")) if not e.get("asset_removed") else None
        if ref:
            hit["refs"].append(ref)
        else:
            hit["gone"].append((str(e.get("asset_key") or ""), link_of(e) if link_of else None))
        if e.get("baseline") is not None:
            hit["baselines"].add(int(e["baseline"]))
    taken = taken if taken is not None else set()
    out: list[dict[str, Any]] = []
    for code, hit in sorted(by_code.items()):
        entry_kb = crypto_kb.entry(namespace, code) or {}
        refs = list(dict.fromkeys(hit["refs"] + [link for _k, link in hit["gone"] if link]))
        gone = list(dict.fromkeys(k for k, _l in hit["gone"] if k))
        bom_ref = f"zs-vuln-{code.lower()}-resolved"
        while bom_ref in taken:
            bom_ref += "-1"
        taken.add(bom_ref)
        analysis = analysis_for(DRIFT_RESOLVED)
        if namespace == "code":
            analysis["detail"] = DETAIL_DRIFT_RESOLVED_CODE
        if truncated:
            from backend.utilities.cbom_sources.drift import EVENT_CAP

            analysis["detail"] += DETAIL_DRIFT_TRUNCATED.format(cap=EVENT_CAP)
        entry: dict[str, Any] = {
            "bom-ref": bom_ref, "id": f"ZS-CBOM-{code}",
            "source": {"name": "ZeroShield crypto knowledge base", "url": "https://cwe.mitre.org/"},
            "cwes": [int(c[4:]) for c in entry_kb.get("cwe") or [] if str(c)[4:].isdigit()],
            "description": entry_kb.get("description"),
            "analysis": analysis,
        }
        if refs:
            entry["affects"] = [{"ref": r} for r in refs[:AFFECTS_CAP]]
        entry["properties"] = [
            prop("zs:vex_basis", DRIFT_RESOLVED),
            *[prop(f"zs:baseline_{baseline_name}_id", b) for b in sorted(hit["baselines"])],
            *affects_cut(min(len(refs), AFFECTS_CAP), len(refs)),
            *([prop("zs:resolved_assets_not_listed", len(gone))] if gone else []),
            *[prop("zs:resolved_asset_key", k) for k in gone[:REMOVED_KEYS_CAP]],
            *([prop("zs:resolved_truncated", "true")] if truncated else []),
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


def code_scan_vulnerabilities(findings: list[Any], *, components: Iterable[str] = (),
                              resolved: Iterable[Mapping[str, Any]] = (), ref_of: Mapping[str, str] | None = None,
                              link_of: Callable[[Mapping[str, Any]], str | None] | None = None,
                              truncated: bool = False) -> list[dict[str, Any]]:
    """A CBOM code scan's VEX entries: one per finding code (``code_basis(code, "code")``: never exploitable), one per
    CVE (``in_triage``; the detail says whether it came from a library advisory or from the algorithm), one
    ``resolved`` per code its drift resolved, and the CERT-In F5 ``not-affected:<ref>`` stub for each component with
    no finding and no CVE (``components``: the BOM's refs, used when the scan stored no result rows)."""
    by_code: dict[str, list[str]] = {}
    by_cve: dict[str, dict[str, Any]] = {}
    clean: list[str] = []
    for i, row in enumerate(findings):
        if not isinstance(row, dict):
            continue
        ref = str(row.get("bom_ref") or row.get("bom-ref") or f"component-{i}")
        codes = [c for c in row.get("finding_codes") or [] if isinstance(c, str) and c]
        for code in codes:
            by_code.setdefault(code, []).append(ref)
        cves = _cve_ids(row)
        library = any(code_basis(c, "code") == INFERRED for c in codes)
        for cid in cves:
            hit = by_cve.setdefault(cid, {"refs": [], "library": False})
            hit["refs"].append(ref)
            hit["library"] = hit["library"] or library
        if not codes and not cves:
            clean.append(ref)
    if not findings:
        clean = [str(r) for r in components if r]
    out: list[dict[str, Any]] = []
    taken: set[str] = set()
    for code, refs in sorted(by_code.items()):
        basis = code_basis(code, "code")
        analysis = analysis_for(basis, code=code, namespace="code",
                                grade_text=CODE_SCAN_GRADE if basis == QUANTUM_ONLY else None)
        bom_ref = f"zs-vuln-{code.lower()}"
        taken.add(bom_ref)
        unique = list(dict.fromkeys(refs))
        out.append({"bom-ref": bom_ref, "id": f"ZS-CBOM-{code}",
                    "source": {"name": "DevSecShield CERT-In VEX", "url": ""},
                    "analysis": analysis, "affects": [{"ref": r} for r in unique[:AFFECTS_CAP]],
                    "properties": [prop("zs:vex_basis", basis), *affects_cut(min(len(unique), AFFECTS_CAP), len(unique))]})
    for cid, hit in sorted(by_cve.items()):
        unique = list(dict.fromkeys(hit["refs"]))
        bom_ref = f"zs-vuln-{cid.lower()}"
        taken.add(bom_ref)
        out.append({"bom-ref": bom_ref, "id": cid,
                    "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cid}"},
                    "analysis": analysis_for(CVE, cve_detail=CODE_CVE_LIBRARY if hit["library"] else CODE_CVE_ALGORITHM),
                    "affects": [{"ref": r} for r in unique[:AFFECTS_CAP]],
                    "properties": [prop("zs:vex_basis", CVE), *affects_cut(min(len(unique), AFFECTS_CAP), len(unique))]})
    out += resolved_entries(resolved, ref_of or {}, namespace="code", baseline_name="scan", taken=taken,
                            link_of=link_of, truncated=truncated)
    for ref in dict.fromkeys(clean):
        out.append({"id": f"not-affected:{ref}", "source": {"name": "DevSecShield CERT-In VEX", "url": ""},
                    "analysis": {"state": "not_affected", "detail": "No weakness or CVE found for this asset (CERT-In F5)"},
                    "affects": [{"ref": ref}], "properties": [prop("zs:vex_basis", "no_finding")]})
    return out


def code_scan_vex(findings: list[Any], *, scan_id: int | None = None, now: _dt.datetime | None = None,
                  components: Iterable[str] = (), resolved: Iterable[Mapping[str, Any]] = (),
                  ref_of: Mapping[str, str] | None = None,
                  link_of: Callable[[Mapping[str, Any]], str | None] | None = None, truncated: bool = False,
                  supersedes: Any = None) -> dict[str, Any]:
    """The CycloneDX 1.6 VEX document of a CBOM code scan (what ``GET /{team}/cbom/scan/{id}/vex`` serves).
    ``serialNumber`` = uuid5(scan id : rules : content digest), so a rebuilt document with other content is another
    BOM; ``metadata.timestamp`` = when it was built; ``supersedes``: the stored document it replaces (its serial, or
    its rules when it had none, in ``zs:supersedes``)."""
    vulns = code_scan_vulnerabilities(findings, components=components, resolved=resolved, ref_of=ref_of,
                                      link_of=link_of, truncated=truncated)
    states = Counter(v["analysis"]["state"] for v in vulns)
    digest = hashlib.sha256(json.dumps(vulns, sort_keys=True).encode()).hexdigest()
    old = None
    if isinstance(supersedes, dict):
        old = supersedes.get("serialNumber") or next(
            (f"rules {p.get('value')}" for p in (supersedes.get("metadata") or {}).get("properties") or []
             if isinstance(p, dict) and p.get("name") == "zs:vex_rules"), "an earlier VEX")
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(_CODE_VEX_NS, f'{scan_id}:{VEX_RULES}:{digest}')}",
        "version": 1,
        "metadata": {
            "timestamp": _iso(now or _dt.datetime.utcnow()),
            "tools": {"components": [{"type": "application", "name": "DevSecShield CERT-In VEX", "version": VEX_RULES}]},
            "properties": [
                prop("zs:vex_rules", VEX_RULES),
                *([prop("zs:scan_id", scan_id)] if scan_id is not None else []),
                *([prop("zs:supersedes", old)] if old else []),
                *([prop("zs:drift_events_truncated", "true")] if truncated else []),
                *[prop(f"zs:entries_{state}", n) for state, n in sorted(states.items())],
                prop("certin:disclaimer", "Advisory VEX alignment to CERT-In TG v2.0; code-scan findings, CVE matches "
                                          "and quantum-only risks are in triage, drift-fixed findings resolved. Does "
                                          "not constitute CERT-In certification."),
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
