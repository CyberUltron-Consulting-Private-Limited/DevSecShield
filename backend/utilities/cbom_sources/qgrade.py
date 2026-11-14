"""Quantum risk grade per asset, model qg-1 (CB-19): a pure function of stored data, computed when a view is read.

* ``FORMULA_TEXT`` is the model the owner signs (OA-10a): the product serves it (``GET …/sources/grade-model``) with its
  sha256, and a test grades 2,000 generated inputs both with ``grade`` and with a reference that reads the rule list
  from this text, so the code and the signed text cannot drift apart.
* ``GRADE_MODEL`` changes only with the text; ``GRADE_MODEL_VERSION`` also hashes this module and ``posture.py`` (the
  class and exposure functions live there) and ``classify.CLASSIFIER_VERSION`` (the fallback test reads the
  classifier's algorithm families), so any edit that can change a grade changes the version.
* Inputs come from the product's single class function (``posture.classify_pqc``), its exposure function
  (``posture.asset_exposure``, with one grade-only precedence change: a collector's internet-facing fact beats an
  "internal" or "unknown" set on the source), the job's metadata snapshot (per-source X, exposure override, node segment) and the
  team's Mosca X/Y/Z: the snapshot the run took at Start (PR-2, ``snapshot_inputs``; the record grade, ``source:
  snapshot``) or, for a run created before PR-2, as they are now (``source: current``). ``GradeContext.with_inputs``
  grades the same rows with the team's inputs now, shown beside the record ("with current inputs").
* Items that are not assets: unread scope (coverage rows, job targets, sources the run did not read), reported as Q0
  items with a stable key; network ranges aggregate per (source, status). A missing Mosca setting is one item
  (``inputs:mosca``) with the count of affected assets, never one item per asset.

Every surface (run asset list, asset detail, run posture) builds its grade context with ``load_context`` and grades a
row with ``GradeContext.grade_row``; nothing else constructs a ``GradeInput`` from stored rows.
"""
from __future__ import annotations

import functools
import hashlib
import json
import re
from collections import Counter
import datetime as _dt
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from sqlmodel import Session, select

from backend.new_models import (
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSettings,
    CbomCollectionSource,
    CbomEvidenceArea,
    CbomEvidenceVendor,
    CbomScanNode,
)
from backend.utilities.cbom_sources import identity as ID
from backend.utilities.cbom_sources import posture as P
from backend.utilities.cbom_sources.classify import CLASSIFIER_VERSION, aws_pq_policy, quantum_vulnerable, ssh_names

FORMULA_TEXT = """\
ZeroShield quantum risk grade, model qg-1.
Grades: Q0 Unknown, Q1 Critical, Q2 High, Q3 Medium, Q4 Low. "No grade" is not a grade.
Items: (a) a collected asset; (b) an unread scope: a coverage row for something the product did not read, a target
the job did not read (whatever its status, "not_supported" included), a source the run did not read (skipped by the
planner, in a group left out of the run, collect job not successful or not finished, or cut at the asset limit /
assets lost); (c) an evidence area or vendor; (d) a code-scan row (team register only).
Not items: a coverage row or a target saying the target has no such thing ("not_installed", or "not_supported" with a
detail the product lists as absent: a cloud region or project with nothing enabled, no AD CS CA, no package
database), an address that answered on no probed port.
Inputs per item:
  class      = the PQC class of the asset (quantum-vulnerable | hybrid | quantum-safe | grover-weakened |
               unknown | not-applicable), from the product's single class function.
  fallback   = the asset is an endpoint of class hybrid or quantum-safe that also completes a classical-only key
               exchange (TLS 1.2 or older, static RSA key transport, a classical TLS 1.3 group it reports, a classical
               SSH key exchange). The grade uses the weakest configuration the endpoint accepts: rules 8 and 14-18.
  exposure   = internet | internal | unknown, from the product's single exposure function, except that a
               collector's internet-facing fact beats an "internal" or "unknown" set on the source.
  anchor     = the asset is a CA certificate (basicConstraints CA true) or a CA (cloud CA, AD CS / Vault CA).
  X          = the asset's source "data must stay secret for (years)" if set, else the team's X.
  Y, Z       = the team's migration years and years until a cryptographically relevant quantum computer.
  provenance = observed (read by a collector), attested (evidence area or vendor), code (code scan).
  level      = E0..E3 of an attested item.
Rules, first match wins:
  1. unread scope                                              -> Q0 "coverage_gap" | "source_not_read" |
                                                                   "source_truncated" | "excluded_by_choice"
  2. attested item at level E0                                 -> Q0 "evidence_e0" (sub-reason: no_answer,
                                                                   rated_unknown, evidence_expired, vendor_no_response)
  3. attested item at E1..E3 whose answer carries no class     -> no grade "attested_no_class"
  4. class unknown                                             -> Q0 "unknown_verdict"
  5. class not-applicable                                      -> no grade "not_applicable"
  6. correlation required and absent                           -> Q0 "not_correlated"  (not produced by qg-1 runs)
  7. class quantum-vulnerable and X, Y or Z not set            -> Q0 "mosca_missing"
  8. fallback and X, Y or Z not set                            -> Q0 "mosca_missing"
  9. class quantum-vulnerable and X + Y > Z and exposure internet -> Q1 "qv_exceeds_internet"
 10. class quantum-vulnerable and X + Y > Z and anchor         -> Q1 "qv_exceeds_anchor"
 11. class quantum-vulnerable and X + Y > Z and exposure unknown -> Q2 "qv_exceeds_exposure_unknown"
 12. class quantum-vulnerable and X + Y > Z                    -> Q2 "qv_exceeds"
 13. class quantum-vulnerable and X + Y <= Z                   -> Q3 "qv_within"
 14. fallback and X + Y > Z and exposure internet              -> Q1 "qv_fallback_exceeds_internet"
 15. fallback and X + Y > Z and anchor                         -> Q1 "qv_fallback_exceeds_anchor"
 16. fallback and X + Y > Z and exposure unknown               -> Q2 "qv_fallback_exceeds_exposure_unknown"
 17. fallback and X + Y > Z                                    -> Q2 "qv_fallback_exceeds"
 18. fallback and X + Y <= Z                                   -> Q3 "qv_fallback_within"
 19. class grover-weakened                                     -> Q3 "grover_weakened"
 20. class hybrid or quantum-safe, attested at E1              -> Q3 "pq_attested_e1"
 21. class hybrid or quantum-safe, observed                    -> Q4 "pq_observed"
 22. class hybrid or quantum-safe, code                        -> Q4 "pq_code"
 23. class hybrid or quantum-safe, attested at E2 or E3        -> Q4 "pq_attested"
Integers only; X, Y, Z in 0..100. A source X of 0 is a value (not "unset").
Network sources: unread scope of one source with the same status is one item, with a count and its addresses
(targets the node folds into one summary row count under their own statuses).
A missing X, Y or Z is one item ("inputs:mosca") with the count of the assets it leaves ungraded.
"""
FORMULA_SHA256 = "e7778cae6c2b3d7468ff7874f532cde57db7d5d98804849623c70c35f17bc901"
GRADE_MODEL = "qg-1"


def model_version(qgrade_source: bytes, posture_source: bytes, classifier_version: str) -> str:
    """``qg-1+`` and the first 12 hex of sha256(qgrade.py ‖ posture.py ‖ CLASSIFIER_VERSION): every module that can
    change a grade (the class and exposure functions live in posture; the fallback test reads the classifier's
    algorithm families at view time)."""
    return f"{GRADE_MODEL}+" + hashlib.sha256(qgrade_source + posture_source
                                              + classifier_version.encode("utf-8")).hexdigest()[:12]


GRADE_MODEL_VERSION = model_version(Path(__file__).read_bytes(), Path(P.__file__).read_bytes(), CLASSIFIER_VERSION)

GRADES = ("Q0", "Q1", "Q2", "Q3", "Q4")
LABELS = {"Q0": "Unknown", "Q1": "Critical", "Q2": "High", "Q3": "Medium", "Q4": "Low"}
CLASSES = ("quantum-vulnerable", "hybrid", "quantum-safe", "grover-weakened", "unknown", "not-applicable")
SCOPE_REASONS = ("coverage_gap", "source_not_read", "source_truncated", "excluded_by_choice")
_PQ = ("hybrid", "quantum-safe")
_E123 = ("E1", "E2", "E3")
Q0_ITEMS_CAP = 200
ADDRESS_CAP = 1000

# code -> grade (None: no grade), kind, what it means; served by the grade-model route
REASONS: dict[str, dict[str, Any]] = {
    "coverage_gap": {"grade": "Q0", "kind": "scope", "text": "A check, target or address range was not read"},
    "source_not_read": {"grade": "Q0", "kind": "scope",
                        "text": "The run did not read the source (skipped by the planner, or its collect job did not "
                                "succeed or has not finished)"},
    "source_truncated": {"grade": "Q0", "kind": "scope",
                         "text": "The collect job was cut at the asset limit, or stored fewer assets than it read"},
    "excluded_by_choice": {"grade": "Q0", "kind": "scope",
                           "text": "Left out by the team's choice (never-scan list, a disabled source, an option off)"},
    "evidence_e0": {"grade": "Q0", "kind": "evidence",
                    "text": "Evidence at E0 (no answer, rated unknown, expired, vendor no response)"},
    "attested_no_class": {"grade": None, "kind": "no_grade", "text": "Evidence answered without a PQC class"},
    "unknown_verdict": {"grade": "Q0", "kind": "asset", "text": "The product could not tell the asset's PQC class"},
    "not_applicable": {"grade": None, "kind": "no_grade", "text": "No public-key cryptography to grade"},
    "not_correlated": {"grade": "Q0", "kind": "asset", "text": "Correlation required and absent (reserved)"},
    "mosca_missing": {"grade": "Q0", "kind": "inputs",
                      "text": "Quantum-vulnerable, and the team's Mosca X, Y or Z is not set"},
    "qv_exceeds_internet": {"grade": "Q1", "kind": "asset",
                            "text": "Quantum-vulnerable, X + Y > Z, reachable from the internet"},
    "qv_exceeds_anchor": {"grade": "Q1", "kind": "asset", "text": "Quantum-vulnerable trust anchor (CA), X + Y > Z"},
    "qv_exceeds_exposure_unknown": {"grade": "Q2", "kind": "asset",
                                    "text": "Quantum-vulnerable, X + Y > Z, internet exposure unknown"},
    "qv_exceeds": {"grade": "Q2", "kind": "asset", "text": "Quantum-vulnerable, X + Y > Z, internal"},
    "qv_within": {"grade": "Q3", "kind": "asset", "text": "Quantum-vulnerable, X + Y <= Z"},
    "qv_fallback_exceeds_internet": {
        "grade": "Q1", "kind": "asset",
        "text": "Post-quantum endpoint that still accepts a classical fallback, X + Y > Z, reachable from the internet"},
    "qv_fallback_exceeds_anchor": {"grade": "Q1", "kind": "asset",
                                   "text": "Post-quantum trust anchor that still accepts a classical fallback, X + Y > Z"},
    "qv_fallback_exceeds_exposure_unknown": {
        "grade": "Q2", "kind": "asset",
        "text": "Post-quantum endpoint that still accepts a classical fallback, X + Y > Z, internet exposure unknown"},
    "qv_fallback_exceeds": {"grade": "Q2", "kind": "asset",
                            "text": "Post-quantum endpoint that still accepts a classical fallback, X + Y > Z, internal"},
    "qv_fallback_within": {"grade": "Q3", "kind": "asset",
                           "text": "Post-quantum endpoint that still accepts a classical fallback, X + Y <= Z"},
    "grover_weakened": {"grade": "Q3", "kind": "asset", "text": "128-bit symmetric key (Grover halves its strength)"},
    "pq_attested_e1": {"grade": "Q3", "kind": "asset", "text": "Hybrid or quantum-safe, resting only on E1 evidence"},
    "pq_observed": {"grade": "Q4", "kind": "asset", "text": "Hybrid or quantum-safe, observed by a collector"},
    "pq_code": {"grade": "Q4", "kind": "asset", "text": "Hybrid or quantum-safe, found in code"},
    "pq_attested": {"grade": "Q4", "kind": "asset", "text": "Hybrid or quantum-safe, attested at E2 or E3"},
    "not_an_item": {"grade": None, "kind": "not_an_item",
                    "text": "A coverage row that is not an unread scope (the target has no such thing, or an "
                            "address answered on no probed port)"},
}


# ----------------------------------------------------------------------------- the pure function
@dataclass(frozen=True)
class GradeInput:
    item: str = "asset"  # asset | scope | evidence
    scope_reason: str | None = None  # one of SCOPE_REASONS when item == "scope"
    cls: str | None = None  # one of CLASSES; None only for scope items and attested answers without a class
    fallback: bool = False
    exposure: str = "unknown"
    anchor: bool = False
    x: int | None = None
    y: int | None = None
    z: int | None = None
    provenance: str = "observed"  # observed | attested | code
    level: str | None = None  # E0..E3 for attested items
    correlation_missing: bool = False


@dataclass(frozen=True)
class Grade:
    q_grade: str | None
    q_reason: str

    @property
    def q_label(self) -> str | None:
        return LABELS.get(self.q_grade or "")


def _mosca_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 100 else None


def graded_class(cls: str | None, fallback: bool) -> str | None:
    """The class the grade is computed on (``q_explain.graded_class``): an endpoint that also completes a
    classical-only exchange is graded on that exchange (rules 8 and 14-18, reasons ``qv_fallback_*``)."""
    return "quantum-vulnerable" if cls in _PQ and fallback else cls


def grade(inp: GradeInput) -> Grade:
    """qg-1, rules 1-23 of ``FORMULA_TEXT`` in order (first match wins)."""
    if inp.item == "scope":
        if inp.scope_reason not in SCOPE_REASONS:
            raise ValueError(f"scope item without a known reason: {inp.scope_reason!r}")
        return Grade("Q0", inp.scope_reason)
    attested = inp.provenance == "attested"
    if attested and inp.level == "E0":
        return Grade("Q0", "evidence_e0")
    if attested and inp.level in _E123 and inp.cls is None:
        return Grade(None, "attested_no_class")
    cls = inp.cls
    if cls not in CLASSES:
        raise ValueError(f"asset without a PQC class: {inp.cls!r}")
    if cls == "unknown":
        return Grade("Q0", "unknown_verdict")
    if cls == "not-applicable":
        return Grade(None, "not_applicable")
    if inp.correlation_missing:
        return Grade("Q0", "not_correlated")
    fallback = cls in _PQ and inp.fallback
    if cls == "quantum-vulnerable" or fallback:
        x, y, z = (_mosca_int(v) for v in (inp.x, inp.y, inp.z))
        if x is None or y is None or z is None:
            return Grade("Q0", "mosca_missing")
        qv = "qv_fallback_" if fallback else "qv_"
        if x + y > z:
            if inp.exposure == "internet":
                return Grade("Q1", qv + "exceeds_internet")
            if inp.anchor:
                return Grade("Q1", qv + "exceeds_anchor")
            if inp.exposure == "unknown":
                return Grade("Q2", qv + "exceeds_exposure_unknown")
            return Grade("Q2", qv + "exceeds")
        return Grade("Q3", qv + "within")
    if cls == "grover-weakened":
        return Grade("Q3", "grover_weakened")
    # hybrid or quantum-safe
    if attested and inp.level == "E1":
        return Grade("Q3", "pq_attested_e1")
    if inp.provenance == "observed":
        return Grade("Q4", "pq_observed")
    if inp.provenance == "code":
        return Grade("Q4", "pq_code")
    if attested and inp.level in ("E2", "E3"):
        return Grade("Q4", "pq_attested")
    raise ValueError(f"no qg-1 rule matches {inp!r}")


def model_payload() -> dict[str, Any]:
    """What ``GET …/sources/grade-model`` serves."""
    return {"model": GRADE_MODEL, "model_version": GRADE_MODEL_VERSION, "text": FORMULA_TEXT,
            "text_sha256": hashlib.sha256(FORMULA_TEXT.encode("utf-8")).hexdigest(),
            "grades": [{"grade": g, "label": LABELS[g]} for g in GRADES],
            "reasons": [{"code": code, "grade": meta["grade"], "label": LABELS.get(meta["grade"] or ""),
                         "kind": meta["kind"], "text": meta["text"]} for code, meta in REASONS.items()]}


# ----------------------------------------------------------------------------- inputs from stored facts
# "not_supported" means both "the target has none" and "the product did not look" (HF-4): a coverage row is absent
# only when its check and detail match an entry here; every other "not_supported" row is an unread scope.
ABSENT: tuple[tuple[re.Pattern[str], re.Pattern[str]], ...] = (
    (re.compile(r"^BitLocker$", re.I), re.compile(r"\bnot installed\b", re.I)),
    (re.compile(r"^package list$", re.I), re.compile(r"\bno dpkg, apk or rpm\b.*\bpackage database\b", re.I)),
    (re.compile(r"AD CS|certificate services", re.I),
     re.compile(r"\bno Active Directory Certificate Services CA is configured\b", re.I)),
)
NO_ANSWER_CHECK = "no answer"


def coverage_kind(facts: dict[str, Any] | None) -> str:
    """``gap`` (an unread scope), ``by_choice`` (left out by the team), ``no_answer`` (an address that answered on no
    probed port: nothing there to read, FP-1) or ``not_present`` (the target has no such thing)."""
    facts = facts if isinstance(facts, dict) else {}
    status = str(facts.get("status") or "").strip()
    check = str(facts.get("check") or "").strip()
    detail = str(facts.get("detail") or "")
    if status == "not_installed":
        return "not_present"
    if status == "not_supported" and any(c.search(check) and d.search(detail) for c, d in ABSENT):
        return "not_present"
    if check == NO_ANSWER_CHECK and status == "unreachable":
        return "no_answer"
    if facts.get("by_choice"):
        return "by_choice"
    return "gap"


def _proto(value: Any) -> str:
    return re.sub(r"[\s_]", "", str(value or "").upper()).replace("TLSV", "TLS").replace("SSLV", "SSL")


def classical_fallback(asset_type: str, facts: dict[str, Any] | None, codes: list[str] | None) -> tuple[bool, str | None]:
    """(True, why) when an endpoint also completes a classical-only key exchange (the owner default: grade a hybrid on
    the weakest configuration it accepts). Only endpoints carry a key exchange."""
    if asset_type not in P.IN_TRANSIT:
        return False, None
    facts = facts if isinstance(facts, dict) else {}
    why: list[str] = []
    versions = facts.get("versions")
    protocols = list(facts.get("protocols") or []) if isinstance(facts.get("protocols"), list) else []
    if isinstance(versions, dict):
        protocols += [name for name, offered in versions.items() if offered]
    elif isinstance(versions, list):
        protocols += versions
    legacy = sorted({str(p) for p in protocols
                     if _proto(p).startswith(("TLS", "SSL")) and _proto(p) not in ("TLS1.3", "TLS13")})
    if legacy:
        why.append("accepts " + ", ".join(legacy[:3]).replace("TLSv", "TLS ").replace("TLS1", "TLS 1"))
    weak = facts.get("weak_ciphers_accepted") if isinstance(facts.get("weak_ciphers_accepted"), dict) else {}
    if facts.get("static_rsa_kex") or weak.get("static_rsa") or "STATIC_RSA_KEX" in (codes or []):
        why.append("accepts static RSA key transport")
    groups = [facts.get("group"), facts.get("negotiated_group")]
    groups += list(facts.get("groups") or []) if isinstance(facts.get("groups"), list) else []
    classical = sorted({str(gr) for gr in groups if gr and quantum_vulnerable(gr) is True})
    if classical:
        why.append("accepts classical group " + ", ".join(classical[:3]))
    elif facts.get("classical_tls13_accepted") is True:  # CB-12's prober: a classical TLS 1.3 key share answered
        why.append("accepts a classical TLS 1.3 key share")
    elif aws_pq_policy(facts):
        # AWS documents every post-quantum ELB and API Gateway policy as also accepting classical key exchange, for
        # compatibility: the hybrid is graded on the classical exchange a client without post-quantum support completes
        policy = facts.get("ssl_policy") or facts.get("security_policy")
        why.append(f"AWS post-quantum policy {str(policy)[:64]} also accepts classical key exchange")
    kex = ssh_names(facts.get("kex")) or ssh_names(facts.get("kexalgorithms"))  # read as the classifier reads it
    # the classifier's verdict, which reads algid's SSH key-exchange registry (GSS families included): one source
    classical_kex = sorted({k for k in kex if quantum_vulnerable(k) is True})
    if classical_kex:
        why.append("offers classical SSH key exchange " + ", ".join(classical_kex[:3]))
    return (bool(why), "; ".join(why) or None)


ANCHOR_TYPES = ("cloud_ca", "ca_authority")


def trust_anchor(asset_type: str, facts: dict[str, Any] | None) -> tuple[bool, str | None]:
    """(anchor, basis): a CA certificate (``is_ca``) or a CA (``cloud_ca``, ``ca_authority``). IdP token-signing keys
    are not anchors (OQ-4); code-signing certificates are undetectable today (no EKU fact)."""
    if asset_type in ANCHOR_TYPES:
        return True, asset_type
    if isinstance(facts, dict) and facts.get("is_ca") is True:
        return True, "is_ca"
    return False, None


def grade_exposure(facts: dict[str, Any] | None, target: str | None, location: str | None, *, override: str | None,
                   segment: str | None, memo: dict | None = None) -> tuple[str, str]:
    """``posture.asset_exposure`` (one exposure function), memoised per (override, segment, target, location, the
    collector's fact), with one grade-only change: a collector's ``internet_facing: true`` beats an ``internal``
    or ``unknown`` override (HF-8; review B). The risk score keeps ``asset_exposure`` unchanged."""
    facts = facts if isinstance(facts, dict) else {}
    flag = facts.get("internet_facing")
    flag = flag if isinstance(flag, bool) else None
    reason = str(facts.get("internet_facing_reason") or "").strip()[:120]
    memo = {} if memo is None else memo

    def one(loc: str | None) -> tuple[str, str]:
        key = (override, segment, flag, reason, target, loc)
        if key not in memo:
            if override in ("internal", "unknown") and flag is True:
                memo[key] = ("internet", "reported internet-facing by the collector"
                             + (f" ({reason})" if reason else "") + f"; the source says {override}")
            else:
                slim = {"internet_facing": flag, "internet_facing_reason": reason} if flag is not None else {}
                memo[key] = P.asset_exposure(slim, target, loc, override=override, node_segment=segment)
        return memo[key]

    # the location is read only when nothing before it decides (asset_exposure reads it last), so most rows share
    # one memo entry per (override, segment, collector fact, target) instead of one per location
    out = one(None)
    return out if out[0] != "unknown" or not location else one(location)


@functools.lru_cache(maxsize=4096)
def _grade_observed(cls: str, fallback: bool, exposure: str, anchor: bool, x: int | None, y: int | None,
                    z: int | None) -> Grade:
    """``grade`` for an observed asset, memoised on its (few, small) inputs: the posture loop grades every row."""
    return grade(GradeInput(item="asset", cls=cls, fallback=fallback, exposure=exposure, anchor=anchor, x=x, y=y, z=z,
                            provenance="observed"))


# ----------------------------------------------------------------------------- one context loader for every surface
@dataclass
class _JobInfo:
    x: int | None
    exposure: str | None
    segment: str | None
    source_uid: str
    source_id: int | None
    source_name: str | None
    network: bool


@dataclass
class RowGrade:
    q_grade: str | None
    q_reason: str
    q_item_key: str | None
    explain: dict[str, Any]

    @property
    def q_label(self) -> str | None:
        return LABELS.get(self.q_grade or "")

    def fields(self) -> dict[str, Any]:
        return {"q_grade": self.q_grade, "q_label": self.q_label, "q_reason": self.q_reason,
                "q_item_key": self.q_item_key}


@functools.lru_cache(maxsize=4096)
def _row_observed(cls: str, fallback: bool, exposure: str, anchor: bool, x: int | None, y: int | None,
                  z: int | None) -> RowGrade | None:
    """The shared explain=False result of an observed asset; None for a Q0 that is keyed by the asset itself."""
    out = _grade_observed(cls, fallback, exposure, anchor, x, y, z)
    if out.q_reason == "mosca_missing":
        missing = [k for k, v in (("x", x), ("y", y), ("z", z)) if v is None]
        return RowGrade(out.q_grade, out.q_reason, "inputs:mosca", {"missing": missing})
    if out.q_grade == "Q0":
        return None
    return RowGrade(out.q_grade, out.q_reason, None, {"missing": []})


# classes whose grade reads nothing but the class (rules 5 and 19): shared results for explain=False (never mutated)
_NO_INPUTS = {"not-applicable": RowGrade(None, "not_applicable", None, {"missing": []}),
              "grover-weakened": RowGrade("Q3", "grover_weakened", None, {"missing": []})}


@dataclass
class GradeContext:
    """The inputs every surface grades one run (or job) with: team Mosca now, each job's metadata snapshot."""
    team_x: int | None
    y: int | None
    z: int | None
    jobs: dict[int, _JobInfo]
    run: CbomCollectionRun | None
    job_rows: list[CbomCollectionJob]
    sources: dict[int, CbomCollectionSource]
    memo: dict = field(default_factory=dict)
    # CB-18 EC-3: an unknown row another job of the run read with a verdict is not an unknown verdict
    elsewhere: P.JudgedElsewhere | None = None
    # CB-19 PR-2: "snapshot" (the run's inputs at Start: the record) or "current" (the team's inputs now)
    inputs_source: str = "current"
    snapshot: dict[str, Any] | None = None

    @property
    def mosca(self) -> dict[str, int | None]:
        return {"x": self.team_x, "y": self.y, "z": self.z}

    @functools.cached_property
    def digest(self) -> str:
        """sha256 of the canonical inputs (team Mosca; each source's snapshotted X / exposure override / segment, by
        source ref, never by job id, so two runs with the same inputs share a digest), first 16 hex."""
        jobs = sorted([j.source_uid, j.x, j.exposure, j.segment] for j in self.jobs.values())
        doc = {"mosca": self.mosca, "sources": jobs}
        return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]

    def inputs(self) -> dict[str, Any]:
        snap = self.snapshot if self.inputs_source == "snapshot" else None
        return {"source": self.inputs_source, "mosca": self.mosca, "digest": self.digest,
                "snapshot_digest": snap.get("digest") if snap else None,
                "captured_at": snap.get("captured_at") if snap else None}

    def with_inputs(self, risk_model: dict[str, Any] | None) -> GradeContext:
        """The same run graded with the team's inputs now (``source: current``): what the run page shows beside the
        record when the inputs changed after Start. Shares the jobs, sources and the exposure memo."""
        m = mosca_of(risk_model)
        return replace(self, team_x=m["x"], y=m["y"], z=m["z"], inputs_source="current")

    def inputs_changed(self, risk_model: dict[str, Any] | None) -> bool:
        """True when this run graded from its snapshot and the team's Mosca differs from it now."""
        return self.inputs_source == "snapshot" and mosca_of(risk_model) != self.mosca

    def _job(self, job_id: int | None) -> _JobInfo:
        return self.jobs.get(job_id or 0) or _JobInfo(None, None, None, "unknown", None, None, False)

    def grade_row(self, row: CbomCollectedAsset, codes: list[str] | None, *, explain: bool = True,
                  score_exposure: tuple[str, str] | None = None, cls: str | None = None) -> RowGrade:
        """The grade of one stored row; ``codes``: the finding codes as every view shows them (``classify.shown``).
        ``explain=False`` (list pages, posture) skips the inputs no rule reads for this row's class (exposure and
        anchor only matter to a quantum-vulnerable grade); the grade is the same either way. ``score_exposure``: the
        (exposure, basis) ``posture.asset_exposure`` already gave this row with the same job metadata; reused except
        where the grade's precedence differs (a collector's internet-facing fact against an "internal" or "unknown"
        source setting)."""
        job = self._job(row.job_id)
        asset_type = row.asset_type
        if asset_type == "coverage":
            return self._coverage(row, job)
        facts = row.facts if isinstance(row.facts, dict) else {}
        codes = codes or []  # the class and fallback tests read DISK_XTS_128 / STATIC_RSA_KEX; COVERAGE_* never match
        if cls is None:  # the posture loop passes the class it already computed with the same function
            cls = P.classify_pqc(row, codes, elsewhere=self.elsewhere)[0]
        if not explain:  # the posture loop and list pages: only the inputs this class's rules read
            fast = _NO_INPUTS.get(cls)
            if fast is not None:
                return fast
            fallback = classical_fallback(asset_type, facts, codes)[0] if cls in _PQ else False
            if cls == "quantum-vulnerable" or fallback:
                if score_exposure is not None and not (job.exposure in ("internal", "unknown")
                                                       and facts.get("internet_facing") is True):
                    exposure = score_exposure[0]
                else:
                    exposure = grade_exposure(facts, row.target, row.location, override=job.exposure,
                                              segment=job.segment, memo=self.memo)[0]
                anchor = asset_type in ANCHOR_TYPES or facts.get("is_ca") is True
            else:
                exposure, anchor = "unknown", False
            shared = _row_observed(cls, fallback, exposure, anchor, job.x if job.x is not None else self.team_x,
                                   self.y, self.z)
            if shared is not None:
                return shared
        fallback, fallback_basis = classical_fallback(row.asset_type, facts, codes) if cls in _PQ else (False, None)
        if explain or graded_class(cls, fallback) == "quantum-vulnerable":
            if score_exposure is not None and not (job.exposure in ("internal", "unknown")
                                                   and facts.get("internet_facing") is True):
                exposure, exposure_basis = score_exposure
            else:
                exposure, exposure_basis = grade_exposure(facts, row.target, row.location, override=job.exposure,
                                                          segment=job.segment, memo=self.memo)
            anchor, anchor_basis = trust_anchor(row.asset_type, facts)
        else:
            exposure, exposure_basis, anchor, anchor_basis = "unknown", None, False, None
        x, x_basis = (job.x, "source") if job.x is not None else (self.team_x, "team" if self.team_x is not None else None)
        out = _grade_observed(cls, fallback, exposure, anchor, x, self.y, self.z)
        missing = [k for k, v in (("x", x), ("y", self.y), ("z", self.z)) if v is None]
        item_key = "inputs:mosca" if out.q_reason == "mosca_missing" else (
            f"asset:{ID.stable_key('node', job.source_uid, ID.node_identity(row))}" if out.q_grade == "Q0" else None)
        if not explain:  # list pages and the posture loop read only the grade and what is missing
            return RowGrade(out.q_grade, out.q_reason, item_key,
                            {"missing": missing if out.q_reason == "mosca_missing" else []})
        inequality = None
        if not missing:
            inequality = f"{x} + {self.y} {'>' if x + self.y > self.z else '<='} {self.z}"  # type: ignore[operator]
        detail = {
            "class": cls, "class_basis": None, "graded_class": graded_class(cls, fallback), "fallback": fallback,
            "fallback_basis": fallback_basis, "exposure": exposure, "exposure_basis": exposure_basis,
            "anchor": anchor, "anchor_basis": anchor_basis, "x": x, "x_basis": x_basis, "y": self.y, "z": self.z,
            "missing": missing if out.q_reason == "mosca_missing" else [], "inequality": inequality,
            "provenance": "observed", "item_kind": "asset", "coverage": None, "check": None, "status": None,
        }
        return RowGrade(out.q_grade, out.q_reason, item_key, self._stamp(detail))

    def _stamp(self, explain: dict[str, Any]) -> dict[str, Any]:
        return {**explain, "model": GRADE_MODEL, "model_version": GRADE_MODEL_VERSION,
                "inputs_source": self.inputs_source,
                "inputs_digest": self.digest,
                "classifier_version": CLASSIFIER_VERSION,  # the classifier this view graded with (in the model version)
                "run_classifier_version": self.run.classifier_version if self.run is not None else None}

    def _coverage(self, row: CbomCollectedAsset, job: _JobInfo) -> RowGrade:
        facts = row.facts if isinstance(row.facts, dict) else {}
        kind = coverage_kind(facts)
        status = str(facts.get("status") or "")
        empty = {k: None for k in ("class", "class_basis", "graded_class", "fallback_basis", "exposure",
                                   "exposure_basis", "anchor_basis", "x", "x_basis", "y", "z", "inequality")}
        explain = {**empty, "fallback": False, "anchor": False, "missing": [], "provenance": "observed",
                   "item_kind": "scope", "coverage": kind, "check": facts.get("check"), "status": status}
        if kind in ("not_present", "no_answer"):
            return RowGrade(None, "not_an_item", None, self._stamp(explain))
        reason = "excluded_by_choice" if kind == "by_choice" else "coverage_gap"
        target = str(row.target or "")
        if job.network and kind != "by_choice":
            key = f"coverage:{job.source_uid}:*:{status}"
        else:
            key = f"coverage:{job.source_uid}:{target}:{facts.get('check') or ''}"
        out = grade(GradeInput(item="scope", scope_reason=reason))
        return RowGrade(out.q_grade, out.q_reason, key, self._stamp(explain))


def _source_ref(source: CbomCollectionSource | None, source_id: int | None) -> str:
    """A source without a job (planner-skipped, left out of the run): named as ``identity.job_source_ref`` would."""
    if source is not None and source.source_uid:
        return source.source_uid
    return f"source-{source_id}" if source_id is not None else "deleted:unknown"


def load_context(session: Session, *, team_id: int, run_id: int | None = None, job_id: int | None = None,
                 risk_model: dict[str, Any] | None = None, inputs: str = "record") -> GradeContext:
    """Jobs of the run (or the one job when it has no run), their sources and nodes, and the Mosca X/Y/Z to grade with:
    the run's snapshot taken at Start (``inputs="record"``, the default, when the run has one), else the team's Mosca
    now (``risk_model``, or read without creating a settings row when it is not given)."""
    from backend.utilities.cbom_sources.kinds import KINDS

    if run_id is None and job_id is not None:
        job = session.get(CbomCollectionJob, job_id)
        if job is not None and job.team_id == team_id and job.run_id is not None:
            run_id = job.run_id
    run = session.get(CbomCollectionRun, run_id) if run_id is not None else None
    if run is not None and run.team_id != team_id:
        run = None
    query = select(CbomCollectionJob).where(CbomCollectionJob.team_id == team_id)
    query = query.where(CbomCollectionJob.run_id == run_id) if run_id is not None else \
        query.where(CbomCollectionJob.id == (job_id or 0))
    job_rows = list(session.exec(query.order_by(CbomCollectionJob.id)).all())
    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id)).all() if s.id is not None}
    nodes = {n.id: n for n in session.exec(select(CbomScanNode).where(CbomScanNode.team_id == team_id)).all()}
    if risk_model is None:
        settings = session.exec(select(CbomCollectionSettings).where(CbomCollectionSettings.team_id == team_id)).first()
        risk_model = (settings.risk_model if settings is not None else None) or {}
    risk_model = risk_model or {}
    snapshot = run.grade_inputs if run is not None and inputs == "record" else None
    if not (isinstance(snapshot, dict) and isinstance(snapshot.get("mosca"), dict)):
        snapshot = None
    jobs: dict[int, _JobInfo] = {}
    for job in job_rows:
        params = job.params if isinstance(job.params, dict) else {}
        source = sources.get(job.source_id or 0)
        meta = P.job_metadata(params, source, nodes.get(job.node_id or 0))
        spec = KINDS.get(source.kind) if source is not None else None
        jobs[job.id] = _JobInfo(  # type: ignore[index]
            # normalised: a legacy or corrupt snapshot value (a list, a dict) must not break every grade surface
            x=_mosca_int(meta.get("data_lifetime_years")),
            exposure=meta.get("exposure") if meta.get("exposure") in P.EXPOSURES else None,
            segment=meta.get("segment") if isinstance(meta.get("segment"), str) else None,
            source_uid=ID.job_source_ref(job, source), source_id=job.source_id,
            source_name=(source.name if source else None) or params.get("source_name"),
            network=bool(spec is not None and spec.group == "network"))
    m = {k: _mosca_int(snapshot["mosca"].get(k)) for k in "xyz"} if snapshot is not None else mosca_of(risk_model)
    return GradeContext(team_x=m["x"], y=m["y"], z=m["z"],
                        jobs=jobs, run=run, job_rows=job_rows, sources=sources,
                        elsewhere=P.JudgedElsewhere(session=session, team_id=team_id, run_id=run_id)
                        if run_id is not None else None,
                        inputs_source="snapshot" if snapshot is not None else "current", snapshot=snapshot)


# ----------------------------------------------------------------------------- the run's inputs at Start (PR-2)
_MOSCA_KEYS = {"x": "data_shelf_life_years", "y": "migration_years", "z": "threat_years"}


def mosca_of(risk_model: dict[str, Any] | None) -> dict[str, int | None]:
    """The team's Mosca X/Y/Z as the grade reads them (integers 0..100, anything else unset)."""
    model = risk_model if isinstance(risk_model, dict) else {}
    return {k: _mosca_int(model.get(name)) for k, name in _MOSCA_KEYS.items()}


def risk_model_of(mosca: dict[str, Any]) -> dict[str, Any]:
    """A snapshot's ``mosca`` in the settings' ``risk_model`` spelling (for ``posture.mosca``)."""
    return {name: mosca.get(k) for k, name in _MOSCA_KEYS.items()}


def evidence_snapshot(session: Session, team_id: int, now: _dt.datetime) -> dict[str, Any]:
    """The evidence levels and Q0 gaps a run is graded against, from the same functions the Evidence tab uses
    (``serialize.public_area`` / ``public_vendor`` / ``evidence.q0_gaps``), read without writing (an area nobody opened
    has no row yet: it is graded as an empty one, which is what the tab shows once it creates it).

    One item per area and per vendor: identity ``id`` = ``area:<area_key>`` / ``vendor:<id>`` (``kind`` + ``key``; the
    reason is an attribute), the effective level, and the gap reason (null above E0). The third-party-vendors area's
    roll-up gap is not an item (its vendors carry the gaps, FP-8). No answers, e-mails or evidence URLs."""
    from backend.utilities.cbom_sources import evidence as EV
    from backend.utilities.cbom_sources.serialize import public_area, public_vendor

    today = now.date()
    stored = {a.area_key: a for a in session.exec(select(CbomEvidenceArea).where(
        CbomEvidenceArea.team_id == team_id)).all()}
    areas = [stored.get(key) or CbomEvidenceArea(team_id=team_id, area_key=key) for key in EV.AREAS]
    areas += [row for key, row in sorted(stored.items()) if key not in EV.AREAS]
    vendors = session.exec(select(CbomEvidenceVendor).where(CbomEvidenceVendor.team_id == team_id)
                           .order_by(CbomEvidenceVendor.id)).all()
    vendor_rows = [public_vendor(v, now) for v in vendors]
    rows = [public_area(a, today, [v["effective_confidence"] for v in vendor_rows]) for a in areas]
    _gaps, count = EV.q0_gaps(rows, vendor_rows, today)
    items: list[dict[str, Any]] = []
    for row in rows:
        if row["q0_gap_rollup"]:
            continue
        gap = row["q0_gap"] or {}
        items.append({"id": f"area:{row['area_key']}", "kind": "area", "key": row["area_key"], "title": row["title"],
                      "level": row["effective_confidence"], "reason": gap.get("reason"), "detail": gap.get("detail"),
                      "evidence_date": row["evidence_date"]})
    for row in vendor_rows:
        gap = row["q0_gap"] or {}
        items.append({"id": f"vendor:{row['id']}", "kind": "vendor", "key": str(row["id"]), "title": row["name"],
                      "level": row["effective_confidence"], "reason": gap.get("reason"), "detail": gap.get("detail"),
                      "status": row["status"]})
    return {"as_of": today.isoformat(), "gap_count": count, "items": items}


def snapshot_inputs(session: Session, team_id: int, settings: CbomCollectionSettings,
                    now: _dt.datetime) -> dict[str, Any]:
    """What ``runs.queue_run`` records on a run at Start (PLAN §2.4): the model, the team's Mosca from the settings
    row the Start read (``settings_row_version`` names it), the evidence levels and Q0 gaps, and a digest of all of
    it but ``captured_at`` (the same inputs give the same digest). Per-source X, exposure and segment are already in
    each job's metadata snapshot."""
    from backend.utilities.cbom_sources.common import iso_z

    doc: dict[str, Any] = {"model": GRADE_MODEL, "model_version": GRADE_MODEL_VERSION,
                           "settings_row_version": settings.row_version, "mosca": mosca_of(settings.risk_model),
                           "evidence": evidence_snapshot(session, team_id, now)}
    doc["digest"] = hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":"), default=str)
                                   .encode("utf-8")).hexdigest()[:16]
    doc["captured_at"] = iso_z(now)
    return doc


def run_grades(run: CbomCollectionRun, risk_model: dict[str, Any] | None) -> dict[str, Any]:
    """``GET …/runs/{id}`` ``grades``: the run's model and snapshot, and whether the team's Mosca (``risk_model``,
    now) or the grade model differs from them. Every key always present; ``inputs_changed`` is null when the caller
    has no current inputs to compare with."""
    snap = run.grade_inputs if isinstance(run.grade_inputs, dict) and isinstance(
        run.grade_inputs.get("mosca"), dict) else None
    changed: bool | None = None
    if risk_model is not None or snap is None:
        changed = snap is not None and mosca_of(risk_model) != {k: _mosca_int(snap["mosca"].get(k)) for k in "xyz"}
    return {"model_version": run.grade_model_version, "inputs": snap,
            "inputs_digest": snap.get("digest") if snap else None,
            "inputs_source": "snapshot" if snap else "current", "inputs_changed": changed,
            "model_changed": run.grade_model_version != GRADE_MODEL_VERSION,
            "mosca_now": mosca_of(risk_model) if changed else None}


# ----------------------------------------------------------------------------- unread scope of a run
_UNREAD_JOB = {"failure": "collection failure", "expired": "collection expired", "cancelled": "collection cancelled",
               "pending": "collection not finished", "claimed": "collection not finished"}
_BY_CHOICE_SKIPS = ("Disabled", "0 targets left after the never-scan list")
# "not_supported" on a target means "not read" (a zstd image layer, Oracle NNE, TDS 8.0 strict, a protocol this node
# version cannot speak ...) unless it says the target has nothing there (cx2 HF-4: not-read by default)
_TARGET_ABSENT = (re.compile(r"\bno Active Directory Certificate Services CA is configured\b", re.I),)


def target_kind(target: dict[str, Any]) -> str:
    """One row of a job's ``result.targets``: ``read`` (ok / partial), ``by_choice`` (never-scan list), ``summary``
    (the node's "+N more" row, whose error is JSON {status: count}), ``not_present`` (a cloud region or project with
    every service not enabled, a server with no AD CS CA) or ``gap`` (every other status, "not_supported" included)."""
    status = str(target.get("status") or "")
    if status in ("", "ok", "partial"):
        return "read"
    if status == "skipped_never_scan":
        return "by_choice"
    if status == "summary":
        return "summary"
    if status == "not_supported":
        services = target.get("services")
        if isinstance(services, dict) and services and all(v == "not_enabled" for v in services.values()):
            return "not_present"
        if any(p.search(str(target.get("error") or "")) for p in _TARGET_ABSENT):
            return "not_present"
    return "gap"


def _summary_counts(target: dict[str, Any]) -> dict[str, int]:
    try:
        counts = json.loads(str(target.get("error") or "{}"))
    except ValueError:
        return {}
    return {str(k): v for k, v in counts.items() if isinstance(v, int) and not isinstance(v, bool) and v > 0} \
        if isinstance(counts, dict) else {}


class _Items:
    def __init__(self) -> None:
        self.by_key: dict[str, dict[str, Any]] = {}

    def add(self, key: str, reason: str, *, source: _JobInfo | None = None, count: int = 1,
            **extra: Any) -> dict[str, Any]:
        item = self.by_key.get(key)
        if item is None:
            item = self.by_key[key] = {
                "key": key, "kind": REASONS[reason]["kind"], "reason": reason, "q_grade": REASONS[reason]["grade"],
                "source_id": source.source_id if source else None, "source_name": source.source_name if source else None,
                "count": 0, **extra}
        item["count"] += count
        return item


def scope_items(ctx: GradeContext, coverage: list[tuple[CbomCollectedAsset, RowGrade]]) -> tuple[list[dict[str, Any]], Counter[str]]:
    """The run's unread-scope Q0 items, and the coverage rows that are not items (by kind):

    * coverage rows graded Q0 by ``GradeContext.grade_row`` (one item per key; a network source's rows of one status
      are one item with a count, the first 1,000 addresses and the row ids);
    * job targets the job did not read (``target_kind``: ``skipped_never_scan`` is excluded by choice; network sources
      aggregated the same way; the node's "summary" row adds its per-status counts to the same per-status items);
    * collect jobs that did not succeed or have not finished (``source_not_read``), or were cut at the asset limit or
      lost assets (``source_truncated``, the reasons ``drift.job_comparable`` gives);
    * sources the planner skipped (``run.breakdown.skipped``): "Disabled" and "0 targets left after the never-scan
      list" are excluded by choice, every other reason is ``source_not_read`` with the planner's text;
    * the team's other sources that existed when the run started and that the run neither collected nor skipped: in a
      group the run's ``include`` left out, or not chosen for the run (``excluded_by_choice``, cx2 HF-5)."""
    items = _Items()
    not_items: Counter[str] = Counter()
    for row, out in coverage:
        if out.q_item_key is None:
            not_items[out.explain.get("coverage") or "not_an_item"] += 1
            continue
        facts = row.facts if isinstance(row.facts, dict) else {}
        job = ctx._job(row.job_id)
        aggregated = job.network and out.q_reason == "coverage_gap"
        item = items.add(out.q_item_key, out.q_reason, source=job, target="*" if aggregated else row.target,
                         check=None if aggregated else facts.get("check"), status=facts.get("status"),
                         detail=str(facts.get("detail") or "")[:300] or None, refs=[])
        if len(item["refs"]) < ADDRESS_CAP:
            item["refs"].append(row.id)
        if aggregated:
            item.setdefault("addresses", [])
            if row.target and len(item["addresses"]) < ADDRESS_CAP:
                item["addresses"].append(row.target)
    for job in ctx.job_rows:
        if job.kind != "collect":
            continue
        info = ctx._job(job.id)
        result = job.result if isinstance(job.result, dict) else {}
        if job.status != "success":
            items.add(f"source:{info.source_uid}", "source_not_read", source=info,
                      detail=_UNREAD_JOB.get(job.status, f"collection {job.status}")
                      + (f": {job.error[:200]}" if job.error else ""))
            continue
        if result.get("truncated") or result.get("asset_mismatch"):
            mismatch = result.get("asset_mismatch") if isinstance(result.get("asset_mismatch"), dict) else None
            items.add(f"source:{info.source_uid}", "source_truncated", source=info,
                      detail=mismatch or {"truncated": True, "stored": job.asset_count})
        for t in result.get("targets") if isinstance(result.get("targets"), list) else []:
            if not isinstance(t, dict):
                continue
            status, target = str(t.get("status") or ""), str(t.get("target") or "")
            kind = target_kind(t)
            if kind in ("read", "not_present"):
                continue
            if kind == "summary":  # targets past the node's 1,000 rows: counted under their own statuses
                for sub, n in sorted(_summary_counts(t).items()):
                    if target_kind({"status": sub}) != "gap":
                        continue
                    item = items.add(f"coverage:{info.source_uid}:*:{sub}", "coverage_gap", source=info, target="*",
                                     check=None, status=sub, detail=f"targets not read: {sub}", count=n, refs=[])
                    item.setdefault("addresses", [])
                continue
            if kind == "by_choice":
                items.add(f"coverage:{info.source_uid}:{target}:by_choice", "excluded_by_choice", source=info,
                          target=target, check=None, status=status, detail="on the never-scan list")
            elif info.network:
                item = items.add(f"coverage:{info.source_uid}:*:{status}", "coverage_gap", source=info, target="*",
                                 check=None, status=status, detail=f"addresses not read: {status}", refs=[])
                item.setdefault("addresses", [])
                if len(item["addresses"]) < ADDRESS_CAP:
                    item["addresses"].append(target)
            else:
                items.add(f"coverage:{info.source_uid}:{target}:target", "coverage_gap", source=info, target=target,
                          check="target", status=status, detail=str(t.get("error") or "")[:300] or None)
    run = ctx.run
    breakdown = run.breakdown if run is not None and isinstance(run.breakdown, dict) else {}
    seen = {j.source_id for j in ctx.job_rows if j.kind == "collect"}
    for entry in breakdown.get("skipped") or []:
        if not isinstance(entry, dict):
            continue
        sid = entry.get("source_id") if isinstance(entry.get("source_id"), int) else None
        seen.add(sid)
        source = ctx.sources.get(sid or 0)
        info = _JobInfo(None, None, None, _source_ref(source, sid), sid,
                        entry.get("name") or (source.name if source else None), False)
        reason = str(entry.get("reason") or "skipped")
        items.add(f"source:{info.source_uid}", "excluded_by_choice" if reason in _BY_CHOICE_SKIPS else "source_not_read",
                  source=info, detail=f"skipped by the planner: {reason}"[:300])
    if run is not None and run.created_at is not None:
        from backend.utilities.cbom_sources.kinds import KINDS

        include = run.include if isinstance(run.include, dict) else {}
        for sid, source in sorted(ctx.sources.items()):
            spec = KINDS.get(source.kind)
            if sid in seen or spec is None or (source.created_at is not None and source.created_at > run.created_at):
                continue
            key = "cloud" if spec.group in ("cloud", "identity") else spec.group
            left_out = bool(include) and not include.get(key, False)
            info = _JobInfo(None, None, None, _source_ref(source, sid), sid, source.name, False)
            items.add(f"source:{info.source_uid}", "excluded_by_choice", source=info,
                      detail=(f"the {key} group was left out of this run" if left_out
                              else "not chosen for this run"))
    return list(items.by_key.values()), not_items


# ----------------------------------------------------------------------------- run posture: the accumulator
_ITEM_RANK = {"inputs": 0, "source": 1, "asset": 2, "coverage": 3}

class RunGrades:
    """Grades of one run's rows, fed one row at a time from ``posture.run_posture``'s loop; ``result`` adds the
    run's unread scope (``scope_items``) and the Q0 item list."""

    def __init__(self, session: Session, *, team_id: int, run_id: int, risk_model: dict[str, Any] | None) -> None:
        self.ctx = load_context(session, team_id=team_id, run_id=run_id, risk_model=risk_model or {})
        # PR-2: the record grades with the run's snapshot; when the team's Mosca differs now, every row is also graded
        # with it (``q_grades_now``), beside the record and never in its place
        self.risk_model = risk_model or {}
        self.now = self.ctx.with_inputs(risk_model) if self.ctx.inputs_changed(risk_model) else None
        self.q_grades_now: Counter[str] = Counter()
        self.changed_now = 0
        self.q_grades: Counter[str] = Counter()
        self.coverage: list[tuple[CbomCollectedAsset, RowGrade]] = []
        self.assets = _Items()
        self.asset_q0 = 0
        self._mosca: dict[str, Any] | None = None

    @property
    def record_risk_model(self) -> dict[str, Any]:
        """The Mosca the record grades with, in the settings' spelling."""
        return risk_model_of(self.ctx.mosca) if self.ctx.inputs_source == "snapshot" else self.risk_model

    def add(self, row: CbomCollectedAsset, codes: list[str] | None,
            exposure: tuple[str, str] | None = None, cls: str | None = None) -> RowGrade:
        out = self.ctx.grade_row(row, codes, explain=False, score_exposure=exposure, cls=cls)
        if row.asset_type == "coverage":
            self.coverage.append((row, out))
            return out
        self.q_grades[out.q_grade or "none"] += 1
        if self.now is not None:
            now = self.now.grade_row(row, codes, explain=False, score_exposure=exposure, cls=cls)
            self.q_grades_now[now.q_grade or "none"] += 1
            self.changed_now += (now.q_grade, now.q_reason) != (out.q_grade, out.q_reason)
        if out.q_grade == "Q0":
            self.asset_q0 += 1
            if out.q_reason == "mosca_missing":  # one missing team setting is one item (FP-5)
                m = self._mosca = self._mosca or {"key": "inputs:mosca", "kind": "inputs", "reason": "mosca_missing",
                                                  "q_grade": "Q0", "source_id": None, "source_name": None,
                                                  "count": 0, "missing": []}
                m["count"] += 1
                m["missing"] = sorted(set(m["missing"]) | set(out.explain["missing"]), key="xyz".index)
            elif out.q_item_key:
                self.assets.add(out.q_item_key, out.q_reason, source=self.ctx._job(row.job_id), asset_id=row.id,
                                type=row.asset_type, location=row.location)
        return out

    def result(self) -> dict[str, Any]:
        scope, not_items = scope_items(self.ctx, self.coverage)
        items = scope + list(self.assets.by_key.values()) + ([self._mosca] if self._mosca else [])
        # inputs, then sources, then assets, then coverage: the cap never drops the one setting or the source that
        # leaves the most unread (review A); deterministic within each rank
        items.sort(key=lambda i: (_ITEM_RANK.get(i["key"].split(":", 1)[0], 9), i["reason"], i["key"]))
        return {
            "q_grades": {g: self.q_grades.get(g, 0) for g in (*GRADES, "none")},
            "q0_reasons": dict(sorted(Counter(i["reason"] for i in items).items())),
            "q0_items": items[:Q0_ITEMS_CAP],
            "q0_items_total": len(items),
            "q0_counts": {"assets": self.asset_q0, "scope_items": len(scope),
                          "scope_rows": sum(i["count"] for i in scope)},
            "q_not_items": {"no_answer": not_items.get("no_answer", 0),
                            "not_present": not_items.get("not_present", 0)},
            "grade_model": GRADE_MODEL,
            "grade_model_version": GRADE_MODEL_VERSION,
            "grade_inputs": self.ctx.inputs(),
            # PR-2: the same rows with the team's inputs now (null when they equal the run's snapshot)
            "inputs_changed": self.now is not None,
            "model_changed": self.ctx.run is not None and self.ctx.run.grade_model_version != GRADE_MODEL_VERSION,
            "q_grades_now": {g: self.q_grades_now.get(g, 0) for g in (*GRADES, "none")} if self.now else None,
            "q_changed_now": self.changed_now if self.now else None,
            "grade_inputs_now": self.now.inputs() if self.now else None,
        }


__all__ = ["FORMULA_TEXT", "FORMULA_SHA256", "GRADE_MODEL", "GRADE_MODEL_VERSION", "GradeInput", "Grade", "grade",
           "GradeContext", "RowGrade", "RunGrades", "load_context", "scope_items", "snapshot_inputs",
           "evidence_snapshot", "run_grades", "mosca_of", "risk_model_of", "model_payload", "coverage_kind",
           "classical_fallback", "trust_anchor", "grade_exposure", "REASONS", "LABELS"]
