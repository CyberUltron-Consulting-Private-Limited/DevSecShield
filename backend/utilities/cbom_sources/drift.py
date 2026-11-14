"""Diff, drift and proof that fixes landed: one comparison for collection runs and for code scans.

Rules (WP10 / plan C2):

* Only collections in which EVERY TARGET WAS READ are compared: a collect job that succeeded with outcome ``ok``, or
  ``partial`` only because some targets were read with coverage gaps (``counts.partial``; no failed or skipped
  target). A job with a failed, skipped or unread target, a cancelled or failed job, and one truncated at the asset
  limit are "not compared" with their reason, never a list of removals.
* Coverage gaps (``coverage`` rows of the later job, ``job_gaps``) are never read as removals: an asset under a gap's
  ``scope`` (location prefixes within its target; no scope = the whole target, target "" = the whole job) that is
  missing from the later run is listed as ``not_read``, not removed, and its findings are not resolved; under an
  ``incomplete`` gap (the asset is listed, some of its facts were not read) its vanished findings are not resolved
  either. Everything outside the gaps still drifts normally. This also covers the gaps a customer chose (an option
  left off: ``by_choice``), which keep the job ``ok``. ``not_supported`` / ``not_installed`` rows say what a target
  does not have, not what was missed, and hide nothing.
* Identity is stable (``identity``): source uid + asset key; certificates by (target, location, subject, issuer), so a
  renewal is "changed (renewed)"; code-scan rows by a line-independent key within ``repository@branch``.
* Version-aware: a run records the knowledge-base and classifier versions that judged it. When the two sides differ,
  both sides are RE-CLASSIFIED with the current rules (the classifier is deterministic and every input is stored), so
  the lists show what changed in the estate; what changed only because a rule changed is listed apart as
  ``rule_changes`` ("rule change"). Code scans cannot be re-judged (the engine ran in the worker), so a different
  engine version labels every finding change "rule change possible".
* A finding (identity + code) missing from a later complete collection of the same source is RESOLVED in that run or
  scan. The drift events are the one record of it: the run's "Changes", the integrations, and for code scans the
  Mongo finding status and the Jira close-on-fixed (``finding_state.mark_finding_fixed``, shared with the manual
  "fixed" toggle) all read the same comparison.
* A code-scan resolution is recorded (event, Mongo "fixed", Jira close) only when the comparison proves it: the
  baseline is the previous scan of the same repository and branch made with the same scope options
  (``include_vendored``, ``scan_history``, ``scan_binaries``), neither scan was cut short (an uploaded CBOM truncated
  at its component limit is never compared), and the same engine version judged both. A different engine version,
  or an uploaded zip / CBOM file (matched to earlier uploads only by its title), still gets the comparison and its
  "opened" events, labelled, but nothing is marked fixed or resolved.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import re
from dataclasses import dataclass, field, replace
from typing import Any, Iterable, Mapping

from sqlalchemy import update
from sqlmodel import Session, select

from backend.new_models import (
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSource,
    CbomDriftEvent,
    Scan,
)
from backend.utilities.cbom_sources import algid
from backend.utilities.cbom_sources import identity as ID
from backend.utilities.cbom_sources.cbom_metrics import code_row_quantum_vulnerable
from backend.utilities.cbom_sources.cbom_rows import display_row, is_finding
from backend.utilities.cbom_sources.common import iso_z, log

LIST_CAP = 500  # per list in an API diff
EVENT_CAP = 5_000  # drift events recorded per run or scan
EXPIRING_DAYS = 30
FINISHED = ("done", "partial", "failed", "cancelled")
_IMPACT_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
_FIELDS = ("algorithm", "key_size", "protocol", "impact", "quantum_vulnerable", "fingerprint", "not_after")
EVENT_KINDS = ("opened", "resolved", "new_asset", "removed_asset", "cert_renewed", "cert_expiring",
               "schedule_skipped")


@dataclass
class View:
    identity: str
    key: str
    label: str
    asset_type: str
    codes: frozenset[str]
    impact: str | None
    quantum_vulnerable: bool | None
    finding: bool
    judged: bool  # has a quantum verdict (readiness denominator)
    algorithm: str | None = None
    key_size: Any = None
    protocol: str | None = None
    fingerprint: str | None = None
    not_after: str | None = None
    certificate: bool = False
    asset_id: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    # internals, never in ``public()``: the stored rows (the introduced-fact guard re-judges them and reads which
    # facts they carried), and the fact names a carried view may claim (both levels' facts, when codes were carried)
    rows: tuple[Any, ...] = field(default=(), repr=False, compare=False)  # the stored rows (re-judging needs them)
    fact_override: frozenset[str] | None = field(default=None, repr=False, compare=False)

    @property
    def fact_keys(self) -> frozenset[str]:
        """The fact names the stored rows carried (computed only when the introduced-fact guard asks)."""
        if self.fact_override is not None:
            return self.fact_override
        return frozenset(k for row in self.rows for k in (row.facts or {}))

    def public(self) -> dict[str, Any]:
        return {"key": self.key, "label": self.label, "type": self.asset_type, "impact": self.impact,
                "finding_codes": sorted(self.codes), "quantum_vulnerable": self.quantum_vulnerable,
                "asset_id": self.asset_id, **self.extra}


def _worse(a: str | None, b: str | None) -> str | None:
    return min((x for x in (a, b) if x), key=lambda x: _IMPACT_RANK.get(x, 9), default=None)


def _merge(table: dict[str, View], view: View) -> None:
    old = table.get(view.identity)
    if old is None:
        table[view.identity] = view
        return
    old.codes = old.codes | view.codes
    old.impact = _worse(old.impact, view.impact)
    old.finding = old.finding or view.finding
    if old.quantum_vulnerable is not True and view.quantum_vulnerable is not None:
        old.quantum_vulnerable = view.quantum_vulnerable if old.quantum_vulnerable is None else (
            old.quantum_vulnerable or view.quantum_vulnerable)
    old.judged = old.judged or view.judged
    old.rows = old.rows + view.rows
    old.extra["occurrences"] = int(old.extra.get("occurrences", 1)) + int(view.extra.get("occurrences", 1))


# ----------------------------------------------------------------------------- views
def node_views(rows: Iterable[CbomCollectedAsset], source_ref: str, *, reclassify: bool) -> dict[str, View]:
    """Views of one collect job's assets; ``reclassify`` re-judges them with the current classifier (as of each
    asset's own collection time, so certificate expiry is still "as of the run")."""
    from backend.utilities.cbom_sources.classify import classify
    from backend.utilities.cbom_sources.posture import JUDGED_CLASSES, classify_pqc

    out: dict[str, View] = {}
    for row in rows:
        if row.asset_type == "coverage":
            continue
        codes, impact, qv = list(row.finding_codes or []), row.impact, row.quantum_vulnerable
        if reclassify:
            try:
                verdict = classify(row.asset_type, row.algorithm, row.key_size, row.protocol, row.facts or {},
                                   row.created_at)
                codes, impact, qv = verdict["finding_codes"], verdict["impact"], verdict["quantum_vulnerable"]
            except Exception:  # an asset the current rules cannot read keeps its stored verdict
                pass
        clean = frozenset(c for c in codes if isinstance(c, str) and c and not c.startswith("COVERAGE_"))
        facts = row.facts or {}
        ident = ID.node_identity(row)
        # the one class function, on the (re-judged) verdict; per job, so no read-elsewhere rule here: an unknown
        # row and a not-applicable one are both outside the readiness denominator, so readiness is the same
        cls, basis = classify_pqc(row, sorted(clean), quantum_vulnerable=qv)
        cert = ID.is_certificate(row)
        _merge(out, View(
            identity=ident, key=ID.stable_key("node", source_ref, ident), label=ID.node_label(row),
            asset_type=row.asset_type, codes=clean, impact=impact if clean or impact else None,
            quantum_vulnerable=qv, finding=bool(clean), judged=cls in JUDGED_CLASSES,
            # an OID or a cloud enum compares as its canonical name: a node upgrade that names an algorithm it used
            # to report as an OID is not a change (S-2); any other text compares as stored
            algorithm=algid.compare_key(row.algorithm), key_size=row.key_size, protocol=row.protocol,
            fingerprint=(str(facts.get("fingerprint_sha256")) if cert and facts.get("fingerprint_sha256") else None),
            not_after=(str(facts.get("not_after")) if cert and facts.get("not_after") else None),
            certificate=cert, asset_id=row.id,
            extra={"target": row.target, "location": row.location, "pqc_class": cls, "pqc_class_basis": basis},
            rows=(row,),
        ))
    return out


def code_views(rows: Iterable[Any], source_ref: str) -> dict[str, View]:
    out: dict[str, View] = {}
    for raw in rows:
        if not isinstance(raw, dict):
            continue
        row = display_row(raw)
        finding = is_finding(row)
        if "finding_codes" in row:
            codes = frozenset(c for c in row.get("finding_codes") or [] if isinstance(c, str) and c)
        else:
            codes = frozenset({"FINDING"}) if finding else frozenset()  # legacy rows: one finding, no code
        if finding and not codes:
            codes = frozenset({"WEAK_OR_QUANTUM_VULNERABLE"})
        qv = code_row_quantum_vulnerable(row)
        # the stored row, not display_row's copy: the roll-up and the Mongo "fixed" marking read the stored row too
        # (display_row retypes legacy library / configuration rows, which would give them another identity)
        ident = ID.code_identity(raw)
        cert = str(row.get("asset_type") or row.get("algorithm_type") or "") == "certificate"
        _merge(out, View(
            identity=ident, key=ID.stable_key("code", source_ref, ident), label=ID.code_label(row),
            asset_type=str(row.get("asset_type") or row.get("algorithm_type") or "other"), codes=codes,
            impact=(str(row.get("impact") or "Low") if finding else None), quantum_vulnerable=qv, finding=finding,
            judged=qv is not None, algorithm=row.get("algorithm_name") or row.get("title"),
            key_size=row.get("key_size"), protocol=row.get("protocol_version"),
            not_after=(str(row.get("not_valid_after")) if cert and row.get("not_valid_after") else None),
            certificate=cert,
            extra={"location": row.get("location"), "bom_ref": row.get("bom_ref"),
                   "occurrences": int(row.get("occurrence_count") or 1)},
        ))
    return out


@dataclass(frozen=True)
class Gap:
    """What one coverage row of a job says was not read (see the module docstring)."""
    target: str  # "" = every target of the job
    prefixes: tuple[str, ...]  # () = the whole target
    incomplete: bool  # assets under it may be listed with facts missing
    types: tuple[str, ...] = ()  # () = every asset type; else only these types (node checks, NODE_CHECK_TYPES)
    reason: str | None = None  # the coverage row's detail, shown with what it left "not read"
    by_choice: bool = False  # an option the customer left off: hides its assets, but nothing is carried past it

    def covers(self, view: View, *, listed: bool) -> bool:
        if listed and not self.incomplete:
            return False
        target, location = str(view.extra.get("target") or ""), str(view.extra.get("location") or "")
        if self.target and self.target != target:
            return False
        if self.types and view.asset_type not in self.types:
            return False
        # a prefix that starts with "#" names a part of the location anywhere in it (no location starts with "#"):
        # a job-wide gap scoped ["#sni="] covers every certificate read with an SNI name, on any endpoint
        return not self.prefixes or any(p in location if p.startswith("#") else location.startswith(p)
                                        for p in self.prefixes)


NOT_GAPS = ("not_supported", "not_installed")  # what a target does not have, not what was missed

# Scan-node coverage rows carry no location scope, so on their own they would hide every asset of their host from
# removal and resolution, and a host with one persistent gap (sudo denied for process maps, a root-only key) would
# never drift again (AWS lab, round 5: the host agent's first run had two such rows).  Each check below can only
# have missed assets of these types; a check not listed still covers the whole target.  ``True``: the assets are
# still listed with facts missing (their findings may be incomplete), so vanished findings are not resolved either.
_KEYS = ("private_key", "public_key", "certificate", "keystore", "key_store", "ssh_host_key")
_DB = ("database_config", "database_tls", "database_user_auth", "db_crypto_policy", "db_login_policy", "db_encryption")
NODE_CHECK_TYPES: tuple[tuple[re.Pattern[str], tuple[str, ...], bool], ...] = (
    (re.compile(r"^key and certificate files\b"), _KEYS, False),
    (re.compile(r"^process crypto libraries\b"), ("process_library",), False),
    (re.compile(r"^package list\b"), ("crypto_library",), False),
    (re.compile(r"^sshd configuration\b"), ("ssh_server_config",), True),
    (re.compile(r"^(postgres|mysql|mssql|oracle|redis|mongodb)\b"), _DB, True),
    (re.compile(r"^AD CS template"), ("ca_template",), True),
    (re.compile(r"^(Certificate stores|TLS secrets|cert-manager certificates)\b"), ("certificate",), False),
)


def _node_check_types(check: str) -> tuple[tuple[str, ...], bool] | None:
    for pattern, types, incomplete in NODE_CHECK_TYPES:
        if pattern.search(check):
            return types, incomplete
    return None


def job_gaps(rows: Iterable[CbomCollectedAsset]) -> list[Gap]:
    """The coverage gaps of one job attempt's rows."""
    out: list[Gap] = []
    for row in rows:
        if row.asset_type != "coverage":
            continue
        facts = row.facts or {}
        if str(facts.get("status") or "") in NOT_GAPS:
            continue
        reason = _gap_reason(facts)
        scope = facts.get("scope")
        prefixes = tuple(p for p in scope if isinstance(p, str) and p) if isinstance(scope, list) else ()
        typed = None if prefixes or "scope" in facts else _node_check_types(str(facts.get("check") or ""))
        if typed is not None:
            out.append(Gap(target=str(row.target or ""), prefixes=(), incomplete=typed[1], types=typed[0],
                           reason=reason, by_choice=bool(facts.get("by_choice"))))
            continue
        # no scope: nothing says which assets the gap left out, so it covers its whole target, listed ones included
        out.append(Gap(target=str(row.target or ""), prefixes=prefixes,
                       incomplete=bool(facts.get("incomplete")) or not prefixes, reason=reason,
                       by_choice=bool(facts.get("by_choice"))))
    return out


def _gap_reason(facts: Mapping[str, Any]) -> str | None:
    """Why the gap's assets were not read: the coverage row's detail ("172.31.67.4 did not answer on any listed port
    ..."), else its check and status."""
    detail = str(facts.get("detail") or "").strip()
    if detail:
        return detail[:300]
    check, status = str(facts.get("check") or "").strip(), str(facts.get("status") or "").strip()
    return ": ".join(p for p in (check, status) if p)[:300] or None


def _gap_for(view: View, gaps: list[Gap], *, listed: bool) -> Gap | None:
    return next((g for g in gaps if g.covers(view, listed=listed)), None)


def readiness(views: Mapping[str, View]) -> float | None:
    """Readiness of one side, by the posture card's rule (``posture.readiness``): withheld when more assets are
    ``unknown`` than judged."""
    from backend.utilities.cbom_sources.posture import readiness_pct

    judged = [v for v in views.values() if v.judged]
    unknown = sum(1 for v in views.values() if not v.judged and v.extra.get("pqc_class") == "unknown")
    return readiness_pct(sum(1 for v in judged if v.quantum_vulnerable is True), len(judged), unknown)


# ----------------------------------------------------------------------------- compare
def compare(before: Mapping[str, View], after: Mapping[str, View], gaps: Iterable[Gap] = ()
            ) -> dict[str, list[dict[str, Any]]]:
    """added / removed / changed assets and opened / resolved findings (identity + code). ``gaps``: the later side's
    coverage gaps; what they cover is ``not_read`` (with the findings that could not be confirmed), never removed or
    resolved."""
    gaps = list(gaps)
    added = [after[i] for i in sorted(after) if i not in before]
    gone = [before[i] for i in sorted(before) if i not in after]
    removed = [v for v in gone if _gap_for(v, gaps, listed=False) is None]
    # "reason": the covering coverage row's detail, so a list of what was not read says why (lab UI r1 F2)
    not_read: list[dict[str, Any]] = [
        {**v.public(), "asset_removed": True, "codes": sorted(v.codes), "reason": gap.reason}
        for v in gone if (gap := _gap_for(v, gaps, listed=False)) is not None]
    changed: list[dict[str, Any]] = []
    opened: list[dict[str, Any]] = []
    resolved: list[dict[str, Any]] = []
    collector_changes: list[dict[str, Any]] = []
    for ident in sorted(before.keys() & after.keys()):
        b, a = before[ident], after[ident]
        fields = {f: [getattr(b, f), getattr(a, f)] for f in _FIELDS if getattr(b, f) != getattr(a, f)}
        if b.codes != a.codes:
            fields["finding_codes"] = [sorted(b.codes), sorted(a.codes)]
        renewed = a.certificate and bool(
            (b.fingerprint and a.fingerprint and b.fingerprint != a.fingerprint)
            or (b.not_after and a.not_after and a.not_after > b.not_after))
        if fields:
            changed.append({**a.public(), "changes": fields, "renewed": renewed})
        for code in sorted(a.codes - b.codes):
            opened.append({**a.public(), "code": code})
        vanished = sorted(b.codes - a.codes)
        gap = _gap_for(b, gaps, listed=True) if vanished else None
        if gap is not None:
            not_read.append({**b.public(), "asset_removed": False, "codes": vanished, "reason": gap.reason})
            continue
        explained, facts = _introduced_explains(b, a, vanished) if vanished else (frozenset(), ())
        for code in vanished:
            if code in explained:
                collector_changes.append({**a.public(), "code": code, "direction": "resolved",
                                          "label_change": "collector change", "facts": list(facts)})
            else:
                resolved.append({**b.public(), "code": code, "asset_removed": False})
    for view in added:
        for code in sorted(view.codes):
            opened.append({**view.public(), "code": code, "new_asset": True})
    for view in removed:
        for code in sorted(view.codes):
            resolved.append({**view.public(), "code": code, "asset_removed": True})
    return {"added": [v.public() for v in added], "removed": [v.public() for v in removed], "changed": changed,
            "opened": opened, "resolved": resolved, "not_read": not_read, "collector_changes": collector_changes}


# Facts a collector started sending after rows without them were stored (CB-33: the ACM ``exported`` flag and the
# certificate ``key_pair_origin``).  A rule that withdraws a finding on such a fact would read the first run carrying
# it as "resolved" against a baseline that never had it, although only the collector changed (CB-33 DA RC-5, X1).  A
# rule that suppresses an AWS finding on a fact the collector did not send before CB-33 must list the fact here
# (tests/test_cbom_drift_last_known.py fails otherwise).
INTRODUCED_FACTS = frozenset({"exported", "key_pair_origin"})


def _introduced_explains(before: View, after: View, vanished: list[str]) -> tuple[frozenset[str], tuple[str, ...]]:
    """The vanished codes that only a newly sent fact explains, and those facts. The later rows are re-judged without
    the introduced facts their baseline lacked; a code that comes back vanished because the collector changed, not
    the estate (``collector_changes``, no event). Nothing when no introduced fact is new."""
    from backend.utilities.cbom_sources.classify import classify

    new = tuple(sorted((after.fact_keys - before.fact_keys) & INTRODUCED_FACTS))
    if not new or not after.rows:
        return frozenset(), ()
    back: set[str] = set()
    for row in after.rows:
        try:
            verdict = classify(row.asset_type, row.algorithm, row.key_size, row.protocol,
                               {k: v for k, v in (row.facts or {}).items() if k not in new}, row.created_at)
        except Exception:  # a row the current rules cannot read is not guarded: it drifts as before
            continue
        back.update(c for c in verdict["finding_codes"] if isinstance(c, str))
    return frozenset(back) & frozenset(vanished), new


def _finding_pairs(diff: Mapping[str, list[dict[str, Any]]]) -> set[tuple[str, str, str]]:
    return ({("opened", d["key"], d["code"]) for d in diff["opened"]}
            | {("resolved", d["key"], d["code"]) for d in diff["resolved"]})


def rule_only_changes(stored: Mapping[str, list[dict[str, Any]]], current: Mapping[str, list[dict[str, Any]]]
                      ) -> list[dict[str, Any]]:
    """Finding changes that appear with the verdicts as stored but not when both sides are judged by the current
    rules (or the other way round): a rule changed, the estate did not."""
    s, c = _finding_pairs(stored), _finding_pairs(current)
    lookup = {(k, d["key"], d["code"]): d for k in ("opened", "resolved") for d in stored[k]}
    lookup.update({(k, d["key"], d["code"]): d for k in ("opened", "resolved") for d in current[k]})
    out = []
    for item in sorted(s ^ c):
        d = lookup[item]
        out.append({"key": d["key"], "label": d["label"], "code": d["code"], "direction": item[0],
                    "label_change": "rule change",
                    "seen_with": "stored verdicts" if item in s else "current rules"})
    return out


def _cap(items: list[Any]) -> tuple[list[Any], bool]:
    return items[:LIST_CAP], len(items) > LIST_CAP


# ----------------------------------------------------------------------------- collection runs
def job_comparable(job: CbomCollectionJob) -> tuple[bool, str | None]:
    if job.kind != "collect":
        return False, "not a collection job"
    if job.status != "success":
        return False, f"collection {job.status}"
    result = job.result if isinstance(job.result, dict) else {}
    if result.get("truncated"):
        return False, "collection truncated at the asset limit"
    if job.outcome == "ok":
        return True, None
    counts = result.get("counts") if isinstance(result.get("counts"), dict) else {}

    def count(name: str) -> int:
        value = counts.get(name)
        return value if isinstance(value, int) and not isinstance(value, bool) else 0

    if (job.outcome == "partial" and count("partial") > 0 and count("failed") == 0 and count("skipped") == 0
            and not result.get("asset_mismatch")):
        return True, None  # every target was read; what was not is in its coverage gaps, which never read as removals
    return False, f"collection {job.outcome or 'incomplete'} (some targets were not read)"


def _versions(run: CbomCollectionRun | None) -> dict[str, Any]:
    if run is None:
        return {}
    return {"kb_version": run.kb_version, "classifier_version": run.classifier_version,
            "engine_version": run.engine_version}


def runs_rules_differ(a: CbomCollectionRun | None, b: CbomCollectionRun | None) -> bool:
    """Whether the knowledge base or the classifier that judged the two runs differ from each other (unknown counts as
    different). This is what a comparison reports as "rules changed"; two runs judged by the same older rules do not
    differ, even though ``rules_differ`` re-judges them both."""
    va, vb = _versions(a), _versions(b)
    return any(va.get(k) is None or va.get(k) != vb.get(k) for k in ("kb_version", "classifier_version"))


def rules_differ(a: CbomCollectionRun | None, b: CbomCollectionRun | None) -> bool:
    """Whether the two runs must be re-judged before they are compared: the knowledge base or the classifier that
    judged them differ (``runs_rules_differ``), or either one was judged by rules other than the current ones.
    The second case covers a run created before a deploy and ingested after it (its label is the old rules' while its
    assets were judged by the new ones), so both sides are always compared by the same, current, rules (ST-1)."""
    from backend.utilities.cbom_sources import crypto_kb
    from backend.utilities.cbom_sources.classify import CLASSIFIER_VERSION

    if runs_rules_differ(a, b):
        return True
    va, vb = _versions(a), _versions(b)
    current = {"kb_version": crypto_kb.version(), "classifier_version": CLASSIFIER_VERSION}
    return any(side.get(k) != current[k] for side in (va, vb) for k in current)


def _job_assets(session: Session, job: CbomCollectionJob) -> list[CbomCollectedAsset]:
    return list(session.exec(select(CbomCollectedAsset).where(
        CbomCollectedAsset.team_id == job.team_id, CbomCollectedAsset.job_id == job.id,
        CbomCollectedAsset.attempt == job.attempts)).all())


def _run_jobs(session: Session, run: CbomCollectionRun) -> list[CbomCollectionJob]:
    return list(session.exec(select(CbomCollectionJob).where(
        CbomCollectionJob.team_id == run.team_id, CbomCollectionJob.run_id == run.id,
        CbomCollectionJob.kind == "collect").order_by(CbomCollectionJob.id)).all())


def _sources(session: Session, team_id: int) -> dict[int, CbomCollectionSource]:
    return {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id)).all()}


def previous_comparable_run(session: Session, run: CbomCollectionRun) -> CbomCollectionRun | None:
    """The newest earlier run of the team with a complete collection of at least one source this run collected
    completely."""
    sources = _sources(session, run.team_id)
    mine = {ID.job_source_ref(j, sources.get(j.source_id or 0)) for j in _run_jobs(session, run)
            if job_comparable(j)[0]}
    if not mine:
        return None
    earlier = session.exec(select(CbomCollectionRun).where(
        CbomCollectionRun.team_id == run.team_id, CbomCollectionRun.id < run.id)
        .order_by(CbomCollectionRun.id.desc()).limit(50)).all()  # type: ignore[union-attr]
    for other in earlier:
        refs = {ID.job_source_ref(j, sources.get(j.source_id or 0)) for j in _run_jobs(session, other)
                if job_comparable(j)[0]}
        if refs & mine:
            return other
    return None


# ----------------------------------------------------------------------------- last-known baseline
# The baseline of a comparison is the LAST KNOWN state of each asset (CB-33 DA RC-4): the baseline job's views, plus
# what that job's real gaps left unread, carried from the newest earlier comparable job that read it.  The walk is
# bounded: at most CARRY_LEVELS jobs, and an older job is read only for the rows the baseline job's gaps could cover
# (filtered in SQL) plus its own coverage rows, one job at a time.  An asset still unread after CARRY_LEVELS jobs is
# no longer carried: it drops out of "not read" with no event (dev drops it after one run; follow-up on #126).
CARRY_LEVELS = 20  # comparable jobs (the baseline job included) a baseline may reach back through, past real gaps


@dataclass
class _Level:
    """One comparable job of a source's history, as a baseline level (only the rows the walk needs)."""
    job: CbomCollectionJob
    run: CbomCollectionRun | None
    rows: list[CbomCollectedAsset]
    gaps: list[Gap]  # its real gaps (not ``by_choice``): only these carry anything from older jobs


@dataclass
class _Carry:
    """The last-known baseline views (``views``; ``stored``: the same, every level with its stored verdicts, built only
    when asked) and whether any carried view came from a level re-judged with the current rules."""
    views: dict[str, View]
    stored: dict[str, View] | None = None
    rejudged: bool = False


def _level(session: Session, job: CbomCollectionJob, rows: list[CbomCollectedAsset] | None = None) -> _Level:
    rows = _job_assets(session, job) if rows is None else rows
    return _Level(job=job, run=session.get(CbomCollectionRun, job.run_id) if job.run_id else None, rows=rows,
                  gaps=[g for g in job_gaps(rows) if not g.by_choice])


def _like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _candidates(gaps: list[Gap]):
    """A SQL condition matching every asset row one of ``gaps`` could cover (its target, types and location prefixes;
    a ``#`` prefix anywhere in the location), or None when a gap covers the whole job."""
    from sqlalchemy import and_, or_

    clauses = []
    for gap in gaps:
        parts = []
        if gap.target:
            parts.append(CbomCollectedAsset.target == gap.target)
        if gap.types:
            parts.append(CbomCollectedAsset.asset_type.in_(gap.types))  # type: ignore[attr-defined]
        if gap.prefixes:
            parts.append(or_(*[CbomCollectedAsset.location.like(  # type: ignore[attr-defined]
                ("%" + _like(p) + "%") if p.startswith("#") else (_like(p) + "%"), escape="\\") for p in gap.prefixes]))
        if not parts:
            return None
        clauses.append(and_(*parts))
    return or_(*clauses)


def _older_jobs(session: Session, base: CbomCollectionJob, ref: str,
                sources: Mapping[int, CbomCollectionSource], limit: int) -> list[CbomCollectionJob]:
    """Up to ``limit`` comparable jobs of the same source before ``base``, newest first (one query)."""
    if base.source_id is None or limit <= 0:
        return []
    out = []
    for other in session.exec(select(CbomCollectionJob).where(
            CbomCollectionJob.team_id == base.team_id, CbomCollectionJob.kind == "collect",
            CbomCollectionJob.source_id == base.source_id, CbomCollectionJob.status == "success",
            CbomCollectionJob.id < base.id).order_by(CbomCollectionJob.id.desc()).limit(limit * 2)).all():  # type: ignore[union-attr]
        if job_comparable(other)[0] and ID.job_source_ref(other, sources.get(other.source_id or 0)) == ref:
            out.append(other)
            if len(out) == limit:
                break
    return out


def _level_rows(session: Session, jobs: list[CbomCollectionJob], cond) -> dict[int, list[CbomCollectedAsset]]:
    """The older levels' rows the walk can use, in one query: each job's coverage rows and the rows ``cond``
    matches (never whole jobs: review #132 blocker), grouped by job."""
    from sqlalchemy import or_

    if not jobs:
        return {}
    attempts = {j.id: j.attempts for j in jobs}
    query = select(CbomCollectedAsset).where(
        CbomCollectedAsset.team_id == jobs[0].team_id,
        CbomCollectedAsset.job_id.in_(list(attempts)))  # type: ignore[attr-defined]
    if cond is not None:
        query = query.where(or_(CbomCollectedAsset.asset_type == "coverage", cond))
    out: dict[int, list[CbomCollectedAsset]] = {j: [] for j in attempts}
    for row in session.exec(query).all():
        if row.attempt == attempts.get(row.job_id):
            out[row.job_id].append(row)
    return out


def _overlap(a: Gap, b: Gap) -> bool:
    """Whether some asset could be covered by both gaps (conservative: True when unsure)."""
    if a.target and b.target and a.target != b.target:
        return False
    if a.types and b.types and not set(a.types) & set(b.types):
        return False
    if not a.prefixes or not b.prefixes or any(p.startswith("#") for p in a.prefixes + b.prefixes):
        return True
    return any(p.startswith(q) or q.startswith(p) for p in a.prefixes for q in b.prefixes)


class _State:
    """The walk's state for one way of judging the levels (current rules, or stored verdicts)."""

    def __init__(self, out: dict[str, View], gaps: list[Gap]):
        self.out = out
        self.known = set(out)
        self.pending = {i for i, v in out.items() if _gap_for(v, gaps, listed=True) is not None}
        self.rejudged = False

    def absorb(self, level: _Level, views: dict[str, View], chain: list[list[Gap]], judged: bool) -> None:
        run_id = level.job.run_id
        for ident, view in views.items():
            if ident in self.pending:
                old = self.out[ident]
                codes = old.codes | view.codes
                # the facts both levels had: a fact the older, code-bearing level lacked still counts as introduced
                self.out[ident] = replace(old, codes=codes, impact=_worse(old.impact, view.impact), finding=bool(codes),
                                          fact_override=old.fact_keys & view.fact_keys)
                self.rejudged = self.rejudged or (judged and bool(view.codes - old.codes))
                if _gap_for(view, level.gaps, listed=True) is None:
                    self.pending.discard(ident)  # read fully here: its codes are known from this level on
            elif ident not in self.known:
                self.known.add(ident)
                if all(_gap_for(view, gaps, listed=False) is not None for gaps in chain):
                    # the run that last read it: events and "not read" name it (a BOM-Link must point into it)
                    view.extra["last_read_run_id"] = run_id
                    self.out[ident] = view
                    self.rejudged = self.rejudged or judged
                    if _gap_for(view, level.gaps, listed=True) is not None:
                        self.pending.add(ident)
        for ident in [i for i in self.pending if i not in views]:
            if _gap_for(self.out[ident], level.gaps, listed=False) is None:
                self.pending.discard(ident)  # read here and absent: nothing older is its last known state


def _carried(session: Session, base: CbomCollectionJob, ref: str, sources: Mapping[int, CbomCollectionSource],
             judge, *, stored: bool = False, later: Mapping[str, View] | None = None) -> _Carry:
    """The last-known baseline (see above).

    * An identity absent from the baseline job under its gaps is carried from the newest older job that has it, if
      every newer level's gaps cover it too (one level that read the place without it means it was really gone).
    * A listed identity under an incomplete gap keeps the codes the older levels saw, up to the first one that read
      it fully.
    * Each level is judged by ``judge(level)`` (re-judged with the current rules when its run's rules differ from the
      compared run's, DA-2b); ``stored`` also builds the views with every level's stored verdicts (rule changes).
    * The walk goes on only while the last level has a real gap (never past a ``by_choice`` one, DA-2c), that gap can
      share an asset with the baseline job's gaps or something is pending, and for at most CARRY_LEVELS jobs.
    * When a gap outlasts CARRY_LEVELS jobs (a key pending deletion for 30 days, a key policy that always denies the
      reader), the identities that still matter are looked up further back by asset key only (``_deep``): those still
      pending, and those of ``later`` (the compared run's views) the baseline lacks.  So a finding that was never
      resolved is never opened again when its asset is read again (#136 review)."""
    first = _level(session, base)
    judged = judge(first)
    states = [(_State(node_views(first.rows, ref, reclassify=judged), first.gaps), judge)]
    if stored:
        states.append((_State(node_views(first.rows, ref, reclassify=False), first.gaps), _not_judged))
    base_gaps = first.gaps
    if base_gaps:
        jobs = _older_jobs(session, base, ref, sources, CARRY_LEVELS - 1)
        rows = _level_rows(session, jobs, _candidates(base_gaps))
        chain: list[list[Gap]] = [base_gaps]
        exhausted = len(jobs) == CARRY_LEVELS - 1
        for older in jobs:
            level = _level(session, older, rows.pop(older.id, []))
            for state, how in states:
                judged = how(level)
                state.absorb(level, node_views(level.rows, ref, reclassify=judged), chain, judged)
            chain.append(level.gaps)
            if not level.gaps or (not any(s.pending for s, _h in states)
                                  and not any(_overlap(g, h) for g in level.gaps for h in base_gaps)):
                exhausted = False  # nothing older can carry: the walk ended on its own
                break
        if exhausted:
            _deep(session, jobs[-1], ref, sources, states, chain, later or {})
    main = states[0][0]
    return _Carry(views=main.out, stored=states[1][0].out if stored else None,
                  rejudged=judge(first) or main.rejudged)


DEEP_JOBS = 500  # comparable jobs searched by asset key past CARRY_LEVELS (indexed: job id + asset key)


def _deep(session: Session, last: CbomCollectionJob, ref: str, sources: Mapping[int, CbomCollectionSource],
          states: list, chain: list[list[Gap]], later: Mapping[str, View]) -> None:
    """Past CARRY_LEVELS: the identities still pending, and the later run's identities the baseline lacks that every
    level so far left unread, looked up by asset key in up to DEEP_JOBS older jobs (their rows with those keys and
    their coverage rows only), newest first, with the same rules as the walk."""
    keys: set[str] = set()
    for state, _how in states:
        keys.update(r.asset_key for i in state.pending for r in state.out[i].rows)
        keys.update(r.asset_key for i, v in later.items() if i not in state.known
                    and all(_gap_for(v, gaps, listed=False) is not None for gaps in chain) for r in v.rows)
    if not keys:
        return
    jobs = _older_jobs(session, last, ref, sources, DEEP_JOBS)
    if not jobs:
        return
    attempts = {j.id: j.attempts for j in jobs}
    found: dict[int, list[CbomCollectedAsset]] = {j: [] for j in attempts}
    from sqlalchemy import or_

    for row in session.exec(select(CbomCollectedAsset).where(
            CbomCollectedAsset.team_id == last.team_id,
            CbomCollectedAsset.job_id.in_(list(attempts)),  # type: ignore[attr-defined]
            or_(CbomCollectedAsset.asset_type == "coverage",
                CbomCollectedAsset.asset_key.in_(sorted(keys))))).all():  # type: ignore[attr-defined]
        if row.attempt == attempts.get(row.job_id):
            found[row.job_id].append(row)
    wanted = {i for i, v in later.items() if any(r.asset_key in keys for r in v.rows)}
    for older in jobs:
        level = _level(session, older, found.pop(older.id, []))
        for state, how in states:
            judged = how(level)
            state.absorb(level, node_views(level.rows, ref, reclassify=judged), chain, judged)
        chain.append(level.gaps)
        wanted = {i for i in wanted if i not in states[0][0].known
                  and _gap_for(later[i], level.gaps, listed=False) is not None}
        if not wanted and not any(s.pending for s, _h in states):
            break


def _judge(run: CbomCollectionRun):
    """Each baseline level is re-judged with the current rules when its run's rules differ from ``run``'s (ST-1)."""
    return lambda level: rules_differ(level.run, run)


def _not_judged(_level: _Level) -> bool:
    return False


def _after_for_readiness(before: Mapping[str, View], after: Mapping[str, View], gaps: list[Gap]) -> dict[str, View]:
    """The later side as readiness counts it: an asset its gaps left unread keeps its last known verdict (an unread
    key does not move readiness)."""
    out = dict(after)
    for ident, view in before.items():
        if ident not in out and _gap_for(view, gaps, listed=False) is not None:
            out[ident] = view
    return out


def run_diff(session: Session, run: CbomCollectionRun, base: CbomCollectionRun) -> dict[str, Any]:
    """Compare ``base`` (before) with ``run`` (after), source by source; only sources complete in both are compared."""
    sources = _sources(session, run.team_id)
    reclassify = rules_differ(base, run)
    sides: dict[str, dict[str, CbomCollectionJob]] = {"before": {}, "after": {}}
    names: dict[str, str] = {}
    for side, which in (("before", base), ("after", run)):
        for job in _run_jobs(session, which):
            src = sources.get(job.source_id or 0)
            ref = ID.job_source_ref(job, src)
            names.setdefault(ref, ID.job_source_name(job, src))
            sides[side][ref] = job
    per_source: list[dict[str, Any]] = []
    totals: dict[str, list[Any]] = {k: [] for k in ("added", "removed", "changed", "opened", "resolved", "not_read",
                                                   "collector_changes")}
    rule_changes: list[dict[str, Any]] = []
    before_all: dict[str, View] = {}
    after_all: dict[str, View] = {}
    rejudged_any, carried_unread = reclassify, 0
    for ref in sorted(set(sides["before"]) | set(sides["after"]), key=lambda r: names.get(r, r)):
        b_job, a_job = sides["before"].get(ref), sides["after"].get(ref)
        entry: dict[str, Any] = {"source_ref": ref, "name": names.get(ref), "status": "not_compared", "reason": None}
        if b_job is None or a_job is None:
            entry["reason"] = f"not collected in run #{(base if b_job is None else run).id}"
            per_source.append(entry)
            continue
        ok_b, why_b = job_comparable(b_job)
        ok_a, why_a = job_comparable(a_job)
        if not (ok_b and ok_a):
            entry["reason"] = (f"run #{base.id}: {why_b}" if not ok_b else f"run #{run.id}: {why_a}")
            per_source.append(entry)
            continue
        # the before side is the last known state (the same baseline the drift events use, DA-2a)
        a_rows = _job_assets(session, a_job)
        after = node_views(a_rows, ref, reclassify=reclassify)
        carry = _carried(session, b_job, ref, sources, _judge(run), stored=reclassify, later=after)
        if carry.rejudged and carry.stored is None:  # only a carried older level was re-judged (rare): walk again
            carry = _carried(session, b_job, ref, sources, _judge(run), stored=True, later=after)
        before = carry.views
        gaps = job_gaps(a_rows)
        diff = compare(before, after, gaps)
        if reclassify or carry.rejudged:  # also when only a carried older level was re-judged (review #132 nit)
            rejudged_any = rejudged_any or carry.rejudged
            stored = compare(carry.stored or {}, node_views(a_rows, ref, reclassify=False), gaps)
            rule_changes += [{**r, "source_name": names.get(ref)} for r in rule_only_changes(stored, diff)]
        for k in totals:
            totals[k] += [{**d, "source_name": names.get(ref)} for d in diff[k]]
        before_all.update({f"{ref}|{i}": v for i, v in before.items()})
        counted = _after_for_readiness(before, after, gaps)
        carried_unread += len(counted) - len(after)
        after_all.update({f"{ref}|{i}": v for i, v in counted.items()})
        entry.update(status="compared", reason=None, counts={k: len(v) for k, v in diff.items()},
                     before_job_id=b_job.id, after_job_id=a_job.id)
        per_source.append(entry)
    out: dict[str, Any] = {"run_id": run.id, "against_run_id": base.id,
                           "versions": {"before": _versions(base), "after": _versions(run),
                                        # the runs' own rules differ, and whether both were re-judged with the
                                        # current rules (also when two runs share older rules: ST-1)
                                        "rules_changed": runs_rules_differ(base, run), "reclassified": rejudged_any},
                           "sources": per_source}
    truncated = False
    for k, items in totals.items():
        out[k], cut = _cap(items)
        truncated = truncated or cut
    out["rule_changes"], cut = _cap(rule_changes)
    out["counts"] = {**{k: len(v) for k, v in totals.items()}, "rule_changes": len(rule_changes),
                     "compared_sources": sum(1 for s in per_source if s["status"] == "compared"),
                     "not_compared_sources": sum(1 for s in per_source if s["status"] != "compared")}
    rb, ra = readiness(before_all), readiness(after_all)
    out["readiness"] = {"before": rb, "after": ra,
                        "delta": None if rb is None or ra is None else round(ra - rb, 1),
                        "scope": "compared sources only",
                        # unread assets counted at their last known verdict on the "after" side (the run's own
                        # posture counts only what it read)
                        "carried_unread": carried_unread}
    out["truncated"] = truncated or cut
    return out


# ----------------------------------------------------------------------------- events
def dedupe(*parts: Any) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode("utf-8", "replace")).hexdigest()


def insert_events(session: Session, rows: list[dict[str, Any]]) -> int:
    """INSERT ... ON CONFLICT (team_id, dedupe_key) DO NOTHING: recording the same change twice stores it once."""
    if not rows:
        return 0
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as dialect_insert
    else:
        from sqlalchemy.dialects.sqlite import insert as dialect_insert
    total = 0
    for start in range(0, len(rows), 500):
        stmt = dialect_insert(CbomDriftEvent.__table__).values(rows[start:start + 500]).on_conflict_do_nothing(
            index_elements=["team_id", "dedupe_key"])
        total += int(session.exec(stmt).rowcount or 0)  # type: ignore[call-overload]
    return total


def _event(team_id: int, now: _dt.datetime, kind: str, item: Mapping[str, Any] | None, *, scope: str,
           source_ref: str, source_name: str | None, key_parts: tuple[Any, ...], **links: Any) -> dict[str, Any]:
    item = item or {}
    detail = {k: v for k, v in item.items() if k in ("finding_codes", "type", "location", "target", "changes",
                                                       "asset_removed", "new_asset", "not_after", "asset_id",
                                                       "bom_ref", "rule_change", "reason", "cause", "last_read_run_id")}
    return {"team_id": team_id, "at": now, "scope": scope, "kind": kind,
            "run_id": links.get("run_id"), "baseline_run_id": links.get("baseline_run_id"),
            "scan_id": links.get("scan_id"), "baseline_scan_id": links.get("baseline_scan_id"),
            "source_ref": (source_ref or "")[:255], "source_name": (source_name or None) and source_name[:255],
            "asset_key": item.get("key"), "asset_label": (item.get("label") or None) and str(item["label"])[:255],
            "code": (item.get("code") or None) and str(item["code"])[:48], "severity": item.get("impact"),
            "detail": detail, "dedupe_key": dedupe(scope, *key_parts), "forwarded_at": None}


def diff_events(team_id: int, now: _dt.datetime, diff: Mapping[str, list[dict[str, Any]]], *, scope: str,
                source_ref: str, source_name: str | None, anchor: str, cause: str | None = None,
                **links: Any) -> list[dict[str, Any]]:
    """Events for one source's comparison. ``anchor`` ("run:12" / "scan:40") makes them idempotent per run."""
    out: list[dict[str, Any]] = []

    def add(kind: str, item: Mapping[str, Any], *extra: Any) -> None:
        payload = {**item, "cause": cause} if cause else dict(item)
        # a view carried from an older collection: its baseline is the run that last read it (review #132 major:
        # a BOM-Link built from baseline_run_id + asset_id must point into that run)
        item_links = {**links, "baseline_run_id": item["last_read_run_id"]} if item.get("last_read_run_id") else links
        out.append(_event(team_id, now, kind, payload, scope=scope, source_ref=source_ref, source_name=source_name,
                          key_parts=(anchor, kind, item.get("key"), *extra), **item_links))

    for item in diff["added"]:
        add("new_asset", item)
    for item in diff["removed"]:
        add("removed_asset", item)
    for item in diff["changed"]:
        if item.get("renewed"):
            add("cert_renewed", item)
    for item in diff["opened"]:
        add("opened", item, item["code"])
    for item in diff["resolved"]:
        add("resolved", item, item["code"])
    return out


def _expiring(team_id: int, now: _dt.datetime, views: Mapping[str, View], *, scope: str, source_ref: str,
              source_name: str | None, **links: Any) -> list[dict[str, Any]]:
    """Certificates that expire within EXPIRING_DAYS: once per certificate and expiry date (not once per run)."""
    out = []
    horizon = now + _dt.timedelta(days=EXPIRING_DAYS)
    for view in views.values():
        when = parse_time(view.not_after)
        if not view.certificate or when is None or not (now <= when <= horizon):
            continue
        item = {**view.public(), "not_after": view.not_after}
        out.append(_event(team_id, now, "cert_expiring", item, scope=scope, source_ref=source_ref,
                          source_name=source_name, key_parts=("expiring", view.key, view.not_after), **links))
    return out


def parse_time(value: Any) -> _dt.datetime | None:
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        moment = _dt.datetime.fromisoformat(text)
    except ValueError:
        try:
            moment = _dt.datetime.strptime(str(value).strip(), "%b %d %H:%M:%S %Y %Z")
        except ValueError:
            return None
    if moment.tzinfo is not None:
        moment = moment.astimezone(_dt.timezone.utc).replace(tzinfo=None)
    return moment


def _baseline_job(session: Session, job: CbomCollectionJob, ref: str,
                  sources: Mapping[int, CbomCollectionSource]) -> CbomCollectionJob | None:
    if job.source_id is None:
        return None
    for other in session.exec(select(CbomCollectionJob).where(
            CbomCollectionJob.team_id == job.team_id, CbomCollectionJob.kind == "collect",
            CbomCollectionJob.source_id == job.source_id, CbomCollectionJob.status == "success",
            CbomCollectionJob.id < job.id).order_by(CbomCollectionJob.id.desc()).limit(20)).all():  # type: ignore[union-attr]
        if job_comparable(other)[0] and ID.job_source_ref(other, sources.get(other.source_id or 0)) == ref:
            return other
    return None


def record_run_drift(session: Session, run: CbomCollectionRun, now: _dt.datetime) -> int | None:
    """Record the drift events of a FINISHED run, once (``drift_at`` compare-and-set). The caller commits.
    Returns events stored, or None when the run is not finished or another caller recorded it."""
    if run.status not in FINISHED or run.finished_at is None or run.drift_at is not None:
        return None
    won = session.exec(update(CbomCollectionRun).where(
        CbomCollectionRun.id == run.id, CbomCollectionRun.drift_at.is_(None))  # type: ignore[union-attr]
        .values(drift_at=now)).rowcount == 1
    if not won:
        return None
    sources = _sources(session, run.team_id)
    rows: list[dict[str, Any]] = []
    not_read = 0
    for job in _run_jobs(session, run):
        if not job_comparable(job)[0]:
            continue
        src = sources.get(job.source_id or 0)
        ref, name = ID.job_source_ref(job, src), ID.job_source_name(job, src)
        base = _baseline_job(session, job, ref, sources)
        base_run = session.get(CbomCollectionRun, base.run_id) if base is not None and base.run_id else None
        reclassify = base is not None and rules_differ(base_run, run)
        a_rows = _job_assets(session, job)
        after = node_views(a_rows, ref, reclassify=reclassify)
        rows += _expiring(run.team_id, now, after, scope="node", source_ref=ref, source_name=name, run_id=run.id)
        if base is None:
            continue
        diff = compare(_carried(session, base, ref, sources, _judge(run), later=after).views, after, job_gaps(a_rows))
        not_read += len(diff["not_read"])
        rows += diff_events(run.team_id, now, diff, scope="node", source_ref=ref, source_name=name,
                            anchor=f"run:{run.id}", cause="re-judged with the current rules" if reclassify else None,
                            run_id=run.id, baseline_run_id=base.run_id)
    stored = insert_events(session, rows[:EVENT_CAP])
    log("drift recorded", team=run.team_id, run=run.id, events=stored, not_read=not_read or None,
        truncated=len(rows) > EVENT_CAP or None)
    jobs = _run_jobs(session, run)
    complete = [j for j in jobs if job_comparable(j)[0]]
    _emit_finished(session, run.team_id, now, scope="node", run_id=run.id, at=run.finished_at, summary={
        "status": run.status, "kb_version": run.kb_version, "sources": len(jobs),
        "complete_sources": len(complete),
        # read with coverage gaps, and what those gaps left unread: "0 resolved" is not "everything was read" (F2)
        "partial_sources": sum(1 for j in complete if j.outcome == "partial"), "not_read": not_read,
        "assets": sum(int(j.asset_count or 0) for j in jobs), "events": _kind_counts(rows[:EVENT_CAP])})
    return stored


def run_not_read(session: Session, run: CbomCollectionRun) -> list[dict[str, Any]]:
    """What each complete collection of ``run`` did not read again (under one of its coverage gaps) that the source's
    last known state had: the same comparison as ``record_run_drift``, whose events leave these out (they are neither
    removed nor resolved), so the run's "Changes" can list them apart with the reason (lab UI r1 F2: a stopped TLS
    target silently dropped out)."""
    sources = _sources(session, run.team_id)
    out: list[dict[str, Any]] = []
    for job in _run_jobs(session, run):
        if not job_comparable(job)[0]:
            continue
        a_rows = _job_assets(session, job)
        gaps = job_gaps(a_rows)
        if not gaps:  # nothing is "not read" without a gap
            continue
        src = sources.get(job.source_id or 0)
        ref, name = ID.job_source_ref(job, src), ID.job_source_name(job, src)
        base = _baseline_job(session, job, ref, sources)
        if base is None:
            continue
        base_run = session.get(CbomCollectionRun, base.run_id) if base.run_id else None
        reclassify = rules_differ(base_run, run)
        diff = compare(_carried(session, base, ref, sources, _judge(run)).views,
                       node_views(a_rows, ref, reclassify=reclassify), gaps)
        out += [{**d, "source_name": name} for d in diff["not_read"]]
    return out


def _kind_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["kind"]] = counts.get(row["kind"], 0) + 1
    return counts


def _emit_finished(session: Session, team_id: int, now: _dt.datetime, **fields: Any) -> None:
    """Queue a "scan finished" event for the team's integrations (WP11; never fails the drift recording)."""
    from backend.utilities.integrations.events import emit_safely, scan_finished_payload

    emit_safely(session, team_id, [scan_finished_payload(team_id, **fields)], now)


def record_pending_drift(engine, now: _dt.datetime, *, limit: int = 20) -> int:
    """Scheduler tick: record drift for finished runs that have none yet (each in its own transaction)."""
    with Session(engine) as session:
        ids = session.exec(select(CbomCollectionRun.id).where(
            CbomCollectionRun.drift_at.is_(None), CbomCollectionRun.finished_at.is_not(None),  # type: ignore[union-attr]
            CbomCollectionRun.status.in_(FINISHED)).order_by(CbomCollectionRun.id).limit(limit)).all()  # type: ignore[attr-defined]
    done = 0
    for run_id in ids:
        with Session(engine) as session:
            try:
                run = session.get(CbomCollectionRun, run_id)
                if run is not None and record_run_drift(session, run, now) is not None:
                    done += 1
                session.commit()
            except Exception as exc:
                session.rollback()
                log("drift FAILED", run=run_id, error=type(exc).__name__)
    return done


def public_event(e: CbomDriftEvent) -> dict[str, Any]:
    return {"id": e.id, "at": iso_z(e.at), "scope": e.scope, "kind": e.kind, "run_id": e.run_id,
            "baseline_run_id": e.baseline_run_id, "scan_id": e.scan_id, "baseline_scan_id": e.baseline_scan_id,
            "source_ref": e.source_ref, "source_name": e.source_name, "asset_key": e.asset_key,
            "asset_label": e.asset_label, "code": e.code, "severity": e.severity, "detail": e.detail or {}}


# ----------------------------------------------------------------------------- code scans
def _code_rows(scan: Scan) -> list[Any]:
    data = scan.scan_data if isinstance(scan.scan_data, dict) else {}
    rows = data.get("results")
    return rows if isinstance(rows, list) else []


def _tool_version(scan: Scan) -> str | None:
    data = scan.scan_data if isinstance(scan.scan_data, dict) else {}
    meta = ((data.get("cbom_json") or {}).get("metadata") or {}) if isinstance(data.get("cbom_json"), dict) else {}
    tools = meta.get("tools")
    items = tools.get("components") if isinstance(tools, dict) else tools
    if isinstance(items, list) and items and isinstance(items[0], dict):
        return f"{items[0].get('name')}@{items[0].get('version')}"
    return None


def code_source(scan: Scan) -> tuple[str, str]:
    return ID.code_source_ref(scan.scan_metadata, scan.title, scan.id or 0)


SCOPE_OPTIONS = ("include_vendored", "scan_history", "scan_binaries")  # what a code scan read (db/metadata.py)


def scan_scope(meta: Mapping[str, Any] | None) -> dict[str, bool]:
    """The scope options a code scan ran with; a scan stored before an option existed ran with its default (off)."""
    meta = meta if isinstance(meta, Mapping) else {}
    return {k: bool(meta.get(k)) for k in SCOPE_OPTIONS}


def scan_truncated(scan: Scan) -> bool:
    """An uploaded CBOM cut at its component limit (``cbom_input.truncated``): what is missing was never read."""
    data = scan.scan_data if isinstance(scan.scan_data, dict) else {}
    report = data.get("cbom_input")
    return isinstance(report, dict) and report.get("truncated") is True


def previous_code_scan(session: Session, scan: Scan) -> Scan | None:
    """The newest earlier successful CBOM scan of the same repository and branch (or the same zip / file title), made
    with the same scope options and not truncated: a scan that read less is no baseline (what it skipped would read
    as fixed). Scans with no stable source (``scan:<id>``) have no previous scan."""
    key, _label = code_source(scan)
    if key.startswith("scan:"):
        return None
    scope = scan_scope(scan.scan_metadata)
    heads = session.exec(select(Scan.id, Scan.scan_metadata, Scan.title).where(
        Scan.team_id == scan.team_id, Scan.scan_type == "cbom", Scan.scan_status == "success",
        Scan.id != scan.id, Scan.created_at <= scan.created_at)
        .order_by(Scan.created_at.desc(), Scan.id.desc()).limit(200)).all()  # type: ignore[union-attr]
    for scan_id, meta, title in heads:
        if ID.code_source_ref(meta, title, scan_id)[0] != key or scan_scope(meta) != scope:
            continue
        other = session.get(Scan, scan_id)
        if other is not None and not scan_truncated(other):
            return other
    return None


def resolution_unproven(scan: Scan, base: Scan) -> str | None:
    """Why a finding missing from ``scan`` is not proven fixed (None: it is). Missing because a different engine
    version judged it, or because an upload of the same title may be other code, is not "fixed"."""
    key, _label = code_source(scan)
    if not key.startswith("repo:"):
        return "an uploaded zip or CBOM file is matched to earlier uploads by its title only"
    if _tool_version(base) != _tool_version(scan):
        return "the scans were made by different engine versions"
    if scan_scope(base.scan_metadata) != scan_scope(scan.scan_metadata):
        return "the scans were made with different scope options"
    if scan_truncated(base) or scan_truncated(scan):
        return "a scan was truncated"
    return None


def code_scan_diff(scan: Scan, base: Scan) -> dict[str, Any]:
    key, label = code_source(scan)
    before, after = code_views(_code_rows(base), key), code_views(_code_rows(scan), key)
    diff = compare(before, after)
    tb, ta = _tool_version(base), _tool_version(scan)
    rules_changed = tb != ta
    if rules_changed:
        for k in ("opened", "resolved"):
            for item in diff[k]:
                item["rule_change"] = "possible: the scans were made by different engine versions"
    unproven = resolution_unproven(scan, base)
    sb, sa = scan_scope(base.scan_metadata), scan_scope(scan.scan_metadata)
    out: dict[str, Any] = {"scan_id": scan.id, "against_scan_id": base.id, "source": label, "source_ref": key,
                           "versions": {"before": tb, "after": ta, "rules_changed": rules_changed,
                                        "reclassified": False},
                           "scope": {"before": sb, "after": sa, "differs": sb != sa},
                           "truncated_scans": [s.id for s in (base, scan) if scan_truncated(s)],
                           # resolved / removed are what the comparison shows; only a proven one is marked fixed
                           "resolutions": {"proven": unproven is None, "reason": unproven}}
    truncated = False
    for k, items in diff.items():
        out[k], cut = _cap(items)
        truncated = truncated or cut
    rb, ra = readiness(before), readiness(after)
    out["counts"] = {k: len(v) for k, v in diff.items()}
    out["readiness"] = {"before": rb, "after": ra, "delta": None if rb is None or ra is None else round(ra - rb, 1)}
    out["truncated"] = truncated
    out["_views"] = (before, after)
    return out


def record_code_scan_drift(session: Session, scan: Scan, now: _dt.datetime) -> tuple[dict[str, Any] | None, int]:
    """Events for a successful code scan against the previous scan of the same source. The caller commits. A
    truncated scan is not compared; when a resolution is not proven (``resolution_unproven``) only the events that
    open something are recorded -- integrations close tickets on "resolved" / "removed" / "renewed"."""
    if scan_truncated(scan):
        return None, 0
    base = previous_code_scan(session, scan)
    if base is None:
        return None, 0
    diff = code_scan_diff(scan, base)
    key, label = code_source(scan)
    before, after = diff["_views"]
    full = compare(before, after)
    if not diff["resolutions"]["proven"]:
        full = {**full, "removed": [], "resolved": [], "changed": [c for c in full["changed"] if not c.get("renewed")]}
    rows = diff_events(scan.team_id, now, full, scope="code", source_ref=key, source_name=label,
                       anchor=f"scan:{scan.id}", cause=("engine version changed" if diff["versions"]["rules_changed"]
                                                        else None),
                       scan_id=scan.id, baseline_scan_id=base.id)
    rows += _expiring(scan.team_id, now, after, scope="code", source_ref=key, source_name=label, scan_id=scan.id)
    return diff, insert_events(session, rows[:EVENT_CAP])


def fixed_identities(diff: Mapping[str, Any]) -> set[str]:
    """Identities whose every finding was resolved: the asset is gone, or still listed but no longer a finding.
    Empty when the comparison does not prove the resolutions (see ``resolution_unproven``)."""
    if not (diff.get("resolutions") or {}).get("proven", True):
        return set()
    before, after = diff["_views"]
    return {ident for ident, view in before.items()
            if view.finding and (ident not in after or not after[ident].finding)}


def on_code_scan_success(scan_id: int, engine, now: _dt.datetime | None = None) -> dict[str, int]:
    """After a CBOM code scan's results were ingested (once): drift events, and the previous scan's findings that are
    gone marked fixed in Mongo with their Jira tickets closed (the same helper as the manual "fixed" toggle)."""
    from backend.utilities.cbom_sources.common import utcnow

    now = now or utcnow()
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        if scan is None or scan.scan_type != "cbom" or scan.scan_status != "success":
            return {"events": 0, "fixed": 0}
        diff, stored = record_code_scan_drift(session, scan, now)
        rows = [r for r in _code_rows(scan) if isinstance(r, dict)]
        _emit_finished(session, scan.team_id, now, scope="code", scan_id=scan.id, at=scan.last_updated or now,
                       source_name=code_source(scan)[1], summary={
                           "status": "success", "assets": len(rows),
                           "findings": sum(1 for r in rows if is_finding(display_row(r))),
                           "against_scan_id": diff["against_scan_id"] if diff else None, "events": stored})
        session.commit()
        if diff is None:
            return {"events": 0, "fixed": 0}
        gone = fixed_identities(diff)
        base_id, team_id = diff["against_scan_id"], scan.team_id
    fixed = 0
    if gone:
        from backend.utilities.db.finding_state import mark_code_findings_fixed

        fixed = mark_code_findings_fixed(engine, team_id=team_id, scan_id=base_id, identities=gone,
                                         resolved_in_scan=scan_id, now=now)
    log("code drift recorded", team=team_id, scan=scan_id, against=base_id, events=stored, fixed=fixed)
    return {"events": stored, "fixed": fixed}
