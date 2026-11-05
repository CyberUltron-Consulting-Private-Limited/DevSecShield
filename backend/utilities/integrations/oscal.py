"""OSCAL assessment results for a CBOM collection run or a CBOM code scan, and the signed push to a GRC tool.

* Model: NIST OSCAL v1.2.3 assessment-results; every document is validated against the official JSON schema
  (``data/oscal_assessment-results_schema_v1.2.3.json``, from the usnistgov/OSCAL v1.2.3 release asset
  ``oscal_assessment-results_schema.json``, sha256 4034e203...ff42c) before it leaves the server, offline. The
  schema's patterns use Unicode classes (``\\p{L}``), so ``pattern`` is checked with the ``regex`` module.
* Content: one result per run / scan. Every asset with a weakness finding is an inventory item (local definition) and
  an observation (method TEST, type finding) listing its finding codes. Each (finding code, control) pair is a finding
  whose target is the control's assessment objective with state ``not-satisfied`` and which links the observations.
* Controls: the knowledge base maps each finding code to compliance areas (``tls_min``, ``algorithms``,
  ``certificates`` ...) whose references are CERT-In, SEBI CSCRF, RBI, NIST SP 800-131A and CNSA 2.0 clauses. Those
  references go into each finding's links (source URL and clause). For OSCAL ``reviewed-controls`` the areas map to
  NIST SP 800-53 Rev. 5 controls (``COMPLIANCE_TO_CONTROLS``); ids, titles and objective ids are taken from the
  official OSCAL catalog (``data/nist_sp800_53_r5_controls.json`` records the catalog version and hash).
* Honest scope: automated cryptographic checks only. A control with no finding is reviewed, not attested as
  satisfied (said in the reviewed-controls description).
"""
from __future__ import annotations

import datetime as _dt
import functools
import json
import uuid
from pathlib import Path
from typing import Any, Iterable

from pydantic import Field, field_validator
from sqlmodel import Session, select

from backend.new_models import CbomCollectionJob, CbomCollectedAsset, CbomCollectionRun, CbomCollectionSource, Scan
from backend.utilities.cbom_sources.common import iso_z, utcnow
from backend.utilities.integrations.base import Cfg, Context, Outcome, ca_pem, https_url
from backend.utilities.integrations.webhook import post_signed

OSCAL_VERSION = "1.2.3"
_DATA = Path(__file__).resolve().parent / "data"
SCHEMA_FILE = _DATA / "oscal_assessment-results_schema_v1.2.3.json"
CONTROLS_FILE = _DATA / "nist_sp800_53_r5_controls.json"
NS = "https://zeroshield.ai/ns/oscal"
_UUID_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://zeroshield.ai/ns/oscal/cbom")
MAX_OBSERVATIONS = 5000
COMPLIANCE_TO_CONTROLS: dict[str, tuple[str, ...]] = {
    "tls_min": ("sc-8", "sc-8.1", "sc-13"),
    "in_transit": ("sc-8", "sc-8.1"),
    "algorithms": ("sc-13",),
    "keysize": ("sc-12", "sc-13"),
    "key_mgmt": ("sc-12",),
    "certificates": ("sc-17", "ia-5.2"),
    "at_rest": ("sc-28", "sc-28.1"),
    "auth": ("ia-5",),
    "components": ("si-2", "sa-22"),
    "pqc": ("sc-13",),
}
# codes with no compliance area: the KB's OWASP tag picks the control family (legacy_controls)
OWASP_TAG_TO_CONTROLS = {"crypto": ("sc-13",), "misconfig": ("cm-6",), "components": ("si-2",), "integrity": ("si-2",),
                         "auth": ("ia-5",)}
_IMPACT_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


class OscalPushConfig(Cfg):
    url: str = Field(max_length=1000)
    ca_pem: str | None = Field(default=None, max_length=64 * 1024)
    events: list[str] | None = None

    _u = field_validator("url")(classmethod(lambda cls, v: https_url(v)))
    _c = field_validator("ca_pem")(classmethod(lambda cls, v: ca_pem(v)))


@functools.lru_cache(maxsize=1)
def catalog() -> dict[str, dict[str, Any]]:
    data = json.loads(CONTROLS_FILE.read_text())
    return {c["id"]: c for c in data["controls"]}


@functools.lru_cache(maxsize=1)
def _validator():
    import jsonschema
    import regex

    schema = json.loads(SCHEMA_FILE.read_text())

    def pattern(validator, patrn, instance, _schema):
        if validator.is_type(instance, "string") and not regex.search(patrn, instance):
            yield jsonschema.ValidationError(f"{instance[:80]!r} does not match {patrn[:80]!r}")

    cls = jsonschema.validators.extend(jsonschema.Draft7Validator, {"pattern": pattern})
    return cls(schema)


def validate(doc: dict[str, Any], limit: int = 20) -> list[str]:
    """Schema errors (empty when the document is valid OSCAL 1.2.3 assessment results)."""
    errors = sorted(_validator().iter_errors(doc), key=lambda e: list(e.absolute_path))
    return [f"{'/'.join(str(p) for p in e.absolute_path) or '(root)'}: {e.message}" for e in errors[:limit]]


def _uuid(*parts: Any) -> str:
    return str(uuid.uuid5(_UUID_NS, "|".join(str(p) for p in parts)))


def _ts(moment: _dt.datetime | None) -> str:
    return iso_z(moment or utcnow()) or ""


def _prop(name: str, value: Any) -> dict[str, str] | None:
    text = " ".join(str(value).split()) if value is not None else ""
    return {"name": name, "ns": NS, "value": text[:500]} if text else None


def _props(*pairs: tuple[str, Any]) -> list[dict[str, str]]:
    return [p for p in (_prop(n, v) for n, v in pairs) if p]


def controls_for(namespace: str, code: str) -> list[str]:
    from backend.utilities.cbom_sources.crypto_kb import entry

    e = entry(namespace, code) or {}
    out: list[str] = []
    for area in e.get("compliance") or []:
        out += COMPLIANCE_TO_CONTROLS.get(area, ())
    if not out:
        for tag in e.get("owasp") or []:
            out += OWASP_TAG_TO_CONTROLS.get(tag, ())
    known = catalog()
    return [c for c in dict.fromkeys(out or ["sc-13"]) if c in known]


def _references(namespace: str, code: str) -> list[dict[str, str]]:
    from backend.utilities.cbom_sources.crypto_kb import entry, load

    e = entry(namespace, code) or {}
    table = load().get("compliance") or {}
    links, seen = [], set()
    for area in e.get("compliance") or []:
        for ref in table.get(area) or []:
            href, text = str(ref.get("source") or ""), f"{ref.get('framework')}: {ref.get('id')}"
            if href.startswith(("http://", "https://")) and (href, text) not in seen:
                seen.add((href, text))
                links.append({"href": href, "rel": "reference", "text": text[:300]})
    return links


def _text(value: Any, fallback: str) -> str:
    text = " ".join(str(value or "").split())
    return text or fallback


def assessment_results(*, team_id: int, anchor: str, title: str, namespace: str, start: _dt.datetime | None,
                       end: _dt.datetime | None, views: Iterable[tuple[str | None, Any]], kb_version: str | None,
                       description: str, not_read: Iterable[str] = (),
                       partly_read: Iterable[tuple[str, str]] = ()) -> dict[str, Any]:
    """Build the document from drift ``View``s (``drift.node_views`` / ``drift.code_views``) of finding assets.
    ``not_read``: sources whose collection failed; ``partly_read``: (source, what was not read). Neither is claimed
    as reviewed: they are listed in the result's props and in the reviewed-controls remarks."""
    from backend.utilities.cbom_sources.crypto_kb import entry

    findings_views = [(src, v) for src, v in views if v.finding and v.codes]
    truncated = len(findings_views) > MAX_OBSERVATIONS
    findings_views = findings_views[:MAX_OBSERVATIONS]
    collected = _ts(end or start)
    items, observations = [], []
    by_code: dict[str, list[tuple[str, str | None]]] = {}
    for source_name, view in findings_views:
        item_uuid, obs_uuid = _uuid(team_id, "item", view.key), _uuid(team_id, anchor, "obs", view.key)
        extra = view.extra or {}
        items.append({"uuid": item_uuid, "description": _text(view.label, view.key),
                      "props": _props(("asset-key", view.key), ("asset-type", view.asset_type),
                                      ("location", extra.get("location")), ("target", extra.get("target")),
                                      ("source", source_name))})
        codes = sorted(view.codes)
        observations.append({
            "uuid": obs_uuid, "title": _text(view.label, view.key)[:250],
            "description": _text(f"{', '.join(codes)} on {view.label}" + (f" ({source_name})" if source_name else ""),
                                 "finding"),
            "props": _props(*[("finding-code", c) for c in codes], ("impact", view.impact)),
            "methods": ["TEST"], "types": ["finding"],
            "subjects": [{"subject-uuid": item_uuid, "type": "inventory-item"}],
            "collected": collected,
        })
        for code in codes:
            by_code.setdefault(code, []).append((obs_uuid, view.impact))
    findings, reviewed = [], set()
    known = catalog()
    for code in sorted(by_code):
        e = entry(namespace, code) or {}
        worst = min((i for _o, i in by_code[code] if i), key=lambda i: _IMPACT_RANK.get(i, 9), default=None)
        for control in controls_for(namespace, code):
            reviewed.add(control)
            c = known[control]
            finding: dict[str, Any] = {
                "uuid": _uuid(team_id, anchor, "finding", code, control),
                "title": _text(f"{code}: {e.get('title') or code} ({control.upper()})", code)[:250],
                "description": _text(e.get("description"), f"ZeroShield CBOM finding {code}"),
                "props": _props(("finding-code", code), ("severity", worst), ("assets", len(by_code[code]))),
                "target": {"type": "objective-id", "target-id": c["objective_id"], "title": c["title"],
                           "status": {"state": "not-satisfied"}},
                "related-observations": [{"observation-uuid": o} for o, _i in by_code[code]],
            }
            links = _references(namespace, code)
            if links:
                finding["links"] = links
            findings.append(finding)
    all_controls = sorted({c for cs in COMPLIANCE_TO_CONTROLS.values() for c in cs} & set(known))
    not_read, partly_read = list(dict.fromkeys(not_read)), list(partly_read)
    gaps = []
    if not_read:
        gaps.append(f"Not reviewed for {len(not_read)} source(s) whose collection failed: {', '.join(not_read)}.")
    if partly_read:
        gaps.append(f"Reviewed only in part for {len(partly_read)} source(s): "
                    + "; ".join(f"{name} ({what})" for name, what in partly_read)
                    + ". What was not read has no finding here because it was not checked, not because it passed.")
    result: dict[str, Any] = {
        "uuid": _uuid(team_id, anchor, "result"), "title": title, "description": description,
        "start": _ts(start), "reviewed-controls": {
            "description": ("NIST SP 800-53 Rev. 5 controls the ZeroShield CBOM knowledge base maps its cryptographic "
                            "checks to. Automated checks only: a control without a finding here is reviewed by these "
                            "checks, not attested as satisfied"
                            + (", and only for what was read (see remarks)." if gaps else ".")),
            "control-selections": [{"include-controls": [{"control-id": c} for c in all_controls]}]},
    }
    if gaps:
        result["reviewed-controls"]["remarks"] = " ".join(gaps)[:20000]
        result["props"] = (_props(*[("source-not-read", name) for name in not_read])
                           + _props(*[("source-partly-read", f"{name}: {what}") for name, what in partly_read]))
    if end is not None:
        result["end"] = _ts(end)
    if items:
        result["local-definitions"] = {"inventory-items": items}
    if observations:
        result["observations"] = observations
    if findings:
        result["findings"] = findings
    if truncated:
        result["remarks"] = f"Only the first {MAX_OBSERVATIONS} assets with findings are included."
    return {"assessment-results": {
        "uuid": _uuid(team_id, anchor, "document"),
        "metadata": {"title": title, "last-modified": _ts(utcnow()), "version": anchor, "oscal-version": OSCAL_VERSION,
                     "props": _props(("kb-version", kb_version), ("generator", "ZeroShield DevSecShield CBOM"),
                                     ("controls-catalog", "NIST SP 800-53 Rev. 5.2.0"))},
        "import-ap": {"href": "urn:zeroshield:cbom:assessment-plan",
                      "remarks": "No separate assessment plan: the scope is the sources of this collection run or the "
                                 "repository of this code scan."},
        "results": [result],
    }}


# ----------------------------------------------------------------------------- run / scan
def run_document(session: Session, run: CbomCollectionRun) -> dict[str, Any]:
    from backend.utilities.cbom_sources import drift as DRIFT
    from backend.utilities.cbom_sources import identity as ID

    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == run.team_id)).all()}
    views: list[tuple[str | None, Any]] = []
    not_read: list[str] = []
    partly_read: list[tuple[str, str]] = []
    jobs = session.exec(select(CbomCollectionJob).where(
        CbomCollectionJob.team_id == run.team_id, CbomCollectionJob.run_id == run.id,
        CbomCollectionJob.kind == "collect").order_by(CbomCollectionJob.id)).all()
    for job in jobs:
        rows = session.exec(select(CbomCollectedAsset).where(
            CbomCollectedAsset.team_id == run.team_id, CbomCollectedAsset.job_id == job.id,
            CbomCollectedAsset.attempt == job.attempts)).all()
        src = sources.get(job.source_id or 0)
        ref, name = ID.job_source_ref(job, src), ID.job_source_name(job, src)
        views += [(name, v) for v in DRIFT.node_views(rows, ref, reclassify=False).values()]
        # a source is "reviewed" only for what was read: a failed collection is not reviewed at all, and the targets
        # and coverage gaps of a partial one are named (a missing finding there means "not checked")
        if job.status != "success" or job.outcome == "failed":
            not_read.append(f"{name} ({job.status if job.status != 'success' else 'nothing read'})")
            continue
        result = job.result if isinstance(job.result, dict) else {}
        counts = result.get("counts") if isinstance(result.get("counts"), dict) else {}
        gaps = sum(1 for r in rows if r.asset_type == "coverage")
        unread = [f"{counts[k]} target(s) {label}" for k, label in (("failed", "not read"), ("skipped", "skipped"),
                                                                     ("partial", "read in part"))
                  if isinstance(counts.get(k), int) and counts[k] > 0]
        unread += ([f"{gaps} check(s) not collected"] if gaps else [])
        unread += (["truncated at the asset limit"] if result.get("truncated") else [])
        if unread:
            partly_read.append((name, ", ".join(unread)))
    return assessment_results(
        team_id=run.team_id, anchor=f"run-{run.id}", title=f"ZeroShield CBOM collection run #{run.id}",
        namespace="node", start=run.created_at, end=run.finished_at, views=views, kb_version=run.kb_version,
        description=f"Cryptographic inventory collected from {len(jobs)} source(s); run status {run.status}.",
        not_read=not_read, partly_read=partly_read)


def scan_document(scan: Scan) -> dict[str, Any]:
    from backend.utilities.cbom_sources import drift as DRIFT

    key, label = DRIFT.code_source(scan)
    data = scan.scan_data if isinstance(scan.scan_data, dict) else {}
    rows = data.get("results") if isinstance(data.get("results"), list) else []
    views = [(label, v) for v in DRIFT.code_views(rows, key).values()]
    return assessment_results(
        team_id=scan.team_id, anchor=f"scan-{scan.id}", title=f"ZeroShield CBOM code scan #{scan.id}",
        namespace="code", start=scan.created_at, end=scan.last_updated, views=views, kb_version=None,
        description=f"Cryptographic inventory of {label} (CBOM code scan).",
        partly_read=[(label, "the uploaded CBOM was truncated at its component limit")]
        if DRIFT.scan_truncated(scan) else ())


def document_for(engine, team_id: int, *, run_id: int | None = None, scan_id: int | None = None) -> dict | None:
    with Session(engine) as session:
        if run_id is not None:
            run = session.get(CbomCollectionRun, run_id)
            return run_document(session, run) if run is not None and run.team_id == team_id else None
        scan = session.get(Scan, scan_id) if scan_id is not None else None
        if scan is None or scan.team_id != team_id or scan.scan_type != "cbom" or scan.scan_status != "success":
            return None
        return scan_document(scan)


# ----------------------------------------------------------------------------- push connector
def send(ctx: Context, events: list[dict[str, Any]]) -> list[Outcome]:
    out: list[Outcome] = []
    secret = ctx.secrets.get("signing_secret") or ""
    for event in events:
        if out and ctx.expired():  # the dispatcher's time budget: the rest stay queued, in order
            break
        if event["kind"] != "scan_finished":
            out.append(Outcome("ok", "not a scan-finished event; nothing to push"))
            continue
        try:
            doc = document_for(ctx.engine, ctx.team_id, run_id=event.get("run_id"), scan_id=event.get("scan_id"))
        except Exception as exc:
            out.append(Outcome("retry", f"building the OSCAL document failed ({type(exc).__name__})"))
            break
        if doc is None:
            out.append(Outcome("reject", "the run or scan no longer exists"))
            continue
        problems = validate(doc)
        if problems:
            out.append(Outcome("reject", f"the document failed OSCAL schema validation: {problems[0][:150]}"))
            continue
        body = json.dumps(doc, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        outcome = post_signed(ctx.config.url, secret, event["id"], event["type"], body, ctx.config.ca_pem)
        out.append(outcome)
        if outcome.status == "retry":
            break
    return out


def test(ctx: Context, event: dict[str, Any]) -> Outcome:
    """Push a small valid document (no findings) so the GRC side can check the signature and the format."""
    doc = assessment_results(team_id=ctx.team_id, anchor=f"test-{event['id']}", title="ZeroShield OSCAL push test",
                             namespace="node", start=utcnow(), end=utcnow(), views=[], kb_version=None,
                             description="Connection test: no assets.")
    body = json.dumps(doc, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return post_signed(ctx.config.url, ctx.secrets.get("signing_secret") or "", event["id"], "integration.test", body,
                       ctx.config.ca_pem)
