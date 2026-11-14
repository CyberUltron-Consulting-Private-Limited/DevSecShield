"""Deliverables of one CBOM Sources run (CB-38 PR-8): the signed CycloneDX JSON, a VEX with honest analysis states,
the PDF report and the evidence pack. The code-scan lane has the same four (``routers/certin.py``); a run has no
stored ``scan_data``, so each is built from the run's export (``inventory.cyclonedx``, called as is and only
post-processed here) at request time.

Same bytes every time
---------------------
``write_run_cbom`` writes the run's export (``inventory._document``, the builder behind ``inventory.write_cyclonedx``,
one component at a time, as #103 streams it) with ``metadata.timestamp`` set to the run's ``last_updated`` (when its data
last changed) instead of the request time. Two downloads of an unchanged run on the same day are byte-identical, so the
signature from ``GET .../runs/{id}/signature`` (HMAC-SHA256 with the code lane's key and ``bom_signature`` fields, over
the exact bytes of ``GET .../runs/{id}/cbom``) verifies the file a customer downloaded: ``HMAC(key, file bytes)``.
The file changes (and the signature with it) only when the content does: new assets on an active run, a certificate
or library judged differently on a later day (``zs:judged_on``), or a new build (``zs:build``). The code lane signs
canonical JSON of a stored BOM; a run's export is streamed (never held whole), so here the raw bytes are signed.

VEX analysis (``run_vex``; ``zs:vex_rules`` = ``VEX_RULES``)
-------------------------------------------------------------
The run export's own ``vulnerabilities`` say ``exploitable`` for every finding code (KF-11). This VEX re-judges each
(finding, asset) pair and groups the assets of one finding by the analysis they get:

====================================================  ============  ==============  ====================================
Finding on the asset                                  state         response        why
====================================================  ============  ==============  ====================================
weak / broken algorithm or setting the collector      exploitable   -               observed on the collected asset; a
observed (TLS 1.0, RC4, RSA-1024, plain-text secret,                                classical attack exists today
unencrypted storage ...: every node KB code not
listed below)
quantum-only: KB category ``pqc`` (NO_PQ_KEX,         in_triage     -               no classical attack; ``detail``
SSH_NO_PQ_KEX, IKE_NO_PQ, QUANTUM_VULNERABLE) or                                    says harvest-now-decrypt-later
``pqc: grover-weakened`` (DISK_XTS_128)                                             (key exchange in transit) or
                                                                                    future forgery / key recovery
inferred from a version or date, not behaviour        in_triage     -               a version match is not proof
(``INFERRED``: LIB_KNOWN_CVE, LIB_EOL, DB_EOL_VERSION)
CVE matched from the evidence (as in the export)      in_triage     -               a match is not proof of exposure
asset's remediation status ``done``                   resolved      -               the team marked it fixed; the next
                                                                                    run confirms
asset's remediation status ``accepted_risk``          (unchanged)   will_not_fix    CycloneDX ``not_affected`` means
                                                                                    "not affected" and needs a
                                                                                    justification; an accepted risk is
                                                                                    still affected, so the state stays
                                                                                    and the response says the team
                                                                                    will not fix it
asset's remediation status ``in_progress``            (unchanged)   update          the fix is being applied
====================================================  ============  ==============  ====================================

Affected assets are referenced with BOM-Links into the run CBOM (``urn:cdx:<serial>/1#zs-asset-<id>``), so the VEX
travels as a separate document. An active run is allowed everywhere, with an "as of" note (the run CBOM download
treats active runs the same way: it serves what has been collected so far and names the run status).
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import hmac
import json
import shutil
import tempfile
import uuid
import zipfile
from typing import Any, BinaryIO, Callable, Iterator

from sqlmodel import Session, select

from backend.new_models import CbomCollectionJob, CbomCollectionRun, CbomCollectionSource, CbomScanNode
from backend.utilities.cbom_sources import crypto_kb
from backend.utilities.cbom_sources import inventory as INV
from backend.utilities.cbom_sources.common import iso_z

VEX_RULES = "run-1"
FINISHED = ("done", "partial", "failed", "cancelled")
INFERRED = frozenset({"LIB_KNOWN_CVE", "LIB_EOL", "DB_EOL_VERSION"})
PDF_FINDINGS_CAP = 500
SPOOL_BYTES = 8 * 1024 * 1024  # a file up to this size stays in memory; a larger one goes to a temp file
KEY_ID = "certin-hmac-1"  # the code lane's signing key id (routers/certin.py, cert_in/sign.py)
_VEX_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://zeroshield.ai/cbom/sources/run/vex")

DETAIL_OBSERVED = ("Observed directly by the collector on each listed asset: the weak algorithm or setting is in use "
                   "where it was collected, and a classical attack on it is known today.")
DETAIL_HNDL = ("Quantum-only exposure, no classical attack known today: the key exchange is quantum-vulnerable, so "
               "traffic recorded now can be decrypted once a cryptographically relevant quantum computer exists "
               "(harvest now, decrypt later). Plan the post-quantum migration (Mosca X + Y > Z).")
DETAIL_QUANTUM = ("Quantum-only exposure, no classical attack known today: a future cryptographically relevant "
                  "quantum computer could forge these signatures or recover these keys (or, for 128-bit symmetric "
                  "keys, halve their strength). Plan the post-quantum migration (Mosca X + Y > Z).")
DETAIL_INFERRED = ("Inferred from a version or date, not from observed behaviour: confirm whether the affected code "
                   "path or release is in use before treating it as exploitable.")
DETAIL_DONE = ("Marked done in the team's remediation plan; this run collected the asset before the fix or the next "
               "run confirms it.")
DETAIL_ACCEPTED = "The team accepted this risk in the remediation plan and will not fix it."
DETAIL_IN_PROGRESS = "Remediation is in progress in the team's remediation plan."


# ----------------------------------------------------------------------------- run identity
def is_active(run: CbomCollectionRun) -> bool:
    return run.status not in FINISHED


def as_of_note(run: CbomCollectionRun, now: _dt.datetime) -> str | None:
    """The sentence every deliverable carries for a run that is still collecting (None once it has finished)."""
    if not is_active(run):
        return None
    return (f"As of {iso_z(now)}: run #{run.id} is still {run.status}; this file holds what has been collected so far "
            "and will change when the run finishes.")


def run_sources(session: Session, run: CbomCollectionRun) -> list[dict[str, Any]]:
    """The run's sources (name and kind), in job order; deleted sources keep the name snapshotted on the job."""
    jobs = session.exec(select(CbomCollectionJob).where(CbomCollectionJob.team_id == run.team_id,
                                                        CbomCollectionJob.run_id == run.id)
                        .order_by(CbomCollectionJob.id)).all()
    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == run.team_id)).all()}
    out: dict[str, dict[str, Any]] = {}
    for job in jobs:
        src = sources.get(job.source_id or 0)
        name = (src.name if src else None) or str((job.params or {}).get("source_name") or "Deleted source")
        out.setdefault(f"{job.source_id}:{name}", {"id": job.source_id, "name": name,
                                                   "kind": src.kind if src else (job.params or {}).get("kind")})
    return list(out.values())


# ----------------------------------------------------------------------------- CBOM JSON (signed bytes)
Document = tuple[dict[str, Any], Iterator[dict[str, Any]], Callable[[], list[dict[str, Any]]]]


def document(session: Session, run: CbomCollectionRun, now: _dt.datetime) -> Document:
    """``inventory._document`` (head, components one at a time, vulnerabilities) with a timestamp that only moves when
    the run's data does, so the same run downloads as the same bytes."""
    head, components, vulns = INV._document(session, run, now)
    stamp = iso_z(run.last_updated or run.finished_at or run.created_at)
    if stamp:
        head["metadata"]["timestamp"] = stamp
    return head, components, vulns


def _dumps(value: Any) -> bytes:  # what inventory.write_cyclonedx writes (starlette's JSONResponse encoding)
    return json.dumps(value, ensure_ascii=False, allow_nan=False, indent=None, separators=(",", ":")).encode()


def write_document(doc: Document, fmt: str, out: Any) -> None:
    """``inventory.write_cyclonedx``'s writer over ``doc``: JSON piece by piece, or XML through ``cdx_xml.write_xml``."""
    head, components, vulns = doc
    if fmt == "xml":
        from backend.utilities.cbom_sources import cdx_xml

        cdx_xml.write_xml(out, head, components, vulns)
        return
    out.write(_dumps(head)[:-1] + b',"components":[')
    for index, component in enumerate(components):
        out.write((b"," if index else b"") + _dumps(component))
    out.write(b'],"vulnerabilities":' + _dumps(vulns()) + b"}")


def write_run_cbom(session: Session, run: CbomCollectionRun, now: _dt.datetime, fmt: str, out: BinaryIO) -> None:
    """Exactly the bytes ``GET .../runs/{id}/cbom`` serves (and, for JSON, the signature covers)."""
    write_document(document(session, run, now), fmt, out)


def props(head: dict[str, Any]) -> dict[str, str]:
    return {p.get("name"): p.get("value") for p in (head.get("metadata") or {}).get("properties") or []
            if isinstance(p, dict)}


def sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


class Digests:
    """A write-through file: sha256 (and HMAC-SHA256 when given a key) of every byte written to ``out``."""

    def __init__(self, out: BinaryIO, secret: bytes | None = None):
        self.out, self.size = out, 0
        self.sha = hashlib.sha256()
        self.mac = hmac.new(secret, digestmod=hashlib.sha256) if secret else None

    def write(self, data: bytes) -> int:
        self.out.write(data)
        self.sha.update(data)
        if self.mac is not None:
            self.mac.update(data)
        self.size += len(data)
        return len(data)


def spool() -> BinaryIO:
    return tempfile.SpooledTemporaryFile(max_size=SPOOL_BYTES)  # type: ignore[return-value]


def written(session: Session, run: CbomCollectionRun, now: _dt.datetime, fmt: str, secret: bytes | None = None
            ) -> tuple[BinaryIO, dict[str, Any], Digests]:
    """The run CBOM in ``fmt`` written to a temp file (positioned at its start), its head, and its digests."""
    out = spool()
    try:
        doc = document(session, run, now)
        tee = Digests(out, secret)
        write_document(doc, fmt, tee)
        out.seek(0)
    except BaseException:
        out.close()
        raise
    return out, doc[0], tee


def run_signature(run: CbomCollectionRun, head: dict[str, Any], tee: Digests, now: _dt.datetime) -> dict[str, Any]:
    """The code lane's ``bom_signature`` fields (alg, key_id, digest, signature_b64, signed_at) over the run CBOM JSON
    bytes ``tee`` saw, plus what they cover."""
    if tee.mac is None:
        raise RuntimeError("signing needs a key")
    signature: dict[str, Any] = {
        "alg": "HMAC-SHA256", "key_id": KEY_ID, "digest": tee.sha.hexdigest(),
        "signature_b64": base64.b64encode(tee.mac.digest()).decode("ascii"), "signed_at": iso_z(now),
        "covers": f"cbom-sources-run-{run.id}.cdx.json",
        "scope": ("HMAC-SHA256 over the exact bytes of GET /{team}/cbom/sources/runs/{run}/cbom (format=json) as "
                  "downloaded: HMAC(key, file bytes) = signature_b64 and sha256(file bytes) = digest. The XML form "
                  "is not covered."),
        "canonicalization": "none (the raw file bytes)",
        "serialNumber": head.get("serialNumber"),
        "document_timestamp": (head.get("metadata") or {}).get("timestamp"),
        "bytes": tee.size,
        "run_id": run.id,
        "run_status": run.status,
    }
    note = as_of_note(run, now)
    if note:
        signature["as_of"] = note
    return signature


def signature_bytes(signature: dict[str, Any]) -> bytes:
    return json.dumps(signature, indent=2, ensure_ascii=False).encode("utf-8")


def summary(session: Session, run: CbomCollectionRun, now: _dt.datetime
            ) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    """One pass over the export for the VEX and the PDF: its head, its findings (the asset components whose
    ``zs:impact`` is a severity, worst first; small dicts, never the whole document) and its vulnerabilities."""
    head, components, vulns = document(session, run, now)
    found = []
    for comp in components:
        p: dict[str, list[str]] = {}
        for prop in comp.get("properties") or []:
            p.setdefault(str(prop.get("name")), []).append(str(prop.get("value") or ""))
        impact = (p.get("zs:impact") or ["Info"])[0]
        if impact not in _IMPACT_RANK:
            continue
        found.append({"ref": comp.get("bom-ref"), "impact": impact, "name": comp.get("name"),
                      "type": (p.get("zs:asset_type") or [""])[0], "location": (p.get("zs:location") or [""])[0],
                      "source": (p.get("zs:source") or [""])[0], "finding": (p.get("zs:finding") or [""])[0]})
    found.sort(key=lambda r: (_IMPACT_RANK[r["impact"]], str(r["ref"])))
    return head, found, vulns()


_IMPACT_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


# ----------------------------------------------------------------------------- VEX
def code_basis(code: str) -> str:
    """``observed`` | ``quantum_only`` | ``inferred`` for a node finding code (module docstring table)."""
    if code in INFERRED:
        return "inferred"
    entry = crypto_kb.entry("node", code) or {}
    if entry.get("category") == "pqc" or entry.get("pqc") == "grover-weakened":
        return "quantum_only"
    return "observed"


def analysis_for(basis: str, *, status: str | None, hndl: bool, cve_detail: str | None = None) -> dict[str, Any]:
    """The CycloneDX ``analysis`` of one finding on one asset."""
    if status == "done":
        return {"state": "resolved", "detail": DETAIL_DONE}
    if basis == "observed":
        state, detail = "exploitable", DETAIL_OBSERVED
    elif basis == "quantum_only":
        state, detail = "in_triage", DETAIL_HNDL if hndl else DETAIL_QUANTUM
    elif basis == "cve":
        state, detail = "in_triage", cve_detail or "A version or configuration match is not proof of exposure."
    else:
        state, detail = "in_triage", DETAIL_INFERRED
    out: dict[str, Any] = {"state": state, "detail": detail}
    if status == "accepted_risk":
        out["response"] = ["will_not_fix"]
        out["detail"] = f"{DETAIL_ACCEPTED} {detail}"
    elif status == "in_progress":
        out["response"] = ["update"]
        out["detail"] = f"{DETAIL_IN_PROGRESS} {detail}"
    return out


def bom_link(serial: str, ref: str) -> str:
    return f"urn:cdx:{serial.removeprefix('urn:uuid:')}/1#{ref}"


def asset_context(session: Session, run: CbomCollectionRun) -> dict[str, dict[str, Any]]:
    """Per asset (by its CBOM bom-ref): remediation status (``waves.node_items``, the run's assignment join) and
    harvest-now-decrypt-later."""
    from backend.utilities.cbom_sources.waves import node_items

    out: dict[str, dict[str, Any]] = {}
    for item in node_items(session, run.team_id, run):
        assignment = item.get("assignment") or {}
        out[f"zs-asset-{item['asset_id']}"] = {"status": assignment.get("status"), "hndl": bool(item.get("hndl")),
                                               "asset_key": item["asset_key"]}
    return out


def run_vex(run: CbomCollectionRun, head: dict[str, Any], vulnerabilities: list[dict[str, Any]],
            context: dict[str, dict[str, Any]], now: _dt.datetime) -> dict[str, Any]:
    """The VEX of the run CBOM whose ``head`` and ``vulnerabilities`` are given (module docstring table)."""
    serial = str(head.get("serialNumber") or "")
    out: list[dict[str, Any]] = []
    states: dict[str, int] = {}
    for vuln in vulnerabilities:
        vid = str(vuln.get("id") or "")
        basis = code_basis(vid[len("ZS-CBOM-"):]) if vid.startswith("ZS-CBOM-") else "cve"
        cve_detail = (vuln.get("analysis") or {}).get("detail") if basis == "cve" else None
        groups: dict[str, tuple[dict[str, Any], list[str]]] = {}
        for affected in vuln.get("affects") or []:
            ref = str(affected.get("ref") or "")
            ctx = context.get(ref) or {}
            analysis = analysis_for(basis, status=ctx.get("status"), hndl=bool(ctx.get("hndl")), cve_detail=cve_detail)
            key = json.dumps(analysis, sort_keys=True)
            groups.setdefault(key, (analysis, []))[1].append(ref)
        for index, (analysis, refs) in enumerate(groups.values()):
            entry = {k: v for k, v in vuln.items() if k not in ("analysis", "affects", "bom-ref", "properties")}
            suffix = analysis["state"] + ("-" + "-".join(analysis["response"]) if analysis.get("response") else "")
            entry["bom-ref"] = f"{vuln.get('bom-ref') or vid.lower()}-{suffix}" + (f"-{index}" if index else "")
            entry["analysis"] = analysis
            entry["affects"] = [{"ref": bom_link(serial, r)} for r in refs]
            entry["properties"] = [*(vuln.get("properties") or []), {"name": "zs:vex_basis", "value": basis}]
            states[analysis["state"]] = states.get(analysis["state"], 0) + len(refs)
            out.append(entry)
    meta = props(head)
    note = as_of_note(run, now)
    vex_props = [
        {"name": "zs:vex_rules", "value": VEX_RULES},
        {"name": "zs:run_id", "value": str(run.id)},
        {"name": "zs:run_status", "value": run.status},
        {"name": "zs:bom_serial", "value": serial},
        {"name": "zs:kb_version", "value": meta.get("zs:kb_version") or crypto_kb.version()},
        {"name": "zs:truncated", "value": meta.get("zs:truncated") or "false"},
        *([{"name": "zs:export_cap", "value": f"The CBOM holds the first {INV.EXPORT_CAP:,} assets of this run; "
                                               "assets past the cap are not judged here."}]
          if meta.get("zs:truncated") == "true" else []),
        *([{"name": "zs:as_of", "value": note}] if note else []),
        *[{"name": f"zs:affected_{state}", "value": str(n)} for state, n in sorted(states.items())],
    ]
    digest = hashlib.sha256(json.dumps(out, sort_keys=True).encode()).hexdigest()
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(_VEX_NS, f'{serial}:{VEX_RULES}:{digest}')}",
        "version": 1,
        "metadata": {
            "timestamp": (head.get("metadata") or {}).get("timestamp"),
            "tools": {"components": [{"type": "application", "name": "ZeroShield CBOM Sources VEX",
                                      "version": VEX_RULES}]},
            "properties": vex_props,
        },
        "vulnerabilities": out,
    }


def vex_bytes(vex: dict[str, Any]) -> bytes:
    return json.dumps(vex, indent=2, ensure_ascii=False).encode("utf-8")


# ----------------------------------------------------------------------------- provenance
def provenance(session: Session, run: CbomCollectionRun) -> list[dict[str, Any]]:
    jobs = session.exec(select(CbomCollectionJob).where(CbomCollectionJob.team_id == run.team_id,
                                                        CbomCollectionJob.run_id == run.id)
                        .order_by(CbomCollectionJob.id)).all()
    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == run.team_id)).all()}
    nodes = {n.id: n for n in session.exec(select(CbomScanNode).where(CbomScanNode.team_id == run.team_id)).all()}
    out = []
    for job in jobs:
        src = sources.get(job.source_id or 0)
        node = nodes.get(job.node_id or 0)
        result = job.result if isinstance(job.result, dict) else {}
        out.append({"job_id": job.id, "kind": job.kind,
                    "source": (src.name if src else None) or (job.params or {}).get("source_name") or "Deleted source",
                    "node": node.name if node else None, "status": job.status, "outcome": job.outcome,
                    "assets": job.asset_count, "attempts": job.attempts, "duration_s": result.get("duration_s"),
                    "error": job.error})
    return out


# ----------------------------------------------------------------------------- evidence pack
PackFile = tuple[str, "bytes | tuple[BinaryIO, Digests]", str, str]  # name, body or (temp file, its digests), type, route


def evidence_pack(*, run: CbomCollectionRun, sources: list[dict[str, Any]], now: _dt.datetime,
                  files: list[PackFile], omitted: list[dict[str, str]], head: dict[str, Any],
                  signature: dict[str, Any] | None) -> BinaryIO:
    """Zip of ``files`` plus ``manifest.json`` with the sha256 of each, written to a temp file (at its start). Large
    files (the CycloneDX JSON and XML) are copied in from their temp files, never held whole in memory."""
    meta = props(head)
    entries = []
    for name, body, media, endpoint in files:
        digest, size = (sha256(body), len(body)) if isinstance(body, bytes) else (body[1].sha.hexdigest(), body[1].size)
        entries.append({"name": name, "sha256": digest, "bytes": size, "media_type": media, "endpoint": endpoint})
    manifest: dict[str, Any] = {
        "format": "zeroshield-cbom-run-evidence-pack/1",
        "generated_at": iso_z(now),
        "run": {"id": run.id, "status": run.status, "active": is_active(run), "created_at": iso_z(run.created_at),
                "finished_at": iso_z(run.finished_at), "last_updated": iso_z(run.last_updated),
                "sources": sources,
                "versions": {"kb": run.kb_version, "classifier": run.classifier_version, "engine": run.engine_version}},
        "inputs": {"bom_serial": head.get("serialNumber"),
                   "bom_timestamp": (head.get("metadata") or {}).get("timestamp"),
                   "kb_version": meta.get("zs:kb_version"), "build": meta.get("zs:build"),
                   "judged_on": meta.get("zs:judged_on"), "asset_count": int(meta.get("zs:asset_count") or 0),
                   "export_cap": INV.EXPORT_CAP, "truncated": meta.get("zs:truncated") == "true",
                   "vex_rules": VEX_RULES},
        "files": entries,
        "omitted": omitted,
        "signature": ({"covers": "bom.cdx.json", "alg": signature.get("alg"), "key_id": signature.get("key_id"),
                       "digest": signature.get("digest")} if signature else None),
    }
    note = as_of_note(run, now)
    if note:
        manifest["as_of"] = note
    if manifest["inputs"]["truncated"]:
        manifest["export_cap_note"] = (f"The CBOM holds the first {INV.EXPORT_CAP:,} assets of this run; the files "
                                       "in this pack cover those assets only.")
    out = spool()
    stamp = (now.year, now.month, now.day, now.hour, now.minute, now.second)
    try:
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for name, body, _media, _endpoint in files:
                info = zipfile.ZipInfo(name, date_time=stamp)
                info.compress_type = zipfile.ZIP_DEFLATED
                if isinstance(body, bytes):
                    zf.writestr(info, body)
                    continue
                with zf.open(info, "w", force_zip64=True) as dest:
                    shutil.copyfileobj(body[0], dest, 1024 * 1024)
            info = zipfile.ZipInfo("manifest.json", date_time=stamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8"))
        out.seek(0)
    except BaseException:
        out.close()
        raise
    return out
