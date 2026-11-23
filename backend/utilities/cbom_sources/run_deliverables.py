"""Deliverables of one CBOM Sources run (CB-38 PR-8): the signed CycloneDX JSON, a VEX with honest analysis states,
the PDF report and the evidence pack. The code-scan lane has the same four (``routers/certin.py``); a run has no
stored ``scan_data``, so each is built from the run's export (``inventory._document``, called as is and only
post-processed here) at request time.

Same bytes every time
---------------------
Every time a deliverable prints comes from the run, never from the request (``stamp``): a finished run uses its
``last_updated`` (else ``finished_at``), an active run the newest asset it has stored (else its ``last_updated``) and says
"as of". ``write_run_cbom`` writes the run's export (``inventory._document``, the builder behind
``inventory.write_cyclonedx``, one component at a time, as #103 streams it) with that ``metadata.timestamp``; the
signature's ``signed_at``, the PDF, the VEX (its own time: the later of the stamp and the newest remediation-plan
change of the run's assets), the pack's manifest, zip entry times and OSCAL copy use it too. So repeat downloads of a
finished run are byte-identical; bytes change only when content does (new assets on an active run, a certificate or
library judged differently on a later day: ``zs:judged_on``, a remediation-plan change for the VEX, a new build:
``zs:build``).

The signature (``GET .../runs/{id}/signature``, D11): the run CBOM JSON carries an embedded JSF ES256 signature
(``bom_signing.write_json``, written while the file is streamed), and the signature document adds an ES256 detached
signature (DER, base64) over the exact bytes of ``GET .../runs/{id}/cbom`` (JSON), with the published public key (PEM,
JWK, fingerprint; ``GET /{team}/bom-signing-keys``). A customer verifies offline (openssl, or ``zs_bom_verify.py`` from
the evidence pack) or with ``POST .../runs/{id}/signature/verify``, which still accepts the code lane's HMAC
(``legacy_hmac``) of files signed before the ES256 key. The XML download is signed detached (``X-ZS-Signature``) and
the evidence pack signs its manifest (``bom_signing.pack_files``). ECDSA nonces are deterministic (RFC 6979), so a
finished run still downloads as the same bytes.

VEX (``run_vex``)
-----------------
CB-22 (``vex_semantics``, PR #134) owns which analysis a finding gets, and the run export's ``vulnerabilities``
(``inventory.vulnerabilities``) already carry it: state, detail, ``zs:vex_basis``, Q-grades, drift-resolved entries
and the ``affects`` cap with the true count. The run VEX takes those entries as they are and only overlays each
asset's remediation-plan status with ``vex_semantics.apply_plan_status`` (``done`` after collection = ``resolved``;
``accepted_risk`` = ``will_not_fix``; ``in_progress`` = ``update``); an entry whose assets get different overlays is
split into one entry per analysis. Nothing is re-judged by its code (``tests/test_cbom_cb22_vex.py`` holds the
contract). Affected assets are BOM-Links into the run CBOM (``urn:cdx:<serial>/1#zs-asset-<id>``), so the VEX travels
as a separate document. An active run is allowed everywhere, with an "as of" note (the run CBOM download treats active
runs the same way: it serves what has been collected so far and names the run status).
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
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Callable, Iterator

from sqlalchemy import func
from sqlmodel import Session, select

from backend.new_models import (
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSource,
    CbomScanNode,
)
from backend.utilities.cbom_sources import bom_signing as SIGN
from backend.utilities.cbom_sources import bom_verify as BV
from backend.utilities.cbom_sources import crypto_kb
from backend.utilities.cbom_sources import inventory as INV
from backend.utilities.cbom_sources import vex_semantics as VEX
from backend.utilities.cbom_sources.common import iso_z

PLAN_OVERLAY = "plan-1"  # the remediation-plan overlay on CB-22 rules (vex_semantics.apply_plan_status)
FINISHED = ("done", "partial", "failed", "cancelled")
PDF_FINDINGS_CAP = 500
SPOOL_BYTES = 8 * 1024 * 1024  # a file up to this size stays in memory; a larger one goes to a temp file
KEY_ID = "certin-hmac-1"  # the code lane's signing key id (routers/certin.py, cert_in/sign.py)
_VEX_NS = uuid.uuid5(uuid.NAMESPACE_URL, "https://zeroshield.ai/cbom/sources/run/vex")
_IMPACT_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

SIGNATURE_SCOPE = (
    "ES256 (ECDSA P-256, SHA-256) over the exact bytes of GET /{team}/cbom/sources/runs/{run}/cbom (format=json) as "
    "downloaded; the file also carries an embedded JSF signature. The public key is published at GET "
    "/{team}/bom-signing-keys and in the evidence pack: verify offline with openssl dgst -sha256 -verify <key.pem> "
    "-signature <signature as DER> <file>, or zs_bom_verify.py from the pack; or online with POST "
    "/{team}/cbom/sources/runs/{run}/signature/verify. The XML form (format=xml) is signed the same way: its detached "
    "signature is the X-ZS-Signature header of its download and bom.cdx.xml.sig in the evidence pack.")
LEGACY_SCOPE = (
    "HMAC-SHA256 over the exact bytes of GET /{team}/cbom/sources/runs/{run}/cbom (format=json) as downloaded. No "
    "asymmetric signing key is configured on this server: verify with POST "
    "/{team}/cbom/sources/runs/{run}/signature/verify, or check sha256(file) = digest.")


# ----------------------------------------------------------------------------- run identity and time
def is_active(run: CbomCollectionRun) -> bool:
    return run.status not in FINISHED


def _naive(moment: _dt.datetime) -> _dt.datetime:
    return moment if moment.tzinfo is None else moment.astimezone(_dt.timezone.utc).replace(tzinfo=None)


def stamp(session: Session, run: CbomCollectionRun, now: _dt.datetime) -> _dt.datetime:
    """The one time every deliverable of the run prints (module docstring): finished run: ``last_updated`` (else
    ``finished_at``, ``created_at``); active run: the newest asset it has stored, else (nothing stored yet) the run's
    ``last_updated``, so two requests a second apart still get the same bytes."""
    if not is_active(run):
        return _naive(run.last_updated or run.finished_at or run.created_at or now).replace(microsecond=0)
    newest = session.exec(select(func.max(CbomCollectedAsset.created_at)).where(
        CbomCollectedAsset.team_id == run.team_id, CbomCollectedAsset.run_id == run.id)).one()
    return _naive(newest or run.last_updated or run.created_at or now).replace(microsecond=0)


def as_of_note(run: CbomCollectionRun, at: _dt.datetime) -> str | None:
    """The sentence every deliverable carries for a run that is still collecting (None once it has finished)."""
    if not is_active(run):
        return None
    return (f"As of {iso_z(at)}: run #{run.id} is still {run.status}; this file holds what has been collected so far "
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


# ----------------------------------------------------------------------------- the export, one pass
Document = tuple[dict[str, Any], Iterator[dict[str, Any]], Callable[[], list[dict[str, Any]]]]


def document(session: Session, run: CbomCollectionRun, now: _dt.datetime) -> Document:
    """``inventory._document`` (head, components one at a time, vulnerabilities) with ``metadata.timestamp`` =
    ``stamp``, so the same run downloads as the same bytes."""
    head, components, vulns = INV._document(session, run, now)
    head["metadata"]["timestamp"] = iso_z(stamp(session, run, now))
    return head, components, vulns


def write_document(doc: Document, fmt: str, out: Any) -> dict[str, Any] | None:
    """``inventory.write_cyclonedx``'s writer (``cdx_write.write``) over ``doc``: JSON piece by piece with its embedded
    JSF signature, or XML (``test_run_cbom_bytes_are_inventorys_writer_with_a_stable_timestamp`` keeps the two equal).
    Returns the JSF signature written into the JSON (None for XML or without a key)."""
    from backend.utilities.cbom_sources import cdx_write

    head, components, vulns = doc
    return cdx_write.write(out, head, components, vulns, fmt)


def write_run_cbom(session: Session, run: CbomCollectionRun, now: _dt.datetime, fmt: str, out: BinaryIO) -> None:
    """Exactly the bytes ``GET .../runs/{id}/cbom`` serves (and, for JSON, the signature covers)."""
    write_document(document(session, run, now), fmt, out)


def props(head: dict[str, Any]) -> dict[str, str]:
    return {p.get("name"): p.get("value") for p in (head.get("metadata") or {}).get("properties") or []
            if isinstance(p, dict)}


def sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


@dataclass
class Summary:
    """What the VEX and the PDF need from one pass over the export: its head, its findings (the asset components
    whose ``zs:impact`` is a severity, worst first; small dicts, never the whole document) and its vulnerabilities."""
    head: dict[str, Any]
    findings: list[dict[str, Any]] = field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    refs: set[str] = field(default_factory=set)  # every bom-ref of the document (the VEX names only these)
    jsf: dict[str, Any] | None = None  # the JSF signature written into the JSON (None: XML, or no signing key)


def _collecting(doc: Document, summary: Summary) -> Document:
    """``doc`` again, filling ``summary`` while it is written (so the JSON write is also the summary pass)."""
    head, components, vulns = doc

    def comps() -> Iterator[dict[str, Any]]:
        for comp in components:
            if isinstance(comp.get("bom-ref"), str):
                summary.refs.add(comp["bom-ref"])
            p: dict[str, list[str]] = {}
            for prop in comp.get("properties") or []:
                p.setdefault(str(prop.get("name")), []).append(str(prop.get("value") or ""))
            impact = (p.get("zs:impact") or ["Info"])[0]
            if impact in _IMPACT_RANK:
                summary.findings.append({
                    "ref": comp.get("bom-ref"), "impact": impact, "name": comp.get("name"),
                    "type": (p.get("zs:asset_type") or [""])[0], "location": (p.get("zs:location") or [""])[0],
                    "source": (p.get("zs:source") or [""])[0], "finding": (p.get("zs:finding") or [""])[0]})
            yield comp
        summary.findings.sort(key=lambda r: (_IMPACT_RANK[r["impact"]], str(r["ref"])))

    def vulnerabilities() -> list[dict[str, Any]]:
        summary.vulnerabilities = vulns()
        return summary.vulnerabilities

    return head, comps(), vulnerabilities


def summary(session: Session, run: CbomCollectionRun, now: _dt.datetime) -> Summary:
    doc = document(session, run, now)
    out = Summary(head=doc[0])
    _head, components, vulns = _collecting(doc, out)
    for _component in components:
        pass
    vulns()
    return out


class Digests:
    """A write-through file: sha256 (and HMAC-SHA256 when given a key) of every byte written to ``out``."""

    def __init__(self, out: Any, secret: bytes | None = None):
        self.out, self.size = out, 0
        self.sha = hashlib.sha256()
        self.mac = hmac.new(secret, digestmod=hashlib.sha256) if secret else None

    def write(self, data: bytes) -> int:
        if self.out is not None:
            self.out.write(data)
        self.sha.update(data)
        if self.mac is not None:
            self.mac.update(data)
        self.size += len(data)
        return len(data)


def spool() -> BinaryIO:
    return tempfile.SpooledTemporaryFile(max_size=SPOOL_BYTES)  # type: ignore[return-value]


def written(session: Session, run: CbomCollectionRun, now: _dt.datetime, fmt: str, secret: bytes | None = None, *,
            keep: bool = True) -> tuple[BinaryIO | None, Summary, Digests]:
    """The run CBOM in ``fmt`` written once: to a temp file at its start (``keep``) or only digested, with its digests
    and, for JSON, the summary filled in the same pass."""
    out = spool() if keep else None
    try:
        doc = document(session, run, now)
        result = Summary(head=doc[0])
        tee = Digests(out, secret)
        result.jsf = write_document(_collecting(doc, result) if fmt == "json" else doc, fmt, tee)
        if out is not None:
            out.seek(0)
    except BaseException:
        if out is not None:
            out.close()
        raise
    return out, result, tee


# ----------------------------------------------------------------------------- signature
def run_signature(run: CbomCollectionRun, head: dict[str, Any], tee: Digests, at: _dt.datetime,
                  jsf: dict[str, Any] | None = None) -> dict[str, Any]:
    """The run CBOM JSON's signature document (``GET .../signature``): an ES256 detached signature (DER, base64) over
    the exact bytes ``tee`` saw, by the deployment's published key (``bom_signing``), the embedded JSF signature
    those bytes carry (``jsf``), the public key (PEM, JWK, fingerprint) and, while existing downloads may still rely
    on it, the code lane's HMAC (``legacy_hmac``; verified only by ``POST .../signature/verify``). Without a
    configured key: the HMAC fields alone, as before. ``signed_at`` is the run's ``stamp``."""
    common: dict[str, Any] = {
        "signed_at": iso_z(at), "covers": f"cbom-sources-run-{run.id}.cdx.json",
        "canonicalization": "none (the raw file bytes)",
        "serialNumber": head.get("serialNumber"),
        "document_timestamp": (head.get("metadata") or {}).get("timestamp"),
        "bytes": tee.size, "run_id": run.id, "run_status": run.status,
    }
    hmac_fields = ({"alg": "HMAC-SHA256", "key_id": KEY_ID,
                    "signature_b64": base64.b64encode(tee.mac.digest()).decode("ascii")} if tee.mac is not None else None)
    try:
        key = SIGN.keyring().active
    except SIGN.SigningUnavailable:
        key = None
    if key is None:
        if hmac_fields is None:
            raise RuntimeError("signing needs a key")
        signature: dict[str, Any] = {**hmac_fields, "digest": tee.sha.hexdigest(), **common,
                                     "scope": LEGACY_SCOPE.replace("{run}", str(run.id)).replace("{team}", str(run.team_id))}
    else:
        signature = {
            "alg": SIGN.ALG, "key_id": key.kid, "digest": tee.sha.hexdigest(),
            "signature_b64": base64.b64encode(SIGN.detached_digest(tee.sha.digest(), key)).decode("ascii"),
            "signature_format": "DER ECDSA (openssl dgst -sha256 -verify)",
            **common,
            "scope": SIGNATURE_SCOPE.replace("{run}", str(run.id)).replace("{team}", str(run.team_id)),
            "embedded": ({"format": "JSF 0.82 (CycloneDX 1.6 signature)", "algorithm": jsf.get("algorithm"),
                          "keyId": jsf.get("keyId"), "covers": "the JSON document without signature.value, in its "
                                                               "RFC 8785 (JCS) canonical form"} if jsf else None),
            "public_key_pem": key.pem(), "public_key_jwk": key.published(), "fingerprint": key.fingerprint(),
            "keys_route": SIGN.KEYS_ROUTE.replace("{team_id}", str(run.team_id)),
            **({"legacy_hmac": hmac_fields} if hmac_fields else {}),
        }
    note = as_of_note(run, at)
    if note:
        signature["as_of"] = note
    return signature


def signature_bytes(signature: dict[str, Any]) -> bytes:
    return json.dumps(signature, indent=2, ensure_ascii=False).encode("utf-8")


def _decode(sent_b64: str) -> bytes:
    try:
        return base64.b64decode(sent_b64.strip(), validate=True)
    except (ValueError, TypeError):
        return b""


def verify_upload(file_sha: str, file_mac: bytes, *, sent_b64: str | None, current: dict[str, Any] | None,
                  embedded: dict[str, Any] | None = None, run_id: int | None = None) -> dict[str, Any]:
    """The answer of ``POST .../signature/verify`` for an uploaded file (its sha256 and HMAC given):

    * ``sent_b64`` (``X-ZS-Signature-B64``): an ES256 DER signature (``signature_b64`` of today's signature document)
      checked against the published keys, or an HMAC (files signed before the ES256 key) checked with the server key;
    * else the file's own embedded JSF signature (``embedded``: ``bom_signing.verify_bom`` of the upload) when it is
      valid and the file says it is this run's (``zs:run_id``): a download of this run, unchanged since it was signed;
    * else the run's current CBOM JSON (``current``: its signature document).
    ``digest_match``: the file equals the run's current CBOM JSON (None when nothing was compared)."""
    digest_match = None if current is None else hmac.compare_digest(file_sha, str(current["digest"]))
    alg, key_id = (current or {}).get("alg") or "HMAC-SHA256", (current or {}).get("key_id") or KEY_ID
    if sent_b64 is not None:
        sent = _decode(sent_b64)
        signature_match, compared = False, "the signature sent with the file"
        if sent:
            es = None
            if SIGN.available():
                try:
                    es = SIGN.keyring()
                except SIGN.SigningUnavailable:
                    es = None
            checked = BV.verify_detached_digest(bytes.fromhex(file_sha), sent, es.verifier_keys()) if es else None
            if checked and checked["valid"]:
                signature_match, alg, key_id = True, SIGN.ALG, checked["kid"]
            elif hmac.compare_digest(sent, file_mac):
                signature_match, alg, key_id = True, "HMAC-SHA256", KEY_ID
    elif embedded is not None and embedded.get("valid") and embedded.get("run_id") == run_id:
        signature_match, compared = True, "the file's embedded JSF signature"
        alg, key_id = SIGN.ALG, embedded.get("kid") or key_id
    else:
        assert current is not None
        if current.get("alg") == SIGN.ALG:
            signature_match = bool(digest_match)  # the current signature is over the current bytes
        else:
            signature_match = hmac.compare_digest(base64.b64encode(file_mac).decode("ascii"),
                                                  str(current["signature_b64"]))
        compared = "the run's current CBOM JSON"
    out = {"valid": bool(signature_match), "signature_match": bool(signature_match), "digest_match": digest_match,
           "digest": file_sha, "key_id": key_id, "alg": alg, "compared_with": compared}
    if embedded is not None:
        out["embedded_signature"] = {k: embedded.get(k) for k in ("valid", "kid", "reason") if k in embedded}
    return out


# ----------------------------------------------------------------------------- VEX (CB-22 owns the semantics)
def asset_context(session: Session, run: CbomCollectionRun) -> dict[str, dict[str, Any]]:
    """Per asset (by its CBOM bom-ref): its remediation-plan status and the plan's last change (``waves.node_items``,
    the run's assignment join), and when this run collected it (for ``vex_semantics.apply_plan_status``)."""
    from backend.utilities.cbom_sources.waves import _assignments, node_items

    collected = dict(session.exec(select(CbomCollectedAsset.id, CbomCollectedAsset.created_at).where(
        CbomCollectedAsset.team_id == run.team_id, CbomCollectedAsset.run_id == run.id)).all())
    items = node_items(session, run.team_id, run)
    plans = _assignments(session, run.team_id, (i["asset_key"] for i in items))  # full-precision plan times
    out: dict[str, dict[str, Any]] = {}
    for item in items:
        plan = plans.get(item["asset_key"])
        out[f"zs-asset-{item['asset_id']}"] = {"status": plan.status if plan else None,
                                               "changed": plan.last_updated if plan else None,
                                               "collected": collected.get(item["asset_id"]),
                                               "asset_key": item["asset_key"]}
    return out


def run_vex(run: CbomCollectionRun, data: Summary, context: dict[str, dict[str, Any]], at: _dt.datetime
            ) -> dict[str, Any]:
    """The run's VEX: the export's ``vulnerabilities`` (``inventory.vulnerabilities``, CB-22 ``vex_semantics``: state,
    detail, ``zs:vex_basis``, Q-grades, cut ``affects``) taken as they are, with each asset's remediation-plan status
    overlaid by ``vex_semantics.apply_plan_status``. An entry whose assets get different plan analyses is split into one
    entry per analysis; nothing is re-judged by its code and no property is added to an entry. Its timestamp: the later
    of ``at`` and the newest plan change among the run's assets (its content changes with the plan)."""
    head = data.head
    serial = str(head.get("serialNumber") or "")
    version = head.get("version") or 1
    out: list[dict[str, Any]] = []
    pairs: dict[str, int] = {}
    dropped = 0
    for vuln in data.vulnerabilities:
        base = vuln.get("analysis") or {}
        groups: dict[str, tuple[dict[str, Any], list[str]]] = {}
        listed = vuln.get("affects") or []
        for affected in listed:
            ref = str(affected.get("ref") or "")
            # D11: only components of the BOM (a bare ref the CBOM does not hold is dropped), or a BOM-Link the export
            # already made into another BOM (a drift-resolved asset gone since its baseline run), kept as it is
            if not ref.startswith("urn:cdx:") and data.refs and ref not in data.refs:
                dropped += 1
                continue
            ctx = context.get(ref) or {}
            analysis = VEX.apply_plan_status(base, ctx.get("status"), plan_changed_at=ctx.get("changed"),
                                             collected_at=ctx.get("collected"))
            groups.setdefault(json.dumps(analysis, sort_keys=True), (analysis, []))[1].append(ref)
        if not groups:
            if listed:  # every asset it named is outside the BOM: the VEX does not state it
                continue
            groups[""] = (dict(base), [])  # an entry without listed assets keeps its own analysis
        for index, (analysis, refs) in enumerate(groups.values()):
            entry = {k: v for k, v in vuln.items() if k not in ("analysis", "affects", "bom-ref")}
            if index or analysis != base:
                suffix = analysis["state"] + ("-" + "-".join(analysis["response"]) if analysis.get("response") else "")
                entry["bom-ref"] = f"{vuln.get('bom-ref') or str(vuln.get('id')).lower()}-{suffix}-{index}"
            elif vuln.get("bom-ref"):
                entry["bom-ref"] = vuln["bom-ref"]
            entry["analysis"] = analysis
            entry["affects"] = [{"ref": r if r.startswith("urn:cdx:") else VEX.bom_link(serial, version, r)}
                                for r in refs]
            pairs[analysis["state"]] = pairs.get(analysis["state"], 0) + len(refs)
            out.append(entry)
    meta = props(head)
    note = as_of_note(run, at)
    changes = [iso_z(c["changed"]) or "" for c in context.values() if c.get("changed")]
    timestamp = max([iso_z(at) or "", *changes])
    vex_props = [
        {"name": "zs:vex_rules", "value": f"{VEX.VEX_RULES}+{PLAN_OVERLAY}"},
        {"name": "zs:run_id", "value": str(run.id)},
        {"name": "zs:run_status", "value": run.status},
        {"name": "zs:bom_serial", "value": serial},
        {"name": "zs:kb_version", "value": meta.get("zs:kb_version") or crypto_kb.version()},
        {"name": "zs:truncated", "value": meta.get("zs:truncated") or "false"},
        *([{"name": "zs:export_cap", "value": f"The CBOM holds the first {INV.EXPORT_CAP:,} assets of this run; "
                                               "assets past the cap are not judged here."}]
          if meta.get("zs:truncated") == "true" else []),
        *([{"name": "zs:as_of", "value": note}] if note else []),
        *[{"name": f"zs:pairs_{state}", "value": str(n)} for state, n in sorted(pairs.items())],
        *([{"name": "zs:affects_not_in_bom", "value": str(dropped)}] if dropped else []),
    ]
    digest = hashlib.sha256(json.dumps(out, sort_keys=True).encode()).hexdigest()
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(_VEX_NS, f'{serial}:{VEX.VEX_RULES}:{digest}')}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {"components": [{"type": "application", "name": "ZeroShield CBOM Sources VEX",
                                      "version": f"{VEX.VEX_RULES}+{PLAN_OVERLAY}"}]},
            "properties": vex_props,
        },
        "vulnerabilities": out,
    }


def vex_bytes(vex: dict[str, Any]) -> bytes:
    return json.dumps(vex, indent=2, ensure_ascii=False).encode("utf-8")


def vex_states(vex: dict[str, Any]) -> dict[str, int]:
    """(finding, asset) pairs per analysis state, as the VEX metadata counts them."""
    return {p["name"][len("zs:pairs_"):]: int(p["value"]) for p in vex["metadata"]["properties"]
            if p["name"].startswith("zs:pairs_") and p["value"].isdigit()}


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
# Files whose route answers with the same bytes on every request (finished run, same day, same build). OSCAL's route
# stamps last-modified with the request time; the pack's copy carries the run's stamp instead.
REPRODUCIBLE = {"bom.cdx.json": True, "bom.cdx.xml": True, "oscal-assessment-results.json": False, "vex.json": True,
                "bom_signature.json": True, "report.pdf": True}


def evidence_pack(*, run: CbomCollectionRun, sources: list[dict[str, Any]], at: _dt.datetime,
                  files: list[PackFile], omitted: list[dict[str, str]], head: dict[str, Any],
                  signature: dict[str, Any] | None, logo_sha256: str | None = None) -> BinaryIO:
    """Zip of ``files`` plus ``manifest.json`` with the sha256 of each, written to a temp file (at its start). Large
    files (the CycloneDX JSON and XML) are copied in from their temp files, never held whole in memory. Every time in
    it (manifest, zip entries) is ``at``: a finished run's pack is the same bytes on every download.

    Inputs: the run's rows, the day's judgement and build, and (``logo_sha256``) the team's report logo drawn in
    report.pdf. The logo is recorded only when one is set, so a team without one gets today's manifest exactly."""
    meta = props(head)
    entries = []
    for name, body, media, endpoint in files:
        digest, size = (sha256(body), len(body)) if isinstance(body, bytes) else (body[1].sha.hexdigest(), body[1].size)
        entries.append({"name": name, "sha256": digest, "bytes": size, "media_type": media, "endpoint": endpoint,
                        "endpoint_same_bytes": REPRODUCIBLE.get(name, False) and not is_active(run)})
    manifest: dict[str, Any] = {
        "format": "zeroshield-cbom-run-evidence-pack/1",
        "generated_at": iso_z(at),
        "run": {"id": run.id, "status": run.status, "active": is_active(run), "created_at": iso_z(run.created_at),
                "finished_at": iso_z(run.finished_at), "last_updated": iso_z(run.last_updated),
                "sources": sources,
                "versions": {"kb": run.kb_version, "classifier": run.classifier_version, "engine": run.engine_version}},
        "inputs": {"bom_serial": head.get("serialNumber"),
                   "bom_timestamp": (head.get("metadata") or {}).get("timestamp"),
                   "kb_version": meta.get("zs:kb_version"), "build": meta.get("zs:build"),
                   "judged_on": meta.get("zs:judged_on"), "asset_count": int(meta.get("zs:asset_count") or 0),
                   "export_cap": INV.EXPORT_CAP, "truncated": meta.get("zs:truncated") == "true",
                   "vex_rules": f"{VEX.VEX_RULES}+{PLAN_OVERLAY}",
                   **({"logo_sha256": logo_sha256} if logo_sha256 else {})},
        "files": entries,
        "endpoint_note": ("endpoint_same_bytes: the route answers with these exact bytes again (finished run; the "
                          "same day's judgement and build"
                          + ("; for report.pdf, the same team report logo" if logo_sha256 else "")
                          + "). OSCAL's route stamps last-modified with the request time; "
                          "this copy carries the run's time."),
        "omitted": omitted,
        "signature": ({"covers": "bom.cdx.json", "alg": signature.get("alg"), "key_id": signature.get("key_id"),
                       "digest": signature.get("digest")} if signature else None),
    }
    note = as_of_note(run, at)
    if note:
        manifest["as_of"] = note
    if manifest["inputs"]["truncated"]:
        manifest["export_cap_note"] = (f"The CBOM holds the first {INV.EXPORT_CAP:,} assets of this run; the files "
                                       "in this pack cover those assets only.")
    # D11: signed, so a client verifies the pack offline: keys/, verify/, the .sig of both BOM files, and the manifest
    # (every file's sha256, these too) with its own detached signature, SHA256SUMS likewise (bom_signing.pack_files)
    hashed = [(name, (sha256(body), len(body)) if isinstance(body, bytes) else (body[1].sha.hexdigest(), body[1].size))
              for name, body, _media, _endpoint in files]
    try:
        added = SIGN.pack_files(hashed, subject={"kind": "cbom-sources-run", "run_id": run.id, "team_id": run.team_id},
                                detached_for=("bom.cdx.json", "bom.cdx.xml"),
                                manifest_extra={**manifest, "format": "zeroshield-cbom-run-evidence-pack/2"})
    except SIGN.SigningUnavailable:
        added = [("manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8"))]
    out = spool()
    when = (max(at.year, 1980), at.month, at.day, at.hour, at.minute, at.second)
    try:
        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for name, body, _media, _endpoint in files:
                info = zipfile.ZipInfo(name, date_time=when)
                info.compress_type = zipfile.ZIP_DEFLATED
                if isinstance(body, bytes):
                    zf.writestr(info, body)
                    continue
                with zf.open(info, "w", force_zip64=True) as dest:
                    shutil.copyfileobj(body[0], dest, 1024 * 1024)
            for name, body in added:
                info = zipfile.ZipInfo(name, date_time=when)
                info.compress_type = zipfile.ZIP_DEFLATED
                zf.writestr(info, body)
        out.seek(0)
    except BaseException:
        out.close()
        raise
    return out
