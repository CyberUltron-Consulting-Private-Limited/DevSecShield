"""The team's certificate estate as ONE list of unique certificates (SOW D8; CB-38 Rule P).

``unique_certificates(view)`` is the only function that decides which certificates the team has and how many there
are. The Certificate Estate Register (D8) PDF and CSV print its rows and the Network, TLS and Crypto Protocol
Assessment (D7) prints its count, so the three numbers cannot disagree. The estate hygiene list
(``cert_hygiene``) keys and filters its rows with ``thumbprint`` / ``is_certificate_record`` from here too.

Identity: a certificate is the same certificate when its SHA-256 thumbprint (the DER fingerprint) is the same. Rows
without a thumbprint are joined through the cross-source asset key ``collections_view.link_certificates`` gave them
(serial + notAfter, SHA-1 thumbprint, DN + notAfter: ``asset_keys``), and a cloud CA without either (an AWS Private CA
whose certificate could not be read) through its resource ARN, which is unique in the world. Code-scan certificates
(CN-only names, no thumbprint) keep the identity the team roll-up gave them.

What is in the set: the certificate rows of each source's latest completed collection (``collections_view``) and the
current code-scan certificates of the roll-up (``TeamCbomView.certs``). Not in the set:

* a trust-store bundle row (``/etc/ssl/certs/ca-certificates.crt``: ``trust_store`` facts, a count of 120 roots, no
  subject): it is a summary of a file, not a certificate;
* a certificate seen only by a source that has since been deleted (counted in ``EstateResult.deleted_only``; the
  documents say how many were left out).

Pure apart from ``load_inputs`` (one small read of the jobs' owner metadata). No clock: expiry is computed against
``view.as_of``.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from backend.utilities.dashboard.cbom_team_rollup import (
    EXPIRED,
    IMPACT_LEVELS,
    LE_30,
    LE_90,
    UNKNOWN,
    CertAgg,
    ExpiryBand,
    TeamCbomView,
    classify_expiry,
)

CERT_NODE_TYPES = frozenset({"certificate", "k8s_certificate", "cloud_ca"})
DELETED_SOURCE = "deleted source"
STATUS_TEXT = {EXPIRED: "expired", LE_30: "expiring <=30 d", LE_90: "expiring <=90 d", "VALID": "valid",
               UNKNOWN: "unknown"}
_HEX = re.compile(r"^[0-9a-f]+$")
_CHAIN_INDEX = re.compile(r"#chain\[(\d+)\]")
_SEVERITY = {level: rank for rank, level in enumerate(IMPACT_LEVELS)}  # Critical 0 ... Low 3


# ----------------------------------------------------------------------------- shared normalisers
def thumbprint(facts: Mapping[str, Any] | None) -> str:
    """The SHA-256 thumbprint (lower-case hex, 64 characters) a row records, or "" (never computed or guessed)."""
    if not isinstance(facts, Mapping):
        return ""
    for value in (facts.get("fingerprint_sha256"), facts.get("certificate_sha256"), facts.get("sha256")):
        text = re.sub(r"[\s:]", "", str(value or "")).lower()
        if text.startswith("sha256"):
            text = ""  # an OpenSSH "SHA256:<base64>" key fingerprint is not a certificate thumbprint
        if len(text) == 64 and _HEX.match(text):
            return text
    return ""


def is_certificate_record(facts: Mapping[str, Any] | None) -> bool:
    """False for a row that summarises a trust-store FILE (``trust_store``: a bundle of N roots) rather than holding
    one certificate; such a row has no subject, issuer, serial, thumbprint or validity of its own."""
    if not isinstance(facts, Mapping):
        return True
    if facts.get("trust_store") is True and not (facts.get("subject") or facts.get("serial") or thumbprint(facts)):
        return False
    return True


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, Mapping):  # an AWS Subject dict that reached a fact unformatted
        return dn_from_mapping(value)
    return " ".join(str(value).split())


# AWS Private CA ASN1Subject member -> RFC 4514 attribute (order: most to least significant, as AWS prints it)
_AWS_DN = (("Country", "C"), ("State", "ST"), ("Locality", "L"), ("Organization", "O"),
           ("OrganizationalUnit", "OU"), ("DistinguishedNameQualifier", "dnQualifier"), ("Title", "title"),
           ("Surname", "SN"), ("GivenName", "GN"), ("Initials", "initials"), ("Pseudonym", "pseudonym"),
           ("GenerationQualifier", "generationQualifier"), ("SerialNumber", "serialNumber"), ("CommonName", "CN"))


def _escape_rdn(value: str) -> str:
    text = value.replace("\\", "\\\\")
    for ch in (",", "+", '"', "<", ">", ";", "="):
        text = text.replace(ch, "\\" + ch)
    if text.startswith((" ", "#")):
        text = "\\" + text
    if text.endswith(" "):
        text = text[:-1] + "\\ "
    return text


def dn_from_mapping(subject: Mapping[str, Any] | None) -> str:
    """An AWS ``ASN1Subject`` dict as an RFC 4514 DN, CN first (``CN=Root,O=Bank,C=IN``); custom attributes by OID."""
    if not isinstance(subject, Mapping):
        return ""
    parts = []
    for member, attr in _AWS_DN:
        value = subject.get(member)
        if isinstance(value, str) and value.strip():
            parts.append(f"{attr}={_escape_rdn(value.strip())}")
    for custom in subject.get("CustomAttributes") or []:
        if isinstance(custom, Mapping) and custom.get("ObjectIdentifier") and custom.get("Value"):
            parts.append(f"{custom['ObjectIdentifier']}={_escape_rdn(str(custom['Value']))}")
    return ",".join(reversed(parts))


# ----------------------------------------------------------------------------- inputs
@dataclass(frozen=True)
class EstateInputs:
    """What the deliverables read from the Sources side beyond the roll-up: every row of each source's latest
    completed collection (``collections_view.SourcesRow``, facts included) and the owner each source names."""

    rows: tuple[Any, ...] = ()
    owners: Mapping[str, str] = field(default_factory=dict)  # source_ref -> owner (job metadata, else source config)


def load_inputs(session: Any, team_id: int, found: Any) -> EstateInputs:
    """``found``: the ``collections_view.SourcesResult`` the roll-up already loaded (no second asset read)."""
    from sqlmodel import select

    from backend.new_models import CbomCollectionJob, CbomCollectionSource

    rows = tuple(getattr(found, "rows", ()) or ())
    job_ids = sorted({int(c.job_id) for c in getattr(found, "collections", ()) or ()})
    owners: dict[str, str] = {}
    if job_ids:
        sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
            CbomCollectionSource.team_id == team_id)).all()}
        refs = {int(c.job_id): c.source_ref for c in found.collections}
        for start in range(0, len(job_ids), 500):
            for job in session.exec(select(CbomCollectionJob).where(
                    CbomCollectionJob.team_id == team_id,
                    CbomCollectionJob.id.in_(job_ids[start:start + 500]))).all():  # type: ignore[union-attr]
                params = job.params if isinstance(job.params, dict) else {}
                meta = params.get("metadata") if isinstance(params.get("metadata"), dict) else None
                if meta is None:
                    source = sources.get(job.source_id or 0)
                    config = source.config if source is not None and isinstance(source.config, dict) else {}
                    meta = config.get("metadata") if isinstance(config.get("metadata"), dict) else config
                owner = str((meta or {}).get("owner") or "").strip()
                if owner:
                    owners[refs[int(job.id)]] = owner[:120]
    return EstateInputs(rows=rows, owners=owners)


def inputs_of(view: TeamCbomView) -> EstateInputs:
    found = getattr(view, "estate", None)
    return found if isinstance(found, EstateInputs) else EstateInputs()


def is_deleted(collection: Any) -> bool:
    """A collection whose source no longer exists (``Collection.source_kind`` is "" for a deleted source)."""
    return not str(getattr(collection, "source_kind", "") or "")


# ----------------------------------------------------------------------------- the estate
@dataclass(frozen=True)
class Sighting:
    """One place a certificate was seen."""

    source: str  # "Sources run #52 · Lab network" or a code-scan source label
    location: str  # host:port#chain[0], a file path, an ARN
    source_ref: str = ""


@dataclass(frozen=True)
class EstateCert:
    """One unique certificate. ``cert`` is the register row the PDF draws (a ``CertAgg``)."""

    key: str  # "sha256:<hex>" when the thumbprint is known, else the identity it was joined on
    thumbprint: str
    serial: str
    subject: str
    issuer: str
    sans: tuple[str, ...]
    key_algorithm: str
    key_size: str
    curve: str
    signature_algorithm: str
    not_before: str
    not_after: str
    band: ExpiryBand
    is_ca: bool | None
    self_signed: bool | None
    chain_position: str  # leaf | intermediate | root | unknown
    issuer_thumbprint: str  # thumbprint of the issuing certificate when it is in the estate, else ""
    sightings: tuple[Sighting, ...]
    owners: tuple[str, ...]
    pqc_class: str
    impact: str
    finding_codes: tuple[str, ...]
    origin: str  # "sources" | "code_scan" | "both"
    cert: CertAgg

    @property
    def status(self) -> str:
        return STATUS_TEXT.get(self.band.band, "unknown")

    @property
    def days_left(self) -> int | None:
        return self.band.days_left

    @property
    def sources(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(s.source for s in self.sightings))

    @property
    def locations(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(s.location for s in self.sightings if s.location))


@dataclass(frozen=True)
class EstateResult:
    certificates: tuple[EstateCert, ...]
    deleted_only: int = 0  # certificates seen only by deleted sources (left out)
    bundles_skipped: int = 0  # trust-store bundle rows (not certificates)

    def __len__(self) -> int:
        return len(self.certificates)

    @property
    def served(self) -> int:
        """Certificates a probed endpoint presented (``host:port#chain[i]``)."""
        return sum(1 for c in self.certificates if any("#chain[" in loc for loc in c.locations))


class _Groups:
    """Union-find over string keys: rows sharing any key are one certificate."""

    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, key: str) -> str:
        self.parent.setdefault(key, key)
        while self.parent[key] != key:
            self.parent[key] = self.parent[self.parent[key]]
            key = self.parent[key]
        return key

    def union(self, keys: Sequence[str]) -> str:
        roots = [self.find(k) for k in keys]
        head = min(roots)
        for root in roots:
            self.parent[root] = head
        return head


def _row_keys(item: Any) -> list[str]:
    facts = item.facts if isinstance(item.facts, Mapping) else {}
    keys = []
    fp = thumbprint(facts)
    if fp:
        keys.append("sha256:" + fp)
    identity = str(getattr(item, "identity", "") or "")
    if identity.startswith("cert:"):
        keys.append("id:" + identity)  # the CB-21 cross-source key (serial, SHA-1 thumbprint, DN + notAfter)
    location = str(item.row.get("location") or "") if isinstance(getattr(item, "row", None), Mapping) else ""
    if location.startswith("arn:") and getattr(item, "node_type", "") == "cloud_ca":
        keys.append("arn:" + location.split("#", 1)[0])  # a cloud CA is one resource whichever source read it
    if not keys:
        keys.append("id:" + identity)
    return keys


def _chain_index(location: str) -> int | None:
    match = _CHAIN_INDEX.search(location or "")
    return int(match.group(1)) if match else None


def _tri(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _chain_position(is_ca: bool | None, self_signed: bool | None, indexes: Iterable[int]) -> str:
    if self_signed and is_ca is not False:
        return "root"
    if is_ca is True:
        return "intermediate"
    found = [i for i in indexes if i is not None]
    if is_ca is False or (found and min(found) == 0):
        return "leaf"
    if found:
        return "intermediate"
    return "unknown"


def _pqc_class(node_type: str, key_alg: str, row: Mapping[str, Any] | None, facts: Mapping[str, Any],
               codes: Sequence[str]) -> str:
    """``posture.classify_pqc`` (the one class function of the run pages) for a Sources row; for a code-scan
    certificate, its public-key family."""
    if row is not None:
        try:
            from backend.utilities.cbom_sources.posture import classify_pqc

            safe = row.get("quantum_safe")
            found = classify_pqc({"asset_type": node_type, "quantum_vulnerable": None if safe is None else not safe,
                                  "facts": dict(facts), "algorithm": row.get("algorithm_name")}, list(codes))[0]
            if found != "unknown":
                return found
        except Exception:  # a class never costs a certificate its row
            pass
    # no stored verdict: the public-key family decides (RSA / EC keys are broken by Shor's algorithm)
    from backend.utilities.cbom_sources import algid

    verdict = algid.quantum_vulnerable(key_alg)  # the CB-04 single source of algorithm identity
    return "quantum-vulnerable" if verdict is True else ("quantum-safe" if verdict is False else "unknown")


def _worst_impact(impacts: Iterable[str | None]) -> str:
    ranked = [i for i in impacts if i in _SEVERITY]
    return min(ranked, key=lambda i: _SEVERITY[i]) if ranked else "Info"


_AWS_KEY_ENUM = re.compile(r"^(RSA|EC|ECDSA|SM2)[_-]?(.*)$", re.I)
_CURVE_BITS = {"prime256v1": "256", "secp256r1": "256", "secp384r1": "384", "secp521r1": "521", "p256": "256",
               "p384": "384", "p521": "521"}


def key_family(raw: str, size: str, curve: str) -> tuple[str, str, str]:
    """(family, size, curve) with a cloud enum such as AWS ``RSA_2048`` / ``EC_secp384r1`` read as what it means
    (``RSA``, ``2048``); other names (post-quantum ones included) pass through unchanged."""
    match = _AWS_KEY_ENUM.match(raw or "")
    if not match or not match.group(2):
        return raw, size, curve
    family, rest = match.group(1).upper(), match.group(2)
    if family == "RSA" and rest.isdigit():
        return "RSA", size or rest, curve
    if family in ("EC", "ECDSA"):
        return "EC", size or _CURVE_BITS.get(rest.casefold(), ""), curve or rest
    return raw, size, curve


def _dn_first(values: Iterable[Any]) -> str:
    """The first value written as a DN (``CN=...,O=...``), else the first non-empty one: ACM names the issuer
    "Amazon" where the probe read the full DN of the same certificate."""
    texts = [t for t in (_text(v) for v in values) if t]
    return next((t for t in texts if "=" in t), texts[0] if texts else "")


def _first(values: Iterable[Any]) -> str:
    for value in values:
        text = _text(value)
        if text:
            return text
    return ""


def _sans(facts_list: Iterable[Mapping[str, Any]]) -> tuple[str, ...]:
    out: list[str] = []
    for facts in facts_list:
        for value in facts.get("san") or facts.get("sans") or []:
            text = _text(value)
            if text and text not in out:
                out.append(text)
    return tuple(out[:100])


def _from_sources(view: TeamCbomView, inputs: EstateInputs) -> tuple[list[dict[str, Any]], int, int]:
    """Group the Sources certificate rows; returns (groups, deleted-only groups, bundle rows skipped)."""
    groups = _Groups()
    members: list[tuple[str, Any]] = []
    bundles = 0
    for item in inputs.rows:
        node_type = str(getattr(item, "node_type", "") or "")
        row = item.row if isinstance(getattr(item, "row", None), Mapping) else {}
        if node_type not in CERT_NODE_TYPES and row.get("algorithm_type") != "certificate":
            continue
        if not is_certificate_record(item.facts):
            bundles += 1
            continue
        members.append((groups.union(_row_keys(item)), item))
    by_root: dict[str, list[Any]] = {}
    for _head, item in members:
        by_root.setdefault(groups.find(_row_keys(item)[0]), []).append(item)
    out, deleted_only = [], 0
    for items in by_root.values():
        live = [i for i in items if not is_deleted(i.collection)]
        if not live:
            deleted_only += 1
            continue
        live.sort(key=lambda i: (i.collection.observed_at, i.collection.job_id), reverse=True)
        out.append({"items": live})
    return out, deleted_only, bundles


def _code_src_key(identity: str) -> str:
    """The ``CertAgg.key`` ``merge_collections`` gives the certificate whose winning row has ``identity``."""
    return "src:" + hashlib.sha256(identity.encode("utf-8", "replace")).hexdigest()[:16]


def _estate_from_group(view: TeamCbomView, inputs: EstateInputs, items: Sequence[Any],
                       aggs: Mapping[str, CertAgg]) -> EstateCert:
    head = items[0]
    facts_list = [i.facts if isinstance(i.facts, Mapping) else {} for i in items]
    pick = lambda *names: _first(f.get(n) for f in facts_list for n in names)  # noqa: E731 - newest row first
    fp = next((thumbprint(f) for f in facts_list if thumbprint(f)), "")
    subject = _dn_first(f.get("subject") for f in facts_list) or _text(head.row.get("title"))
    issuer = _dn_first(f.get("issuer") for f in facts_list)
    serial_raw = pick("serial", "serial_number")
    from backend.utilities.cbom_sources.asset_keys import norm_serial

    serial = norm_serial(serial_raw) or serial_raw
    key_alg, key_size, curve = key_family(pick("key_alg"), pick("key_size") or _text(head.row.get("key_size")),
                                          pick("curve"))
    not_after = pick("not_after")
    codes = tuple(dict.fromkeys(c for i in items for c in (i.row.get("finding_codes") or []) if isinstance(c, str)))
    impact = _worst_impact(i.row.get("impact") for i in items)
    sightings = tuple(dict.fromkeys(Sighting(i.collection.label, str(i.row.get("location") or ""),
                                             i.collection.source_ref) for i in items))
    merged = next((aggs[k] for k in (_code_src_key(str(i.identity)) for i in items) if k in aggs), None)
    if merged is not None:  # earlier code-scan locations of the same certificate (merge_collections kept them)
        extra = [Sighting(label, path) for label, path in merged.locations
                 if not any(s.location == path for s in sightings)]
        sightings = sightings + tuple(extra)
    is_ca = next((_tri(f.get("is_ca")) for f in facts_list if _tri(f.get("is_ca")) is not None), None)
    self_signed = next((_tri(f.get("self_signed")) for f in facts_list if _tri(f.get("self_signed")) is not None),
                       None)
    band = classify_expiry(not_after or None, view.as_of)
    cert = merged or CertAgg(key=_code_src_key(str(head.identity)), identity_strong=bool(fp or subject),
                             name=subject or str(head.row.get("title") or ""))
    cert = CertAgg(
        key=cert.key, identity_strong=bool(fp) or cert.identity_strong, name=cert.name or subject,
        file_names=tuple(dict.fromkeys([s.location for s in sightings if s.location])),
        subject_cn=subject or None, issuer_cn=issuer or None, not_before=pick("not_before") or None,
        not_after=not_after or None, public_key_algorithm=key_alg or None, key_size=key_size or None,
        curve=curve or None, signature_algorithm=pick("sig_alg", "signature_algorithm") or None,
        self_signed=self_signed, is_ca=is_ca, expiry=band, impact=impact, finding_codes=codes, tier=cert.tier or "A",
        source_keys=tuple(dict.fromkeys(i.collection.key for i in items)),
        current_source_keys=tuple(dict.fromkeys(i.collection.key for i in items)),
        locations=_grouped(sightings)[:12], locations_total=len(_grouped(sightings)),
        current=True, first_seen=min([i.collection.observed_at for i in items] + (
            [merged.first_seen] if merged is not None and merged.first_seen else [])),
        last_seen=head.collection.observed_at, scan_count=len({i.collection.job_id for i in items}),
        scan_ids=(), latest_scan_id=None)
    owners = tuple(sorted({inputs.owners[s.source_ref] for s in sightings if s.source_ref in inputs.owners}))
    return EstateCert(
        key=("sha256:" + fp) if fp else _row_keys(head)[0], thumbprint=fp,
        serial=serial, subject=subject, issuer=issuer, sans=_sans(facts_list),
        key_algorithm=key_alg, key_size=key_size, curve=curve,
        signature_algorithm=pick("sig_alg", "signature_algorithm"), not_before=pick("not_before"),
        not_after=not_after, band=band, is_ca=is_ca, self_signed=self_signed,
        chain_position=_chain_position(is_ca, self_signed, (_chain_index(s.location) for s in sightings)),
        issuer_thumbprint="", sightings=sightings, owners=owners,
        pqc_class=_pqc_class(str(head.node_type), key_alg, head.row, facts_list[0], codes),
        impact=impact, finding_codes=codes, origin="both" if merged is not None and merged.locations_total > 1
        and any(not str(k).startswith("sources:") for k in merged.source_keys) else "sources", cert=cert)


def _grouped(sightings: Sequence[Sighting]) -> tuple[tuple[str, str], ...]:
    """(sources, location) per distinct location, newest first: one ARN read by two AWS sources is one place."""
    by_place: dict[str, list[str]] = {}
    for s in sightings:
        by_place.setdefault(s.location, [])
        if s.source not in by_place[s.location]:
            by_place[s.location].append(s.source)
    return tuple(("; ".join(sources), place) for place, sources in by_place.items())


def _estate_from_code(view: TeamCbomView, cert: CertAgg) -> EstateCert:
    band = classify_expiry(cert.not_after, view.as_of)
    sightings = tuple(Sighting(label, path) for label, path in cert.locations)
    key_alg = cert.public_key_algorithm or ""
    return EstateCert(
        key="code:" + cert.key, thumbprint="", serial="", subject=cert.subject_cn or cert.name,
        issuer=cert.issuer_cn or "", sans=(), key_algorithm=key_alg, key_size=cert.key_size or "",
        curve=cert.curve or "", signature_algorithm=cert.signature_algorithm or "", not_before=cert.not_before or "",
        not_after=cert.not_after or "", band=band, is_ca=cert.is_ca, self_signed=cert.self_signed,
        chain_position=_chain_position(cert.is_ca, cert.self_signed, ()), issuer_thumbprint="",
        sightings=sightings, owners=(), pqc_class=_pqc_class("certificate", key_alg, None, {}, cert.finding_codes),
        impact=cert.impact, finding_codes=tuple(cert.finding_codes), origin="code_scan", cert=cert)


def _link_issuers(certs: list[EstateCert]) -> list[EstateCert]:
    """Fill ``issuer_thumbprint`` where exactly one CA certificate in the estate has the issuer's DN as subject."""
    from dataclasses import replace

    from backend.utilities.cbom_sources.asset_keys import norm_dn

    by_subject: dict[str, set[str]] = {}
    for c in certs:
        if c.thumbprint and c.subject and c.is_ca is not False:
            by_subject.setdefault(norm_dn(c.subject), set()).add(c.thumbprint)
    out = []
    for c in certs:
        found = by_subject.get(norm_dn(c.issuer), set()) - ({c.thumbprint} if not c.self_signed else set())
        if c.self_signed and c.thumbprint:
            found = {c.thumbprint}
        out.append(replace(c, issuer_thumbprint=next(iter(found))) if len(found) == 1 and c.issuer else c)
    return out


def unique_certificates(view: TeamCbomView) -> EstateResult:
    """THE certificate set of the team (Rule P): every unique current certificate, sorted by key.

    Without Sources inputs on the view (a hand-built view, or a team without Sources) it is the roll-up's current
    certificates, one per ``CertAgg``."""
    inputs = inputs_of(view)
    aggs = {c.key: c for c in view.certs}
    groups, deleted_only, bundles = _from_sources(view, inputs) if inputs.rows else ([], 0, 0)
    certs = [_estate_from_group(view, inputs, g["items"], aggs) for g in groups]
    covered = {c.cert.key for c in certs}
    for cert in view.certs:
        if not cert.current or cert.key in covered:
            continue
        if cert.key.startswith("src:") and inputs.rows:
            continue  # a Sources certificate: built from its rows above (or seen only by a deleted source)
        certs.append(_estate_from_code(view, cert))
    certs = _link_issuers(certs)
    certs.sort(key=lambda c: c.key)
    return EstateResult(certificates=tuple(certs), deleted_only=deleted_only, bundles_skipped=bundles)


def count_phrase(count: int) -> str:
    """The one wording every document uses for the number (``159 unique certificates``)."""
    return f"{count} unique certificate" + ("" if count == 1 else "s")


__all__ = ["CERT_NODE_TYPES", "DELETED_SOURCE", "EstateCert", "EstateInputs", "EstateResult", "Sighting",
           "count_phrase", "dn_from_mapping", "inputs_of", "is_certificate_record", "is_deleted", "load_inputs",
           "thumbprint", "unique_certificates"]
