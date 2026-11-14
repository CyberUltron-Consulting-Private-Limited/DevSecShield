"""Post-quantum and risk posture of one collection run, computed from the stored assets (no model, no network).

* PQC class per asset: quantum-vulnerable (Shor breaks it), hybrid (a post-quantum key exchange is accepted next to
  the classical one), quantum-safe (symmetric, hash or post-quantum), grover-weakened (128-bit symmetric keys),
  not-applicable (inventory without a public-key algorithm, such as a database setting).
* PQC readiness: share of assets with a quantum verdict that are not quantum-vulnerable (the one definition every CBOM
  view uses: ``cbom_metrics.quantum_readiness_pct``).
* Harvest-now-decrypt-later (HNDL): endpoints whose key exchange is quantum-vulnerable; traffic recorded today can be
  decrypted later. Certificates and signatures are not HNDL (a forged signature in future does not reveal past data).
* Mosca: data must stay secret for X years, migration takes Y years, a quantum computer arrives in Z years.
  X + Y > Z means data is already at risk. The team sets X, Y and Z; there is no built-in Z.
* Risk score per asset: impact weight x the source's business criticality x its internet exposure. Criticality and the
  exposure override are read from the job (snapshotted when the run was created), so later edits never re-score an old
  run; jobs created before the snapshot existed fall back to the source's current values.
* Compliance: which regulatory clauses (from the knowledge base) the run's findings touch.
"""
from __future__ import annotations

import datetime as _dt
import ipaddress
import re
from collections import Counter, defaultdict
from typing import Any, Callable, Iterable, Mapping

from sqlalchemy import or_
from sqlmodel import Session, select

from backend.new_models import CbomCollectedAsset, CbomCollectionJob, CbomCollectionSource, CbomScanNode
from backend.utilities.cbom_sources import agility as AGILITY
from backend.utilities.cbom_sources import algid, crypto_kb
from backend.utilities.cbom_sources.cbom_metrics import quantum_readiness_pct
from backend.utilities.cbom_sources.classify import (
    KEX_PRIMITIVES,
    cert_identity_input,
    kex_identity,
    pq_kex_evidence,
    pq_key_exchange,
)

IN_TRANSIT = {"tls_endpoint", "ssh_endpoint", "ssh_server_config", "database_tls", "load_balancer_tls", "cdn_tls",
              "api_tls", "k8s_ingress_tls"}
IMPACT_WEIGHT = {"Critical": 10.0, "High": 7.0, "Medium": 4.0, "Low": 1.0}
CRITICALITY = {"low": 0.5, "medium": 1.0, "high": 1.5, "critical": 2.0}
# Internet exposure multiplier: a weakness anyone on the internet can reach ranks 1.5x. Internal and unknown are
# neutral (1.0), so a missing exposure fact never LOWERS a risk; only a positive internet signal raises it.
EXPOSURE_FACTOR = {"internet": 1.5, "internal": 1.0, "unknown": 1.0}
EXPOSURES = tuple(EXPOSURE_FACTOR)
PQC_CLASSES = ("quantum-vulnerable", "hybrid", "quantum-safe", "grover-weakened", "unknown", "not-applicable")
# the classes with a quantum verdict: the readiness denominator (``unknown`` and ``not-applicable`` are outside it)
JUDGED_CLASSES = ("quantum-vulnerable", "hybrid", "quantum-safe", "grover-weakened")
# Bumped whenever a class rule changes: the export serial and ``zs:pqc_class_model`` carry it, so a re-export whose
# classes changed is a new BOM (CB-18 ST-A). pc-1: dev before CB-18; pc-2: the ``unknown`` class, hybrid only with an
# identified post-quantum component, the read-elsewhere rule.
PQC_CLASS_MODEL = "pc-2"

# Why an asset has its class (``pqc_class_basis``): one code per rule of ``classify_pqc``, with the sentence the drawer,
# the export and the posture card show.
CLASS_BASIS: dict[str, tuple[str, str]] = {
    "shor_breaks": ("quantum-vulnerable", "RSA, elliptic-curve or Diffie-Hellman: a large quantum computer breaks it"),
    "grover_128_bit": ("grover-weakened", "A 128-bit symmetric key: still secure, smaller margin against quantum search"),
    "pq_kex_accepted": ("hybrid", "A named post-quantum key-exchange group is accepted next to the classical one"),
    "hybrid_construction": ("hybrid", "A hybrid or composite construction whose post-quantum component is identified; "
                                      "classical public-key cryptography is still part of it"),
    "pq_with_classical": ("hybrid", "An identified post-quantum key exchange is offered next to a classical one"),
    "pq_or_symmetric": ("quantum-safe", "Post-quantum, symmetric or hash cryptography"),
    "algorithm_unknown": ("unknown", "The collector could not identify the algorithm"),
    "key_unidentified": ("unknown", "The key's algorithm identifier is one the product does not know (for example an "
                                    "OID in a private arc)"),
    "key_encrypted": ("unknown", "The key file is passphrase-protected, so its algorithm was not read"),
    "key_format_unread": ("unknown", "The key file could not be parsed"),
    "not_readable": ("unknown", "The file could not be read (permissions)"),
    "no_tls_handshake": ("unknown", "No TLS handshake completed: not TLS, no common parameters, or the server needs a "
                                    "server name (SNI)"),
    "kex_not_read": ("unknown", "The key exchange was not read"),
    "pq_component_unidentified": ("unknown", "A hybrid or composite identifier whose post-quantum component is not "
                                             "identified (an arc prefix or a name marker only)"),
    "pq_group_unnamed": ("unknown", "A post-quantum key exchange was reported without naming the group"),
    "no_public_key": ("not-applicable", "Settings and inventory with no public-key algorithm"),
    "no_tls_in_use": ("not-applicable", "No TLS in use (plaintext only)"),
    "trust_store_summary": ("not-applicable", "A CA bundle summary (inventory, one row per bundle)"),
    "no_key_material": ("not-applicable", "No key or certificate was found in the file"),
    "kex_judged_elsewhere": ("not-applicable", "The key exchange is judged on another row (the database's TLS endpoint, "
                                               "the gateway's first IKE port) or is outside this source (ingress)"),
    "read_elsewhere": ("not-applicable", "Another collector of the same run read this object and judged it"),
}
_CERT_TYPES = frozenset({"certificate", "k8s_tls_secret", "iam_certificate", "cloud_ca", "k8s_certificate",
                         "ca_authority", "public_key"})
_PRIVATE_KEY_TYPES = frozenset({"private_key", "ssh_host_key", "signing_key"})
_KEY_TYPES = _CERT_TYPES | _PRIVATE_KEY_TYPES | {"kms_key", "managed_key"}
_TLS_TYPES = frozenset({"tls_endpoint", "load_balancer_tls", "cdn_tls", "api_tls"})
_KEX_ELSEWHERE_TYPES = frozenset({"database_tls", "k8s_ingress_tls"})
_SSH_TYPES = frozenset({"ssh_endpoint", "ssh_server_config"})
_UNNAMED = ("marker", "oid-prefix", "fallback")  # algid hits that name no table row


def _named_pq(found: algid.Identity | None) -> bool:
    """A post-quantum identity algid knows by a table row (not a marker or arc-prefix hit)."""
    return found is not None and found.quantum == "safe" and bool(found.name) and found.matched_by not in _UNNAMED


def _pq_component_named(found: algid.Identity) -> bool:
    """A hybrid or composite identity whose post-quantum component resolves to a table row (EC-1)."""
    return found.matched_by not in ("oid-prefix",) and any(_named_pq(algid.resolve(c)) for c in found.components)


def _names(value: Any) -> list[str]:
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if isinstance(v, (str, int)) and str(v).strip()]
    return []


def _list_class(identities: list[algid.Identity | None], pq_flag: bool) -> tuple[str, str]:
    """The class of a key-exchange list (SSH kex methods, IKE groups) judged quantum-safe by the classifier."""
    pq = [f for f in identities if f is not None and f.quantum in ("safe", "hybrid")
          and f.primitive in KEX_PRIMITIVES]
    if any(f.construction in ("hybrid", "composite") and _pq_component_named(f) for f in pq):
        return "hybrid", "hybrid_construction"
    named = [f for f in pq if f.construction not in ("hybrid", "composite") and _named_pq(f)]
    if named:
        classical = any(f is not None and f.quantum == "vulnerable" for f in identities)
        return ("hybrid", "pq_with_classical") if classical else ("quantum-safe", "pq_or_symmetric")
    if pq or pq_flag:
        return "unknown", "pq_component_unidentified" if pq else "pq_group_unnamed"
    return "quantum-safe", "pq_or_symmetric"


def _safe_class(asset_type: str, algorithm: Any, facts: dict[str, Any]) -> tuple[str, str]:
    """``quantum_vulnerable is False``: hybrid only with an identified post-quantum component, else unknown (EC-1); a
    pure post-quantum or symmetric identity is quantum-safe."""
    if asset_type in _TLS_TYPES or asset_type in _KEX_ELSEWHERE_TYPES:
        if pq_kex_evidence(facts):  # the raw facts, as stored: classify reads the same evidence (CB-04)
            groups = [facts.get(k) for k in ("negotiated_group", "pq_group", "group")] + _names(facts.get("groups"))
            if any(pq_key_exchange(g, "tls_group") and _named_pq_kex(g) for g in groups):
                return "hybrid", "pq_kex_accepted"
            return "unknown", "pq_group_unnamed"
        return "quantum-safe", "pq_or_symmetric"
    if asset_type in _SSH_TYPES or (asset_type == "appliance_config" and facts.get("kind") == "ssh"):
        kex = _names(facts.get("kex")) or _names(facts.get("kexalgorithms"))
        return _list_class([algid.ssh_kex(k) or algid.resolve(k) for k in kex], False)
    if asset_type == "ike_endpoint":
        v2 = facts.get("ikev2") if isinstance(facts.get("ikev2"), dict) else {}
        pq = v2.get("pq") if isinstance(v2.get("pq"), dict) else {}
        method = pq.get("method")
        found = (algid.resolve(method, "ike_ke") or algid.resolve(method)) if isinstance(method, str) else None
        if _named_pq(found) or (found is not None and _pq_component_named(found)):
            return "hybrid", "pq_with_classical"  # RFC 9370: an additional key exchange after the classical one
        return ("unknown", "pq_group_unnamed") if pq.get("supported") is True else ("quantum-safe", "pq_or_symmetric")
    if asset_type == "appliance_config" and facts.get("kind") == "ike_policy":
        groups = _names(facts.get("groups"))
        ids = [_ike_group(g) for g in groups]
        return _list_class(ids, facts.get("pq") is True)
    if asset_type in _KEY_TYPES:
        subject = cert_identity_input(algorithm, facts)
        if asset_type == "kms_key" and facts.get("key_spec") and facts.get("key_spec") != "SYMMETRIC_DEFAULT":
            spec = algid.aws("kms", "KeySpec", facts.get("key_spec"))
            subject = spec.name if spec is not None else facts.get("key_spec")
        found = algid.resolve(subject) if isinstance(subject, str) else None
        if found is not None and found.construction in ("hybrid", "composite"):
            return ("hybrid", "hybrid_construction") if _pq_component_named(found) else \
                ("unknown", "pq_component_unidentified")
        if found is not None and found.matched_by == "oid-prefix":
            return "unknown", "pq_component_unidentified"  # an OID in a post-quantum arc that no table row names
    return "quantum-safe", "pq_or_symmetric"


def _named_pq_kex(group: Any) -> bool:
    found = kex_identity(group, "tls_group")
    if found is None:
        return False
    return _named_pq(found) or (found.construction in ("hybrid", "composite") and _pq_component_named(found))


def _ike_group(group: str) -> algid.Identity | None:
    m = re.fullmatch(r"(?i)group\s*(\d+)", group.strip())
    if m:
        return algid.ike_ke(int(m.group(1)))
    return algid.resolve(group, "ike_ke") or algid.resolve(group)


def _key_evidence(facts: dict[str, Any], algorithm: Any) -> str | None:
    """Why a certificate or key row with no verdict is ``unknown`` (FP-4, EC-2): the basis, or None when the row holds
    no key material (no certificate found, an empty authorized_keys, an unparsed Kubernetes secret)."""
    if facts.get("encrypted") is True:
        return "key_encrypted"
    if algorithm or facts.get("key_alg") or facts.get("key_alg_oid"):
        return "key_unidentified"
    if facts.get("readable") is False:
        return "not_readable"
    return None


def _unread_class(asset_type: str, algorithm: Any, facts: dict[str, Any]) -> tuple[str, str]:
    """``quantum_vulnerable is None``: ``unknown`` when public-key cryptography is there but was not identified or not
    read; ``not-applicable`` otherwise (SPEC §3.3 with review changes FP-3, FP-4, FP-6, EC-2)."""
    if facts.get("algorithm_unknown"):
        return "unknown", "algorithm_unknown"
    if asset_type == "certificate" and facts.get("trust_store"):
        return "not-applicable", "trust_store_summary"
    if asset_type in _PRIVATE_KEY_TYPES:  # the type itself says a private key is there (EC-2)
        if facts.get("parsed") is False and not facts.get("encrypted") and facts.get("readable") is not False:
            return "unknown", "key_format_unread"
        return "unknown", _key_evidence(facts, algorithm) or "key_format_unread"
    if asset_type in _CERT_TYPES:
        basis = _key_evidence(facts, algorithm)
        return ("unknown", basis) if basis else ("not-applicable", "no_key_material")
    if asset_type in _TLS_TYPES:
        if facts.get("tls") is False or facts.get("plaintext_only"):
            return "not-applicable", "no_tls_in_use"
        if "tls" in facts and facts.get("tls") is None:
            return "unknown", "no_tls_handshake"
        return "unknown", "kex_not_read"
    if asset_type in _KEX_ELSEWHERE_TYPES:
        return "not-applicable", "kex_judged_elsewhere"
    if asset_type in _SSH_TYPES:
        return "unknown", "kex_not_read"
    if asset_type == "ike_endpoint":
        unread = facts.get("mode") == "fragile" or "packet budget used up" in (facts.get("unknown") or [])
        return ("unknown", "kex_not_read") if unread else ("not-applicable", "kex_judged_elsewhere")
    return "not-applicable", "no_public_key"


_ROW = object()


def _get(row: Any, name: str) -> Any:
    return row.get(name) if isinstance(row, dict) else getattr(row, name, None)


def classify_pqc(row: Any, codes: list[str] | None = None, *, quantum_vulnerable: Any = _ROW,
                 elsewhere: Callable[[Any], int | None] | None = None) -> tuple[str, str]:
    """The PQC class of one stored asset and why: ``(class, basis)``, ``basis`` a key of ``CLASS_BASIS``.

    The one class function: the run posture, the asset detail, the run asset list, drift, the heat map, the export
    (``zs:pqc_class``) and the quantum risk grade all call it. ``row``: a stored asset (or a dict with ``asset_type``,
    ``quantum_vulnerable``, ``facts``, ``algorithm``); ``codes``: the finding codes as the view shows them;
    ``quantum_vulnerable``: a re-judged verdict (drift) instead of the stored one; ``elsewhere``: for a run-wide
    view, the id of a row of the same run that another job read with a verdict (``JudgedElsewhere``): such an
    ``unknown`` row is ``not-applicable`` / ``read_elsewhere`` (EC-3)."""
    asset_type = str(_get(row, "asset_type") or "")
    qv = _get(row, "quantum_vulnerable") if quantum_vulnerable is _ROW else quantum_vulnerable
    facts = _get(row, "facts")
    facts = facts if isinstance(facts, dict) else {}
    algorithm = _get(row, "algorithm")
    codes = codes or []
    if "DISK_XTS_128" in codes:
        return "grover-weakened", "grover_128_bit"
    if asset_type == "disk_encryption" and qv is False and \
            "128" in str(facts.get("method") or facts.get("cipher") or ""):
        return "grover-weakened", "grover_128_bit"  # any 128-bit volume key (BitLocker Aes128, aes-cbc-128), not only XTS
    if qv is True:
        return "quantum-vulnerable", "shor_breaks"
    if qv is False:
        return _safe_class(asset_type, algorithm, facts)
    cls, basis = _unread_class(asset_type, algorithm, facts)
    if cls == "unknown" and elsewhere is not None and elsewhere(row) is not None:
        return "not-applicable", "read_elsewhere"
    return cls, basis


def sibling_key(row: Any) -> tuple[str, str, str]:
    """What "the same object" means for the read-elsewhere rule: asset type, target and location as stored."""
    return (str(_get(row, "asset_type") or ""), str(_get(row, "target") or ""), str(_get(row, "location") or ""))


class JudgedElsewhere:
    """For one run: the id of a row with a quantum verdict that another job read for the same (asset type, target,
    location), or None (EC-3: one key file read by Tier-1 SSH without permission and by the host agent as root is
    one quantum-vulnerable key, not one vulnerable and one unknown).

    Built from the run's rows when the caller has them all (posture, export summary), else it asks the database once
    per key, only for rows whose class would be ``unknown`` (list pages, asset detail)."""

    def __init__(self, rows: Iterable[Any] | None = None, *, session: Session | None = None,
                 team_id: int | None = None, run_id: int | None = None) -> None:
        self._known: dict[tuple[str, str, str], list[tuple[int | None, int]]] | None = None
        self._session, self._team_id, self._run_id = session, team_id, run_id
        self._cache: dict[tuple[str, str, str], list[tuple[int | None, int]]] = {}
        if rows is not None:
            known: dict[tuple[str, str, str], list[tuple[int | None, int]]] = defaultdict(list)
            for r in rows:
                if _get(r, "quantum_vulnerable") is not None and _get(r, "asset_type") != "coverage":
                    known[sibling_key(r)].append((_get(r, "job_id"), _get(r, "id")))
            self._known = dict(known)

    def _judged(self, key: tuple[str, str, str]) -> list[tuple[int | None, int]]:
        if self._known is not None:
            return self._known.get(key, [])
        if self._session is None or self._run_id is None:
            return []
        if key not in self._cache:
            a_type, target, location = key
            query = select(CbomCollectedAsset.job_id, CbomCollectedAsset.id).where(
                CbomCollectedAsset.team_id == self._team_id, CbomCollectedAsset.run_id == self._run_id,
                CbomCollectedAsset.asset_type == a_type, CbomCollectedAsset.location == location,
                CbomCollectedAsset.quantum_vulnerable.is_not(None))  # type: ignore[union-attr]
            query = query.where(CbomCollectedAsset.target == target) if target else query.where(
                or_(CbomCollectedAsset.target.is_(None), CbomCollectedAsset.target == ""))  # type: ignore[union-attr]
            self._cache[key] = [(j, i) for j, i in self._session.exec(query.order_by(CbomCollectedAsset.id)).all()]
        return self._cache[key]

    def __call__(self, row: Any) -> int | None:
        job_id = _get(row, "job_id")
        for other_job, other_id in self._judged(sibling_key(row)):
            if other_job != job_id:
                return other_id
        return None


def readiness(classes: Mapping[str, int]) -> tuple[float | None, dict[str, Any]]:
    """PQC readiness and what it rests on. The percentage is ``cbom_metrics.quantum_readiness_pct`` over the judged
    classes; it is withheld (None, ``status: "not_enough_identified"``) when more assets are ``unknown`` than judged,
    so 999 unidentified assets and one AES key never read "100 %" (EC-4)."""
    judged = sum(int(classes.get(c, 0) or 0) for c in JUDGED_CLASSES)
    vulnerable = int(classes.get("quantum-vulnerable", 0) or 0)
    unknown = int(classes.get("unknown", 0) or 0)
    basis = {"judged": judged, "ready": judged - vulnerable, "unknown": unknown,
             "not_applicable": int(classes.get("not-applicable", 0) or 0), "status": "ok"}
    if unknown > judged:
        basis["status"] = "not_enough_identified"
        return None, basis
    pct = quantum_readiness_pct(vulnerable, judged)
    if pct is None:
        basis["status"] = "nothing_judged"
    return pct, basis


def readiness_pct(vulnerable: int, judged: int, unknown: int) -> float | None:
    """``readiness`` for callers that count views, not classes (drift)."""
    return readiness({"quantum-vulnerable": vulnerable, "quantum-safe": max(0, judged - vulnerable),
                      "unknown": unknown})[0]


def run_class_summary(session: Session, *, team_id: int, run_id: int) -> dict[str, Any]:
    """Whole-run class counts and readiness from ``classify_pqc`` (with the read-elsewhere rule), over every stored
    asset of the run whatever its size: the export's metadata reads it, so an export cut at its cap still says how
    many assets of each class the run holds (EC-8). Stored finding codes stand in for today's view: the one code the
    class reads (``DISK_XTS_128``) is never date-based."""
    cols = (CbomCollectedAsset.id, CbomCollectedAsset.job_id, CbomCollectedAsset.asset_type,
            CbomCollectedAsset.target, CbomCollectedAsset.location, CbomCollectedAsset.algorithm,
            CbomCollectedAsset.quantum_vulnerable, CbomCollectedAsset.facts, CbomCollectedAsset.finding_codes)
    query = select(*cols).where(CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.run_id == run_id,
                                CbomCollectedAsset.asset_type != "coverage").order_by(CbomCollectedAsset.id)
    names = ("id", "job_id", "asset_type", "target", "location", "algorithm", "quantum_vulnerable", "facts",
             "finding_codes")
    rows = [dict(zip(names, r)) for r in session.exec(query).all()]
    elsewhere = JudgedElsewhere(rows)
    classes: Counter[str] = Counter(classify_pqc(r, list(r["finding_codes"] or []), elsewhere=elsewhere)[0]
                                    for r in rows)
    pct, basis = readiness(classes)
    return {"assets": len(rows), "pqc_classes": {c: classes.get(c, 0) for c in PQC_CLASSES},
            "pqc_readiness_pct": pct, "readiness_basis": basis, "pqc_class_model": PQC_CLASS_MODEL}


def hndl(asset_type: str, quantum_vulnerable: bool | None) -> bool:
    return asset_type in IN_TRANSIT and quantum_vulnerable is True


def mosca(risk_model: dict[str, Any] | None) -> dict[str, Any]:
    model = risk_model or {}
    x, y, z = (model.get(k) for k in ("data_shelf_life_years", "migration_years", "threat_years"))
    if not all(isinstance(v, (int, float)) for v in (x, y, z)):
        return {"configured": False, "x": x, "y": y, "z": z,
                "note": "Set how long your data must stay secret (X), how long migration takes (Y) and when you "
                        "expect a cryptographically relevant quantum computer (Z) in Settings."}
    gap = (x or 0) + (y or 0) - (z or 0)
    return {"configured": True, "x": x, "y": y, "z": z, "at_risk": gap > 0, "years_over": gap,
            "verdict": (f"At risk: X + Y = {x + y} years exceeds Z = {z}; data encrypted today with quantum-vulnerable "
                        f"key exchange can be decrypted while it still needs to be secret.") if gap > 0 else
                       (f"Inside the window: X + Y = {x + y} years does not exceed Z = {z}, with {-gap} year(s) "
                        "to spare.")}


def _ip_of(value: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    host, _port = _host_port(value or "")
    if not host:
        return None
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None  # a host name: no DNS lookups here, so its exposure stays unknown


def asset_exposure(facts: dict[str, Any] | None, target: str | None, location: str | None, *,
                   override: str | None = None, node_segment: str | None = None) -> tuple[str, str]:
    """(exposure, basis): ``internet`` | ``internal`` | ``unknown`` and why; the first rule that applies wins:

    1. the source's exposure set by the team (``override``);
    2. the collector's own ``internet_facing`` fact (cloud collectors: load balancer scheme, public database, public IP,
       CloudFront, API Gateway, EKS endpoint ...);
    3. the scan node sits in a segment named DMZ;
    4. the target is an IP address: public (``ipaddress.is_global``) is internet, private / loopback / link-local is
       internal. Host names stay unknown (no DNS lookups).
    """
    if override in EXPOSURES:
        return override, "set on the source"
    facts = facts if isinstance(facts, dict) else {}
    flag = facts.get("internet_facing")
    if isinstance(flag, bool):
        reason = str(facts.get("internet_facing_reason") or "").strip()[:120]
        return ("internet" if flag else "internal"), ("reported by the collector" + (f": {reason}" if reason else ""))
    if str(node_segment or "").strip().lower() == "dmz":
        return "internet", "scan node segment DMZ"
    for value in (target, location):
        ip = _ip_of(value)
        if ip is None:
            continue
        if ip.is_global:
            return "internet", f"public IP address {ip}"
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return "internal", f"private IP address {ip}"
    return "unknown", "no exposure fact"


def job_metadata(params: dict[str, Any] | None, source: CbomCollectionSource | None,
                 node: CbomScanNode | None) -> dict[str, Any]:
    """Business criticality, exposure override, node segment and data lifetime (Mosca X of the source) for one job:
    the values snapshotted in the job when the run was created, else (jobs created before the snapshot) the source's
    and node's current values."""
    snap = (params or {}).get("metadata")
    if isinstance(snap, dict):
        return {"criticality": snap.get("business_criticality"), "exposure": snap.get("exposure"),
                "segment": snap.get("node_segment"), "data_lifetime_years": snap.get("data_lifetime_years")}
    cfg = (source.config or {}) if source else {}
    return {"criticality": cfg.get("business_criticality"), "exposure": cfg.get("exposure"),
            "segment": node.segment if node else None, "data_lifetime_years": cfg.get("data_lifetime_years")}


def _job_context(session: Session, team_id: int, run_id: int, sources: dict[int, CbomCollectionSource]
                 ) -> dict[int, dict[str, Any]]:
    jobs = session.exec(select(CbomCollectionJob).where(CbomCollectionJob.team_id == team_id,
                                                        CbomCollectionJob.run_id == run_id)).all()
    nodes = {n.id: n for n in session.exec(select(CbomScanNode).where(CbomScanNode.team_id == team_id)).all()}
    return {job.id: job_metadata(job.params, sources.get(job.source_id or 0), nodes.get(job.node_id or 0))
            for job in jobs if job.id is not None}


def run_posture(session: Session, *, team_id: int, run_id: int, risk_model: dict[str, Any] | None,
                top: int = 10) -> dict[str, Any]:
    from backend.utilities.cbom_sources.classify import shown
    from backend.utilities.cbom_sources.qgrade import RunGrades

    rows = session.exec(select(CbomCollectedAsset)
                        .where(CbomCollectedAsset.team_id == team_id, CbomCollectedAsset.run_id == run_id)).all()
    now = _dt.datetime.utcnow()
    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id)).all()}
    job_ctx = _job_context(session, team_id, run_id, sources)
    agility = AGILITY.RunAgility(session, team_id, run_id, sources)  # CB-24: fix class per asset, at view time
    grades = RunGrades(session, team_id=team_id, run_id=run_id, risk_model=risk_model)  # quantum risk grade (CB-19)
    elsewhere = JudgedElsewhere(rows)  # CB-18 EC-3: an object another job of this run read is not "unknown"
    bases: Counter[str] = Counter()
    exposure_counts: Counter[str] = Counter()
    classes: Counter[str] = Counter()
    impacts: Counter[str] = Counter()
    codes: Counter[str] = Counter()
    hndl_count = 0
    risky: list[dict[str, Any]] = []
    clause_assets: dict[tuple[str, str], set[int]] = defaultdict(set)
    clause_meta: dict[tuple[str, str], dict[str, Any]] = {}
    kb = crypto_kb.load()
    compliance = kb.get("compliance") or {}
    for row in rows:
        aid, a_type, qv, facts, source_id = row.id, row.asset_type, row.quantum_vulnerable, row.facts, row.source_id
        location, name, job_id, target = row.location, row.name, row.job_id, row.target
        view = shown(row, now)  # date-based findings (certificate expiry, library end of life) judged today
        impact, a_codes, finding = view["impact"], view["finding_codes"], view["finding"]
        a_codes = [c for c in a_codes if not c.startswith("COVERAGE_")]
        if a_type == "coverage":
            grades.add(row, a_codes)
            continue
        cls, basis = classify_pqc(row, a_codes, elsewhere=elsewhere)
        classes[cls] += 1
        bases[basis] += 1
        agility.add(row, a_codes)
        if impact:
            impacts[impact] += 1
        codes.update(a_codes)
        if hndl(a_type, qv):
            hndl_count += 1
        source = sources.get(source_id or 0)
        ctx = job_ctx.get(job_id or 0) or {}
        crit = str(ctx.get("criticality") or "medium").lower()
        exposure, basis_exposure = asset_exposure(facts, target, location, override=ctx.get("exposure"),
                                                  node_segment=ctx.get("segment"))
        # the quantum risk grade reuses the score's exposure (CB-19) and this loop's class (one class per row)
        grades.add(row, a_codes, (exposure, basis_exposure), cls=cls)
        exposure_counts[exposure] += 1
        if impact:
            risky.append({"id": aid, "type": a_type, "name": name or location, "location": location, "impact": impact,
                          "criticality": crit, "exposure": exposure, "exposure_basis": basis_exposure,
                          "source_name": source.name if source else None,
                          "score": round(IMPACT_WEIGHT.get(impact, 0) * CRITICALITY.get(crit, 1.0)
                                         * EXPOSURE_FACTOR[exposure], 1),
                          "hndl": hndl(a_type, qv), "finding": finding})
        for code in a_codes:
            for key in (crypto_kb.entry("node", code) or {}).get("compliance") or []:
                for ref in compliance.get(key) or []:
                    clause = (ref["framework"], ref["id"])
                    clause_assets[clause].add(aid)
                    meta = clause_meta.setdefault(clause, {**ref, "codes": set()})
                    meta["codes"].add(code)
    readiness_value, readiness_basis = readiness(classes)
    frameworks: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for clause, assets in sorted(clause_assets.items(), key=lambda kv: (kv[0][0], -len(kv[1]))):
        meta = clause_meta[clause]
        frameworks[clause[0]].append({"id": meta["id"], "text": meta["text"], "source": meta["source"],
                                      "note": meta.get("note"), "assets": len(assets), "codes": sorted(meta["codes"])})
    risky.sort(key=lambda r: (-r["score"], r["id"]))
    return {
        "assets": sum(classes.values()),
        "pqc_classes": {c: classes.get(c, 0) for c in PQC_CLASSES},
        # why each class: basis code -> count, and the sentence for each code (CB-18 OB-8)
        "pqc_class_bases": dict(sorted(bases.items())),
        "pqc_class_basis_text": {code: CLASS_BASIS[code][1] for code in sorted(bases)},
        "pqc_class_model": PQC_CLASS_MODEL,
        "pqc_readiness_pct": readiness_value,
        "readiness_basis": readiness_basis,
        "hndl_assets": hndl_count,
        "impacts": {k: impacts.get(k, 0) for k in IMPACT_WEIGHT},
        "top_codes": [{"code": c, "count": n, "title": (crypto_kb.entry("node", c) or {}).get("title", c)}
                      for c, n in codes.most_common(15)],
        "mosca": mosca(risk_model),
        "top_risks": risky[:top],
        "exposure": {e: exposure_counts.get(e, 0) for e in EXPOSURES},
        "exposure_factors": dict(EXPOSURE_FACTOR),
        "compliance": [{"framework": fw, "clauses": items} for fw, items in sorted(frameworks.items())],
        "kb_version": crypto_kb.version(),
        **agility.result(),
        "pqc_context": {k: v for k, v in crypto_kb.pqc_context().items() if k in ("mosca", "expert_survey",
                                                                                 "nist_ir_8547", "z_note")},
        **grades.result(),
    }


def _host_port(value: str) -> tuple[str | None, str | None]:
    """Host and port from 'host:443', '[2001:db8::1]:443', a bare IPv6 address or a bare host; None for paths, ARNs
    and other values with colons. An IPv6 host keeps its brackets so 'openssl -connect {host}:{port}' stays valid."""
    v = (value or "").strip().split("#", 1)[0]  # '10.0.0.5:443#chain[0]': a certificate in an endpoint's chain
    m = re.match(r"^\[([0-9A-Fa-f:.]+)\](?::(\d{1,5}))?$", v)
    if m:
        return f"[{m.group(1)}]", m.group(2)
    if re.fullmatch(r"[0-9A-Fa-f]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*", v):  # bare IPv6 (two or more colons, hex only)
        return f"[{v}]", None
    m = re.match(r"^([A-Za-z0-9.\-]+):(\d{1,5})$", v)
    if m:
        return m.group(1), m.group(2)
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.\-]*", v):
        return v, None
    return None, None


def asset_detail(row: CbomCollectedAsset, source: CbomCollectionSource | None, *,
                 job: CbomCollectionJob | None = None, node: CbomScanNode | None = None,
                 today: _dt.date | None = None, session: Session | None = None) -> dict[str, Any]:
    """Everything known about one collected asset: the knowledge-base explanation of each finding code (with commands
    filled in for this host), library CVEs and end-of-life (as of the run, and today when that differs), PQC class,
    HNDL and internet exposure."""
    from backend.utilities.cbom_sources.classify import classify, shown

    facts = row.facts or {}
    now = _dt.datetime.combine(today, _dt.time()) if today else _dt.datetime.utcnow()
    view = shown(row, now)  # the finding as every other view shows it: date-based rules judged today
    codes = view["finding_codes"]
    ctx: dict[str, Any] = {"name": facts.get("name") or facts.get("package") or row.name, "location": row.location,
                           "resource": facts.get("arn") or facts.get("resource") or facts.get("key_id")}
    host, port = _host_port(row.target or "")
    loc_host, loc_port = _host_port(row.location or "")
    ctx["host"] = facts.get("host") or host or loc_host or None
    ctx["port"] = facts.get("port") or port or loc_port or None
    if row.location.startswith("/"):
        ctx["path"] = row.location
    elif facts.get("path"):
        ctx["path"] = facts["path"]
    # the classifier is deterministic, so re-running it on the stored facts (as of collection time, or today when a
    # date-based rule changed the finding since) gives the sentence it wrote for each code
    verdict = classify(row.asset_type, row.algorithm, row.key_size, row.protocol, facts,
                       now if view["as_of_run"] else row.created_at)
    texts = verdict["texts"]
    ordered = [c for c in codes if c != "QUANTUM_VULNERABLE"] + [c for c in codes if c == "QUANTUM_VULNERABLE"]
    library = None
    if row.asset_type in ("crypto_library", "process_library") and facts.get("version"):
        package, version = str(facts.get("name") or facts.get("package") or ""), str(facts["version"])
        # end of life as of the run (the classifier's LIB_EOL used the run date too), and today when that differs
        as_of = (row.created_at or _dt.datetime.utcnow()).date()
        library = crypto_kb.library_status(package, version, today=as_of)
        if library:
            eol_now = (crypto_kb.library_status(package, version, today=today or _dt.date.today()) or {}).get("eol")
            changed = (eol_now or {}).get("passed") != (library.get("eol") or {}).get("passed")
            library = {**library, "cve_details": [crypto_kb.cve(c) for c in library["cves"]],
                       "eol_as_of": as_of.isoformat(), "eol_today": eol_now if changed else None}
    meta = job_metadata(job.params if job is not None else None, source, node)
    crit = str(meta["criticality"] or "medium")
    sibling = None
    if session is not None and row.run_id is not None:
        lookup = JudgedElsewhere(session=session, team_id=row.team_id, run_id=row.run_id)
        pqc_class_value, pqc_basis = classify_pqc(row, codes, elsewhere=lookup)
        sibling = lookup(row) if pqc_basis == "read_elsewhere" else None
    else:
        pqc_class_value, pqc_basis = classify_pqc(row, codes)
    exposure, exposure_basis = asset_exposure(facts, row.target, row.location, override=meta["exposure"],
                                              node_segment=meta["segment"])
    return {
        "id": row.id, "type": row.asset_type, "name": row.name, "location": row.location, "target": row.target,
        "impact": view["impact"], "finding": view["finding"], "finding_codes": codes, "as_of_run": view["as_of_run"],
        "algorithm": row.algorithm,
        "key_size": row.key_size, "protocol": row.protocol, "quantum_vulnerable": row.quantum_vulnerable,
        "pqc_class": pqc_class_value,
        "pqc_class_basis": pqc_basis,
        "pqc_class_basis_text": CLASS_BASIS[pqc_basis][1],
        "pqc_class_read_elsewhere": sibling,
        "hndl": hndl(row.asset_type, row.quantum_vulnerable),
        "source_name": source.name if source else None,
        "criticality": crit,
        "exposure": exposure,
        "exposure_basis": exposure_basis,
        "exposure_factor": EXPOSURE_FACTOR[exposure],
        "agility": AGILITY.detail(row.asset_type, codes, facts, AGILITY.node_context(job, source), row.location),
        "facts": facts,
        "details": [{**d, "impact": verdict["impacts"].get(d["code"]) or d["impact"]}
                    for d in crypto_kb.render("node", ordered, context=ctx, evidence=view["finding"] or "", texts=texts,
                                              title=str(row.algorithm or row.name or ""))],
        "library": library,
        "kb_version": crypto_kb.version(),
    }
