"""Crypto-agility fix class (CB-24, model fx-1): how hard each finding, asset and evidence item is to fix.

The four classes, easiest to hardest (the architecture diagram's chip order; "hardest" = who controls the timeline):

* ``configurable``   - a setting, policy, key or certificate change with what is already deployed;
* ``code-fixed``     - the team's own source or build changes, then a release;
* ``vendor-fixed``   - the cryptography lives in a third party's product or service; only the vendor can change it;
* ``hardware-fixed`` - the cryptography is bound to a device (HSM, TPM, smart card, appliance, OT device).

Two more values describe an asset: ``unknown`` (a fact that decides the class was not read; shown with the class it is
at least, ``floor``) and ``none`` (no finding code: nothing to change today).

Where a class comes from:

1. **The table**: one reviewed row per KB finding code (``scripts/crypto_kb/sources/fix_class.json``, built into
   ``crypto_kb.json`` as ``findings.<ns>.<CODE>.fix_class``: class, capability, basis). A code whose class does not
   depend on context (a protocol version, cipher, key size, account or policy is a setting on every platform that has
   the code) takes it as is (rule R-TABLE, observed).
2. **Context rules** (a closed set, ``RULES``): capability codes (the platform must implement the algorithm) are
   decided by the first rule that matches (R-HW, R-HW-UNREAD, R-STACK, R-TYPE, else R-INFERRED); R-VENDOR raises every
   node code of a vendor-operated source to at least vendor-fixed; CL-1 / CL-2 for code-scan rows; R-NO-ROW makes a
   code without a row ``unknown``.
3. **The asset rule**: the hardest class among its codes; ``unknown`` (floor = the hardest known class) when a
   deciding fact was not read and nothing is already hardware-fixed; ``none`` when the asset has no code.

Everything here is pure and computed at view time from what is stored (codes, facts, the job's metadata snapshot): no
migration, no stored column. A later metadata edit never re-classifies an old run (the job snapshot is read, as the
risk score does in ``posture.job_metadata``), and neither does deleting the source (its kind and provider are kept on
its jobs, ``deleted_source_params``). A deciding fact a collector wrote as a list or an object reads as not read.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

from backend.utilities.cbom_sources import crypto_kb

MODEL = "fx-1"
CLASSES = ("configurable", "code-fixed", "vendor-fixed", "hardware-fixed")
RANK = {name: i + 1 for i, name in enumerate(CLASSES)}
VALUES = (*CLASSES, "unknown", "none")
SELF_FIXABLE = ("configurable", "code-fixed")
# Post-quantum migration codes: they count in an asset's class (owner default OQ-2) and every distribution is also
# given without them ("current weaknesses only").
PQ_CODES = frozenset({"QUANTUM_VULNERABLE", "NO_PQ_KEX", "SSH_NO_PQ_KEX", "IKE_NO_PQ"})
# SaaS identity providers: the signing keys and endpoints are the vendor's (kinds.IdpConfig.provider)
SAAS_IDP = frozenset({"entra_id", "okta"})
# Code-scan library codes (rule CL-2 reads the artifact the library was found in, when the row says it)
CODE_LIBRARY_CODES = frozenset({"EOL_CRYPTO_LIBRARY", "LIBRARY_CVE_RANGE", "VULNERABLE_CRYPTO_LIBRARY",
                                "EOL_BASE_IMAGE"})
CL2_ARTIFACT = {"firmware": "hardware-fixed", "binary": "vendor-fixed", "image": "code-fixed", "manifest": "code-fixed"}
HW_PROVIDER_CLASSES = frozenset({"tpm", "smartcard", "hsm"})
SYSTEMS_CAP = 500
_CODE_CERT_TYPES = frozenset({"certificate", "protocol", "related-crypto-material"})
_OPENSSH = re.compile(r"OpenSSH_(\d+)\.(\d+)", re.I)
AWS_PARTITIONS = frozenset({"aws", "aws-us-gov", "aws-cn"})
# A deciding fact a collector wrote as a list, dict or other non-scalar: read as "not read" (never guessed, never a
# crash: node facts are free-form JSON and the memo key must stay hashable).
UNREADABLE = "\x00unreadable"

CLASS_TEXT: dict[str, dict[str, str]] = {
    "configurable": {
        "label": "Configurable",
        "what": "The owner fixes it by changing a setting, policy, key or certificate with the software, hardware and "
                "services already deployed. No code change, no new release.",
        "example": "nginx accepts TLS 1.0: set `ssl_protocols TLSv1.2 TLSv1.3;` and reload. Windows SCHANNEL: set the "
                   "`TLS 1.0\\Server\\Enabled` registry value to 0."},
    "code-fixed": {
        "label": "Code-fixed",
        "what": "The team's own source code or build must change, then be rebuilt, tested and released (includes a "
                "dependency or base-image bump in the team's own build).",
        "example": "Java code calls `KeyPairGenerator.initialize(1024)`: change it to 3072 (or a post-quantum signature "
                   "algorithm when the platform has it) and ship a release."},
    "vendor-fixed": {
        "label": "Vendor-fixed",
        "what": "The cryptography lives in a third party's product or service (OS distribution, commercial software, "
                "SaaS, cloud service, CA ecosystem). Only the vendor can change it; the owner installs the update when "
                "it exists, or asks for it.",
        "example": "A SaaS provider's API still accepts TLS 1.0; or an OpenSSL 3.0 server cannot offer a post-quantum "
                   "key exchange until the distribution ships OpenSSL 3.5."},
    "hardware-fixed": {
        "label": "Hardware-fixed",
        "what": "The cryptography is bound to a device: HSM, TPM, smart card, network appliance or OT device. It needs "
                "a firmware update or a hardware replacement.",
        "example": "An HSM whose firmware has no post-quantum signature algorithm keeps RSA root keys until the "
                   "firmware is upgraded or the HSM replaced."},
    "unknown": {
        "label": "Unknown",
        "what": "A fact that decides the class was not read (key provider of a Windows certificate, type of a PKCS#11 "
                "token, a code with no row). Never treated as the easiest class; shows the class it is at least.",
        "example": "A Windows certificate with a private key, read by a node that does not report the key provider yet."},
    "none": {
        "label": "None",
        "what": "The asset has no finding code: nothing to change today.",
        "example": "An AES-256-GCM key in Vault."},
}
INFERRED_TEXT = ("Likely: no fact the product read decides this class; it is the table's default for a capability "
                 "code (the platform must implement the algorithm), never easier than the evidence allows.")

RULES: tuple[dict[str, str], ...] = (
    {"id": "R-TABLE", "applies_to": "non-capability codes",
     "condition": "none: the class does not depend on context", "result": "table class (observed)"},
    {"id": "R-HW", "applies_to": "capability codes",
     "condition": "source kind appliance; asset type ot_endpoint; PKCS#11 key on a hardware token; Windows certificate "
                  "whose key provider is a TPM, smart card or HSM", "result": "hardware-fixed (observed)"},
    {"id": "R-HW-UNREAD", "applies_to": "capability codes",
     "condition": "PKCS#11 key whose token type was not read; Windows certificate with a private key and no key "
                  "provider read; a key provider not in the reviewed list; a deciding fact that is a list or an "
                  "object", "result": "unknown, at least vendor-fixed"},
    {"id": "R-STACK", "applies_to": "SSH_NO_PQ_KEX",
     "condition": "SSH banner OpenSSH >= 9.0 (the first release with a post-quantum key exchange)",
     "result": "configurable; an older OpenSSH banner: vendor-fixed (observed)"},
    {"id": "R-TYPE", "applies_to": "node QUANTUM_VULNERABLE",
     "condition": "AWS KMS key (KMS offers post-quantum signature keys; the callers' signing code changes) -> code-fixed; SaaS IdP "
                  "signing key, cloud CA, IAM or ACM certificate, PKCS#11 software token -> vendor-fixed",
     "result": "as stated (observed)"},
    {"id": "R-VENDOR", "applies_to": "every node code",
     "condition": "the source is operated by a vendor (source metadata operated_by = vendor), or the IdP is a SaaS "
                  "provider (Entra ID, Okta)", "result": "at least vendor-fixed (observed)"},
    {"id": "R-INFERRED", "applies_to": "capability codes with no rule above",
     "condition": "-", "result": "table class (inferred)"},
    {"id": "CL-1", "applies_to": "code-scan QUANTUM_VULNERABLE",
     "condition": "an algorithm (API call) row -> code-fixed (observed); certificate, protocol or key-material rows -> "
                  "vendor-fixed (inferred)", "result": "-"},
    {"id": "CL-2", "applies_to": "code-scan library codes",
     "condition": "the row's artifact_kind: firmware -> hardware-fixed; third-party binary -> vendor-fixed; image or "
                  "manifest -> code-fixed (observed); not stated -> table class", "result": "-"},
    {"id": "R-NO-ROW", "applies_to": "any code",
     "condition": "the code has no fix-class row (legacy rows such as FINDING, a future code)", "result": "unknown"},
)
UNKNOWN_REASONS = {
    "token_type_not_read": "PKCS#11 token type (hardware or software) not read",
    "key_provider_not_read": "key provider of a Windows certificate with a private key not read",
    "key_provider_unlisted": "key provider not in the reviewed list",
    "no_fix_class": "a finding code without a fix-class row",
    "fact_unreadable": "a fact that decides the class has a value the rules cannot read (a list or an object)",
}


# ----------------------------------------------------------------------------------------------- table and version
def _kb_rows() -> tuple[str, dict[tuple[str, str], dict[str, Any]]]:
    data = crypto_kb.load()
    return str(data.get("kb_version") or ""), {
        (ns, code): e["fix_class"] for ns in ("node", "code")
        for code, e in ((data.get("findings") or {}).get(ns) or {}).items()
        if isinstance(e, dict) and isinstance(e.get("fix_class"), dict) and e["fix_class"].get("class") in RANK}


@lru_cache(maxsize=4)
def _table(kb_version: str) -> dict[tuple[str, str], dict[str, Any]]:
    return _kb_rows()[1]


def table() -> dict[tuple[str, str], dict[str, Any]]:
    """(namespace, CODE) -> {class, capability, basis} of the knowledge base in force."""
    return _table(crypto_kb.version())


@lru_cache(maxsize=4)
def _version(kb_version: str) -> str:
    rows = {f"{ns}:{code}": row for (ns, code), row in sorted(_table(kb_version).items())}
    blob = Path(__file__).read_bytes() + json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    return f"{MODEL}+{hashlib.sha256(blob).hexdigest()[:12]}"


def version() -> str:
    """``fx-1+<12 hex>``: changes when this module or the fix-class table in force changes."""
    return _version(crypto_kb.version())


# ----------------------------------------------------------------------------------------------- context
def node_context(job: Any = None, source: Any = None) -> dict[str, Any]:
    """The facts about where an asset was collected that rules read: the source kind, the IdP provider, and the
    job's metadata snapshot (``operated_by``, ``application``), else (jobs created before the snapshot) the source's
    current metadata."""
    params = (getattr(job, "params", None) or {}) if job is not None else {}
    cfg = (getattr(source, "config", None) or {}) if source is not None else {}
    snap = params.get("metadata") if isinstance(params.get("metadata"), dict) else None
    meta = snap if snap is not None else cfg
    if source is not None:
        kind = getattr(source, "kind", None)
        provider = cfg.get("provider") if kind in _PROVIDER_KINDS else None
    else:  # a deleted source: what deleted_source_params kept on its jobs, so its old runs keep their class
        kind, provider = params.get("source_kind"), params.get("source_provider")
    return {"lane": "node", "source_kind": kind, "provider": provider,
            "operated_by": meta.get("operated_by"), "application": meta.get("application")}


_PROVIDER_KINDS = ("idp", "key_manager", "ca_connector")


def deleted_source_params(source: Any) -> dict[str, Any]:
    """What the rules read from a source (its kind; the provider of an IdP, key manager or CA connector), kept on
    each of its jobs when the source is deleted (``routers.cbom_sources._remove_source``)."""
    kind = getattr(source, "kind", None)
    cfg = getattr(source, "config", None) or {}
    return {"source_kind": kind, "source_provider": cfg.get("provider") if kind in _PROVIDER_KINDS else None}


CODE_CONTEXT: dict[str, Any] = {"lane": "code", "source_kind": None, "provider": None, "operated_by": None,
                                "application": None}


def _vendor_reason(ctx: dict[str, Any]) -> str | None:
    if ctx.get("operated_by") == "vendor":
        return "source operated by a vendor (source metadata)"
    if ctx.get("source_kind") == "idp" and ctx.get("provider") in SAAS_IDP:
        return f"identity provider {ctx['provider']} is a SaaS service"
    return None


# ----------------------------------------------------------------------------------------------- per code
def _result(code: str, cls: str, rule: str, basis: str, *, capability: bool = False, confidence: str | None = "observed",
            fact: str | None = None, floor: str | None = None, reason: str | None = None) -> dict[str, Any]:
    return {"code": code, "class": cls, "floor": floor, "capability": capability, "rule": rule, "basis": basis,
            "fact": fact, "confidence": None if cls == "unknown" else confidence, "unknown_reason": reason}


def _windows_cert(asset_type: str, facts: dict[str, Any]) -> bool:
    return asset_type == "certificate" and facts.get("source") == "windows-store"


def _capability(code: str, asset_type: str, facts: dict[str, Any], ctx: dict[str, Any], row: dict[str, Any]
                ) -> dict[str, Any]:
    """First match among R-HW, R-HW-UNREAD, R-STACK, R-TYPE; else R-INFERRED."""
    # every way an unread fact can resolve (hardware token or TPM / smart card / HSM -> hardware-fixed; software ->
    # vendor-fixed) is at least vendor-fixed, so that is the floor of R-HW-UNREAD
    floor = _max(row["class"], "vendor-fixed")
    unreadable = sorted(k for k, v in facts.items() if v == UNREADABLE)
    if unreadable:
        return _result(code, "unknown", "R-HW-UNREAD", UNKNOWN_REASONS["fact_unreadable"], capability=True,
                       fact="unreadable: " + ", ".join(k.lstrip("_") for k in unreadable), floor=floor,
                       reason="fact_unreadable")
    store = facts.get("store")
    token = facts.get("token_class")
    provider = facts.get("key_provider_class")
    # R-HW
    hw = None
    if ctx.get("source_kind") == "appliance":
        hw = "source kind: network appliance"
    elif asset_type == "ot_endpoint":
        hw = "asset type: OT device endpoint"
    elif store == "pkcs11" and token == "hardware":
        hw = "PKCS#11 key on a hardware token"
    elif _windows_cert(asset_type, facts) and provider in HW_PROVIDER_CLASSES:
        hw = f"certificate key held by a {provider} key provider"
    if hw:
        return _result(code, "hardware-fixed", "R-HW", "the cryptography is bound to a device: firmware update or "
                       "hardware replacement", capability=True, fact=hw)
    # R-HW-UNREAD
    if store == "pkcs11" and not token:
        return _result(code, "unknown", "R-HW-UNREAD", UNKNOWN_REASONS["token_type_not_read"], capability=True,
                       floor=floor, reason="token_type_not_read")
    if _windows_cert(asset_type, facts) and facts.get("has_private_key") and not provider:
        return _result(code, "unknown", "R-HW-UNREAD", UNKNOWN_REASONS["key_provider_not_read"], capability=True,
                       floor=floor, reason="key_provider_not_read")
    if provider and provider not in HW_PROVIDER_CLASSES and provider != "software":
        return _result(code, "unknown", "R-HW-UNREAD", UNKNOWN_REASONS["key_provider_unlisted"], capability=True,
                       fact=f"key provider class {str(provider)[:32]}", floor=floor, reason="key_provider_unlisted")
    # R-STACK
    if code == "SSH_NO_PQ_KEX":
        m = _OPENSSH.search(str(facts.get("banner") or ""))
        if m:
            major, minor = int(m.group(1)), int(m.group(2))
            fact = f"SSH banner OpenSSH {major}.{minor}"
            if (major, minor) >= (9, 0):
                return _result(code, "configurable", "R-STACK", "the server already implements a post-quantum key "
                               "exchange (OpenSSH 9.0 and later): enable it in "
                               "KexAlgorithms", capability=True, fact=fact)
            return _result(code, "vendor-fixed", "R-STACK", "OpenSSH before 9.0 has no post-quantum key exchange: "
                           "the OS or appliance vendor's newer OpenSSH is needed", capability=True, fact=fact)
    # R-TYPE
    if code == "QUANTUM_VULNERABLE":
        service = facts.get("_aws_service") or aws_service(facts.get("arn"))
        if asset_type == "kms_key" and (ctx.get("source_kind") == "aws_account" or service == "kms"):
            return _result(code, "code-fixed", "R-TYPE", "AWS KMS offers post-quantum signature keys: create one "
                           "and change the "
                           "callers' signing code", capability=True, fact="AWS KMS key")
        if asset_type == "signing_key" and ctx.get("provider") in SAAS_IDP:
            return _result(code, "vendor-fixed", "R-TYPE", "the SaaS identity provider owns its signing keys",
                           capability=True, fact=f"identity provider {ctx['provider']}")
        if asset_type in ("cloud_ca", "iam_certificate") or (asset_type == "certificate" and service == "acm"):
            return _result(code, "vendor-fixed", "R-TYPE", "the cloud provider's certificate service decides which "
                           "algorithms it issues", capability=True, fact=f"asset type {asset_type}")
        if store == "pkcs11" and token == "software":
            return _result(code, "vendor-fixed", "R-TYPE", "a software token's algorithms come from its vendor's "
                           "release (SoftHSM, PKCS#11 library)", capability=True, fact="PKCS#11 software token")
    # R-INFERRED
    return _result(code, row["class"], "R-INFERRED", row.get("basis") or "", capability=True, confidence="inferred")


def code_class(ns: str, code: str, asset_type: str, facts: dict[str, Any] | None, ctx: dict[str, Any]
               ) -> dict[str, Any]:
    """The class of one finding code on one asset, with the rule that decided it, its basis and the fact read."""
    facts = facts if isinstance(facts, dict) else {}
    row = table().get((ns, code))
    if row is None:
        return _result(code, "unknown", "R-NO-ROW", f"no fix class for {code}", reason="no_fix_class")
    if ns == "code":
        if code == "QUANTUM_VULNERABLE":
            if asset_type == "algorithm":
                return _result(code, "code-fixed", "CL-1", "the algorithm is chosen by an API call in the team's code",
                               capability=True, fact="code row type algorithm")
            if asset_type in _CODE_CERT_TYPES:
                return _result(code, "vendor-fixed", "CL-1", "a post-quantum certificate, protocol or key needs the "
                               "CA, peers and libraries to implement it", capability=True, confidence="inferred",
                               fact=f"code row type {asset_type}")
            return _result(code, row["class"], "R-INFERRED", row.get("basis") or "", capability=True,
                           confidence="inferred")
        kind = str(facts.get("artifact_kind") or "").lower()
        if code in CODE_LIBRARY_CODES and kind in CL2_ARTIFACT:
            return _result(code, CL2_ARTIFACT[kind], "CL-2", f"the library ships inside a {kind}",
                           fact=f"artifact kind {kind}")
        if row.get("capability"):
            return _result(code, row["class"], "R-INFERRED", row.get("basis") or "", capability=True,
                           confidence="inferred")
        return _result(code, row["class"], "R-TABLE", row.get("basis") or "")
    out = _capability(code, asset_type, facts, ctx, row) if row.get("capability") else \
        _result(code, row["class"], "R-TABLE", row.get("basis") or "")
    vendor = _vendor_reason(ctx)
    if vendor:
        if out["class"] == "unknown":
            out["floor"] = _max(out["floor"], "vendor-fixed")
        elif RANK[out["class"]] < RANK["vendor-fixed"] or out["confidence"] == "inferred" and \
                out["class"] == "vendor-fixed":
            out = _result(code, "vendor-fixed", "R-VENDOR", "only the vendor operating the service can change it",
                          capability=out["capability"], fact=vendor)
    return out


def _max(a: str | None, b: str | None) -> str | None:
    known = [c for c in (a, b) if c in RANK]
    return max(known, key=RANK.__getitem__) if known else None


# ----------------------------------------------------------------------------------------------- per asset
def asset_class(per_code: list[dict[str, Any]]) -> dict[str, Any]:
    """The asset rule: hardest class; unknown (with floor) when a deciding fact was not read and nothing is
    hardware-fixed; none when there is no code. ``confidence``: observed when every code that reached the hardest
    class was observed, else inferred; None for unknown and none."""
    if not per_code:
        return {"fix_class": "none", "floor": None, "confidence": None}
    known = [p for p in per_code if p["class"] in RANK]
    hardest = max((p["class"] for p in known), key=RANK.__getitem__, default=None)
    if any(p["class"] == "unknown" for p in per_code) and hardest != "hardware-fixed":
        floor = hardest
        for p in per_code:
            floor = _max(floor, p.get("floor"))
        return {"fix_class": "unknown", "floor": floor, "confidence": None}
    top = [p for p in known if p["class"] == hardest]
    return {"fix_class": hardest, "floor": None,
            "confidence": "observed" if all(p["confidence"] == "observed" for p in top) else "inferred"}


def _codes(codes: Iterable[Any]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(c for c in codes or () if isinstance(c, str) and c and not c.startswith("COVERAGE_")))


def aws_service(arn: Any) -> str | None:
    """The service of an AWS ARN in any partition (``arn:aws|aws-us-gov|aws-cn:<service>:...``), else None."""
    parts = arn.split(":", 5) if isinstance(arn, str) else []
    return parts[2][:32] if len(parts) >= 3 and parts[0] == "arn" and parts[1] in AWS_PARTITIONS else None


def _h(value: Any, limit: int = 80) -> Any:
    """A memo-key value: scalars as they are (text bounded), anything else UNREADABLE."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:limit]
    return UNREADABLE


def _deciding(asset_type: str, facts: dict[str, Any], location: str | None) -> tuple:
    """The facts any rule reads (memo key; the rest of the facts never changes a class), each hashable."""
    arn = location if isinstance(location, str) and location.startswith("arn:") else facts.get("arn")
    service = UNREADABLE if _h(arn) == UNREADABLE else aws_service(arn)
    private = facts.get("has_private_key")
    return (_h(facts.get("store")), _h(facts.get("token_class")), _h(facts.get("source")),
            UNREADABLE if _h(private) == UNREADABLE else bool(private),
            _h(facts.get("key_provider_class")), _h(facts.get("banner")), service,
            _h(facts.get("artifact_kind")))


def _ctx_key(ctx: dict[str, Any]) -> tuple:
    return (_h(ctx.get("lane")), _h(ctx.get("source_kind")), _h(ctx.get("provider")), _h(ctx.get("operated_by")))


@lru_cache(maxsize=16384)
def _evaluate(kb_version: str, ns: str, asset_type: str, codes: tuple[str, ...], deciding: tuple, ctx_key: tuple
              ) -> tuple[dict[str, Any], tuple[dict[str, Any], ...], str, tuple[str, ...]]:
    store, token, source, private, provider, banner, service, artifact = deciding
    facts = {"store": store, "token_class": token, "source": source, "has_private_key": private,
             "key_provider_class": provider, "banner": banner, "_aws_service": service, "artifact_kind": artifact}
    ctx = dict(zip(("lane", "source_kind", "provider", "operated_by"), ctx_key))
    per = tuple(code_class(ns, code, asset_type, facts, ctx) for code in codes)
    whole = asset_class(list(per))
    excl_pq = asset_class([p for p in per if p["code"] not in PQ_CODES])["fix_class"]
    # each reason once per asset: unknown_reasons counts assets per reason
    reasons = tuple(dict.fromkeys(p["unknown_reason"] for p in per if p["unknown_reason"])) \
        if whole["fix_class"] == "unknown" else ()
    return whole, per, excl_pq, reasons


def _cached(ns: str, asset_type: str | None, codes: Iterable[Any], facts: dict[str, Any] | None,
            ctx: dict[str, Any], location: str | None) -> tuple:
    facts = facts if isinstance(facts, dict) else {}
    a_type = str(asset_type or "")
    return _evaluate(crypto_kb.version(), ns, a_type, _codes(codes), _deciding(a_type, facts, location), _ctx_key(ctx))


def evaluate(ns: str, asset_type: str | None, codes: Iterable[Any], facts: dict[str, Any] | None,
             ctx: dict[str, Any], location: str | None = None) -> dict[str, Any]:
    """{fix_class, floor, confidence, by_code: [...]} for one asset or code-scan row (memoised on the deciding facts).
    ``codes``: the codes the view shows (``classify.shown``); COVERAGE_* codes are not findings and are ignored."""
    whole, per, _excl, _reasons = _cached(ns, asset_type, codes, facts, ctx, location)
    return {**whole, "by_code": [dict(p) for p in per]}


def list_fields(result: dict[str, Any]) -> dict[str, Any]:
    return {"fix_class": result["fix_class"], "fix_class_floor": result["floor"],
            "fix_class_confidence": result["confidence"]}


def excluding_pq(result: dict[str, Any]) -> str:
    """The asset's class with the post-quantum migration codes left out ("current weaknesses only")."""
    return asset_class([p for p in result["by_code"] if p["code"] not in PQ_CODES])["fix_class"]


# ----------------------------------------------------------------------------------------------- views
def annotate_assets(session: Any, team_id: int, jobs: Iterable[Any], items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add fix_class, fix_class_floor and fix_class_confidence to each asset of a list page (``inventory.public_asset``
    dicts), from its shown codes, facts and its job's context."""
    from sqlmodel import select

    from backend.new_models import CbomCollectionSource

    ids = sorted({i.get("source_id") for i in items if i.get("source_id")})
    sources = {s.id: s for s in session.exec(select(CbomCollectionSource).where(
        CbomCollectionSource.team_id == team_id, CbomCollectionSource.id.in_(ids))).all()} if ids else {}  # type: ignore[union-attr]
    by_job = {j.id: j for j in jobs}
    contexts: dict[tuple, dict[str, Any]] = {}
    for item in items:
        key = (item.get("job_id"), item.get("source_id"))
        if key not in contexts:
            contexts[key] = node_context(by_job.get(key[0]), sources.get(key[1] or 0))
        result = evaluate("node", item.get("type"), item.get("finding_codes") or [], item.get("facts"), contexts[key],
                          item.get("location"))
        item.update(list_fields(result))
    return items


def detail(asset_type: str, codes: Iterable[Any], facts: dict[str, Any] | None, ctx: dict[str, Any],
           location: str | None = None) -> dict[str, Any]:
    """The ``agility`` block of the asset detail: class, floor, confidence and the per-code list."""
    result = evaluate("node", asset_type, codes, facts, ctx, location)
    return {"fix_class": result["fix_class"], "floor": result["floor"], "confidence": result["confidence"],
            "fix_class_excl_pq": excluding_pq(result),
            "by_code": [{k: p[k] for k in ("code", "class", "floor", "capability", "rule", "basis", "fact",
                                           "confidence")} for p in result["by_code"]],
            "model": MODEL, "model_version": version(), "source": "view"}


def code_row_fields(row: dict[str, Any]) -> dict[str, Any]:
    """fix_class, fix_class_floor and fix_class_confidence of a code-scan row (``cbom_rows.page_row``)."""
    facts = {"artifact_kind": row.get("artifact_kind")} if row.get("artifact_kind") else {}
    return list_fields(evaluate("code", row.get("asset_type"), row.get("finding_codes") or [], facts, CODE_CONTEXT))


def _counts(counter: Counter) -> dict[str, int]:
    return {v: counter.get(v, 0) for v in VALUES}


def self_fixable_pct(counts: dict[str, int]) -> float | None:
    """(configurable + code-fixed) over the assets with one of the four classes; None when there are none."""
    classified = sum(counts.get(c, 0) for c in CLASSES)
    return round(100.0 * sum(counts.get(c, 0) for c in SELF_FIXABLE) / classified, 1) if classified else None


class RunAgility:
    """Run posture accumulator: ``add(row, codes)`` per asset with the codes the posture already shows, then
    ``result()``: counts per class (all codes, and without the post-quantum codes), unknown reasons (assets per reason:
    an unknown asset counts once for each distinct reason of its codes), the self-fixable
    share and per-system counts (system = the job snapshot's ``application``, else the source)."""

    def __init__(self, session: Any, team_id: int, run_id: int, sources: dict[int, Any]) -> None:
        from sqlmodel import select

        from backend.new_models import CbomCollectionJob

        jobs = session.exec(select(CbomCollectionJob).where(CbomCollectionJob.team_id == team_id,
                                                            CbomCollectionJob.run_id == run_id)).all()
        self._jobs = {j.id: j for j in jobs}
        self._sources = sources
        self._ctx: dict[tuple, tuple[tuple, Counter]] = {}
        self._kb = crypto_kb.version()
        self.all: Counter = Counter()
        self.excl_pq: Counter = Counter()
        self.reasons: Counter = Counter()
        self.systems: dict[tuple[str, str], dict[str, Any]] = {}

    def _system(self, job: Any, source: Any, ctx: dict[str, Any]) -> tuple[tuple[str, str], str]:
        app = str(ctx.get("application") or "").strip()
        if app:
            return ("application", app.lower()), app
        params = (getattr(job, "params", None) or {}) if job is not None else {}
        uid = getattr(source, "source_uid", None) or params.get("source_uid") or getattr(source, "id", None) or "?"
        name = getattr(source, "name", None) or params.get("source_name") or str(uid)
        return ("source", str(uid)), str(name)

    def add(self, row: Any, codes: list[str]) -> None:
        key = (row.job_id, row.source_id)
        entry = self._ctx.get(key)
        if entry is None:
            job, source = self._jobs.get(row.job_id or 0), self._sources.get(row.source_id or 0)
            ctx = node_context(job, source)
            (kind, skey), label = self._system(job, source, ctx)
            system = self.systems.setdefault((kind, skey), {"key": f"{kind}:{skey}", "label": label, "kind": kind,
                                                            "counts": Counter()})
            entry = self._ctx[key] = (_ctx_key(ctx), system["counts"])
        ctx_key, system_counts = entry
        facts = row.facts if isinstance(row.facts, dict) else {}
        a_type = row.asset_type or ""
        whole, _per, excl_pq, reasons = _evaluate(self._kb, "node", a_type, _codes(codes),
                                                  _deciding(a_type, facts, row.location), ctx_key)
        cls = whole["fix_class"]
        self.all[cls] += 1
        self.excl_pq[excl_pq] += 1
        if reasons:
            self.reasons.update(reasons)
        system_counts[cls] += 1

    def result(self) -> dict[str, Any]:
        systems = []
        for item in self.systems.values():
            counts = _counts(item["counts"])
            hardest = max((c for c in CLASSES if counts[c]), key=RANK.__getitem__, default=None)
            systems.append({"key": item["key"], "label": item["label"], "kind": item["kind"],
                            "assets": sum(counts.values()), "hardest": hardest, "counts": counts,
                            "self_fixable_pct": self_fixable_pct(counts)})
        systems.sort(key=lambda s: (-s["assets"], s["label"]))
        counts = _counts(self.all)
        return {
            "fix_classes": counts,
            "fix_classes_excl_pq": _counts(self.excl_pq),
            "fix_class_self_fixable_pct": self_fixable_pct(counts),
            "unknown_reasons": dict(sorted(self.reasons.items())),
            "fix_class_systems": systems[:SYSTEMS_CAP],
            "fix_class_systems_truncated": len(systems) > SYSTEMS_CAP,
            "agility_version": version(),
        }


# ----------------------------------------------------------------------------------------------- evidence items
_AREA_CLASS = {"hsm_firmware": "hardware-fixed", "third_party_vendors": "vendor-fixed"}


def evidence_area_fields(area_key: str, answers: dict[str, Any] | None) -> dict[str, Any]:
    """An evidence area as an agility subject: an answered HSM firmware area is hardware-fixed and an answered
    third-party area vendor-fixed (by definition, observed); an unanswered one is "not assessed" (not unknown); the
    process areas (key hierarchy, ceremonies, escrow, backup encryption) carry no class."""
    cls = _AREA_CLASS.get(area_key)
    if cls is None:
        return {"fix_class": None, "not_assessed": False}
    answered = any(str(v or "").strip() for v in (answers or {}).values())
    return {"fix_class": cls if answered else None, "not_assessed": not answered}


def evidence_vendor_fields() -> dict[str, Any]:
    """Each third-party vendor is vendor-fixed: only the vendor changes the cryptography of its service."""
    return {"fix_class": "vendor-fixed", "not_assessed": False}


# ----------------------------------------------------------------------------------------------- model
def model() -> dict[str, Any]:
    """The classes, their order and text, and the rules: what the (i) tips and the export cite."""
    return {"model": MODEL, "model_version": version(), "kb_version": crypto_kb.version(),
            "classes": [{"key": key, "rank": RANK.get(key), **CLASS_TEXT[key]} for key in VALUES],
            "inferred": INFERRED_TEXT, "pq_codes": sorted(PQ_CODES), "self_fixable": list(SELF_FIXABLE),
            "rules": [dict(r) for r in RULES], "unknown_reasons": dict(UNKNOWN_REASONS)}


__all__ = ["CLASSES", "MODEL", "PQ_CODES", "RunAgility", "VALUES", "annotate_assets", "asset_class", "code_class",
           "code_row_fields", "detail", "evaluate", "evidence_area_fields", "evidence_vendor_fields", "model",
           "node_context", "table", "version"]
