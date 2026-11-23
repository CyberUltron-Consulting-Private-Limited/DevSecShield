"""NIST post-quantum target per asset FUNCTION, and the proposed date per remediation wave (D13 roadmap, D12 CSV).

One table drives every surface: the crypto knowledge base's ``pqc_context.migration_targets`` (one row per usage:
key establishment, TLS / SSH / IKE key exchange, signatures, certificates, CAs, code signing, symmetric, hashes) and
``pqc_context.wave_milestones`` (each wave's date, tied to NIST IR 8547 and CNSA 2.0). A KB row never spells a
post-quantum name: it holds an algid SELECTOR (published standard, NIST category, construction, registry), and this
module resolves it against algid's rows, the single source of post-quantum names and parameter sets
(``tests/test_algid_single_source.py``). So the names printed in a PDF, a CSV or an API response are algid's.

``usage_of`` derives an asset's function from what was collected (its type, the code lane's primitive, its facts and
algorithm); ``target_for`` gives the row; ``asset_target`` is both in one call. Pure and memoised; no database.
"""
from __future__ import annotations

import functools
import re
from typing import Any

from backend.utilities.cbom_sources import algid as A
from backend.utilities.cbom_sources import crypto_kb

# --------------------------------------------------------------------------------------------- the asset's function
_TLS_TYPES = frozenset({"tls_endpoint", "database_tls", "load_balancer_tls", "cdn_tls", "api_tls", "k8s_ingress_tls",
                        "k8s_mesh_policy", "k8s_mesh_destination", "k8s_mesh_server", "db_crypto_policy"})
_SSH_KEX_TYPES = frozenset({"ssh_endpoint", "ssh_server_config"})
_VPN_TYPES = frozenset({"ike_endpoint"})
_CERT_TYPES = frozenset({"certificate", "k8s_tls_secret", "iam_certificate", "k8s_certificate"})
_CA_TYPES = frozenset({"cloud_ca", "ca_authority", "ca_template"})
_SIGNING_TYPES = frozenset({"ssh_host_key", "signing_key", "identity_provider"})
_SYMMETRIC_TYPES = frozenset({"storage_encryption", "db_encryption", "disk_encryption"})
# code lane primitives (CycloneDX 1.6 cryptoProperties.algorithmProperties.primitive)
_PRIMITIVE = {"kem": "key_establishment", "key-agree": "key_establishment", "pke": "key_establishment",
              "signature": "signature", "block-cipher": "symmetric", "stream-cipher": "symmetric", "ae": "symmetric",
              "hash": "hash", "mac": "hash", "xof": "hash", "kdf": "hash"}
_CODE_SIGNING = re.compile(r"code[\s_-]?sign|firmware", re.IGNORECASE)
_SIGN_USAGE = re.compile(r"sign|verify", re.IGNORECASE)
_ENCRYPT_USAGE = re.compile(r"encrypt|decrypt|wrap|key[\s_-]?agreement|derive", re.IGNORECASE)
_HASH = re.compile(r"^(sha|md[245]|ripemd|blake|hmac|whirlpool)", re.IGNORECASE)
_SYMMETRIC = re.compile(r"^(aes|3des|tdea|des|desede|triple|rc[24]|blowfish|chacha|camellia|seed|idea|sm4|"
                        r"symmetric|oct\b)", re.IGNORECASE)
_KEX_FAMILIES = frozenset({"ECDH", "DH", "X25519", "X448"})
_SIG_FAMILIES = frozenset({"ECDSA", "ED25519", "ED448", "EDDSA", "DSA"})


def _facts(facts: Any) -> dict[str, Any]:
    return facts if isinstance(facts, dict) else {}


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _by_algorithm(algorithm: str, facts: dict[str, Any]) -> str | None:
    """A key or algorithm row's usage from its stated key usage, else its algorithm family."""
    usage = " ".join(_text(facts.get(k)) for k in ("key_usage", "usage", "purpose", "key_spec_usage", "use"))
    if _CODE_SIGNING.search(usage):
        return "code_signing"
    if _SIGN_USAGE.search(usage) and not _ENCRYPT_USAGE.search(usage):
        return "signature"
    name = algorithm.strip()
    if not name:
        return None
    if _HASH.match(name):
        return "hash"
    if _SYMMETRIC.match(name) or name.upper() in ("SYMMETRIC_DEFAULT", "AES"):
        return "symmetric"
    if _ENCRYPT_USAGE.search(usage):
        return "key_establishment"
    family = A.family_label(name)
    if family in _KEX_FAMILIES:
        return "key_establishment"
    if family in _SIG_FAMILIES:
        return "signature"
    if family in ("RSA", "EC", "SM2", "PQ"):
        return "asymmetric"
    return None


def usage_of(asset_type: str | None, algorithm: Any = None, facts: Any = None, primitive: Any = None) -> str | None:
    """The function the asset's cryptography serves (a ``migration_targets`` usage), or None when nothing collected
    says it (a coverage row, a setting with no algorithm)."""
    kind, facts, algorithm = str(asset_type or ""), _facts(facts), _text(algorithm)
    prim = _text(primitive).strip().casefold()
    if prim in _PRIMITIVE:
        usage = _PRIMITIVE[prim]
        if usage == "signature" and _CODE_SIGNING.search(" ".join(_text(facts.get(k)) for k in ("eku", "usage"))):
            return "code_signing"
        return usage
    if kind in _TLS_TYPES:
        return "tls_kex"
    if kind in _SSH_KEX_TYPES:
        return "ssh_kex"
    if kind in _VPN_TYPES:
        return "vpn_kex"
    if kind in _CA_TYPES:
        return "ca_signature"
    if kind in _CERT_TYPES:
        eku = facts.get("eku") or facts.get("extended_key_usage") or ""
        eku = " ".join(eku) if isinstance(eku, list) else _text(eku)
        if _CODE_SIGNING.search(eku):
            return "code_signing"
        return "ca_signature" if facts.get("is_ca") is True else "certificate"
    if kind in _SIGNING_TYPES:
        return "code_signing" if _CODE_SIGNING.search(_text(facts.get("usage"))) else "signature"
    if kind in _SYMMETRIC_TYPES:
        return "symmetric"
    if kind == "kms_key" and _text(facts.get("key_spec")).upper() == "SYMMETRIC_DEFAULT":
        return "symmetric"
    return _by_algorithm(algorithm or _text(facts.get("key_alg")) or _text(facts.get("key_spec")), facts)


# --------------------------------------------------------------------------------------------- algid selectors
def _rows() -> dict[str, tuple[Any, ...]]:
    return dict(A._ALGS)  # algid's identity rows (vendored, generated): name -> (family, primitive, standard, status, ...)


@functools.lru_cache(maxsize=256)
def _select(items: tuple[tuple[str, Any], ...]) -> str:
    """The name(s) a KB selector stands for. Rows of status ``standard`` only; a pure parameter set prints as its
    FIPS parameter set name (one name for its pre-hash twin); ``all`` joins every match."""
    sel = dict(items)
    registry = {"tls_group": set(A._TLS_GROUPS.values()), "ssh_kex": set(A._SSH_KEX.values())}.get(
        sel.get("registry"))
    names: list[str] = []
    for name, row in _rows().items():
        _fam, _prim, standard, status, parameter_set, category, construction = row[:7]
        components = row[9] if len(row) > 9 and isinstance(row[9], tuple) else ()
        if status != "standard" or standard != sel.get("standard"):
            continue
        if "category" in sel and category != sel["category"]:
            continue
        if construction != sel.get("construction", "pure"):
            continue
        if sel.get("with") and sel["with"] not in components:
            continue
        if registry is not None and name not in registry:
            continue
        label = parameter_set if construction == "pure" and parameter_set else name
        if sel.get("variant") and not label.endswith(sel["variant"]):
            continue
        if label not in names:
            names.append(label)
    if not names:
        raise LookupError(f"no standard algid row for selector {sel}")
    if len(names) > 1 and not sel.get("all"):
        raise LookupError(f"selector {sel} is ambiguous: {names}")
    return " / ".join(sorted(names)) if sel.get("all") else names[0]


def render(parts: Any) -> str:
    """A KB target (a list of ``{"select": ...}`` / ``{"text": ...}`` parts) as text."""
    out = []
    for part in parts or ():
        if "select" in part:
            out.append(_select(tuple(sorted(part["select"].items()))) + part.get("suffix", ""))
        else:
            out.append(str(part.get("text") or ""))
    return "".join(out)


# --------------------------------------------------------------------------------------------- the table
@functools.lru_cache(maxsize=4)
def _table(kb_version: str) -> dict[str, dict[str, Any]]:
    ctx = crypto_kb.pqc_context()
    out: dict[str, dict[str, Any]] = {}
    for row in ctx.get("migration_targets") or ():
        target = render(row["target"])
        then = render(row.get("then"))
        out[row["usage"]] = {
            "usage": row["usage"], "usage_label": row["label"], "target": target, "then": then or None,
            "target_text": f"{target}, then {then}" if then else target,
            "cnsa_target": render(row.get("cnsa")), "reference": row["reference"], "note": row.get("note") or "",
        }
    return out


def table() -> dict[str, dict[str, Any]]:
    """usage -> {usage, usage_label, target, then, target_text, cnsa_target, reference, note} (names from algid)."""
    return _table(crypto_kb.version())


def target_for(usage: str | None) -> dict[str, Any] | None:
    return table().get(usage or "")


def asset_target(asset_type: str | None, algorithm: Any = None, facts: Any = None,
                 primitive: Any = None) -> dict[str, Any] | None:
    """The NIST PQ target row of one asset (its usage derived from what was collected), or None."""
    return target_for(usage_of(asset_type, algorithm, facts, primitive))


def cell_text(target: dict[str, Any] | None) -> str:
    """One table cell: the target, its CNSA 2.0 variant when different, and the standard."""
    if not target:
        return "not derivable (no algorithm recorded)"
    text = target["target_text"]
    if target["cnsa_target"] and target["cnsa_target"] != target["target"]:
        text += f"\nCNSA 2.0: {target['cnsa_target']}"
    return f"{text}\n({target['reference']})"


# --------------------------------------------------------------------------------------------- wave dates
@functools.lru_cache(maxsize=4)
def _milestones(kb_version: str) -> dict[int, dict[str, Any]]:
    return {int(m["wave"]): dict(m) for m in crypto_kb.pqc_context().get("wave_milestones") or ()}


def wave_milestone(wave: Any) -> dict[str, Any] | None:
    """{wave, date (YYYY-MM-DD), basis, sources} of a remediation wave (1-4), or None."""
    try:
        return _milestones(crypto_kb.version()).get(int(wave))
    except (TypeError, ValueError):
        return None


def milestones() -> list[dict[str, Any]]:
    return [m for _w, m in sorted(_milestones(crypto_kb.version()).items())]


UNASSIGNED_OWNER = "unassigned — confirm with owner"
# the waves of ``waves.WAVE_RULES`` (waves.WAVE_LABEL is this table)
WAVE_LABEL = {1: "Wave 1: urgent (exposed or HNDL)", 2: "Wave 2: high", 3: "Wave 3: other weaknesses",
              4: "Wave 4: post-quantum migration"}

__all__ = ["UNASSIGNED_OWNER", "WAVE_LABEL", "asset_target", "cell_text", "milestones", "render", "table", "target_for", "usage_of",
           "wave_milestone"]
