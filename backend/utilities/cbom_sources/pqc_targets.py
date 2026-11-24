"""NIST post-quantum target per asset FUNCTION, and the proposed date per remediation wave (D13 roadmap, D12 CSV).

One table drives every surface: the crypto knowledge base's ``pqc_context.migration_targets`` (one row per usage:
key establishment, TLS / SSH / IKE key exchange, signatures, certificates, CAs, code signing, symmetric, hashes) and
``pqc_context.wave_milestones`` (each wave's date, tied to NIST IR 8547 and CNSA 2.0). A KB row never spells a
post-quantum name: it holds an algid SELECTOR (published standard, NIST category, construction, registry), and this
module resolves it against algid's rows, the single source of post-quantum names and parameter sets
(``tests/test_algid_single_source.py``). So the names printed in a PDF, a CSV or an API response are algid's.

``usage_of`` derives an asset's function from what was collected (its type, the code lane's primitive, its facts and
algorithm); ``target_for`` gives the row; ``asset_target`` is both in one call. The KB table and the selectors are
memoised per KB version; ``usage_of`` is a cheap pure function. No database.

Dates (D13, the wave API): a wave's CLASSICAL weaknesses (any weakness a classical attacker can use today: an
algorithm or key size SP 800-131A disallows such as RSA-1024 or Triple DES, and others such as TLS 1.0 or an expired
certificate) are due within the wave's window (``fix_within_days``, a team setting) of when the asset was FIRST FOUND
(``proposed_dates`` ``found_on``), never of the day a document is rendered, so the date is fixed and becomes overdue;
the IR 8547 / CNSA 2.0 dates (``pq_date``) are for the post-quantum migration only.

NIST IR 8547: every status, date and URL a deliverable prints comes from the ONE knowledge-base entry
``pqc_context.nist_ir_8547`` (``ir8547``), so a document cannot cite it as final in one place and as a draft in another.
"""
from __future__ import annotations

import datetime as _dt
import functools
import logging
import re
from collections.abc import Iterable, Mapping
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
    only = set(sel.get("names") or ())
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
        if only and name not in only:
            continue
        label = parameter_set if construction == "pure" and parameter_set else name
        if sel.get("variant") and not label.endswith(sel["variant"]):
            continue
        if label not in names:
            names.append(label)
    if not names:
        raise LookupError(f"no standard algid row for selector {sel}")
    if only and len(names) != len(only):
        raise LookupError(f"selector {sel}: names not standard algid rows of its standard: {sorted(only)}")
    if len(names) > 1 and not sel.get("all"):
        raise LookupError(f"selector {sel} is ambiguous: {names}")
    return " / ".join(sorted(names)) if sel.get("all") else names[0]


def _key(sel: Mapping[str, Any]) -> tuple[tuple[str, Any], ...]:
    return tuple(sorted((k, tuple(v) if isinstance(v, list) else v) for k, v in sel.items()))


def excluded(sel: Mapping[str, Any]) -> list[str]:
    """The names a ``names``-restricted selector leaves out of its standard (CNSA 2.0: the multi-tree SP 800-208
    schemes), from algid, for the note that says so."""
    if not sel.get("names"):
        return []
    full = _select(_key({**{k: v for k, v in sel.items() if k != "names"}, "all": True}))
    return [n for n in full.split(" / ") if n not in set(sel["names"])]


def render(parts: Any) -> str:
    """A KB target (a list of ``{"select": ...}`` / ``{"text": ...}`` parts) as text."""
    out = []
    for part in parts or ():
        if "select" in part:
            out.append(_select(_key(part["select"])) + part.get("suffix", ""))
        else:
            out.append(str(part.get("text") or ""))
    return "".join(out)


# --------------------------------------------------------------------------------------------- the table
@functools.lru_cache(maxsize=4)
def _table(kb_version: str) -> dict[str, dict[str, Any]]:
    ctx = crypto_kb.pqc_context()
    out: dict[str, dict[str, Any]] = {}
    for row in ctx.get("migration_targets") or ():
        try:
            target = render(row["target"])
            then = render(row.get("then"))
            cnsa = render(row.get("cnsa"))
        except LookupError:  # a KB row algid cannot resolve: logged, the row is left out (never a crash)
            _LOG.exception("pqc_targets: KB migration target %s does not resolve against algid", row.get("usage"))
            continue
        cnsa_excluded = [n for part in row.get("cnsa") or () if "select" in part for n in excluded(part["select"])]
        out[row["usage"]] = {
            "usage": row["usage"], "usage_label": row["label"], "target": target, "then": then or None,
            "target_text": f"{target}, then {then}" if then else target,
            "cnsa_target": cnsa, "cnsa_excluded": cnsa_excluded, "reference": row["reference"],
            "note": row.get("note") or "",
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


# --------------------------------------------------------------------------------------------- NIST IR 8547
# Only for a knowledge base without the entry's own fields; never printed over a value the KB records.
_IR_DEFAULT = {"citation": "NIST IR 8547", "deprecated_after": 2030, "disallowed_after": 2035}
_TRAILING_NOTE = re.compile(r"\s*\([^()]*\)\s*$")


def ir8547() -> dict[str, Any]:
    """NIST IR 8547 as the knowledge base records it (``pqc_context.nist_ir_8547``): name, citation, status ("final" |
    "draft"), url, published, deprecated_after, disallowed_after.

    The status is the entry's own ``status``; a KB that does not record one is read from its URL (``/ipd`` is the
    initial public draft), so the status and the URL never disagree. The printed ``citation`` is BUILT from the name
    (the KB citation without any parenthetical, e.g. "NIST IR 8547 (final, 2026)" -> "NIST IR 8547"), the status and
    the publication year: "NIST IR 8547 (final, 2026)" for a final entry with a ``published`` date, the bare name
    otherwise (a draft's sentences say "is a draft" themselves). A status embedded in the KB's citation text never
    decides what is printed, so the citation and the status cannot contradict each other."""
    found = (crypto_kb.pqc_context() or {}).get("nist_ir_8547") or {}
    out = {**_IR_DEFAULT, **{k: v for k, v in found.items() if v not in (None, "")}}
    out["url"] = str(out.get("landing") or out.get("source") or "")
    if not out.get("status"):
        out["status"] = "draft" if re.search(r"(/ipd\b|\.ipd\.)", out["url"]) else "final"
    out["status"] = "draft" if str(out["status"]).strip().lower() != "final" else "final"
    name = _TRAILING_NOTE.sub("", str(out.get("citation") or "")).strip() or _IR_DEFAULT["citation"]
    year = str(out.get("published") or "")[:4]
    out["name"] = name
    out["citation"] = f"{name} (final, {year})" if out["status"] == "final" and year.isdigit() else name
    return out


def _cite_url(key: str) -> str:
    if key == "nist_ir_8547":
        return ir8547()["url"]
    entry = (crypto_kb.pqc_context() or {}).get(key) or {}
    return str(entry.get("source") or "")


# --------------------------------------------------------------------------------------------- wave dates
@functools.lru_cache(maxsize=4)
def _milestones(kb_version: str) -> dict[int, dict[str, Any]]:
    out = {}
    for m in crypto_kb.pqc_context().get("wave_milestones") or ():
        row = dict(m)
        row["sources"] = [u for u in (_cite_url(k) for k in row.get("cites") or ()) if u] or list(
            row.get("sources") or [])
        row["basis"] = row.get("pq_basis") or row.get("basis") or ""
        row["pq_date"] = row.get("pq_date") or row.get("date")
        out[int(m["wave"])] = row
    return out


def wave_milestone(wave: Any) -> dict[str, Any] | None:
    """{wave, pq_date (YYYY-MM-DD), pq_basis, fix_within_days, fix_basis, date (= pq_date), basis, sources} of a
    remediation wave (1-4), or None."""
    try:
        return _milestones(crypto_kb.version()).get(int(wave))
    except (TypeError, ValueError):
        return None


def milestones() -> list[dict[str, Any]]:
    return [m for _w, m in sorted(_milestones(crypto_kb.version()).items())]


# the team setting (``risk_model``) that replaces a wave's classical window; 1..3650 days
FIX_DAYS_KEYS = {1: "wave1_fix_days", 2: "wave2_fix_days", 3: "wave3_fix_days"}


def fix_windows(risk_model: Mapping[str, Any] | None = None) -> dict[int, int]:
    """Days from when an asset was first found to fix each wave's classical weaknesses: the team's setting, else the
    KB default."""
    model = risk_model if isinstance(risk_model, Mapping) else {}
    out: dict[int, int] = {}
    for wave, key in FIX_DAYS_KEYS.items():
        value = model.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 3650:
            out[wave] = value
        else:
            default = (wave_milestone(wave) or {}).get("fix_within_days")
            if isinstance(default, int):
                out[wave] = default
    return out


def window_order_error(windows: Mapping[int, Any]) -> str | None:
    """Why ``windows`` (wave -> days, any of 1-3) are out of order, else None: wave 1 is the urgent one, so its window
    may not be longer than wave 2's, nor wave 2's than wave 3's (``wave1 <= wave2 <= wave3``; equal is allowed)."""
    known = [(w, windows[w]) for w in (1, 2, 3) if isinstance(windows.get(w), int) and not isinstance(windows[w], bool)]
    for (wa, da), (wb, db) in zip(known, known[1:]):
        if da > db:
            return (f"risk_model: wave {wa} ({da} days) must not take longer than wave {wb} ({db} days); "
                    "wave1_fix_days <= wave2_fix_days <= wave3_fix_days")
    return None


def _quantum_code(code: str) -> bool:
    """A finding that is only the quantum verdict (KB category ``pqc``: QUANTUM_VULNERABLE, NO_PQ_KEX ...)."""
    if code == "QUANTUM_VULNERABLE":
        return True
    entry = crypto_kb.entry("node", code) or crypto_kb.entry("code", code) or {}
    return entry.get("category") == "pqc"


def classical_weakness(codes: Iterable[Any]) -> bool:
    """The asset has a weakness a classical attacker can use today (a finding that is not a coverage note and not
    the quantum verdict): its fix is dated from when the asset was first found, not from a post-quantum milestone."""
    return any(isinstance(c, str) and c and not c.startswith("COVERAGE_") and not _quantum_code(c) for c in codes)


# Why a classical weakness is dated (``proposed_dates`` ``fix_basis``): only an algorithm or key size NIST disallows
# today (``qgrade.disallowed_now``: SP 800-131A, DSA by FIPS 186-5) is cited as disallowed; any other weakness (an
# expired or self-signed certificate, a legacy protocol setting ...) is described as what it is.
FIX_BASIS_TEXT = {
    "disallowed": "an algorithm or key size NIST disallows today, under SP 800-131A or, for DSA, FIPS 186-5",
    "classical": "a weakness a classical attacker can use today, such as an expired or self-signed certificate or a "
                 "legacy protocol setting, with no SP 800-131A disallowance claimed",
}


def _iso_day(value: Any) -> _dt.date | None:
    if isinstance(value, _dt.datetime):
        return value.date()
    if isinstance(value, _dt.date):
        return value
    if isinstance(value, str) and len(value) >= 10:
        try:
            return _dt.date.fromisoformat(value[:10])
        except ValueError:
            return None
    return None


def proposed_dates(wave: Any, codes: Iterable[Any], quantum_vulnerable: Any, as_of: _dt.date,
                   windows: Mapping[int, int] | None = None, *, found_on: Any = None,
                   disallowed: bool | None = None) -> dict[str, Any]:
    """The proposed dates of one asset in ``wave``.

    ``fix_by``: its classical weakness (waves 1-3 only), the wave's window counted from ``found_on``, the day the asset
    was first found (node assets: the estate's ``first_seen_at``; code rows: the earliest included scan with the same
    stable key); ``as_of`` only when that is unknown. So the date never moves with the day a document is rendered.
    ``pq_by``: its post-quantum migration, the wave's IR 8547 / CNSA 2.0 milestone (quantum-vulnerable assets, and any
    asset with no classical weakness). ``date`` / ``kind``: the one the asset is due by first. ``overdue``: ``as_of`` is
    past ``date``. ``found_on``: the anchor used (YYYY-MM-DD) and ``found_basis`` "first_seen" | "as_of".
    ``fix_basis``: "disallowed" (``disallowed`` is True) | "classical" | None (``FIX_BASIS_TEXT``)."""
    milestone = wave_milestone(wave)
    if milestone is None:
        return {"date": None, "kind": None, "fix_by": None, "pq_by": None, "found_on": None, "found_basis": None,
                "overdue": False, "fix_basis": None}
    windows = fix_windows() if windows is None else windows
    classical = classical_weakness(codes or ())
    days = windows.get(int(milestone["wave"])) if classical else None
    anchor = _iso_day(found_on)
    basis = "first_seen" if anchor is not None else "as_of"
    anchor = anchor or as_of
    fix_by = (anchor + _dt.timedelta(days=int(days))).isoformat() if days else None
    pq_by = milestone.get("pq_date") if (quantum_vulnerable is True or not fix_by) else None
    kind = "fix" if fix_by else ("pq" if pq_by else None)
    date = fix_by or pq_by
    return {"date": date, "kind": kind, "fix_by": fix_by, "pq_by": pq_by,
            "found_on": anchor.isoformat() if fix_by else None, "found_basis": basis if fix_by else None,
            "overdue": bool(date) and as_of.isoformat() > str(date),
            "fix_basis": ("disallowed" if disallowed else "classical") if fix_by else None}


_LOG = logging.getLogger(__name__)
UNASSIGNED_OWNER = "unassigned — confirm with owner"
# the waves of ``waves.WAVE_RULES`` (waves.WAVE_LABEL is this table)
WAVE_LABEL = {1: "Wave 1: urgent (exposed or HNDL)", 2: "Wave 2: high", 3: "Wave 3: other weaknesses",
              4: "Wave 4: post-quantum migration"}

__all__ = ["FIX_BASIS_TEXT", "FIX_DAYS_KEYS", "UNASSIGNED_OWNER", "WAVE_LABEL", "asset_target", "cell_text", "classical_weakness",
           "excluded", "fix_windows", "ir8547", "milestones", "proposed_dates", "render", "table", "target_for",
           "usage_of", "wave_milestone", "window_order_error"]
