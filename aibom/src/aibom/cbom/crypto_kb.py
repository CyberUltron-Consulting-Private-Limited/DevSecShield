"""Offline cryptography knowledge base: explanation, CWE / OWASP / CVE mapping, remediation and proof-of-exposure
commands for every CBOM finding code. No network access and no language model: everything comes from the JSON file
shipped next to this module (built from NVD, MITRE CWE, OWASP and the regulators' own documents).

This file is kept byte-identical in two places (the code-scan engine and the API) so both read the same rules;
a test compares them.

Updates: an operator may point CBOM_KB_BUNDLE at a newer crypto_kb.json. It is used only when CBOM_KB_BUNDLE_SIG
holds a valid Ed25519 signature of the exact file by one of the keys in CBOM_KB_PUBKEYS (comma-separated, base64
raw 32-byte public keys) and when it keeps every finding code of the built-in file (stored scans reference them; an
update may add or change entries, never drop one). Anything else falls back to the built-in file and logs why.
"""
from __future__ import annotations

import base64
import datetime as _dt
import json
import logging
import os
import re
from functools import lru_cache
from typing import Any

log = logging.getLogger(__name__)

_BUILTIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "crypto_kb.json")
SCHEMA = 1

# OWASP Top 10:2021 id -> the enum name the code-scan dashboard stores (labels come from the KB, which copies them
# from owasp.org; the enum labels in the product use the same text).
_OWASP_2021_ENUM = {
    "A01:2021": "BROKEN_ACCESS_CONTROL", "A02:2021": "CRYPTOGRAPHIC_FAILURES", "A03:2021": "INJECTION",
    "A04:2021": "INSECURE_DESIGN", "A05:2021": "SECURITY_MISCONFIGURATION",
    "A06:2021": "VULNERABLE_AND_OUTDATED_COMPONENTS", "A07:2021": "IDENTIFICATION_AND_AUTHENTICATION_FAILURES",
    "A08:2021": "SOFTWARE_AND_DATA_INTEGRITY_FAILURES", "A09:2021": "SECURITY_LOGGING_AND_MONITORING_FAILURES",
    "A10:2021": "SERVER_SIDE_REQUEST_FORGERY",
}
_PLACEHOLDER = re.compile(r"\{(host|port|path|name|location|resource|line)\}")


# --------------------------------------------------------------------------------------------------------- loading
def _verify_bundle(data: bytes, sig_path: str, keys: str) -> str | None:
    """None when the signature is valid for one of the keys, else the reason it is not."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return "the cryptography package is not installed, so the signature cannot be checked"
    try:
        with open(sig_path, "rb") as fh:
            signature = base64.b64decode(fh.read().strip(), validate=True)
    except (OSError, ValueError) as exc:
        return f"signature file unreadable ({exc.__class__.__name__})"
    malformed = 0
    for raw in [k.strip() for k in keys.split(",") if k.strip()]:
        try:
            key = Ed25519PublicKey.from_public_bytes(base64.b64decode(raw, validate=True))
        except ValueError:
            malformed += 1
            continue
        try:
            key.verify(signature, data)
            return None
        except InvalidSignature:
            continue
    note = f" ({malformed} key(s) in CBOM_KB_PUBKEYS are not base64 raw Ed25519 keys)" if malformed else ""
    return "the signature does not match any trusted key" + note


def _read_builtin() -> dict[str, Any]:
    with open(_BUILTIN, encoding="utf-8") as fh:
        return json.load(fh)


def _version_key(value: Any) -> tuple[int, ...]:
    """'2026.10.31.10' > '2026.10.31.9' and > '2026.9.30.1' (numbers, not text); anything malformed sorts lowest."""
    parts = str(value or "").strip().split(".")
    if not parts or not all(p.isdigit() for p in parts):
        return (-1,)
    return tuple(int(p) for p in parts)


def _missing_codes(candidate: dict[str, Any], builtin: dict[str, Any]) -> list[str]:
    """'namespace:CODE' for every finding code of the built-in knowledge base the candidate does not have."""
    have = candidate.get("findings") if isinstance(candidate.get("findings"), dict) else {}
    out = []
    for namespace, entries in sorted((builtin.get("findings") or {}).items()):
        theirs = have.get(namespace) if isinstance(have.get(namespace), dict) else {}
        out += [f"{namespace}:{code}" for code in sorted(entries or {}) if code not in theirs]
    return out


@lru_cache(maxsize=1)
def load() -> dict[str, Any]:
    """The knowledge base in force: a signed update bundle when one is configured and valid, else the built-in."""
    builtin = _read_builtin()
    bundle = os.environ.get("CBOM_KB_BUNDLE")
    if not bundle:
        return builtin
    sig = os.environ.get("CBOM_KB_BUNDLE_SIG") or bundle + ".sig"
    keys = os.environ.get("CBOM_KB_PUBKEYS") or ""
    reason = None
    try:
        with open(bundle, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        reason = f"bundle unreadable ({exc.__class__.__name__})"
        data = b""
    if reason is None:
        reason = "CBOM_KB_PUBKEYS is empty" if not keys else _verify_bundle(data, sig, keys)
    if reason is None:
        try:
            candidate = json.loads(data)
        except ValueError:
            candidate, reason = None, "bundle is not JSON"
        if candidate is not None:
            missing = _missing_codes(candidate, builtin) if isinstance(candidate, dict) else []
            if not isinstance(candidate, dict) or candidate.get("schema") != SCHEMA:
                reason = f"bundle schema {candidate.get('schema') if isinstance(candidate, dict) else None} is not {SCHEMA}"
            elif _version_key(candidate.get("kb_version")) <= _version_key(builtin.get("kb_version")):
                reason = "bundle is not newer than the built-in knowledge base"
            elif missing:
                # stored scans and runs reference these codes; an update may add and change entries, never drop them
                reason = (f"bundle lacks {len(missing)} finding code(s) the built-in knowledge base has "
                          f"({', '.join(missing[:10])})")
            else:
                log.info("crypto KB: using signed bundle %s", candidate.get("kb_version"))
                return candidate
    log.warning("crypto KB: ignoring update bundle %s: %s; using built-in %s", bundle, reason, builtin.get("kb_version"))
    return builtin


def version() -> str:
    return str(load().get("kb_version") or "")


def entry(namespace: str, code: str) -> dict[str, Any] | None:
    """Knowledge entry for a finding code. namespace: 'node' (scan-node runs) or 'code' (code and CBOM-file scans)."""
    return (load().get("findings") or {}).get(namespace, {}).get(code)


# ------------------------------------------------------------------------------------------------ CVEs and mapping
def cve(cve_id: str) -> dict[str, Any] | None:
    return (load().get("cves") or {}).get(cve_id)


# Findings whose evidence IS an advisory (the code scanner copies the advisory's CVE IDs into it). Only for these are
# CVE IDs taken from the evidence text; elsewhere a CVE ID in stored text may belong to another finding on the same
# asset or to an older knowledge base, and must not be attached.
_ADVISORY_CODES = {("code", "VULNERABLE_CRYPTO_LIBRARY"), ("code", "KNOWN_TLS_VULNERABILITY")}


def cves_for(namespace: str, code: str, evidence: str = "") -> list[dict[str, Any]]:
    """CVEs that apply to this finding: the entry's own list, plus rules whose pattern matches the evidence text
    (and, for advisory findings only, the CVE IDs the advisory names)."""
    e = entry(namespace, code)
    if not e:
        return []
    out: dict[str, dict[str, Any]] = {}
    for cid in e.get("cves") or []:
        out[cid] = {"matched_on": "finding type"}
    for rule in e.get("cve_rules") or []:
        m = re.search(rule["match"], evidence or "", re.I)
        if m:
            for cid in rule["cves"]:
                out.setdefault(cid, {"matched_on": m.group(0)})
    if (namespace, code) in _ADVISORY_CODES:
        for cid in re.findall(r"CVE-\d{4}-\d{4,7}", evidence or ""):
            out.setdefault(cid, {"matched_on": "reported by the scanner"})
    result = []
    for cid, why in out.items():
        rec = cve(cid) or {"id": cid, "url": f"https://nvd.nist.gov/vuln/detail/{cid}", "summary": None, "cvss": None}
        result.append({**rec, **why})
    return result


def owasp_legacy(namespace: str, codes: list[str]) -> dict[str, str]:
    """OWASP Top 10:2021 as the code-scan dashboard stores it: {ENUM_NAME: 'A02:2021 - Cryptographic Failures'}."""
    out: dict[str, str] = {}
    for code in codes:
        for item in (entry(namespace, code) or {}).get("owasp_2021") or []:
            enum = _OWASP_2021_ENUM.get(item["id"])
            if enum:
                out[enum] = item["label"]
    return out


def controls_legacy(namespace: str, codes: list[str]) -> dict[str, str]:
    """ISO 27001 / NIST 800-53 control families for the code-scan dashboard's compliance card."""
    table = load().get("legacy_controls") or {}
    out: dict[str, str] = {}
    for code in codes:
        for tag in (entry(namespace, code) or {}).get("owasp") or []:
            out.update(table.get(tag) or {})
    return out


# -------------------------------------------------------------------------------------------------------- rendering
def _safe_value(kind: str, value: Any) -> str | None:
    """A context value made safe to paste into a shell command. Commands are copied and run by people, so nothing
    from a scanned system may add a shell construct or an extra option: host, port, line, name and resource appear
    unquoted in the templates and get no spaces; path and location appear inside single quotes. A value that cannot be
    made safe leaves the placeholder visible for the user to fill in."""
    text = str(value).strip()
    if kind in ("port", "line"):
        return text if text.isdigit() and len(text) <= 6 else None
    if kind == "host":
        if not text.isascii():
            try:
                text = ".".join(p.encode("idna").decode("ascii") if p else p for p in text.split("."))
            except UnicodeError:
                return None
        allowed = r"[A-Za-z0-9.\-:\[\]]+"
    elif kind in ("name", "resource"):
        allowed = r"[A-Za-z0-9._:/@=,+\-]+"
    else:  # path, location: inside single quotes; letters of any script are fine, a quote never is
        allowed = r"[\w./@=,+\- \[\]:~]+"
    # a value with anything else is not altered into a different name; the placeholder stays for the user to fill
    if len(text) > 300 or not re.fullmatch(allowed, text):
        return None
    if text.startswith("-"):
        return "./" + text if kind in ("path", "location") else None
    return text


def _fill(command: str, context: dict[str, Any]) -> str:
    def sub(m: re.Match[str]) -> str:
        value = context.get(m.group(1))
        safe = None if value in (None, "") else _safe_value(m.group(1), value)
        return safe if safe is not None else f"<{m.group(1)}>"
    return _PLACEHOLDER.sub(sub, command)


def _remediation_for(e: dict[str, Any], title: str) -> dict[str, Any]:
    """The entry's remediation, or the more specific one of the first summary rule whose pattern matches the finding's
    title (for example RSA-1024 under WEAK_ALGORITHM gets key-size advice, not hashing advice)."""
    if title:
        for rule in e.get("summary_rules") or []:
            if re.search(rule["match"], title, re.I):
                return {"summary": rule["summary"], "steps": rule.get("steps") or e["remediation"].get("steps") or []}
    return e["remediation"]


def render(namespace: str, codes: list[str], *, context: dict[str, Any] | None = None, evidence: str = "",
           texts: dict[str, str] | None = None, title: str = "") -> list[dict[str, Any]]:
    """Full explanation for each finding code on one asset, with commands filled in from the asset's context.

    context: host / port / path / name / location / resource / line of the asset. texts: the asset-specific sentence
    the classifier wrote for each code. title: the finding's title (algorithm name), which picks the specific fix.
    Unknown codes are skipped (coverage notes are not findings).
    """
    context = context or {}
    kb = load()
    compliance = kb.get("compliance") or {}
    cwe_names = kb.get("cwe") or {}
    out = []
    for code in codes:
        e = entry(namespace, code)
        if not e:
            continue
        out.append({
            "code": code,
            "title": e["title"],
            "observed": (texts or {}).get(code),
            "description": e["description"],
            "attack": e["attack"],
            "impact": e["default_impact"],
            "category": e["category"],
            "pqc": e.get("pqc"),
            "cwe": [{"id": c, "name": cwe_names.get(c), "url": f"https://cwe.mitre.org/data/definitions/{c[4:]}.html"}
                    for c in e["cwe"]],
            "owasp_2021": e.get("owasp_2021") or [],
            "owasp_2025": e.get("owasp_2025") or [],
            "cves": cves_for(namespace, code, evidence),
            "standards": e.get("standards") or [],
            "compliance": [ref for key in e.get("compliance") or [] for ref in compliance.get(key) or []],
            "remediation": _remediation_for(e, title),
            "verify": [{"label": v["label"], "command": _fill(v["command"], context)} for v in e.get("verify") or []],
            "references": e.get("references") or [],
        })
    return out


def summary_fix(namespace: str, codes: list[str], evidence: str = "") -> str | None:
    """One-line fix for the most important code (codes are expected worst-first); a rule whose pattern matches the
    evidence (for example the algorithm name) gives a more specific fix than the entry's general one."""
    for code in codes:
        e = entry(namespace, code)
        if e:
            return _remediation_for(e, evidence or "")["summary"]
    return None


# ------------------------------------------------------------------------------------------- library versions
_EPOCH = re.compile(r"^\d+:")


def upstream_version(package_version: str) -> str:
    """Upstream part of a distro package version: '1:3.0.7-27.el9' -> '3.0.7', '1:8.9p1-3ubuntu0.10' -> '8.9p1'."""
    v = _EPOCH.sub("", str(package_version or "").strip())
    v = re.split(r"[-~+]", v, maxsplit=1)[0]
    return v


def _key(version: str) -> tuple:
    """Comparable key: numbers, then an OpenSSL letter suffix ('1.1.1w'), then an OpenSSH portable patch level
    ('9.3p2' > '9.3p1' > '9.3'; the patch release is often the fix, e.g. 9.3p2 for CVE-2023-38408)."""
    v = version.strip().lower()
    m = re.match(r"^(\d+(?:\.\d+)*)(?:p(\d+))?([a-z]*)", v)
    if not m:
        return ((), "", 0)
    nums = tuple(int(x) for x in m.group(1).split("."))
    nums = nums + (0,) * (4 - len(nums)) if len(nums) < 4 else nums
    return (nums, m.group(3), int(m.group(2) or 0))


def compare_versions(a: str, b: str) -> int:
    ka, kb_ = _key(a), _key(b)
    return (ka > kb_) - (ka < kb_)


def _in_range(version: str, rng: dict[str, str]) -> bool:
    if "exact" in rng:
        return compare_versions(version, rng["exact"]) == 0
    if rng.get("versionStartIncluding") and compare_versions(version, rng["versionStartIncluding"]) < 0:
        return False
    if rng.get("versionStartExcluding") and compare_versions(version, rng["versionStartExcluding"]) <= 0:
        return False
    if rng.get("versionEndIncluding") and compare_versions(version, rng["versionEndIncluding"]) > 0:
        return False
    if rng.get("versionEndExcluding") and compare_versions(version, rng["versionEndExcluding"]) >= 0:
        return False
    return True


def library_for(package: str) -> str | None:
    name = str(package or "").lower()
    for lib, rules in (load().get("libraries") or {}).items():
        if name in rules.get("packages") or []:
            return lib
    return None


def library_status(package: str, package_version: str, *, today: _dt.date | None = None) -> dict[str, Any] | None:
    """CVE ranges and upstream end-of-life for a crypto library package; None when the package is not tracked."""
    lib = library_for(package)
    if not lib or not package_version:
        return None
    rules = load()["libraries"][lib]
    version = upstream_version(package_version)
    if not _key(version)[0]:
        return None
    hits = sorted({r["cve"] for r in rules.get("ranges") or [] if _in_range(version, r)})
    eol = None
    table = rules.get("eol") or {}
    if table:
        nums = _key(version)[0]
        branch = f"{nums[0]}.{nums[1]}" if nums[0] >= 3 else f"{nums[0]}.{nums[1]}.{nums[2]}"
        date = table.get(branch)
        if date:
            today = today or _dt.date.today()
            eol = {"branch": branch, "date": date, "passed": _dt.date.fromisoformat(date) < today,
                   "sources": rules.get("eol_sources") or []}
    return {"library": lib, "package": package, "package_version": package_version, "upstream_version": version,
            "cves": hits, "eol": eol}


def pqc_context() -> dict[str, Any]:
    return load().get("pqc_context") or {}
