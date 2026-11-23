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


NOT_RECORDED = (
    "Cited for review: this clause applies to specific algorithms, and the algorithm "
    "behind the finding was not recorded for this asset: verify which one it uses."
)
_NAME_SPLIT = re.compile(r"[\s,;/()]+")


def evidence_names(evidence: Any) -> list[str]:
    """The algorithm names a clause rule reads: a string is one name (or, for a
    code-scan finding, the scanner's own sentence about its algorithm), a list holds
    one name each; None or nothing is "not recorded" ([])."""
    if evidence is None:
        return []
    items = [evidence] if isinstance(evidence, str) else list(evidence)
    return [str(i).strip() for i in items if i is not None and str(i).strip()]


def rule_matches(rule: dict[str, Any], names: Any) -> bool:
    """Whether a ``clause_rules`` rule matches one of the names. The pattern is
    searched in each name and in each part of it ("3DES (IKEv1)", "PFS MODP-1024",
    "one of DES/3DES" are read part by part, so a pattern anchored on one algorithm
    name, such as the classifier's own lists, matches too); a part that matches
    ``unless`` never counts."""
    pattern = re.compile(rule["match"], re.IGNORECASE)
    unless = re.compile(rule["unless"], re.IGNORECASE) if rule.get("unless") else None
    for name in evidence_names(names):
        for part in dict.fromkeys([name, *_NAME_SPLIT.split(name)]):
            if part and pattern.search(part) and not (unless and unless.search(part)):
                return True
    return False


def has_clause_rules(namespace: str, code: str) -> bool:
    return bool((entry(namespace, code) or {}).get("clause_rules"))


def applies(ref: dict[str, Any], team: dict[str, Any] | None) -> bool:
    """Whether a clause (or a framework's applicability entry) binds a team (A-11).

    ``team``: the team's profile, {"jurisdiction": "IN", "entity": "nbfc", "flags":
    [...]} (the backend's ``regulated_entity.profile_of``). The clause's
    ``applies_to`` must name the entity type, its ``applicability.jurisdiction``
    must be the team's (or "*", a technical standard cited everywhere) and its
    ``applicability.requires`` must be one of the team's flags. A superseded
    clause binds nobody. None (the code-scan engine, which grades a repository
    with no team) keeps every clause."""
    if team is None:
        return True
    if ref.get("superseded"):
        return False
    scope = ref.get("applies_to") or ref.get("entities")
    if scope and team.get("entity") not in scope:
        return False
    rule = ref.get("applicability")
    rule = rule if isinstance(rule, dict) else ref
    place = rule.get("jurisdiction")
    if place and place != "*" and place != team.get("jurisdiction"):
        return False
    need = rule.get("requires")
    return not need or need in (team.get("flags") or ())


def framework_applicability(key: str) -> dict[str, Any] | None:
    """Who a pooled framework (``aibom.cbom.compliance`` key) or a clause
    framework ("RBI") binds; None if unknown."""
    section = load().get("applicability") or {}
    found = (section.get("frameworks") or {}).get(key)
    found = found or (section.get("clause_frameworks") or {}).get(key)
    return dict(found) if isinstance(found, dict) else None


def clauses_for(
    namespace: str, code: str, evidence: Any = None, *,
    team: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """The regulatory clauses one finding breaks (or whose obligation it triggers),
    as {key, framework, id, text, source, note?, evidence?}: the entry's own
    ``clauses``, plus those of every ``clause_rules`` rule the evidence matches,
    e.g. NIST TDEA only when the evidence names Triple DES.

    ``evidence`` is algorithm names only (#289): for a collected asset, the
    algorithms the classifier flagged for the code; never the asset's name,
    location or finding sentence (a host called "des3-gw" is no Triple DES). When
    no algorithm was recorded (None, "" or []) the rules cannot decide: their
    clauses are cited with ``evidence: "not_recorded"`` and a note, never dropped.

    Never a whole compliance area: an area groups clauses for the NIST SP 800-53
    control families, and a finding does not inherit the other clauses of its area
    (#269: an SSH CBC cipher is not "PKCS#1 v1.5 padding disallowed").

    ``team``: only the clauses that bind the team (``applies``); every surface of a
    team (run page, asset detail, OSCAL, the PDFs) passes it, so they cite the same
    clauses. None keeps every clause (the code-scan engine has no team)."""
    e = entry(namespace, code)
    if not e:
        return []
    catalog = load().get("clauses") or {}
    names = evidence_names(evidence)
    keys = list(e.get("clauses") or [])
    unrecorded: list[str] = []
    for rule in e.get("clause_rules") or []:
        if not names:
            unrecorded += [k for k in rule["clauses"] if k not in keys]
        elif rule_matches(rule, names):
            keys += rule["clauses"]
    notes = e.get("clause_notes") or {}
    out = []
    for key in dict.fromkeys(keys + unrecorded):
        if key not in catalog:
            continue
        if not applies(catalog[key], team):
            continue
        ref = {**catalog[key], "key": key}
        if notes.get(key):
            ref["note"] = notes[key]
        if key in unrecorded and key not in keys:
            ref["evidence"] = "not_recorded"
            ref["note"] = NOT_RECORDED + (" " + ref["note"] if ref.get("note") else "")
        out.append(ref)
    return out


# ------------------------------------------------------------------------------------------------ CVEs and mapping
def cve(cve_id: str) -> dict[str, Any] | None:
    return (load().get("cves") or {}).get(cve_id)


# Findings whose evidence IS an advisory (the code scanner copies the advisory's CVE IDs into it). Only for these are
# CVE IDs taken from the evidence text; elsewhere a CVE ID in stored text may belong to another finding on the same
# asset or to an older knowledge base, and must not be attached.
_ADVISORY_CODES = {("code", "VULNERABLE_CRYPTO_LIBRARY"), ("code", "KNOWN_TLS_VULNERABILITY"), ("code", "LIBRARY_CVE_RANGE")}


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
            # IDNA 2008 (UTS #46, non-transitional), the same rule as stored host names. Python's codec
            # is IDNA 2003 and would turn faß.lab into fass.lab in a command the customer pastes.
            import unicodedata

            import idna
            folded = unicodedata.normalize("NFC", text.strip().rstrip("."))
            if "\u200c" in folded or "\u200d" in folded:
                return None
            try:
                text = idna.encode(folded, uts46=True, transitional=False).decode("ascii")
            except (idna.IDNAError, UnicodeError):
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


def _clause_names(code: str, given: dict[str, Any] | None, fields: tuple) -> Any:
    if given is not None:
        return given.get(code)
    return [p for p in fields if p]


def render(namespace: str, codes: list[str], *, context: dict[str, Any] | None = None, evidence: str = "",
           texts: dict[str, str] | None = None, title: str = "",
           clause_evidence: dict[str, Any] | None = None,
           team: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Full explanation for each finding code on one asset, with commands filled in from the asset's context.

    context: host / port / path / name / location / resource / line of the asset. texts: the asset-specific sentence
    the classifier wrote for each code. title: the finding's title (algorithm name), which picks the specific fix.
    clause_evidence: code -> the algorithm names its compliance clauses are decided
    on (``clauses_for``). A collected asset passes it: its name and sentences never
    decide a clause (#289). Without it, the code-scan finding's title, evidence and
    texts are used.
    team: only the clauses that bind the team (``clauses_for``).
    Unknown codes are skipped (coverage notes are not findings).
    """
    context = context or {}
    kb = load()
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
            "compliance": clauses_for(namespace, code, _clause_names(
                code, clause_evidence, (title, evidence, (texts or {}).get(code))),
                team=team),
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


# Cached: a pure function returning an immutable tuple. Every library row compares its
# version with every CVE range bound of its library, so one 50k-asset export parsed the
# same few hundred strings millions of times (CB-06 bench: most of its CPU before this).
@lru_cache(maxsize=8192)
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


def _library_in(kb: dict[str, Any], package: str) -> str | None:
    name = str(package or "").lower()
    for lib, rules in (kb.get("libraries") or {}).items():
        if name in rules.get("packages") or []:
            return lib
    return None


def library_for(package: str) -> str | None:
    return _library_in(load(), package)


# (library, upstream version, CVE ids, end-of-life branch, its date, its sources)
LibraryFacts = tuple[str, str, tuple[str, ...], str | None, str | None, tuple[Any, ...]]


def _library_facts(kb: dict[str, Any], package: str,
                   package_version: str) -> LibraryFacts | None:
    """The date-free part of ``library_status`` for one knowledge base; None when
    the package is not tracked."""
    lib = _library_in(kb, package)
    if not lib or not package_version:
        return None
    rules = kb["libraries"][lib]
    version = upstream_version(package_version)
    if not _key(version)[0]:
        return None
    ranges = rules.get("ranges") or []
    hits = tuple(sorted({r["cve"] for r in ranges if _in_range(version, r)}))
    branch: str | None = None
    date: str | None = None
    table = rules.get("eol") or {}
    if table:
        nums = _key(version)[0]
        branch = f"{nums[0]}.{nums[1]}" if nums[0] >= 3 else f"{nums[0]}.{nums[1]}.{nums[2]}"
        date = table.get(branch)
    return lib, version, hits, branch, date, tuple(rules.get("eol_sources") or [])


# F-1: every view judges a library row's end of life on two dates (classify.shown ->
# _date_may_matter), so a 50k-asset run compared the same few package versions with
# every CVE range of their library on every row, twice. The date-free part is
# memoised per (package, version) for ONE knowledge-base object: the memo is a
# (knowledge base, entries) pair, replaced as a whole when load() returns another
# object (a signed bundle, load.cache_clear(), a test's patched KB). An entry never
# outlives the KB it came from, even when two KBs carry the same kb_version; holding
# the KB keeps its id from being reused, and a thread still on the old KB writes
# into the old pair only. The memo is process-wide, shared by every team's runs, and
# also holds untracked packages (as None). Bounded at 4,096 entries: a full memo is
# cleared and refilled, which costs what an unmemoised lookup costs, never a wrong
# answer.
_LIBRARY_MEMO_MAX = 4096
_library_memo: tuple[Any, dict[tuple[str, str], LibraryFacts | None]] = (None, {})
_MISS: Any = object()


def library_status(package: str, package_version: str, *, today: _dt.date | None = None) -> dict[str, Any] | None:
    """CVE ranges and upstream end-of-life for a crypto library package; None when the package is not tracked."""
    global _library_memo
    kb = load()
    memo = _library_memo
    if memo[0] is not kb:
        memo = _library_memo = (kb, {})
    entries = memo[1]
    key = (package, package_version)
    facts = entries.get(key, _MISS)  # one lookup: another thread may clear the dict
    if facts is _MISS:
        facts = _library_facts(kb, package, package_version)
        if len(entries) >= _LIBRARY_MEMO_MAX:
            entries.clear()
        entries[key] = facts
    if facts is None:
        return None
    lib, version, hits, branch, date, sources = facts
    eol = None
    if date:
        today = today or _dt.date.today()
        eol = {"branch": branch, "date": date, "passed": _dt.date.fromisoformat(date) < today,
               "sources": list(sources)}
    return {"library": lib, "package": package, "package_version": package_version, "upstream_version": version,
            "cves": list(hits), "eol": eol}


def pqc_context() -> dict[str, Any]:
    return load().get("pqc_context") or {}
