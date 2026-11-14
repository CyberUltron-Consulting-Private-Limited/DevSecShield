"""Grounding for one subject: knowledge-base items (K*) and allow-listed asset facts (F*).

Built server-side from what the team-scoped loaders return for ONE asset or ONE code-scan finding; nothing of any
other asset is read. K items come from ``crypto_kb.render`` (the same entries the KB remediation panel shows), F items
from an explicit allow-list of fact keys, each value length-capped. Secrets never reach here (collectors do not return
key material and the code-scan snippet is not an allowed fact).
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any

CVE_RE = re.compile(r"\bCVE[-_ ]?(\d{4})[-_ ]?(\d{4,7})\b", re.I)
CWE_RE = re.compile(r"\bCWE[-_ ]?(\d{1,5})\b", re.I)
URL_RE = re.compile(r"(?:https?|ftp)://[^\s<>\"'`)\]]+|\bwww\.[^\s<>\"'`)\]]+", re.I)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

MAX_ITEM = 900       # characters per K/F item text
MAX_VALUE = 200      # characters per fact value
MAX_LIST = 20        # entries per list-valued fact

# Run-asset fields and facts the model may see (everything else is dropped). Q-grade / fix class pass through when
# CB-19 / CB-24 add them.
RUN_ASSET_FIELDS = ("type", "name", "location", "target", "algorithm", "key_size", "protocol", "quantum_vulnerable",
                    "pqc_class", "hndl", "criticality", "exposure", "exposure_basis", "impact", "finding",
                    "source_name", "q_grade", "q_label", "fix_class")
RUN_FACT_KEYS = ("protocols", "tls_versions", "group", "groups", "pq_hybrid", "cipher_suites", "weak_ciphers",
                 "ciphers", "kex", "kex_algorithms", "macs", "host_key_algorithms", "not_before", "not_after",
                 "issuer", "subject", "sig_alg", "key_alg", "key_size", "self_signed", "package", "version",
                 "key_spec", "key_state", "key_manager", "rotation_enabled", "method", "status", "protection", "os",
                 "os_family", "engine", "tls_mode", "q_grade", "fix_class")
# Code-scan finding fields the model may see (no snippet, no description: those are copied from source code).
CODE_FINDING_FIELDS = ("title", "algorithm_name", "algorithm_type", "crypto_strength", "key_size", "quantum_safe",
                       "quantum_vulnerable", "impact", "location", "line", "language", "q_grade", "fix_class")
ALLOWED_FACT_KEYS = frozenset(RUN_ASSET_FIELDS) | frozenset(RUN_FACT_KEYS) | frozenset(CODE_FINDING_FIELDS) | {
    "library", "library_version", "library_end_of_life"}
_HOST_KEYS = ("target", "location", "host", "subject", "issuer", "exposure_basis", "source_name")


@dataclass
class Item:
    id: str
    label: str
    text: str
    command: str | None = None


@dataclass
class Grounding:
    subject_key: str
    items: list[Item]
    baseline: dict[str, Any]
    commands: set[str] = field(default_factory=set)      # normalised KB step / verify commands
    urls: set[str] = field(default_factory=set)          # KB reference URLs
    hosts: list[str] = field(default_factory=list)       # host names / addresses (for CBOM_AI_REDACT_HOSTS)

    @property
    def ids(self) -> set[str]:
        return {i.id for i in self.items}

    def identifiers(self) -> set[str]:
        """Every CVE / CWE id present in the items (the only ones an answer may name)."""
        out: set[str] = set()
        for item in self.items:
            out |= {f"CVE-{a}-{b}" for a, b in CVE_RE.findall(item.text)}
            out |= {f"CWE-{int(a)}" for a in CWE_RE.findall(item.text)}
        return out

    def digest(self) -> str:
        blob = json.dumps([[i.id, i.text, i.command] for i in self.items], sort_keys=True)
        return hashlib.sha256(blob.encode()).hexdigest()


def norm_command(text: str) -> str:
    return " ".join(str(text or "").split())


def _cap(text: Any, n: int = MAX_VALUE) -> str:
    s = " ".join(str(text).split())
    return s if len(s) <= n else s[: n - 1] + "…"


def _cvss(value: Any) -> str | None:
    if isinstance(value, dict):
        return str(value.get("score")) if value.get("score") is not None else None
    return str(value) if value not in (None, "") else None


def _fact_value(value: Any) -> str | None:
    if value is None or value == "" or value == [] or value == {}:
        return None
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (int, float, str)):
        return _cap(value)
    if isinstance(value, (list, tuple)):
        scalars = [_cap(v, 80) for v in value if isinstance(v, (str, int, float)) and not isinstance(v, bool)]
        if not scalars:
            return None
        more = f" (+{len(scalars) - MAX_LIST} more)" if len(scalars) > MAX_LIST else ""
        return ", ".join(scalars[:MAX_LIST]) + more
    if isinstance(value, dict):
        # an OS block {"Caption": "Windows Server 2022"} or {"name": ..., "version": ...}: its name only
        for key in ("Caption", "caption", "name", "pretty_name", "family"):
            if isinstance(value.get(key), str):
                return _cap(value[key])
    return None


def _kb_items(entries: list[dict[str, Any]], start: int = 1) -> tuple[list[Item], set[str], set[str], dict]:
    """K items for each rendered KB entry, plus the command and URL allow-lists and the KB baseline."""
    items: list[Item] = []
    commands: set[str] = set()
    urls: set[str] = set()
    summaries: list[tuple[str, str]] = []
    steps: list[dict[str, Any]] = []
    verify: list[dict[str, str]] = []
    for n, e in enumerate(entries, start=start):
        k = f"K{n}"
        code = str(e.get("code") or "")
        head = [f"{code}: {e.get('title') or ''}."]
        if e.get("observed"):
            head.append(f"Observed on this asset: {e['observed']}.")
        head.append(str(e.get("description") or ""))
        if e.get("attack"):
            head.append(f"Attack: {e['attack']}")
        if e.get("impact"):
            head.append(f"Impact: {e['impact']}.")
        if e.get("pqc"):
            head.append(f"Post-quantum note: {e['pqc'] if isinstance(e['pqc'], str) else json.dumps(e['pqc'])}")
        items.append(Item(k, f"{k} {code}", _cap(" ".join(head), MAX_ITEM)))
        rem = e.get("remediation") or {}
        if rem.get("summary"):
            items.append(Item(f"{k}.fix", f"{k} {code} · fix", _cap(rem["summary"], MAX_ITEM)))
            summaries.append((rem["summary"], f"{k}.fix"))
        for j, step in enumerate(rem.get("steps") or [], start=1):
            how, platform = str(step.get("how") or ""), str(step.get("platform") or "")
            sid = f"{k}.s{j}"
            items.append(Item(sid, f"{k} {code} · step {j}" + (f" ({platform})" if platform else ""),
                              _cap(f"{platform}: {how}" if platform else how, MAX_ITEM), command=how))
            commands.add(norm_command(how))
            for part in re.split(r"\s*;\s*|\s+&&\s+", how) + re.findall(r"`([^`]+)`", how):
                if part.strip():
                    commands.add(norm_command(part))
            steps.append({"text": f"{platform}: {how}" if platform else how, "cites": [sid]})
        for j, v in enumerate(e.get("verify") or [], start=1):
            vid = f"{k}.v{j}"
            items.append(Item(vid, f"{k} {code} · check {j}", _cap(f"{v.get('label')}: {v.get('command')}", MAX_ITEM),
                              command=str(v.get("command") or "")))
            commands.add(norm_command(v.get("command")))
            verify.append({"command": str(v.get("command") or ""), "cite": vid})
        cwes = e.get("cwe") or []
        if cwes:
            items.append(Item(f"{k}.cwe", f"{k} {code} · CWE",
                              _cap("; ".join(f"{c['id']} {c.get('name') or ''}".strip() for c in cwes), MAX_ITEM)))
            urls |= {c["url"] for c in cwes if c.get("url")}
        cves = e.get("cves") or []
        if cves:
            text = "; ".join(f"{c['id']}" + (f" (CVSS {_cvss(c.get('cvss'))})" if _cvss(c.get("cvss")) else "")
                             + (f": {_cap(c['summary'], 160)}" if c.get("summary") else "") for c in cves)
            items.append(Item(f"{k}.cve", f"{k} {code} · CVEs", _cap(text, MAX_ITEM)))
            urls |= {c["url"] for c in cves if c.get("url")}
        std = [str(s) for s in e.get("standards") or []] + [
            f"{c.get('framework') or ''} {c.get('id') or c.get('clause') or ''}: {_cap(c.get('text') or '', 160)}".strip(" :")
            for c in e.get("compliance") or [] if isinstance(c, dict)]
        if std:
            items.append(Item(f"{k}.std", f"{k} {code} · standards", _cap("; ".join(std), MAX_ITEM)))
            urls |= {c["source"] for c in e.get("compliance") or [] if isinstance(c, dict) and c.get("source")}
        refs = [str(r) for r in e.get("references") or []]
        if refs:
            items.append(Item(f"{k}.ref", f"{k} {code} · references", _cap(" ".join(refs), MAX_ITEM)))
            urls |= set(refs)
    commands.discard("")
    baseline = {"summary": " ".join(dict.fromkeys(s for s, _ in summaries)),
                "summary_cites": [c for _, c in summaries], "steps": steps, "commands": verify}
    return items, commands, urls, baseline


def _host_of(location: str) -> str | None:
    m = re.match(r"^(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.\-]+):\d{1,5}$", location or "")
    return m.group(1) if m else None


def _fact_items(pairs: list[tuple[str, Any]]) -> list[Item]:
    out: list[Item] = []
    for key, value in pairs:
        if key not in ALLOWED_FACT_KEYS:
            continue
        text = _fact_value(value)
        if text is None:
            continue
        fid = f"F{len(out) + 1}"
        out.append(Item(fid, f"{fid} {key.replace('_', ' ')}", f"{key}: {text}"))
    return out


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _hosts(values: list[Any], items: list[Item]) -> list[str]:
    """Host names and addresses to hide when CBOM_AI_REDACT_HOSTS=1 (longest first, so a name is replaced before
    a shorter one it contains)."""
    found: set[str] = set()
    for v in values:
        s = str(v or "").strip()
        if not s:
            continue
        hp = _host_of(s)
        if hp:
            found.add(hp.strip("[]"))
        try:
            ipaddress.ip_address(s.strip("[]"))
            found.add(s.strip("[]"))
        except ValueError:
            if re.fullmatch(r"[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+", s) and not re.fullmatch(r"[\d.]+", s):
                found.add(s)
        for cn in re.findall(r"CN=([^,/]+)", s):
            found.add(cn.strip())
    for item in items:  # addresses inside fact values (KB text has version numbers that look like addresses)
        if item.id.startswith("F"):
            found |= {a for a in IPV4_RE.findall(item.text) if _is_ip(a)}
    return sorted((h for h in found if len(h) >= 3), key=len, reverse=True)


def for_run_asset(detail: dict[str, Any]) -> Grounding:
    """detail: ``posture.asset_detail(...)`` for one asset the caller already loaded team-scoped."""
    k_items, commands, urls, baseline = _kb_items(list(detail.get("details") or []))
    library = detail.get("library") or None
    if library:
        n = len(detail.get("details") or []) + 1
        lid = f"K{n}"
        parts = [f"Library {library.get('library')} package {library.get('package')} "
                 f"{library.get('package_version')} (upstream {library.get('upstream_version')})."]
        if library.get("cves"):
            parts.append("Knowledge-base version ranges list: " + ", ".join(library["cves"][:40]) + ".")
        eol = library.get("eol") or {}
        if eol:
            parts.append(f"Branch {eol.get('branch')} end of life {eol.get('date')}"
                         + (" (passed)." if eol.get("passed") else "."))
        k_items.append(Item(lid, f"{lid} library", _cap(" ".join(parts), MAX_ITEM)))
        urls |= {c["url"] for c in library.get("cve_details") or [] if isinstance(c, dict) and c.get("url")}
    facts = detail.get("facts") or {}
    pairs: list[tuple[str, Any]] = [(k, detail.get(k)) for k in RUN_ASSET_FIELDS]
    pairs += [(k, facts.get(k)) for k in RUN_FACT_KEYS if k not in RUN_ASSET_FIELDS or detail.get(k) is None]
    if library:
        pairs += [("library", library.get("library")), ("library_version", library.get("upstream_version")),
                  ("library_end_of_life", (library.get("eol") or {}).get("date"))]
    f_items = _fact_items(pairs)
    items = k_items + f_items
    host_values = [detail.get(k) for k in _HOST_KEYS] + [facts.get("host"), facts.get("subject"), facts.get("issuer")]
    return Grounding(subject_key=f"run_asset:{detail.get('id')}", items=items, baseline=baseline, commands=commands,
                     urls=urls, hosts=_hosts(host_values, items))


def for_code_finding(scan_id: int, finding_id: str, finding: dict[str, Any],
                     entries: list[dict[str, Any]]) -> Grounding:
    """finding: the stored ``finding_data`` of one code-scan finding; entries: ``kb_remediation.explain(finding)``."""
    k_items, commands, urls, baseline = _kb_items(entries)
    pairs = [(k, finding.get(k)) for k in CODE_FINDING_FIELDS]
    f_items = _fact_items(pairs)
    items = k_items + f_items
    return Grounding(subject_key=f"scan_finding:{scan_id}:{finding_id}", items=items, baseline=baseline,
                     commands=commands, urls=urls, hosts=_hosts([finding.get("location")], items))
