"""Remediation, code fix and exploit demonstration for CBOM findings, built in-house (no model, no network).

Returns the shape the AI remediation endpoint stores (fix / exploit_payload / diff) so every consumer keeps
working, plus ``details`` (CWE, OWASP, CVEs, compliance, verify commands from the offline crypto knowledge base),
``code_fix`` (deterministic rewrite of the stored, redacted code window with a real diff - see fixgen.py) and
``exploit_demo`` (how the weakness is abused, with a self-contained proof that runs only against keys, messages
and servers it creates on the analyst's machine, plus the read-only commands that confirm the exposure on the
real asset - see exploit_demo.py). ``engine`` versions the result so stale stored copies are rebuilt.
"""
from __future__ import annotations

import datetime as _dt
import re
from typing import Any

import logging

from backend.utilities.cbom_sources import crypto_kb, exploit_demo, fixgen

log = logging.getLogger(__name__)
ENGINE = f"kb+fixgen{fixgen.FIXGEN_VERSION}+demo{exploit_demo.DEMO_VERSION}"

_NETWORK = {"protocol", "cipher", "ssh", "database", "windows", "pqc", "identity", "kubernetes"}
_LOCAL = {"key", "disk", "host", "library"}
_DIFFICULTY = {"Critical": "easy", "High": "moderate", "Medium": "moderate", "Low": "hard"}


_SOURCE_FILE = re.compile(r"\.(py|pyi|js|jsx|mjs|cjs|ts|tsx|java|kt|kts|scala|go|rb|php|cs|c|h|cc|cpp|cxx|hpp|rs|swift|m|"
                          r"tf|hcl|yaml|yml|json|xml|toml|txt|conf|cfg|ini|properties|pem|crt|cer|key|lock|mod|sum|"
                          r"gradle|sh|env|config)(:\d+)?$", re.I)


def _location_context(finding: dict[str, Any]) -> dict[str, Any]:
    """host / port / path / line / name for the verify commands, from what the finding records."""
    loc = str(finding.get("location") or "")
    ctx: dict[str, Any] = {"name": finding.get("algorithm_name") or finding.get("title"), "location": loc}
    m = re.match(r"^(?P<path>[^:]+?)(?::(?P<line>\d+))?(?::\d+)?$", loc)
    looks_like_file = finding.get("line") is not None or "/" in loc.split(":", 1)[0] or bool(_SOURCE_FILE.search(loc))
    if m and ("/" in loc or "." in loc) and not re.match(r"^\d+\.\d+\.\d+\.\d+", loc):
        ctx["path"], ctx["line"] = m.group("path"), m.group("line")
    hp = re.match(r"^(?P<host>[A-Za-z0-9.\-]+|\[[0-9a-fA-F:]+\]):(?P<port>\d{1,5})$", loc)
    if hp and not looks_like_file:  # "app.py:5" is a file and line, not a host and port
        ctx["host"], ctx["port"] = hp.group("host"), hp.group("port")
        ctx.pop("path", None)
        ctx.pop("line", None)
    for key in ("host", "port", "path", "resource", "line"):
        if finding.get(key) not in (None, ""):
            ctx[key] = finding[key]
    return ctx


def _legacy_codes(finding: dict[str, Any]) -> list[str]:
    """Code-scan rows stored before finding codes existed carry only flags; derive the codes those flags mean, so an
    old weak row is never told 'no weakness was flagged'."""
    codes: list[str] = []
    kind = str(finding.get("asset_type") or finding.get("algorithm_type") or "").lower()
    if finding.get("expired"):
        codes.append("EXPIRED_CERTIFICATE")
    if finding.get("weak") or str(finding.get("crypto_strength") or "").lower() == "weak":
        codes.append("WEAK_PROTOCOL" if kind == "protocol" else "WEAK_CERTIFICATE_KEY" if kind == "certificate"
                     else "WEAK_ALGORITHM")
    if finding.get("quantum_vulnerable") is True:
        codes.append("QUANTUM_VULNERABLE")
    return codes


def explain(finding: dict[str, Any], namespace: str = "code") -> list[dict[str, Any]]:
    """Rendered knowledge entries for every finding code on the row (worst first, quantum note last)."""
    raw = finding.get("finding_codes")
    if raw is None and namespace == "code":
        raw = _legacy_codes(finding)
    codes = [c for c in raw or [] if isinstance(c, str)]
    codes = [c for c in codes if c != "QUANTUM_VULNERABLE"] + [c for c in codes if c == "QUANTUM_VULNERABLE"]
    evidence = " ".join(str(finding.get(k) or "") for k in ("title", "description", "finding", "algorithm_name"))
    title = str(finding.get("title") or finding.get("algorithm_name") or "")
    return crypto_kb.render(namespace, codes, context=_location_context(finding), evidence=evidence, title=title)


def remediation(finding: dict[str, Any], namespace: str = "code") -> dict[str, Any]:
    out = _remediation(finding, namespace)
    try:
        fix = out.get("code_fix") or {}
        demo = out.get("exploit_demo") or {}
        log.info("cbom remediation: codes=%s language=%s fix=%s rules=%s confidence=%s kb=%s demo=%s",
                 finding.get("finding_codes"), fix.get("language"), fix.get("kind"), fix.get("rules"),
                 fix.get("confidence"), out.get("kb_version"), demo.get("family"))
    except Exception:  # logging never breaks remediation
        pass
    return out


def _remediation(finding: dict[str, Any], namespace: str = "code") -> dict[str, Any]:
    entries = explain(finding, namespace)
    now = _dt.datetime.now(_dt.timezone.utc).isoformat()
    base = {"generated_at": now, "source": "knowledge_base", "kb_version": crypto_kb.version(), "engine": ENGINE}
    if not entries:
        return {**base, "status": "completed", "fix": {
            "description": finding.get("suggested_fix") or "No weakness was flagged on this asset; keep it in the "
                                                            "crypto inventory and the post-quantum migration plan.",
            "original_code": "", "fixed_code": "", "language": "text", "confidence": 100,
            "validation_notes": "Inventory item without a finding.", "references": []},
            "exploit_payload": None, "diff": "", "details": [], "code_fix": None, "exploit_demo": None}
    main = entries[0]
    steps = [f"{s['platform']}: {s['how']}" for e in entries for s in e["remediation"]["steps"]]
    summary = " ".join(dict.fromkeys(e["remediation"]["summary"] for e in entries))
    references = list(dict.fromkeys(
        [c["url"] for e in entries for c in e["cwe"]]
        + [c["url"] for e in entries for c in e["cves"]]
        + [r for e in entries for r in e["references"]]
        + [r["source"] for e in entries for r in e["compliance"]]
    ))[:30]
    verify = [v for e in entries for v in e["verify"]]
    observed = finding.get("description") or main.get("observed") or ""
    category = main.get("category")
    attack_vector = "network" if category in _NETWORK else "local" if category in _LOCAL else (
        "source code or configuration in the repository" if category in ("code", "config", "certificate") else "network")
    code_fix = fixgen.generate(finding) if namespace == "code" else None
    kb_note = (f"Built in-house from the offline crypto knowledge base {crypto_kb.version()} and rewrite rules "
               f"fixgen/{fixgen.FIXGEN_VERSION} (no AI). Re-run the scan after the change to confirm the finding "
               "is gone.")
    if code_fix and code_fix["available"]:
        notes = code_fix["warnings"] + code_fix["notes"] + ([f"Run: {c}" for c in code_fix["commands"]])
        fix = {
            "description": code_fix["summary"] + (" " + summary if summary not in code_fix["summary"] else ""),
            "original_code": code_fix["original_code"][:4000],
            "fixed_code": code_fix["fixed_code"][:4000] or "\n".join(code_fix["commands"]),
            "language": code_fix["language"],
            "confidence": code_fix["confidence"],
            "validation_notes": " ".join(notes + [kb_note]),
            "references": references,
        }
    else:
        fix = {
            "description": summary + (f" {code_fix['summary']}" if code_fix and code_fix.get("summary") else ""),
            "original_code": str(finding.get("snippet") or observed or "")[:4000],
            # no rewrite applies (a host, a config the rules do not cover): the per-platform steps are the fix
            "fixed_code": "\n".join(steps) or summary,
            "language": "text",
            "confidence": 90,
            "validation_notes": " ".join(["No automatic code change; the steps are listed per platform, apply the "
                                          "ones that match this asset."] + [kb_note]),
            "references": references,
        }
    demo = exploit_demo.build(finding, entries)
    verify_text = "\n".join(f"# {v['label']}\n{v['command']}" for v in verify)
    # exploit_payload keeps its contract (read-only commands aimed at THIS asset, difficulty from its impact) for
    # every existing consumer; the self-contained demonstration lives in exploit_demo.
    proof = {
        "description": " ".join(dict.fromkeys(e["attack"] for e in entries)),
        "payload": verify_text or "No read-only check applies.",
        "impact_demonstration": (
            "The commands are read-only. If their output shows the weak setting described in this finding, the "
            "exposure is confirmed on the live system. " + (f"Observed by the scan: {observed}" if observed else "")),
        "prerequisites": "Read access to the repository or file." if attack_vector.startswith("source") else
                         "Network reach to the endpoint, or a shell on the host, as the scanner had.",
        "difficulty": _DIFFICULTY.get(str(finding.get("impact") or main["impact"]).capitalize(), "moderate"),
        "attack_vector": attack_vector,
    }
    return {**base, "status": "completed", "fix": fix, "exploit_payload": proof,
            "diff": (code_fix or {}).get("diff") or "", "details": entries, "code_fix": code_fix,
            "exploit_demo": demo or None}
