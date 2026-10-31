"""Remediation and proof of exposure for CBOM findings, built from the offline crypto knowledge base.

Returns the same shape the AI remediation endpoint stores (fix / exploit_payload / diff) so the existing panel can
show it, plus ``details`` (CWE, OWASP, CVEs, compliance, verify commands). Nothing here calls a model or the network.
The "exploit" part is a safe, read-only proof: commands that show the weak setting is in use, never attack code.
"""
from __future__ import annotations

import datetime as _dt
import re
from typing import Any

from backend.utilities.cbom_sources import crypto_kb

_NETWORK = {"protocol", "cipher", "ssh", "database", "windows", "pqc", "identity", "kubernetes"}
_LOCAL = {"key", "disk", "host", "library"}
_DIFFICULTY = {"Critical": "easy", "High": "moderate", "Medium": "moderate", "Low": "hard"}


def _location_context(finding: dict[str, Any]) -> dict[str, Any]:
    """host / port / path / line / name for the verify commands, from what the finding records."""
    loc = str(finding.get("location") or "")
    ctx: dict[str, Any] = {"name": finding.get("algorithm_name") or finding.get("title"), "location": loc}
    m = re.match(r"^(?P<path>[^:]+?)(?::(?P<line>\d+))?(?::\d+)?$", loc)
    if m and ("/" in loc or "." in loc) and not re.match(r"^\d+\.\d+\.\d+\.\d+", loc):
        ctx["path"], ctx["line"] = m.group("path"), m.group("line")
    hp = re.match(r"^(?P<host>[A-Za-z0-9.\-]+|\[[0-9a-fA-F:]+\]):(?P<port>\d{1,5})$", loc)
    if hp:
        ctx["host"], ctx["port"] = hp.group("host"), hp.group("port")
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
    entries = explain(finding, namespace)
    now = _dt.datetime.now(_dt.timezone.utc).isoformat()
    base = {"generated_at": now, "source": "knowledge_base", "kb_version": crypto_kb.version()}
    if not entries:
        return {**base, "status": "completed", "fix": {
            "description": finding.get("suggested_fix") or "No weakness was flagged on this asset; keep it in the "
                                                            "crypto inventory and the post-quantum migration plan.",
            "original_code": "", "fixed_code": "", "language": "text", "confidence": 100,
            "validation_notes": "Inventory item without a finding.", "references": []},
            "exploit_payload": None, "diff": "", "details": []}
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
    fix = {
        "description": summary,
        "original_code": str(finding.get("snippet") or observed or "")[:4000],
        "fixed_code": "\n".join(steps) or summary,
        "language": "text",
        "confidence": 90,
        "validation_notes": (
            f"From the offline crypto knowledge base {crypto_kb.version()} (no AI). Steps are listed per platform; "
            "apply the ones that match this asset, then re-run the scan to confirm the finding is gone."),
        "references": references,
    }
    proof = {
        "description": " ".join(dict.fromkeys(e["attack"] for e in entries)),
        "payload": "\n".join(f"# {v['label']}\n{v['command']}" for v in verify) or "No read-only check applies.",
        "impact_demonstration": (
            "The commands are read-only. If their output shows the weak setting described in this finding, the "
            "exposure is confirmed on the live system. " + (f"Observed by the scan: {observed}" if observed else "")),
        "prerequisites": "Read access to the repository or file." if attack_vector.startswith("source") else
                         "Network reach to the endpoint, or a shell on the host, as the scanner had.",
        "difficulty": _DIFFICULTY.get(str(finding.get("impact") or main["impact"]).capitalize(), "moderate"),
        "attack_vector": attack_vector,
    }
    return {**base, "status": "completed", "fix": fix, "exploit_payload": proof, "diff": "", "details": entries}
