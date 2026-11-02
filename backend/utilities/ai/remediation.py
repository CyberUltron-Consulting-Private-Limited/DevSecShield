import difflib
from datetime import datetime, timezone

from rich.console import Console

from backend.utilities.ai.llm import generate_structured_response
from backend.utilities.ai.remediation_models import (
    ExploitPayload,
    RemediationFixCode,
    RemediationResponse,
)

console = Console()

# ── Scan-type-aware system prompts for fix generation ──

REMEDIATION_SYSTEM_PROMPTS: dict[str, str] = {
    "sast": (
        "You are a senior application security engineer specializing in source code analysis.\n"
        "Given a SAST vulnerability finding, generate a precise code fix that eliminates the "
        "vulnerability while preserving functionality. The fix should be a direct replacement for "
        "the vulnerable code snippet.\n"
        "Focus on: input validation, output encoding, secure API usage, least privilege, defense in depth."
    ),
    "dast": (
        "You are a senior web application security engineer specializing in dynamic testing.\n"
        "Given a DAST vulnerability finding, generate server-side code or configuration changes to "
        "fix the vulnerability. The fix should address the root cause, not just the symptom.\n"
        "Focus on: HTTP headers, CSP, CORS, input validation, authentication, session management."
    ),
    "iac": (
        "You are a senior cloud security engineer specializing in Infrastructure as Code.\n"
        "Given an IaC vulnerability finding, generate the corrected IaC configuration that fixes "
        "the security misconfiguration. Follow cloud security best practices and CIS benchmarks.\n"
        "Focus on: least privilege, encryption, network segmentation, logging, compliance."
    ),
    "sbom_sca": (
        "You are a senior software supply chain security engineer.\n"
        "Given an SCA/SBOM vulnerability finding about a vulnerable dependency, generate the "
        "package manager file changes needed (requirements.txt, package.json, etc.). If no safe "
        "version exists, provide an alternative library suggestion.\n"
        "Focus on: version pinning, transitive dependency management, license compliance."
    ),
    "mcp": (
        "You are a senior AI security engineer specializing in Model Context Protocol security.\n"
        "Given an MCP tool/prompt/resource vulnerability finding, generate configuration or code "
        "changes to secure the MCP integration. Include input validation and output sanitization.\n"
        "Focus on: prompt injection, tool poisoning, data exfiltration, permission boundaries."
    ),
    "llm": (
        "You are a senior AI/ML security researcher specializing in LLM security.\n"
        "Given an LLM security benchmarking finding, generate system prompt hardening, guardrail "
        "configuration, or model serving changes to improve robustness against the identified attack.\n"
        "Focus on: prompt injection defense, jailbreak resistance, output filtering, content safety."
    ),
    "leakage": (
        "You are a senior data security engineer specializing in data leakage prevention.\n"
        "Given a code/data leakage finding, generate code changes to prevent the identified exposure.\n"
        "Focus on: secret management, data classification, access controls, encryption."
    ),
    "agent_discovery": (
        "You are a senior AI agent security engineer.\n"
        "Given an AI agent discovery finding, generate security hardening for the agent integration.\n"
        "Focus on: agent permissions, sandboxing, output validation, monitoring."
    ),
    "cbom": (
        "You are a senior cryptography engineer specializing in cryptographic bill of materials.\n"
        "Given a CBOM vulnerability finding about a weak or quantum-vulnerable cryptographic asset, "
        "generate code or configuration changes to migrate to a stronger algorithm.\n"
        "Focus on: post-quantum readiness, algorithm migration (e.g., RSA→ML-KEM, SHA-1→SHA-256), "
        "key size upgrades, certificate rotation, compliance with NIST SP 800-131A."
    ),
    "ai_bom": (
        "You are a senior AI/ML supply-chain security engineer specializing in AI Bill of Materials (AI-BOM).\n"
        "Given an AI-BOM finding about an AI/ML component (local model file, external model provider, dataset, "
        "framework, or prompt asset), generate code or configuration changes to remediate the identified risk.\n"
        "Focus on: replacing unsafe pickle-serialized models (.pkl/.pt) with safetensors, pinning model/provider "
        "versions to dated snapshots or revision SHAs, adding model cards / provenance / lineage, resolving "
        "license-compliance gaps, removing deprecated/EOL models, and protecting training-data privacy. "
        "Map fixes to the OWASP Top 10 for LLM Applications where relevant."
    ),
}

EXPLOIT_SYSTEM_PROMPT = (
    "You are a cybersecurity educator creating EDUCATIONAL security demonstrations.\n"
    "Given a vulnerability finding, generate a DEMONSTRATIVE proof-of-concept that shows:\n"
    "1. How the vulnerability could be exploited (conceptual payload)\n"
    "2. What observable impact the exploit would have\n"
    "3. Prerequisites and difficulty level\n\n"
    "IMPORTANT SAFETY RULES:\n"
    "- This is for EDUCATIONAL purposes to help developers understand the risk\n"
    "- Payloads should demonstrate the CONCEPT, not provide weaponized tools\n"
    "- Use benign placeholder values (e.g., alert('XSS') not actual malicious code)\n"
    "- For injection attacks, show the pattern with safe example data\n"
    "- Never include real credentials, real target URLs, or real exploit kits\n"
    "- Always explain what the payload does and why it works"
)


# ── Prompt builder ──

def _build_finding_prompt(finding_data: dict, scan_type: str) -> str:
    """Build a detailed prompt from finding data for LLM consumption."""
    parts = ["## Vulnerability Finding\n"]
    parts.append(f"**Title:** {finding_data.get('title', 'Unknown')}")
    parts.append(f"**Impact/Severity:** {finding_data.get('impact', 'Unknown')}")
    parts.append(f"**Description:** {finding_data.get('description', 'N/A')}")

    if finding_data.get("location"):
        parts.append(f"**Location:** {finding_data['location']}")
    if finding_data.get("snippet"):
        parts.append(f"**Vulnerable Code:**\n```\n{finding_data['snippet']}\n```")
    if finding_data.get("url"):
        parts.append(f"**Affected URL:** {finding_data['url']}")
    if finding_data.get("dependency"):
        parts.append(f"**Vulnerable Dependency:** {finding_data['dependency']}")
    if finding_data.get("category"):
        parts.append(f"**Category:** {finding_data['category']}")
    if finding_data.get("owasp_top_10"):
        parts.append(f"**OWASP Top 10:** {finding_data['owasp_top_10']}")
    if finding_data.get("owasp_top_10_llm"):
        parts.append(f"**OWASP Top 10 for LLM:** {finding_data['owasp_top_10_llm']}")
    if finding_data.get("suggested_fix"):
        parts.append(f"**Existing Fix Guidance:** {finding_data['suggested_fix']}")
    if finding_data.get("cves"):
        parts.append(f"**Related CVEs:** {finding_data['cves']}")
    if finding_data.get("compliance_controls"):
        parts.append(f"**Compliance Controls:** {finding_data['compliance_controls']}")
    if finding_data.get("resource"):
        parts.append(f"**Resource:** {finding_data['resource']}")
    if finding_data.get("reachability"):
        parts.append(f"**Reachability:** {finding_data['reachability']}")
    if finding_data.get("type"):
        parts.append(f"**MCP Component Type:** {finding_data['type']}")
    # AI-BOM fields (tolerate both stored worker names and frontend-facing names)
    if finding_data.get("component_name") or finding_data.get("asset_name"):
        parts.append(f"**AI/ML Component:** {finding_data.get('component_name') or finding_data.get('asset_name')}")
    if finding_data.get("component_type") or finding_data.get("asset_type"):
        parts.append(f"**Component Type:** {finding_data.get('component_type') or finding_data.get('asset_type')}")
    if finding_data.get("source") or finding_data.get("provider"):
        parts.append(f"**Provider/Source:** {finding_data.get('source') or finding_data.get('provider')}")
    if finding_data.get("framework"):
        parts.append(f"**Framework:** {finding_data['framework']}")
    if finding_data.get("version"):
        parts.append(f"**Version:** {finding_data['version']}")
    if finding_data.get("license") or finding_data.get("license_type"):
        parts.append(f"**License:** {finding_data.get('license') or finding_data.get('license_type')}")
    if finding_data.get("risk_category"):
        parts.append(f"**AI Risk Category:** {finding_data['risk_category']}")

    return "\n".join(parts)


def _generate_diff(original: str, fixed: str, file_path: str = "file") -> str:
    """Generate a unified diff between original and fixed code."""
    if not original or not fixed:
        return ""
    original_lines = original.splitlines(keepends=True)
    fixed_lines = fixed.splitlines(keepends=True)
    if original_lines and not original_lines[-1].endswith("\n"):
        original_lines[-1] += "\n"
    if fixed_lines and not fixed_lines[-1].endswith("\n"):
        fixed_lines[-1] += "\n"
    diff = difflib.unified_diff(
        original_lines,
        fixed_lines,
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
    )
    return "".join(diff)


# ── Main generation function ──

def generate_remediation(finding_data: dict, scan_type: str) -> dict:
    """
    Generate AI remediation (fix code + exploit payload) for a single finding.

    Returns a dict suitable for MongoDB storage with keys:
        generated_at, status, fix, exploit_payload, diff
    """
    console.print(f"[bold cyan]Generating remediation for {scan_type} finding: {finding_data.get('title', '?')}[/]")

    finding_prompt = _build_finding_prompt(finding_data, scan_type)
    system_prompt = REMEDIATION_SYSTEM_PROMPTS.get(scan_type, REMEDIATION_SYSTEM_PROMPTS["sast"])

    try:
        # ── Call 1: Generate fix code ──
        fix_prompt = (
            f"{finding_prompt}\n\n"
            "Generate a precise code fix for this vulnerability. "
            "Include the original vulnerable code and the corrected replacement code."
        )
        fix_result: RemediationFixCode = generate_structured_response(
            input_prompt=fix_prompt,
            system_prompt=system_prompt,
            output_model=RemediationFixCode,
        )

        # ── Call 2: Generate exploit payload ──
        exploit_prompt = (
            f"{finding_prompt}\n\n"
            "Generate an EDUCATIONAL proof-of-concept demonstrating how this vulnerability "
            "could be exploited. Use benign placeholder values. Explain the attack concept clearly."
        )
        exploit_result: ExploitPayload = generate_structured_response(
            input_prompt=exploit_prompt,
            system_prompt=EXPLOIT_SYSTEM_PROMPT,
            output_model=ExploitPayload,
        )

        # ── Generate diff ──
        file_path = finding_data.get("location", "file")
        diff = _generate_diff(fix_result.original_code, fix_result.fixed_code, file_path)

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "status": "completed",
            "fix": fix_result.model_dump(),
            "exploit_payload": exploit_result.model_dump(),
            "diff": diff,
        }

    except Exception as e:
        # #region agent log
        try:
            import json as _json, os as _os, time as _time
            _debug_log = _os.environ.get("DSS_AGENT_DEBUG_LOG")  # a developer's local trace file; off unless set
            if not _debug_log:
                raise OSError("agent debug log is off")
            with open(_debug_log, "a", encoding="utf-8") as _f:
                _f.write(_json.dumps({
                    "sessionId": "dd4a33",
                    "runId": "pre-fix",
                    "hypothesisId": "A",
                    "location": "remediation.py:generate_remediation",
                    "message": "Remediation generation exception",
                    "data": {"scan_type": scan_type, "error_type": type(e).__name__, "error": str(e)},
                    "timestamp": int(_time.time() * 1000),
                }) + "\n")
        except Exception:
            pass
        # #endregion
        console.print(f"[bold red]Remediation generation failed: {e}[/]")
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "status": "failed",
            "error": str(e),
        }
