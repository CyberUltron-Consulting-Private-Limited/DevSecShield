"""
HIPAA Security Rule mapping for AI systems that touch ePHI (e.g. GenAI clinical
scribes). The AI-BOM supports the §164.308 risk-analysis / §164.314 business-
associate / §164.312 technical-safeguard requirements by inventorying which
LLM/scribe is used, its provider (→ BAA question), data flows, secrets exposure,
and de-identification of training data. ADVISORY ONLY — a HIPAA risk analysis and
signed BAA remain the provider's legal obligation.
"""
from __future__ import annotations

from helpers.tools.ai_bom_agent.compliance import base as B
from helpers.tools.ai_bom_agent.compliance.base import (
    FrameworkReport,
    RequirementResult,
    register,
)

KEY = "hipaa"
NAME = "HIPAA Security Rule (ePHI / GenAI scribe governance)"
VERSION = "45 CFR §164.308/.312/.314"

# External LLM/SaaS providers whose use implies a Business Associate relationship.
_EXTERNAL_PROVIDER_HINTS = (
    "openai", "anthropic", "cohere", "mistral", "google", "gemini", "azure",
    "bedrock", "aws", "huggingface", "hugging face", "replicate", "together",
    "groq", "perplexity", "vertex", "deepseek", "openrouter",
)


def _external_providers(bom: dict) -> list[str]:
    found: set[str] = set()
    for c in B.components(bom):
        props = B.component_properties(c)
        provider = (props.get("aibom:provider") or c.get("publisher") or c.get("group") or "")
        text = f"{provider} {c.get('name','')}".lower()
        for hint in _EXTERNAL_PROVIDER_HINTS:
            if hint in text:
                found.add(hint)
    return sorted(found)


@register(KEY)
def evaluate(bom: dict, findings: list[dict]) -> FrameworkReport:
    reqs: list[RequirementResult] = []
    providers = _external_providers(bom)
    ml = B.models(bom)

    # §164.308(a)(1)(ii)(A) — risk analysis: inventory of systems handling ePHI
    reqs.append(RequirementResult(
        id="HIPAA-164.308-risk-analysis",
        title="Security risk analysis input: AI/ML systems that may process ePHI are inventoried",
        status="met" if ml else "not_applicable",
        mapped_fields=["components[type=machine-learning-model]", "properties[aibom:provider]"],
        evidence=(f"{len(ml)} AI/ML system(s) inventoried as risk-analysis input" if ml else "No AI systems detected"),
        gap=None,
        recommendation=None if ml else "If AI scribes/LLMs are used, ensure provider SDK calls are detected.",
    ))

    # §164.314(a) — business associate agreement needed for external providers
    reqs.append(RequirementResult(
        id="HIPAA-164.314-BAA",
        title="Business-Associate exposure: external LLM/SaaS providers flagged for BAA review",
        status="partial" if providers else ("met" if ml else "not_applicable"),
        mapped_fields=["properties[aibom:provider]", "publisher", "group"],
        evidence=(f"External provider(s) detected: {', '.join(providers)} — each requires a signed BAA"
                  if providers else ("Only local/first-party models detected (no external BAA implied)" if ml else None)),
        gap=("External AI providers are used; a BAA is REQUIRED before any ePHI is sent. "
             "Generic consumer LLM tiers (no BAA, train on data) are a HIPAA violation."
             if providers else None),
        recommendation=("For each external provider, confirm a signed BAA and an enterprise/no-training tier "
                        "before processing ePHI." if providers else None),
    ))

    # §164.312(a)(2)(iv) — encryption / no plaintext secrets (key exposure)
    secret_findings = B.findings_with_category(findings, "secret", "key", "credential", "token")
    has_secret_prop = B.bom_has_property(bom, "aibom:secret", "aibom:api-key")
    secrets_present = bool(secret_findings) or has_secret_prop
    reqs.append(RequirementResult(
        id="HIPAA-164.312-secrets",
        title="Technical safeguards: no exposed API keys/credentials to AI services",
        status="gap" if secrets_present else "met",
        mapped_fields=["findings[risk_category~secret]", "properties[aibom:secret]"],
        evidence=(f"{len(secret_findings)} secret/credential finding(s) detected near AI calls"
                  if secret_findings else "No exposed AI-service secrets detected"),
        gap=("Exposed credentials to AI services found — rotate and move to a secrets manager."
             if secrets_present else None),
        recommendation=("Remove hard-coded keys; use a secrets manager and per-environment injection."
                        if secrets_present else "Continue to keep AI-service credentials out of source."),
    ))

    # §164.502 — de-identification of training data (Safe Harbor / Expert Determination)
    has_deid = B.bom_has_property(bom, "dataset:sensitivity", "dataset:anonymization",
                                  "clinical:deidentification")
    ds = B.datasets(bom)
    reqs.append(RequirementResult(
        id="HIPAA-164.502-deidentification",
        title="Training-data de-identification documented (Safe Harbor / Expert Determination)",
        status="met" if has_deid else ("gap" if ds else "not_applicable"),
        mapped_fields=["properties[dataset:sensitivity]", "properties[dataset:anonymization]",
                       "properties[clinical:deidentification]"],
        evidence="De-identification/sensitivity documented on dataset(s)" if has_deid else None,
        gap=(None if has_deid else
             ("Datasets present without documented de-identification method." if ds else None)),
        recommendation="Add dataset:sensitivity and dataset:anonymization (Safe Harbor vs Expert Determination).",
    ))

    # data-flow / retention disclosure for scribe audio+transcript
    has_dataflow = B.bom_has_property(bom, "clinical:data_flow", "aibom:data-retention",
                                      "clinical:retention")
    reqs.append(RequirementResult(
        id="HIPAA-data-flow-retention",
        title="Data-flow & retention disclosed for ePHI handled by AI (audio/transcript)",
        status="met" if has_dataflow else ("gap" if providers else "not_applicable"),
        mapped_fields=["metadata.properties[clinical:data_flow]", "properties[aibom:data-retention]"],
        evidence="Data-flow/retention property documented" if has_dataflow else None,
        gap=(None if has_dataflow else
             ("ePHI data-flow and retention not documented for external AI usage." if providers else None)),
        recommendation="Document clinical:data_flow and aibom:data-retention (incl. secondary/training use = none).",
    ))

    return FrameworkReport(framework=NAME, framework_key=KEY, version=VERSION, requirements=reqs)
