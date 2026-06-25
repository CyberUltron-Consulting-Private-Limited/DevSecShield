"""Optional LLM enrichment. Always fail-open: any error or offline -> None, so a
scan never depends on an LLM. Sole provider: Amazon Bedrock (see bedrock_llm)."""
from aibom.enrich.bedrock_llm import enrich

__all__ = ["enrich"]
