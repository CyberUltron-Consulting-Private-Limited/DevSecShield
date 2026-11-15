"""AI remediation assistant for CBOM findings (CB-38 PR-6, PLAN §6).

An optional addition under the knowledge-base remediation: it explains and orders the KB entry of ONE finding for ONE
asset, and every answer passes a deterministic validator before anyone sees it. Providers: AWS Bedrock (primary; the
product's only outbound call, HTTPS to ``bedrock-runtime.<region>.amazonaws.com``) or an OpenAI-compatible model the
customer runs on a private address. Off unless configured; free (no credits).

This package never imports ``backend.utilities.ai`` (the SAST Bedrock chat) or ``langchain*``; ``boto3`` / ``botocore``
are imported inside the Bedrock call only, so a backend without AWS credentials imports and runs it.
"""
from backend.utilities.cbom_ai.config import AiConfig, load as load_config  # noqa: F401
from backend.utilities.cbom_ai.prompt import PROMPT_VERSION  # noqa: F401
