"""Deployment-level configuration of the CBOM AI remediation assistant (environment only; nothing in the database).

Two providers:

* ``bedrock`` (primary; ``CBOM_AI_PROVIDER=bedrock``): AWS Bedrock Converse in ``CBOM_AI_BEDROCK_REGION``, with
  credentials from exactly one source (``CBOM_AI_AWS_CREDENTIALS``: env, profile, instance, container, web_identity). The product's only outbound call: HTTPS to ``bedrock-runtime.<region>.amazonaws.com``
  (or a Bedrock PrivateLink endpoint set in ``CBOM_AI_BEDROCK_ENDPOINT_URL``).
* ``openai_compat`` (``CBOM_AI_PROVIDER=openai_compat``, or ``CBOM_AI_BASE_URL`` set without a provider): an
  OpenAI-compatible model on a private address (Ollama, vLLM, llama.cpp server, TGI); nothing leaves the network.

Neither configured means the feature is off: the status route says unavailable, the assist route is a 404 and no
socket is ever opened.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

DEFAULT_TIMEOUT_S = 60.0
DEFAULT_MAX_TOKENS = 700
DEFAULT_CONCURRENCY = 2
# the model the SAST lane already uses on Bedrock (backend/utilities/ai/llm.py get_llm default) and its region default
DEFAULT_BEDROCK_MODEL = "openai.gpt-oss-120b-1:0"
DEFAULT_BEDROCK_REGION = "ap-south-1"
PROVIDERS = ("bedrock", "openai_compat")
CREDENTIAL_SOURCES = ("env", "profile", "instance", "container", "web_identity")
# non-secret AWS settings the credential sources need (the key values themselves are read by botocore only)
_AWS_SETTING_KEYS = ("AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                     "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE",
                     "AWS_ROLE_SESSION_NAME", "AWS_EC2_METADATA_DISABLED")
_REGION = re.compile(r"^[a-z]{2}(-gov|-iso[a-z]*)?-[a-z]+-\d$")


@dataclass(frozen=True)
class AiConfig:
    provider: str          # "bedrock" | "openai_compat"
    base_url: str          # openai_compat: OpenAI-compatible root ending in /v1; bedrock: the runtime endpoint URL
    model: str
    api_key: str | None
    ca_file: str | None
    timeout_s: float
    max_tokens: int
    concurrency: int
    redact_hosts: bool
    allow_nonprivate: bool
    honor_proxy: bool = False
    region: str | None = None          # bedrock only
    endpoint_override: bool = False    # bedrock: CBOM_AI_BEDROCK_ENDPOINT_URL was set
    aws_profile: str | None = None     # bedrock: a named profile (then AWS_* environment keys are not used)
    # bedrock: where credentials come from, explicitly (no fall-through to other sources): env | profile | instance |
    # container | web_identity
    aws_credentials: str = "env"
    # bedrock: the non-secret settings of that source, read once here (paths, URIs, role ARN; never key values)
    aws_settings: tuple[tuple[str, str], ...] = ()
    allow_loopback: bool = False       # bedrock: CBOM_AI_BEDROCK_ENDPOINT_URL may be a loopback forwarder

    def aws(self, key: str) -> str:
        return dict(self.aws_settings).get(key, "")

    @property
    def scheme(self) -> str:
        return urlsplit(self.base_url).scheme

    @property
    def host(self) -> str:
        return urlsplit(self.base_url).hostname or ""

    @property
    def port(self) -> int:
        parts = urlsplit(self.base_url)
        return parts.port or (443 if parts.scheme == "https" else 80)


def _flag(name: str, default: bool = False) -> bool:
    raw = (os.environ.get(name) or "").strip().lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


def _number(name: str, default: float, low: float, high: float) -> float:
    raw = (os.environ.get(name) or "").strip()
    try:
        value = float(raw) if raw else default
    except ValueError:
        value = default
    return min(max(value, low), high)


def _url_ok(url: str, schemes: tuple[str, ...]) -> bool:
    parts = urlsplit(url)
    if parts.scheme not in schemes or not parts.hostname or parts.username or parts.password \
            or parts.query or parts.fragment:
        return False
    try:
        _ = parts.port
    except ValueError:
        return False
    return True


def bedrock_host(region: str) -> str:
    return f"bedrock-runtime.{region}.amazonaws.com"


def load() -> AiConfig | None:
    """The configuration in force, or None when the assistant is off or misconfigured (a malformed URL or region is
    treated as unset, never guessed at)."""
    provider = (os.environ.get("CBOM_AI_PROVIDER") or "").strip().lower()
    base = (os.environ.get("CBOM_AI_BASE_URL") or "").strip().rstrip("/")
    if not provider and base:
        provider = "openai_compat"
    if provider not in PROVIDERS:
        return None
    common = dict(
        api_key=(os.environ.get("CBOM_AI_API_KEY") or "").strip() or None,
        ca_file=(os.environ.get("CBOM_AI_CA_FILE") or "").strip() or None,
        timeout_s=_number("CBOM_AI_TIMEOUT_S", DEFAULT_TIMEOUT_S, 1, 600),
        max_tokens=int(_number("CBOM_AI_MAX_TOKENS", DEFAULT_MAX_TOKENS, 64, 8192)),
        concurrency=int(_number("CBOM_AI_CONCURRENCY", DEFAULT_CONCURRENCY, 1, 64)),
        allow_nonprivate=_flag("CBOM_AI_ALLOW_NONPRIVATE"),
        honor_proxy=_flag("CBOM_AI_HONOR_PROXY"),
    )
    model = (os.environ.get("CBOM_AI_MODEL") or "").strip()
    if provider == "bedrock":
        region = (os.environ.get("CBOM_AI_BEDROCK_REGION") or os.environ.get("AWS_REGION")
                  or os.environ.get("AWS_DEFAULT_REGION") or DEFAULT_BEDROCK_REGION).strip()
        if not _REGION.match(region):
            return None
        override = (os.environ.get("CBOM_AI_BEDROCK_ENDPOINT_URL") or "").strip().rstrip("/")
        if override and not _url_ok(override, ("https",)):
            return None
        profile = (os.environ.get("CBOM_AI_AWS_PROFILE") or "").strip() or None
        source = (os.environ.get("CBOM_AI_AWS_CREDENTIALS") or ("profile" if profile else "env")).strip().lower()
        if source not in CREDENTIAL_SOURCES:
            return None
        settings = tuple((k, os.environ.get(k, "").strip()) for k in _AWS_SETTING_KEYS if os.environ.get(k, "").strip())
        settings += (("env_keys_present", "1" if os.environ.get("AWS_ACCESS_KEY_ID") and
                      os.environ.get("AWS_SECRET_ACCESS_KEY") else ""),)
        return AiConfig(provider="bedrock", base_url=override or f"https://{bedrock_host(region)}",
                        aws_credentials=source, aws_settings=settings,
                        allow_loopback=_flag("CBOM_AI_BEDROCK_ALLOW_LOOPBACK"),
                        model=(model or DEFAULT_BEDROCK_MODEL)[:200], region=region,
                        endpoint_override=bool(override),
                        aws_profile=profile,
                        # the prompt leaves the network here: host names are hidden unless the operator says otherwise
                        redact_hosts=_flag("CBOM_AI_REDACT_HOSTS", default=True), **common)
    if not base or not model or not _url_ok(base, ("http", "https")):
        return None
    return AiConfig(provider="openai_compat", base_url=base, model=model[:200],
                    redact_hosts=_flag("CBOM_AI_REDACT_HOSTS"), **common)
