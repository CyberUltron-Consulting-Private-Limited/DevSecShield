"""Deployment-level configuration of the CBOM AI remediation assistant (environment only; nothing in the database).

Two providers:

* ``bedrock`` (primary; ``CBOM_AI_PROVIDER=bedrock``): AWS Bedrock Converse in ``CBOM_AI_BEDROCK_REGION``, with
  credentials from exactly one source (``CBOM_AI_AWS_CREDENTIALS``: static, env, profile, instance, container,
  web_identity; ``static`` is the default when ``CBOM_AI_AWS_ACCESS_KEY_ID`` / ``CBOM_AI_AWS_SECRET_ACCESS_KEY`` are
  set: the assistant's own IAM user, not the host's ``AWS_*``). The product's only outbound call: HTTPS to
  ``bedrock-runtime.<region>.amazonaws.com``
  (or a Bedrock PrivateLink endpoint set in ``CBOM_AI_BEDROCK_ENDPOINT_URL``).
* ``openai_compat`` (``CBOM_AI_PROVIDER=openai_compat``, or ``CBOM_AI_BASE_URL`` set without a provider): an
  OpenAI-compatible model on a private address (Ollama, vLLM, llama.cpp server, TGI); nothing leaves the network.

Neither configured means the feature is off: the status route says unavailable, the assist route is a 404 and no
socket is ever opened.
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

DEFAULT_TIMEOUT_S = 60.0
# 0: no deployment-wide cap, each mode has its own output budget (service.MODE_MAX_TOKENS); CBOM_AI_MAX_TOKENS sets a
# cap for a model with a small output or context limit
DEFAULT_MAX_TOKENS = 0
# the whole request (slot wait, model call, at most one retry) answers within this, so a proxy with nginx's 60 s
# default read timeout never cuts it; the UI waits 90 s (CBOM_AI_UI_TIMEOUT_MS), longer than the largest deadline
DEFAULT_DEADLINE_S = 50.0
MIN_DEADLINE_S = 10.0
MAX_DEADLINE_S = 85.0
DEFAULT_CONCURRENCY = 2
# the model the SAST lane already uses on Bedrock (backend/utilities/ai/llm.py get_llm default) and its region default
DEFAULT_BEDROCK_MODEL = "openai.gpt-oss-120b-1:0"
DEFAULT_BEDROCK_REGION = "ap-south-1"
PROVIDERS = ("bedrock", "openai_compat")
CREDENTIAL_SOURCES = ("static", "env", "profile", "instance", "container", "web_identity")
# the assistant's own keys (a dedicated IAM user with Bedrock invoke rights only), read here and nowhere else
STATIC_KEY_VARS = ("CBOM_AI_AWS_ACCESS_KEY_ID", "CBOM_AI_AWS_SECRET_ACCESS_KEY", "CBOM_AI_AWS_SESSION_TOKEN")
# per process: tells key pairs apart in the client cache without the cache key holding (or revealing) a key
_KEY_TAG_SALT = os.urandom(16)
# non-secret AWS settings the credential sources need (the key values themselves are read by botocore only)
_AWS_SETTING_KEYS = ("AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                     "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE",
                     "AWS_ROLE_SESSION_NAME", "AWS_EC2_METADATA_DISABLED")
_REGION = re.compile(r"^[a-z]{2}(-gov|-iso[a-z]*)?-[a-z]+-\d$")


class StaticKeys:
    """The ``static`` source's key pair (and optional session token). Never printed: the repr names no value, and the
    values are only handed to botocore's signer (transport._credential_provider)."""
    __slots__ = ("access_key", "secret_key", "token")

    def __init__(self, access_key: str, secret_key: str, token: str | None) -> None:
        self.access_key, self.secret_key, self.token = access_key, secret_key, token

    def __repr__(self) -> str:
        return "StaticKeys(<redacted>)"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        return isinstance(other, StaticKeys) and (self.access_key, self.secret_key, self.token) == \
            (other.access_key, other.secret_key, other.token)

    def __hash__(self) -> int:
        return hash(tag(self))


def tag(keys: StaticKeys) -> str:
    """A salted digest that differs per key pair and process: safe in a cache key, useless to anyone reading it."""
    return hashlib.blake2b("\0".join((keys.access_key, keys.secret_key, keys.token or "")).encode(),
                           key=_KEY_TAG_SALT, digest_size=8).hexdigest()


@dataclass(frozen=True)
class AiConfig:
    provider: str          # "bedrock" | "openai_compat"
    base_url: str          # openai_compat: OpenAI-compatible root ending in /v1; bedrock: the runtime endpoint URL
    model: str
    api_key: str | None
    ca_file: str | None
    timeout_s: float       # one model call (capped by deadline_s)
    max_tokens: int        # the operator's output cap, 0 when unset (each mode's own budget)
    concurrency: int
    redact_hosts: bool
    allow_nonprivate: bool
    honor_proxy: bool = False
    region: str | None = None          # bedrock only
    endpoint_override: bool = False    # bedrock: CBOM_AI_BEDROCK_ENDPOINT_URL was set
    aws_profile: str | None = None     # bedrock: a named profile (then AWS_* environment keys are not used)
    # bedrock: where credentials come from, explicitly (no fall-through to other sources): static | env | profile |
    # instance | container | web_identity
    aws_credentials: str = "env"
    # bedrock: the non-secret settings of that source, read once here (paths, URIs, role ARN; never key values)
    aws_settings: tuple[tuple[str, str], ...] = ()
    allow_loopback: bool = False       # bedrock: CBOM_AI_BEDROCK_ENDPOINT_URL may be a loopback forwarder
    # bedrock, source static: CBOM_AI_AWS_* (both halves, or None: then the source is refused, never a fall-back)
    aws_static: StaticKeys | None = field(default=None, repr=False)
    deadline_s: float = DEFAULT_DEADLINE_S  # the whole request: slot wait + model call + at most one retry

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
    if value != value:  # "nan" would pass both bounds
        value = default
    return min(max(value, low), high)


def _max_tokens() -> int:
    """CBOM_AI_MAX_TOKENS, clamped to 64 - 8192; DEFAULT_MAX_TOKENS (each mode's own budget) when unset or not a
    number."""
    raw = (os.environ.get("CBOM_AI_MAX_TOKENS") or "").strip()
    try:
        value = int(float(raw)) if raw else 0
    except (ValueError, OverflowError):  # "abc", "nan", "inf"
        value = 0
    return min(max(value, 64), 8192) if value > 0 else DEFAULT_MAX_TOKENS


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
        max_tokens=_max_tokens(),
        deadline_s=_number("CBOM_AI_DEADLINE_S", DEFAULT_DEADLINE_S, MIN_DEADLINE_S, MAX_DEADLINE_S),
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
        key_id, key_secret, key_token = ((os.environ.get(k) or "").strip() for k in STATIC_KEY_VARS)
        # either half of the dedicated pair set means "these keys": half a pair is refused (credential_plan), never
        # replaced by the host's AWS_* (shared with the SAST chat and, on some hosts, MinIO)
        default = "static" if key_id or key_secret else ("profile" if profile else "env")
        source = (os.environ.get("CBOM_AI_AWS_CREDENTIALS") or default).strip().lower()
        if source not in CREDENTIAL_SOURCES:
            return None
        static = StaticKeys(key_id, key_secret, key_token or None) if source == "static" and key_id and key_secret \
            else None
        settings = tuple((k, os.environ.get(k, "").strip()) for k in _AWS_SETTING_KEYS if os.environ.get(k, "").strip())
        settings += (("env_keys_present", "1" if os.environ.get("AWS_ACCESS_KEY_ID") and
                      os.environ.get("AWS_SECRET_ACCESS_KEY") else ""),)
        if static is not None:
            settings += (("static_keys", tag(static)),)
        return AiConfig(provider="bedrock", base_url=override or f"https://{bedrock_host(region)}",
                        aws_credentials=source, aws_settings=settings, aws_static=static,
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
