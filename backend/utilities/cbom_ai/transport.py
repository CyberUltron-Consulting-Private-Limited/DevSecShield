"""The only network paths of the CBOM AI assistant: one Bedrock Converse call, or one POST to an on-prem
OpenAI-compatible endpoint.

Bedrock (primary provider):

* boto3 is imported inside the call only (the backend imports without it), with the standard AWS credential chain;
* the endpoint is ``bedrock-runtime.<region>.amazonaws.com`` (or its FIPS twin); an override must be a Bedrock
  PrivateLink name (``vpce-*.bedrock-runtime.<region>.vpce.amazonaws.com``) or a private address literal;
* credentials come from exactly one configured source (``CBOM_AI_AWS_CREDENTIALS``), resolved on the first assist,
  never on a status check (a status check only builds the client for the sources that need no network: static, env,
  profile); the client is built in botocore's legacy defaults mode, so it never asks instance metadata for a region;
* environment proxies and ``AWS_CA_BUNDLE`` are ignored unless ``CBOM_AI_HONOR_PROXY=1``, for the Bedrock call and
  for the credential fetchers (IMDS, container endpoint, STS); botocore makes one attempt, so a redirect is an error,
  never followed (the assistant itself retries at most once, see service.assist);
* connect + read timeouts fit the request deadline (``CBOM_AI_DEADLINE_S``); a pooled connection idle longer than
  ``IDLE_REUSE_S`` is not reused (a NAT or load balancer may have dropped it silently: reusing it hangs until the read
  timeout), and after a timeout or a dropped connection the pool is closed, so the next call starts fresh.

Both providers return the text with the model's stop reason (Converse ``stopReason``, OpenAI ``finish_reason``), so a
reply cut at the output-token cap is told apart from one that is not JSON.

On-prem OpenAI-compatible endpoint:

* The endpoint host is resolved once; every address it resolves to must be loopback, RFC 1918 or IPv6 unique-local
  (fc00::/7) unless ``CBOM_AI_ALLOW_NONPRIVATE=1``. Link-local (169.254/16, fe80::/10, which holds the cloud metadata
  service) is refused in every mode.
* The request goes to the resolved address itself (the hostname is kept for the Host header and TLS SNI / certificate
  check), so a DNS answer that changes between the check and the connection cannot redirect it.
* Redirects are refused, environment proxies and ``.netrc`` are ignored (``trust_env=False``) unless
  ``CBOM_AI_HONOR_PROXY=1``, and no other host is ever contacted.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

import httpx

from backend.utilities.cbom_ai.config import AiConfig, bedrock_host

PRIVATE_NETS = [ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7")]
LINK_LOCAL_NETS = [ipaddress.ip_network(n) for n in ("169.254.0.0/16", "fe80::/10")]

Resolver = Callable[[str, int], list[str]]


class EndpointRefused(Exception):
    """The endpoint may not be contacted (address policy or a redirect); the message is safe to log."""


class Busy(Exception):
    """No concurrency slot within SLOT_WAIT_S: the request was not sent."""


SLOT_WAIT_S = 2.0


class EndpointError(Exception):
    """The endpoint answered with an error or something that is not a chat completion."""


class ConnectionLost(EndpointError):
    """The connection broke before an answer came (a reused keep-alive connection the far end had closed). The pool
    is closed, so one retry goes out on a fresh connection."""


# stop reasons of an answer cut at the output-token cap: Converse max_tokens (and the context window filling up),
# OpenAI-compatible finish_reason length
TRUNCATED_STOPS = frozenset({"max_tokens", "model_context_window_exceeded", "length"})
DEFAULT_CALL_MAX_TOKENS = 1024  # a call made without a budget (service.assist always passes the mode's budget)


@dataclass(frozen=True)
class Reply:
    """The model's text and why it stopped ("" when the endpoint did not say)."""
    text: str
    stop: str = ""

    @property
    def truncated(self) -> bool:
        return self.stop in TRUNCATED_STOPS


def system_resolve(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    return list(dict.fromkeys(info[4][0] for info in infos))


def _ip(address: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def address_allowed(address: str, allow_nonprivate: bool) -> bool:
    try:
        ip = _ip(address)
    except ValueError:
        return False
    if any(ip in net for net in LINK_LOCAL_NETS) or ip.is_unspecified or ip.is_multicast:
        return False
    if allow_nonprivate:
        return True
    return any(ip in net for net in PRIVATE_NETS)


def pin_address(cfg: AiConfig, resolve: Resolver = system_resolve) -> str:
    """The one address the request will use. Every address the host resolves to must pass the policy (a name that
    answers with one private and one public address is refused: which one a client picks is not ours to decide)."""
    host = cfg.host
    try:
        literal = _ip(host.strip("[]"))
        addresses = [str(literal)]
    except ValueError:
        try:
            addresses = resolve(host, cfg.port)
        except (OSError, UnicodeError) as exc:
            raise EndpointRefused(f"endpoint host does not resolve ({exc.__class__.__name__})") from None
    if not addresses:
        raise EndpointRefused("endpoint host does not resolve")
    bad = [a for a in addresses if not address_allowed(a, cfg.allow_nonprivate)]
    if bad:
        raise EndpointRefused("endpoint resolves to an address outside loopback / RFC 1918 / ULA"
                              if not cfg.allow_nonprivate else "endpoint resolves to a link-local or unusable address")
    return str(_ip(addresses[0]))


@dataclass
class Pinned:
    url: str            # the chat completions URL with the pinned address in place of the host
    host_header: str
    sni: str | None


def pinned_request(cfg: AiConfig, address: str, path: str = "/chat/completions") -> Pinned:
    parts = urlsplit(cfg.base_url)
    ip = ipaddress.ip_address(address)
    netloc_host = f"[{ip}]" if ip.version == 6 else str(ip)
    netloc = f"{netloc_host}:{cfg.port}"
    url = urlunsplit((parts.scheme, netloc, parts.path.rstrip("/") + path, "", ""))
    default_port = 443 if parts.scheme == "https" else 80
    host_header = parts.hostname if cfg.port == default_port else f"{parts.hostname}:{cfg.port}"
    if ":" in (parts.hostname or "") and not host_header.startswith("["):
        host_header = f"[{parts.hostname}]" + ("" if cfg.port == default_port else f":{cfg.port}")
    sni = parts.hostname if parts.scheme == "https" else None
    return Pinned(url=url, host_header=host_header, sni=sni)


def _verify(cfg: AiConfig) -> ssl.SSLContext | bool:
    if cfg.ca_file:
        return ssl.create_default_context(cafile=cfg.ca_file)
    return True


def make_client(cfg: AiConfig, transport: httpx.AsyncBaseTransport | None = None) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=transport,
        verify=_verify(cfg),
        # HTTP(S)_PROXY / ALL_PROXY / NO_PROXY / SSL_CERT_FILE / .netrc are ignored unless the operator opts in
        trust_env=cfg.honor_proxy,
        follow_redirects=False,
        timeout=httpx.Timeout(cfg.timeout_s),
    )


async def chat(cfg: AiConfig, messages: list[dict[str, str]], *, resolve: Resolver = system_resolve,
               transport: httpx.AsyncBaseTransport | None = None) -> Reply:
    """One chat completion; returns the assistant message text and its finish_reason. Raises EndpointRefused /
    EndpointError / httpx.TimeoutException."""
    address = pin_address(cfg, resolve)
    target = pinned_request(cfg, address)
    headers = {"Host": target.host_header, "Content-Type": "application/json", "Accept": "application/json"}
    if cfg.api_key:
        headers["Authorization"] = f"Bearer {cfg.api_key}"
    extensions = {"sni_hostname": target.sni} if target.sni else {}
    body: dict[str, Any] = {"model": cfg.model, "messages": messages,
                            "max_tokens": cfg.max_tokens or DEFAULT_CALL_MAX_TOKENS,
                            "temperature": 0, "stream": False, "response_format": {"type": "json_object"}}
    async with make_client(cfg, transport) as client:
        for attempt in (1, 2):
            response = await client.post(target.url, content=json.dumps(body), headers=headers, extensions=extensions)
            if response.is_redirect or 300 <= response.status_code < 400:
                raise EndpointRefused("endpoint answered with a redirect; redirects are refused")
            if response.status_code == 400 and attempt == 1 and "response_format" in body:
                # a runtime without guided JSON: ask again without it, the validator parses the text either way
                body.pop("response_format")
                continue
            break
    if response.status_code != 200:
        raise EndpointError(f"endpoint answered HTTP {response.status_code}")
    try:
        data = response.json()
        choice = data["choices"][0]
        content = choice["message"]["content"]
        finish = choice.get("finish_reason")
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        raise EndpointError("endpoint answer is not an OpenAI-compatible chat completion") from None
    stop = _stop_name(finish)
    if content is None and stop in TRUNCATED_STOPS:
        content = ""  # the budget ran out before any text (a reasoning model): a cut-off answer, not an error
    if not isinstance(content, str):
        raise EndpointError("endpoint answer has no text")
    return Reply(content, stop)


def _stop_name(value: Any) -> str:
    """A stop reason as it goes into the audit line: a short token, never the endpoint's free text."""
    return re.sub(r"[^A-Za-z0-9_.-]", "", value)[:40] if isinstance(value, str) else ""


# ================================================================================================ AWS Bedrock
_VPCE = r"vpce-[a-z0-9]+(?:-[a-z0-9]+)*\.bedrock-runtime\.{region}\.vpce\.amazonaws\.com"
IMDS_HOST = "169.254.169.254"
ECS_CONTAINER_HOST = "169.254.170.2"
BEDROCK_CLIENT_HOOKS: list[Callable[[Any], None]] = []   # tests register botocore event handlers here
# credential sources that read local configuration only: building their client contacts nothing, so a status check
# may build it ahead of the first assist
LOCAL_CREDENTIAL_SOURCES = ("static", "env", "profile")
MARGIN_S = 3.0        # between the end of the worker thread's call and the request deadline
IDLE_REUSE_S = 30.0   # a pooled connection idle longer than this is closed before the next call, not reused
_clients: dict[tuple, Any] = {}
_last_use: dict[tuple, float] = {}
_clients_lock = threading.Lock()
_slots: dict[int, threading.BoundedSemaphore] = {}
_slots_lock = threading.Lock()
log = logging.getLogger("backend.cbom_ai")


def bedrock_hosts_allowed(cfg: AiConfig) -> tuple[str, ...]:
    region = cfg.region or ""
    return (bedrock_host(region), f"bedrock-runtime-fips.{region}.amazonaws.com")


def check_bedrock_endpoint(cfg: AiConfig, resolve: Resolver = system_resolve) -> None:
    """The Bedrock endpoint must be the regional runtime host (with PrivateLink private DNS it resolves to the VPC
    endpoint), a Bedrock PrivateLink name for the region (AWS DNS), or a private (RFC 1918 / ULA) address literal of
    the VPC endpoint. A custom name is refused: botocore resolves it again when it connects, so its address cannot be
    pinned. Loopback (a local forwarder could relay anywhere) only with CBOM_AI_BEDROCK_ALLOW_LOOPBACK=1."""
    host = cfg.host.lower().strip("[]")
    if cfg.scheme != "https":
        raise EndpointRefused("the Bedrock endpoint must use https")
    if host in bedrock_hosts_allowed(cfg) or re.fullmatch(_VPCE.format(region=re.escape(cfg.region or "")), host):
        return
    try:
        ip = _ip(host)
    except ValueError:
        raise EndpointRefused("CBOM_AI_BEDROCK_ENDPOINT_URL must be the regional bedrock-runtime host, a "
                              "vpce-*.bedrock-runtime.<region>.vpce.amazonaws.com name or a private address") from None
    if ip.is_loopback:
        if cfg.allow_loopback:
            return
        raise EndpointRefused("a loopback Bedrock endpoint needs CBOM_AI_BEDROCK_ALLOW_LOOPBACK=1")
    if not address_allowed(str(ip), False):
        raise EndpointRefused("the Bedrock endpoint address is not private")


def _host_port(uri: str, default_port: int) -> tuple[str, int]:
    parts = urlsplit(uri)
    try:
        port = parts.port
    except ValueError:
        port = None
    return (parts.hostname or "", port or (443 if parts.scheme == "https" else default_port))


def credential_plan(cfg: AiConfig) -> list[dict[str, Any]]:
    """The endpoints the configured credential source will contact, worked out from the configuration alone (no
    network: the status route calls this). Raises EndpointRefused when the source is not usable as configured."""
    kind = cfg.aws_credentials
    if kind == "static":
        if cfg.aws_static is None:
            raise EndpointRefused("CBOM_AI_AWS_CREDENTIALS=static but CBOM_AI_AWS_ACCESS_KEY_ID / "
                                  "CBOM_AI_AWS_SECRET_ACCESS_KEY are not both set")
        return []  # the assistant's own keys, from its configuration: no network
    if kind == "env":
        if not cfg.aws("env_keys_present"):
            raise EndpointRefused("CBOM_AI_AWS_CREDENTIALS=env but AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY are not set")
        return []
    if kind == "profile":
        return []  # keys from the shared credentials / config file: no network (assume-role profiles are refused)
    if kind == "instance":
        if cfg.aws("AWS_EC2_METADATA_DISABLED").lower() == "true":
            raise EndpointRefused("CBOM_AI_AWS_CREDENTIALS=instance but AWS_EC2_METADATA_DISABLED=true")
        return [{"host": IMDS_HOST, "port": 80,
                 "purpose": "EC2 instance metadata (IMDSv2): instance-role credentials (link-local)"}]
    if kind == "container":
        full = cfg.aws("AWS_CONTAINER_CREDENTIALS_FULL_URI")
        if full:
            host, port = _host_port(full, 80)
            purpose = ("EKS Pod Identity agent: container credentials" if host == "169.254.170.23"
                       else "container credentials endpoint (AWS_CONTAINER_CREDENTIALS_FULL_URI)")
            return [{"host": host, "port": port, "purpose": purpose}]
        if cfg.aws("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"):
            return [{"host": ECS_CONTAINER_HOST, "port": 80, "purpose": "ECS container credentials endpoint"}]
        raise EndpointRefused("CBOM_AI_AWS_CREDENTIALS=container but no AWS_CONTAINER_CREDENTIALS_*_URI is set")
    if kind == "web_identity":
        if not (cfg.aws("AWS_ROLE_ARN") and cfg.aws("AWS_WEB_IDENTITY_TOKEN_FILE")):
            raise EndpointRefused("CBOM_AI_AWS_CREDENTIALS=web_identity needs AWS_ROLE_ARN and "
                                  "AWS_WEB_IDENTITY_TOKEN_FILE")
        return [{"host": f"sts.{cfg.region}.amazonaws.com", "port": 443,
                 "purpose": "AWS STS AssumeRoleWithWebIdentity (IRSA): credentials"}]
    raise EndpointRefused("unknown credential source")


def bedrock_egress(cfg: AiConfig) -> list[dict[str, Any]]:
    """Every host the Bedrock provider contacts, as configured: the runtime endpoint plus the credential source's."""
    return [{"host": cfg.host, "port": cfg.port, "purpose": f"AWS Bedrock Converse ({cfg.region}, {cfg.model})"}] + \
        credential_plan(cfg)


def _no_proxy_session(timeout: float) -> Any:
    from botocore.httpsession import URLLib3Session

    return URLLib3Session(timeout=timeout, proxies={})


def _credential_provider(cfg: AiConfig, botocore_session: Any) -> Any:
    """Exactly one credential source, with no fall-through, and its HTTP fetchers built without environment proxies
    unless CBOM_AI_HONOR_PROXY=1 (botocore's own IMDS and container fetchers read HTTP(S)_PROXY)."""
    from botocore import credentials as BC
    from botocore.config import Config
    from botocore.utils import ContainerMetadataFetcher, FileWebIdentityTokenLoader, InstanceMetadataFetcher

    kind = cfg.aws_credentials
    if kind == "static":
        keys = cfg.aws_static
        if keys is None:
            raise EndpointRefused("static credentials are not configured")

        class _Static(BC.CredentialProvider):
            METHOD = "cbom-ai-static"

            def load(self) -> Any:
                return BC.Credentials(keys.access_key, keys.secret_key, keys.token, method=self.METHOD)

        return BC.CredentialResolver([_Static()])
    if kind in ("env", "profile"):
        wanted = {"env"} if kind == "env" else {"shared-credentials-file", "config-file"}
        resolver = BC.create_credential_resolver(botocore_session, region_name=cfg.region)
        providers = [p for p in resolver.providers if p.METHOD in wanted]
        return BC.CredentialResolver(providers)
    if kind == "instance":
        fetcher = InstanceMetadataFetcher(timeout=2, num_attempts=2,
                                          env={"AWS_EC2_METADATA_DISABLED": cfg.aws("AWS_EC2_METADATA_DISABLED")
                                               or "false"})
        if not cfg.honor_proxy:
            fetcher._session = _no_proxy_session(2)  # botocore builds it with get_environ_proxies()
        return BC.CredentialResolver([BC.InstanceMetadataProvider(iam_role_fetcher=fetcher)])
    if kind == "container":
        fetcher = ContainerMetadataFetcher(session=None if cfg.honor_proxy else _no_proxy_session(2))
        return BC.CredentialResolver([BC.ContainerProvider(fetcher=fetcher)])
    if kind == "web_identity":
        def sts_client(service: str, **kwargs: Any) -> Any:
            config = (kwargs.get("config") or Config()).merge(Config(
                proxies=None if cfg.honor_proxy else {}, retries={"total_max_attempts": 2, "mode": "standard"}))
            return botocore_session.create_client(service, region_name=cfg.region, config=config,
                                                  endpoint_url=f"https://sts.{cfg.region}.amazonaws.com")

        fetch = BC.AssumeRoleWithWebIdentityCredentialFetcher(
            client_creator=sts_client,
            web_identity_token_loader=FileWebIdentityTokenLoader(cfg.aws("AWS_WEB_IDENTITY_TOKEN_FILE")),
            role_arn=cfg.aws("AWS_ROLE_ARN"),
            extra_args={"RoleSessionName": cfg.aws("AWS_ROLE_SESSION_NAME") or "zeroshield-cbom-ai"})

        class _WebIdentity(BC.CredentialProvider):
            METHOD = "assume-role-with-web-identity"

            def load(self) -> Any:
                return BC.DeferredRefreshableCredentials(method=self.METHOD, refresh_using=fetch.fetch_credentials)

        return BC.CredentialResolver([_WebIdentity()])
    raise EndpointRefused("unknown credential source")


def _botocore_session(cfg: AiConfig) -> Any:
    import botocore.session  # lazily: the backend imports and runs without boto3 / botocore being loaded

    # a named profile is read only when it is the source (static keys never look at the shared files)
    profile = cfg.aws_profile if cfg.aws_credentials != "static" else None
    session = botocore.session.Session(profile=profile) if profile else botocore.session.Session()
    session.register_component("credential_provider", _credential_provider(cfg, session))
    return session


def bedrock_timeouts(cfg: AiConfig) -> tuple[float, float]:
    """(connect, read) for botocore. They add up to CBOM_AI_TIMEOUT_S, but never to more than the request deadline
    leaves after the slot wait (and a margin), so a worker thread ends before the caller stops waiting: with the
    default 50 s deadline that is 5 + 40 s, also when CBOM_AI_TIMEOUT_S is 180 (staging's value, #449)."""
    attempt = max(2.0, min(cfg.timeout_s, cfg.deadline_s - SLOT_WAIT_S - MARGIN_S))
    connect = min(5.0, max(1.0, attempt / 4))
    return connect, max(1.0, attempt - connect)


def bedrock_deadline_s(cfg: AiConfig) -> float:
    """How long the caller waits for the whole request (slot wait, Converse call, at most one retry):
    CBOM_AI_DEADLINE_S. One call's slot wait + connect + read timeouts fit inside it (bedrock_timeouts)."""
    return cfg.deadline_s


def _client_key(cfg: AiConfig) -> tuple:
    return (cfg.region, cfg.base_url, cfg.honor_proxy, cfg.ca_file, bedrock_timeouts(cfg), cfg.aws_profile,
            cfg.aws_credentials, cfg.aws_settings)


def _bedrock_client(cfg: AiConfig) -> Any:
    """Built once per configuration and reused (module level). It resolves credentials, which for the instance /
    container / web_identity sources contacts their endpoint: the status route builds it only for
    LOCAL_CREDENTIAL_SOURCES (warm_bedrock), never for those."""
    key = _client_key(cfg)
    with _clients_lock:
        client = _clients.get(key)
        if client is not None:
            return client
        from botocore.config import Config  # lazily

        connect, read = bedrock_timeouts(cfg)
        config = Config(
            region_name=cfg.region,
            connect_timeout=connect,
            read_timeout=read,
            retries={"total_max_attempts": 1, "mode": "standard"},  # one attempt: an error or a redirect is final
            # {} (not None) means "no proxy": botocore reads HTTP(S)_PROXY from the environment only when this is None
            proxies=None if cfg.honor_proxy else {},
            # "auto" (AWS_DEFAULTS_MODE or the AWS config file) asks instance metadata for the region on every client
            # built: on a host that is not EC2 each probe waits for its timeout. The region is configured here.
            defaults_mode="legacy",
        )
        # verify=True ignores AWS_CA_BUNDLE (the egress proxy's CA); None lets botocore read it when proxies are honoured
        verify: Any = cfg.ca_file or (None if cfg.honor_proxy else True)
        client = _botocore_session(cfg).create_client("bedrock-runtime", region_name=cfg.region,
                                                      endpoint_url=cfg.base_url, config=config, verify=verify)
        for hook in BEDROCK_CLIENT_HOOKS:
            hook(client)
        _clients[key] = client
        return client


def warm_bedrock(cfg: AiConfig) -> None:
    """Build the client ahead of the first assist (the status route calls this), when that contacts nothing: only for
    LOCAL_CREDENTIAL_SOURCES. Never raises: a problem shows on the assist, as before."""
    if cfg.provider != "bedrock" or cfg.aws_credentials not in LOCAL_CREDENTIAL_SOURCES:
        return
    try:
        _bedrock_client(cfg)
    except Exception as exc:  # a broken shared credentials file, for example
        log.warning("cbom_ai client warm-up failed: %s", exc.__class__.__name__)


def _reuse_or_refresh(key: tuple, client: Any) -> None:
    """Close the pool of a client that has been idle longer than IDLE_REUSE_S, so this call opens a fresh connection
    instead of reusing one a NAT, firewall or load balancer may have dropped without a FIN reaching us (a call on it
    hangs until the read timeout). Calls in flight keep their connection: closing the pool only drops idle ones."""
    now = time.monotonic()
    with _clients_lock:
        last = _last_use.get(key)
        _last_use[key] = now
    if last is not None and now - last > IDLE_REUSE_S:
        client.close()


def _drop_pool(client: Any) -> None:
    try:
        client.close()
    except Exception:  # pragma: no cover - closing idle sockets
        pass


def reset_bedrock_clients() -> None:
    with _clients_lock:
        _clients.clear()
        _last_use.clear()
    with _slots_lock:
        _slots.clear()


def _slot(cfg: AiConfig) -> threading.BoundedSemaphore:
    with _slots_lock:
        sem = _slots.get(cfg.concurrency)
        if sem is None:
            sem = _slots[cfg.concurrency] = threading.BoundedSemaphore(cfg.concurrency)
        return sem


def bedrock_chat(cfg: AiConfig, messages: list[dict[str, str]], resolve: Resolver = system_resolve) -> Reply:
    """One Converse call (blocking; run it in a thread); returns the text and the Converse stopReason. The
    concurrency slot is held in this thread until botocore returns, so CBOM_AI_CONCURRENCY holds even when the caller
    has stopped waiting. Raises Busy (no slot within SLOT_WAIT_S; nothing sent) / EndpointRefused / EndpointError /
    ConnectionLost (an EndpointError: retry once) / TimeoutError."""
    from botocore.exceptions import (BotoCoreError, ClientError, ConnectionClosedError, ConnectTimeoutError,
                                     CredentialRetrievalError, NoCredentialsError, ReadTimeoutError)

    check_bedrock_endpoint(cfg, resolve)
    credential_plan(cfg)
    system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
    turns = [{"role": m["role"], "content": [{"text": m["content"]}]} for m in messages if m["role"] != "system"]
    slot = _slot(cfg)
    if not slot.acquire(timeout=SLOT_WAIT_S):
        raise Busy()
    client = None
    try:
        client = _bedrock_client(cfg)
        _reuse_or_refresh(_client_key(cfg), client)
        response = client.converse(
            modelId=cfg.model, system=[{"text": system}] if system else [], messages=turns,
            inferenceConfig={"maxTokens": cfg.max_tokens or DEFAULT_CALL_MAX_TOKENS, "temperature": 0})
    except (ReadTimeoutError, ConnectTimeoutError):
        if client is not None:
            _drop_pool(client)  # the user's next try starts on a fresh connection
        raise TimeoutError("Bedrock did not answer in time") from None
    except ConnectionClosedError:
        if client is not None:
            _drop_pool(client)
        raise ConnectionLost("Bedrock connection closed before an answer (stale pooled connection)") from None
    except (NoCredentialsError, CredentialRetrievalError):
        raise EndpointError(f"no AWS credentials from the {cfg.aws_credentials} source") from None
    except ClientError as exc:
        status = int((exc.response.get("ResponseMetadata") or {}).get("HTTPStatusCode") or 0)
        if 300 <= status < 400:
            raise EndpointRefused("Bedrock endpoint answered with a redirect; redirects are refused") from None
        code = (exc.response.get("Error") or {}).get("Code") or "error"
        raise EndpointError(f"Bedrock {code} (HTTP {status})") from None
    except BotoCoreError as exc:
        if client is not None:
            _drop_pool(client)
        raise EndpointError(f"Bedrock {exc.__class__.__name__}") from None
    finally:
        slot.release()
        with _clients_lock:
            if client is not None:
                _last_use[_client_key(cfg)] = time.monotonic()
    stop = _stop_name(response.get("stopReason") if isinstance(response, dict) else None)
    try:
        blocks = response["output"]["message"]["content"]
    except (KeyError, TypeError):
        raise EndpointError("Bedrock answer has no message") from None
    # reasoning models (gpt-oss) put reasoningContent blocks before the text
    texts = [b["text"] for b in blocks if isinstance(b, dict) and isinstance(b.get("text"), str)]
    if not texts:
        if stop in TRUNCATED_STOPS:
            return Reply("", stop)  # the budget went on reasoning: a cut-off answer, not an endpoint error
        raise EndpointError("Bedrock answer has no text")
    return Reply("\n".join(texts), stop)
