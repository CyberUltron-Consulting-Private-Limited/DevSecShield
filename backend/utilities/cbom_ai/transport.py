"""The only network paths of the CBOM AI assistant: one Bedrock Converse call, or one POST to an on-prem
OpenAI-compatible endpoint.

Bedrock (primary provider):

* boto3 is imported inside the call only (the backend imports without it), with the standard AWS credential chain;
* the endpoint is ``bedrock-runtime.<region>.amazonaws.com`` (or its FIPS twin); an override must be a Bedrock
  PrivateLink name (``vpce-*.bedrock-runtime.<region>.vpce.amazonaws.com``) or a private address literal;
* credentials come from exactly one configured source (``CBOM_AI_AWS_CREDENTIALS``), resolved on the first assist
  only, never on a status check;
* environment proxies and ``AWS_CA_BUNDLE`` are ignored unless ``CBOM_AI_HONOR_PROXY=1``, for the Bedrock call and
  for the credential fetchers (IMDS, container endpoint, STS); no retries, so a redirect is an error, never followed.

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
import re
import socket
import ssl
import threading
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
               transport: httpx.AsyncBaseTransport | None = None) -> str:
    """One chat completion; returns the assistant message text. Raises EndpointRefused / EndpointError /
    httpx.TimeoutException."""
    address = pin_address(cfg, resolve)
    target = pinned_request(cfg, address)
    headers = {"Host": target.host_header, "Content-Type": "application/json", "Accept": "application/json"}
    if cfg.api_key:
        headers["Authorization"] = f"Bearer {cfg.api_key}"
    extensions = {"sni_hostname": target.sni} if target.sni else {}
    body: dict[str, Any] = {"model": cfg.model, "messages": messages, "max_tokens": cfg.max_tokens,
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
        content = data["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError):
        raise EndpointError("endpoint answer is not an OpenAI-compatible chat completion") from None
    if not isinstance(content, str):
        raise EndpointError("endpoint answer has no text")
    return content


# ================================================================================================ AWS Bedrock
_VPCE = r"vpce-[a-z0-9]+(?:-[a-z0-9]+)*\.bedrock-runtime\.{region}\.vpce\.amazonaws\.com"
IMDS_HOST = "169.254.169.254"
ECS_CONTAINER_HOST = "169.254.170.2"
BEDROCK_CLIENT_HOOKS: list[Callable[[Any], None]] = []   # tests register botocore event handlers here
_clients: dict[tuple, Any] = {}
_clients_lock = threading.Lock()
_slots: dict[int, threading.BoundedSemaphore] = {}
_slots_lock = threading.Lock()


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

    session = botocore.session.Session(profile=cfg.aws_profile) if cfg.aws_profile else botocore.session.Session()
    session.register_component("credential_provider", _credential_provider(cfg, session))
    return session


def bedrock_timeouts(cfg: AiConfig) -> tuple[float, float]:
    """(connect, read) for botocore, adding up to CBOM_AI_TIMEOUT_S, so a worker thread ends within it."""
    connect = min(10.0, max(1.0, cfg.timeout_s / 4))
    return connect, max(1.0, cfg.timeout_s - connect)


def bedrock_deadline_s(cfg: AiConfig) -> float:
    """How long the caller waits for one Converse call: the slot wait, then botocore's connect + read timeouts (which
    add up to CBOM_AI_TIMEOUT_S), plus a margin, so the waiter is not cancelled while the call is still running."""
    return SLOT_WAIT_S + sum(bedrock_timeouts(cfg)) + 2


def _bedrock_client(cfg: AiConfig) -> Any:
    """Created on the first assist only (it resolves credentials, which may contact the credential endpoint); the
    status route never builds it."""
    key = (cfg.region, cfg.base_url, cfg.honor_proxy, cfg.ca_file, cfg.timeout_s, cfg.aws_profile,
           cfg.aws_credentials, cfg.aws_settings)
    with _clients_lock:
        client = _clients.get(key)
        if client is not None:
            return client
        from botocore.config import Config  # lazily

        config = Config(
            region_name=cfg.region,
            connect_timeout=bedrock_timeouts(cfg)[0],
            read_timeout=bedrock_timeouts(cfg)[1],
            retries={"total_max_attempts": 1, "mode": "standard"},  # one attempt: an error or a redirect is final
            # {} (not None) means "no proxy": botocore reads HTTP(S)_PROXY from the environment only when this is None
            proxies=None if cfg.honor_proxy else {},
        )
        # verify=True ignores AWS_CA_BUNDLE (the egress proxy's CA); None lets botocore read it when proxies are honoured
        verify: Any = cfg.ca_file or (None if cfg.honor_proxy else True)
        client = _botocore_session(cfg).create_client("bedrock-runtime", region_name=cfg.region,
                                                      endpoint_url=cfg.base_url, config=config, verify=verify)
        for hook in BEDROCK_CLIENT_HOOKS:
            hook(client)
        _clients[key] = client
        return client


def reset_bedrock_clients() -> None:
    with _clients_lock:
        _clients.clear()
    with _slots_lock:
        _slots.clear()


def _slot(cfg: AiConfig) -> threading.BoundedSemaphore:
    with _slots_lock:
        sem = _slots.get(cfg.concurrency)
        if sem is None:
            sem = _slots[cfg.concurrency] = threading.BoundedSemaphore(cfg.concurrency)
        return sem


def bedrock_chat(cfg: AiConfig, messages: list[dict[str, str]], resolve: Resolver = system_resolve) -> str:
    """One Converse call (blocking; run it in a thread). The concurrency slot is held in this thread until botocore
    returns, so CBOM_AI_CONCURRENCY holds even when the caller has stopped waiting. Raises Busy (no slot within
    SLOT_WAIT_S; nothing sent) / EndpointRefused / EndpointError / TimeoutError."""
    from botocore.exceptions import (BotoCoreError, ClientError, ConnectTimeoutError, CredentialRetrievalError,
                                     NoCredentialsError, ReadTimeoutError)

    check_bedrock_endpoint(cfg, resolve)
    credential_plan(cfg)
    system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
    turns = [{"role": m["role"], "content": [{"text": m["content"]}]} for m in messages if m["role"] != "system"]
    slot = _slot(cfg)
    if not slot.acquire(timeout=SLOT_WAIT_S):
        raise Busy()
    try:
        response = _bedrock_client(cfg).converse(
            modelId=cfg.model, system=[{"text": system}] if system else [], messages=turns,
            inferenceConfig={"maxTokens": cfg.max_tokens, "temperature": 0})
    except (ReadTimeoutError, ConnectTimeoutError):
        raise TimeoutError("Bedrock did not answer in time") from None
    except (NoCredentialsError, CredentialRetrievalError):
        raise EndpointError(f"no AWS credentials from the {cfg.aws_credentials} source") from None
    except ClientError as exc:
        status = int((exc.response.get("ResponseMetadata") or {}).get("HTTPStatusCode") or 0)
        if 300 <= status < 400:
            raise EndpointRefused("Bedrock endpoint answered with a redirect; redirects are refused") from None
        code = (exc.response.get("Error") or {}).get("Code") or "error"
        raise EndpointError(f"Bedrock {code} (HTTP {status})") from None
    except BotoCoreError as exc:
        raise EndpointError(f"Bedrock {exc.__class__.__name__}") from None
    finally:
        slot.release()
    try:
        blocks = response["output"]["message"]["content"]
    except (KeyError, TypeError):
        raise EndpointError("Bedrock answer has no message") from None
    # reasoning models (gpt-oss) put reasoningContent blocks before the text
    texts = [b["text"] for b in blocks if isinstance(b, dict) and isinstance(b.get("text"), str)]
    if not texts:
        raise EndpointError("Bedrock answer has no text")
    return "\n".join(texts)
