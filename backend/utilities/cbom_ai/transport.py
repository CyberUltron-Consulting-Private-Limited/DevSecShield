"""The only network paths of the CBOM AI assistant: one Bedrock Converse call, or one POST to an on-prem
OpenAI-compatible endpoint.

Bedrock (primary provider):

* boto3 is imported inside the call only (the backend imports without it), with the standard AWS credential chain;
* the endpoint is ``bedrock-runtime.<region>.amazonaws.com`` (or its FIPS twin); an override must be a Bedrock
  PrivateLink name (``vpce-*.bedrock-runtime.<region>.vpce.amazonaws.com``) or resolve only to private addresses;
* environment proxies and ``AWS_CA_BUNDLE`` are ignored unless ``CBOM_AI_HONOR_PROXY=1``; no retries, so a redirect is
  an error, never followed.

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
# credential provider (botocore ``Credentials.method``) -> the extra endpoint it really calls, when it calls one
_CREDENTIAL_EGRESS = {
    "iam-role": [("169.254.169.254", 80, "EC2 instance metadata (instance-role credentials; link-local, stays on the host)")],
    "container-role": [("169.254.170.2", 80, "ECS / EKS container credentials endpoint (link-local)")],
    "assume-role": [("sts.{region}.amazonaws.com", 443, "AWS STS AssumeRole (credentials)")],
    "assume-role-with-web-identity": [("sts.{region}.amazonaws.com", 443, "AWS STS AssumeRoleWithWebIdentity (IRSA)")],
    "sso": [("portal.sso.{region}.amazonaws.com", 443, "AWS IAM Identity Center (SSO credentials)")],
}
BEDROCK_CLIENT_HOOKS: list[Callable[[Any], None]] = []   # tests register botocore event handlers here
_clients: dict[tuple, Any] = {}
_clients_lock = threading.Lock()


def bedrock_hosts_allowed(cfg: AiConfig) -> tuple[str, ...]:
    region = cfg.region or ""
    return (bedrock_host(region), f"bedrock-runtime-fips.{region}.amazonaws.com")


def check_bedrock_endpoint(cfg: AiConfig, resolve: Resolver = system_resolve) -> None:
    """The Bedrock endpoint must be the regional runtime host, a Bedrock PrivateLink name for the region, or a name
    that resolves only to private (RFC 1918 / ULA) addresses (a PrivateLink endpoint with a custom private name)."""
    host = cfg.host.lower()
    if cfg.scheme != "https":
        raise EndpointRefused("the Bedrock endpoint must use https")
    if host in bedrock_hosts_allowed(cfg) or re.fullmatch(_VPCE.format(region=re.escape(cfg.region or "")), host):
        return
    if not cfg.endpoint_override:
        raise EndpointRefused("unexpected Bedrock endpoint")
    private = AiConfig(**{**cfg.__dict__, "allow_nonprivate": False})
    try:
        pin_address(private, resolve)
    except EndpointRefused:
        raise EndpointRefused("CBOM_AI_BEDROCK_ENDPOINT_URL is neither a bedrock-runtime host of the region nor a "
                              "private VPC-endpoint address") from None


def _session(cfg: AiConfig) -> Any:
    import boto3  # lazily: the backend imports and runs without boto3 being loaded

    # a named profile makes botocore skip the AWS_* environment keys (deploy/local sets those to MinIO's)
    return boto3.session.Session(region_name=cfg.region, profile_name=cfg.aws_profile)


def credential_method(cfg: AiConfig) -> str | None:
    """Which provider of the standard AWS chain supplies credentials (None: there are none)."""
    creds = _session(cfg).get_credentials()
    return getattr(creds, "method", None) or ("unknown" if creds is not None else None)


def bedrock_egress(cfg: AiConfig, method: str | None) -> list[dict[str, Any]]:
    out = [{"host": cfg.host, "port": cfg.port, "purpose": f"AWS Bedrock Converse ({cfg.region}, {cfg.model})"}]
    for host, port, purpose in _CREDENTIAL_EGRESS.get(method or "", []):
        out.append({"host": host.format(region=cfg.region), "port": port, "purpose": purpose})
    return out


def _bedrock_client(cfg: AiConfig) -> Any:
    key = (cfg.region, cfg.base_url, cfg.honor_proxy, cfg.ca_file, cfg.timeout_s, cfg.aws_profile)
    with _clients_lock:
        client = _clients.get(key)
        if client is not None:
            return client
        from botocore.config import Config  # lazily, as boto3

        config = Config(
            region_name=cfg.region,
            connect_timeout=min(cfg.timeout_s, 10),
            read_timeout=cfg.timeout_s,
            retries={"total_max_attempts": 1, "mode": "standard"},  # one attempt: an error or a redirect is final
            # {} (not None) means "no proxy": botocore reads HTTP(S)_PROXY from the environment only when this is None
            proxies=None if cfg.honor_proxy else {},
        )
        # verify=True ignores AWS_CA_BUNDLE (the egress proxy's CA); None lets botocore read it when proxies are honoured
        verify: Any = cfg.ca_file or (None if cfg.honor_proxy else True)
        client = _session(cfg).client("bedrock-runtime", region_name=cfg.region, endpoint_url=cfg.base_url,
                                      config=config, verify=verify)
        for hook in BEDROCK_CLIENT_HOOKS:
            hook(client)
        _clients[key] = client
        return client


def reset_bedrock_clients() -> None:
    with _clients_lock:
        _clients.clear()


def bedrock_chat(cfg: AiConfig, messages: list[dict[str, str]], resolve: Resolver = system_resolve) -> str:
    """One Converse call (blocking; run it in a thread). Raises EndpointRefused / EndpointError / TimeoutError."""
    from botocore.exceptions import (BotoCoreError, ClientError, ConnectTimeoutError, NoCredentialsError,
                                     ReadTimeoutError)

    check_bedrock_endpoint(cfg, resolve)
    system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
    turns = [{"role": m["role"], "content": [{"text": m["content"]}]} for m in messages if m["role"] != "system"]
    try:
        response = _bedrock_client(cfg).converse(
            modelId=cfg.model, system=[{"text": system}] if system else [], messages=turns,
            inferenceConfig={"maxTokens": cfg.max_tokens, "temperature": 0})
    except (ReadTimeoutError, ConnectTimeoutError):
        raise TimeoutError("Bedrock did not answer in time") from None
    except NoCredentialsError:
        raise EndpointError("no AWS credentials in the standard chain") from None
    except ClientError as exc:
        status = int((exc.response.get("ResponseMetadata") or {}).get("HTTPStatusCode") or 0)
        if 300 <= status < 400:
            raise EndpointRefused("Bedrock endpoint answered with a redirect; redirects are refused") from None
        code = (exc.response.get("Error") or {}).get("Code") or "error"
        raise EndpointError(f"Bedrock {code} (HTTP {status})") from None
    except BotoCoreError as exc:
        raise EndpointError(f"Bedrock {exc.__class__.__name__}") from None
    try:
        blocks = response["output"]["message"]["content"]
    except (KeyError, TypeError):
        raise EndpointError("Bedrock answer has no message") from None
    # reasoning models (gpt-oss) put reasoningContent blocks before the text
    texts = [b["text"] for b in blocks if isinstance(b, dict) and isinstance(b.get("text"), str)]
    if not texts:
        raise EndpointError("Bedrock answer has no text")
    return "\n".join(texts)
