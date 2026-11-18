"""Fetch a source's credential from the customer's vault, inside the customer network.

A source's ``vault.path`` is typed by a ZeroShield user, while the vault token / IAM role belongs to the node.
Without a guard any team member could point the node at any secret it can read and send it to a host they
control.  So vault use is OFF unless the node operator sets ``ZS_VAULT_PATH_PREFIX``; only paths under that
prefix are read, and ``..``/empty segments are refused.
"""
from __future__ import annotations

import json
import os
import re
from urllib.parse import urlsplit

from zs_scan_node.collectors import ConfigError

_SEGMENT = re.compile(r"^[A-Za-z0-9._@=+\-]{1,128}$")


def _segments(path: str) -> list[str]:
    parts = path.strip().strip("/").split("/")
    if not parts or any(p in ("", ".", "..") or not _SEGMENT.match(p) for p in parts):
        raise ConfigError("vault path has an empty, '.' or '..' segment or characters that are not allowed")
    return parts


# #364: what this scan node version can read. CyberArk and Azure Key Vault are offered by ZeroShield as "not available
# yet": no reader exists here, so a source that names them can never collect.
PROVIDERS = ("hashicorp", "aws_secrets_manager")
LABELS = {"hashicorp": "HashiCorp Vault", "aws_secrets_manager": "AWS Secrets Manager", "cyberark": "CyberArk",
          "azure_key_vault": "Azure Key Vault"}
CA_ENV = ("ZS_VAULT_CA_FILE", "VAULT_CACERT")  # a PEM file: ours first, then Vault's own variable
CA_HINT = "set ZS_VAULT_CA_FILE to the CA certificate that issued it"


def _logical(parts: list[str], provider: str) -> list[str]:
    """KV v2's API path ``mount/data/...`` is the same secret as ``mount/...`` (#365: for the prefix as for the path).
    HashiCorp only: an AWS Secrets Manager name is read as written."""
    if provider != "hashicorp":
        return parts
    return [p for i, p in enumerate(parts) if not (i == 1 and p == "data")]


def normalised_prefix(prefix: str | None, provider: str = "hashicorp") -> str | None:
    """The prefix as the node compares it (``secret/data/cbom`` -> ``secret/cbom``), or None when vault use is off or
    the prefix is malformed."""
    if not prefix:
        return None
    try:
        return "/".join(_logical(_segments(prefix), provider))
    except ConfigError:
        return None


def check_prefix(path: str, prefix: str | None, provider: str = "hashicorp") -> list[str]:
    if not prefix:
        raise ConfigError("vault credentials are disabled on this scan node (set ZS_VAULT_PATH_PREFIX to allow a path prefix)")
    logical = _logical(_segments(path), provider)
    want = _logical(_segments(prefix), provider)
    if logical[: len(want)] != want:
        shown = "/".join(want)
        both = f"{shown}/... or {want[0]}/data/{'/'.join(want[1:])}/..." if provider == "hashicorp" and len(want) > 1 \
            else f"{shown}/..."
        raise ConfigError(f"vault path is outside the prefix this scan node allows ({both})")
    return logical


def _vault_verify():
    """#365: the trust for the Vault connection only: ZS_VAULT_CA_FILE (or VAULT_CACERT) a PEM file, VAULT_CAPATH a
    hashed directory; else the default trust.  The ZeroShield API and the targets are not affected."""
    import ssl

    for name in CA_ENV:
        path = os.environ.get(name, "").strip()
        if path:
            try:
                return ssl.create_default_context(cafile=path)
            except (OSError, ssl.SSLError) as exc:
                reason = getattr(exc, "strerror", None) or "not a PEM certificate"
                raise ConfigError(f"{name} cannot be read ({reason}); it must name the Vault's CA certificate "
                                  "(PEM)") from None
    capath = os.environ.get("VAULT_CAPATH", "").strip()
    if capath:
        try:
            return ssl.create_default_context(capath=capath)
        except (OSError, ssl.SSLError):
            raise ConfigError("VAULT_CAPATH cannot be read; it must name a directory of hashed CA certificates") from None
    return True


def setup_status(provider: str) -> str:
    """#364: whether this node is set up for ``provider``, for the heartbeat ("ready" or what is missing). Never a
    value: only whether variables are set and files readable."""
    if provider == "hashicorp":
        if not os.environ.get("VAULT_ADDR", "").strip() or not os.environ.get("VAULT_TOKEN", "").strip():
            return "VAULT_ADDR and VAULT_TOKEN are not set on this scan node"
        try:
            _vault_verify()
        except ConfigError as exc:
            return str(exc)
        return "ready"
    if provider == "aws_secrets_manager":
        return "ready"  # the node's own AWS credentials (IAM role); checked by the read itself
    return f"{LABELS.get(provider, provider)} is not available yet on scan nodes"


def capabilities(prefix: str | None) -> dict:
    """What the heartbeat says about vaults (#364): the providers this version reads, the prefix as compared, and
    per provider whether the node is set up.  ``vault`` (bool) is kept as older servers read it."""
    return {"vault": bool(prefix), "vault_providers": list(PROVIDERS), "vault_prefix": normalised_prefix(prefix),
            "vault_setup": {p: setup_status(p) for p in PROVIDERS} if prefix else {}}


def fetch(provider: str, path: str, prefix: str | None, timeout: float = 10.0) -> dict[str, str]:
    if provider not in PROVIDERS:
        raise ConfigError(f"{LABELS.get(provider, provider)} is not available yet on scan nodes: use HashiCorp Vault or "
                          "AWS Secrets Manager for this credential")
    logical = check_prefix(path, prefix, provider)
    if provider == "hashicorp":
        import httpx

        from zs_scan_node import errtext

        addr = os.environ.get("VAULT_ADDR", "").rstrip("/")
        token = os.environ.get("VAULT_TOKEN", "")
        if not addr or not token:
            raise ConfigError("VAULT_ADDR and VAULT_TOKEN are not set on this scan node")
        url = f"{addr}/v1/{logical[0]}/data/{'/'.join(logical[1:])}"
        try:
            r = httpx.get(url, headers={"X-Vault-Token": token}, timeout=timeout, follow_redirects=False,
                          verify=_vault_verify())
        except httpx.HTTPError as exc:
            verify = errtext.tls_verify_problem(exc)
            if verify:
                raise ConfigError(f"the Vault server certificate is not trusted ({verify}): {CA_HINT}") from None
            raise ConfigError(f"vault not reachable: {errtext.socket_problem(exc, urlsplit(addr).hostname or addr, urlsplit(addr).port)[1]}") from None
        if r.status_code in (403, 404):
            raise ConfigError(f"vault refused the secret ({r.status_code})")
        if r.status_code != 200:
            raise ConfigError(f"vault answered {r.status_code}")
        data = ((r.json() or {}).get("data") or {}).get("data") or {}
        return {str(k): str(v) for k, v in data.items() if isinstance(v, (str, int))}
    if provider == "aws_secrets_manager":
        import boto3
        from botocore.config import Config

        name = "/".join(logical)
        client = boto3.client("secretsmanager", config=Config(connect_timeout=5, read_timeout=timeout,
                                                              retries={"max_attempts": 2}))
        try:
            value = client.get_secret_value(SecretId=name).get("SecretString") or ""
        except Exception as exc:
            raise ConfigError(f"AWS Secrets Manager refused the secret ({exc.__class__.__name__})") from None
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return {str(k): str(v) for k, v in parsed.items()}
        except ValueError:
            pass
        return {"password": value}
    raise ConfigError(f"{LABELS.get(provider, provider)} is not available yet on scan nodes")
