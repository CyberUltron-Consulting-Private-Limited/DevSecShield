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

from zs_scan_node.collectors import ConfigError

_SEGMENT = re.compile(r"^[A-Za-z0-9._@=+\-]{1,128}$")


def _segments(path: str) -> list[str]:
    parts = path.strip().strip("/").split("/")
    if not parts or any(p in ("", ".", "..") or not _SEGMENT.match(p) for p in parts):
        raise ConfigError("vault path has an empty, '.' or '..' segment or characters that are not allowed")
    return parts


def check_prefix(path: str, prefix: str | None) -> list[str]:
    if not prefix:
        raise ConfigError("vault credentials are disabled on this scan node (set ZS_VAULT_PATH_PREFIX to allow a path prefix)")
    parts = _segments(path)
    logical = [p for i, p in enumerate(parts) if not (i == 1 and p == "data")]  # kv v2 "mount/data/..." == "mount/..."
    want = _segments(prefix)
    if logical[: len(want)] != want:
        raise ConfigError(f"vault path is outside the prefix this scan node allows ({'/'.join(want)}/...)")
    return logical


def fetch(provider: str, path: str, prefix: str | None, timeout: float = 10.0) -> dict[str, str]:
    logical = check_prefix(path, prefix)
    if provider == "hashicorp":
        import httpx

        addr = os.environ.get("VAULT_ADDR", "").rstrip("/")
        token = os.environ.get("VAULT_TOKEN", "")
        if not addr or not token:
            raise ConfigError("VAULT_ADDR and VAULT_TOKEN are not set on this scan node")
        url = f"{addr}/v1/{logical[0]}/data/{'/'.join(logical[1:])}"
        try:
            r = httpx.get(url, headers={"X-Vault-Token": token}, timeout=timeout, follow_redirects=False)
        except httpx.HTTPError as exc:
            raise ConfigError(f"vault not reachable ({exc.__class__.__name__})") from None
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
    raise ConfigError(f"{provider} vaults are not supported by this scan node version")
