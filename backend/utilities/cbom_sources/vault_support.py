"""Which vaults a scan node reads, and what its operator sets for each (#364, #365).

The scan node reads HashiCorp Vault (KV v2) and AWS Secrets Manager (``scan_node/zs_scan_node/vault.py``).  CyberArk
and Azure Key Vault are offered as "not available yet": listed so a customer sees they are planned, refused when a
credential is saved or imported, and still parsed so a source stored with one can be edited to another vault.

At heartbeat a node reports ``vault`` (on when ``ZS_VAULT_PATH_PREFIX`` is set), ``vault_providers``, ``vault_prefix``
(written without the KV v2 ``data/`` segment) and ``vault_setup`` (``"ready"`` or what is missing, per provider; never
a token).  ``node_problem`` checks an import row against that report.  A node that has not reported it (older node,
never connected) is not blocked: it still refuses at collection with its own message.
"""
from __future__ import annotations

from typing import Any

AVAILABLE = ("hashicorp", "aws_secrets_manager")
LABELS = {"hashicorp": "HashiCorp Vault", "aws_secrets_manager": "AWS Secrets Manager", "cyberark": "CyberArk",
          "azure_key_vault": "Azure Key Vault"}
PREFIX_ENV = "ZS_VAULT_PATH_PREFIX"
# what the node's operator sets, per provider (env on the scan node: scan_node/README.md "Vault credentials")
NODE_SETTINGS: dict[str, list[dict[str, str]]] = {
    "hashicorp": [
        {"name": PREFIX_ENV, "what": "the path prefix this node may read, e.g. secret/cbom (secret/data/cbom works too)"},
        {"name": "VAULT_ADDR", "what": "the Vault address, e.g. https://vault.bank.local:8200"},
        {"name": "VAULT_TOKEN", "what": "a token whose policy can read <prefix>/* (KV v2: secret/data/cbom/*)"},
        {"name": "ZS_VAULT_CA_FILE", "what": "the CA certificate that issued Vault's TLS certificate, if it is private"},
    ],
    "aws_secrets_manager": [
        {"name": PREFIX_ENV, "what": "the secret-name prefix this node may read, e.g. cbom"},
        {"name": "AWS role", "what": "the node's IAM role (or AWS_* credentials) allows secretsmanager:GetSecretValue "
                                     "on those secrets; AWS_REGION names the region"},
    ],
}


def label(provider: str) -> str:
    return LABELS.get(provider, provider)


def provider_list() -> list[dict[str, Any]]:
    """Every vault the forms offer, in order, with whether a scan node reads it and what to set on the node."""
    return [{"value": p, "label": LABELS[p], "available": p in AVAILABLE, "node_settings": NODE_SETTINGS.get(p, [])}
            for p in LABELS]


def unavailable_problem(provider: str | None) -> str | None:
    if not provider or provider in AVAILABLE:
        return None
    return (f"{label(provider)} is not available yet: no scan node version reads it; use HashiCorp Vault or AWS "
            "Secrets Manager")


def _vault_of(cfg: Any) -> dict[str, Any] | None:
    vault = cfg.get("vault") if isinstance(cfg, dict) else getattr(cfg, "vault", None)
    if vault is None:
        return None
    return vault if isinstance(vault, dict) else vault.model_dump(mode="json")


def config_problem(cfg: Any) -> str | None:
    """"vault: <why>" when a config reads its credential from a vault no scan node reads, else None."""
    vault = _vault_of(cfg)
    problem = unavailable_problem((vault or {}).get("provider"))
    return f"vault: {problem}" if problem else None


def _logical(path: str, provider: str) -> list[str]:
    parts = [p for p in path.strip().strip("/").split("/") if p]
    if provider == "hashicorp" and len(parts) >= 2 and parts[1] == "data":
        parts = parts[:1] + parts[2:]  # KV v2 API form: secret/data/cbom == secret/cbom
    return parts


def _forms(prefix: str) -> str:
    parts = prefix.split("/")
    data = "/".join(parts[:1] + ["data"] + parts[1:])
    return f"{prefix}/... or {data}/..."


def node_vault(capabilities: dict[str, Any] | None) -> dict[str, Any]:
    """The node's reported vault support for the node list: enabled is None when it has not reported."""
    caps = capabilities or {}
    return {"enabled": caps.get("vault") if isinstance(caps.get("vault"), bool) else None,
            "providers": caps.get("vault_providers"), "prefix": caps.get("vault_prefix"),
            "setup": caps.get("vault_setup") or {}}


def node_problem(node: Any, provider: str, path: str) -> str | None:
    """Why ``node`` cannot read ``provider`` at ``path`` by what it reported at heartbeat, or None (also when it has
    not reported)."""
    if node is None:
        return None
    caps = node.capabilities or {}
    name = node.name
    if caps.get("vault") is False:
        return (f"vault: scan node {name} has vault use off: its operator sets {PREFIX_ENV} (and, for HashiCorp "
                "Vault, VAULT_ADDR and VAULT_TOKEN) on the node")
    providers = caps.get("vault_providers")
    if isinstance(providers, list) and provider not in providers:
        return f"vault: scan node {name} cannot read {label(provider)} (update the node to a version that does)"
    prefix = caps.get("vault_prefix")
    if provider == "hashicorp" and isinstance(prefix, str) and prefix.strip("/"):
        want = _logical(prefix, provider)
        if _logical(path, provider)[:len(want)] != want or len(_logical(path, provider)) <= len(want):
            return f"vault: the path is outside the prefix scan node {name} allows ({_forms('/'.join(want))})"
    setup = (caps.get("vault_setup") or {}).get(provider)
    if isinstance(setup, str) and setup != "ready":
        return f"vault: scan node {name} is not set up for {label(provider)}: {setup}"
    return None
