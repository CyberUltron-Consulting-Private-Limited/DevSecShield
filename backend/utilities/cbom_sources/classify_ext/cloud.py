"""Cloud collector asset types (WP4): AWS Glue Data Catalog and connections, Azure Key Vault.

Finding codes are documented in scripts/crypto_kb/kb_ext/cloud.py.
"""
from __future__ import annotations

from typing import Any

from backend.utilities.cbom_sources import classify


def _glue_catalog(out, facts: dict[str, Any], _algorithm, _key_size, _now) -> bool | None:
    if str(facts.get("catalog_encryption_mode") or "").upper() == "DISABLED":
        out.add("GLUE_CATALOG_UNENCRYPTED", "Medium",
                "Glue Data Catalog metadata (table definitions and connection properties) is not encrypted with a KMS key")
    return None


def _glue_connection(out, facts: dict[str, Any], _algorithm, _key_size, _now) -> bool | None:
    if facts.get("password_storage") == "plaintext":
        out.add("GLUE_PLAINTEXT_PASSWORD", "High",
                "Glue connection stores its database password in the Data Catalog without encryption; anyone allowed "
                "glue:GetConnection can read it")
    kind = str(facts.get("connection_type") or "").upper()
    if (kind == "JDBC" or facts.get("jdbc_url")) and facts.get("jdbc_enforce_ssl") is not True \
            and facts.get("jdbc_url_requests_tls") is not True:
        out.add("GLUE_JDBC_NO_TLS", "Medium",
                "Glue JDBC connection does not enforce TLS (JDBC_ENFORCE_SSL is not true and the URL does not require it)")
    if kind == "KAFKA" and facts.get("kafka_ssl_enabled") is False:
        out.add("NO_TLS", "High", "Glue Kafka connection does not use TLS (KAFKA_SSL_ENABLED is false)")
    return None


def _key_vault(out, facts: dict[str, Any], _algorithm, _key_size, _now) -> bool | None:
    if facts.get("soft_delete_enabled") is False:
        out.add("KV_SOFT_DELETE_OFF", "High", "Key Vault soft delete is off: a deleted key is gone immediately")
    elif facts.get("purge_protection") is not True:
        out.add("KV_NO_PURGE_PROTECTION", "Medium",
                "Key Vault purge protection is off: a deleted key can be purged before its retention period ends")
    if facts.get("internet_facing") is True:
        out.add("KV_PUBLIC_NETWORK", "Low", "Key Vault accepts requests from any network (public access, no firewall rule)")
    return None


classify.register("glue_catalog", _glue_catalog, "other")
classify.register("glue_connection", _glue_connection, "protocol")
classify.register("key_vault", _key_vault, "other")
