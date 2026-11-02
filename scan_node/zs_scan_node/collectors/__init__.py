"""Dispatch a claimed job to its collector.

Returns ``(status, error)`` where status is the job status posted to the server:
* ``cancelled`` when the server or the operator stopped it,
* ``failure`` when nothing could be collected (bad configuration, missing credential, every target failed),
* ``success`` otherwise (including partial results; per-target outcomes carry the details).
"""
from __future__ import annotations

from zs_scan_node.jobctx import JobContext

SUPPORTED = {
    ("collect", "linux_servers"), ("collect", "windows_servers"), ("collect", "kubernetes"), ("collect", "database"),
    ("collect", "network_range"),
    ("test_connection", "linux_servers"), ("test_connection", "windows_servers"), ("test_connection", "kubernetes"),
    ("test_connection", "database"), ("test_connection", "network_range"),
    ("collect", "key_manager"), ("test_connection", "key_manager"),
    ("collect", "ca_connector"), ("test_connection", "ca_connector"),
}
CAPABILITIES = ["linux_ssh", "windows_winrm", "kubernetes", "postgres", "mysql", "redis", "mongodb", "network_tls",
                "starttls", "ssh_kexinit", "rdp", "tds_prelogin", "discovery", "pq_hybrid_probe",
                "mssql", "oracle", "pkcs11", "kmip", "vault_pki", "ejbca", "adcs"]


class ConfigError(Exception):
    """The job cannot run as configured (safe to show)."""


def run_job(ctx: JobContext, job: dict, scope: dict, source: dict | None) -> tuple[str, str | None, str | None]:
    """(status, error, summary)"""
    kind = job.get("kind")
    source_kind = (source or {}).get("kind")
    config = (source or {}).get("config") or {}
    secrets = (source or {}).get("secrets") or {}
    summary = None
    try:
        if kind == "discovery":
            from zs_scan_node.collectors.network import run_network

            summary = run_network(ctx, scope, discovery_only=True)
        elif (kind, source_kind) not in SUPPORTED:
            return "failure", f"{source_kind or kind} is not supported by this scan node version", None
        elif source_kind == "linux_servers":
            from zs_scan_node.collectors import linux_ssh

            summary = (linux_ssh.test if kind == "test_connection" else linux_ssh.collect)(ctx, config, secrets, scope)
        elif source_kind == "windows_servers":
            from zs_scan_node.collectors import windows_winrm

            summary = (windows_winrm.test if kind == "test_connection" else windows_winrm.collect)(ctx, config, secrets,
                                                                                                    scope)
        elif source_kind == "kubernetes":
            from zs_scan_node.collectors import kubernetes

            summary = (kubernetes.test if kind == "test_connection" else kubernetes.collect)(ctx, config, secrets, scope)
        elif source_kind == "database":
            from zs_scan_node.collectors import database

            summary = (database.test if kind == "test_connection" else database.collect)(ctx, config, secrets, scope)
        elif source_kind == "key_manager":
            from zs_scan_node.collectors import hsm_pkcs11, kmip

            module = kmip if config.get("provider") == "kmip" else hsm_pkcs11
            summary = (module.test if kind == "test_connection" else module.collect)(ctx, config, secrets, scope)
        elif source_kind == "ca_connector":
            from zs_scan_node.collectors import ca

            summary = (ca.test if kind == "test_connection" else ca.collect)(ctx, config, secrets, scope)
        elif source_kind == "network_range":
            from zs_scan_node.collectors import network

            if kind == "test_connection":
                summary = network.test_range(ctx, scope)
            else:
                summary = network.run_network(ctx, scope)
    except ConfigError as exc:
        return "failure", str(exc), None
    if ctx.cancel.is_set():
        return "cancelled", ctx.cancel_reason or "Stopped by ZeroShield", summary
    if kind != "test_connection":
        counted = [o for o in ctx.outcomes if o.counted]
        ok = sum(1 for o in counted if o.status == "ok")
        failed = sum(1 for o in counted if o.status != "ok" and not o.status.startswith("skipped_"))
        if ok == 0 and failed > 0:
            first = next(o for o in counted if o.status != "ok" and not o.status.startswith("skipped_"))
            return "failure", f"Nothing collected: {first.target}: {first.status}" + (f" ({first.error})" if first.error else ""), summary
    return "success", None, summary
