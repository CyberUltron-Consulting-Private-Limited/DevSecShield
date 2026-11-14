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
SUPPORTED |= {("collect", "appliance"), ("test_connection", "appliance")}
SUPPORTED |= {("collect", "container_images"), ("test_connection", "container_images")}
# F1.3: agentless fleets through the customer's AWX/AAP or salt-api (collectors/fleet.py)
SUPPORTED |= {("collect", "awx_hosts"), ("test_connection", "awx_hosts"), ("collect", "salt_hosts"),
              ("test_connection", "salt_hosts")}
# Agent mode (ZS_MODE=agent) runs only these: the node's own host, read from read-only mounts, no credentials.
AGENT_SUPPORTED = {("collect", "host_agent"), ("test_connection", "host_agent")}
CAPABILITIES = ["linux_ssh", "windows_winrm", "kubernetes", "postgres", "mysql", "redis", "mongodb", "network_tls",
                "starttls", "ssh_kexinit", "rdp", "tds_prelogin", "discovery", "pq_hybrid_probe",
                "mssql", "oracle", "pkcs11", "kmip", "vault_pki", "ejbca", "adcs"]
CAPABILITIES += ["ike", "ike_pq_probe", "opcua", "modbus", "appliance_config", "mesh_istio_linkerd"]
CAPABILITIES += ["registry_v2"]
CAPABILITIES += ["transport_awx", "transport_salt", "zs_collect"]
CAPABILITIES += ["ssh_ca"]  # F1.4: credential_type ssh_ca (node key + short-lived certificate from the SSH CA)
AGENT_CAPABILITIES = ["host_agent"]


class ConfigError(Exception):
    """The job cannot run as configured (safe to show)."""


def skipped_never_scan(ctx: JobContext, skipped: list[str], reasons: dict[str, str], samples: bool = False) -> None:
    """Record each target the never-scan list skipped (netutil.expand_targets): an outcome with the reason, and in a
    connection test also a sample, so a skipped target does not silently vanish from the test."""
    for label in skipped:
        why = reasons.get(label) or f"{label} is on the never-scan list"
        ctx.outcome(label, "skipped_never_scan", why)
        if samples:
            ctx.samples.append({"target": label, "status": "skipped_never_scan", "reachable": None, "login": None,
                                "privilege": None, "note": why})


def run_job(ctx: JobContext, job: dict, scope: dict, source: dict | None) -> tuple[str, str | None, str | None]:
    """(status, error, summary)"""
    kind = job.get("kind")
    source_kind = (source or {}).get("kind")
    config = (source or {}).get("config") or {}
    secrets = (source or {}).get("secrets") or {}
    summary = None
    if ctx.agent_mode:
        # Defence in depth: ZeroShield never sends an agent node other work or credentials; refuse it if it does.
        if (kind, source_kind) not in AGENT_SUPPORTED:
            return "failure", ("This scan node runs in agent mode (ZS_MODE=agent): it collects only its own host and "
                               f"does not run {source_kind or kind} jobs"), None
        if any(secrets.values()) if isinstance(secrets, dict) else bool(secrets):
            return "failure", "An agent-mode scan node refused a job that carries credentials", None
    elif source_kind == "host_agent":
        return "failure", "Host agent sources need a scan node started with ZS_MODE=agent", None
    try:
        if kind == "discovery":
            from zs_scan_node.collectors.network import run_network

            summary = run_network(ctx, scope, discovery_only=True)
        elif source_kind == "host_agent":
            from zs_scan_node.collectors import host_agent

            summary = (host_agent.test if kind == "test_connection" else host_agent.collect)(ctx, config, secrets, scope)
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
        elif source_kind == "container_images":
            from zs_scan_node.collectors import container_images

            summary = (container_images.test if kind == "test_connection" else container_images.collect)(
                ctx, config, secrets, scope)
        elif source_kind == "appliance":
            from zs_scan_node.collectors import appliance

            summary = (appliance.test if kind == "test_connection" else appliance.collect)(ctx, config, secrets, scope)
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
        elif source_kind in ("awx_hosts", "salt_hosts"):
            from zs_scan_node.collectors import fleet

            summary = (fleet.test if kind == "test_connection" else fleet.collect)(ctx, config, secrets, scope)
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
