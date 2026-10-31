#!/usr/bin/env python3
"""Static policy checks on the resolved dss-e2e compose model.

Usage:  docker compose -p dss-e2e -f ... --profile seed config --format json | compose_policy.py

Reads the resolved model on stdin (it may contain the generated secrets when .env.e2e exists, so
it is never echoed) and prints one PASS/FAIL line per rule. Exit status 1 if any rule fails.
Standard library only.
"""

from __future__ import annotations

import json
import sys

EXPECTED_PROJECT = "dss-e2e"
LABEL_KEY = "com.dss-e2e"
EXPECTED_SERVICES = {"postgres", "mongo", "backend", "frontend", "aibom-scan", "seed"}
# (host_ip, published, target): the ONLY host exposure the stack may have.
EXPECTED_PORTS = {("127.0.0.1", "43000", "3000"), ("127.0.0.1", "43080", "8080")}
ALLOWED_THIRD_PARTY_IMAGES = {"postgres:15-alpine", "mongo:8.0.6"}

results: list[tuple[bool, str]] = []


def check(ok: bool, message: str) -> None:
    results.append((bool(ok), message))


def labelled(obj: dict) -> bool:
    labels = obj.get("labels") or {}
    if isinstance(labels, list):  # ["k=v", ...] form
        labels = dict(item.split("=", 1) for item in labels if "=" in item)
    return str(labels.get(LABEL_KEY)) == "1"


def env_keys(service: dict) -> set[str]:
    env = service.get("environment") or {}
    if isinstance(env, list):
        return {item.split("=", 1)[0] for item in env}
    return set(env)


def _airgap() -> bool:
    return "--airgap" in sys.argv[1:]


def main() -> int:
    try:
        cfg = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        print(f"FAIL  compose JSON unreadable: {exc}")
        return 1

    services: dict[str, dict] = cfg.get("services") or {}
    airgap = _airgap()
    expected = set(EXPECTED_SERVICES)
    ports = set(EXPECTED_PORTS)
    images = set(ALLOWED_THIRD_PARTY_IMAGES)
    if airgap:
        expected |= {"rabbitmq", "object-store", "scan-worker", "gateway"}
        images |= {"rabbitmq:3.13-alpine", "minio/minio:RELEASE.2024-10-02T17-50-41Z"}

    check(
        cfg.get("name") == EXPECTED_PROJECT, f"project name is exactly {EXPECTED_PROJECT!r} (got {cfg.get('name')!r})"
    )
    missing = expected - set(services)
    extra = set(services) - expected
    check(not missing, f"all expected services defined (missing: {sorted(missing) or 'none'})")
    check(not extra, f"no unexpected services (extra: {sorted(extra) or 'none'})")

    unlabelled = sorted(name for name, svc in services.items() if not labelled(svc))
    check(not unlabelled, f"every service carries label {LABEL_KEY}=1 (unlabelled: {unlabelled or 'none'})")

    # Host exposure: exactly the two loopback ports, nothing else, databases never published.
    published: set[tuple[str, str, str]] = set()
    for svc in services.values():
        for port in svc.get("ports") or []:
            if isinstance(port, dict):
                published.add(
                    (str(port.get("host_ip", "")), str(port.get("published", "")), str(port.get("target", "")))
                )
            else:
                published.add((str(port), "", ""))
    check(
        published == ports,
        f"published ports are exactly 127.0.0.1:43000->3000 and 127.0.0.1:43080->8080 (got {sorted(published)})",
    )
    for name in ("postgres", "mongo"):
        check(not (services.get(name) or {}).get("ports"), f"{name} publishes no host port")

    # Objects: every volume / network labelled and project-owned (no external = no foreign objects).
    volumes: dict[str, dict] = cfg.get("volumes") or {}
    networks: dict[str, dict] = cfg.get("networks") or {}
    check(
        bool(volumes) and all(labelled(v or {}) for v in volumes.values()),
        f"every named volume carries {LABEL_KEY}=1 ({sorted(volumes)})",
    )
    check(
        bool(networks) and all(labelled(n or {}) for n in networks.values()),
        f"every network carries {LABEL_KEY}=1 ({sorted(networks)})",
    )
    external = sorted(
        [f"volume:{k}" for k, v in volumes.items() if (v or {}).get("external")]
        + [f"network:{k}" for k, n in networks.items() if (n or {}).get("external")]
    )
    check(not external, f"no external (foreign) volumes or networks (found: {external or 'none'})")
    check(
        all(str((v or {}).get("name", "")).startswith("dss-e2e_") for v in volumes.values()),
        "volume names are scoped to the dss-e2e project",
    )
    check(
        all(str((n or {}).get("name", "")).startswith("dss-e2e_") for n in networks.values()),
        "network names are scoped to the dss-e2e project",
    )

    # Images: our own build tags plus the two pinned third-party images, nothing else.
    bad_images = sorted(
        {
            str(svc.get("image"))
            for svc in services.values()
            if not (
                str(svc.get("image", "")).startswith("dss-e2e/") or svc.get("image") in images
            )
        }
    )
    check(not bad_images, f"images are dss-e2e/* or the pinned postgres/mongo (unexpected: {bad_images or 'none'})")
    for name in ("backend", "frontend", "aibom-scan", "seed"):
        svc = services.get(name) or {}
        check(
            svc.get("pull_policy") == "never",
            f"{name} uses pull_policy: never (a missing local image must fail, not pull a stranger's)",
        )

    # Backend overlay mount (rbi/cert-in rollup YAMLs) must be read-only.
    overlay = [
        m
        for m in (services.get("backend") or {}).get("volumes") or []
        if isinstance(m, dict) and m.get("target") == "/aibom/config"
    ]
    check(
        len(overlay) == 1
        and overlay[0].get("read_only") is True
        and str(overlay[0].get("source", "")).endswith("/compose/aibom-config-overlay"),
        "backend mounts compose/aibom-config-overlay at /aibom/config read-only",
    )

    # Hermetic scanner and hardened one-shots.
    scan = services.get("aibom-scan") or {}
    check(scan.get("network_mode") == "none", "aibom-scan runs with network_mode: none")
    check(
        scan.get("read_only") is True and "ALL" in (scan.get("cap_drop") or []),
        "aibom-scan: read-only rootfs and all capabilities dropped",
    )

    # Nothing may escape the sandbox.
    escapes: list[str] = []
    for name, svc in services.items():
        if svc.get("privileged"):
            escapes.append(f"{name}: privileged")
        if svc.get("network_mode") == "host" or svc.get("pid") == "host" or svc.get("ipc") == "host":
            escapes.append(f"{name}: host namespace")
        if svc.get("cap_add"):
            escapes.append(f"{name}: cap_add {svc.get('cap_add')}")
        for mount in svc.get("volumes") or []:
            source = str(mount.get("source", "")) if isinstance(mount, dict) else str(mount)
            if "docker.sock" in source or source == "/":
                escapes.append(f"{name}: mounts {source}")
    check(not escapes, f"no privileged / host-namespace / docker.sock / root-bind escapes (found: {escapes or 'none'})")
    if airgap:
        check(
            (networks.get("default") or {}).get("internal") is True,
            "network default is internal",
        )
        edge = networks.get("edge") or {}
        check(
            bool(edge) and labelled(edge) and edge.get("internal") is not True,
            "edge exists, is labelled, and is not internal",
        )

        def attached(svc: dict) -> set[str]:
            if svc.get("network_mode") in {"none", "host"}:
                return set()
            nets = svc.get("networks")
            if isinstance(nets, list):
                return {str(item) for item in nets}
            if isinstance(nets, dict):
                return {str(item) for item in nets}
            return {"default"}

        holders = sorted(name for name, svc in services.items() if "edge" in attached(svc))
        check(holders == ["gateway"], f"edge is attached to gateway only (got {holders or 'none'})")
        publishers = sorted(name for name, svc in services.items() if svc.get("ports"))
        check(publishers == ["gateway"], f"only gateway publishes host ports (got {publishers or 'none'})")
        for name in ("backend", "frontend", "postgres", "mongo", "rabbitmq", "object-store"):
            check(not (services.get(name) or {}).get("ports"), f"{name} publishes no host port")
        gateway = services.get("gateway") or {}
        check(
            str(gateway.get("image", "")).startswith("dss-e2e/") and gateway.get("pull_policy") == "never",
            "gateway uses a dss-e2e image with pull_policy: never",
        )
        worker = services.get("scan-worker") or {}
        check(worker.get("network_mode") == "none", "scan-worker runs with network_mode: none")

    # Mongo is no-auth by design: MONGO_INITDB_* must never be set on any service, mongo gets no env.
    leaked = sorted(
        f"{name}:{key}" for name, svc in services.items() for key in env_keys(svc) if key.startswith("MONGO_INITDB_")
    )
    check(
        not leaked,
        f"MONGO_INITDB_* is not set anywhere (no-auth mongo on the internal network; found: {leaked or 'none'})",
    )
    mongo = services.get("mongo") or {}
    check(not mongo.get("env_file") and not mongo.get("environment"), "mongo receives no env_file / environment")

    # The backend must start gunicorn through the image entrypoint (alembic first).
    command = (services.get("backend") or {}).get("command") or []
    check(command[:3] == ["uv", "run", "gunicorn"], f"backend command is `uv run gunicorn ...` (got {command[:3]})")

    failed = 0
    for ok, message in results:
        print(f"{'PASS' if ok else 'FAIL'}  {message}")
        failed += 0 if ok else 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
