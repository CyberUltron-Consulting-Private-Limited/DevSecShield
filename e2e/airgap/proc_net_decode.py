#!/usr/bin/env python3
"""Decode backend /proc/net/tcp{,6} and reject an outbound peer that is not allowed.

Allowed peers (task 0.6): loopback, postgres, mongo, RabbitMQ, the object store.
Runs on the host. Stdlib only. Does not import product code.
"""

from __future__ import annotations

import ipaddress
import struct
import subprocess
import sys

BACKEND = "dss-e2e-backend"
PEERS = (
    "dss-e2e-postgres",
    "dss-e2e-mongo",
    "dss-e2e-rabbitmq",
    "dss-e2e-object-store",
)
LISTEN = "0A"


def decode_addr(hex_addr: str) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, int]:
    host_hex, port_hex = hex_addr.split(":")
    raw = bytes.fromhex(host_hex)
    if len(raw) == 4:
        address: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.IPv4Address(
            struct.pack("<I", struct.unpack(">I", raw)[0])
        )
    else:
        words = [struct.pack("<I", struct.unpack(">I", raw[i : i + 4])[0]) for i in range(0, 16, 4)]
        parsed = ipaddress.IPv6Address(b"".join(words))
        address = parsed.ipv4_mapped if parsed.ipv4_mapped is not None else parsed
    return address, int(port_hex, 16)


def container_ips(name: str) -> list[str]:
    proc = subprocess.run(
        ["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", name],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return []
    return [ip for ip in proc.stdout.split() if ip]


def read_table(table: str) -> str:
    proc = subprocess.run(
        ["docker", "exec", BACKEND, "cat", f"/proc/net/{table}"],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        if table == "tcp6":
            return ""
        sys.exit(f"could not read /proc/net/{table}: {proc.stderr.strip()}")
    return proc.stdout


def main() -> int:
    allowed = {ipaddress.ip_address(ip) for name in PEERS for ip in container_ips(name)}
    print("allowed peer addresses:", " ".join(sorted(str(ip) for ip in allowed)) or "none")
    if not allowed:
        print("FAIL no peer addresses resolved")
        return 1
    violations: list[str] = []
    for table in ("tcp", "tcp6"):
        text = read_table(table)
        listening: set[int] = set()
        rows = []
        for line in text.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            local_ip, local_port = decode_addr(parts[1])
            remote_ip, remote_port = decode_addr(parts[2])
            state = parts[3].upper()
            rows.append((local_ip, local_port, remote_ip, remote_port, state))
            if state == LISTEN:
                listening.add(local_port)
        print(f"--- /proc/net/{table} ---")
        for local_ip, local_port, remote_ip, remote_port, state in rows:
            local = f"{local_ip}:{local_port}"
            remote = f"{remote_ip}:{remote_port}"
            if state == LISTEN or local_port in listening:
                kind = "listen-or-inbound"
            elif remote_ip.is_loopback or remote_ip in allowed:
                kind = "outbound-allowed"
            else:
                kind = "OUTBOUND-VIOLATION"
                violations.append(remote)
            print(f"{local:<28}{remote:<28}{state:<6}{kind}")
    if violations:
        print("FAIL", violations)
        return 1
    print("OK no disallowed outbound peer")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
