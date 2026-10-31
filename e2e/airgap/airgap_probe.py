#!/usr/bin/env python3
"""Fail if a public TCP connect or a public DNS lookup succeeds.

Stdlib only. Used inside the backend container and inside aibom-scan
(network_mode: none). Exit 0 when every attempt fails.
"""

from __future__ import annotations

import socket

ATTEMPTS = (
    ("tcp4", "1.1.1.1", 443, socket.AF_INET),
    ("tcp6", "2606:4700:4700::1111", 443, socket.AF_INET6),
)


def main() -> int:
    leaked = False
    for kind, host, port, family in ATTEMPTS:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            sock.connect((host, port))
        except OSError as exc:
            print(f"{kind} {host}:{port} FAILED {type(exc).__name__}: {exc}", flush=True)
        else:
            print(f"{kind} {host}:{port} SUCCEEDED", flush=True)
            leaked = True
        finally:
            sock.close()
    try:
        socket.getaddrinfo("example.com", 443)
    except OSError as exc:
        print(f"dns example.com FAILED {type(exc).__name__}: {exc}", flush=True)
    else:
        print("dns example.com SUCCEEDED", flush=True)
        leaked = True
    return 1 if leaked else 0


if __name__ == "__main__":
    raise SystemExit(main())
