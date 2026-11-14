#!/usr/bin/env python3
"""CB-13 scale bench: the network collector reading SSH host keys from N endpoints at the default rate limits.

    PYTHONPATH=scan_node python3 bench/cb13_ssh/scale.py [--endpoints 1000] [--out result.json]

Every address of a private /22 "has" one SSH server on port 22.  Connections are redirected (the collector's ``_tcp``
and tlsprobe's ``connect``, so a node before CB-13 can be measured too) to one local stub that speaks the unencrypted
start of SSH-2: banner, KEXINIT offering curve25519 and three host-key families (Ed25519, ECDSA P-256, RSA), and a
key-exchange reply carrying the family's key.  Rate limits are the product defaults (20 connections per second,
2 parallel per server, 12 handshakes per endpoint).  Reported: wall time, connections per address (sweep + SSH), the
largest number of SSH connections any one address saw, the shortest gap between two SSH connections to one address,
and how many endpoints have every host key read.  It also replays OpenSSH's PerSourcePenalties arithmetic (noauth 1 s,
min 15 s; srclimit.c: a source is refused once more than ``min`` seconds of penalty are pending) over each address's
connection times, and reports the largest pending penalty any address reached.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import struct
import threading
import time
from collections import defaultdict

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa


def _str(b: bytes) -> bytes:
    return struct.pack("!I", len(b)) + b


def _packet(payload: bytes) -> bytes:
    pad = 8 - ((5 + len(payload)) % 8)
    pad = pad + 8 if pad < 4 else pad
    return struct.pack("!IB", len(payload) + pad + 1, pad) + payload + b"\x00" * pad


def _blob(key) -> bytes:
    return base64.b64decode(key.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).split()[1])


BLOBS = {"ssh-ed25519": _blob(ed25519.Ed25519PrivateKey.generate().public_key()),
         "ecdsa-sha2-nistp256": _blob(ec.generate_private_key(ec.SECP256R1()).public_key()),
         "ssh-rsa": _blob(rsa.generate_private_key(public_exponent=65537, key_size=3072).public_key())}
HOSTKEYS = ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256"]
KEXINIT = (b"\x14" + os.urandom(16) + _str(b"curve25519-sha256,curve25519-sha256@libssh.org,ext-info-s")
           + _str(",".join(HOSTKEYS).encode()) + _str(b"aes128-ctr") * 2 + _str(b"hmac-sha2-256") * 2
           + _str(b"none") * 2 + _str(b"") * 2 + b"\x00" * 5)


def _recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return buf


def _serve_one(conn):
    try:
        conn.settimeout(10)
        conn.sendall(b"SSH-2.0-BenchSSH_1.0\r\n" + _packet(KEXINIT))
        line = b""
        while not line.endswith(b"\n"):
            ch = conn.recv(1)
            if not ch:
                return
            line += ch
        for _ in range(3):
            plen, pad = struct.unpack("!IB", _recv_exact(conn, 5))
            payload = _recv_exact(conn, plen - 1)[: plen - 1 - pad]
            if payload[0] == 20:
                pos = 17 + 4 + struct.unpack("!I", payload[17:21])[0]
                n = struct.unpack("!I", payload[pos:pos + 4])[0]
                algs = payload[pos + 4:pos + 4 + n].decode().split(",")
                alg = next(a for a in algs if a in HOSTKEYS)
            elif payload[0] == 30:
                fam = "ssh-rsa" if alg.startswith("rsa") else alg
                sig = _str(_str(alg.encode()) + _str(os.urandom(64)))
                conn.sendall(_packet(b"\x1f" + _str(BLOBS[fam]) + _str(os.urandom(32)) + sig))
                return
    except (EOFError, OSError, StopIteration, struct.error):
        return
    finally:
        conn.close()


def stub() -> int:
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(512)

    def loop():
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=_serve_one, args=(conn,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return srv.getsockname()[1]


def pending_penalty(times: list[float], noauth: float = 1.0) -> float:
    """OpenSSH srclimit.c: each unauthenticated connection adds ``noauth`` to the source's pending penalty; an
    expired entry is dropped; the largest pending amount seen (enforced once it exceeds ``min``)."""
    expiry, worst = None, 0.0
    for t in sorted(times):
        if expiry is None or expiry < t:
            expiry = t + noauth
        else:
            expiry += noauth
        worst = max(worst, expiry - t)
    return worst


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--endpoints", type=int, default=1000)
    p.add_argument("--out")
    args = p.parse_args()

    from zs_scan_node import tlsprobe as T
    from zs_scan_node.collectors import network as N
    from zs_scan_node.jobctx import JobContext
    from zs_scan_node.netutil import NeverScan
    from zs_scan_node.scrub import Scrubber

    port = stub()
    times: dict[str, list[float]] = defaultdict(list)
    lock = threading.Lock()

    def tcp(ip, _port, _never, timeout):
        with lock:
            times[ip].append(time.monotonic())
        return socket.create_connection(("127.0.0.1", port), timeout=timeout)

    def connect(ip, _port, timeout=3.0):
        return tcp(ip, _port, None, timeout)

    N._tcp = tcp
    T.connect = connect  # a node before CB-13 opened its SSH connections here
    ips = [f"10.200.{i // 250}.{i % 250 + 1}" for i in range(args.endpoints)]
    ctx = JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind="network_range",
                     scrubber=Scrubber(), never_scan=NeverScan([]), deadline=time.monotonic() + 7200)
    scope = {"ranges": [{"cidr": f"{ip}/32", "mode": "full"} for ip in ips],
             "ports": [{"port": 22, "protocol": "ssh", "label": "ssh"}],
             "rate_limits": {"connections_per_second": 20, "parallel_per_server": 2, "handshakes_per_endpoint": 12}}
    started = time.monotonic()
    N.run_network(ctx, scope)
    wall = time.monotonic() - started
    ctx.flush()
    eps = [a for a in ctx.collected if a["type"] == "ssh_endpoint"]
    complete = sum(1 for a in eps if a["facts"].get("host_keys_status") == "complete"
                   and len(a["facts"].get("host_keys") or []) == 3)
    per_addr = [len(v) for v in times.values()]
    gaps = [b - a for v in times.values() for a, b in zip(sorted(v)[1:], sorted(v)[2:])]  # after the sweep's connect
    result = {"endpoints": args.endpoints, "wall_s": round(wall, 1), "ssh_endpoints": len(eps),
              "all_three_host_keys_read": complete, "connections_total": sum(per_addr),
              "connections_per_address": {"min": min(per_addr), "max": max(per_addr),
                                          "mean": round(sum(per_addr) / len(per_addr), 2)},
              "ssh_connections_per_address_max": max(per_addr) - 1,
              "min_gap_between_ssh_connections_to_one_address_s": round(min(gaps), 3) if gaps else None,
              "max_pending_noauth_penalty_s (OpenSSH min 15 s)": round(max(pending_penalty(v) for v in
                                                                           times.values()), 2),
              "coverage_rows": sum(1 for a in ctx.collected if a["type"] == "coverage"),
              "rate_limits": scope["rate_limits"], "code": N.__file__}
    print(json.dumps(result, indent=1))
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
