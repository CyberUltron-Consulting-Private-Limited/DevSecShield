"""Shared helpers for the F1.1 node-API bench: deterministic node credentials, request signing, percentiles.

Node keys and tokens are derived from a per-seed secret (``creds.json``, written by ``seed.py`` next to the database
it seeded, never committed), so the seeder and the simulator agree without storing 10,000 private keys.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import secrets
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def node_seed(secret: str, i: int) -> bytes:
    return hashlib.sha256(f"f1-bench-node|{secret}|{i}".encode()).digest()


def node_token(secret: str, i: int) -> str:
    return "zsn_" + hashlib.sha256(f"f1-bench-token|{secret}|{i}".encode()).hexdigest()[:40]


def node_key(secret: str, i: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(node_seed(secret, i))


def public_b64(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes_raw()).decode()


def signing_message(method: str, path: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    """Same bytes as backend/utilities/cbom_sources/node_auth.py and scan_node/zs_scan_node/api.py."""
    return "\n".join((method.upper(), path, timestamp, nonce, hashlib.sha256(body).hexdigest())).encode()


class Signer:
    """Signs like a scan node: protocol 1 = random nonces (scan node 1.0), protocol 2 = sequence nonces."""

    def __init__(self, key: Ed25519PrivateKey, protocol: int) -> None:
        self.key, self.protocol = key, protocol
        self.base = (time.time_ns() // 1000) << 11  # as scan_node/zs_scan_node/api.py
        self.counter = 0

    def nonce(self) -> str:
        if self.protocol >= 2:
            self.counter += 1
            return f"s2_{self.base + self.counter:019d}"
        return secrets.token_urlsafe(18)

    def headers(self, method: str, path: str, body: bytes) -> dict[str, str]:
        ts = str(int(time.time()))
        nonce = self.nonce()
        sig = self.key.sign(signing_message(method, path, ts, nonce, body))
        return {"X-ZS-Timestamp": ts, "X-ZS-Nonce": nonce, "X-ZS-Signature": base64.b64encode(sig).decode()}


def dumps(body) -> bytes:
    return json.dumps(body, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def percentile(sorted_values: list[float], p: float) -> float | None:
    if not sorted_values:
        return None
    k = (len(sorted_values) - 1) * p / 100.0
    lo, hi = math.floor(k), math.ceil(k)
    if lo == hi:
        return sorted_values[int(k)]
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (k - lo)


def load_creds(path: str | Path) -> dict:
    return json.loads(Path(path).read_text())
