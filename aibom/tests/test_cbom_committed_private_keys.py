"""A private key committed to the repository (a PEM / OpenSSH key file, or a PEM block inside source) is a finding:
HARDCODED_KEY at the engine's severity for hardcoded keys (High), like a key shipped inside an artifact or held in a
Kubernetes Secret.  Exceptions: test fixtures (the engine's non-production path rule: tests/, fixtures/, examples/
...) stay inventory; public keys and certificates stay clean; an encrypted private key is Medium, and says so."""

from __future__ import annotations

import base64
import os
import sys
from pathlib import Path

from aibom.cbom.normalize import normalize_crypto
from aibom.cbom.pipeline import scan_crypto

sys.path.insert(0, str(Path(__file__).resolve().parent))
from support.artifacts import fake_rsa_der, pem  # noqa: E402

_FX = Path(__file__).resolve().parent / "fixtures"


def _openssh(cipher: bytes) -> bytes:
    blob = b"openssh-key-v1\x00" + len(cipher).to_bytes(4, "big") + cipher + os.urandom(64)
    b64 = base64.b64encode(blob).decode()
    body = "\n".join(b64[i:i + 70] for i in range(0, len(b64), 70))
    return f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n".encode()


def _legacy_encrypted() -> bytes:
    b64 = base64.b64encode(os.urandom(608)).decode()
    body = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return ("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00112233445566778899AABBCC"
            f"DDEEFF\n\n{body}\n-----END RSA PRIVATE KEY-----\n").encode()


def _rows(root: Path) -> dict[str, dict]:
    run = normalize_crypto(scan_crypto(root), duration_of_scan=0.0)
    return {r["location"]: r for r in run["results"] if r.get("asset_type") == "related-crypto-material"}


def test_committed_private_keys_are_findings(tmp_path: Path) -> None:
    files = {
        "secrets/server.key": pem("RSA PRIVATE KEY", fake_rsa_der(1024)),
        "deploy/tls/app.key": pem("EC PRIVATE KEY", os.urandom(121)),
        "config/id_ed25519": _openssh(b"none"),
        "certs/pkcs8.pem": (_FX / "synthetic-crypto-certs-harden" / "server.key").read_bytes(),
        "keys/legacy.pem": _legacy_encrypted(),
        "keys/pkcs8-enc.pem": pem("ENCRYPTED PRIVATE KEY", os.urandom(1200)),
        "keys/ssh/id_rsa": _openssh(b"aes256-ctr"),
        "test/fixtures/dummy.key": pem("RSA PRIVATE KEY", fake_rsa_der(1024)),
        "examples/demo.key": pem("PRIVATE KEY", os.urandom(1200)),
        "keys/public.pem": pem("PUBLIC KEY", os.urandom(294)),
    }
    for rel, data in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_bytes(data)
    rows = _rows(tmp_path)
    for rel in ("secrets/server.key", "deploy/tls/app.key", "config/id_ed25519", "certs/pkcs8.pem"):
        assert rows[rel]["finding_codes"] == ["HARDCODED_KEY"], rel
        assert rows[rel]["impact"] == "High", rel
        assert "committed to the repository" in rows[rel]["description"], rel
    for rel in ("keys/legacy.pem", "keys/pkcs8-enc.pem", "keys/ssh/id_rsa"):
        assert rows[rel]["finding_codes"] == ["HARDCODED_KEY"], rel
        assert rows[rel]["impact"] == "Medium", rel
        assert "encrypted" in rows[rel]["description"].lower(), rel
    for rel in ("test/fixtures/dummy.key", "examples/demo.key", "keys/public.pem"):
        assert rows[rel]["finding_codes"] == [], rel  # fixtures and public keys stay inventory


def test_a_private_key_block_inside_source_keeps_its_inventory_treatment() -> None:
    """Scope: key FILES.  A PEM block pasted into source is still inventory, as the frozen app's oracle pins
    (an open decision, reported)."""
    run = normalize_crypto(scan_crypto(_FX / "synthetic-crypto-app"), duration_of_scan=0.0)
    keys = [r for r in run["results"] if r["location"] == "crypto_app.py" and r["title"].startswith("private-key")]
    assert keys and keys[0]["finding_codes"] == []
