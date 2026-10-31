"""Sign and verify crypto knowledge-base update bundles (Ed25519). Runs offline.

  python sign.py keygen  <private.pem>            # prints the base64 public key for CBOM_KB_PUBKEYS
  python sign.py sign    <private.pem> <kb.json>  # writes <kb.json>.sig (base64 signature of the exact bytes)
  python sign.py verify  <kb.json> <pubkey-b64> [<sig>]

Keep the private key off the scanning servers; ship only the public key in CBOM_KB_PUBKEYS.
"""
from __future__ import annotations

import base64
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def _pub_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[0] == "keygen":
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
        fd = os.open(argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)
        print(_pub_b64(key))
        return 0
    if len(argv) == 3 and argv[0] == "sign":
        with open(argv[1], "rb") as fh:
            key = serialization.load_pem_private_key(fh.read(), password=None)
        with open(argv[2], "rb") as fh:
            sig = key.sign(fh.read())
        with open(argv[2] + ".sig", "w") as fh:
            fh.write(base64.b64encode(sig).decode() + "\n")
        print(f"wrote {argv[2]}.sig; public key {_pub_b64(key)}")
        return 0
    if len(argv) in (3, 4) and argv[0] == "verify":
        sig_path = argv[3] if len(argv) == 4 else argv[1] + ".sig"
        with open(argv[1], "rb") as fh, open(sig_path) as sh:
            data, sig = fh.read(), base64.b64decode(sh.read().strip())
        Ed25519PublicKey.from_public_bytes(base64.b64decode(argv[2])).verify(sig, data)
        print("signature OK")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
