"""Persistent node state in ``$ZS_STATE_DIR`` (a Docker volume): node token, ids and the node's SSH key.

Files are created 0600 inside a 0700 directory.  The SSH key is generated once (ed25519) and reused; its public
half is sent at enrollment so customers can authorize it for the ``zs-cbom`` login.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

STATE_FILE = "state.json"
KEY_FILE = "id_ed25519"


@dataclass
class NodeState:
    directory: str
    node_token: str | None = None
    node_id: int | None = None
    team_id: int | None = None
    enrolled_with: str | None = None  # sha256 of the registration token used (never the token itself)

    @property
    def key_path(self) -> str:
        return os.path.join(self.directory, KEY_FILE)

    @classmethod
    def load(cls, directory: str) -> "NodeState":
        os.makedirs(directory, mode=0o700, exist_ok=True)
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass
        st = cls(directory)
        try:
            with open(os.path.join(directory, STATE_FILE), encoding="utf-8") as f:
                data = json.load(f)
            st.node_token = data.get("node_token")
            st.node_id = data.get("node_id")
            st.team_id = data.get("team_id")
            st.enrolled_with = data.get("enrolled_with")
        except (OSError, ValueError):
            pass
        return st

    def save(self) -> None:
        path = os.path.join(self.directory, STATE_FILE)
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"node_token": self.node_token, "node_id": self.node_id, "team_id": self.team_id,
                       "enrolled_with": self.enrolled_with}, f)
        os.replace(tmp, path)

    def clear_token(self) -> None:
        self.node_token = None
        self.save()

    def ssh_public_key(self) -> str:
        """Create the node's ed25519 key if missing; return the OpenSSH public key line."""
        if not os.path.exists(self.key_path):
            key = ed25519.Ed25519PrivateKey.generate()
            pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                    serialization.NoEncryption())
            fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(pem)
        with open(self.key_path, "rb") as f:
            key = serialization.load_ssh_private_key(f.read(), password=None)
        pub = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        return pub.decode() + " zs-scan-node"
