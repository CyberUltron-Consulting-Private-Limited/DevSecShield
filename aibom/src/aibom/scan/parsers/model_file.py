"""Detect model weight files and hash them.

Recognizes the common serialized-weight formats. The detected file's SHA-256 is
attached to the model component (CycloneDX ``hashes[]``), giving the BOM an
integrity anchor for the weights.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from aibom.model.component import Hash

# Weight/serialized-model suffixes (lowercased).
MODEL_FILE_SUFFIXES = frozenset(
    {".safetensors", ".onnx", ".pt", ".pth", ".gguf", ".bin", ".h5", ".pb"}
)

_CHUNK = 1 << 20  # 1 MiB streaming read


def find_model_files(root: Path) -> list[Path]:
    """Return weight files under ``root`` (sorted by path for determinism)."""
    if not root.is_dir():
        return []
    found = [
        p
        for p in root.rglob("*")
        if p.is_file() and p.suffix.lower() in MODEL_FILE_SUFFIXES
    ]
    return sorted(found)


def sha256_hash(path: Path) -> Hash:
    """Return a CycloneDX-shaped SHA-256 :class:`Hash` for ``path``."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            digest.update(chunk)
    return Hash(alg="SHA-256", content=digest.hexdigest())


__all__ = ["MODEL_FILE_SUFFIXES", "find_model_files", "sha256_hash"]
