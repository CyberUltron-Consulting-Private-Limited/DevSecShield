"""Capture Base_Commit SHA-256 digests of the 18 frozen crypto trees.

Run from ``aibom/`` before any posture product change::

    uv run python tests/support/make_goldens.py
"""

from __future__ import annotations

import hashlib
import inspect
import json
import sys
from pathlib import Path

AIBOM = Path(__file__).resolve().parents[2]
FIXTURES = AIBOM / "tests" / "fixtures"
OUT = FIXTURES / "frozen_goldens"
TREES = (
    "synthetic-crypto-app",
    "synthetic-crypto-ast",
    "synthetic-crypto-certs",
    "synthetic-crypto-certs-harden",
    "synthetic-crypto-dataflow",
    "synthetic-crypto-inline-cert",
    "synthetic-crypto-jvm-go",
    "synthetic-crypto-manifests",
    "synthetic-crypto-misuse",
    "synthetic-crypto-multilang",
    "synthetic-crypto-native",
    "synthetic-crypto-native-apis",
    "synthetic-crypto-padding",
    "synthetic-crypto-policy",
    "synthetic-crypto-pqc",
    "synthetic-crypto-protocols",
    "synthetic-crypto-suites",
    "synthetic-crypto-web-native",
)


def canonical(value: object) -> str:
    """ASCII JSON with sorted keys. The digest input for every golden."""
    return json.dumps(value, sort_keys=True, ensure_ascii=True)


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value).encode("ascii")).hexdigest()


def normalize_for_digest(run: dict) -> dict:
    """Drop the clock and, once it exists, the posture block."""
    body = dict(run)
    body.pop("duration_of_scan", None)
    body.pop("cbom_posture", None)
    return body


def capture() -> dict:
    sys.path.insert(0, str(AIBOM / "tests"))
    from aibom.cbom.normalize import normalize_crypto
    from aibom.cbom.pipeline import scan_crypto
    from aibom.emit.cyclonedx import emit_cyclonedx
    from aibom.integrations.cbom_devsecshield import scan_crypto_to_devsecshield
    from support.base_commit import BASE_COMMIT

    trees: dict[str, dict[str, str]] = {}
    for name in TREES:
        root = FIXTURES / name
        if not root.is_dir():
            raise SystemExit(f"missing fixture tree: {root}")
        result = scan_crypto(root)
        run = normalize_crypto(result, duration_of_scan=0.0)
        trees[name] = {
            "scan": digest(result.to_dict()),
            "normalize": digest(normalize_for_digest(run)),
            "cyclonedx": digest(emit_cyclonedx(result)),
        }
        print(name, flush=True)
    signature = str(inspect.signature(scan_crypto_to_devsecshield))
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "adapter_signature.txt").write_text(signature + "\n", encoding="ascii")
    payload = {"base_commit": BASE_COMMIT, "trees": trees}
    (OUT / "base_commit_digests.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="ascii",
    )
    return payload


def main() -> None:
    capture()


if __name__ == "__main__":
    main()
