"""Recompute the Base_Commit digests of the 18 frozen crypto trees."""

from __future__ import annotations

import hashlib
import inspect
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aibom.cbom.normalize import normalize_crypto  # noqa: E402
from aibom.cbom.pipeline import scan_crypto  # noqa: E402
from aibom.emit.cyclonedx import emit_cyclonedx  # noqa: E402
from aibom.integrations.cbom_devsecshield import (  # noqa: E402
    scan_crypto_to_devsecshield,
)
from support.make_goldens import TREES, digest, normalize_for_digest  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
GOLDENS = FIXTURES / "frozen_goldens"


def test_frozen_digests_match_the_base_commit() -> None:
    path = GOLDENS / "base_commit_digests.json"
    payload = json.loads(path.read_text(encoding="ascii"))
    assert set(payload["trees"]) == set(TREES)
    for name in TREES:
        result = scan_crypto(FIXTURES / name)
        run = normalize_crypto(result, duration_of_scan=0.0)
        got = {
            "scan": digest(result.to_dict()),
            "normalize": digest(normalize_for_digest(run)),
            "cyclonedx": digest(emit_cyclonedx(result)),
        }
        assert got == payload["trees"][name], name


def test_adapter_signature_is_the_captured_text() -> None:
    saved = (GOLDENS / "adapter_signature.txt").read_text(encoding="ascii").strip()
    assert str(inspect.signature(scan_crypto_to_devsecshield)) == saved


def test_digest_helper_is_stable() -> None:
    raw = json.dumps({"b": 1, "a": 2}, sort_keys=True, ensure_ascii=True)
    assert digest({"b": 1, "a": 2}) == hashlib.sha256(raw.encode("ascii")).hexdigest()
