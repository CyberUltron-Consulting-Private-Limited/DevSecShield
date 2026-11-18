"""CB-32: CB-21's CorrelationIndex in a compact form (a 1.5M-asset team's warm index in the memory budget).

* Answers are unchanged: aliases leave the module as frozensets whatever the stored form (tuples for solo answers);
  ``test_cbom_asset_keys_perf`` already proves the index equals ``correlate_detail`` after random update sequences.
* A link key held by one observation maps to that id; a set exists only while several hold it, and folds back.
* Memory: each correlating observation's share of the index stays under 1,800 bytes (tracemalloc; it was ~2,850).
"""
from __future__ import annotations

import gc
import hashlib
import sys
import tracemalloc
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.utilities.cbom_sources import asset_keys as AK

AFTER = "2027-06-30T12:00:00Z"


def _cert(i: int, **extra) -> AK.Observation:
    facts = {"serial": format(0x9F00000000000000000000 + i * 7919, "x"), "not_after": AFTER,
             "fingerprint_sha256": hashlib.sha256(str(i).encode()).hexdigest(),
             "subject": f"CN=host-{i}.example.com,O=Example", "issuer": "CN=Example CA 2,O=Example", **extra}
    return AK.Observation(kind="certificate", facts=facts, location=f"10.0.0.{i % 250}:443", target="10.0.0.1",
                          cdx_type="certificate", scope="src")


def _clear_memos() -> None:
    for name in dir(AK):
        fn = getattr(AK, name)
        if hasattr(fn, "cache_clear"):
            fn.cache_clear()


def test_aliases_leave_as_frozensets_in_every_path():
    obs = [_cert(i) for i in range(20)] + [_cert(0)]  # the last one shares every key with the first: a group
    full = AK.correlate_detail(obs)
    assert all(type(a) is frozenset for a in full.aliases)
    index = AK.CorrelationIndex({i: o for i, o in enumerate(obs)})
    assert all(type(index.aliases(i)) is frozenset for i in range(len(obs)))
    assert index.correlation(list(range(len(obs)))) == full
    assert set(index.names(0)) == index.aliases(0) == full.aliases[0]


def test_a_link_key_held_once_maps_to_its_id_and_a_shared_one_folds_back():
    index = AK.CorrelationIndex({"a": _cert(1)})
    key = index.key("a")
    assert index._by_key[key] == "a"
    index.update({"b": _cert(1)})  # the same certificate seen by a second source
    assert index._by_key[key] == {"a", "b"} and index.key("b") == key
    index.update({"b": None})
    assert index._by_key[key] == "a"
    index.update({"a": None})
    assert index._by_key == {} and len(index) == 0


def test_the_index_costs_under_1800_bytes_per_correlating_observation():
    obs = {i: _cert(i) for i in range(4000)}
    gc.collect()
    tracemalloc.start()
    index = AK.CorrelationIndex(obs)
    _clear_memos()
    gc.collect()
    size, _peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert len(index) == 4000
    assert size / 4000 < 1800, size / 4000
