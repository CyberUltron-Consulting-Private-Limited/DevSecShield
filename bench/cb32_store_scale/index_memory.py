"""CB-32: memory and time of the estate store's per-process key index (``estate._keys_for_run``) at N observations.

Builds N synthetic stored rows of 4 sources (40 % certificates, 20 % TLS endpoints, 40 % libraries), keys them cold
(an empty index), then warm (same rows: steady state), and measures the index's retained memory (RSS after the rows
and the asset_keys memos are freed, minus RSS with the index dropped) per observation and per correlating one.
Also times a full correlation without an index (``mode=full``: what a team over the memory budget pays each run).

    PYTHONPATH=<tree> CBOM_ESTATE_INDEX_MB=4096 python bench/cb32_store_scale/index_memory.py 1500000
"""
from __future__ import annotations

import gc
import hashlib
import json
import os
import sys
import time
from types import SimpleNamespace

from backend.utilities.cbom_sources import estate as E


def rss_mb() -> float:
    return int(open("/proc/self/statm").read().split()[1]) * os.sysconf("SC_PAGE_SIZE") / 2**20


def rows(n: int, refs=("srcA", "srcB", "srcC", "srcD")) -> list:
    out = []
    for i in range(n):
        b, ref, host = i % 10, refs[i % 4], f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"
        if b < 4:
            facts = {"serial": format(0x9F00000000000000000000 + i * 7919, "x"), "not_after": "2027-06-30T12:00:00Z",
                     "fingerprint_sha256": hashlib.sha256(str(i).encode()).hexdigest(),
                     "subject": f"CN=host-{i}.example.com,O=Example", "issuer": "CN=Example CA 2,O=Example"}
            r = SimpleNamespace(asset_type="certificate", cdx_type="certificate", target=host,
                                location=f"{host}:443#chain[0]", facts=facts)
        elif b < 6:
            r = SimpleNamespace(asset_type="tls_endpoint", cdx_type="x", target=host, location=f"{host}:443",
                                facts={"port": 443})
        else:
            r = SimpleNamespace(asset_type="crypto_library", cdx_type="x", target=host,
                                location=f"{host}/usr/lib/libssl.so.{i}", facts={"name": "openssl"})
        r.asset_key, r.name, r.algorithm = hashlib.sha256(str(i).encode()).hexdigest(), None, None
        out.append((r, ref))
    return out


def _clear_memos() -> None:
    for name in dir(E.AK):
        fn = getattr(E.AK, name)
        if hasattr(fn, "cache_clear"):
            fn.cache_clear()


def main() -> int:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 300_000
    base = rss_mb()
    data = rows(n)
    gc.collect()
    out: dict = {"observations": n, "budget_mb": E.INDEX_BUDGET_MB, "capacity": E.index_capacity(),
                 "rows_mb": round(rss_mb() - base)}
    _clear_memos()
    t0 = time.perf_counter()
    first = E._keys_for_run(1, data)
    out["cold_index_s"], out["mode"] = round(time.perf_counter() - t0, 1), first.mode
    t0 = time.perf_counter()
    E._keys_for_run(1, data)
    out["warm_s"] = round(time.perf_counter() - t0, 2)
    out["indexed"] = E.index_stats()["observations"]
    budget = E.INDEX_BUDGET_MB
    E.INDEX_BUDGET_MB = 0  # over the budget: no index, a full correlation
    _clear_memos()  # a restarted process: asset_keys' memos are empty too
    t0 = time.perf_counter()
    cold = E._keys_for_run(2, data)
    out["full_s"], out["full_mode"] = round(time.perf_counter() - t0, 1), cold.mode
    E.INDEX_BUDGET_MB = budget
    assert cold.keys == first.keys and cold.okeys == first.okeys
    E._drop_index(2)
    del data, first, cold
    _clear_memos()
    gc.collect()
    kept = rss_mb()
    E._INDEXES.clear()
    gc.collect()
    freed = kept - rss_mb()
    out.update(index_mb=round(freed), bytes_per_observation=round(freed * 2**20 / n),
               bytes_per_indexed=round(freed * 2**20 / max(1, out["indexed"])))
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
