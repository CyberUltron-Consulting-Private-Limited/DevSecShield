#!/usr/bin/env python3
"""classify() over 50,000 mixed assets: CB-04's performance budget is +5 % against dev (DA §7 PR-3a, §9 row S).

The mix is fixed (seeded): 60 % the lab assets a scan node emitted against the CB-04 lab (certificates, TLS and SSH
endpoints), 40 % the T-B3 corpus inputs (every registry identifier as a certificate key, a managed key, a TLS group and
an SSH key exchange). It reports CPU time (process time, the best of N rounds), so a busy machine distorts it less than
wall time. Compare two commits by running it at each, alternately:

    cd backend && PYTHONPATH=.. .venv/bin/python tests/bench_algid_classify.py 7
"""
from __future__ import annotations

import contextlib
import io
import json
import random
import sys
import time
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / "fixtures"
sys.path.insert(0, str(FIXTURES.parents[2]))
sys.path.insert(0, str(FIXTURES))

import make_algid_verdict_corpus as corpus  # noqa: E402

from backend.utilities.cbom_sources.classify import CLASSIFIER_VERSION, classify  # noqa: E402

ASSETS = 50_000


def mix() -> list[dict]:
    rows = corpus.inputs()
    lab = [r for r in rows if r["key"].startswith("lab|")]
    rng = random.Random(7)
    return [rng.choice(lab) if rng.random() < 0.6 else rng.choice(rows) for _ in range(ASSETS)]


def run(assets: list[dict]) -> float:
    start = time.process_time()
    with contextlib.redirect_stdout(io.StringIO()):  # unknown-identifier lines are logged once each
        for r in assets:
            classify(r["type"], r["algorithm"], r["key_size"], r["protocol"], r["facts"], corpus.NOW)
    return time.process_time() - start


def main() -> None:
    rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    assets = mix()
    run(assets[:2_000])  # warm-up: imports, the knowledge base, first-seen log lines
    best = min(run(assets) for _ in range(rounds))
    print(json.dumps({"classifier_version": CLASSIFIER_VERSION, "assets": len(assets), "rounds": rounds,
                      "best_cpu_s": round(best, 3), "us_per_asset": round(best / len(assets) * 1e6, 1)}))


if __name__ == "__main__":
    main()
