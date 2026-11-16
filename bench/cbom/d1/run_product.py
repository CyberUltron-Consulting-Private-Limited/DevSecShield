"""Run the product's CBOM code engine on one scan tree, exactly as the scan-worker does, and write observed rows.

This is the ONLY file of the D1 lane that imports the product. The call and its arguments are the worker's
(`RabbitMQ/worker/helpers/tools/cbom_agent/main.py`, `CBOMAgent.scan`): `scan_crypto_to_devsecshield(dir, level=4)`
with the worker's defaults (no vendored code, no binaries, git history only when complete; the scan trees have no
.git). Run it with an interpreter that has aibom installed, e.g. `aibom/.venv/bin/python`.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lane import fetch, observed  # noqa: E402  (stdlib-only lane helpers)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--scan-root", required=True, type=Path)
    ap.add_argument("--bench", required=True)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[3])
    a = ap.parse_args()
    from aibom.cbom import crypto_kb
    from aibom.integrations.cbom_devsecshield import scan_crypto_to_devsecshield

    digest, files = fetch.tree_digest(a.scan_root)
    t = time.monotonic()
    run = scan_crypto_to_devsecshield(str(a.scan_root), level=4)
    seconds = round(time.monotonic() - t, 2)
    sha = subprocess.run(["git", "-C", str(a.repo), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "-C", str(a.repo), "status", "--porcelain", "--untracked-files=no", "--", "aibom"],
                           capture_output=True, text=True).stdout.strip()
    product = {"entry": "aibom.integrations.cbom_devsecshield.scan_crypto_to_devsecshield", "level": 4,
               "git_sha": sha, "aibom_dirty": bool(dirty), "kb_version": crypto_kb.version(),
               "scan_tree_sha256": digest, "scan_tree_files": files, "seconds": seconds,
               "result_rows": len(run.get("results") or [])}
    doc = observed.document(a.bench, observed.from_run_object(run.get("results") or []), product)
    if fetch.tree_digest(a.scan_root)[0] != digest:
        print("the scan tree changed while the product scanned it", file=sys.stderr)
        return 2
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
