"""Failing-first proofs of the self-check (DEVILS-ADVOCATE §5.2 CB-02): each broken lab must be caught.

  z02-3des      z02 asks for TLS_RSA_WITH_3DES_EDE_CBC_SHA; Alpine's OpenSSL 3.5 does not build 3DES, so nmap must
                show the suite missing and the self-check must call it a lab bug.
  z01-unpinned  z01 leaves the groups at OpenSSL 3.5's default, which offers X25519MLKEM768; the Go client must
                see the hybrid group and the self-check must call it a lab bug.
  oracle-edit   an oracle file edited after generation (after "Start") must be detected by the O-5 hash.

`gen.py negative --run-dir-base DIR` runs all three against real containers and writes DIR/negative.json.
Exit 0 only when every broken lab was caught for the stated reason; the lab is taken down before and after.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

CASES = {
    "z02-3des": {"target": "z02", "key": "cipher_suites[TLSv1.2]",
                 "why": lambda c: "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in c["expected"]
                 and "TLS_RSA_WITH_3DES_EDE_CBC_SHA" not in (c["observed"] or [])},
    "z01-unpinned": {"target": "z01", "key": "groups",
                     "why": lambda c: "X25519MLKEM768" in (c["observed"] or []) and "X25519MLKEM768" not in c["expected"]},
}


def gen_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(HERE / "gen.py"), *args], capture_output=True, text=True, timeout=900)


def main(base: Path) -> int:
    base.mkdir(parents=True, exist_ok=True)
    results = []
    gen_cli("down")
    for variant, case in CASES.items():
        run = base / variant
        if run.exists():
            subprocess.run(["rm", "-rf", str(run)], check=True)
        up = gen_cli("up", "--run-dir", str(run), "--wave", "core", "--variant", variant, "--only", case["target"])
        sc = gen_cli("selfcheck", "--run-dir", str(run))
        row = {"case": variant, "up_exit": up.returncode, "selfcheck_exit": sc.returncode, "caught": False}
        try:
            report = json.loads((run / "lab" / "selfcheck.json").read_text())
            target = next(t for t in report["targets"] if t["target_id"] == case["target"])
            hits = [c for c in target["checks"] if c["key"] == case["key"] and not c["agree"]]
            row["evidence"] = hits
            row["caught"] = sc.returncode == 2 and any(case["why"](c) for c in hits)
        except (OSError, StopIteration, json.JSONDecodeError) as exc:
            row["error"] = f"{type(exc).__name__}: {exc}"
        results.append(row)
        gen_cli("down")
    # O-5: an oracle edited after generation
    run = base / "oracle-edit"
    if run.exists():
        subprocess.run(["rm", "-rf", str(run)], check=True)
    up = gen_cli("up", "--run-dir", str(run), "--wave", "core", "--only", "z01")
    facts = run / "oracle" / "facts" / "z01.json"
    o = json.loads(facts.read_text())
    o["expect"]["versions"]["TLSv1.2"] = True  # what a hand edit "to make it pass" would look like
    facts.write_text(json.dumps(o, indent=1, sort_keys=True) + "\n")
    sc = gen_cli("selfcheck", "--run-dir", str(run))
    report = json.loads((run / "lab" / "selfcheck.json").read_text())
    results.append({"case": "oracle-edit", "up_exit": up.returncode, "selfcheck_exit": sc.returncode,
                    "caught": sc.returncode == 2 and "oracle changed" in report.get("error", ""),
                    "evidence": {k: report.get(k) for k in ("error", "oracle_sha256", "oracle_sha256_recorded")}})
    gen_cli("down")
    out = {"checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "results": results,
           "all_caught": all(r["caught"] for r in results)}
    (base / "negative.json").write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps({"all_caught": out["all_caught"], "cases": {r["case"]: r["caught"] for r in results}}))
    return 0 if out["all_caught"] else 2


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("base", type=Path)
    sys.exit(main(ap.parse_args().base.resolve()))
