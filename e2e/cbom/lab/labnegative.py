"""Failing-first proofs of the self-check (DEVILS-ADVOCATE §5.2 CB-02): each broken lab must be caught.

  z02-3des      z02 asks for TLS_RSA_WITH_3DES_EDE_CBC_SHA; Alpine's OpenSSL 3.5 does not build 3DES, so nmap must
                show the suite missing and the self-check must call it a lab bug.
  z01-unpinned  z01 leaves the groups at OpenSSL 3.5's default, which offers X25519MLKEM768; the Go client must
                see the hybrid group and the self-check must call it a lab bug.
  oracle-edit   an oracle file edited after generation (after "Start") must be detected by the O-5 hash, also
                after someone runs the read-only `gen.py hash`.
  hsm-parser-inverted   (review 5873265185, mutation C) the generator's pkcs11-tool parser inverts `extractable`; the
                independent p11tool observation and the catalogue must disagree with that oracle.
  z02-groups-accepted   (mutation B) z02's oracle groups edited to x25519 and accepted with a reason; nmap's ECDHE
                kex_info (secp256r1) must disagree, and the report must carry the accepted change.

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


def gen_cli(*args: str, lab: Path = HERE) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(lab / "gen.py"), *args], capture_output=True, text=True, timeout=900)


def mutated_copy(base: Path, file: str, old: str, new: str) -> Path:
    """A copy of the lab code with one line changed (the images are unchanged, so nothing is rebuilt)."""
    import shutil
    dest = base / "mutated-lab"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(HERE, dest, ignore=shutil.ignore_patterns(".work", "__pycache__", "tests"))
    path = dest / file
    text = path.read_text()
    assert old in text, f"mutation anchor not found in {file}"
    path.write_text(text.replace(old, new, 1))
    return dest


def failing_rows(run: Path, target: str, key_part: str) -> list[dict]:
    report = json.loads((run / "lab" / "selfcheck.json").read_text())
    tgt = next((t for t in report["targets"] if t["target_id"] == target), {"checks": []})
    return [c for c in tgt["checks"] if key_part in c["key"] and not c["agree"]]


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
    rehash = gen_cli("hash", "--run-dir", str(run))  # the documented read-only command must not bless the edit
    sc = gen_cli("selfcheck", "--run-dir", str(run))
    report = json.loads((run / "lab" / "selfcheck.json").read_text())
    results.append({"case": "oracle-edit", "up_exit": up.returncode, "hash_exit": rehash.returncode,
                    "selfcheck_exit": sc.returncode,
                    "caught": rehash.returncode == 2 and sc.returncode == 2 and "oracle changed" in report.get("error", ""),
                    "evidence": {k: report.get(k) for k in ("error", "oracle_sha256", "oracle_sha256_recorded")}})
    gen_cli("down")
    # mutation C: the generator's pkcs11-tool parser inverts `extractable`
    run = base / "hsm-parser-inverted"
    subprocess.run(["rm", "-rf", str(run)], check=True)
    lab = mutated_copy(base, "labgen.py", 'o["extractable"] = "extractable" in access',
                       'o["extractable"] = "extractable" not in access')
    up = gen_cli("up", "--run-dir", str(run), "--wave", "hsm", lab=lab)
    sc = gen_cli("selfcheck", "--run-dir", str(run), lab=lab)
    rows = failing_rows(run, "softhsm", "independent observation")
    results.append({"case": "hsm-parser-inverted", "up_exit": up.returncode, "selfcheck_exit": sc.returncode,
                    "caught": sc.returncode == 2 and bool(rows), "evidence": rows})
    gen_cli("down", lab=lab)
    subprocess.run(["rm", "-rf", str(lab)], check=True)
    # mutation B: an accepted edit of z02's groups
    run = base / "z02-groups-accepted"
    subprocess.run(["rm", "-rf", str(run)], check=True)
    up = gen_cli("up", "--run-dir", str(run), "--wave", "core", "--only", "z02")
    facts = run / "oracle" / "facts" / "z02.json"
    o = json.loads(facts.read_text())
    o["expect"]["groups"] = ["x25519"]
    facts.write_text(json.dumps(o, indent=1, sort_keys=True) + "\n")
    acc = gen_cli("hash", "--run-dir", str(run), "--accept-change", "--reason", "negative proof: mutation B")
    sc = gen_cli("selfcheck", "--run-dir", str(run))
    rows = failing_rows(run, "z02", "groups (TLS <= 1.2")
    report = json.loads((run / "lab" / "selfcheck.json").read_text())
    results.append({"case": "z02-groups-accepted", "up_exit": up.returncode, "accept_exit": acc.returncode,
                    "selfcheck_exit": sc.returncode,
                    "caught": sc.returncode == 2 and bool(rows) and len(report.get("oracle_changes", [])) == 1,
                    "evidence": {"rows": rows, "oracle_changes": report.get("oracle_changes")}})
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
