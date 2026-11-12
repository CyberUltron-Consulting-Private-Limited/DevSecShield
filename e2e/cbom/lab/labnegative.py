"""Failing-first proofs of the self-check (DEVILS-ADVOCATE §5.2 CB-02): each broken lab must be caught.

  z02-3des            z02 asks for TLS_RSA_WITH_3DES_EDE_CBC_SHA; Alpine's OpenSSL 3.5 does not build 3DES, so nmap
                      must show the suite missing and the self-check must call it a lab bug.
  z01-unpinned        z01 leaves the groups at OpenSSL 3.5's default, which offers X25519MLKEM768; the Go client
                      must see the hybrid group.
  E2 z02-extra-group  (review 5874442142) z02's server also accepts X25519 after prime256v1 while the oracle keeps
                      [secp256r1]: one TLS 1.2 handshake per group must see the extra group (equality, not subset).
  oracle-edit         an oracle file edited after generation must be detected by the O-5 hash, also after someone
                      runs the read-only `gen.py hash`.
  C hsm-parser-inverted  the generator's pkcs11-tool parser inverts `extractable`: p11tool must disagree.
  D1 hsm-parser-bits  (review 5874442142) the generator's pkcs11-tool parser doubles `bits`: p11tool (private keys)
                      and the SoftHSM object store (secret keys) must disagree on key_size.
  D2 keytool-bits     (review 5874442142) the generator's keytool parser reports key_bits + 1: the JKS / PKCS#12
                      readers must disagree on the keystore entries.
  B z02-groups-accepted   z02's facts edited to x25519 and accepted with a reason: nmap's kex_info and the rebuild
                      of run1.json from the facts must disagree, and the report must carry the accepted change.
  B run1-groups-accepted  (review 5874442142, the original form) oracle/run1.json, the file CB-01 judges, edited to
                      X25519 and accepted: the self-check compares that file and rebuilds it, so it must fail.

`gen.py negative --run-dir-base DIR` runs every case against real containers and writes DIR/negative.json. Exit 0
only when every broken lab was caught for the stated reason; the lab is taken down before and after each case.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

VARIANTS = {
    "z02-3des": {"target": "z02", "key": "cipher_suites[TLSv1.2]",
                 "why": lambda c: "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in c["expected"]
                 and "TLS_RSA_WITH_3DES_EDE_CBC_SHA" not in (c["observed"] or [])},
    "z01-unpinned": {"target": "z01", "key": "groups",
                     "why": lambda c: "X25519MLKEM768" in (c["observed"] or []) and "X25519MLKEM768" not in c["expected"]},
    "z02-extra-group": {"target": "z02", "key": "groups",
                        "why": lambda c: "X25519" in (c["observed"] or []) and "X25519" not in c["expected"]},
}
# One-line mutations of the generator's own parsers (a copy of the lab code; the images are unchanged).
PARSER_MUTATIONS = {
    "hsm-parser-inverted": {"wave": "hsm", "target": "softhsm", "key": "extractable", "file": "labgen.py",
                            "old": 'o["extractable"] = "extractable" in access',
                            "new": 'o["extractable"] = "extractable" not in access'},
    "hsm-parser-bits": {"wave": "hsm", "target": "softhsm", "key": "key_size", "file": "labgen.py",
                        "old": "        objs.append(o)\n",
                        "new": '        o["bits"] = o["bits"] * 2 if o["bits"] else o["bits"]  # D1\n        objs.append(o)\n'},
    "keytool-bits": {"wave": "core", "only": "host", "target": "host", "key": "entries", "file": "labgen.py",
                     "old": 'e["key_bits"], e["key_algorithm"] = (int(m.group(1)), m.group(2)) if m else (None, "")',
                     "new": 'e["key_bits"], e["key_algorithm"] = (int(m.group(1)) + 1, m.group(2)) if m else (None, "")'},
}


def wait_for_memory(wave: str, limit_s: int = 300) -> None:
    """`up` refuses below the memory floor (gen.MEM_FLOOR_MB); on the shared machine wait for room instead of
    recording a refused case as "not caught"."""
    import gen
    need = gen.MEM_FLOOR_MB + sum(gen.WAVE_MEM_MB.get(w, 0) for w in wave.split(","))
    deadline = time.time() + limit_s
    while gen.mem_available_mb() < need and time.time() < deadline:
        time.sleep(10)


def gen_cli(*args: str, lab: Path = HERE) -> subprocess.CompletedProcess:
    if args and args[0] == "up":
        wait_for_memory(args[args.index("--wave") + 1] if "--wave" in args else "core")
    return subprocess.run([sys.executable, str(lab / "gen.py"), *args], capture_output=True, text=True, timeout=900)


def mutated_copy(base: Path, file: str, old: str, new: str) -> Path:
    """A copy of the lab code with one line changed (the images are unchanged, so nothing is rebuilt)."""
    dest = base / "mutated-lab"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(HERE, dest, ignore=shutil.ignore_patterns(".work", "__pycache__", "tests"))
    path = dest / file
    text = path.read_text()
    assert old in text, f"mutation anchor not found in {file}"
    path.write_text(text.replace(old, new, 1))
    return dest


def report_of(run: Path) -> dict:
    path = run / "lab" / "selfcheck.json"
    return json.loads(path.read_text()) if path.exists() else {"targets": [], "error": "no selfcheck.json"}


def failing_rows(run: Path, target: str, key_part: str, exact: bool = False) -> list[dict]:
    tgt = next((t for t in report_of(run)["targets"] if t["target_id"] == target), {"checks": []})
    return [c for c in tgt["checks"] if (c["key"] == key_part if exact else key_part in c["key"]) and not c["agree"]]


def fresh(run: Path) -> None:
    if run.exists():
        subprocess.run(["rm", "-rf", str(run)], check=True)


def main(base: Path) -> int:
    base.mkdir(parents=True, exist_ok=True)
    results = []
    gen_cli("down")
    for variant, case in VARIANTS.items():
        run = base / variant
        fresh(run)
        up = gen_cli("up", "--run-dir", str(run), "--wave", "core", "--variant", variant, "--only", case["target"])
        sc = gen_cli("selfcheck", "--run-dir", str(run))
        row = {"case": variant, "up_exit": up.returncode, "selfcheck_exit": sc.returncode, "caught": False}
        try:
            hits = failing_rows(run, case["target"], case["key"], exact=True)
            row["evidence"] = hits
            row["caught"] = sc.returncode == 2 and any(case["why"](c) for c in hits)
        except (OSError, StopIteration, json.JSONDecodeError) as exc:
            row["error"] = f"{type(exc).__name__}: {exc}"
        results.append(row)
        gen_cli("down")
    # O-5: an oracle edited after generation
    run = base / "oracle-edit"
    fresh(run)
    up = gen_cli("up", "--run-dir", str(run), "--wave", "core", "--only", "z01")
    facts = run / "oracle" / "facts" / "z01.json"
    o = json.loads(facts.read_text())
    o["expect"]["versions"]["TLSv1.2"] = True  # what a hand edit "to make it pass" would look like
    facts.write_text(json.dumps(o, indent=1, sort_keys=True) + "\n")
    rehash = gen_cli("hash", "--run-dir", str(run))  # the documented read-only command must not bless the edit
    sc = gen_cli("selfcheck", "--run-dir", str(run))
    report = report_of(run)
    results.append({"case": "oracle-edit", "up_exit": up.returncode, "hash_exit": rehash.returncode,
                    "selfcheck_exit": sc.returncode,
                    "caught": rehash.returncode == 2 and sc.returncode == 2 and "oracle changed" in report.get("error", ""),
                    "evidence": {k: report.get(k) for k in ("error", "oracle_sha256", "oracle_sha256_recorded")}})
    gen_cli("down")
    # C, D1, D2: the generator's own parsers are wrong; the independent readers must disagree with the oracle.
    for name, m in PARSER_MUTATIONS.items():
        run = base / name
        fresh(run)
        lab = mutated_copy(base, m["file"], m["old"], m["new"])
        up = gen_cli("up", "--run-dir", str(run), "--wave", m["wave"], *(["--only", m["only"]] if m.get("only") else []),
                     lab=lab)
        sc = gen_cli("selfcheck", "--run-dir", str(run), lab=lab)
        rows = failing_rows(run, m["target"], m["key"], exact=True)
        results.append({"case": name, "mutation": m["new"].strip(), "up_exit": up.returncode,
                        "selfcheck_exit": sc.returncode, "caught": sc.returncode == 2 and bool(rows),
                        "evidence": rows})
        gen_cli("down", lab=lab)
        shutil.rmtree(lab)
    # B: accepted edits, of the facts and of the run file CB-01 judges
    for name, edit in (("z02-groups-accepted", "facts"), ("run1-groups-accepted", "run1")):
        run = base / name
        fresh(run)
        up = gen_cli("up", "--run-dir", str(run), "--wave", "core", "--only", "z02")
        if edit == "facts":
            path = run / "oracle" / "facts" / "z02.json"
            o = json.loads(path.read_text())
            o["expect"]["groups"] = ["x25519"]
        else:
            path = run / "oracle" / "run1.json"
            o = json.loads(path.read_text())
            tls = next(a for t in o["targets"] if t["target_id"] == "z02" for a in t["assets"] if a["oracle_id"] == "z02/tls")
            tls["expect"]["groups"] = ["X25519"]
        path.write_text(json.dumps(o, indent=1, sort_keys=True) + "\n")
        acc = gen_cli("hash", "--run-dir", str(run), "--accept-change", "--reason", f"negative proof: mutation B ({edit})")
        sc = gen_cli("selfcheck", "--run-dir", str(run))
        report = report_of(run)
        rows = (failing_rows(run, "z02", "groups (TLS <= 1.2") if edit == "facts"
                else failing_rows(run, "z02", "groups", exact=True))
        rebuild = failing_rows(run, "oracle", "equals its rebuild")
        results.append({"case": name, "up_exit": up.returncode, "accept_exit": acc.returncode,
                        "selfcheck_exit": sc.returncode,
                        "caught": sc.returncode == 2 and bool(rows) and bool(rebuild)
                        and len(report.get("oracle_changes", [])) == 1,
                        "evidence": {"rows": rows, "rebuild": rebuild, "oracle_changes": report.get("oracle_changes")}})
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
