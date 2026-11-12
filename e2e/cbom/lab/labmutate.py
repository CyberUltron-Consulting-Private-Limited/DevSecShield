"""`gen.py mutate --step run2`: apply the G13/G13b change set (labspec.RUN2_CHANGES) to a running lab.

The generator (labgen.py --mutate run2, in the tools image) rewrites the affected lab files and writes the run-2
facts, oracle/run2.json (with `drift`) and lab/lab-run2.json; this module then restarts or starts the containers and
records the new oracle hash (O-5: run 2 has its own frozen oracle, hashed before the customer starts run 2).
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gen  # noqa: E402
import labspec as S  # noqa: E402


def main(run_dir: Path, step: str) -> int:
    gj_path = run_dir / "lab" / "gen.json"
    gj = json.loads(gj_path.read_text())
    if gj.get("current_step", "run1") != "run1":
        raise gen.LabError(f"{run_dir} is already at {gj['current_step']}")
    if gen.oracle_hash(run_dir) != gj.get("oracle_sha256"):
        raise gen.LabError("run-1 oracle changed after generation (O-5); start a new run", 2)
    gen.run(["docker", "run", "--rm", "--network", "none", "--user", f"{os.getuid()}:{os.getgid()}", "-e", "HOME=/tmp",
             "-v", f"{run_dir}:/out", "-v", f"{HERE}:/opt/cb02:ro", gen.IMAGES["tools"], "python3",
             "/opt/cb02/labgen.py", "--out", "/out", "--mutate", step, "--commit", gen.git_commit()])
    containers = {c["target"]: f"cb02-{c['target']}" for c in S.RUN2_CHANGES}
    for ch in S.RUN2_CHANGES:
        name = containers[ch["target"]]
        if ch["change"] in ("disable_version", "reissue_cert"):
            gen.run(["docker", "restart", name])
        elif ch["change"] == "remove_file":
            gen.run(["docker", "exec", name, "rm", "-f", f"/srv/cbom-lab/{ch['path']}"])
        elif ch["change"] == "start" and ch.get("replaces"):
            gen.run(["docker", "rm", "-f", f"cb02-{ch['replaces']}"], check=False)
    starts = [ch["target"] for ch in S.RUN2_CHANGES if ch["change"] == "start"]
    gen.compose(run_dir, "up", "-d", "--wait", "--wait-timeout", "120", *starts, profiles=["run2"])
    for ch in S.RUN2_CHANGES:
        if ch["change"] in ("disable_version", "reissue_cert"):
            gen.compose(run_dir, "up", "-d", "--wait", "--wait-timeout", "60", "--no-recreate", ch["target"],
                        profiles=[S.by_id(ch["target"])["profile"]])
    gj = json.loads(gj_path.read_text())
    gj.setdefault("oracle_sha256_history", []).append({"step": "run1", "oracle_sha256": gj.get("oracle_sha256")})
    gj["current_step"] = step
    gj_path.write_text(json.dumps(gj, indent=1, sort_keys=True) + "\n")
    gen.cmd_hash(gen.argparse.Namespace(run_dir=str(run_dir), verify=None))
    drift = json.loads((run_dir / "oracle" / f"{step}.json").read_text())["drift"]
    print(json.dumps({"step": step, "drift": drift, "oracle_sha256": gen.oracle_hash(run_dir)}))
    return 0
