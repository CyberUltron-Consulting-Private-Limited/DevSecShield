#!/usr/bin/env python3
"""Isolation proof for zs-collect, observed from inside a target container while it runs.

    python bench/f1_transports/isolation.py --release-dir DIR [--out DIR] [--interval 0.05] [--keep]

Uses the lab image that parity.py builds (``f1-3-lab-target:1``) and the signed release from zs_collect/build.sh.

1. **No listener, no network socket.**  While the launcher runs zs-collect (Tier 2, as root, dropping to zs-cbom),
   a sampler inside the same container records, every ``--interval`` seconds,
   * ``ss -H -tuawnp``: every TCP/UDP socket in the container (listening or not) with its owning processes, and
   * for every process whose command line contains ``zs-collect`` (the launcher, the PyInstaller bootloader and the
     collector), each ``/proc/<pid>/fd`` entry that is a socket, with ``/proc/net/{tcp,tcp6,udp,udp6,unix,netlink}``
     looked up for its inode.
   A sampled socket is attributed to zs-collect when its owner is one of those processes.  sshd's own listener is
   expected (it is the target's sshd) and is reported, not attributed.  The proof needs samples taken while
   zs-collect was running (the report counts them).
2. **No writes outside its temp dir.**  ``docker diff`` of the (writable) container right before and right after the
   run: zs-collect's private temp dir is created under /tmp and removed at exit, so the two lists must be equal.
   The same run inside a container with a read-only root file system (``--read-only``, tmpfs /tmp and /run) is in
   parity.py ``--readonly-check``.
Writes ``isolation-report.json`` to ``--out``; exit 0 only when no socket was attributed to zs-collect, at least one
sample was taken while it ran, and the before/after file-system diffs are equal.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
IMAGE = "f1-3-lab-target:1"
NAME = "f1-3-isolation"

# Runs inside the target with /bin/sh (no Python there).  One line per sample, tab-separated sections.
SAMPLER = r"""#!/bin/sh
# sample until the stop file appears; one record per sample
i=0
while [ ! -e /run/zs-sampler.stop ]; do
  i=$((i+1))
  pids=""
  for p in /proc/[0-9]*; do
    pid=${p#/proc/}
    [ "$pid" = "$$" ] && continue
    if tr '\0' ' ' < "$p/cmdline" 2>/dev/null | grep -q 'zs-collect'; then pids="$pids $pid"; fi
  done
  echo "SAMPLE $i $(date +%s.%N) pids:$pids"
  for pid in $pids; do
    for fd in /proc/$pid/fd/*; do
      t=$(readlink "$fd" 2>/dev/null) || continue
      case "$t" in socket:*) echo "FDSOCK $pid $fd $t $(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null | cut -c1-120)";; esac
    done
  done
  ss -H -tuawnp 2>/dev/null | sed 's/^/SS /'
  sleep "$1"
done
echo "DONE $i"
"""


def sh(*args: str, check: bool = True, **kw) -> subprocess.CompletedProcess:
    p = subprocess.run(list(args), capture_output=True, text=True, **kw)
    if check and p.returncode != 0:
        raise SystemExit(f"{' '.join(args[:4])}...: exit {p.returncode}: {p.stderr[-800:]}")
    return p


def docker_diff(name: str) -> list[str]:
    return sorted(sh("docker", "diff", name).stdout.splitlines())


def analyse(lines: list[str]) -> dict:
    samples, during, attributed, sshd, fd_sockets = 0, 0, [], set(), []
    current_pids: set[str] = set()
    for line in lines:
        if line.startswith("SAMPLE "):
            samples += 1
            current_pids = set(line.split("pids:", 1)[1].split())
            # the launcher's own `sh` matches too; a sample counts as "during" when a zs-collect binary process exists
            if current_pids:
                during += 1
        elif line.startswith("FDSOCK "):
            fd_sockets.append(line[7:])
            attributed.append(line)
        elif line.startswith("SS "):
            row = line[3:]
            owners = [part for part in row.split("pid=")[1:]]
            owner_pids = {o.split(",", 1)[0] for o in owners}
            if owner_pids & current_pids:
                attributed.append(line)
            elif "sshd" in row:
                sshd.add(" ".join(row.split()[:5]))
    return {"samples": samples, "samples_while_zs_collect_ran": during, "sockets_attributed_to_zs_collect": attributed,
            "zs_collect_fd_sockets": fd_sockets, "other_sockets_seen (target's own sshd)": sorted(sshd)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release-dir", required=True)
    ap.add_argument("--public-key", default=str(ROOT / "scan_node" / "zs_collect" / "zs-release-ed25519.pub"))
    ap.add_argument("--out", default="isolation-out")
    ap.add_argument("--interval", default="0.05")
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    release = Path(args.release_dir)
    manifest = next(release.glob("zs-collect-*.manifest.json"))
    wrapper = out / "zs-collect-run.sh"
    sh(sys.executable, str(ROOT / "scan_node" / "zs_collect" / "release.py"), "wrapper", "--public", args.public_key,
       "--out", str(wrapper), str(manifest))
    tmp = Path(tempfile.mkdtemp(prefix="f1-3-iso."))
    sampler = tmp / "sampler.sh"
    sampler.write_text(SAMPLER)
    report: dict = {}
    try:
        sh("docker", "run", "-d", "--name", NAME, "--hostname", "lab-iso", "--label", "zs-owner=f1-3", "--memory",
           "256m", IMAGE)
        deadline = time.time() + 60  # the entrypoint generates host keys, then starts sshd: wait for the listener
        while "0.0.0.0:22" not in sh("docker", "exec", NAME, "ss", "-H", "-ltn", check=False).stdout:
            if time.time() > deadline:
                raise SystemExit("sshd did not start in the isolation target")
            time.sleep(0.5)
        time.sleep(1)
        sh("docker", "exec", NAME, "mkdir", "-p", "/opt/zeroshield/zs-collect")
        for f in release.iterdir():
            if f.name.startswith("zs-collect-"):
                sh("docker", "cp", str(f), f"{NAME}:/opt/zeroshield/zs-collect/{f.name}")
        sh("docker", "cp", str(wrapper), f"{NAME}:/usr/local/sbin/zs-collect-run")
        sh("docker", "cp", str(sampler), f"{NAME}:/usr/local/sbin/zs-sampler")
        before = docker_diff(NAME)
        # the sampler itself writes nothing to disk (stdout only); its stop file lives on /run and is removed below
        smp = subprocess.Popen(["docker", "exec", NAME, "/bin/sh", "/usr/local/sbin/zs-sampler", args.interval],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(0.5)
        nonce = "isolation-" + os.urandom(8).hex()
        t0 = time.monotonic()
        run = sh("docker", "exec", NAME, "/bin/sh", "/usr/local/sbin/zs-collect-run", "--nonce", nonce, "--tier", "2",
                 "--label", "lab-iso", check=False)
        secs = time.monotonic() - t0
        time.sleep(0.3)
        sh("docker", "exec", NAME, "touch", "/run/zs-sampler.stop")
        s_out, _s_err = smp.communicate(timeout=60)
        sh("docker", "exec", NAME, "rm", "-f", "/run/zs-sampler.stop")
        after = docker_diff(NAME)
        (out / "sampler.log").write_text(s_out)
        doc = json.loads(run.stdout) if run.stdout.strip().startswith("{") else {}
        (out / "zs-collect-isolation.json").write_text(json.dumps(doc, indent=1))
        a = analyse(s_out.splitlines())
        report = {
            "zs_collect_exit": run.returncode, "zs_collect_status": doc.get("status"),
            "nonce_echoed": doc.get("run_nonce") == nonce, "assets": len(doc.get("assets") or []),
            "zs_collect_seconds": round(secs, 2), **a,
            "docker_diff_before": before, "docker_diff_after": after,
            "docker_diff_added_by_run": sorted(set(after) - set(before)),
            "docker_diff_removed_by_run": sorted(set(before) - set(after)),
        }
        # positive control: the same sampler must catch a listener owned by a process named like zs-collect
        # (sshd copied to /tmp/zs-collect-control, listening on :2222) or the empty result above proves nothing
        smp = subprocess.Popen(["docker", "exec", NAME, "/bin/sh", "/usr/local/sbin/zs-sampler", args.interval],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        sh("docker", "exec", NAME, "cp", "/usr/sbin/sshd", "/tmp/zs-collect-control")
        ctl = subprocess.Popen(["docker", "exec", NAME, "/tmp/zs-collect-control", "-D", "-p", "2222", "-o",
                                "PidFile=none"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)
        sh("docker", "exec", NAME, "pkill", "-f", "zs-collect-control", check=False)
        ctl.wait(timeout=30)
        sh("docker", "exec", NAME, "touch", "/run/zs-sampler.stop")
        c_out, _ = smp.communicate(timeout=60)
        sh("docker", "exec", NAME, "rm", "-f", "/run/zs-sampler.stop", "/tmp/zs-collect-control")
        control = analyse(c_out.splitlines())
        report["positive_control"] = {"sockets_attributed": control["sockets_attributed_to_zs_collect"][:4],
                                      "caught": bool(control["sockets_attributed_to_zs_collect"])}
        ok = (run.returncode == 0 and report["nonce_echoed"] and a["samples_while_zs_collect_ran"] > 0
              and not a["sockets_attributed_to_zs_collect"] and before == after
              and report["positive_control"]["caught"])
        report["ok"] = ok
        (out / "isolation-report.json").write_text(json.dumps(report, indent=1))
        print(json.dumps({k: v for k, v in report.items() if not k.startswith("docker_diff_before")
                          and k != "docker_diff_after"}, indent=1))
        return 0 if ok else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        if not args.keep:
            sh("docker", "rm", "-f", NAME, check=False)


if __name__ == "__main__":
    raise SystemExit(main())
