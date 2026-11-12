#!/usr/bin/env python3
"""Parity proof: the SSH path and zs-collect give the same assets on the same hosts.

    python bench/f1_transports/parity.py --release-dir DIR --count 20 [--readonly-check] [--keep]
        [--base-image IMG --apt-https] [--out DIR]

1. Builds ``f1-3-lab-target`` (scan_node/tests/fixtures/zs-collect/lab/Dockerfile.target: a deliberately weak host,
   so it lives with the other detector fixtures; lab/entrypoint.sh; the exact zs-cbom sudoers file from
   zs_scan_node.commands)
   and starts ``--count`` containers ``f1-3-parity-<i>`` on network ``f1-3-parity``, each with its own host keys.
2. SSH path: ``python -m zs_scan_node.collect --kind linux_servers`` (Tier 2, node key, trust on first use) against
   every container address, from this machine, exactly as a scan node runs it.
3. zs-collect path: copies the signed release (binary, manifest, signature) to /opt/zeroshield/zs-collect in each
   container and runs the generated launcher as root (``docker exec``): sha256 + signature check, drop to zs-cbom,
   collect, print the zs-collect/1 document.
4. Normalises both (normalize.py) per target and diffs them; ``--readonly-check`` also runs zs-collect in a copy of
   the first target started with a read-only root file system (``--read-only --tmpfs /tmp --tmpfs /run``) and
   compares it with the writable run.
Exit 0 only when every diff is empty.  Writes report.json and the raw documents to ``--out``.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
LAB_DOCKERFILE = ROOT / "scan_node" / "tests" / "fixtures" / "zs-collect" / "lab" / "Dockerfile.target"
sys.path.insert(0, str(ROOT / "scan_node"))
sys.path.insert(0, str(HERE))

from normalize import diff, normalise  # noqa: E402
from zs_scan_node import commands as C  # noqa: E402

IMAGE = "f1-3-lab-target:1"
NETWORK = "f1-3-parity"
PREFIX = "f1-3-parity-"


def sh(*args: str, check: bool = True, **kw) -> subprocess.CompletedProcess:
    p = subprocess.run(list(args), capture_output=True, text=True, **kw)
    if check and p.returncode != 0:
        raise SystemExit(f"{' '.join(args[:4])}...: exit {p.returncode}: {p.stderr[-800:]}")
    return p


def build_image(base: str | None, apt_https: bool) -> None:
    ctx = Path(tempfile.mkdtemp(prefix="f1-3-lab."))
    try:
        shutil.copy(LAB_DOCKERFILE, ctx / "Dockerfile")
        shutil.copy(HERE / "lab" / "entrypoint.sh", ctx / "entrypoint.sh")
        (ctx / "sudoers.zs-cbom").write_text(C.sudoers_file("zs-cbom"))
        args = ["docker", "build", "-q", "-t", IMAGE]
        if base:
            args += ["--build-arg", f"BASE_IMAGE={base}"]
        if apt_https:
            proxy = os.environ.get("HTTPS_PROXY", "")
            args += ["--build-arg", "APT_HTTPS=1", "--network", "host", "--build-arg", f"HTTPS_PROXY={proxy}",
                     "--build-arg", f"https_proxy={proxy}"]
        sh(*args, str(ctx))
    finally:
        shutil.rmtree(ctx, ignore_errors=True)


def node_key(state: Path) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = ed25519.Ed25519PrivateKey.generate()
    path = state / "id_ed25519"
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                       serialization.NoEncryption()))
    path.chmod(0o600)
    pub = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    return pub.decode() + " zs-node-parity"


def start_targets(count: int, pub: str) -> list[tuple[str, str]]:
    sh("docker", "network", "create", "--label", "zs-owner=f1-3", NETWORK, check=False)
    out = []
    for i in range(count):
        name = f"{PREFIX}{i:02d}"
        sh("docker", "run", "-d", "--name", name, "--hostname", f"lab-{i:02d}", "--network", NETWORK,
           "--label", "zs-owner=f1-3", "--memory", "64m", "-e", f"ZS_NODE_PUB={pub}", IMAGE)
        out.append(name)
    addrs = []
    for name in out:
        ip = sh("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name).stdout.strip()
        addrs.append((name, ip))
    deadline = time.time() + 60
    for _name, ip in addrs:
        while True:
            try:
                socket.create_connection((ip, 22), 2).close()
                break
            except OSError:
                if time.time() > deadline:
                    raise SystemExit(f"sshd on {ip} did not start")
                time.sleep(0.5)
    return addrs


def ssh_path(addrs: list[tuple[str, str]], state: Path, out: Path) -> dict:
    cfg, scope = state / "cfg.json", state / "scope.json"
    ips = [ip for _n, ip in addrs]
    cfg.write_text(json.dumps({"targets": ips, "tier": 2, "credential_type": "node_key", "host_key_policy": "tofu",
                               "parallel": 8, "timeout_s": 300}))
    scope.write_text(json.dumps({"targets": ips}))
    env = {**os.environ, "PYTHONPATH": str(ROOT / "scan_node")}
    t0 = time.monotonic()
    p = sh(sys.executable, "-m", "zs_scan_node.collect", "--kind", "linux_servers", "--config", str(cfg),
           "--scope", str(scope), "--state-dir", str(state), "--out", str(out / "ssh-path.json"), check=False, env=env)
    print(f"SSH path: {p.stdout.strip()} ({time.monotonic() - t0:.1f}s)")
    return json.loads((out / "ssh-path.json").read_text())


def install_release(name: str, release: Path, wrapper: Path) -> None:
    sh("docker", "exec", name, "mkdir", "-p", "/opt/zeroshield/zs-collect")
    for f in release.iterdir():
        if f.name.startswith("zs-collect-"):
            sh("docker", "cp", str(f), f"{name}:/opt/zeroshield/zs-collect/{f.name}")
    sh("docker", "cp", str(wrapper), f"{name}:/usr/local/sbin/zs-collect-run")


def zs_collect(name: str, label: str, nonce: str) -> tuple[dict, float]:
    t0 = time.monotonic()
    p = sh("docker", "exec", name, "/bin/sh", "/usr/local/sbin/zs-collect-run", "--nonce", nonce, "--tier", "2",
           "--label", label, check=False)
    if p.returncode not in (0, 1):
        raise SystemExit(f"zs-collect on {name}: exit {p.returncode}: {p.stderr[-800:]}")
    return json.loads(p.stdout), time.monotonic() - t0


def readonly_copy(name: str) -> str:
    """The first target, committed (same files and host keys), restarted with a read-only root file system."""
    image = "f1-3-lab-target:ro"
    sh("docker", "commit", name, image)
    ro = f"{PREFIX}ro"
    # tmpfs counts against the container's memory: the binary copy and its unpacked modules live in /tmp here
    sh("docker", "run", "-d", "--name", ro, "--network", NETWORK, "--label", "zs-owner=f1-3", "--memory", "256m",
       "--read-only", "--tmpfs", "/tmp:rw,exec,mode=1777", "--tmpfs", "/run:rw,mode=0755", image)
    time.sleep(2)
    return ro


def _without_docker_dns(norm: dict) -> dict:
    for a in norm["assets"]:
        listening = (a.get("facts") or {}).get("listening")
        if isinstance(listening, list):
            a["facts"]["listening"] = sorted((s for s in listening if s.get("address") != "127.0.0.11"),
                                             key=lambda s: json.dumps(s, sort_keys=True))
    return norm


def teardown(names: list[str]) -> None:
    for name in names:
        sh("docker", "rm", "-f", name, check=False)
    sh("docker", "network", "rm", NETWORK, check=False)
    sh("docker", "image", "rm", "f1-3-lab-target:ro", check=False)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release-dir", required=True, help="binary, manifest and .sig from zs_collect/build.sh")
    ap.add_argument("--public-key", default=str(ROOT / "scan_node" / "zs_collect" / "zs-release-ed25519.pub"))
    ap.add_argument("--count", type=int, default=20)
    ap.add_argument("--out", default="parity-out")
    ap.add_argument("--base-image")
    ap.add_argument("--apt-https", action="store_true")
    ap.add_argument("--readonly-check", action="store_true")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--build-only", action="store_true", help="build the lab image and stop (run it under the build lock)")
    ap.add_argument("--skip-build", action="store_true", help="use the lab image already built")
    args = ap.parse_args()
    if args.build_only:
        build_image(args.base_image, args.apt_https)
        return 0
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    release = Path(args.release_dir)
    manifest = next(release.glob("zs-collect-*.manifest.json"))
    wrapper = out / "zs-collect-run.sh"
    sh(sys.executable, str(ROOT / "scan_node" / "zs_collect" / "release.py"), "wrapper", "--public", args.public_key,
       "--out", str(wrapper), str(manifest))
    if not args.skip_build:
        build_image(args.base_image, args.apt_https)
    state = Path(tempfile.mkdtemp(prefix="f1-3-node."))
    names: list[str] = []
    report: dict = {"targets": [], "count": args.count}
    try:
        addrs = start_targets(args.count, node_key(state))
        names = [n for n, _ip in addrs]
        ssh_doc = ssh_path(addrs, state, out)
        for name, _ip in addrs:
            install_release(name, release, wrapper)
        nonce = "parity-" + os.urandom(8).hex()
        t0 = time.monotonic()
        with cf.ThreadPoolExecutor(max_workers=4) as pool:
            docs = dict(zip([n for n, _ in addrs], pool.map(lambda a: zs_collect(a[0], a[1], nonce), addrs)))
        zs_wall = time.monotonic() - t0
        failures = 0
        for name, ip in addrs:
            doc, secs = docs[name]
            (out / f"zs-collect-{name}.json").write_text(json.dumps(doc, indent=1))
            a, b = normalise(ssh_doc, ip), normalise(doc, ip)
            # the normalised pair on disk, so `diff -u normalised-ssh-X.json normalised-zs-X.json` can be re-run
            (out / f"normalised-ssh-{name}.json").write_text(json.dumps(a, indent=1, sort_keys=True) + "\n")
            (out / f"normalised-zs-{name}.json").write_text(json.dumps(b, indent=1, sort_keys=True) + "\n")
            d = diff(a, b)
            failures += bool(d) or not a["assets"]
            report["targets"].append({"container": name, "address": ip, "ssh_assets": len(a["assets"]),
                                      "zs_collect_assets": len(b["assets"]), "nonce_echoed": doc["run_nonce"] == nonce,
                                      "zs_collect_seconds": round(secs, 1), "diff": d})
            print(f"{name} {ip}: ssh {len(a['assets'])} assets, zs-collect {len(b['assets'])}, "
                  f"diff {'EMPTY' if not d else str(len(d)) + ' lines'}")
        report["zs_collect_wall_seconds"] = round(zs_wall, 1)
        if args.readonly_check:
            ro = readonly_copy(addrs[0][0])
            names.append(ro)
            doc_rw, _ = zs_collect(addrs[0][0], addrs[0][1], nonce)
            doc_ro, _ = zs_collect(ro, addrs[0][1], nonce)
            (out / "zs-collect-readonly.json").write_text(json.dumps(doc_ro, indent=1))
            # two containers: Docker's embedded DNS resolver listens on 127.0.0.11 at a random port in each one
            d = diff(_without_docker_dns(normalise(doc_rw, addrs[0][1])), _without_docker_dns(normalise(doc_ro, addrs[0][1])))
            report["readonly_root"] = {"status": doc_ro["status"], "assets": len(doc_ro["assets"]), "diff": d}
            failures += bool(d) or doc_ro["status"] != "success"
            print(f"read-only root fs: {doc_ro['status']}, {len(doc_ro['assets'])} assets, diff "
                  f"{'EMPTY' if not d else d[:5]}")
        report["failures"] = failures
        (out / "report.json").write_text(json.dumps(report, indent=1))
        print(f"{args.count} targets, {failures} with a non-empty diff -> {out / 'report.json'}")
        return 1 if failures else 0
    finally:
        shutil.rmtree(state, ignore_errors=True)
        if not args.keep:
            teardown(names)


if __name__ == "__main__":
    raise SystemExit(main())
