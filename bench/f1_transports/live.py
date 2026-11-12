#!/usr/bin/env python3
"""Live proof of the AWX/AAP and Salt transports: real hosts (containers), real salt-master / salt-api / salt-ssh /
salt-minions, real ansible-runner behind an AWX REST emulator, and the scan node's own code path
(``python -m zs_scan_node.collect --kind salt_hosts|awx_hosts``, i.e. collectors/fleet.py and transports/*), compared
host by host with the SSH path on the same hosts.

    python bench/f1_transports/live.py --release-dir DIR [--targets 20] [--minions 5] [--out DIR]
        [--build] [--base-image IMG --apt-https] [--keep] [--ssh-max-procs 50]

* ``--targets`` hosts (role target) are collected three ways: the SSH path, Salt with ``client: ssh`` (salt-ssh roster,
  ``cmd.script`` mode) and AWX (job template 42, one launch per 200 hosts).
* ``--minions`` hosts (role minion: a real salt-minion) are collected by the SSH path and by Salt with
  ``client: local_async`` in ``state`` mode (``state.apply zeroshield.zs_collect``).
* The release (binary, manifest, signature) is mounted read-only at /opt/zeroshield/zs-collect on every host (the
  customer's mirror); the launcher, the Salt state and the playbook are rendered from it by
  ``zs_scan_node.transports.wrappers`` exactly as the backend's transport artifacts are.
Every per-host normalised diff (normalize.py) must be empty.  Writes report.json and the raw outputs to ``--out``.
Containers are named ``f1-3-fleet-*`` and removed at the end unless ``--keep``.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "scan_node"))
sys.path.insert(0, str(HERE))

from normalize import diff, normalise  # noqa: E402
from zs_scan_node.transports import wrappers  # noqa: E402

IMAGE = "f1-3-fleet:1"
NETWORK = "f1-3-fleet"
PREFIX = "f1-3-fleet-"
MASTER = PREFIX + "salt"
AWX = PREFIX + "awx"


def sh(*args: str, check: bool = True, **kw) -> subprocess.CompletedProcess:
    p = subprocess.run(list(args), capture_output=True, text=True, **kw)
    if check and p.returncode != 0:
        raise SystemExit(f"{' '.join(args[:5])}...: exit {p.returncode}: {p.stderr[-1500:]}")
    return p


def keypair(path: Path, comment: str) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = ed25519.Ed25519PrivateKey.generate()
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                       serialization.NoEncryption()))
    path.chmod(0o600)
    return key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                         serialization.PublicFormat.OpenSSH).decode() + " " + comment


def build(base: str | None, apt_https: bool) -> None:
    ctx = Path(tempfile.mkdtemp(prefix="f1-3-fleet."))
    try:
        # the image is built FROM the deliberately weak lab target, so its Dockerfile lives with it in the fixtures
        shutil.copy(ROOT / "scan_node" / "tests" / "fixtures" / "zs-collect" / "lab" / "Dockerfile.fleet",
                    ctx / "Dockerfile.fleet")
        for name in ("fleet-entrypoint.sh", "awx_emulator.py"):
            shutil.copy(HERE / "lab" / name, ctx / name)
        args = ["docker", "build", "-q", "-f", str(ctx / "Dockerfile.fleet"), "-t", IMAGE]
        if base:
            args += ["--build-arg", f"BASE_IMAGE={base}"]
        if apt_https or os.environ.get("HTTPS_PROXY"):
            proxy = os.environ.get("HTTPS_PROXY", "")
            args += ["--network", "host", "--build-arg", f"HTTPS_PROXY={proxy}", "--build-arg", f"https_proxy={proxy}"]
        sh(*args, str(ctx))
    finally:
        shutil.rmtree(ctx, ignore_errors=True)


def ip_of(name: str) -> str:
    return sh("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name).stdout.strip()


def run_container(name: str, role: str, env: dict[str, str], mounts: list[str], memory: str) -> None:
    args = ["docker", "run", "-d", "--name", name, "--hostname", name.removeprefix(PREFIX), "--network", NETWORK,
            "--label", "zs-owner=f1-3", "--memory", memory, "-e", f"ZS_ROLE={role}"]
    for k, v in env.items():
        args += ["-e", f"{k}={v}"]
    for m in mounts:
        args += ["-v", m]
    sh(*args, IMAGE)


def wait_port(ip: str, port: int, timeout: float = 120) -> None:
    deadline = time.time() + timeout
    while True:
        try:
            socket.create_connection((ip, port), 2).close()
            return
        except OSError:
            if time.time() > deadline:
                raise SystemExit(f"{ip}:{port} did not open")
            time.sleep(0.5)


def node_collect(kind: str, cfg: dict, secrets_: dict, scope: dict, state: Path, out: Path, tag: str) -> dict:
    files = {}
    for name, data in (("cfg", cfg), ("sec", secrets_), ("scope", scope)):
        files[name] = state / f"{tag}-{name}.json"
        files[name].write_text(json.dumps(data))
    env = {**os.environ, "PYTHONPATH": str(ROOT / "scan_node")}
    t0 = time.monotonic()
    p = sh(sys.executable, "-m", "zs_scan_node.collect", "--kind", kind, "--config", str(files["cfg"]),
           "--secrets", str(files["sec"]), "--scope", str(files["scope"]), "--state-dir", str(state),
           "--out", str(out / f"{tag}.json"), check=False, env=env)
    secs = time.monotonic() - t0
    print(f"{tag}: {p.stdout.strip() or p.stderr.strip()[-400:]} ({secs:.1f}s)")
    doc = json.loads((out / f"{tag}.json").read_text())
    doc["_seconds"] = round(secs, 1)
    return doc


def compare(ref: dict, got: dict, labels: list[str]) -> list[dict]:
    rows = []
    for label in labels:
        a, b = normalise(ref, label), normalise(got, label)
        d = diff(a, b)
        rows.append({"target": label, "ssh_assets": len(a["assets"]), "transport_assets": len(b["assets"]),
                     "diff": d})
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release-dir", required=True)
    ap.add_argument("--public-key", default=str(ROOT / "scan_node" / "zs_collect" / "zs-release-ed25519.pub"))
    ap.add_argument("--targets", type=int, default=20)
    ap.add_argument("--minions", type=int, default=5)
    ap.add_argument("--out", default="live-out")
    ap.add_argument("--build", action="store_true", help="build the fleet image (run under the docker build lock)")
    ap.add_argument("--build-only", action="store_true")
    ap.add_argument("--base-image")
    ap.add_argument("--apt-https", action="store_true")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--ssh-max-procs", type=int, default=50)
    ap.add_argument("--target-memory", default="160m")  # salt-ssh runs a Python salt-call on the host
    # The salt master runs up to --ssh-max-procs salt-ssh processes at once (~70 MB each, measured on the sandbox
    # EC2): a fixed 768 MB was OOM-killed at 50 (salt-api exited 137 and every target failed), so it scales with them.
    ap.add_argument("--master-memory", default=None, help="salt master container memory (default 512m + 80m per "
                                                          "salt-ssh process)")
    ap.add_argument("--awx-forks", type=int, default=10)
    ap.add_argument("--awx-memory", default="1g")
    ap.add_argument("--skip", default="", help="comma list of: salt-ssh, salt-minions, awx")
    args = ap.parse_args()
    if args.build or args.build_only:
        build(args.base_image, args.apt_https)
        if args.build_only:
            return 0
    skip = set(filter(None, args.skip.split(",")))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    release = Path(args.release_dir).resolve()
    manifest_path = next(release.glob("zs-collect-*.manifest.json"))
    manifest = json.loads(manifest_path.read_text())
    pub = Path(args.public_key).read_text()
    sig = (Path(str(manifest_path) + ".sig")).read_text()
    launcher = wrappers.render_wrapper(manifest, pub, sig)
    version = manifest["version"]
    sha = {f["arch"]: f["sha256"] for f in manifest["files"]}
    state = Path(tempfile.mkdtemp(prefix="f1-3-live."))
    names: list[str] = []
    report: dict = {"targets": args.targets, "minions": args.minions, "zs_collect_version": version,
                    "zs_collect_sha256": sha, "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    try:
        node_pub = keypair(state / "id_ed25519", "zs-node")          # ZeroShield's scan node key (SSH path)
        auto_pub = keypair(state / "automation_ed25519", "customer-automation")  # the customer's Ansible/salt-ssh key
        salt_pw = secrets.token_urlsafe(18)
        awx_token = secrets.token_urlsafe(24)
        sh("docker", "network", "create", "--label", "zs-owner=f1-3", NETWORK, check=False)
        mirror = f"{release}:/opt/zeroshield/zs-collect:ro"
        tnames = [f"{PREFIX}t{i:03d}" for i in range(args.targets)]
        mnames = [f"{PREFIX}m{i:03d}" for i in range(args.minions)]
        t0 = time.monotonic()
        run_container(MASTER, "master", {"ZS_SALT_PASSWORD": salt_pw, "ZS_SSH_MAX_PROCS": str(args.ssh_max_procs)},
                      [], args.master_memory or f"{512 + 80 * args.ssh_max_procs}m")
        names.append(MASTER)
        run_container(AWX, "awx", {"ZS_AWX_TOKEN": awx_token, "ZS_AWX_FORKS": str(args.awx_forks)}, [], args.awx_memory)
        names.append(AWX)
        for n in tnames:
            run_container(n, "target", {"ZS_NODE_PUB": node_pub, "ZS_ROOT_PUB": auto_pub}, [mirror], args.target_memory)
            names.append(n)
        for n in mnames:
            run_container(n, "minion", {"ZS_NODE_PUB": node_pub, "ZS_ROOT_PUB": auto_pub, "ZS_SALT_MASTER": MASTER},
                          [mirror], "160m")
            names.append(n)
        ips = {n: ip_of(n) for n in tnames + mnames + [MASTER, AWX]}
        for n in tnames + mnames:
            wait_port(ips[n], 22)
        wait_port(ips[MASTER], 8000)
        wait_port(ips[AWX], 8443)
        report["start_seconds"] = round(time.monotonic() - t0, 1)

        # the customer's side: salt files + roster + key on the master, project + inventory + key on AWX
        salt_files = wrappers.render_salt(version, launcher)
        stage = state / "salt"
        for rel, text in salt_files.items():
            (stage / rel).parent.mkdir(parents=True, exist_ok=True)
            (stage / rel).write_text(text)
        sh("docker", "cp", str(stage / "zeroshield") + "/.", f"{MASTER}:/srv/salt/zeroshield/")
        roster = "".join(f"{n.removeprefix(PREFIX)}:\n  host: {ips[n]}\n  user: root\n  priv: /etc/salt/ssh/id_ed25519\n"
                         for n in tnames)
        (state / "roster").write_text(roster)
        sh("docker", "cp", str(state / "roster"), f"{MASTER}:/etc/salt/roster")
        sh("docker", "cp", str(state / "automation_ed25519"), f"{MASTER}:/etc/salt/ssh/id_ed25519")
        sh("docker", "exec", MASTER, "chmod", "0600", "/etc/salt/ssh/id_ed25519")
        proj = state / "project"
        for rel, text in wrappers.render_ansible(version, launcher).items():
            (proj / rel).parent.mkdir(parents=True, exist_ok=True)
            (proj / rel).write_text(text)
        inv = "[lab]\n" + "".join(f"{n.removeprefix(PREFIX)} ansible_host={ips[n]}\n" for n in tnames) + \
            "[lab:vars]\nansible_user=root\nansible_ssh_private_key_file=/opt/awx-emu/id_ed25519\n" \
            "ansible_python_interpreter=/usr/bin/python3\n"
        (state / "inventory.ini").write_text(inv)
        sh("docker", "cp", str(proj), f"{AWX}:/opt/awx-emu/project")
        sh("docker", "cp", str(state / "inventory.ini"), f"{AWX}:/opt/awx-emu/inventory.ini")
        sh("docker", "cp", str(state / "automation_ed25519"), f"{AWX}:/opt/awx-emu/id_ed25519")
        sh("docker", "exec", AWX, "chmod", "0600", "/opt/awx-emu/id_ed25519")
        salt_ca = sh("docker", "exec", MASTER, "cat", "/etc/zs-tls/api.crt").stdout
        awx_ca = sh("docker", "exec", AWX, "cat", "/etc/zs-tls/api.crt").stdout
        if mnames:  # minions authenticate to the master (auto_accept) and answer test.ping
            deadline = time.time() + 180
            while True:
                up = sh("docker", "exec", MASTER, "/opt/salt/bin/salt", "--out=json", "--static", "-t", "10", "*",
                        "test.ping", check=False).stdout
                try:
                    alive = {k for k, v in json.loads(up or "{}").items() if v is True}
                except ValueError:
                    alive = set()
                if {n.removeprefix(PREFIX) for n in mnames} <= alive:
                    break
                if time.time() > deadline:
                    raise SystemExit(f"minions up: {sorted(alive)}")
                time.sleep(3)

        # 1. the SSH path on every host (the reference)
        all_hosts = tnames + mnames
        labels = {n: ips[n] for n in all_hosts}
        ssh_cfg = {"targets": list(labels.values()), "tier": 2, "credential_type": "node_key", "host_key_policy": "tofu",
                   "parallel": 16, "timeout_s": 300}
        ref = node_collect("linux_servers", ssh_cfg, {}, {"targets": list(labels.values())}, state, out, "ssh-path")
        zs = {"version": version, "sha256": sha}
        results: dict[str, dict] = {"ssh-path": {"seconds": ref["_seconds"], "summary": ref["result"]["summary"]}}

        # 2. Salt over salt-ssh (client: ssh, cmd.script) for the targets
        if "salt-ssh" not in skip and tnames:
            t_labels = [labels[n] for n in tnames]
            cfg = {"targets": t_labels, "handles": {labels[n]: n.removeprefix(PREFIX) for n in tnames}, "tier": 2,
                   "timeout_s": 600, "zs_collect": zs,
                   "transport": {"base_url": f"https://{ips[MASTER]}:8000", "eauth": "pam", "client": "ssh",
                                 "mode": "cmd", "batch_size": 500, "timeout_s": 900, "ca_pem": salt_ca}}
            doc = node_collect("salt_hosts", cfg, {"username": "zs", "password": salt_pw}, {"targets": t_labels},
                               state, out, "salt-ssh")
            rows = compare(ref, doc, t_labels)
            results["salt-ssh"] = {"seconds": doc["_seconds"], "summary": doc["result"]["summary"], "rows": rows}

        # 3. Salt minions (client: local_async, state.apply)
        if "salt-minions" not in skip and mnames:
            m_labels = [labels[n] for n in mnames]
            cfg = {"targets": m_labels, "handles": {labels[n]: n.removeprefix(PREFIX) for n in mnames}, "tier": 2,
                   "timeout_s": 600, "zs_collect": zs,
                   "transport": {"base_url": f"https://{ips[MASTER]}:8000", "eauth": "pam", "client": "local_async",
                                 "mode": "state", "batch_size": 100, "timeout_s": 600, "ca_pem": salt_ca}}
            doc = node_collect("salt_hosts", cfg, {"username": "zs", "password": salt_pw}, {"targets": m_labels},
                               state, out, "salt-minions")
            rows = compare(ref, doc, m_labels)
            results["salt-minions"] = {"seconds": doc["_seconds"], "summary": doc["result"]["summary"], "rows": rows}

        # 4. AWX (job template 42 -> real ansible-runner) for the targets
        if "awx" not in skip and tnames:
            t_labels = [labels[n] for n in tnames]
            cfg = {"targets": t_labels, "handles": {labels[n]: n.removeprefix(PREFIX) for n in tnames}, "tier": 2,
                   "timeout_s": 900, "zs_collect": zs,
                   "transport": {"base_url": f"https://{ips[AWX]}:8443", "job_template_id": 42, "timeout_s": 60,
                                 "max_hosts_per_launch": 200, "ca_pem": awx_ca}}
            doc = node_collect("awx_hosts", cfg, {"token": awx_token}, {"targets": t_labels}, state, out, "awx")
            rows = compare(ref, doc, t_labels)
            stats = sh("docker", "exec", AWX, "/opt/ansible/bin/python", "-c",
                       "import json,ssl,urllib.request as u;"
                       f"r=u.Request('https://127.0.0.1:8443/api/v2/emulator/stats/',headers={{'Authorization':'Bearer {awx_token}'}});"
                       "print(u.urlopen(r,context=ssl._create_unverified_context()).read().decode())", check=False).stdout
            results["awx"] = {"seconds": doc["_seconds"], "summary": doc["result"]["summary"], "rows": rows,
                              "emulator_stats": json.loads(stats or "{}")}

        failures = 0
        for name, r in results.items():
            if "rows" not in r:
                continue
            bad = [row for row in r["rows"] if row["diff"] or not row["transport_assets"]]
            r["hosts"], r["hosts_with_empty_diff"] = len(r["rows"]), len(r["rows"]) - len(bad)
            r["assets"] = sum(row["transport_assets"] for row in r["rows"])
            failures += len(bad)
            print(f"{name}: {r['hosts_with_empty_diff']}/{r['hosts']} hosts with an EMPTY normalised diff vs the SSH "
                  f"path, {r['assets']} assets, {r['seconds']}s; {r['summary']}")
            for row in bad[:5]:
                print(f"  {row['target']}: ssh {row['ssh_assets']} vs {row['transport_assets']}: {row['diff'][:3]}")
        report["results"] = results
        report["failures"] = failures
        (out / "report.json").write_text(json.dumps(report, indent=1))
        print(f"report -> {out / 'report.json'}; failures {failures}")
        return 1 if failures else 0
    finally:
        shutil.rmtree(state, ignore_errors=True)
        if not args.keep:
            with cf.ThreadPoolExecutor(8) as pool:
                list(pool.map(lambda n: sh("docker", "rm", "-f", n, check=False), names))
            sh("docker", "network", "rm", NETWORK, check=False)


if __name__ == "__main__":
    raise SystemExit(main())
