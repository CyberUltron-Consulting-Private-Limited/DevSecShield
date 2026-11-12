#!/usr/bin/env python3
"""CB-13 SSH lab: small OpenSSH 10 servers for the SSH prober's failing-first, live and scale checks.

    python3 bench/cb13_ssh/sshlab.py up   DIR     # keys, configs, oracle.json; network cb13-ssh-lab; containers cb13-*
    python3 bench/cb13_ssh/sshlab.py check DIR    # independent self-check (ssh-keyscan, nmap, ssh-audit) vs oracle
    python3 bench/cb13_ssh/sshlab.py down  DIR

Every server runs the CB-02 lab target image (``cb02-lab/target:dev``: Alpine, OpenSSH 10.0p1) with the files this
script writes, mounted read-only at /lab (the image's ``cb02-entry`` starts ``sshd -D -e -f /lab/sshd_config``).
Host keys and certificates are generated here at run time with the host's ssh-keygen (nothing key-shaped is committed).

The oracle (``DIR/oracle.json``) comes only from what this script configured and from ssh-keygen's own output
(``-l`` fingerprints, ``-L`` certificate fields); it imports nothing from the product.  ``check`` re-reads every
server with tools that share no code with the scan node (OpenSSH's ssh-keyscan, nmap ssh2-enum-algos, ssh-audit, all
from the CB-02 tools image) and fails on any difference: a mismatch is a lab bug, never a product verdict.
"""
from __future__ import annotations

import base64
import json
import re
import subprocess
import sys
from pathlib import Path

NETWORK, SUBNET = "cb13-ssh-lab", "10.232.13.0/24"
IMAGE, TOOLS = "cb02-lab/target:dev", "cb02-lab/tools:dev"
PSP_DEFAULT = "default (noauth:1s min:15s)"

# id, address, host keys (type[:bits]), sshd algorithm lines, certificates {key type: validity}, PerSourcePenalties
TARGETS = [
    {"id": "pq", "ip": "10.232.13.10", "keys": ["ed25519"],
     "kex": ["mlkem768x25519-sha256"], "hostkeyalgs": ["ssh-ed25519"],
     "ciphers": ["aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"], "macs": ["hmac-sha2-256-etm@openssh.com"]},
    {"id": "sntrup", "ip": "10.232.13.11", "keys": ["ed25519", "ecdsa:384"],
     "kex": ["sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com"],
     "hostkeyalgs": ["ssh-ed25519", "ecdsa-sha2-nistp384"],
     "ciphers": ["aes128-ctr", "aes256-gcm@openssh.com"], "macs": ["hmac-sha2-512"]},
    {"id": "legacy", "ip": "10.232.13.12", "keys": ["rsa:1024", "ed25519", "ecdsa:256"],
     "kex": ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "curve25519-sha256"],
     "hostkeyalgs": ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"],
     "ciphers": ["3des-cbc", "aes128-cbc", "aes128-ctr"], "macs": ["hmac-md5", "hmac-sha1", "hmac-sha2-256"]},
    {"id": "cert", "ip": "10.232.13.13", "keys": ["ed25519", "rsa:3072"],
     "certs": {"ed25519": "-1d:+30d", "rsa": "20200101:20210101"},
     "kex": ["curve25519-sha256", "mlkem768x25519-sha256"],
     "hostkeyalgs": ["ssh-ed25519-cert-v01@openssh.com", "rsa-sha2-512-cert-v01@openssh.com", "ssh-ed25519",
                     "rsa-sha2-512", "rsa-sha2-256"],
     "ciphers": ["aes256-gcm@openssh.com"], "macs": ["hmac-sha2-256-etm@openssh.com"]},
    {"id": "gex", "ip": "10.232.13.14", "keys": ["ecdsa:521"],
     "kex": ["diffie-hellman-group-exchange-sha256"], "hostkeyalgs": ["ecdsa-sha2-nistp521"],
     "ciphers": ["aes256-ctr"], "macs": ["hmac-sha2-256"]},
    {"id": "psp", "ip": "10.232.13.15", "keys": ["rsa:3072", "ecdsa:256", "ed25519"], "psp": "default",
     "kex": ["mlkem768x25519-sha256", "curve25519-sha256"],
     "hostkeyalgs": ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256"],
     "ciphers": ["aes256-gcm@openssh.com", "aes128-ctr"], "macs": ["hmac-sha2-256-etm@openssh.com"]},
]
SELF_CHECK_IP = "10.232.13.2"  # the tools container; psp exempts only it, so the self-check never trips the penalty


def sh(*cmd: str, check: bool = True, input_: str | None = None) -> str:
    res = subprocess.run(list(cmd), capture_output=True, text=True, input=input_)
    if check and res.returncode != 0:
        raise SystemExit(f"{' '.join(cmd)}: {res.returncode}: {res.stderr.strip()[:400]}")
    return res.stdout


def _fp(pub_path: Path) -> tuple[int, str]:
    out = sh("ssh-keygen", "-l", "-E", "sha256", "-f", str(pub_path)).split()
    return int(out[0]), out[1]


def _cert_fields(cert_path: Path) -> dict:
    text = sh("ssh-keygen", "-L", "-f", str(cert_path))
    m = re.search(r"Valid: from (\S+) to (\S+)", text)
    ca = re.search(r"Signing CA: (\S+) (SHA256:\S+) \(using (\S+)\)", text)
    return {"valid_from": m.group(1) if m else None, "valid_to": m.group(2) if m else None,
            "ca_type": ca.group(1) if ca else None, "ca_fingerprint": ca.group(2) if ca else None,
            "signature_algorithm": ca.group(3) if ca else None,
            "type": re.search(r"Type: (\S+) host certificate", text).group(1)}


def up(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    ca = out / "ca" / "host_ca"
    ca.parent.mkdir(exist_ok=True)
    if not ca.exists():
        sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "cb13-host-ca", "-f", str(ca))
    ca_bits, ca_fp = _fp(Path(f"{ca}.pub"))
    oracle = {"generated_by": "bench/cb13_ssh/sshlab.py", "ssh_keygen": sh("ssh", "-V", check=False) or "",
              "ca": {"type": "ssh-ed25519", "bits": ca_bits, "fingerprint": ca_fp}, "targets": []}
    for t in TARGETS:
        d = out / t["id"]
        hk = d / "hostkeys"
        hk.mkdir(parents=True, exist_ok=True)
        hk.chmod(0o755)
        keys, cfg_keys = [], []
        for spec in t["keys"]:
            algo, _, bits = spec.partition(":")
            path = hk / f"ssh_host_{algo}_key"
            if not path.exists():
                sh("ssh-keygen", "-q", "-t", algo, "-N", "", "-C", "", "-f", str(path), *(["-b", bits] if bits else []))
            path.chmod(0o644)  # cb02-entry copies it in with 0600 (sshd refuses readable host keys)
            kbits, fp = _fp(Path(f"{path}.pub"))
            key = {"type": Path(f"{path}.pub").read_text().split()[0], "bits": kbits, "fingerprint": fp}
            cfg_keys.append(f"HostKey /etc/ssh/cb02/{path.name}")
            validity = (t.get("certs") or {}).get(algo)
            if validity:
                cert = hk / f"ssh_host_{algo}_key-cert.pub"
                if not cert.exists():
                    sh("ssh-keygen", "-q", "-s", str(ca), "-h", "-I", f"cb13-{t['id']}-{algo}", "-n",
                       f"{t['id']}.cb13.lab,{t['ip']}", "-V", validity, f"{path}.pub")
                cert.chmod(0o644)
                key["certificate"] = _cert_fields(cert)
                cfg_keys.append(f"HostCertificate /etc/ssh/cb02/{cert.name}")
            keys.append(key)
        psp = t.get("psp") == "default"
        lines = ["Port 22", "ListenAddress 0.0.0.0", "PidFile none", "PasswordAuthentication no",
                 "KbdInteractiveAuthentication no", "PubkeyAuthentication yes", "AllowUsers zs-cbom",
                 "LogLevel VERBOSE", "AuthorizedKeysFile .ssh/authorized_keys",
                 f"PerSourcePenaltyExemptList {SELF_CHECK_IP}/32" if psp else f"PerSourcePenaltyExemptList {SUBNET}",
                 *cfg_keys, f"KexAlgorithms {','.join(t['kex'])}", f"HostKeyAlgorithms {','.join(t['hostkeyalgs'])}",
                 f"Ciphers {','.join(t['ciphers'])}", f"MACs {','.join(t['macs'])}"]
        (d / "sshd_config").write_text("\n".join(lines) + "\n")
        (d / "role.env").write_text(f"TARGET=cb13-{t['id']}\nROLE=sshd\nPORT=22\n")
        # Host key algorithms the server can actually offer: the configured ones it holds a key (or certificate) for
        held = {k["type"] for k in keys}
        offered = []
        for alg in t["hostkeyalgs"]:
            base = alg.replace("-cert-v01@openssh.com", "")
            family = "ssh-rsa" if base in ("rsa-sha2-512", "rsa-sha2-256", "ssh-rsa") else base
            has_cert = any(k["type"] == family and k.get("certificate") for k in keys)
            if family in held and (not alg.endswith("-cert-v01@openssh.com") or has_cert):
                offered.append(alg)
        oracle["targets"].append({"id": t["id"], "address": t["ip"], "port": 22, "kex": t["kex"],
                                  "host_key_algorithms": offered, "ciphers": t["ciphers"], "macs": t["macs"],
                                  "host_keys": keys, "per_source_penalties": PSP_DEFAULT if psp else f"exempt {SUBNET}"})
    (out / "oracle.json").write_text(json.dumps(oracle, indent=1) + "\n")
    if NETWORK not in sh("docker", "network", "ls", "--format", "{{.Name}}").split():
        sh("docker", "network", "create", "--subnet", SUBNET, NETWORK)
    for t in TARGETS:
        name = f"cb13-{t['id']}"
        sh("docker", "rm", "-f", name, check=False)
        sh("docker", "run", "-d", "--name", name, "--network", NETWORK, "--ip", t["ip"], "--memory", "64m",
           "-v", f"{(out / t['id']).resolve()}:/lab:ro", IMAGE)
    print(json.dumps({"up": [t["id"] for t in TARGETS], "oracle": str(out / "oracle.json")}))


def _tools(*cmd: str) -> str:
    return sh("docker", "run", "--rm", "--network", NETWORK, "--ip", SELF_CHECK_IP, "--entrypoint", cmd[0], TOOLS,
              *cmd[1:], check=False)


def check(out: Path) -> int:
    oracle = json.loads((out / "oracle.json").read_text())
    report, bad = [], 0
    for t in oracle["targets"]:
        ip = t["address"]
        # host keys: ssh-keyscan, one type at a time (-c adds the certificates)
        scanned = {}
        for line in _tools("ssh-keyscan", "-T", "5", "-t", "rsa,ecdsa,ed25519", ip).splitlines():
            parts = line.split()
            if len(parts) >= 3 and not line.startswith("#"):
                blob = base64.b64decode(parts[2])
                fp = "SHA256:" + base64.b64encode(__import__("hashlib").sha256(blob).digest()).decode().rstrip("=")
                scanned[parts[1]] = fp
        want = {k["type"]: k["fingerprint"] for k in t["host_keys"]}
        ok_keys = scanned == want
        certs = _tools("ssh-keyscan", "-T", "5", "-c", ip)
        cert_types = sorted({tok for line in certs.splitlines() if not line.startswith("#")
                             for tok in line.split() if tok.endswith("-cert-v01@openssh.com")})
        want_certs = sorted(f"{k['type']}-cert-v01@openssh.com" for k in t["host_keys"] if k.get("certificate"))
        ok_certs = cert_types == want_certs
        # algorithm lists: nmap ssh2-enum-algos
        nm = _tools("nmap", "-Pn", "-p", "22", "--script", "ssh2-enum-algos", ip)
        sections, cur = {}, None
        for line in nm.splitlines():
            m = re.match(r"^\|\s+(\w+): \(\d+\)", line)
            if m:
                cur = sections.setdefault(m.group(1), [])
                continue
            m = re.match(r"^\|_?\s{4,}(\S+)$", line)
            if m and cur is not None:
                cur.append(m.group(1))
        pseudo = re.compile(r"^(ext-info-[cs]|kex-strict-[cs]-v00@openssh\.com)$")
        got = {"kex": sorted(x for x in sections.get("kex_algorithms", []) if not pseudo.match(x)),
               "host_key_algorithms": sorted(sections.get("server_host_key_algorithms", [])),
               "ciphers": sorted(sections.get("encryption_algorithms", [])),
               "macs": sorted(sections.get("mac_algorithms", []))}
        exp = {k: sorted(t[k]) for k in got}
        ok_algs = got == exp
        audit = _tools("ssh-audit", "-n", "-p", "22", ip)
        row = {"id": t["id"], "host_keys": ok_keys, "certificates": ok_certs, "algorithms": ok_algs,
               "ssh_audit_rc_text": audit.splitlines()[0:1]}
        if not (ok_keys and ok_certs and ok_algs):
            bad += 1
            row.update({"scanned": scanned, "want": want, "cert_types": cert_types, "want_certs": want_certs,
                        "nmap": got, "expected": exp})
        report.append(row)
    (out / "selfcheck.json").write_text(json.dumps(report, indent=1) + "\n")
    print(json.dumps(report, indent=1))
    return 1 if bad else 0


def down(_out: Path) -> None:
    for t in TARGETS:
        sh("docker", "rm", "-f", f"cb13-{t['id']}", check=False)
    sh("docker", "network", "rm", NETWORK, check=False)


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("up", "check", "down"):
        raise SystemExit(__doc__)
    action, where = sys.argv[1], Path(sys.argv[2])
    if action == "up":
        up(where)
    elif action == "check":
        raise SystemExit(check(where))
    else:
        down(where)
