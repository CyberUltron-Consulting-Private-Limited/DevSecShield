#!/usr/bin/env python3
"""CB-02 lab generator: writes every lab target AND its oracle in one step, from the same values (DEVILS-ADVOCATE §3).

Runs inside the cb02-lab/tools image (OpenSSL 3.5, ssh-keygen, keytool, SoftHSM, pkcs11-tool); the host CLI
`gen.py up` starts it with the run directory mounted at --out. Standard library only; imports nothing from the product.

    python3 labgen.py --out /run [--now 2026-11-12T08:00:00Z] [--profiles core,db,...] [--variant z02-3des]

Output, inside the run directory (layout agreed with CB-01 in cbom/INTERFACES.md):
    lab/targets/<id>/           the files the target container mounts read-only at /lab
    lab/secrets/                0700: the operator SSH key the self-check logs in with
    lab/gen.json                run id, `now`, tool versions, profiles and targets generated
    oracle/facts/<id>.json      per-target facts, each section naming the tool output it was taken from
    oracle/facts/index.json     every target: kind, profile, address, container, facts file
    oracle/run1.json            the same facts as CB-01 judges them (oraclefmt.py), oracle/canaries.json
    lab/lab.json                what CB-01 needs to drive the customer flow (addresses, names, sources)

Every date is relative to `now`, so an oracle never rots. Values that come from a tool's own output (fingerprints,
certificate fields, keytool listings) are copied from that output, never retyped.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import labspec as S  # noqa: E402  (sibling modules; the lab has no package)
import oraclefmt  # noqa: E402

GEN_VERSION = "cb02-gen/1"
VARIANTS = {
    # Deliberately broken labs for the self-check's failing-first proofs (CB-02 exit F).
    "z02-3des": "z02 also asks for TLS_RSA_WITH_3DES_EDE_CBC_SHA, which Alpine's OpenSSL 3.5 does not build",
    "z01-unpinned": "z01 leaves the group list at OpenSSL 3.5's default, which includes X25519MLKEM768",
}


class Gen:
    def __init__(self, out: Path, now: dt.datetime, run_id: str, variant: str | None, cache: Path | None):
        self.out, self.now, self.run_id, self.variant, self.cache = out, now, run_id, variant, cache
        self.canaries: list[dict] = []
        self.versions: dict[str, str] = {}
        self.tmp = Path(tempfile.mkdtemp(prefix="cb02-gen-"))

    # ---------------------------------------------------------------- helpers
    def sh(self, *cmd: str, env: dict | None = None, cwd: Path | None = None, input_: bytes | None = None) -> str:
        res = subprocess.run(list(cmd), capture_output=True, env={**os.environ, **(env or {})}, cwd=cwd,
                             input=input_, check=False)
        if res.returncode != 0:
            raise SystemExit(f"gen: {cmd[0]} failed ({res.returncode}): {res.stderr.decode(errors='replace')[-800:]}")
        return res.stdout.decode(errors="replace")

    def when(self, days: int) -> dt.datetime:
        return self.now + dt.timedelta(days=days)

    @staticmethod
    def asn1_time(t: dt.datetime) -> str:
        return t.strftime("%Y%m%d%H%M%SZ")

    @staticmethod
    def iso(t: dt.datetime) -> str:
        return t.strftime("%Y-%m-%dT%H:%M:%SZ")

    def tdir(self, target_id: str) -> Path:
        d = self.out / "lab" / "targets" / target_id
        d.mkdir(parents=True, exist_ok=True)
        d.chmod(0o755)
        return d

    def write(self, path: Path, text: str | bytes, mode: int = 0o644) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, str):
            path.write_text(text, encoding="utf-8")
        else:
            path.write_bytes(text)
        path.chmod(mode)
        return path

    def secret(self, kind: str, label: str, allowed: list[str], nbytes: int = 18) -> str:
        """A random lab secret. It is also written to lab/secrets/<label>.txt, the canary's positive control."""
        value = "cb02" + secrets.token_hex(nbytes)
        control = self.out / "lab" / "secrets" / f"{label}.txt"
        self.write(control, value + "\n", 0o600)
        rel = str(control.relative_to(self.out))
        self.canaries.append({"id": label, "kind": "string", "secret_kind": kind, "value": value,
                              "allowed": ["oracle/canaries.json", rel, *allowed], "control": rel})
        return value

    def key_canary(self, label: str, path: Path, allowed: list[str]) -> None:
        rel = str(path.relative_to(self.out))
        self.canaries.append({"id": label, "kind": "private_key", "pem_path": rel,
                              "allowed": ["oracle/canaries.json", rel, *allowed], "control": rel})

    def provenance(self, tool: str, commands: list[str]) -> dict:
        return {"tool": tool, "version": self.versions.get(tool.split()[0], ""), "commands": commands,
                "generated_at": self.iso(self.now), "generator": f"{S.GENERATOR} {GEN_VERSION}"}

    # ---------------------------------------------------------------- tool versions
    def collect_versions(self) -> None:
        def first(cmd: list[str]) -> str:
            try:
                r = subprocess.run(cmd, capture_output=True, check=False)
            except FileNotFoundError:
                return "missing"
            return (r.stdout or r.stderr).decode(errors="replace").strip().splitlines()[0] if (r.stdout or r.stderr) else ""
        self.versions = {
            "openssl": first(["openssl", "version"]),
            "ssh-keygen": first(["ssh", "-V"]),
            "keytool": first(["java", "-version"]),
            "softhsm2-util": first(["softhsm2-util", "--version"]),
            "pkcs11-tool": first(["sh", "-c", "pkcs11-tool --help 2>&1 | head -1"]),
            "python": sys.version.split()[0],
        }

    # ---------------------------------------------------------------- keys and certificates
    def genkey(self, spec: str, path: Path) -> list[str]:
        algo, _, param = spec.partition(":")
        cmd = ["openssl", "genpkey", "-out", str(path)]
        if algo == "rsa":
            cmd += ["-algorithm", "RSA", "-pkeyopt", f"rsa_keygen_bits:{param}"]
        elif algo == "ec":
            cmd += ["-algorithm", "EC", "-pkeyopt", f"ec_paramgen_curve:{param}"]
        else:  # ML-DSA-44/65/87, SLH-DSA-*: OpenSSL 3.5 algorithm names
            cmd += ["-algorithm", spec]
        self.sh(*cmd)
        path.chmod(0o644)  # throw-away lab key, mounted read-only into an unprivileged container
        return [" ".join(cmd[:2] + cmd[4:])]

    def ca(self) -> tuple[Path, Path]:
        d = self.out / "lab" / "targets" / "_ca"
        crt, key = d / "ca.pem", d / "ca.key"
        if crt.exists():
            return crt, key
        d.mkdir(parents=True, exist_ok=True)
        self.genkey("rsa:2048", key)
        self.sh("openssl", "req", "-new", "-x509", "-key", str(key), "-out", str(crt), "-sha256",
                "-subj", f"/O=ZeroShield CBOM lab/CN=CBOM Lab Targets CA {self.run_id}",
                "-not_before", self.asn1_time(self.when(-2)), "-not_after", self.asn1_time(self.when(3650)),
                "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        crt.chmod(0o644)
        self.key_canary("targets-ca-key", key, ["lab/targets/_ca/ca.key"])
        return crt, key

    def cert(self, spec: dict, cn: str, sans: list[str], key: Path, crt: Path) -> list[str]:
        """Issue a certificate for `key` as `spec` says (issuer self|ca, digest, relative dates)."""
        nb = self.asn1_time(self.when(spec["not_before"]))
        na = self.asn1_time(self.when(spec["not_after"]))
        san = ",".join(f"DNS:{s}" for s in sans) or f"DNS:{cn}"
        digest = [] if spec["sig"].startswith(("ML-DSA", "SLH-DSA")) else [f"-{spec['sig']}"]
        if spec["issuer"] == "self":
            cmd = ["openssl", "req", "-new", "-x509", "-key", str(key), "-out", str(crt), *digest, "-subj", f"/CN={cn}",
                   "-not_before", nb, "-not_after", na, "-addext", f"subjectAltName={san}",
                   "-addext", "basicConstraints=critical,CA:FALSE"]
            self.sh(*cmd)
            used = [" ".join(cmd[:3] + digest + ["-subj", f"/CN={cn}", "-not_before", nb, "-not_after", na])]
        else:
            ca_crt, ca_key = self.ca()
            csr = self.tmp / f"{cn}.csr"
            ext = self.tmp / f"{cn}.ext"
            ext.write_text(f"[v3]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                           f"extendedKeyUsage=serverAuth\nsubjectAltName={san}\n")
            self.sh("openssl", "req", "-new", "-key", str(key), "-out", str(csr), "-subj", f"/CN={cn}")
            cmd = ["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_crt), "-CAkey", str(ca_key), "-out", str(crt),
                   *digest, "-set_serial", str(int.from_bytes(secrets.token_bytes(8), "big")), "-not_before", nb,
                   "-not_after", na, "-extfile", str(ext), "-extensions", "v3"]
            self.sh(*cmd)
            used = [f"openssl x509 -req -CA targets-ca {' '.join(digest)} -not_before {nb} -not_after {na}"]
        crt.chmod(0o644)
        return used

    def cert_facts(self, crt: Path) -> dict:
        """Certificate fields as `openssl x509` (the tool that wrote the file) prints them."""
        text = self.sh("openssl", "x509", "-in", str(crt), "-noout", "-text", "-nameopt", "RFC2253")
        head = self.sh("openssl", "x509", "-in", str(crt), "-noout", "-subject", "-issuer", "-serial", "-dates",
                       "-fingerprint", "-sha256", "-nameopt", "RFC2253", "-dateopt", "iso_8601")
        f = dict(line.split("=", 1) for line in head.splitlines() if "=" in line)
        der = base64.b64decode("".join(ln for ln in crt.read_text().splitlines() if ln and not ln.startswith("-----")))
        sha = hashlib.sha256(der).hexdigest()
        if f.get("sha256 Fingerprint", "").replace(":", "").lower() != sha:
            raise SystemExit(f"gen: openssl fingerprint of {crt} disagrees with the DER hash")
        m_sig = re.search(r"Signature Algorithm: (\S+)", text)
        m_pk = re.search(r"Public Key Algorithm: (\S+)", text)
        m_bits = re.search(r"Public-Key: \((\d+) bit\)", text)
        m_curve = re.search(r"NIST CURVE: (\S+)", text)
        m_san = re.search(r"Subject Alternative Name:.*?\n\s+(.+)", text)
        key_alg = m_pk.group(1) if m_pk else ""
        family = {"rsaEncryption": "RSA", "id-ecPublicKey": "EC"}.get(key_alg, key_alg)
        return {
            "sha256": sha,
            "subject": f.get("subject", ""), "issuer": f.get("issuer", ""),
            "serial": f.get("serial", "").lower(),
            "not_before": self.iso_from_openssl(f.get("notBefore", "")),
            "not_after": self.iso_from_openssl(f.get("notAfter", "")),
            "signature_algorithm": m_sig.group(1) if m_sig else "",
            "key_algorithm": family,
            "key_bits": int(m_bits.group(1)) if m_bits else None,
            "curve": m_curve.group(1) if m_curve else None,
            "san": [s.strip().removeprefix("DNS:") for s in m_san.group(1).split(",")] if m_san else [],
            "self_issued": f.get("subject") == f.get("issuer"),
        }

    @staticmethod
    def iso_from_openssl(value: str) -> str:
        # "2026-11-11 08:00:00Z" (iso_8601 dateopt)
        return value.strip().replace(" ", "T")

    # ---------------------------------------------------------------- targets
    def tls_target(self, t: dict) -> dict:
        t = json.loads(json.dumps(t))
        if self.variant == "z02-3des" and t["id"] == "z02":
            t["suites"].append("TLS_RSA_WITH_3DES_EDE_CBC_SHA")
        if self.variant == "z01-unpinned" and t["id"] == "z01":
            t["pin_groups"] = False
        d = self.tdir(t["id"])
        cn = f"{t['id']}.lab" if not t["sni"] else t["sni"][0]
        sans = sorted({cn, f"{t['id']}.lab", *t["sni"]})
        key, crt = d / "key.pem", d / "cert.pem"
        cmds = self.genkey(t["cert"]["key"], key) + self.cert(t["cert"], cn, sans, key, crt)
        self.key_canary(f"{t['id']}-key", key, [f"lab/targets/{t['id']}/key.pem"])
        facts = self.cert_facts(crt)
        chain = [facts]
        if t["cert"]["issuer"] == "ca":
            # nginx and s_server serve leaf + issuing CA; the oracle names both, leaf first.
            ca_crt, _ = self.ca()
            (d / "chain.pem").write_text(crt.read_text() + ca_crt.read_text())
            (d / "chain.pem").chmod(0o644)
            chain.append(self.cert_facts(ca_crt))
        served = "chain.pem" if t["cert"]["issuer"] == "ca" else "cert.pem"

        ossl_suites = ":".join(S.SUITES[s] for s in t["suites"])
        if t["seclevel"] is not None:
            ossl_suites += f":@SECLEVEL={t['seclevel']}"
        ossl_groups = ":".join(S.GROUPS[g] for g in t["groups"])
        tls13 = ":".join(S.TLS13_SUITES)
        expansion = ""
        if ossl_suites:
            expansion = self.sh("sh", "-c", f"openssl ciphers -stdname '{ossl_suites}' 2>/dev/null || true")

        if t["server"] == "nginx":
            protocols = " ".join(S.NGINX_PROTOCOL[v] for v in t["versions"])
            lines = ["worker_processes 1;", "pid /tmp/nginx.pid;", "error_log stderr notice;",
                     "events { worker_connections 128; }", "http {",
                     "  access_log /dev/stdout;", "  client_body_temp_path /tmp/nginx-body;",
                     "  proxy_temp_path /tmp/nginx-proxy;", "  fastcgi_temp_path /tmp/nginx-fastcgi;",
                     "  uwsgi_temp_path /tmp/nginx-uwsgi;", "  scgi_temp_path /tmp/nginx-scgi;",
                     f"  ssl_protocols {protocols};", "  ssl_prefer_server_ciphers on;",
                     f"  ssl_conf_command Ciphersuites {tls13};"]
            if ossl_suites:
                lines.append(f"  ssl_ciphers '{ossl_suites}';")
            if t["pin_groups"] and ossl_groups:
                lines.append(f"  ssl_ecdh_curve {ossl_groups};")
            elif not t["pin_groups"]:
                lines.append("  ssl_ecdh_curve auto;  # variant: OpenSSL's default group list")
            vhost = [f"    ssl_certificate /lab/{served};", "    ssl_certificate_key /lab/key.pem;",
                     f"    location / {{ return 200 'cb02 {t['id']}\\n'; }}"]
            if t["sni_required"]:
                lines += ["  server {", "    listen 443 ssl default_server;", "    ssl_reject_handshake on;", "  }"]
                for name in t["sni"]:
                    lines += ["  server {", "    listen 443 ssl;", f"    server_name {name};", *vhost, "  }"]
            else:
                lines += ["  server {", "    listen 443 ssl default_server;", "    server_name _;", *vhost, "  }"]
            lines.append("}")
            self.write(d / "nginx.conf", "\n".join(lines) + "\n")
            server_cmd = "nginx -c /lab/nginx.conf"
        else:
            args = ["-accept", "443", "-cert", f"/lab/{'cert.pem'}", "-key", "/lab/key.pem", "-www",
                    *[S.S_SERVER_PROTOCOL[v] for v in t["versions"]], "-ciphersuites", tls13]
            if t["cert"]["issuer"] == "ca":
                args += ["-cert_chain", "/lab/_ca.pem"]
                shutil.copy(self.ca()[0], d / "_ca.pem")
                (d / "_ca.pem").chmod(0o644)
            if ossl_suites:
                args += ["-cipher", ossl_suites]
            if t["pin_groups"] and ossl_groups:
                args += ["-groups", ossl_groups]
            self.write(d / "s_server.args", "\n".join(args) + "\n")
            server_cmd = "openssl s_server " + " ".join(args)
        self.write(d / "role.env", f"TARGET={t['id']}\nROLE={t['server'] if t['server'] == 'nginx' else 's_server'}\n"
                                   f"PORT={t['port']}\n")

        expect = {
            "versions": {v: v in t["versions"] for v in S.VERSIONS},
            "suites": {v: sorted(t["suites"]) for v in t["versions"] if v != "TLSv1.3"},
            "tls13_suites": sorted(S.TLS13_SUITES) if "TLSv1.3" in t["versions"] else [],
            "groups": sorted(t["groups"]) if t["pin_groups"] else None,
            "sni_required": t["sni_required"], "sni_names": t["sni"],
            "certificates": chain,
        }
        if not t["pin_groups"]:
            expect["groups_note"] = "variant z01-unpinned: groups as requested by the lab designer"
            expect["groups"] = sorted(t["groups"])
        return self.oracle(t, expect, {
            "certificates": self.provenance("openssl x509", cmds),
            "versions": self.provenance("openssl", [server_cmd]),
            "suites": {**self.provenance("openssl", [server_cmd]), "openssl_expansion": expansion.splitlines()},
        }, aliases=[f"{t['id']}.lab", *t["sni"]])

    def ssh_keys(self, d: Path, specs: list[str]) -> tuple[list[dict], list[str]]:
        hk = d / "hostkeys"
        hk.mkdir(exist_ok=True)
        hk.chmod(0o755)
        keys, cmds = [], []
        for spec in specs:
            algo, _, bits = spec.partition(":")
            path = hk / f"ssh_host_{algo}_key"
            cmd = ["ssh-keygen", "-q", "-t", algo, "-N", "", "-C", "", "-f", str(path)] + (["-b", bits] if bits else [])
            self.sh(*cmd)
            path.chmod(0o644)  # cb02-entry copies it to 0600 inside the container (sshd refuses readable host keys)
            fp = self.sh("ssh-keygen", "-l", "-E", "sha256", "-f", f"{path}.pub").split()
            pub = (Path(f"{path}.pub")).read_text().split()
            keys.append({"type": pub[0], "bits": int(fp[0]), "fingerprint_sha256": fp[1], "public_key": pub[1]})
            cmds.append(" ".join(cmd[:-2]) + (f" -b {bits}" if bits else ""))
            self.key_canary(f"{d.name}-hostkey-{algo}", path, [f"lab/targets/{d.name}/hostkeys/{path.name}"])
        return keys, cmds

    def sshd_config(self, t: dict, d: Path) -> None:
        # PerSourcePenalties (OpenSSH >= 9.8) stays at its default for everyone but the self-check's address: its
        # keyscan/nmap/ssh-audit probes never authenticate and would otherwise get its later login dropped.
        lines = ["Port 22", "ListenAddress 0.0.0.0", "PidFile none", "StrictModes yes",
                 f"PerSourcePenaltyExemptList {S.TOOLS_IP}/32",
                 "PasswordAuthentication no", "KbdInteractiveAuthentication no", "PubkeyAuthentication yes",
                 "AuthorizedKeysFile .ssh/authorized_keys", "AllowUsers zs-cbom", "LogLevel VERBOSE",
                 "Subsystem sftp internal-sftp", "PermitUserEnvironment no", "X11Forwarding no",
                 "AllowTcpForwarding no",
                 *[f"HostKey /etc/ssh/cb02/ssh_host_{s.partition(':')[0]}_key" for s in t["host_keys"]],
                 f"KexAlgorithms {','.join(t['kex'])}", f"HostKeyAlgorithms {','.join(t['host_key_algorithms'])}",
                 f"Ciphers {','.join(t['ciphers'])}", f"MACs {','.join(t['macs'])}"]
        if t.get("force_command"):
            lines.append("ForceCommand /usr/local/bin/cb02-forcecommand")
        self.write(d / "sshd_config", "\n".join(lines) + "\n")
        self.write(d / "role.env", f"TARGET={t['id']}\nROLE=sshd\nPORT={t['port']}\n")

    def ssh_target(self, t: dict) -> dict:
        d = self.tdir(t["id"])
        keys, cmds = self.ssh_keys(d, t["host_keys"])
        self.sshd_config(t, d)
        expect = {"kex": t["kex"], "host_key_algorithms": t["host_key_algorithms"], "ciphers": t["ciphers"],
                  "macs": t["macs"], "host_keys": keys,
                  "pq_kex": [k for k in t["kex"] if k.startswith(("mlkem", "sntrup"))]}
        return self.oracle(t, expect, {"host_keys": self.provenance("ssh-keygen", cmds),
                                       "algorithms": self.provenance("ssh-keygen", ["sshd_config written by gen.py"])},
                           aliases=[f"{t['id']}.lab"])

    def host_target(self, t: dict) -> dict:
        oracle = self.ssh_target(t)
        d = self.out / "lab" / "targets" / t["id"]
        # Operator key: the self-check logs in with it (positive control of the ForceCommand logger).
        sec = self.out / "lab" / "secrets"
        op = sec / "operator_ed25519"
        if not op.exists():
            self.sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"cb02-operator-{self.run_id}", "-f", str(op))
            op.chmod(0o600)
        self.write(d / "authorized_keys", Path(f"{op}.pub").read_text())
        plant = d / "plant"
        files, modes = [], []
        for p in t["plant"]:
            path = plant / p["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            entry: dict = {"path": f"/srv/cbom-lab/{p['path']}", "mode": p["mode"]}
            if p["make"] == "rsa_key":
                self.genkey(f"rsa:{p['bits']}", path)
                entry.update(kind="private_key", key_algorithm="RSA", key_bits=p["bits"], encrypted=False,
                             spki_sha256=self.spki_sha256(path))
                self.key_canary(f"host-{path.name}", path, [f"lab/targets/host/plant/{p['path']}", entry["path"]])
            elif p["make"] == "cert":
                key = self.tmp / f"{path.name}.key"
                self.genkey(p["key"], key)
                self.cert(p, path.stem + ".lab", [], key, path)
                entry.update(kind="certificate", certificate=self.cert_facts(path))
            elif p["make"] in ("pkcs12", "jks"):
                entry.update(self.keystore(p, path))
            path.chmod(0o644)  # inside the container cb02-entry applies `mode` (plant.modes)
            entry["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            files.append(entry)
            modes.append(f"{p['mode']} {p['path']}")
        self.write(d / "plant.modes", "\n".join(modes) + "\n")
        oracle["expect"]["files"] = files
        oracle["expect"]["login"] = {"user": "zs-cbom", "force_command_logger": True,
                                     "command_log": "/var/log/cb02/commands.log (and the container log, prefix cb02-cmd)"}
        oracle["provenance"]["files"] = self.provenance("openssl", ["see certificate/keystore sections"])
        return self.save_oracle(oracle)

    def spki_sha256(self, key: Path) -> str:
        der = subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout", "-outform", "DER"], capture_output=True,
                             check=True).stdout
        return hashlib.sha256(der).hexdigest()

    def keystore(self, p: dict, path: Path) -> dict:
        """PKCS#12 / JKS built with keytool; the oracle entries are parsed from `keytool -list -v` of the result."""
        storetype = "PKCS12" if p["make"] == "pkcs12" else "JKS"
        pw = self.secret("keystore_password", f"host-{path.name}-storepass", ["lab/targets/host/**"])
        env = {"CB02_STOREPASS": pw, "HOME": str(self.tmp)}
        cmds = []
        for e in p["entries"]:
            algo, _, bits = e["key"].partition(":")
            nb = self.when(e["not_before"])
            days = max(1, e["not_after"] - e["not_before"])
            sigalg = {"sha256": f"SHA256with{algo.upper()}", "sha1": f"SHA1with{algo.upper()}"}[e["sig"]]
            if e["type"] == "PrivateKeyEntry":
                cmd = ["keytool", "-genkeypair", "-storetype", storetype, "-keystore", str(path),
                       "-storepass:env", "CB02_STOREPASS", "-alias", e["alias"], "-keyalg", algo.upper(),
                       "-keysize", bits, "-sigalg", sigalg, "-dname", f"CN={e['alias']}.lab",
                       "-startdate", nb.strftime("%Y/%m/%d %H:%M:%S"), "-validity", str(days)]
                if storetype == "JKS":
                    cmd += ["-keypass:env", "CB02_STOREPASS"]
                self.sh(*cmd, env=env)
            else:
                # A trusted certificate: an openssl-made self-signed cert imported into the store.
                key, crt = self.tmp / f"{e['alias']}.key", self.tmp / f"{e['alias']}.crt"
                self.genkey(e["key"], key)
                self.cert({**e, "issuer": "self"}, f"{e['alias']}.lab", [], key, crt)
                cmd = ["keytool", "-importcert", "-noprompt", "-storetype", storetype, "-keystore", str(path),
                       "-storepass:env", "CB02_STOREPASS", "-alias", e["alias"], "-file", str(crt)]
                self.sh(*cmd, env=env)
            cmds.append(" ".join(c for c in cmd if not c.startswith(str(self.tmp))))
        listing = self.sh("keytool", "-list", "-v", "-storetype", storetype, "-keystore", str(path),
                          "-storepass:env", "CB02_STOREPASS", env=env)
        return {"kind": "keystore", "storetype": storetype, "password_protected": True,
                "entries": parse_keytool(listing), "provenance": self.provenance("keytool", cmds)}

    def listener_target(self, t: dict) -> dict:
        d = self.tdir(t["id"])
        self.write(d / "role.env", f"TARGET={t['id']}\nROLE=listener\nPORT={t['port']}\n")
        expect = {"role": t["role"], "aliases": t["aliases"],
                  "product_connections": 0 if t["role"] == "canary" else ">=1",
                  "accept_log": f"lab/listeners/{t['id']}.jsonl", 
                  "excluded_sources": [S.TOOLS_IP, "127.0.0.1"]}
        return self.oracle(t, expect, {"listener": self.provenance("socat", ["socat -d -d TCP-LISTEN:443,fork"])},
                           aliases=t["aliases"])

    def postgres_target(self, t: dict) -> dict:
        d = self.tdir(t["id"])
        initdb = d / "initdb"
        initdb.mkdir(exist_ok=True)
        initdb.chmod(0o755)
        su = self.secret("db_password", f"{t['id']}-postgres", [f"lab/targets/{t['id']}/pg.env"])
        reader = self.secret("db_password", f"{t['id']}-cbom_reader", [f"lab/targets/{t['id']}/initdb/10-roles.sql"])
        md5pw = self.secret("db_password", f"{t['id']}-cbom_md5", [f"lab/targets/{t['id']}/initdb/10-roles.sql"])
        self.write(d / "pg.env", f"POSTGRES_PASSWORD={su}\n", 0o644)
        self.write(initdb / "10-roles.sql",
                   "SET password_encryption = 'md5';\n"
                   f"CREATE ROLE cbom_md5 LOGIN PASSWORD '{md5pw}';\n"
                   "SET password_encryption = 'scram-sha-256';\n"
                   f"CREATE ROLE cbom_reader LOGIN PASSWORD '{reader}';\n"
                   "GRANT pg_read_all_settings TO cbom_reader;\n"
                   "CREATE EXTENSION IF NOT EXISTS pgcrypto;\n")
        if t["tls"]:
            hba = [("local", "all", "all", "", "trust"), ("hostssl", "all", "cbom_md5", "0.0.0.0/0", "md5"),
                   ("hostssl", "all", "all", "0.0.0.0/0", "scram-sha-256"), ("host", "all", "all", "0.0.0.0/0", "reject")]
        else:
            hba = [("local", "all", "all", "", "trust"), ("host", "all", "all", "0.0.0.0/0", "scram-sha-256")]
        self.write(d / "pg_hba.conf", "\n".join("  ".join(x for x in row if x) for row in hba) + "\n")
        args = ["-c", "listen_addresses=*", "-c", "hba_file=/tmp/cb02/pg_hba.conf", "-c", "log_connections=on",
                "-c", "password_encryption=scram-sha-256"]
        setup = ["install -d -o postgres -g postgres -m 0700 /tmp/cb02",
                 "install -o postgres -g postgres -m 0600 /lab/pg_hba.conf /tmp/cb02/pg_hba.conf"]
        expect: dict = {"ssl": "on" if t["tls"] else "off",
                        "hba": [{"type": r[0], "database": r[1], "user": r[2], "address": r[3] or None, "method": r[4]}
                                for r in hba],
                        "roles": {"cbom_md5": "md5", "cbom_reader": "SCRAM-SHA-256"}, "extensions": ["pgcrypto"]}
        prov = {"config": self.provenance("openssl", ["pg_hba.conf and start.sh written by gen.py"])}
        if t["tls"]:
            key, crt = d / "server.key", d / "server.crt"
            cmds = self.genkey(t["cert"]["key"], key) + self.cert(t["cert"], f"{t['id']}.lab", [f"{t['id']}.lab"], key, crt)
            self.key_canary(f"{t['id']}-key", key, [f"lab/targets/{t['id']}/server.key"])
            shutil.copy(self.ca()[0], d / "ca.pem")
            setup += ["install -o postgres -g postgres -m 0600 /lab/server.key /tmp/cb02/server.key",
                      "install -o postgres -g postgres -m 0644 /lab/server.crt /tmp/cb02/server.crt"]
            args += ["-c", "ssl=on", "-c", "ssl_cert_file=/tmp/cb02/server.crt", "-c", "ssl_key_file=/tmp/cb02/server.key",
                     "-c", "ssl_min_protocol_version=TLSv1.2"]
            expect["tls"] = {"versions": {"TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True},
                             "certificates": [self.cert_facts(crt)]}
            prov["certificates"] = self.provenance("openssl x509", cmds)
        else:
            args += ["-c", "ssl=off"]
        self.write(d / "start.sh", "#!/bin/sh\n# generated by gen.py: copy config with the owner and mode postgres "
                                   "insists on, then the image's own entrypoint\nset -eu\n" + "\n".join(setup) +
                   "\nexec docker-entrypoint.sh postgres " + " ".join(args) + "\n", 0o755)
        return self.oracle(t, expect, prov, aliases=[f"{t['id']}.lab"])

    def mysql_target(self, t: dict) -> dict:
        d = self.tdir(t["id"])
        initdb = d / "initdb"
        initdb.mkdir(exist_ok=True)
        initdb.chmod(0o755)
        root = self.secret("db_password", f"{t['id']}-root", [f"lab/targets/{t['id']}/mysql.env"])
        native = self.secret("db_password", f"{t['id']}-cbom_native", [f"lab/targets/{t['id']}/initdb/10-users.sql"])
        reader = self.secret("db_password", f"{t['id']}-cbom_reader", [f"lab/targets/{t['id']}/initdb/10-users.sql"])
        self.write(d / "mysql.env", f"MYSQL_ROOT_PASSWORD={root}\n", 0o644)
        self.write(initdb / "10-users.sql",
                   f"CREATE USER 'cbom_native'@'%' IDENTIFIED WITH mysql_native_password BY '{native}';\n"
                   f"CREATE USER 'cbom_reader'@'%' IDENTIFIED WITH caching_sha2_password BY '{reader}';\n"
                   "GRANT PROCESS, SHOW DATABASES ON *.* TO 'cbom_reader'@'%';\n")
        args = ["--performance-schema=OFF", "--innodb-buffer-pool-size=16M", "--innodb-log-buffer-size=1M",
                "--key-buffer-size=1M", "--max-connections=30", "--table-open-cache=64", "--skip-name-resolve",
                "--mysql-native-password=ON", "--require-secure-transport=OFF"]
        expect: dict = {"users": {"cbom_native": "mysql_native_password", "cbom_reader": "caching_sha2_password"}}
        prov = {"config": self.provenance("openssl", ["start.sh written by gen.py"])}
        if t["tls"]:
            key, crt = d / "server.key", d / "server.crt"
            cmds = self.genkey(t["cert"]["key"], key) + self.cert(t["cert"], f"{t['id']}.lab", [f"{t['id']}.lab"], key, crt)
            self.key_canary(f"{t['id']}-key", key, [f"lab/targets/{t['id']}/server.key"])
            shutil.copy(self.ca()[0], d / "ca.pem")
            (d / "ca.pem").chmod(0o644)
            args += ["--ssl-ca=/lab/ca.pem", "--ssl-cert=/lab/server.crt", "--ssl-key=/lab/server.key",
                     "--tls-version=TLSv1.2,TLSv1.3"]
            expect["tls_version"] = "TLSv1.2,TLSv1.3"
            expect["tls"] = {"ssl_supported": True, "certificates": [self.cert_facts(crt)]}
            prov["certificates"] = self.provenance("openssl x509", cmds)
        else:
            args += ["--tls-version="]
            expect["tls_version"] = ""
            expect["tls"] = {"ssl_supported": False}
        self.write(d / "start.sh", "#!/bin/sh\n# generated by gen.py\nset -eu\nexec docker-entrypoint.sh mysqld " +
                   " ".join(args) + "\n", 0o755)
        return self.oracle(t, expect, prov, aliases=[f"{t['id']}.lab"])

    def softhsm_target(self, t: dict) -> dict:
        d = self.tdir(t["id"])
        tokens = d / "tokens"
        tokens.mkdir(exist_ok=True)
        lib = "/usr/lib/softhsm/libsofthsm2.so"
        conf_gen = self.tmp / "softhsm2.conf"
        conf_gen.write_text(f"directories.tokendir = {tokens}\nobjectstore.backend = file\nlog.level = ERROR\n")
        self.write(d / "softhsm2.conf", "# mount targets/softhsm at /lab (read-write copy: SoftHSM locks token files)\n"
                                        "directories.tokendir = /lab/tokens\nobjectstore.backend = file\nlog.level = ERROR\n")
        env = {"SOFTHSM2_CONF": str(conf_gen)}
        out_tokens, cmds = [], []
        for tok in t["tokens"]:
            pin = self.secret("hsm_pin", f"softhsm-{tok['label']}-pin", ["lab/targets/softhsm/**"], 9)
            so = self.secret("hsm_so_pin", f"softhsm-{tok['label']}-so-pin", ["lab/targets/softhsm/**"], 9)
            self.sh("softhsm2-util", "--init-token", "--free", "--label", tok["label"], "--so-pin", so, "--pin", pin, env=env)
            cmds.append(f"softhsm2-util --init-token --free --label {tok['label']}")
            for i, o in enumerate(tok["objects"], start=1):
                base = ["pkcs11-tool", "--module", lib, "--token-label", tok["label"], "--login", "--pin", pin,
                        "--label", o["label"], "--id", f"{i:02x}", "--key-type", o["key_type"]]
                flags = ["--sensitive"] + (["--extractable"] if o["extractable"] else [])
                cmd = base + (["--keypairgen"] if o["make"] == "keypair" else ["--keygen"]) + flags
                self.sh(*cmd, env=env)
                cmds.append(" ".join(c for c in cmd if c != pin).replace("--pin", "--pin <canary>"))
            listing = self.sh("pkcs11-tool", "--module", lib, "--token-label", tok["label"], "--login", "--pin", pin,
                              "--list-objects", env=env)
            out_tokens.append({"label": tok["label"], "objects": parse_pkcs11_objects(listing),
                               "requested": tok["objects"]})
        for p in tokens.rglob("*"):
            p.chmod(0o755 if p.is_dir() else 0o644)
        expect = {"module": "SoftHSM 2.6 (libsofthsm2.so)", "tokens": out_tokens,
                  "pin_spray_canary": t["tokens"][1]["label"]}
        return self.oracle(t, expect, {"objects": self.provenance("pkcs11-tool", cmds)})

    def code_target(self, t: dict) -> dict:
        if not self.cache:
            raise SystemExit("gen: the code target needs --cache with the CryptoAPI-Bench checkout (lab.sh fetch)")
        src = self.cache / f"cryptoapi-bench-{t['commit'][:7]}"
        head = (src / ".cb02-commit").read_text().strip() if (src / ".cb02-commit").exists() else ""
        if head != t["commit"]:
            raise SystemExit(f"gen: {src} is at {head or 'unknown'}, not the pinned {t['commit']}")
        d = self.tdir(t["id"])
        tree = d / "cryptoapi-bench"
        if tree.exists():
            shutil.rmtree(tree)
        shutil.copytree(src, tree, ignore=shutil.ignore_patterns(".git", ".cb02-commit"))
        files = sorted(p for p in tree.rglob("*") if p.is_file())
        zpath = d / f"cryptoapi-bench-{t['commit'][:7]}.zip"
        with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
            for p in files:  # fixed timestamps and order: the archive is byte-for-byte reproducible
                info = zipfile.ZipInfo(str(p.relative_to(d)), date_time=(2019, 9, 12, 0, 0, 0))
                info.external_attr = 0o644 << 16
                z.writestr(info, p.read_bytes(), zipfile.ZIP_DEFLATED)
        labels_path = tree / t["labels_file"]
        labels = read_xlsx_labels(labels_path)
        java = {p.name: str(p.relative_to(tree)) for p in tree.rglob("*.java")}
        cases = []
        for row in labels:
            paths = [java.get(f) for f in row["files"]]
            cases.append({**row, "paths": paths, "resolved": all(paths),
                          "sha256": [hashlib.sha256((tree / r).read_bytes()).hexdigest() if r else None for r in paths]})
        expect = {"commit": t["commit"], "labels_sha256": hashlib.sha256(labels_path.read_bytes()).hexdigest(),
                  "archive": zpath.name, "archive_sha256": hashlib.sha256(zpath.read_bytes()).hexdigest(),
                  "java_files": len(java), "cases": cases,
                  "summary": {"labelled": len(cases), "vulnerable": sum(1 for c in cases if c["vulnerable"] is True),
                              "secure": sum(1 for c in cases if c["vulnerable"] is False),
                              "unlabelled": sorted(f for c in cases if c["vulnerable"] is None for f in c["files"]),
                              "unresolved": sorted(f for c in cases for f, r in zip(c["files"], c["paths"]) if not r),
                              "java_files_without_label": sorted(set(java) - {f for c in cases for f in c["files"]})}}
        return self.oracle(t, expect, {"cases": {"tool": "CryptoAPI-Bench_details.xlsx (the benchmark's own labels)",
                                                 "version": t["commit"], "url": t["repo"],
                                                 "generated_at": self.iso(self.now)}})

    # ---------------------------------------------------------------- oracle files
    def oracle(self, t: dict, expect: dict, provenance: dict, aliases: list[str] | None = None) -> dict:
        o = {"schema": S.SCHEMA_ORACLE, "run_id": self.run_id, "target": t["id"], "kind": t["kind"],
             "profile": t["profile"], "world": t["world"], "purpose": t.get("purpose", ""),
             "address": t.get("ip"), "port": t.get("port"), "aliases": aliases or [],
             "container": f"cb02-{t['id']}" if t.get("ip") else None,
             "variant": self.variant if self.variant and self.variant.startswith(t["id"]) else None,
             "expect": expect, "provenance": provenance}
        return self.save_oracle(o)

    def save_oracle(self, o: dict) -> dict:
        self.write(self.out / "oracle" / "facts" / f"{o['target']}.json", json.dumps(o, indent=1, sort_keys=True) + "\n")
        return o


def mutate_run2(out: Path, now: dt.datetime, commit: str) -> int:
    """Apply S.RUN2_CHANGES to the generated lab files and write the run-2 facts and oracle (O-5: a new oracle file,
    hashed before run 2 starts). The containers are restarted by the host CLI (mutate.py)."""
    run1 = {p.stem: json.loads(p.read_text()) for p in (out / "oracle" / "facts").glob("*.json") if p.stem != "index"}
    if (out / "oracle" / "run2").exists():
        raise SystemExit("gen: run 2 already generated for this run directory")
    gen1 = json.loads((out / "lab" / "gen.json").read_text())
    g = Gen(out, now, gen1["run_id"], None, None)
    g.collect_versions()
    g.canaries = json.loads((out / "oracle" / "canaries.json").read_text())["canaries"]
    facts = json.loads(json.dumps(run1))
    drift: list[dict] = []
    try:
        for ch in S.RUN2_CHANGES:
            tid = ch["target"]
            if ch["change"] == "disable_version":
                t = json.loads(json.dumps(S.by_id(tid)))
                t["versions"] = [v for v in t["versions"] if v != ch["version"]]
                conf = out / "lab" / "targets" / tid / "nginx.conf"
                protocols = " ".join(S.NGINX_PROTOCOL[v] for v in t["versions"])
                conf.write_text(re.sub(r"ssl_protocols [^;]+;", f"ssl_protocols {protocols};", conf.read_text()))
                e = facts[tid]["expect"]
                e["versions"][ch["version"]] = False
                e["suites"].pop(ch["version"], None)
                drift.append({"change": "resolved", "code": "PROTO_TLS10", "location": f"{t['ip']}:{t['port']}"})
            elif ch["change"] == "reissue_cert":
                t = S.by_id(tid)
                d = out / "lab" / "targets" / tid
                spec = {**t["cert"], **S.VALID}
                cn = f"{tid}.lab"
                g.genkey(spec["key"], d / "key.pem")
                g.cert(spec, cn, sorted({cn}), d / "key.pem", d / "cert.pem")
                ca_crt, _ = g.ca()
                (d / "chain.pem").write_text((d / "cert.pem").read_text() + ca_crt.read_text())
                facts[tid]["expect"]["certificates"][0] = g.cert_facts(d / "cert.pem")
                loc = f"{t['ip']}:{t['port']}"
                drift += [{"change": "cert_renewed", "location": loc,
                           "old_sha256": run1[tid]["expect"]["certificates"][0]["sha256"],
                           "new_sha256": facts[tid]["expect"]["certificates"][0]["sha256"]},
                          {"change": "resolved", "code": "CERT_EXPIRED", "location": loc}]
            elif ch["change"] == "remove_file":
                d = out / "lab" / "targets" / tid
                (d / "plant" / ch["path"]).unlink()
                modes = d / "plant.modes"
                modes.write_text("".join(ln + "\n" for ln in modes.read_text().splitlines() if not ln.endswith(" " + ch["path"])))
                full = f"/srv/cbom-lab/{ch['path']}"
                facts[tid]["expect"]["files"] = [f for f in facts[tid]["expect"]["files"] if f["path"] != full]
                drift.append({"change": "removed_asset", "asset_type": "private_key", "location": S.by_id(tid)["ip"],
                              "path": full})
            elif ch["change"] == "start":
                o = g.tls_target(S.by_id(tid))
                facts[tid] = o
                if ch.get("replaces"):
                    facts.pop(ch["replaces"], None)
                drift.append({"change": "new_asset", "asset_type": "tls_endpoint", "location": f"{o['address']}:{o['port']}"})
    finally:
        shutil.rmtree(g.tmp, ignore_errors=True)
    # tls_target() saved z08 / control-tls into oracle/facts (run 1): move them to the run-2 facts only.
    for ch in S.RUN2_CHANGES:
        if ch["change"] == "start":
            (out / "oracle" / "facts" / f"{ch['target']}.json").unlink(missing_ok=True)
    fdir = out / "oracle" / "run2" / "facts"
    fdir.mkdir(parents=True)
    for tid, o in sorted(facts.items()):
        o = {**o, "run_step": "run2"}
        g.write(fdir / f"{tid}.json", json.dumps(o, indent=1, sort_keys=True) + "\n")
    index = [{k: o.get(k) for k in ("target", "kind", "profile", "world", "address", "port", "aliases", "container",
                                    "variant")} | {"facts": f"oracle/run2/facts/{tid}.json"} for tid, o in sorted(facts.items())]
    g.write(fdir / "index.json", json.dumps({"schema": S.SCHEMA_INDEX, "run_id": gen1["run_id"], "step": "run2",
                                             "now": g.iso(now), "targets": index}, indent=1, sort_keys=True) + "\n")
    flist = [facts[k] for k in sorted(facts)]
    _, by_target = oraclefmt.sources_for(flist)
    run2 = oraclefmt.run_oracle(flist, "run2", g.iso(now), commit, gen1.get("profiles", ["core"])[0], by_target)
    run2["drift"] = drift
    run2["changes"] = S.RUN2_CHANGES
    g.write(out / "oracle" / "run2.json", json.dumps(run2, indent=1, sort_keys=True, ensure_ascii=False) + "\n")
    g.write(out / "oracle" / "canaries.json", json.dumps(oraclefmt.canaries_json(g.canaries), indent=1) + "\n", 0o600)
    g.write(out / "lab" / "lab-run2.json", json.dumps(oraclefmt.lab_json(flist, g.iso(now), commit, "run2", S.NETWORK,
                                                                        S.NODE_IP), indent=1, sort_keys=True,
                                                         ensure_ascii=False) + "\n")
    print(f"gen: run 2 change set applied ({len(drift)} drift rows)")
    return 0


def parse_keytool(listing: str) -> list[dict]:
    """Entries of `keytool -list -v`: alias, entry type, key algorithm and size, signature, validity, SHA-256."""
    entries = []
    for block in re.split(r"\n\*{40,}\n", listing):
        m_alias = re.search(r"^Alias name: (.+)$", block, re.M)
        if not m_alias:
            continue
        e = {"alias": m_alias.group(1).strip()}
        m = re.search(r"^Entry type: (\S+)", block, re.M)
        e["type"] = m.group(1) if m else ""
        m = re.search(r"^Subject Public Key Algorithm: (\d+)-bit (\S+) key", block, re.M)
        e["key_bits"], e["key_algorithm"] = (int(m.group(1)), m.group(2)) if m else (None, "")
        m = re.search(r"^Signature algorithm name: (\S+)", block, re.M)
        e["signature_algorithm"] = m.group(1) if m else ""
        m = re.search(r"^Valid from: (.+) until: (.+)$", block, re.M)
        e["valid_from"], e["valid_until"] = (m.group(1).strip(), m.group(2).strip()) if m else ("", "")
        m = re.search(r"SHA256: ([0-9A-F:]+)", block)
        e["cert_sha256"] = m.group(1).replace(":", "").lower() if m else ""
        m = re.search(r"^Owner: (.+)$", block, re.M)
        e["owner"] = m.group(1).strip() if m else ""
        entries.append(e)
    return sorted(entries, key=lambda x: x["alias"])


def parse_pkcs11_objects(listing: str) -> list[dict]:
    """Objects of `pkcs11-tool --list-objects` (OpenSC): class, key type, label, ID, usage and access flags."""
    objs = []
    for block in re.split(r"\n(?=\S)", listing.strip()):
        m = re.match(r"(Private Key|Public Key|Secret Key) Object; (\S+?)(?:\s+(\d+) bits)?\s*$", block.splitlines()[0])
        if not m:
            m2 = re.match(r"(Private Key|Public Key|Secret Key) Object; (\S+)", block.splitlines()[0])
            if not m2:
                continue
            m = m2
        o = {"class": m.group(1), "key_type": m.group(2).rstrip(";"), "bits": None}
        mb = re.search(r"(\d+) bits", block.splitlines()[0])
        if mb:
            o["bits"] = int(mb.group(1))
        mb = re.search(r"EC_POINT\s+(\d+) bits", block)
        if mb:
            o["bits"] = int(mb.group(1))
        mb = re.search(r"length (\d+)", block.splitlines()[0])
        if mb:  # secret keys: CKA_VALUE_LEN in bytes
            o["bits"] = 8 * int(mb.group(1))
        mu = re.search(r"Usage:\s+(.+)", block)
        o["usage"] = sorted(u.strip() for u in mu.group(1).split(",")) if mu else []
        ml = re.search(r"label:\s+(.+)", block)
        o["label"] = ml.group(1).strip() if ml else ""
        mi = re.search(r"ID:\s+(\S+)", block)
        o["id"] = mi.group(1) if mi else ""
        ma = re.search(r"Access:\s+(.+)", block)
        access = [a.strip() for a in ma.group(1).split(",")] if ma else []
        o["access"] = sorted(access)
        o["extractable"] = "extractable" in access
        o["sensitive"] = "sensitive" in access
        objs.append(o)
    return sorted(objs, key=lambda x: (x["label"], x["class"]))


def read_xlsx_labels(path: Path) -> list[dict]:
    """The CryptoAPI-Bench label sheet, read with the standard library (an .xlsx is a zip of XML parts)."""
    import xml.etree.ElementTree as ET
    ns = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    with zipfile.ZipFile(path) as z:
        shared = []
        if "xl/sharedStrings.xml" in z.namelist():
            for si in ET.fromstring(z.read("xl/sharedStrings.xml")).findall("m:si", ns):
                shared.append("".join(x.text or "" for x in si.iter(f"{{{ns['m']}}}t")))
        sheet = ET.fromstring(z.read("xl/worksheets/sheet1.xml"))
    rows = []
    for row in sheet.iter(f"{{{ns['m']}}}row"):
        cells: dict[str, str] = {}
        for c in row.findall("m:c", ns):
            col = re.match(r"[A-Z]+", c.get("r", "")).group(0)
            v, f = c.find("m:v", ns), c.find("m:f", ns)
            text = ""
            if c.get("t") == "s" and v is not None:
                text = shared[int(v.text)]
            elif c.get("t") == "inlineStr":
                text = "".join(x.text or "" for x in c.iter(f"{{{ns['m']}}}t"))
            elif c.get("t") == "b" and v is not None:
                text = "TRUE" if v.text == "1" else "FALSE"
            elif f is not None and (f.text or "").upper() in ("TRUE()", "FALSE()"):
                text = (f.text or "").upper().rstrip("()")
            elif v is not None:
                text = v.text or ""
            cells[col] = text.strip()
        rows.append(cells)
    out, group = [], ""
    for cells in rows[1:]:
        if cells.get("A"):
            group = cells["A"]
        # One case may span several classes: the cell lists them one per line, sometimes without ".java".
        names = [n.strip() for n in cells.get("B", "").splitlines() if n.strip()]
        if not names:
            continue
        flag = cells.get("D", "").upper()
        vulnerable = (True if flag.startswith("TRUE") or flag == "1" else
                      False if flag.startswith("FALSE") or flag == "0" else None)
        out.append({"files": [n if n.endswith(".java") else n + ".java" for n in names], "code": cells.get("C", ""),
                    "group": group, "vulnerable": vulnerable, "label_raw": cells.get("D", ""),
                    "type": cells.get("E", ""), "method": cells.get("F", ""), "lines_raw": cells.get("G", "")})
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--now", help="UTC time all relative dates hang off (default: now)")
    ap.add_argument("--run-id")
    ap.add_argument("--profiles", default="core")
    ap.add_argument("--only", help="comma-separated target ids")
    ap.add_argument("--variant", choices=sorted(VARIANTS))
    ap.add_argument("--cache", type=Path)
    ap.add_argument("--commit", default="unknown", help="git commit of the lab code (written into the oracle)")
    ap.add_argument("--wave", default="core")
    ap.add_argument("--mutate", choices=["run2"])
    a = ap.parse_args(argv)
    if a.mutate:
        now = (dt.datetime.fromisoformat(a.now.replace("Z", "+00:00")) if a.now
               else dt.datetime.now(dt.timezone.utc)).replace(microsecond=0)
        return mutate_run2(a.out, now, a.commit)
    problems = S.validate_catalogue()
    if problems:
        raise SystemExit("gen: catalogue problems: " + "; ".join(problems))
    now = (dt.datetime.fromisoformat(a.now.replace("Z", "+00:00")) if a.now
           else dt.datetime.now(dt.timezone.utc)).replace(microsecond=0)
    run_id = a.run_id or "lab-" + now.strftime("%Y%m%dT%H%M%SZ")
    out: Path = a.out
    for sub in ("oracle/facts", "lab/targets"):
        if (out / sub).exists() and any((out / sub).iterdir()):
            raise SystemExit(f"gen: {out / sub} is not empty; an oracle is generated once per run (rule O-5)")
    (out / "lab" / "secrets").mkdir(parents=True, exist_ok=True)
    (out / "lab" / "secrets").chmod(0o700)
    g = Gen(out, now, run_id, a.variant, a.cache)
    g.collect_versions()
    profiles = set(a.profiles.split(","))
    only = set(a.only.split(",")) if a.only else None
    makers = {"tls": g.tls_target, "ssh": g.ssh_target, "host": g.host_target, "listener": g.listener_target,
              "postgres": g.postgres_target, "mysql": g.mysql_target, "softhsm": g.softhsm_target,
              "code": g.code_target}
    facts, index = [], []
    try:
        for t in S.TARGETS:
            if t["profile"] not in profiles or (only and t["id"] not in only):
                continue
            o = makers[t["kind"]](t)
            facts.append(o)
            index.append({k: o[k] for k in ("target", "kind", "profile", "world", "address", "port", "aliases",
                                            "container", "variant")} | {"facts": f"oracle/facts/{o['target']}.json"})
    finally:
        shutil.rmtree(g.tmp, ignore_errors=True)
    # Shared lab files: the targets CA (lab/ca.pem, also what database sources trust), live logs the containers write.
    ca = out / "lab" / "targets" / "_ca" / "ca.pem"
    if ca.exists():
        shutil.copy(ca, out / "lab" / "ca.pem")
        (out / "lab" / "ca.pem").chmod(0o644)
    (out / "lab" / "listeners").mkdir(exist_ok=True)
    (out / "lab" / "listeners").chmod(0o777)  # written by the unprivileged listener containers (uid 10001)
    fc = out / "lab" / "forcecommand.log"
    fc.touch()
    fc.chmod(0o666)
    iso = g.iso(now)
    g.write(out / "oracle" / "facts" / "index.json", json.dumps(
        {"schema": S.SCHEMA_INDEX, "run_id": run_id, "now": iso, "network": S.NETWORK, "node_ip": S.NODE_IP,
         "tools_ip": S.TOOLS_IP, "variant": a.variant, "targets": index}, indent=1, sort_keys=True) + "\n")
    g.write(out / "lab" / "gen.json", json.dumps(
        {"run_id": run_id, "now": iso, "generator": f"{S.GENERATOR} {GEN_VERSION}", "commit": a.commit,
         "tools": g.versions, "profiles": sorted(profiles), "variant": a.variant,
         "variant_note": VARIANTS.get(a.variant or ""), "targets": [i["target"] for i in index]},
        indent=1, sort_keys=True) + "\n")
    oraclefmt.write_all(out, facts, g.canaries, step="run1", generated_at=iso, commit=a.commit, wave=a.wave,
                        network=S.NETWORK, node_ip=S.NODE_IP)
    print(f"gen: {len(index)} targets, run {run_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
