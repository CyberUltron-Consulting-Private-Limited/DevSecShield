"""CB-02 independent self-check (DEVILS-ADVOCATE §3 O-3, O-5, O-8): every running lab target is measured with tools
that share no code with the scan node's collectors, and compared with the oracle gen.py wrote.

Runs on the host (stdlib only) and drives the tools through `docker exec cb02-tools ...`:
  TLS versions, TLS 1.3 groups, served certificates  tlscheck (Go crypto/tls)    [node: OpenSSL s_client + cryptography]
  TLS <= 1.2 cipher suites                            nmap ssl-enum-ciphers (NSE's own TLS code)
  SSH algorithms / host keys                          nmap ssh2-enum-algos, ssh-keyscan + ssh-keygen, ssh-audit
                                                                                  [node: paramiko]
  PostgreSQL / MySQL TLS                              tlscheck pg|mysql; the server's own view (psql / mysql client)
  keystores, SoftHSM objects, planted files            keytool, pkcs11-tool, ssh login + sha256sum (ForceCommand-logged)
  ML-DSA certificate endpoints (Go has no ML-DSA)     openssl s_client from the tools image, recorded as the fallback
A disagreement is a lab bug: the target's rows become "not judged (lab)" (exit 2), never a product pass.
Every negative observation is paired with a positive control seen by the same tool in the same capture (O-8).
Writes <run>/lab/selfcheck.json (INTERFACES v1 §7) and keeps raw tool output under <run>/lab/selfcheck-raw/.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import labgen  # noqa: E402  (parsers shared with the generator: keytool, pkcs11-tool)
import labspec as S  # noqa: E402
import oraclefmt  # noqa: E402

TOOLS = "cb02-tools"
SCHEMA = "zs-cbom-selfcheck/1"
# Protocol markers OpenSSH appends to its KEXINIT lists; they are not algorithms (RFC 8308 ext-info,
# OpenSSH PROTOCOL "strict KEX"), so they are dropped before comparing.
SSH_MARKERS = re.compile(r"^(ext-info-[cs]|kex-strict-[cs]-v00@openssh\.com)$")


def iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class Ctx:
    def __init__(self, run_dir: Path):
        self.run = run_dir
        self.raw = run_dir / "lab" / "selfcheck-raw"
        self.raw.mkdir(parents=True, exist_ok=True)
        self.tool_versions: dict[str, str] = {}
        self.observed: dict[str, dict] = {}   # target -> facts observed (for positive controls)
        canaries = json.loads((run_dir / "oracle" / "canaries.json").read_text())["canaries"]
        self.secrets = {c["id"]: c.get("value") for c in canaries if c["kind"] == "string"}

    def exec(self, *cmd: str, env: dict | None = None, input_: str | None = None, timeout: int = 180,
             container: str = TOOLS) -> subprocess.CompletedProcess:
        envs = [x for k, v in (env or {}).items() for x in ("-e", f"{k}={v}")]
        return subprocess.run(["docker", "exec", *(["-i"] if input_ is not None else []), *envs, container, *cmd],
                              capture_output=True, text=True, input=input_, timeout=timeout)

    def save(self, name: str, text: str) -> str:
        p = self.raw / name
        p.write_text(text)
        return str(p.relative_to(self.run))

    def tlscheck(self, *args: str) -> dict:
        res = self.exec("tlscheck", *args)
        try:
            return json.loads(res.stdout)
        except json.JSONDecodeError:
            return {"error": (res.stderr or res.stdout)[-500:]}


class Target:
    """Collects the checks of one target in the CB-01 §7 row format."""

    def __init__(self, tid: str):
        self.tid, self.checks, self.controls = tid, [], []

    def check(self, oracle_id: str, key: str, tool: str, expected, observed, agree: bool | None = None,
              note: str = "") -> bool:
        ok = (expected == observed) if agree is None else agree
        row = {"oracle_id": oracle_id, "key": key, "tool": tool, "expected": expected, "observed": observed, "agree": ok}
        if note:
            row["note"] = note
        self.checks.append(row)
        return ok

    def control(self, negative: str, control_target: str | None, satisfied: bool, detail: str) -> None:
        self.controls.append({"negative": negative, "control_target": control_target, "satisfied": satisfied,
                              "detail": detail})

    def result(self) -> dict:
        agree = all(c["agree"] for c in self.checks) and all(c["satisfied"] for c in self.controls)
        return {"target_id": self.tid, "agree": agree, "checks": self.checks, "controls": self.controls}


# ------------------------------------------------------------------ parsers (pure, unit-tested)
def parse_nmap_ciphers(xml_text: str) -> dict[str, list[str]]:
    """ssl-enum-ciphers -oX: {"TLSv1.2": [IANA suite names]} for every protocol table nmap printed."""
    out: dict[str, list[str]] = {}
    root = ET.fromstring(xml_text)
    for script in root.iter("script"):
        if script.get("id") != "ssl-enum-ciphers":
            continue
        for proto in script.findall("table"):
            names = []
            for ciphers in proto.findall("table"):
                if ciphers.get("key") != "ciphers":
                    continue
                for c in ciphers.findall("table"):
                    for elem in c.findall("elem"):
                        if elem.get("key") == "name" and elem.text:
                            names.append(elem.text.strip())
            out[proto.get("key", "")] = sorted(names)
    return out


def parse_nmap_ssh(xml_text: str) -> dict[str, list[str]]:
    """ssh2-enum-algos -oX: lists keyed kex_algorithms, server_host_key_algorithms, encryption_algorithms, ..."""
    out: dict[str, list[str]] = {}
    root = ET.fromstring(xml_text)
    for script in root.iter("script"):
        if script.get("id") != "ssh2-enum-algos":
            continue
        for table in script.findall("table"):
            out[table.get("key", "")] = [e.text.strip() for e in table.findall("elem") if e.text]
    return out


def strip_markers(algs: list[str]) -> list[str]:
    return [a for a in algs if not SSH_MARKERS.match(a)]


def parse_keyscan(text: str) -> dict[str, str]:
    """ssh-keyscan lines `host type base64` -> {type: base64}."""
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3 and not line.startswith("#"):
            out[parts[1]] = parts[2]
    return out


def pem_certs(text: str) -> list[str]:
    """sha256 of each DER certificate in a PEM text (s_client -showcerts)."""
    out = []
    for m in re.finditer(r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", text, re.S):
        out.append(hashlib.sha256(base64.b64decode("".join(m.group(1).split()))).hexdigest())
    return out


def hba_address(addr: str | None) -> str:
    """pg_hba_file_rules splits an address into address + netmask: 0.0.0.0/0 -> 0.0.0.0/0.0.0.0."""
    if not addr:
        return ""
    import ipaddress
    net = ipaddress.ip_network(addr, strict=False)
    return f"{net.network_address}/{net.netmask}"


def jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text().splitlines():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            rows.append({"unparsed": line})
    return rows


# ------------------------------------------------------------------ per-kind checks
def check_tls(ctx: Ctx, o: dict) -> Target:
    t, e = Target(o["target"]), o["expect"]
    addr = f"{o['address']}:{o['port']}"
    oid = f"{o['target']}/tls"
    leaf_alg = (e["certificates"][0].get("key_algorithm") or "") if e["certificates"] else ""
    sni = (e.get("sni_names") or [None])[0]
    obs: dict = {}
    if leaf_alg.startswith(("ML-DSA", "SLH-DSA")):
        return check_tls_mldsa(ctx, o, t)
    m = ctx.tlscheck("matrix", "-addr", addr, *(["-sni", sni] if sni else []))
    ctx.save(f"{o['target']}.tlscheck.json", json.dumps(m, indent=1))
    tool = m.get("tool", "tlscheck")
    ctx.tool_versions["tlscheck"] = tool
    if e.get("sni_required"):
        bare = ctx.tlscheck("matrix", "-addr", addr)
        ctx.save(f"{o['target']}.tlscheck-nosni.json", json.dumps(bare, indent=1))
        refused = not any((bare.get("versions") or {}).values())
        t.check(oid, "sni_required", tool, True, refused,
                note="every version refused without SNI: " + "; ".join(sorted(set((bare.get("version_errors") or {}).values())))[:200])
        t.control("handshake refused without SNI", o["target"], any((m.get("versions") or {}).values()),
                  f"the same tool completes a handshake with SNI {sni}")
    obs["versions"] = m.get("versions") or {}
    t.check(oid, "protocol_versions", tool, e["versions"], obs["versions"])
    if e.get("groups") is not None and e["versions"].get("TLSv1.3"):
        obs["groups"] = sorted(m.get("groups_tls13") or [])
        t.check(oid, "groups", tool, sorted(e["groups"]), obs["groups"])
    ctx.observed[o["target"]] = obs
    # certificates served (leaf first) vs the generated files
    chain = [c.get("sha256") for c in (m.get("chain") or [])]
    t.check(f"{o['target']}/cert", "fingerprint_sha256 (served chain)", tool,
            [c["sha256"] for c in e["certificates"]], chain)
    if m.get("leaf"):
        leaf, want = m["leaf"], e["certificates"][0]
        t.check(f"{o['target']}/cert[0]", "key_size", tool, want.get("key_bits"), leaf.get("key_bits"))
        t.check(f"{o['target']}/cert[0]", "not_after", tool, want.get("not_after"), leaf.get("not_after"))
    # cipher suites, TLS <= 1.2: nmap
    legacy = [v for v, on in e["versions"].items() if on and v != "TLSv1.3"]
    if legacy:
        args = ["nmap", "-Pn", "-n", "-p", str(o["port"]), "--script", "ssl-enum-ciphers", "-oX", "-", o["address"]]
        if sni:
            args[-1:-1] = ["--script-args", f"tls.servername={sni}"]
        res = ctx.exec(*args)
        ctx.save(f"{o['target']}.nmap-ssl.xml", res.stdout)
        ctx.tool_versions["nmap"] = "nmap 7.97 ssl-enum-ciphers"
        try:
            suites = parse_nmap_ciphers(res.stdout)
        except ET.ParseError:
            suites = {}
        for v in legacy:
            t.check(oid, f"cipher_suites[{v}]", "nmap ssl-enum-ciphers", sorted(e["suites"].get(v, [])),
                    suites.get(v, []))
        go = m.get("suites_go") or {}
        for v in legacy:
            extra = sorted(set(go.get(v, [])) - set(e["suites"].get(v, [])))
            t.check(oid, f"cipher_suites[{v}] (Go subset)", tool, [], extra,
                    note="suites Go negotiated that the oracle does not list")
    return t


def check_tls_mldsa(ctx: Ctx, o: dict, t: Target) -> Target:
    """Go's crypto/tls cannot verify an ML-DSA CertificateVerify, so it must fail; openssl s_client (tools image,
    OpenSSL 3.5) fetches the certificate and measures versions and groups. Recorded as the documented fallback."""
    e, addr, oid = o["expect"], f"{o['address']}:{o['port']}", f"{o['target']}/tls"
    m = ctx.tlscheck("matrix", "-addr", addr)
    ctx.save(f"{o['target']}.tlscheck.json", json.dumps(m, indent=1))
    t.check(oid, "classical-only client refused", m.get("tool", "tlscheck"), True,
            not any((m.get("versions") or {}).values()),
            note="the server holds only an ML-DSA certificate, so a client without ML-DSA signature schemes fails")
    tool = "openssl s_client 3.5 (tools image; fallback, see module doc)"
    ctx.tool_versions["openssl s_client"] = tool
    flags = {"TLSv1.0": "-tls1", "TLSv1.1": "-tls1_1", "TLSv1.2": "-tls1_2", "TLSv1.3": "-tls1_3"}
    versions, groups, certs = {}, [], []
    for v, flag in flags.items():
        res = ctx.exec("sh", "-c", f"openssl s_client -connect {addr} {flag} -showcerts </dev/null 2>&1")
        ok = "Cipher is (NONE)" not in res.stdout and bool(re.search(r"Protocol\s*:\s*TLSv|New, TLSv", res.stdout))
        versions[v] = ok
        if ok and not certs:
            certs = pem_certs(res.stdout)
            ctx.save(f"{o['target']}.s_client.txt", res.stdout)
    for g in ["x25519", "secp256r1", "secp384r1", "X25519MLKEM768"]:
        res = ctx.exec("sh", "-c", f"openssl s_client -connect {addr} -tls1_3 -groups {S.GROUPS[g]} </dev/null 2>&1")
        if re.search(r"New, TLSv1\.3", res.stdout):
            groups.append(g)
    t.check(oid, "protocol_versions", tool, e["versions"], versions)
    t.check(oid, "groups", tool, sorted(e["groups"] or []), sorted(groups))
    t.check(f"{o['target']}/cert", "fingerprint_sha256 (served chain)", tool, [c["sha256"] for c in e["certificates"]],
            certs)
    ctx.observed[o["target"]] = {"versions": versions, "groups": sorted(groups)}
    return t


def known_hosts(o: dict) -> str:
    return "".join(f"{o['address']} {k['type']} {k['public_key']}\n" for k in o["expect"]["host_keys"])


def check_ssh(ctx: Ctx, o: dict) -> Target:
    t, e = Target(o["target"]), o["expect"]
    oid = f"{o['target']}/ssh"
    res = ctx.exec("nmap", "-Pn", "-n", "-p", str(o["port"]), "--script", "ssh2-enum-algos", "-oX", "-", o["address"])
    ctx.save(f"{o['target']}.nmap-ssh.xml", res.stdout)
    try:
        algs = parse_nmap_ssh(res.stdout)
    except ET.ParseError:
        algs = {}
    tool = "nmap 7.97 ssh2-enum-algos"
    t.check(oid, "kex_algorithms", tool, e["kex"], strip_markers(algs.get("kex_algorithms", [])))
    # sshd lists host key algorithms in the order of its loaded keys, not of HostKeyAlgorithms: compared as a set.
    t.check(oid, "host_key_algorithms", tool, sorted(e["host_key_algorithms"]),
            sorted(algs.get("server_host_key_algorithms", [])))
    t.check(oid, "ciphers", tool, e["ciphers"], algs.get("encryption_algorithms", []))
    t.check(oid, "macs", tool, e["macs"], algs.get("mac_algorithms", []))
    types = ",".join(sorted({k["type"].replace("ssh-", "").replace("ecdsa-sha2-nistp256", "ecdsa") for k in e["host_keys"]}
                            | {"rsa", "ecdsa", "ed25519"}))
    ks = ctx.exec("ssh-keyscan", "-T", "5", "-t", types, "-p", str(o["port"]), o["address"])
    ctx.save(f"{o['target']}.keyscan.txt", ks.stdout)
    seen = parse_keyscan(ks.stdout)
    t.check(oid, "host_keys", "ssh-keyscan (OpenSSH 10)", {k["type"]: k["public_key"] for k in e["host_keys"]}, seen)
    bits = {}
    for typ, blob in seen.items():
        fp = ctx.exec("ssh-keygen", "-l", "-E", "sha256", "-f", "-", input_=f"{typ} {blob}\n")
        parts = fp.stdout.split()
        if len(parts) >= 2:
            bits[typ] = [int(parts[0]), parts[1]]
    t.check(oid, "host_key bits+fingerprint", "ssh-keygen -l",
            {k["type"]: [k["bits"], k["fingerprint_sha256"]] for k in e["host_keys"]}, bits)
    au = ctx.exec("ssh-audit", "-j", "-p", str(o["port"]), o["address"])
    ctx.save(f"{o['target']}.ssh-audit.json", au.stdout)
    try:
        audit = json.loads(au.stdout)
        kex = strip_markers([k.get("algorithm", "") for k in audit.get("kex", [])])
    except json.JSONDecodeError:
        kex = []
    t.check(oid, "kex_algorithms (cross-check)", "ssh-audit 3.3.0", sorted(e["kex"]), sorted(kex))
    ctx.tool_versions.update({"nmap": "nmap 7.97", "ssh-keyscan": "OpenSSH_10.0p2", "ssh-audit": "ssh-audit 3.3.0"})
    pq = [k for k in strip_markers(algs.get("kex_algorithms", [])) if k.startswith(("mlkem", "sntrup"))]
    ctx.observed[o["target"]] = {"pq_kex": pq}
    return t


def check_host(ctx: Ctx, o: dict) -> Target:
    t = check_ssh(ctx, o)
    e = o["expect"]
    ctx.exec("sh", "-c", "cat > /tmp/kh-host", input_=known_hosts(o))
    files = [f["path"] for f in e["files"]]
    remote = "sha256sum " + " ".join(files) + "; stat -c '%a %n' " + " ".join(files)
    key = "/run-lab/lab/secrets/operator_ed25519"
    res = ctx.exec("ssh", "-i", key, "-o", "UserKnownHostsFile=/tmp/kh-host", "-o", "StrictHostKeyChecking=yes",
                   "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-p", str(o["port"]), f"zs-cbom@{o['address']}",
                   remote)
    ctx.save("host.ssh-files.txt", res.stdout + res.stderr)
    sums = {line.split()[1]: line.split()[0] for line in res.stdout.splitlines() if re.match(r"^[0-9a-f]{64}\s", line)}
    modes = {line.split()[1]: line.split()[0].zfill(4) for line in res.stdout.splitlines() if re.match(r"^\d{3,4} /", line)}
    for f in e["files"]:
        t.check(f"host:{f['path']}", "sha256 (on the host, over SSH)", "ssh + sha256sum (busybox)", f["sha256"],
                sums.get(f["path"]))
        t.check(f"host:{f['path']}", "mode", "ssh + stat", f["mode"], modes.get(f["path"]))
    time.sleep(1)
    logged = [r for r in jsonl(ctx.run / "lab" / "forcecommand.log") if r.get("command") == remote]
    t.check("host/login", "ForceCommand logged the self-check's command", "lab/forcecommand.log", True, bool(logged))
    t.control("read-only command log (O-8)", o["target"], bool(logged), "the self-check's own command is in the log")
    for f in e["files"]:
        if f["kind"] == "keystore":
            pw = ctx.secrets.get(f"host-{Path(f['path']).name}-storepass")
            local = f"/run-lab/lab/targets/host/plant/{f['path'].removeprefix('/srv/cbom-lab/')}"
            res = ctx.exec("keytool", "-list", "-v", "-storetype", f["storetype"], "-keystore", local,
                           "-storepass:env", "CB02_STOREPASS", env={"CB02_STOREPASS": pw or ""})
            got = labgen.parse_keytool(res.stdout)
            t.check(f"host:{f['path']}", "entries", "keytool (JRE 21)", f["entries"], got)
        if f["kind"] == "certificate":
            local = f"/run-lab/lab/targets/host/plant/{f['path'].removeprefix('/srv/cbom-lab/')}"
            res = ctx.exec("openssl", "x509", "-in", local, "-noout", "-fingerprint", "-sha256")
            fp = res.stdout.strip().split("=", 1)[-1].replace(":", "").lower()
            t.check(f"host:{f['path']}", "fingerprint_sha256", "openssl x509", f["certificate"]["sha256"], fp)
    return t


def check_listener(ctx: Ctx, o: dict, health: dict[str, str]) -> Target:
    t, e = Target(o["target"]), o["expect"]
    oid = f"{o['target']}/listener"
    t.check(oid, "listening (health, read from /proc/net/tcp)", "docker health", "healthy", health.get(o["container"]))
    for alias in o["aliases"]:
        res = ctx.exec("getent", "hosts", alias)
        t.check(oid, f"name {alias} resolves on the lab network", "getent (docker DNS)", o["address"],
                (res.stdout.split() or [None])[0])
    log = ctx.run / "lab" / "listeners" / f"{o['target']}.jsonl"
    if e["role"] == "control":
        res = ctx.exec("python3", "-c", f"import socket; socket.create_connection(('{o['address']}', {o['port']}), 3).close()")
        time.sleep(1)
        rows = [r for r in jsonl(log) if str(r.get("peer", "")).startswith(S.TOOLS_IP + ":")]
        t.check(oid, "accept logged with the peer address", "socat + cb02-accept", True, bool(rows) and res.returncode == 0)
        ctx.observed[o["target"]] = {"accept_logged": bool(rows)}
    else:
        rows = [r for r in jsonl(log) if not str(r.get("peer", "")).startswith((S.TOOLS_IP + ":", "127.0.0.1:"))]
        t.check(oid, "no connection before the scan", "lab/listeners/*.jsonl", 0, len(rows))
    return t


def check_postgres(ctx: Ctx, o: dict) -> Target:
    t, e = Target(o["target"]), o["expect"]
    addr, oid = f"{o['address']}:{o['port']}", f"{o['target']}/tls"
    tls_on = e["ssl"] == "on"
    first = ctx.tlscheck("pg", "-addr", addr)
    ctx.save(f"{o['target']}.tlscheck-pg.json", json.dumps(first, indent=1))
    tool = first.get("tool", "tlscheck")
    t.check(oid, "SSLRequest answer", tool, "S" if tls_on else "N", first.get("answer"))
    if tls_on:
        versions = {}
        for v in S.VERSIONS:
            r = ctx.tlscheck("pg", "-addr", addr, "-version", v.removeprefix("TLSv"))
            versions[v] = bool((r.get("tls") or {}).get("ok"))
        t.check(oid, "protocol_versions", tool, e["tls"]["versions"], versions)
        chain = [c.get("sha256") for c in ((first.get("tls") or {}).get("certs") or [])]
        t.check(f"{o['target']}/cert", "fingerprint_sha256", tool, [e["tls"]["certificates"][0]["sha256"]], chain[:1])
    ctx.observed[o["target"]] = {"ssl": first.get("answer")}
    pw = ctx.secrets.get(f"{o['target']}-postgres", "")
    mode = "require" if tls_on else "disable"
    sql = ("SHOW ssl; SELECT string_agg(concat_ws('|', type, array_to_string(database, ','), array_to_string(user_name, ','),"
           " coalesce(address || '/' || netmask, address, ''), auth_method), ';' ORDER BY line_number) FROM pg_hba_file_rules;"
           " SELECT string_agg(rolname || '=' || left(rolpassword, 3), ',' ORDER BY rolname) FROM pg_authid"
           " WHERE rolname IN ('cbom_md5', 'cbom_reader');"
           " SELECT string_agg(extname, ',' ORDER BY extname) FROM pg_extension WHERE extname <> 'plpgsql';")
    res = ctx.exec("psql", f"host={o['address']} port={o['port']} user=postgres dbname=postgres sslmode={mode}",
                   "-Atc", sql, env={"PGPASSWORD": pw, "PGCONNECT_TIMEOUT": "5"})
    lines = res.stdout.strip().splitlines()
    ctx.save(f"{o['target']}.psql.txt", res.stdout + res.stderr)
    t.check(f"{o['target']}/config", "SHOW ssl", "psql 16 (server's own view)", e["ssl"], lines[0] if lines else None)
    want_hba = ";".join("|".join([r["type"], r["database"], r["user"], hba_address(r["address"]), r["method"]])
                        for r in e["hba"])
    t.check(f"{o['target']}/auth", "pg_hba_file_rules", "psql 16", want_hba, lines[1] if len(lines) > 1 else None)
    t.check(f"{o['target']}/auth", "stored password types", "psql 16", "cbom_md5=md5,cbom_reader=SCR",
            lines[2] if len(lines) > 2 else None)
    t.check(f"{o['target']}/config", "extensions", "psql 16", ",".join(e["extensions"]), lines[3] if len(lines) > 3 else None)
    time.sleep(1)
    logs = subprocess.run(["docker", "logs", "--since", "2m", o["container"]], capture_output=True, text=True)
    pattern = r"connection authorized: user=postgres database=postgres\b[^\n]*" + (r"SSL enabled \(protocol=TLSv1\.[23]"
                                                                                  if tls_on else "")
    seen = re.search(pattern, logs.stdout + logs.stderr) is not None
    t.check(f"{o['target']}/config", "log_connections records the self-check login", "postgres log", True, seen)
    if tls_on:
        t.control("no login on the no-TLS server (O-8)", o["target"], seen, "the TLS server logs this login")
    return t


def check_mysql(ctx: Ctx, o: dict) -> Target:
    t, e = Target(o["target"]), o["expect"]
    addr, oid = f"{o['address']}:{o['port']}", f"{o['target']}/tls"
    first = ctx.tlscheck("mysql", "-addr", addr)
    ctx.save(f"{o['target']}.tlscheck-mysql.json", json.dumps(first, indent=1))
    tool = first.get("tool", "tlscheck")
    t.check(oid, "CLIENT_SSL offered", tool, e["tls"]["ssl_supported"], first.get("ssl_supported"))
    if e["tls"]["ssl_supported"]:
        want = {v: v in e["tls_version"].split(",") for v in S.VERSIONS}
        got = {}
        for v in S.VERSIONS:
            r = ctx.tlscheck("mysql", "-addr", addr, "-version", v.removeprefix("TLSv"))
            got[v] = bool((r.get("tls") or {}).get("ok"))
        t.check(oid, "protocol_versions", tool, want, got)
        chain = [c.get("sha256") for c in ((first.get("tls") or {}).get("certs") or [])]
        t.check(f"{o['target']}/cert", "fingerprint_sha256", tool, [e["tls"]["certificates"][0]["sha256"]], chain[:1])
    ctx.observed[o["target"]] = {"ssl": first.get("ssl_supported")}
    pw = ctx.secrets.get(f"{o['target']}-root", "")
    res = ctx.exec("mysql", "-uroot", "-N", "-B", "-e",
                   "SELECT @@tls_version; SELECT GROUP_CONCAT(CONCAT(user, '=', plugin) ORDER BY user) FROM mysql.user "
                   "WHERE user LIKE 'cbom%';", env={"MYSQL_PWD": pw}, container=o["container"])
    lines = res.stdout.rstrip("\n").split("\n")  # keep the first line even when @@tls_version is empty
    t.check(f"{o['target']}/config", "@@tls_version", "mysql client (server's own view)", e["tls_version"],
            lines[0] if lines else None)
    t.check(f"{o['target']}/auth", "user plugins", "mysql client",
            ",".join(f"{u}={p}" for u, p in sorted(e["users"].items())), lines[1] if len(lines) > 1 else None)
    return t


def check_softhsm(ctx: Ctx, o: dict) -> Target:
    t, e = Target(o["target"]), o["expect"]
    lib = "/usr/lib/softhsm/libsofthsm2.so"
    prep = ("rm -rf /tmp/hsm && mkdir -p /tmp/hsm && cp -R /run-lab/lab/targets/softhsm/tokens /tmp/hsm/ && "
            "printf 'directories.tokendir = /tmp/hsm/tokens\\nobjectstore.backend = file\\nlog.level = ERROR\\n' > /tmp/hsm/c")
    ctx.exec("sh", "-c", prep)
    env = {"SOFTHSM2_CONF": "/tmp/hsm/c"}
    pins = {tok["label"]: ctx.secrets.get(f"softhsm-{tok['label']}-pin", "") for tok in e["tokens"]}
    for tok in e["tokens"]:
        res = ctx.exec("pkcs11-tool", "--module", lib, "--token-label", tok["label"], "--login", "--pin",
                       pins[tok["label"]], "--list-objects", env=env)
        got = labgen.parse_pkcs11_objects(res.stdout)
        t.check(f"softhsm/{tok['label']}", "objects", "pkcs11-tool (OpenSC 0.26)", tok["objects"], got)
    a, b = e["tokens"][0]["label"], e["tokens"][1]["label"]
    wrong = ctx.exec("pkcs11-tool", "--module", lib, "--token-label", b, "--login", "--pin", pins[a], "--list-objects",
                     env=env)
    refused = "CKR_PIN_INCORRECT" in (wrong.stdout + wrong.stderr)
    t.check(f"softhsm/{b}", "token B refuses token A's PIN (on a copy)", "pkcs11-tool", True, refused)
    t.control("PIN refused (O-8)", o["target"], refused and bool(e["tokens"][0]["objects"]),
              "the right PIN lists token A's objects with the same tool")
    return t


def check_code(ctx: Ctx, o: dict) -> Target:
    import zipfile
    t, e = Target(o["target"]), o["expect"]
    d = ctx.run / "lab" / "targets" / o["target"]
    tree = d / "cryptoapi-bench"
    labels = tree / "CryptoAPI-Bench_details.xlsx"
    t.check("code/labels", "labels sha256", "sha256", e["labels_sha256"],
            hashlib.sha256(labels.read_bytes()).hexdigest() if labels.exists() else None)
    zpath = d / e["archive"]
    t.check("code/archive", "archive sha256", "sha256", e["archive_sha256"],
            hashlib.sha256(zpath.read_bytes()).hexdigest() if zpath.exists() else None)
    with zipfile.ZipFile(zpath) as z:
        inside = {n.removeprefix("cryptoapi-bench/"): hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist()}
    on_disk = {str(p.relative_to(tree)): hashlib.sha256(p.read_bytes()).hexdigest() for p in tree.rglob("*") if p.is_file()}
    t.check("code/archive", "archive == tree", "zipfile", True, inside == on_disk)
    relabel = labgen.read_xlsx_labels(labels)
    t.check("code/labels", "cases re-read from the xlsx", "xlsx reader (stdlib)",
            [(c["files"], c["vulnerable"]) for c in e["cases"]], [(c["files"], c["vulnerable"]) for c in relabel])
    for c in e["cases"]:
        for path, digest in zip(c["paths"], c["sha256"]):
            if path and on_disk.get(path) != digest:
                t.check(f"code/{path}", "case file sha256", "sha256", digest, on_disk.get(path))
    both = e["summary"]["vulnerable"] > 0 and e["summary"]["secure"] > 0
    t.control("benchmark has both classes (O-8)", o["target"], both,
              f"{e['summary']['vulnerable']} vulnerable and {e['summary']['secure']} secure cases")
    return t


# ------------------------------------------------------------------ controls and driver
def apply_controls(results: dict[str, Target], facts: dict[str, dict], ctx: Ctx) -> None:
    """O-8: each negative observation needs the positive seen by the same tool on the named control target."""
    for tid, o in facts.items():
        tgt = results.get(tid)
        if not tgt:
            continue
        e = o["expect"]
        if o["kind"] == "tls":
            for v, on in e["versions"].items():
                if not on:
                    ctl = S.CONTROLS.get(f"tls_version_refused:{v}")
                    seen = (ctx.observed.get(ctl) or {}).get("versions", {}).get(v) is True
                    tgt.control(f"{v} refused", ctl, seen, f"{ctl} accepts {v} with the same tool" if ctl else "")
            if e.get("groups") is not None and e["versions"].get("TLSv1.3"):
                for g in sorted(S.OBSERVABLE_GROUPS - set(e["groups"])):
                    ctl = S.CONTROLS.get(f"tls_group_absent:{g}")
                    if ctl is None:
                        continue  # no lab target offers it; the absence is reported but needs no control
                    seen = g in (ctx.observed.get(ctl) or {}).get("groups", [])
                    tgt.control(f"group {g} absent", ctl, seen, f"{ctl} negotiates {g} with the same tool")
        if o["kind"] == "ssh" and not e.get("pq_kex"):
            ctl = S.CONTROLS["ssh_no_pq_kex"]
            tgt.control("no PQ key exchange", ctl, bool((ctx.observed.get(ctl) or {}).get("pq_kex")),
                        f"{ctl} offers PQ KEX to the same tool")
        if o["kind"] == "postgres" and e["ssl"] == "off":
            ctl = S.CONTROLS["pg_ssl_off"]
            tgt.control("SSLRequest refused", ctl, (ctx.observed.get(ctl) or {}).get("ssl") == "S",
                        f"{ctl} answers S to the same tool")
        if o["kind"] == "mysql" and not e["tls"]["ssl_supported"]:
            ctl = S.CONTROLS["mysql_ssl_off"]
            tgt.control("CLIENT_SSL absent", ctl, (ctx.observed.get(ctl) or {}).get("ssl") is True,
                        f"{ctl} offers CLIENT_SSL to the same tool")
        if o["kind"] == "listener" and e["role"] == "canary":
            ctls = [c for c in S.CONTROLS["listener_untouched"] if c in facts]
            seen = [c for c in ctls if (ctx.observed.get(c) or {}).get("accept_logged") is True]
            tgt.control("0 connections at the canary", ",".join(ctls) or None, bool(seen),
                        f"{','.join(seen) or 'no control listener'} logs the self-check's connection with the same code")


def container_health() -> dict[str, str]:
    res = subprocess.run(["docker", "ps", "-a", "--filter", "label=com.zeroshield.cbom-lab=cb02", "--format",
                          "{{.Names}}\t{{.Status}}"], capture_output=True, text=True)
    out = {}
    for line in res.stdout.splitlines():
        name, _, status = line.partition("\t")
        out[name] = "healthy" if "(healthy)" in status else ("up" if status.startswith("Up") else status)
    return out


def main(run_dir: Path, only: str | None = None) -> int:
    started = iso_now()
    gen_json = json.loads((run_dir / "lab" / "gen.json").read_text())
    recorded, now_hash = gen_json.get("oracle_sha256"), oraclefmt.oracle_hash(run_dir)
    report: dict = {"schema": SCHEMA, "checked_at": started, "run_id": gen_json["run_id"], "oracle_sha256": now_hash,
                    "oracle_sha256_recorded": recorded, "targets": []}
    if recorded != now_hash:
        report["error"] = "oracle changed after generation (rule O-5): start a new run"
        (run_dir / "lab" / "selfcheck.json").write_text(json.dumps(report, indent=1) + "\n")
        print(json.dumps({"agree": False, "error": report["error"]}))
        return 2
    step = gen_json.get("current_step", "run1")
    facts_dir = run_dir / "oracle" / ("facts" if step == "run1" else f"{step}/facts")
    report["step"] = step
    idx = json.loads((facts_dir / "index.json").read_text())
    facts = {t["target"]: json.loads((run_dir / t["facts"]).read_text()) for t in idx["targets"]}
    health = container_health()
    if health.get(TOOLS) not in ("healthy", "up"):
        print(json.dumps({"agree": False, "error": "cb02-tools is not running (gen.py up)"}))
        return 1
    ctx = Ctx(run_dir)
    wanted = set(only.split(",")) if only else set(facts)
    results: dict[str, Target] = {}
    order = sorted(facts, key=lambda k: (facts[k]["kind"] == "listener" and facts[k]["expect"]["role"] == "canary", k))
    for tid in order:
        o = facts[tid]
        if tid not in wanted:
            continue
        if o.get("container") and health.get(o["container"]) not in ("healthy", "up"):
            t = Target(tid)
            t.check(f"{tid}/container", "running", "docker ps", "healthy", health.get(o["container"], "absent"))
            results[tid] = t
            continue
        fn = {"tls": check_tls, "ssh": check_ssh, "host": check_host, "postgres": check_postgres,
              "mysql": check_mysql, "softhsm": check_softhsm, "code": check_code}.get(o["kind"])
        try:
            results[tid] = check_listener(ctx, o, health) if o["kind"] == "listener" else fn(ctx, o)
        except Exception as exc:  # a crashed check is a lab problem, reported, never a pass
            t = Target(tid)
            t.check(f"{tid}/selfcheck", "check ran", "selfcheck.py", "completed", f"{type(exc).__name__}: {exc}")
            results[tid] = t
    apply_controls(results, facts, ctx)
    report["tools"] = ctx.tool_versions
    report["targets"] = [results[k].result() for k in sorted(results)]
    report["summary"] = {"targets": len(results), "agree": sum(r["agree"] for r in report["targets"]),
                         "disagree": sorted(r["target_id"] for r in report["targets"] if not r["agree"]),
                         "checks": sum(len(r["checks"]) for r in report["targets"]),
                         "controls": sum(len(r["controls"]) for r in report["targets"])}
    report["finished_at"] = iso_now()
    (run_dir / "lab" / "selfcheck.json").write_text(json.dumps(report, indent=1, ensure_ascii=False) + "\n")
    print(json.dumps(report["summary"]))
    return 0 if not report["summary"]["disagree"] else 2


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]).resolve(), sys.argv[2] if len(sys.argv) > 2 else None))
