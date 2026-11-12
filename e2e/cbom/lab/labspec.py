"""CB-02 lab catalogue: every target, its address, profile and the values gen.py plants.

This module is data plus small pure helpers. It imports nothing from the product (oracle rule O-1: the harness never
imports backend/, aibom/, scan_node/ or frontend/). gen.py turns each entry into the target's files and its oracle in
one step; selfcheck.py reads the oracle, never this file, so a target's expected values exist exactly once.

Names follow the public registries, never the product's vocabulary:
  * TLS versions as "TLSv1.0".."TLSv1.3" (nmap and the IETF RFC titles);
  * cipher suites by their IANA "TLS Cipher Suites" names;
  * groups by their IANA "TLS Supported Groups" names (x25519, secp256r1, X25519MLKEM768);
  * SSH algorithms by their IANA "Secure Shell (SSH) Protocol Parameters" / OpenSSH names.
"""
from __future__ import annotations

import ipaddress

SCHEMA_ORACLE = "zs-cbom-lab-oracle/1"
SCHEMA_INDEX = "zs-cbom-lab-index/1"
GENERATOR = "e2e/cbom/lab/gen.py"

NETWORK = {"name": "cbom-e2e-net", "subnet": "10.231.0.0/24", "gateway": "10.231.0.1", "ip_range": "10.231.0.0/29"}
NODE_IP = "10.231.0.5"     # informative only: the node gets a dynamic address in .2-.7 (INTERFACES v2)
NGINX_IP = "10.231.0.10"   # the stack nginx, aliases api.dss.test / devsec.dss.test (CB-03)
TOOLS_IP = "10.231.0.11"   # cb02-tools, the self-check source (excluded from accept counts); .10 is nginx (CB-03)
BURST_IP = "10.231.0.12"   # cb02-burst, a throwaway source for the PerSourcePenalties burst (review 5874442142)
LAB_SOURCES = (TOOLS_IP, BURST_IP)  # the lab's own peers: listener logs keep them out of <name>.jsonl
ZOO_RANGE = "10.231.0.16/28"     # S-zoo, the TLS/SSH zoo the customer scans as a network range
CANARY_RANGE = "10.231.0.32/30"  # R-canary: the never-scan canary and its control neighbour

# Compose profiles. `core` is the Tier-L gate lab (DEVILS-ADVOCATE section 4.2); the others are waves.
PROFILES = {
    "core": "TLS zoo, SSH pair, host with planted files and keystores, Postgres with TLS, canary/control and IDNA listeners",
    "db": "Postgres without TLS, MySQL 8.4 with and without TLS",
    "run2": "targets started only for the drift run (z08)",
    "hsm": "SoftHSM2 tokens (files; no container)",
    "code": "CryptoAPI-Bench repository and archive (files; no container)",
    "psp": "one sshd that keeps OpenSSH's default PerSourcePenalties (the product's behaviour against them)",
    "k8s": "kind cluster with kubernetes.io/tls secrets (deferred: see DEFERRED)",
    "tools": "the self-check container cb02-tools",
}

# IANA cipher suite name -> OpenSSL name (both sides from the registries / OpenSSL's ciphers(1) table).
SUITES = {
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": "ECDHE-RSA-AES128-SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA": "ECDHE-RSA-AES256-SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA": "AES128-SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA": "AES256-SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA": "DES-CBC3-SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": "ECDHE-RSA-AES128-GCM-SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": "ECDHE-RSA-AES256-GCM-SHA384",
}
TLS13_SUITES = ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]

# IANA group name -> the name OpenSSL / nginx accept.
GROUPS = {"x25519": "X25519", "secp256r1": "prime256v1", "secp384r1": "secp384r1", "secp521r1": "secp521r1",
          "X25519MLKEM768": "X25519MLKEM768"}
# Groups the Go observer can offer one at a time; an oracle may only name these for TLS 1.3 (checked by gen.py).
OBSERVABLE_GROUPS = {"x25519", "secp256r1", "secp384r1", "secp521r1", "X25519MLKEM768"}

VERSIONS = ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
NGINX_PROTOCOL = {"TLSv1.0": "TLSv1", "TLSv1.1": "TLSv1.1", "TLSv1.2": "TLSv1.2", "TLSv1.3": "TLSv1.3"}
S_SERVER_PROTOCOL = {"TLSv1.0": "-tls1", "TLSv1.1": "-tls1_1", "TLSv1.2": "-tls1_2", "TLSv1.3": "-tls1_3"}

# Certificate profiles. Dates are offsets in days from the run's `now` (rule: dates relative to the run).
VALID = {"not_before": -1, "not_after": 397}
EXPIRED = {"not_before": -765, "not_after": -400}


def tls(id_: str, last_octet: int, server: str, versions: list[str], cert: dict, *, suites: list[str] | None = None,
        groups: list[str] | None = None, pin_groups: bool = True, seclevel: int | None = None,
        sni: list[str] | None = None, sni_required: bool = False, profile: str = "core", purpose: str = "",
        must_report: dict | None = None) -> dict:
    """`must_report`: the planted weaknesses the product must name among what the server accepts (CB-01 INTERFACES
    v7 #3), e.g. every CBC / static-RSA suite of a deliberately weak endpoint."""
    return {"id": id_, "kind": "tls", "server": server, "ip": f"10.231.0.{last_octet}", "port": 443,
            "profile": profile, "world": "closed", "purpose": purpose, "versions": versions, "cert": cert,
            "suites": suites or [], "groups": groups or [], "pin_groups": pin_groups, "seclevel": seclevel,
            "sni": sni or [], "sni_required": sni_required, "must_report": must_report or {}}


TARGETS: list[dict] = [
    tls("z01", 17, "nginx", ["TLSv1.3"], {"key": "ec:P-256", "sig": "sha256", "issuer": "ca", **VALID},
        groups=["x25519", "secp256r1"], purpose="clean control: TLS 1.3 only, EC P-256, groups pinned (no hybrid)"),
    tls("z02", 18, "nginx", ["TLSv1.0", "TLSv1.1", "TLSv1.2"],
        {"key": "rsa:1024", "sig": "sha1", "issuer": "self", **VALID},
        suites=["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA"],
        groups=["secp256r1"], seclevel=0,
        must_report={"cipher_suites": ["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                                       "TLS_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_256_CBC_SHA"]},
        purpose="weak: TLS 1.0-1.2, RSA-1024 SHA-1 self-signed, CBC and static-RSA suites at @SECLEVEL=0"),
    tls("z04", 19, "nginx", ["TLSv1.2", "TLSv1.3"], {"key": "rsa:2048", "sig": "sha256", "issuer": "ca", **EXPIRED},
        suites=["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"],
        groups=["x25519", "secp256r1"], purpose="expired lab-CA certificate (now-400 d), strong suites"),
    tls("z05", 20, "s_server", ["TLSv1.3"], {"key": "rsa:2048", "sig": "sha256", "issuer": "ca", **VALID},
        groups=["X25519MLKEM768"], purpose="hybrid PQC: the group X25519MLKEM768 is the only one offered"),
    tls("z05b", 21, "s_server", ["TLSv1.3"], {"key": "ML-DSA-65", "sig": "ML-DSA-65", "issuer": "self", **VALID},
        groups=["X25519MLKEM768", "x25519"], purpose="ML-DSA-65 certificate (FIPS 204), hybrid and classical groups"),
    tls("z09", 22, "nginx", ["TLSv1.2", "TLSv1.3"], {"key": "rsa:2048", "sig": "sha256", "issuer": "ca", **VALID},
        suites=["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"], groups=["x25519", "secp256r1"],
        sni=["sni.lab"], sni_required=True,
        purpose="SNI-only virtual host: handshakes without SNI are rejected (ssl_reject_handshake)"),
    tls("z16", 26, "nginx", ["TLSv1.0"], {"key": "rsa:2048", "sig": "sha256", "issuer": "ca", **VALID},
        suites=["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA"], groups=["secp256r1"],
        seclevel=0, must_report={"cipher_suites": ["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "TLS_RSA_WITH_AES_128_CBC_SHA"]},
        purpose="TLS 1.0 only, modern RSA-2048 certificate"),
    tls("z08", 25, "nginx", ["TLSv1.2"], {"key": "rsa:2048", "sig": "sha256", "issuer": "ca", **VALID},
        suites=["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"],
        groups=["secp256r1"], profile="run2", purpose="new endpoint that appears only in the drift run"),
    {**tls("control-tls", 34, "nginx", ["TLSv1.2"], {"key": "rsa:2048", "sig": "sha256", "issuer": "ca", **VALID},
           suites=["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"], groups=["secp256r1"], profile="run2",
           purpose="G13b: the canary's neighbour becomes a TLS 1.2 endpoint before run 2 (range drift with a never-scan entry)"),
     "replaces": "control"},
    {"id": "sshd-legacy", "kind": "ssh", "ip": "10.231.0.23", "port": 22, "profile": "core", "world": "closed",
     "purpose": "classic key exchange only, hmac-sha1, RSA-1024 and Ed25519 host keys",
     "host_keys": ["rsa:1024", "ed25519"],
     "kex": ["curve25519-sha256", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1"],
     "host_key_algorithms": ["ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256"],
     "ciphers": ["aes128-ctr", "aes256-ctr"], "macs": ["hmac-sha1", "hmac-sha2-256"], "force_command": False,
     "penalty_exempt": NETWORK["subnet"]},
    {"id": "sshd-pq", "kind": "ssh", "ip": "10.231.0.24", "port": 22, "profile": "core", "world": "closed",
     "purpose": "post-quantum hybrid key exchange only (mlkem768x25519-sha256), Ed25519 host key",
     "host_keys": ["ed25519"], "kex": ["mlkem768x25519-sha256"], "host_key_algorithms": ["ssh-ed25519"],
     "ciphers": ["aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"],
     "macs": ["hmac-sha2-256-etm@openssh.com"], "force_command": False, "penalty_exempt": NETWORK["subnet"]},
    {"id": "sshd-psp", "kind": "ssh", "ip": "10.231.0.28", "port": 22, "profile": "psp", "world": "closed",
     "purpose": "OpenSSH 10 with the default PerSourcePenalties (noauth:1 min:15): about 15 connections that never "
                "authenticate get the source dropped for 16 s and more. Only the self-check (.11) is exempt, so the "
                "self-check can run again at once; the penalty is proven from the throwaway burst source .12",
     "host_keys": ["ed25519"], "kex": ["mlkem768x25519-sha256", "curve25519-sha256"],
     "host_key_algorithms": ["ssh-ed25519"], "ciphers": ["aes256-gcm@openssh.com"],
     "macs": ["hmac-sha2-256-etm@openssh.com"], "force_command": False, "penalties": "default",
     "penalty_exempt": TOOLS_IP + "/32"},
    {"id": "host", "kind": "host", "ip": "10.231.0.40", "port": 22, "profile": "core", "world": "open",
     "purpose": "Linux host reached over SSH as zs-cbom; ForceCommand logger; planted keys, certificates, keystores",
     "host_keys": ["rsa:3072", "ecdsa:256", "ed25519"],
     "kex": ["mlkem768x25519-sha256", "sntrup761x25519-sha512", "curve25519-sha256", "ecdh-sha2-nistp256",
             "diffie-hellman-group14-sha256"],
     "host_key_algorithms": ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256"],
     "ciphers": ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-ctr"],
     "macs": ["hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com"], "force_command": True,
     "penalty_exempt": NETWORK["subnet"],
     "plant": [
         {"path": "keys/legacy-rsa1024.key", "make": "rsa_key", "bits": 1024, "mode": "0600"},
         {"path": "certs/expired-rsa2048.crt", "make": "cert", "key": "rsa:2048", "sig": "sha256", "issuer": "ca",
          **EXPIRED, "mode": "0644"},
         {"path": "certs/selfsigned-sha1.crt", "make": "cert", "key": "rsa:2048", "sig": "sha1", "issuer": "self",
          **VALID, "mode": "0644"},
         {"path": "keystores/app.p12", "make": "pkcs12", "mode": "0640", "entries": [
             {"alias": "app", "type": "PrivateKeyEntry", "key": "rsa:2048", "sig": "sha256", **VALID}]},
         {"path": "keystores/legacy.jks", "make": "jks", "mode": "0640", "entries": [
             {"alias": "app", "type": "PrivateKeyEntry", "key": "rsa:2048", "sig": "sha256", **VALID},
             {"alias": "legacy-ca", "type": "trustedCertEntry", "key": "rsa:1024", "sig": "sha1", **EXPIRED}]},
     ]},
    {"id": "canary", "kind": "listener", "ip": "10.231.0.33", "port": 443, "profile": "core", "world": "closed",
     "aliases": ["cbom-e2e-canary"], "role": "canary",
     "purpose": "never-scan canary (listed by name): the product must open 0 connections; health is read without connecting"},
    {"id": "control", "kind": "listener", "ip": "10.231.0.34", "port": 443, "profile": "core", "world": "closed",
     "aliases": ["cbom-e2e-control"], "role": "control",
     "purpose": "the canary's neighbour (positive control): the product must reach it"},
    {"id": "idn-fass", "kind": "listener", "ip": "10.231.0.44", "port": 443, "profile": "core", "world": "closed",
     "aliases": ["fass.lab"], "role": "canary",
     "purpose": "IDNA 2003 form of faß.lab: a scan of faß.lab must not touch it"},
    {"id": "idn-punycode", "kind": "listener", "ip": "10.231.0.45", "port": 443, "profile": "core", "world": "closed",
     "aliases": ["xn--fa-hia.lab"], "role": "control",
     "purpose": "IDNA 2008 (UTS #46 non-transitional) form of faß.lab: the target the customer named"},
    {"id": "pg-tls", "kind": "postgres", "ip": "10.231.0.41", "port": 5432, "profile": "core", "world": "closed",
     "image": "postgres", "tls": True, "purpose": "PostgreSQL 16, TLS with a lab-CA certificate, one md5 HBA line, pgcrypto",
     "cert": {"key": "rsa:2048", "sig": "sha256", "issuer": "ca", **VALID}},
    {"id": "pg-notls", "kind": "postgres", "ip": "10.231.0.46", "port": 5432, "profile": "db", "world": "closed",
     "image": "postgres", "tls": False, "purpose": "PostgreSQL 16 with ssl=off"},
    {"id": "mysql-tls", "kind": "mysql", "ip": "10.231.0.47", "port": 3306, "profile": "db", "world": "closed",
     "image": "mysql", "tls": True, "purpose": "MySQL 8.4, TLS 1.2/1.3 with a lab-CA certificate, one mysql_native_password user",
     "cert": {"key": "rsa:2048", "sig": "sha256", "issuer": "ca", **VALID}},
    {"id": "mysql-notls", "kind": "mysql", "ip": "10.231.0.48", "port": 3306, "profile": "db", "world": "closed",
     "image": "mysql", "tls": False, "purpose": "MySQL 8.4 with TLS disabled (tls_version empty)"},
    {"id": "softhsm", "kind": "softhsm", "profile": "hsm", "world": "closed",
     "purpose": "two SoftHSM2 tokens: only the labelled one holds the lab keys; the other is a PIN-spray canary",
     "tokens": [
         {"label": "cb02-tok-a", "objects": [
             {"label": "rsa-2048-signing", "make": "keypair", "key_type": "RSA:2048", "extractable": False},
             {"label": "ec-p256-signing", "make": "keypair", "key_type": "EC:prime256v1", "extractable": False},
             {"label": "aes-128-wrap", "make": "secret", "key_type": "AES:16", "extractable": True}]},
         {"label": "cb02-tok-b", "objects": [
             {"label": "aes-256-decoy", "make": "secret", "key_type": "AES:32", "extractable": False}]}]},
    {"id": "code-cryptoapi-bench", "kind": "code", "profile": "code", "world": "closed",
     "purpose": "CryptoAPI-Bench at a pinned commit; expected results are the benchmark's own labels",
     "repo": "https://github.com/CryptoGuardOSS/cryptoapi-bench",
     "commit": "759622ff29c73eba4c47e6a8fe2f505c3fef8526",
     "labels_file": "CryptoAPI-Bench_details.xlsx", "source_root": "src/main/java/org/cryptoapi/bench"},
]

# CryptoAPI-Bench label counts read with openpyxl, independently of labgen.read_xlsx_labels, by CB-02 and by the PR #79
# reviewer (review 5873265185): 171 cases, column D = 1 in 136 rows and 0 in 35. Case 9.8.2 names two files that are
# not in the tree (PredictableSeedsABPM*), so 170 cases (135 vulnerable) can be judged. Not remapped (O-2).
BENCH_PINNED = {"labels_sha256": "d08d3586d0d71f1000e4c693286fc2eaf7c6c1aae152b391a2f67bc3dce1e2b9",
                "cases": 171, "vulnerable": 136, "secure": 35, "judgeable": 170, "judgeable_vulnerable": 135,
                "judgeable_secure": 35, "unresolved_files": ["PredictableSeedsABPM2.java", "PredictableSeedsABPMCase2.java"],
                "date_typed_line_cells": 18}

# Lab parts this build does not provide. lab.json lists them, so the gate reports their rows NOT-RUN from this marking.
DEFERRED_DRAFT = "round6/cbom/cb-02/issue-deferred.md"
DEFERRED_ISSUE = "#93"  # filed by CB-01 from the draft (INTERFACES v6, ledger row LAB-deferred)
DEFERRED = [
    {"part": "idp", "address": "10.231.0.42", "gate": ["G7"],
     "reason": "OIDC discovery + JWKS target not in the CB-02 brief's target list"},
    {"part": "receiver", "address": "10.231.0.43", "gate": ["G13", "W-INT"],
     "reason": "webhook receiver (scripts/integrations_lab) not in the CB-02 brief's target list"},
    {"part": "ubuntu-tier2", "address": "10.231.0.40", "gate": ["G4", "G15"],
     "reason": ".40 is Alpine + OpenSSH 10 without the product's Tier-2 sudoers; sshd, host keys and planted files "
               "belong to the login user, so a Tier-1 login reads more than on a real host and can write the file "
               "copy of the command log (the container log is the authoritative record)"},
    {"part": "k8s", "address": None, "gate": ["W-HOST"],
     "reason": "kind node image needs ~2.5 GB of disk; the shared machine had 3.8-7 GB free (rule: keep >= 3 GB)"},
]

# The drift change set applied between run 1 and run 2 (DEVILS-ADVOCATE §4.3 G13 / G13b).
RUN2_CHANGES = [
    {"target": "z02", "change": "disable_version", "version": "TLSv1.0"},
    {"target": "z04", "change": "reissue_cert"},  # same subject and issuer, valid again
    {"target": "host", "change": "remove_file", "path": "keys/legacy-rsa1024.key"},
    {"target": "z08", "change": "start"},
    {"target": "control-tls", "change": "start", "replaces": "control"},
]

# Positive controls (rule O-8): a negative observation only counts when the same tool, in the same capture, observed
# the positive on the named target. Keys are "<kind of negative>"; values the target that must show the positive.
CONTROLS = {
    "tls_version_refused:TLSv1.0": "z16", "tls_version_refused:TLSv1.1": "z02",
    "tls_version_refused:TLSv1.2": "z04", "tls_version_refused:TLSv1.3": "z01",
    "tls_group_absent:X25519MLKEM768": "z05", "tls_group_absent:x25519": "z01", "tls_group_absent:secp256r1": "z01",
    "tls_group_absent:secp384r1": None, "tls_group_absent:secp521r1": None,
    "tls12_group_absent:x25519": "z04", "tls12_group_absent:secp256r1": "z02",
    "tls12_group_absent:secp384r1": None, "tls12_group_absent:secp521r1": None,
    "ssh_no_pq_kex": "sshd-pq", "pg_ssl_off": "pg-tls", "mysql_ssl_off": "mysql-tls", "listener_untouched": ["control", "idn-punycode"],
}


def by_id(target_id: str) -> dict:
    for t in TARGETS:
        if t["id"] == target_id:
            return t
    raise KeyError(target_id)


def validate_catalogue(targets: list[dict] | None = None) -> list[str]:
    """Problems that make a catalogue unusable (duplicate ids or addresses, names outside the registries)."""
    targets = TARGETS if targets is None else targets
    problems: list[str] = []
    net = ipaddress.ip_network(NETWORK["subnet"])
    seen_id: set[str] = set()
    seen_ip: dict[str, str] = {NODE_IP: "node", TOOLS_IP: "tools", BURST_IP: "burst", NETWORK["gateway"]: "gateway",
                                NGINX_IP: "nginx (CB-03)"}
    for t in targets:
        if t["id"] in seen_id:
            problems.append(f"duplicate id {t['id']}")
        seen_id.add(t["id"])
        if t["profile"] not in PROFILES:
            problems.append(f"{t['id']}: unknown profile {t['profile']}")
        ip = t.get("ip")
        if ip:
            if ipaddress.ip_address(ip) not in net:
                problems.append(f"{t['id']}: {ip} outside {net}")
            other = next((x for x in targets if x["id"] == seen_ip.get(ip)), {})
            if ip in seen_ip and t.get("replaces") != seen_ip[ip] and other.get("replaces") != t["id"]:
                problems.append(f"{t['id']}: {ip} already used by {seen_ip[ip]}")
            seen_ip[ip] = t["id"]
        if t["kind"] == "tls":
            for v in t["versions"]:
                if v not in VERSIONS:
                    problems.append(f"{t['id']}: unknown version {v}")
            for s in t["suites"]:
                if s not in SUITES:
                    problems.append(f"{t['id']}: suite {s} has no OpenSSL name in SUITES")
            for g in t["groups"]:
                if g not in GROUPS:
                    problems.append(f"{t['id']}: group {g} unknown")
                if "TLSv1.3" in t["versions"] and g not in OBSERVABLE_GROUPS:
                    problems.append(f"{t['id']}: group {g} cannot be observed by tlscheck")
            if any(v != "TLSv1.3" for v in t["versions"]) and not t["suites"]:
                problems.append(f"{t['id']}: TLS <= 1.2 enabled without an explicit suite list")
            if t["sni_required"] and not t["sni"]:
                problems.append(f"{t['id']}: sni_required without a name")
            for key, names in (t.get("must_report") or {}).items():
                pool = {"cipher_suites": t["suites"], "groups": t["groups"]}.get(key)
                if pool is None or not set(names) <= set(pool):
                    problems.append(f"{t['id']}: must_report {key} {names} not all planted")
    return problems
