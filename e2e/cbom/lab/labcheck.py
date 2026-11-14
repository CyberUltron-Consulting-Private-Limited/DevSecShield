"""CB-02 independent self-check (DEVILS-ADVOCATE §3 O-3, O-5, O-8): every running lab target is measured with tools
that share no code with the scan node's collectors, and compared with the oracle gen.py wrote.

Runs on the host (stdlib only) and drives the tools through `docker exec cb02-tools ...`:
  TLS versions, TLS 1.3 groups, served certificates  tlscheck (Go crypto/tls)    [node: OpenSSL s_client + cryptography]
  cipher suites (every enabled version)               nmap ssl-enum-ciphers (NSE's own TLS code)
  SSH algorithms / host keys                          nmap ssh2-enum-algos, ssh-keyscan + labread blobs, ssh-audit
                                                                                  [node: paramiko]
  PostgreSQL / MySQL TLS                              tlscheck pg|mysql; the server's own view (psql / mysql client)
  TLS <= 1.2 groups                                   tlscheck hello, one group per handshake (equality)
  certificates (served, planted, in keystores)        Go crypto/x509 (served), labread's DER reader (files)
  keystores                                           labread's JKS reader; openssl pkcs12 (OpenSSL, not Java)
  SoftHSM objects                                     p11tool (GnuTLS); labread's SoftHSM object-store reader
  planted files                                       ssh login + sha256sum/stat (ForceCommand-logged)
  ML-DSA certificate endpoints (Go has no ML-DSA)     openssl s_client from the tools image, recorded as the fallback;
                                                      certificates: labread DER on served bytes == the generated file
Every key that `oracle/run<k>.json` asserts is compared with such an observation (rows carry `verifies`); per target,
`independent_keys` lists what an independent row confirmed and `unverified_keys` what nothing independent did (the
gate judges those NOT-JUDGED, INTERFACES v7.1). The run file itself is rebuilt from the facts and must be identical.
A disagreement is a lab bug: the target's rows become "not judged (lab)" (exit 2), never a product pass.
Every negative observation is paired with a positive control seen by the same tool in the same capture (O-8).
Writes <run>/lab/selfcheck.json (INTERFACES v1 §7) and keeps raw tool output under <run>/lab/selfcheck-raw/.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import labgen  # noqa: E402  (the generator's pkcs11-tool parser, used only by the identity row)
import labread as R  # noqa: E402  (independent readers: DER, JKS, SoftHSM object store, SSH blobs)
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
        self.step = "run1"
        self.assets: dict[str, dict[str, dict]] = {}   # target -> oracle_id -> asset of oracle/run<k>.json

    def target(self, tid: str) -> "Target":
        return Target(tid, self.assets.get(tid, {}))

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
    """Collects the checks of one target in the CB-01 §7 row format. `assets` are the target's assets of the run
    file CB-01 judges (oracle/run<k>.json), by oracle_id: `expect()` compares their values with an observation."""

    def __init__(self, tid: str, assets: dict[str, dict] | None = None):
        self.tid, self.checks, self.controls, self.gaps = tid, [], [], []
        self.assets = assets or {}

    def check(self, oracle_id: str, key: str, tool: str, expected, observed, agree: bool | None = None,
              note: str = "", independent: bool = True, reason: str = "",
              verifies: list[tuple[str, str]] | None = None) -> bool:
        """One comparison. `independent` is False when the observation cannot disagree with the oracle for reasons
        other than the target (same tool and file as the generator, or the scan node's own library); such rows are
        reported but never count as O-3 evidence. `verifies` names the run-file (oracle_id, expect key) pairs the
        row proves when it agrees."""
        ok = (expected == observed) if agree is None else agree
        row = {"oracle_id": oracle_id, "key": key, "tool": tool, "expected": expected, "observed": observed, "agree": ok,
               "independent": independent, "verifies": [{"oracle_id": o, "key": k} for o, k in verifies or []]}
        if not independent:
            row["not_independent_reason"] = reason or "same tool and file as the generator (identity check)"
        if note:
            row["note"] = note
        self.checks.append(row)
        return ok

    def expect(self, oracle_id: str, key: str, tool: str, observed, *, norm=None, independent: bool = True,
               reason: str = "", note: str = "") -> bool | None:
        """Compare the run file's value of (oracle_id, key) with `observed` (oracle normal form; `norm` maps both
        sides first). Returns None when the run file does not assert the key."""
        asset = self.assets.get(oracle_id)
        if asset is None or key not in (asset.get("expect") or {}):
            return None
        want = asset["expect"][key]
        f = norm or (lambda v: v)
        return self.check(oracle_id, key, tool, want, observed, agree=f(want) == f(observed), note=note,
                          independent=independent, reason=reason, verifies=[(oracle_id, key)])

    def unobserved(self, oracle_id: str, key: str, tool: str, reason: str) -> None:
        """No observation of an asserted key was possible (not a disagreement; the key stays unverified)."""
        self.gaps.append({"oracle_id": oracle_id, "key": key, "tool": tool, "reason": reason})

    def control(self, negative: str, control_target: str | None, satisfied: bool, detail: str) -> None:
        self.controls.append({"negative": negative, "control_target": control_target, "satisfied": satisfied,
                              "detail": detail})

    def asserted(self) -> dict[str, list[str]]:
        """Every (oracle_id, key) the run file asserts for this target: expect keys, plus must_report."""
        return {oid: sorted([*(a.get("expect") or {}), *(["must_report"] if a.get("must_report") else [])])
                for oid, a in self.assets.items()}

    def result(self) -> dict:
        agree = all(c["agree"] for c in self.checks) and all(c["satisfied"] for c in self.controls)
        proven: dict[str, set] = {}
        for c in self.checks:
            if c["agree"] and c["independent"]:
                for v in c.get("verifies", []):
                    proven.setdefault(v["oracle_id"], set()).add(v["key"])
        asserted = self.asserted()
        independent = {oid: sorted(set(keys) & proven.get(oid, set())) for oid, keys in asserted.items()}
        unverified = {oid: sorted(set(keys) - proven.get(oid, set())) for oid, keys in asserted.items()}
        unverified = {oid: keys for oid, keys in unverified.items() if keys}
        return {"target_id": self.tid, "agree": agree, "verified_independently": not unverified,
                "independent_keys": {oid: k for oid, k in independent.items() if k}, "unverified_keys": unverified,
                "unobserved": self.gaps, "checks": self.checks, "controls": self.controls}


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


# nmap names the Montgomery curves "ecdh_x25519" / "ecdh_x448"; the oracle uses the IANA group names.
NMAP_GROUPS = {"ecdh_x25519": "x25519", "ecdh_x448": "x448"}


def parse_nmap_kex(xml_text: str) -> dict[str, list[str]]:
    """ssl-enum-ciphers -oX: the key-exchange group the server chose for its ECDHE suites, per protocol (kex_info)."""
    out: dict[str, list[str]] = {}
    root = ET.fromstring(xml_text)
    for script in root.iter("script"):
        if script.get("id") != "ssl-enum-ciphers":
            continue
        for proto in script.findall("table"):
            groups = set()
            for ciphers in proto.findall("table"):
                if ciphers.get("key") != "ciphers":
                    continue
                for c in ciphers.findall("table"):
                    elems = {e.get("key"): (e.text or "").strip() for e in c.findall("elem")}
                    if "ECDHE" in elems.get("name", "") and elems.get("kex_info"):
                        groups.add(NMAP_GROUPS.get(elems["kex_info"], elems["kex_info"]))
            out[proto.get("key", "")] = sorted(groups)
    return out


def legacy_groups_agree(expected: list[str], by_version: dict[str, list[str]]) -> bool:
    """TLS <= 1.2 cross-check: nmap sees only the group the server prefers, so it must be a non-empty subset (the
    exact list comes from `legacy_groups_accepted`, one group per handshake)."""
    seen = {g for v, gs in by_version.items() if v != "TLSv1.3" for g in gs}
    return bool(seen) and seen <= set(expected)


# Groups a TLS <= 1.2 handshake can carry (the ML-KEM hybrids exist only in TLS 1.3).
LEGACY_PROBE_GROUPS = ["x25519", "secp256r1", "secp384r1", "secp521r1"]


def legacy_groups_accepted(results: dict[str, dict]) -> list[str]:
    """`tlscheck hello -version 1.x -group G` per group: the server accepts G when the handshake completed with G
    (with only G offered, an ECDHE suite cannot use anything else; a refused group ends in static RSA or a failure)."""
    return sorted(g for g, r in results.items() if r.get("ok") and r.get("group") == g)


NMAP_TLS13 = re.compile(r"^TLS_AKE_WITH_")  # nmap names TLS 1.3 suites TLS_AKE_WITH_*; IANA names drop "AKE_WITH_"


def iana_suite(name: str) -> str:
    return NMAP_TLS13.sub("TLS_", name)


P11_TYPE = re.compile(r"Type:\s*(Private key|Public key|Secret key)(?:\s*\(([^)]*)\))?")
EC_BITS = {"SECP256R1": 256, "SECP384R1": 384, "SECP521R1": 521}


def parse_p11tool(text: str) -> list[dict]:
    """`p11tool --list-all` (GnuTLS, a different PKCS#11 client from OpenSC's pkcs11-tool that built the oracle): one
    dict per private or secret key. p11tool prints no algorithm or size for secret keys (key_type/bits None there)."""
    out = []
    for block in re.split(r"\n(?=Object \d+:)", text.strip()):
        m = P11_TYPE.search(block)
        if not m or m.group(1) == "Public key":
            continue
        inner = (m.group(2) or "").upper()
        family, bits = None, None
        if inner.startswith("EC"):
            family, bits = "EC", EC_BITS.get(inner.rsplit("-", 1)[-1])
        elif re.fullmatch(r"[A-Z0-9]+-\d+", inner):
            family, size = inner.rsplit("-", 1)
            bits = int(size)
        flags = re.search(r"Flags:\s*(.*)", block)
        flagset = {f.strip() for f in (flags.group(1) if flags else "").split(";") if f.strip()}
        label = re.search(r"Label:\s*(.*)", block)
        out.append({"label": label.group(1).strip() if label else "",
                    "class": "Private Key" if m.group(1) == "Private key" else "Secret Key",
                    "key_type": family, "bits": bits, "extractable": "CKA_EXTRACTABLE" in flagset})
    return sorted(out, key=lambda o: o["label"])


P11_CLASSES = {"Private key": "Private Key", "Public key": "Public Key", "Secret key": "Secret Key"}
TOKEN_SET_KEY = "non-public objects on the token == the run file's managed_key rows (both ways)"


def p11tool_objects(text: str) -> list[tuple[str, str]]:
    """Every object block `p11tool --list-all` prints, as (label, class); nothing is skipped: a type that is not a key
    (certificate, data) keeps the printed type as its class, an unreadable block becomes ("", "unknown")."""
    out = []
    for block in re.split(r"\n(?=Object \d+:)", text.strip()):
        if not re.match(r"Object \d+:", block):
            continue
        typ = re.search(r"Type:\s*([^\n(]+)", block)
        label = re.search(r"Label:\s*(.*)", block)
        kind = typ.group(1).strip() if typ else "unknown"
        out.append((label.group(1).strip() if label else "", P11_CLASSES.get(kind, kind)))
    return sorted(out)


def token_set_row(t: Target, token: str, objects: list[tuple[str, str]], tool: str) -> bool:
    """Closed world in both directions (review 5878784465): the token's non-public objects, as the independent
    reader lists them, are exactly the run file's managed_key rows of that token. A generator parser that drops an
    object (the oracle omits it) disagrees here, as does one that invents one."""
    prefix = f"softhsm/{token}/"
    asserted = sorted(oid.removeprefix(prefix) for oid in t.assets if oid.startswith(prefix))
    observed = sorted(f"{label}/{cls}" for label, cls in objects if cls != "Public Key")
    return t.check(f"softhsm/{token}", TOKEN_SET_KEY, tool, asserted, observed)


def hsm_mismatches(requested: list[dict], observed: list[dict]) -> list[str]:
    """Compare the catalogue's requested objects (labspec, the designer's intent) with an independent observation."""
    problems = []
    for r in requested:
        family, _, size = r["key_type"].partition(":")
        want_class = "Private Key" if r["make"] == "keypair" else "Secret Key"
        want_bits = {"prime256v1": 256, "secp384r1": 384}.get(size) or (int(size) * 8 if family == "AES" else int(size))
        got = [o for o in observed if o["label"] == r["label"] and o["class"] == want_class]
        if len(got) != 1:
            problems.append(f"{r['label']}: {len(got)} {want_class} objects")
            continue
        o = got[0]
        for key, want in (("key_type", family.upper()), ("bits", want_bits), ("extractable", r["extractable"])):
            if o[key] != want:
                problems.append(f"{r['label']}: {key} {o[key]!r} != requested {want!r}")
    return problems


def forcecommand_missing(file_rows: list[dict], container_rows: list[dict]) -> list[dict]:
    """Entries of the authoritative record (the container log) that the file copy lacks: a truncated or edited file."""
    have = [json.dumps(r, sort_keys=True) for r in file_rows]
    missing = []
    for r in container_rows:
        k = json.dumps(r, sort_keys=True)
        if k in have:
            have.remove(k)
        else:
            missing.append(r)
    return missing


GO_CURVES = {"P-256": "P-256", "P-384": "P-384", "P-521": "P-521"}


def go_cert(ci: dict) -> dict:
    """tlscheck's certificate description (Go crypto/x509) in labread.x509_facts' shape."""
    return {"fingerprint_sha256": ci.get("sha256"), "serial": ci.get("serial"),
            "signature_algorithm_oid": ci.get("sig_alg_oid"), "subject": ci.get("subject"), "issuer": ci.get("issuer"),
            "not_before": ci.get("not_before"), "not_after": ci.get("not_after"),
            "algorithm": R.KEY_ALG.get(ci.get("pubkey_oid") or "", ci.get("pubkey_oid")),
            "key_size": ci.get("key_bits") or None, "curve": GO_CURVES.get(ci.get("curve") or "")}


def _serial(v):
    try:
        return int(str(v), 16)
    except (TypeError, ValueError):
        return v


CERT_NORMS = {"signature_algorithm": lambda v: R.SIG_ALG.get(v, v), "serial": _serial,
              "subject": R.name_key, "issuer": R.name_key}
CERT_KEYS = ("algorithm", "key_size", "curve", "signature_algorithm", "not_before", "not_after", "subject", "issuer",
             "serial", "fingerprint_sha256", "quantum_vulnerable")


def cert_rows(t: "Target", oid: str, ob: dict | None, tool: str, *, independent: bool = True, reason: str = "") -> None:
    """Every certificate key the run file asserts for `oid`, against one observed certificate (labread shape)."""
    if not ob:
        for key in CERT_KEYS:
            if key in ((t.assets.get(oid) or {}).get("expect") or {}):
                t.unobserved(oid, key, tool, "certificate not observed")
        return
    observed = {**ob, "signature_algorithm": ob.get("signature_algorithm_oid"),
                "quantum_vulnerable": oraclefmt.QUANTUM_VULNERABLE.get(ob.get("algorithm") or "")}
    for key in CERT_KEYS:
        t.expect(oid, key, tool, observed.get(key), norm=CERT_NORMS.get(key), independent=independent, reason=reason)


def keystore_entry(alias: str, typ: str, der: bytes) -> dict:
    x = R.x509_facts(der)
    return {"alias": alias, "type": typ, "key_algorithm": x["algorithm"], "key_bits": x["key_size"],
            "signature_algorithm": x["signature_algorithm_oid"], "cert_sha256": x["fingerprint_sha256"]}


def norm_entries(entries) -> list | None:
    """Keystore entries compared by alias, signature algorithms by OID (Java and OpenSSL name them differently)."""
    if entries is None:
        return None
    return sorted(({**e, "signature_algorithm": R.SIG_ALG.get(e.get("signature_algorithm"), e.get("signature_algorithm"))}
                   for e in entries), key=lambda e: e.get("alias") or "")


def parse_p12_bags(text: str) -> list[tuple[str, str, bytes]]:
    """`openssl pkcs12 -nokeys` output: (friendlyName, entry type, certificate DER) per certificate bag. A bag with a
    localKeyID belongs to a key (PrivateKeyEntry); Java marks trusted certificates with its
    "Trusted key usage (Oracle)" attribute (trustedCertEntry)."""
    out = []
    for block in re.split(r"(?=Bag Attributes)", text):
        ders = R.pem_blocks(block)
        if not ders:
            continue
        name = re.search(r"friendlyName:\s*(\S+)", block)
        typ = ("PrivateKeyEntry" if "localKeyID" in block else
               "trustedCertEntry" if "Trusted key usage" in block else "unknown")
        out.append((name.group(1) if name else "", typ, ders[0]))
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
def proto_list(versions: dict[str, bool]) -> list[str]:
    return sorted(oraclefmt.PROTO[v] for v, on in versions.items() if on)


def oracle_groups(names) -> list[str]:
    return sorted(oraclefmt.GROUPS.get(g, g) for g in names)


def check_tls(ctx: Ctx, o: dict) -> Target:
    t, e = ctx.target(o["target"]), o["expect"]
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
    t.check(oid, "versions (facts)", tool, e["versions"], obs["versions"])
    t.expect(oid, "protocol_versions", tool, proto_list(obs["versions"]))
    groups13 = sorted(m.get("groups_tls13") or [])
    if e["versions"].get("TLSv1.3"):
        obs["groups"] = groups13
        t.expect(oid, "groups", tool, oracle_groups(groups13), note="TLS 1.3, one group per handshake")
    t.expect(oid, "quantum_vulnerable", tool, oraclefmt.derive_tls_qv(obs["versions"], groups13),
             note="no accepted key exchange includes ML-KEM (TLS 1.3 groups as observed; unknown group: not derived)")
    ctx.observed[o["target"]] = obs
    # certificates served (leaf first): every asserted field, from Go's crypto/x509
    chain = m.get("chain") or []
    t.check(f"{o['target']}/cert", "fingerprint_sha256 (served chain)", tool, [c["sha256"] for c in e["certificates"]],
            [c.get("sha256") for c in chain])
    for i in range(len(e["certificates"])):
        cert_rows(t, f"{o['target']}/cert[{i}]", go_cert(chain[i]) if i < len(chain) else None, tool)
    # cipher suites, every enabled version: nmap ssl-enum-ciphers (TLS 1.3 included)
    enabled = [v for v, on in e["versions"].items() if on]
    legacy = [v for v in enabled if v != "TLSv1.3"]
    args = ["nmap", "-Pn", "-n", "-p", str(o["port"]), "--script", "ssl-enum-ciphers", "-oX", "-", o["address"]]
    if sni:
        args[-1:-1] = ["--script-args", f"tls.servername={sni}"]
    res = ctx.exec(*args)
    ctx.save(f"{o['target']}.nmap-ssl.xml", res.stdout)
    ntool = "nmap 7.97 ssl-enum-ciphers"
    ctx.tool_versions["nmap"] = "nmap 7.97"
    try:
        suites = {v: sorted(iana_suite(x) for x in names) for v, names in parse_nmap_ciphers(res.stdout).items()}
    except ET.ParseError:
        suites = {}
    want_v = {**e["suites"], **({"TLSv1.3": sorted(e.get("tls13_suites") or [])} if "TLSv1.3" in enabled else {})}
    missing = [v for v in enabled if v not in suites]
    for v in enabled:
        if v in suites:
            t.check(oid, f"cipher_suites[{v}]", ntool, sorted(want_v.get(v, [])), suites[v])
    seen = sorted({x for v in enabled for x in suites.get(v, [])})
    if missing:
        t.unobserved(oid, "cipher_suites", ntool, f"nmap printed no suite table for {', '.join(missing)}")
    else:
        t.expect(oid, "cipher_suites", ntool, seen)
    must_report_row(t, oid, seen, ntool)
    if legacy:
        ecdhe = any("ECDHE" in s_ for v in legacy for s_ in e["suites"].get(v, []))
        if e.get("groups") is not None and ecdhe:
            try:
                kex = parse_nmap_kex(res.stdout)
            except ET.ParseError:
                kex = {}
            legacy_kex = {v: g for v, g in kex.items() if v in legacy}
            t.check(oid, "groups (TLS <= 1.2, nmap's preferred group, cross-check)", ntool, sorted(e["groups"]),
                    sorted({g for gs in legacy_kex.values() for g in gs}),
                    agree=legacy_groups_agree(e["groups"], legacy_kex),
                    note="the server's preferred group per ECDHE suite: must be a non-empty subset of the oracle")
            # exact: one handshake per group at the highest legacy version (review 5874442142, E2)
            top = max(legacy, key=S.VERSIONS.index)
            probes = {g: ctx.tlscheck("hello", "-addr", addr, "-version", top.removeprefix("TLSv"), "-group", g,
                                      *(["-sni", sni] if sni else [])) for g in LEGACY_PROBE_GROUPS}
            ctx.save(f"{o['target']}.tlscheck-groups12.json", json.dumps(probes, indent=1))
            accepted = legacy_groups_accepted(probes)
            obs["groups_legacy"] = accepted
            note = f"{top}, one group per handshake; equality: a group the server accepts beyond the oracle disagrees"
            if "TLSv1.3" not in enabled:
                t.expect(oid, "groups", tool, oracle_groups(accepted), note=note)
            else:  # the TLS 1.3 row proves the list; the classical part must hold at TLS <= 1.2 as well
                want = classical_groups(e["groups"])
                t.check(oid, f"groups ({top}, classical part)", tool, want, accepted, note=note)
        elif e.get("groups") is not None and "TLSv1.3" not in enabled:
            t.unobserved(oid, "groups", "tlscheck hello", "no ECDHE suite, so no group to observe at TLS <= 1.2")
        go = m.get("suites_go") or {}
        for v in legacy:
            extra = sorted(set(go.get(v, [])) - set(e["suites"].get(v, [])))
            t.check(oid, f"cipher_suites[{v}] (Go subset)", tool, [], extra,
                    note="suites Go negotiated that the oracle does not list")
    return t


def must_report_row(t: Target, oid: str, seen: list[str], tool: str) -> None:
    """Every suite the run file says the product must report is one the server accepts (as observed)."""
    must = ((t.assets.get(oid) or {}).get("must_report") or {}).get("cipher_suites")
    if must:
        t.check(oid, "must_report.cipher_suites accepted by the server", tool, sorted(must),
                sorted(set(must) & set(seen)), verifies=[(oid, "must_report")])


def classical_groups(groups: list[str]) -> list[str]:
    """The groups without a PQ KEM (closed table: an unknown name raises, it is never read as classical)."""
    return sorted(g for g in groups if not oraclefmt.tls_group_pq(g))


def ssh_pq_kex(kex: list[str]) -> list[str]:
    """Key exchanges known to include a PQ KEM (positive evidence only: an unknown name is not counted as PQ, and
    the kex_algorithms row reports it as a disagreement)."""
    return [k for k in kex if oraclefmt.SSH_KEX_PQ.get(k) is True]


def generated_certificates(run: Path, target: str) -> dict[str, str]:
    """sha256 -> file of every certificate the generator wrote for a target's server (read from the run directory on
    the host, not through any TLS client)."""
    out: dict[str, str] = {}
    d = run / "lab" / "targets" / target
    for name in ("cert.pem", "_ca.pem", "chain.pem"):
        p = d / name
        if p.is_file():
            for der in R.pem_blocks(p.read_text()):
                out.setdefault(hashlib.sha256(der).hexdigest(), f"lab/targets/{target}/{name}")
    return out


def check_tls_mldsa(ctx: Ctx, o: dict, t: Target) -> Target:
    """Go's crypto/tls cannot verify an ML-DSA CertificateVerify, so it must fail; openssl s_client (tools image,
    OpenSSL 3.5) fetches the certificate and measures versions and groups. Recorded as the documented fallback:
    every key it proves stays in `unverified_keys` (the gate judges them NOT-JUDGED, lab-not-independent)."""
    e, addr, oid = o["expect"], f"{o['address']}:{o['port']}", f"{o['target']}/tls"
    m = ctx.tlscheck("matrix", "-addr", addr)
    ctx.save(f"{o['target']}.tlscheck.json", json.dumps(m, indent=1))
    t.check(oid, "classical-only client refused", m.get("tool", "tlscheck"), True,
            not any((m.get("versions") or {}).values()),
            note="the server holds only an ML-DSA certificate, so a client without ML-DSA signature schemes fails")
    tool = "openssl s_client 3.5 (tools image; fallback, see module doc)"
    ctx.tool_versions["openssl s_client"] = tool
    flags = {"TLSv1.0": "-tls1", "TLSv1.1": "-tls1_1", "TLSv1.2": "-tls1_2", "TLSv1.3": "-tls1_3"}
    versions, groups, certs, ders = {}, [], [], []
    for v, flag in flags.items():
        res = ctx.exec("sh", "-c", f"openssl s_client -connect {addr} {flag} -showcerts </dev/null 2>&1")
        ok = "Cipher is (NONE)" not in res.stdout and bool(re.search(r"Protocol\s*:\s*TLSv|New, TLSv", res.stdout))
        versions[v] = ok
        if ok and not certs:
            certs = pem_certs(res.stdout)
            ders = R.pem_blocks(res.stdout)
            ctx.save(f"{o['target']}.s_client.txt", res.stdout)
    for g in ["x25519", "secp256r1", "secp384r1", "X25519MLKEM768"]:
        res = ctx.exec("sh", "-c", f"openssl s_client -connect {addr} -tls1_3 -groups {S.GROUPS[g]} </dev/null 2>&1")
        if re.search(r"New, TLSv1\.3", res.stdout):
            groups.append(g)
    why = ("OpenSSL s_client, the program the scan node's prober wraps (tools image 3.5.9, node 3.5.7): Go has no "
           "ML-DSA signature schemes; a non-OpenSSL ML-DSA client (BoringSSL bssl) is the follow-up")
    t.check(oid, "versions (facts)", tool, e["versions"], versions, independent=False, reason=why)
    t.expect(oid, "protocol_versions", tool, proto_list(versions), independent=False, reason=why)
    t.expect(oid, "groups", tool, oracle_groups(groups), independent=False, reason=why)
    t.expect(oid, "quantum_vulnerable", tool, oraclefmt.derive_tls_qv(versions, groups), independent=False,
             reason=why)
    t.unobserved(oid, "cipher_suites", tool, "no independent TLS 1.3 client completes a handshake with an ML-DSA server")
    # The certificate keys need no TLS library: when the served DER is byte-identical (sha256) to the file the
    # generator wrote, read from the run directory on the host, s_client only transported bytes and labread's DER
    # reader (no OpenSSL) parses them, so those rows count as independent (#75 review 5878413538, CB-02 part).
    files = generated_certificates(ctx.run, o["target"])
    identical = [i < len(ders) and hashlib.sha256(ders[i]).hexdigest() in files for i in range(len(e["certificates"]))]
    btool = "sha256 of the served DER vs the generated file (host)"
    t.check(f"{o['target']}/cert", "fingerprint_sha256 (served chain)", btool if all(identical) else tool,
            [c["sha256"] for c in e["certificates"]], certs, independent=all(identical), reason="" if all(identical) else why)
    for i, c in enumerate(e["certificates"]):
        served = hashlib.sha256(ders[i]).hexdigest() if i < len(ders) else None
        t.check(f"{o['target']}/cert[{i}]", "served DER byte-identical to the generated file", btool,
                c["sha256"], served, agree=identical[i] and served == c["sha256"],
                note=files.get(served or "", "no generated file holds these bytes"))
        cert_rows(t, f"{o['target']}/cert[{i}]", R.x509_facts(ders[i]) if i < len(ders) else None,
                  ("labread DER reader on the served bytes (identical to " + files[served] + ")") if identical[i]
                  else tool + " + labread DER reader",
                  independent=identical[i], reason="" if identical[i] else why)
    ctx.observed[o["target"]] = {"versions": versions, "groups": sorted(groups)}
    return t


def known_hosts(o: dict) -> str:
    return "".join(f"{o['address']} {k['type']} {k['public_key']}\n" for k in o["expect"]["host_keys"])


def parse_banner(text: str) -> list[str]:
    """Protocol versions from SSH identification strings (RFC 4253 §4.2) that ssh-keyscan reports."""
    return sorted({"SSHv2" if m in ("2.0", "1.99") else f"SSHv{m}" for m in re.findall(r"SSH-(\d\.\d+)-", text)})


def check_ssh(ctx: Ctx, o: dict) -> Target:
    t, e = ctx.target(o["target"]), o["expect"]
    oid = f"{o['target']}/ssh"
    res = ctx.exec("nmap", "-Pn", "-n", "-p", str(o["port"]), "--script", "ssh2-enum-algos", "-oX", "-", o["address"])
    ctx.save(f"{o['target']}.nmap-ssh.xml", res.stdout)
    try:
        algs = parse_nmap_ssh(res.stdout)
    except ET.ParseError:
        algs = {}
    tool = "nmap 7.97 ssh2-enum-algos"
    kex = strip_markers(algs.get("kex_algorithms", []))
    t.expect(oid, "kex_algorithms", tool, kex)
    # sshd lists host key algorithms in the order of its loaded keys, not of HostKeyAlgorithms: compared as a set.
    t.expect(oid, "host_key_algorithms", tool, algs.get("server_host_key_algorithms", []), norm=lambda v: sorted(v or []))
    t.expect(oid, "ciphers", tool, algs.get("encryption_algorithms", []))
    t.expect(oid, "macs", tool, algs.get("mac_algorithms", []))
    t.expect(oid, "quantum_vulnerable", tool, oraclefmt.derive_ssh_qv(kex),
             note="no accepted key exchange includes a PQ KEM (nmap's KEX list; unknown name: not derived)")
    types = ",".join(sorted({k["type"].replace("ssh-", "").replace("ecdsa-sha2-nistp256", "ecdsa") for k in e["host_keys"]}
                            | {"rsa", "ecdsa", "ed25519"}))
    ks = ctx.exec("ssh-keyscan", "-T", "5", "-t", types, "-p", str(o["port"]), o["address"])
    ctx.save(f"{o['target']}.keyscan.txt", ks.stdout + ks.stderr)
    seen = parse_keyscan(ks.stdout)
    t.check(oid, "host key blobs served", "ssh-keyscan (OpenSSH 10)", {k["type"]: k["public_key"] for k in e["host_keys"]},
            seen)
    t.expect(oid, "protocol_versions", "ssh-keyscan identification strings", parse_banner(ks.stderr + ks.stdout))
    # type, size and SHA256 fingerprint decoded from the served blobs by labread (not ssh-keygen, the generator's tool)
    served = [R.ssh_key_facts(blob) for blob in seen.values()]
    t.expect(oid, "host_keys", "ssh-keyscan + labread (RFC 4253 blob)", served,
             norm=lambda v: sorted((v or []), key=lambda k: (k.get("type"), k.get("fingerprint_sha256"))))
    au = ctx.exec("ssh-audit", "-j", "-p", str(o["port"]), o["address"])
    ctx.save(f"{o['target']}.ssh-audit.json", au.stdout)
    try:
        audit = json.loads(au.stdout)
        akex = strip_markers([k.get("algorithm", "") for k in audit.get("kex", [])])
    except json.JSONDecodeError:
        akex = []
    t.check(oid, "kex_algorithms (cross-check)", "ssh-audit 3.3.0", sorted(e["kex"]), sorted(akex),
            verifies=[(oid, "kex_algorithms")] if sorted(akex) == sorted(kex) else [])
    ctx.tool_versions.update({"nmap": "nmap 7.97", "ssh-keyscan": "OpenSSH_10.0p2", "ssh-audit": "ssh-audit 3.3.0"})
    pq = ssh_pq_kex(kex)
    ctx.observed[o["target"]] = {"pq_kex": pq}
    check_penalties(ctx, o, t)
    return t


BURST = """import json, socket
counts = {{"banner": 0, "eof": 0, "refused": 0, "error": 0, "other": 0}}
samples = []
for i in range(40):
    try:
        s = socket.create_connection(("{addr}", {port}), 3)
    except OSError:
        counts["error"] += 1          # refused, unreachable, timed out: never reached sshd
        continue
    try:
        s.settimeout(3)
        data = s.recv(64)
    except OSError:
        data = None                   # reset or timeout after the connect
    s.close()
    if data is None:
        counts["error"] += 1
    elif data.startswith(b"SSH-"):
        counts["banner"] += 1
    elif data == b"":
        counts["eof"] += 1            # connected, then closed with no banner
    elif data.startswith(b"Not allowed at this time"):
        counts["refused"] += 1        # sshd's own refusal of a penalised source (OpenSSH >= 9.8, sshd.c drop_connection)
    else:
        counts["other"] += 1
        if len(samples) < 3:
            samples.append(repr(data[:40]))
if samples:
    counts["other_samples"] = samples
print(json.dumps(counts))
"""


def penalty_logged(sshd_log: str, source: str) -> bool:
    """An OpenSSH PerSourcePenalties line for exactly `source` (10.231.0.12 never matches 10.231.0.120)."""
    ip = re.compile(r"(?<![\d.])" + re.escape(source) + r"(?![\d])")
    return any("penalty" in ln and ip.search(ln) for ln in sshd_log.splitlines())


def burst_verdict(counts: dict, log_burst: str, log_all: str, exempt_served: bool,
                  source: str = S.BURST_IP) -> tuple[bool, str]:
    """Did sshd penalise the burst source? A penalised connection reaches sshd and gets no banner: OpenSSH >= 9.8
    writes "Not allowed at this time" and closes (``refused``; live at OpenSSH 10.0, 2026-11-14), and a close with no
    bytes (``eof``) counts the same. A refused or timed-out connection never reached sshd and proves nothing (review
    5878784465), nor does any other payload. Either sshd logged a penalty for that source during this burst and
    dropped connections, or the source is still penalised from an earlier burst (OpenSSH rate-limits the logging,
    but always logs the first activation): every connection was dropped, none failed, a penalty for that source is in
    the container's full log, and the exempt self-check source is served in the same capture. sshd has no other
    per-source refusal configured."""
    banner, eof, refused = counts.get("banner", 0), counts.get("eof", 0), counts.get("refused", 0)
    error, other = counts.get("error", 0), counts.get("other", 0)
    dropped = eof + refused
    total = banner + dropped + error + other
    seen = f"{banner} banners, {refused} refused by sshd, {eof} EOF, {error} errors, {other} other"
    now, ever = penalty_logged(log_burst, source), penalty_logged(log_all, source)
    if dropped and now and not error and not other:
        return True, f"sshd logged a penalty for {source} during the burst; {seen}"
    if total and dropped == total and ever and exempt_served:
        return True, f"{source} still penalised: {seen}; a penalty for it is in the full sshd log; the exempt source is served"
    return False, f"{seen}; penalty logged during the burst: {now}, ever: {ever}; exempt source served: {exempt_served}"


def check_penalties(ctx: Ctx, o: dict, t: Target) -> None:
    """PerSourcePenalties: the server's own effective configuration (`sshd -T`), and on the target that keeps the
    default, a positive control: a burst of connections that never authenticate, from a throwaway source address
    (cb02-burst, .12), must get that source dropped, while the exempt self-check source (.11) is still served."""
    want = o["expect"].get("per_source_penalties")
    if not want:
        return
    oid = f"{o['target']}/ssh"
    eff = subprocess.run(["docker", "exec", o["container"], "/usr/sbin/sshd", "-T", "-f", "/lab/sshd_config"],
                         capture_output=True, text=True)
    lines = {ln.split(" ", 1)[0]: ln.split(" ", 1)[-1] for ln in eff.stdout.splitlines() if " " in ln}
    exempt = lines.get("persourcepenaltyexemptlist", "")
    if want != "default":
        t.check(oid, "PerSourcePenaltyExemptList", "sshd -T (the server's own view)", want.removeprefix("exempt "), exempt)
        return
    t.check(oid, "PerSourcePenalties at the default, only the self-check exempt", "sshd -T (the server's own view)",
            {"persourcepenalties": "default", "exempt": o["expect"].get("penalty_exempt") or "none"},
            {"persourcepenalties": "default" if "noauth:1" in lines.get("persourcepenalties", "") else
             lines.get("persourcepenalties"), "exempt": exempt or "none"})
    image = os.environ.get("CB02_TOOLS_IMAGE", "cb02-lab/tools:dev")
    since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 1))
    burst = subprocess.run(["docker", "run", "--rm", "--name", "cb02-burst", "--label", "com.zeroshield.cbom-lab=cb02",
                            "--network", S.NETWORK["name"], "--ip", S.BURST_IP, "--memory", "64m", "--cap-drop", "ALL",
                            "--security-opt", "no-new-privileges:true", "--entrypoint", "python3", image, "-c",
                            BURST.format(addr=o["address"], port=o["port"])],
                           capture_output=True, text=True, timeout=300)
    try:
        counts = json.loads(burst.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        counts = {"banner": 0, "eof": 0, "refused": 0, "error": 0, "other": 0,
                  "burst_failed": (burst.stderr or burst.stdout)[-300:]}
    ctx.save(f"{o['target']}.burst.json", json.dumps(counts))
    time.sleep(1)
    during = subprocess.run(["docker", "logs", "--since", since, o["container"]], capture_output=True, text=True,
                            check=False)
    full = subprocess.run(["docker", "logs", o["container"]], capture_output=True, text=True, check=False)
    ctx.save(f"{o['target']}.sshd.log", full.stdout + full.stderr)
    after = ctx.exec("python3", "-c", f"import socket; s=socket.create_connection(('{o['address']}', {o['port']}), 3); "
                     "s.settimeout(3); print(s.recv(64)[:8])")
    served = "SSH-" in after.stdout
    penalised, how = burst_verdict(counts, during.stdout + during.stderr, full.stdout + full.stderr, served)
    t.check(oid, "unauthenticated burst from the throwaway source is penalised", "python3 socket burst (.12) + sshd log",
            True, penalised, note=how)
    t.check(oid, "the exempt self-check source is served right after the burst", "python3 socket (.11)", True, served)
    t.control("penalty active (O-8)", o["target"], penalised, how)


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
        oid = f"host:{f['path']}"
        served = t.check(oid, "sha256 (on the host, over SSH)", "ssh + sha256sum (busybox)", f["sha256"], sums.get(f["path"]))
        t.check(oid, "mode", "ssh + stat", f["mode"], modes.get(f["path"]))
        t.expect(oid, "path", "ssh + stat", f["path"] if f["path"] in modes else None)
        # The run directory's copy is the served file (same sha256 above): decoded by labread, not by OpenSSL/Java.
        local = ctx.run / "lab" / "targets" / "host" / "plant" / f["path"].removeprefix("/srv/cbom-lab/")
        if not served or not local.exists():
            continue
        tool = "labread (DER) on the served bytes"
        if f["kind"] == "private_key":
            pk = R.pkcs8_facts(local.read_text())
            t.expect(oid, "algorithm", tool, pk["algorithm"])
            t.expect(oid, "key_size", tool, pk["key_size"])
            t.expect(oid, "quantum_vulnerable", tool, oraclefmt.QUANTUM_VULNERABLE.get(pk["algorithm"]))
        elif f["kind"] == "certificate":
            cert_rows(t, oid, R.x509_facts(R.pem_blocks(local.read_text())[0]), tool)
    time.sleep(1)
    file_rows = jsonl(ctx.run / "lab" / "forcecommand.log")
    container_rows = container_command_log(o["container"])
    logged = [r for r in container_rows if r.get("command") == remote]
    t.check("host/login", "ForceCommand logged the self-check's command (container log, authoritative)",
            "docker logs cb02-host (cb02-cmd lines)", True, bool(logged))
    t.check("host/login", "file copy holds every authoritative entry", "lab/forcecommand.log vs container log", [],
            forcecommand_missing(file_rows, container_rows))
    t.control("read-only command log (O-8)", o["target"], bool(logged), "the self-check's own command is in the log")
    spec = {p_["path"]: p_ for p_ in S.by_id("host")["plant"]}
    for f in e["files"]:
        if f["kind"] == "keystore":
            check_keystore(ctx, o, t, f, spec[f["path"].removeprefix("/srv/cbom-lab/")])
    return t


def container_command_log(container: str) -> list[dict]:
    res = subprocess.run(["docker", "logs", container], capture_output=True, text=True)
    rows = []
    for line in (res.stdout + res.stderr).splitlines():
        if line.startswith("cb02-cmd "):
            try:
                rows.append(json.loads(line[len("cb02-cmd "):]))
            except json.JSONDecodeError:
                pass
    return rows


def check_keystore(ctx: Ctx, o: dict, t: Target, f: dict, spec: dict) -> None:
    """The keystore the host serves (fetched over SSH, sha256 compared), read without Java: a JKS by labread's
    reader of the file format, a PKCS#12 by OpenSSL; certificates decoded by labread. Every asserted key (format,
    entries: alias, type, key algorithm and bits, signature algorithm, certificate sha256) is compared, and the
    entries also with the catalogue's requested ones. The generator's keytool listing parser is not used here."""
    oid = f"host:{f['path']}"
    pw = ctx.secrets.get(f"host-{Path(f['path']).name}-storepass") or ""
    key = "/run-lab/lab/secrets/operator_ed25519"
    fetched = ctx.exec("sh", "-c", f"ssh -i {key} -o UserKnownHostsFile=/tmp/kh-host -o StrictHostKeyChecking=yes "
                       f"-o BatchMode=yes -p {o['port']} zs-cbom@{o['address']} 'base64 {f['path']}' "
                       f"| base64 -d > /tmp/ks.bin && sha256sum /tmp/ks.bin")
    same = t.check(oid, "fetched file sha256", "ssh + base64 + sha256sum", f["sha256"],
                   (fetched.stdout.split() or [None])[0])
    local = ctx.run / "lab" / "targets" / "host" / "plant" / f["path"].removeprefix("/srv/cbom-lab/")
    entries, fmt = [], None
    if f["storetype"] == "PKCS12":
        res = ctx.exec("openssl", "pkcs12", "-in", "/tmp/ks.bin", "-nokeys", "-passin", "env:CB02_P",
                       env={"CB02_P": pw})
        if res.returncode == 0:
            fmt = "PKCS12"
            entries = [keystore_entry(name, typ, der) for name, typ, der in parse_p12_bags(res.stdout)]
        tool = "openssl pkcs12 -nokeys (OpenSSL, not Java) + labread DER"
    else:
        tool = "labread JKS reader + DER"
        if same and local.exists():
            jks = R.jks_entries(local.read_bytes(), pw)
            fmt = jks["format"]
            t.check(oid, "JKS integrity digest with the store password", tool, True, jks["integrity"])
            entries = [keystore_entry(x["alias"], x["type"], x["certs"][0]) for x in jks["entries"]]
    t.expect(oid, "format", tool, fmt)
    t.expect(oid, "entries", tool, entries, norm=norm_entries)
    want = []
    for w in spec["entries"]:
        family, _, bits = w["key"].partition(":")
        want.append({"alias": w["alias"], "type": w["type"], "key_bits": int(bits),
                     "signature_algorithm": R.SIG_ALG.get(f"{w['sig'].upper()}with{family.upper()}")})
    t.check(oid, "entries vs catalogue (alias, type, key bits, signature algorithm)", tool, sorted(want, key=str),
            sorted(({k: x[k] for k in ("alias", "type", "key_bits", "signature_algorithm")} for x in entries), key=str))


def check_listener(ctx: Ctx, o: dict, health: dict[str, str]) -> Target:
    t, e = ctx.target(o["target"]), o["expect"]
    oid = f"{o['target']}/listener"
    t.check(oid, "listening (health, read from /proc/net/tcp)", "docker health", "healthy", health.get(o["container"]))
    for alias in o["aliases"]:
        res = ctx.exec("getent", "hosts", alias)
        t.check(oid, f"name {alias} resolves on the lab network", "getent (docker DNS)", o["address"],
                (res.stdout.split() or [None])[0])
    log = ctx.run / e.get("accept_log", f"lab/listeners/{o['target']}.jsonl")
    lab_log = ctx.run / e.get("lab_accept_log", f"lab/listeners/{o['target']}.lab.jsonl")
    t.check(oid, "accept logs exist (created at up)", "the run directory", [True, True], [log.exists(), lab_log.exists()])
    lab_peers = tuple(f"{a}:" for a in e.get("excluded_sources") or [*S.LAB_SOURCES, "127.0.0.1"])
    if e["role"] == "control":
        res = ctx.exec("python3", "-c", f"import socket; socket.create_connection(('{o['address']}', {o['port']}), 3).close()")
        time.sleep(1)
        rows = [r for r in jsonl(lab_log) if str(r.get("peer", "")).startswith(S.TOOLS_IP + ":")]
        t.check(oid, "accept logged with the peer address (lab log)", "socat + /lab/accept.sh", True,
                bool(rows) and res.returncode == 0)
        ctx.observed[o["target"]] = {"accept_logged": bool(rows)}
        # not TLS (CB-12 v1 §5a): Go crypto/tls completes TCP on every version and no handshake
        addr = f"{o['address']}:{o['port']}"
        m = ctx.tlscheck("matrix", "-addr", addr)
        ctx.save(f"{o['target']}.tlscheck.json", json.dumps(m, indent=1))
        tool = m.get("tool", "tlscheck")
        versions = m.get("versions") or {}
        errors = m.get("version_errors") or {}
        accepted_tcp = bool(versions) and not any(str(x).startswith("dial:") for x in errors.values())
        not_tls = accepted_tcp and not any(versions.values())
        t.check(f"{o['target']}/not_tls", "TCP accepted, no TLS handshake on any version", tool,
                {v: False for v in S.VERSIONS}, {v: versions.get(v) for v in S.VERSIONS},
                agree=not_tls, note="; ".join(f"{k}: {v}" for k, v in sorted(errors.items()))[:300])
        t.expect(f"{o['target']}/not_tls", "status", tool, "not_tls" if not_tls else None)
        t.expect(f"{o['target']}/not_tls", "scope", tool, [addr] if accepted_tcp else None)
    t.check(oid, "the product log holds no lab connection", "lab/listeners/<name>.jsonl", 0,
            sum(1 for r in jsonl(log) if str(r.get("peer", "")).startswith(lab_peers)))
    if e["role"] == "canary" and ctx.step == "run1":
        # Only before run 1: after it the log holds what the product did (judged by the gate, not here).
        t.check(oid, "no connection before the scan", "lab/listeners/<name>.jsonl", 0, len(jsonl(log)))
    return t


def check_postgres(ctx: Ctx, o: dict) -> Target:
    t, e = ctx.target(o["target"]), o["expect"]
    addr, oid = f"{o['address']}:{o['port']}", f"{o['target']}/tls"
    tls_on = e["ssl"] == "on"
    first = ctx.tlscheck("pg", "-addr", addr)
    ctx.save(f"{o['target']}.tlscheck-pg.json", json.dumps(first, indent=1))
    tool = first.get("tool", "tlscheck")
    t.check(oid, "SSLRequest answer", tool, "S" if tls_on else "N", first.get("answer"))
    t.expect(oid, "tls_enabled", tool, first.get("answer") == "S" if first.get("answer") in ("S", "N") else None)
    if tls_on:
        versions = {}
        for v in S.VERSIONS:
            r = ctx.tlscheck("pg", "-addr", addr, "-version", v.removeprefix("TLSv"))
            versions[v] = bool((r.get("tls") or {}).get("ok"))
        t.check(oid, "versions (facts)", tool, e["tls"]["versions"], versions)
        t.expect(oid, "protocol_versions", tool, proto_list(versions))
        certs = (first.get("tls") or {}).get("certs") or []
        t.check(f"{o['target']}/cert", "fingerprint_sha256", tool, [e["tls"]["certificates"][0]["sha256"]],
                [c.get("sha256") for c in certs][:1])
        cert_rows(t, f"{o['target']}/cert[0]", go_cert(certs[0]) if certs else None, tool)
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
    t, e = ctx.target(o["target"]), o["expect"]
    addr, oid = f"{o['address']}:{o['port']}", f"{o['target']}/tls"
    first = ctx.tlscheck("mysql", "-addr", addr)
    ctx.save(f"{o['target']}.tlscheck-mysql.json", json.dumps(first, indent=1))
    tool = first.get("tool", "tlscheck")
    t.check(oid, "CLIENT_SSL offered", tool, e["tls"]["ssl_supported"], first.get("ssl_supported"))
    t.expect(oid, "tls_enabled", tool, first.get("ssl_supported"))
    if e["tls"]["ssl_supported"]:
        want = {v: v in e["tls_version"].split(",") for v in S.VERSIONS}
        got = {}
        for v in S.VERSIONS:
            r = ctx.tlscheck("mysql", "-addr", addr, "-version", v.removeprefix("TLSv"))
            got[v] = bool((r.get("tls") or {}).get("ok"))
        t.check(oid, "protocol_versions", tool, want, got)
        certs = (first.get("tls") or {}).get("certs") or []
        t.check(f"{o['target']}/cert", "fingerprint_sha256", tool, [e["tls"]["certificates"][0]["sha256"]],
                [c.get("sha256") for c in certs][:1])
        cert_rows(t, f"{o['target']}/cert[0]", go_cert(certs[0]) if certs else None, tool)
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


def softhsm_store(tokens_dir: Path) -> dict[str, list[dict]]:
    """labread's reading of the SoftHSM2 object store: token label -> objects (no PKCS#11 library involved)."""
    out: dict[str, list[dict]] = {}
    for token in sorted(p for p in tokens_dir.iterdir() if p.is_dir()):
        tobj = token / "token.object"
        if not tobj.exists():
            continue
        label = R.softhsm_token_label(tobj.read_bytes())
        out[label] = [R.softhsm_object(p.read_bytes()) for p in sorted(token.glob("*.object")) if p.name != "token.object"]
    return out


def check_softhsm(ctx: Ctx, o: dict) -> Target:
    """Every managed_key the run file asserts, per (token, label, class): private keys against p11tool (GnuTLS, not
    OpenSC's pkcs11-tool that built the oracle), secret keys against labread's reader of the SoftHSM2 object store
    (p11tool prints no secret-key size). The generator's pkcs11-tool parser only feeds the identity row."""
    t, e = ctx.target(o["target"]), o["expect"]
    lib = "/usr/lib/softhsm/libsofthsm2.so"
    prep = ("rm -rf /tmp/hsm && mkdir -p /tmp/hsm && cp -R /run-lab/lab/targets/softhsm/tokens /tmp/hsm/ && "
            "printf 'directories.tokendir = /tmp/hsm/tokens\\nobjectstore.backend = file\\nlog.level = ERROR\\n' > /tmp/hsm/c")
    ctx.exec("sh", "-c", prep)
    env = {"SOFTHSM2_CONF": "/tmp/hsm/c"}
    pins = {tok["label"]: ctx.secrets.get(f"softhsm-{tok['label']}-pin", "") for tok in e["tokens"]}
    requested = {tok["label"]: tok["objects"] for tok in S.by_id("softhsm")["tokens"]}
    store = softhsm_store(ctx.run / "lab" / "targets" / "softhsm" / "tokens")
    for tok in e["tokens"]:
        oid = f"softhsm/{tok['label']}"
        listing = ctx.exec("pkcs11-tool", "--module", lib, "--token-label", tok["label"], "--login", "--pin",
                           pins[tok["label"]], "--list-objects", env=env)
        p11 = ctx.exec("p11tool", "--provider", lib, "--login", "--list-all", f"pkcs11:token={tok['label']}",
                       env={**env, "GNUTLS_PIN": pins[tok["label"]]})
        ctx.save(f"softhsm-{tok['label']}.p11tool.txt", p11.stdout)
        p11objs = parse_p11tool(p11.stdout)
        secrets_ = {x["label"]: x for x in store.get(tok["label"], []) if x["class"] == "Secret Key" and x["label"]}
        observed = [({**x, "key_type": secrets_[x["label"]]["key_type"], "bits": secrets_[x["label"]]["bits"]}
                     if x["class"] == "Secret Key" and x["label"] in secrets_ else x) for x in p11objs]
        t.check(oid, "objects vs catalogue (type, size, extractable)", "p11tool (GnuTLS 3.8) + labread object store",
                [], hsm_mismatches(requested[tok["label"]], observed))
        for x in observed:
            aid = f"softhsm/{tok['label']}/{x['label']}/{x['class']}"
            tool = ("p11tool (GnuTLS 3.8)" if x["class"] == "Private Key"
                    else "labread SoftHSM2 object store (+ p11tool flags)")
            t.expect(aid, "algorithm", tool, x["key_type"])
            t.expect(aid, "key_size", tool, x["bits"])
            t.expect(aid, "extractable", "p11tool (GnuTLS 3.8)", x["extractable"])
            t.expect(aid, "quantum_vulnerable", tool, oraclefmt.QUANTUM_VULNERABLE.get(x["key_type"] or ""))
            if x["class"] == "Secret Key" and x["label"] in secrets_:
                t.check(aid, "extractable (object store)", "labread SoftHSM2 object store", x["extractable"],
                        secrets_[x["label"]]["extractable"])
        token_set_row(t, tok["label"], p11tool_objects(p11.stdout), "p11tool (GnuTLS 3.8), every object block")
        seen_ids = {f"softhsm/{tok['label']}/{x['label']}/{x['class']}" for x in observed}
        for aid in sorted(t.asserted()):
            if aid.startswith(f"softhsm/{tok['label']}/") and aid not in seen_ids:
                t.check(aid, "object present", "p11tool (GnuTLS 3.8)", True, False)
        t.check(oid, "objects (re-listed with the generator's tool)", "pkcs11-tool (OpenSC 0.26)", tok["objects"],
                labgen.parse_pkcs11_objects(listing.stdout), independent=False)
        ctx.tool_versions["p11tool"] = "p11tool (GnuTLS 3.8.13)"
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
    t, e = ctx.target(o["target"]), o["expect"]
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
    pinned = S.BENCH_PINNED
    t.check("code/labels", "labels sha256 vs pinned", "labspec.BENCH_PINNED (openpyxl reads by two agents)",
            pinned["labels_sha256"], e["labels_sha256"])
    got = {k: e["summary"].get(k) for k in ("vulnerable", "secure", "judgeable", "judgeable_vulnerable",
                                             "judgeable_secure", "date_typed_line_cells")}
    got["cases"] = len(e["cases"])
    got["unresolved_files"] = e["summary"]["unresolved"]
    t.check("code/labels", "counts vs pinned", "labspec.BENCH_PINNED (openpyxl reads by two agents)",
            {k: pinned[k] for k in got}, got)
    try:
        import openpyxl  # a second, independent xlsx reader when the host has it
    except ImportError:
        openpyxl = None
    if openpyxl is not None:
        ws = openpyxl.load_workbook(labels, read_only=True).worksheets[0]
        rows = [r for r in ws.iter_rows(min_row=2, values_only=True) if r[1]]
        flag = {"=TRUE()": True, "TRUE": True, "1": True, "=FALSE()": False, "FALSE": False, "0": False}
        theirs = [([n.strip() if n.strip().endswith(".java") else n.strip() + ".java" for n in str(r[1]).splitlines()
                    if n.strip()], flag.get(str(r[3]).upper())) for r in rows]
        t.check("code/labels", "cases (files, vulnerable) re-read with openpyxl", f"openpyxl {openpyxl.__version__}",
                [(c["files"], c["vulnerable"]) for c in e["cases"]], theirs)
    relabel = labgen.read_xlsx_labels(labels)
    t.check("code/labels", "cases re-read with the generator's reader", "xlsx reader (stdlib)",
            [(c["files"], c["vulnerable"]) for c in e["cases"]], [(c["files"], c["vulnerable"]) for c in relabel],
            independent=False)
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
        if o["kind"] == "tls" and "groups_legacy" in (ctx.observed.get(tid) or {}):
            want = set(classical_groups(e.get("groups") or []))
            for g in sorted(set(LEGACY_PROBE_GROUPS) - want):
                ctl = S.CONTROLS.get(f"tls12_group_absent:{g}")
                if ctl is None:
                    continue  # no lab target offers it at TLS <= 1.2
                seen = g in (ctx.observed.get(ctl) or {}).get("groups_legacy", [])
                tgt.control(f"group {g} absent at TLS <= 1.2", ctl, seen, f"{ctl} accepts {g} at TLS 1.2 with the same tool")
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


def check_oracle_file(run_dir: Path, step: str, results: dict[str, Target]) -> Target:
    """O-5 beyond the hash: oracle/<step>.json must equal its rebuild from oracle/facts (generated_at aside), so an
    accepted edit of the file CB-01 judges cannot pass (review 5874442142). A difference fails the pseudo-target
    `oracle` and every target it touches."""
    t = Target("oracle")
    try:
        diff = oraclefmt.oracle_diff(json.loads((run_dir / "oracle" / f"{step}.json").read_text()),
                                     oraclefmt.rebuild_run(run_dir, step))
    except (OSError, ValueError, KeyError) as exc:
        diff = {"": [f"rebuild failed: {type(exc).__name__}: {exc}"]}
    t.check(f"oracle/{step}.json", "equals its rebuild from oracle/facts (generated_at ignored)", "oraclefmt.rebuild_run",
            {}, diff)
    for tid, paths in diff.items():
        if tid in results:
            results[tid].check(f"oracle/{step}.json#{tid}", "target entry equals its rebuild from the facts",
                               "oraclefmt.rebuild_run", [], paths)
    return t


def network_endpoints(name: str) -> dict[str, str]:
    res = subprocess.run(["docker", "network", "inspect", name], capture_output=True, text=True)
    if res.returncode != 0:
        return {}
    containers = (json.loads(res.stdout)[0].get("Containers") or {}).values()
    return {c.get("IPv4Address", "").split("/")[0]: c.get("Name", "") for c in containers}


def check_ranges(oracle: dict, endpoints: dict[str, str]) -> Target:
    """Every range a lab network source scans: the empty addresses hold no container on the lab network (so nothing
    answers on any port), and every usable host address is a target, empty, or never-scan (INTERFACES v7 #1)."""
    import ipaddress
    assets = {f"ranges/{r['cidr']}": {"expect": {"empty_addresses": r["empty_addresses"]}}
              for r in oracle.get("ranges") or []}
    t = Target("ranges", assets)
    targets = {x.get("address") for x in oracle.get("targets") or [] if x.get("address")}
    for r in oracle.get("ranges") or []:
        oid = f"ranges/{r['cidr']}"
        hosts = [str(h) for h in ipaddress.ip_network(r["cidr"]).hosts()]
        held = {a: endpoints[a] for a in r["empty_addresses"] if a in endpoints}
        t.check(oid, "empty addresses hold no container", "docker network inspect", {}, held,
                verifies=[(oid, "empty_addresses")] if not held else [])
        unclassified = [h for h in hosts if h not in targets and h not in r["empty_addresses"]
                        and h not in r.get("never_scan", [])]
        t.check(oid, "every host address is a target, empty or never-scan", "ipaddress", [], unclassified)
        t.check(oid, "every target address is held by a running container", "docker network inspect", [],
                [h for h in hosts if h in targets and h not in endpoints])
    return t


def main(run_dir: Path, only: str | None = None, expect_sha: str | None = None) -> int:
    started = iso_now()
    gen_json = json.loads((run_dir / "lab" / "gen.json").read_text())
    recorded, now_hash = expect_sha or gen_json.get("oracle_sha256"), oraclefmt.oracle_hash(run_dir)
    report: dict = {"schema": SCHEMA, "checked_at": started, "run_id": gen_json["run_id"], "oracle_sha256": now_hash,
                    "oracle_sha256_recorded": recorded, "oracle_sha256_source": "argument" if expect_sha else "gen.json",
                    "oracle_changes": gen_json.get("oracle_changes", []), "targets": []}
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
    ctx.step = step
    oracle = json.loads((run_dir / "oracle" / f"{step}.json").read_text())
    ctx.assets = {x["target_id"]: {a["oracle_id"]: a for a in x.get("assets") or []} for x in oracle.get("targets") or []}
    wanted = set(only.split(",")) if only else set(facts)
    results: dict[str, Target] = {}
    order = sorted(facts, key=lambda k: (facts[k]["kind"] == "listener" and facts[k]["expect"]["role"] == "canary", k))
    for tid in order:
        o = facts[tid]
        if tid not in wanted:
            continue
        if o.get("container") and health.get(o["container"]) not in ("healthy", "up"):
            t = ctx.target(tid)
            t.check(f"{tid}/container", "running", "docker ps", "healthy", health.get(o["container"], "absent"))
            results[tid] = t
            continue
        fn = {"tls": check_tls, "ssh": check_ssh, "host": check_host, "postgres": check_postgres,
              "mysql": check_mysql, "softhsm": check_softhsm, "code": check_code}.get(o["kind"])
        try:
            results[tid] = check_listener(ctx, o, health) if o["kind"] == "listener" else fn(ctx, o)
        except Exception as exc:  # a crashed check is a lab problem, reported, never a pass
            t = ctx.target(tid)
            t.check(f"{tid}/selfcheck", "check ran", "selfcheck.py", "completed", f"{type(exc).__name__}: {exc}")
            results[tid] = t
    apply_controls(results, facts, ctx)
    pseudo = {"oracle": check_oracle_file(run_dir, step, results)}
    if not only:
        pseudo["ranges"] = check_ranges(oracle, network_endpoints(S.NETWORK["name"]))
    report["tools"] = ctx.tool_versions
    report["targets"] = [results[k].result() for k in sorted(results)] + [t.result() for t in pseudo.values()]
    rows = [r for r in report["targets"]]
    report["summary"] = {"targets": len(rows), "agree": sum(r["agree"] for r in rows),
                         "disagree": sorted(r["target_id"] for r in rows if not r["agree"]),
                         "checks": sum(len(r["checks"]) for r in rows),
                         "independent_checks": sum(1 for r in rows for c in r["checks"] if c["independent"]),
                         "not_independent_checks": sum(1 for r in rows for c in r["checks"] if not c["independent"]),
                         "asserted_keys": sum(len(v) for r in rows for part in ("independent_keys", "unverified_keys")
                                              for v in r[part].values()),
                         "unverified_keys": {r["target_id"]: r["unverified_keys"] for r in rows if r["unverified_keys"]},
                         "accepted_oracle_changes": len(report["oracle_changes"]),
                         "controls": sum(len(r["controls"]) for r in rows)}
    report["finished_at"] = iso_now()
    (run_dir / "lab" / "selfcheck.json").write_text(json.dumps(report, indent=1, ensure_ascii=False) + "\n")
    print(json.dumps({k: v for k, v in report["summary"].items() if k != "unverified_keys"}
                     | {"unverified": sum(len(k) for v in report["summary"]["unverified_keys"].values()
                                          for k in v.values())}))
    return 0 if not report["summary"]["disagree"] else 2


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]).resolve(), sys.argv[2] if len(sys.argv) > 2 else None))
