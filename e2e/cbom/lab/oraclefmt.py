"""Turn the CB-02 per-target facts into the files CB-01 judges with (cbom/INTERFACES.md v1 §4, §5, §8 and the
CB-02 v2 section): oracle/run<k>.json, lab/lab.json and oracle/canaries.json.

Pure functions over dicts (no I/O except `write_all`), standard library only, no product imports (rule O-1).
Field names and normal forms are CB-01's (§6): TLSv1 for TLS 1.0, NIST curve names, IANA group names, UTC ISO times.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path

SCHEMA_RUN = "zs-cbom-oracle/1"
SCHEMA_LAB = "zs-cbom-lab/1"
SCHEMA_CANARIES = "zs-cbom-canaries/1"

# Quantum vulnerability by key family, transcribed from NIST IR 8547 ipd (Nov 2024) §3-4: RSA, ECDSA, EdDSA, DH,
# ECDH and DSA rely on factoring or discrete logarithms and are broken by a cryptographically relevant quantum
# computer (Shor); ML-KEM (FIPS 203), ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) are the standardised replacements.
# Symmetric keys are not listed: the IR does not classify them as vulnerable, and the oracle states nothing for them.
# Two-agent rule (O-9): this table needs an independent reviewer's sign-off (recorded on the PR).
QUANTUM_VULNERABLE = {"RSA": True, "EC": True, "ED25519": True, "ED448": True, "DSA": True, "DH": True,
                      "ML-DSA-44": False, "ML-DSA-65": False, "ML-DSA-87": False,
                      "ML-KEM-512": False, "ML-KEM-768": False, "ML-KEM-1024": False}
QV_SOURCE = ("NIST IR 8547 ipd (2024-11) sections 3-4, https://doi.org/10.6028/NIST.IR.8547.ipd; endpoints: key exchange "
             "per IANA TLS Supported Groups (ML-KEM code points 0x0200-0x0202, 0x11EB-0x11ED) and OpenSSH 9.0/9.9 "
             "release notes (sntrup761x25519-sha512, mlkem768x25519-sha256)")

# Endpoint key exchange (harvest now, decrypt later). An endpoint row is quantum_vulnerable when NO key exchange it
# accepts includes a post-quantum KEM; a server that also accepts a PQ hybrid is not (CB-01 INTERFACES v7 #2, CB-18's
# "hybrid" class). NIST IR 8547 ipd §3-4: ECDH, finite-field DH and RSA key transport are quantum-vulnerable; ML-KEM
# (FIPS 203) is the standardised replacement. TLS <= 1.2 has no PQ group, so it never makes an endpoint safe.
# Unknown names raise: the generator refuses an oracle it cannot classify (fail closed).
TLS_GROUP_PQ = {"x25519": False, "x448": False, "secp256r1": False, "secp384r1": False, "secp521r1": False,
                "ffdhe2048": False, "ffdhe3072": False, "ffdhe4096": False,
                "X25519MLKEM768": True, "SecP256r1MLKEM768": True, "SecP384r1MLKEM1024": True,   # 0x11EC, 0x11EB, 0x11ED
                "MLKEM512": True, "MLKEM768": True, "MLKEM1024": True}                           # 0x0200-0x0202
SSH_KEX_PQ = {"mlkem768x25519-sha256": True, "sntrup761x25519-sha512": True,
              "sntrup761x25519-sha512@openssh.com": True,
              "curve25519-sha256": False, "curve25519-sha256@libssh.org": False, "ecdh-sha2-nistp256": False,
              "ecdh-sha2-nistp384": False, "ecdh-sha2-nistp521": False, "diffie-hellman-group1-sha1": False,
              "diffie-hellman-group14-sha1": False, "diffie-hellman-group14-sha256": False,
              "diffie-hellman-group16-sha512": False, "diffie-hellman-group18-sha512": False,
              "diffie-hellman-group-exchange-sha1": False, "diffie-hellman-group-exchange-sha256": False}


def tls_endpoint_qv(versions: dict, groups: list[str] | None) -> bool | None:
    """`versions` {"TLSv1.2": bool, ...}; `groups` the IANA names of the groups the server accepts (None: not pinned,
    so the oracle states nothing)."""
    if groups is None:
        return None
    unknown = [g for g in groups if g not in TLS_GROUP_PQ]
    if unknown:
        raise ValueError(f"TLS group(s) {unknown} not classified in TLS_GROUP_PQ")
    return not (bool(versions.get("TLSv1.3")) and any(TLS_GROUP_PQ[g] for g in groups))


def ssh_endpoint_qv(kex: list[str]) -> bool:
    unknown = [k for k in kex if k not in SSH_KEX_PQ]
    if unknown:
        raise ValueError(f"SSH key exchange(s) {unknown} not classified in SSH_KEX_PQ")
    return not any(SSH_KEX_PQ[k] for k in kex)

# Planted findings the lab design names (DEVILS-ADVOCATE §4.2 "Planted" column, E2E-PLAN §4 D2). Nothing else is
# asserted as a product code here; verdict tables beyond these belong to the tracks that own them.
PLANTED_CODES = {"sshd-legacy": ["SSH_NO_PQ_KEX"], "pg-tls": ["DB_MD5_ACCEPTED"], "mysql-tls": ["DB_NATIVE_PW"]}
# Known-fail rows at dev 83b570b (DEVILS-ADVOCATE §4.4) that a lab target exercises.
KNOWN_FAIL = {"z05b": "KF-3", "z09": "KF-4", "sshd-pq": "KF-6", "idn-fass": "KF-7"}

CURVES = {"P-256": "P-256", "prime256v1": "P-256", "secp256r1": "P-256", "P-384": "P-384", "secp384r1": "P-384",
          "P-521": "P-521", "secp521r1": "P-521"}
GROUPS = {"x25519": "X25519", "secp256r1": "secp256r1", "secp384r1": "secp384r1", "secp521r1": "secp521r1",
          "X25519MLKEM768": "X25519MLKEM768"}
PROTO = {"TLSv1.0": "TLSv1", "TLSv1.1": "TLSv1.1", "TLSv1.2": "TLSv1.2", "TLSv1.3": "TLSv1.3"}


def algorithm(cert: dict) -> str:
    alg = (cert.get("key_algorithm") or "").upper()
    return {"ED25519": "ED25519", "EC": "EC", "RSA": "RSA"}.get(alg, alg)


def cert_expect(cert: dict, provenance: str) -> dict:
    alg = algorithm(cert)
    e = {"algorithm": alg, "key_size": cert.get("key_bits"), "curve": CURVES.get(cert.get("curve") or "", cert.get("curve")),
         "signature_algorithm": cert.get("signature_algorithm"), "not_before": cert.get("not_before"),
         "not_after": cert.get("not_after"), "subject": cert.get("subject"), "issuer": cert.get("issuer"),
         "serial": cert.get("serial"), "fingerprint_sha256": cert.get("sha256")}
    if alg in QUANTUM_VULNERABLE:
        e["quantum_vulnerable"] = QUANTUM_VULNERABLE[alg]
    if alg.startswith("ML-DSA") or alg.startswith("SLH-DSA"):
        e["key_size"] = None  # FIPS 204/205 name a parameter set, not a key size
    return {k: v for k, v in e.items() if k != "curve" or v is not None}


def _prov(o: dict, section: str) -> dict:
    p = (o.get("provenance") or {}).get(section) or {}
    return {"source": "gen.py", "detail": "; ".join(p.get("commands", []))[:400] or p.get("tool", ""),
            "tool": p.get("tool", ""), "tool_version": p.get("version", ""), "captured_at": p.get("generated_at", "")}


def assets_for(o: dict) -> tuple[list[dict], list[dict]]:
    """(assets, must_not_appear) for one facts file."""
    t, kind, e = o["target"], o["kind"], o["expect"]
    loc = f"{o['address']}:{o['port']}" if o.get("address") else None
    assets: list[dict] = []
    mna: list[dict] = []
    kf = KNOWN_FAIL.get(t)
    if kind == "tls":
        versions = sorted(PROTO[v] for v, on in e["versions"].items() if on)
        suites = sorted({s for v in e["suites"].values() for s in v} | set(e.get("tls13_suites") or []))
        ep = {"protocol_versions": versions, "cipher_suites": suites}
        if e.get("groups") is not None:
            ep["groups"] = sorted(GROUPS[g] for g in e["groups"])
        qv = tls_endpoint_qv(e["versions"], e.get("groups"))
        if qv is not None:
            ep["quantum_vulnerable"] = qv
        a = {"oracle_id": f"{t}/tls", "asset_type": "tls_endpoint", "location": loc, "expect": ep,
             "provenance": _prov(o, "versions")}
        must = {k: sorted(v) for k, v in (e.get("must_report") or {}).items() if v}
        if must:
            if not set(must.get("cipher_suites", [])) <= set(suites):
                raise ValueError(f"{t}: must_report suites {must['cipher_suites']} are not all accepted")
            a["must_report"] = must
        if not any(v in ("TLSv1", "TLSv1.1") for v in versions):
            a["codes_exclude"] = ["PROTO_TLS10", "PROTO_TLS11"]
        assets.append(a)
        for i, c in enumerate(e["certificates"]):
            assets.append({"oracle_id": f"{t}/cert[{i}]", "asset_type": "certificate", "location": loc,
                           "join": "fingerprint_sha256", "sni": (e.get("sni_names") or [None])[0],
                           "expect": cert_expect(c, ""), "provenance": _prov(o, "certificates")})
    elif kind in ("ssh", "host"):
        assets.append({"oracle_id": f"{t}/ssh", "asset_type": "ssh_endpoint", "location": loc,
                       "expect": {"protocol_versions": ["SSHv2"], "kex_algorithms": e["kex"],
                                  "host_key_algorithms": e["host_key_algorithms"], "ciphers": e["ciphers"],
                                  "macs": e["macs"], "quantum_vulnerable": ssh_endpoint_qv(e["kex"]),
                                  "host_keys": [{k: h[k] for k in ("type", "bits", "fingerprint_sha256")}
                                                for h in e["host_keys"]]},
                       "provenance": _prov(o, "host_keys")})
        if kind == "host":
            for f in e.get("files", []):
                base = {"location": o["address"], "provenance": {"source": "gen.py", "detail": f["path"]}}
                if f["kind"] == "private_key":
                    assets.append({**base, "oracle_id": f"{t}:{f['path']}", "asset_type": "private_key",
                                   "expect": {"path": f["path"], "algorithm": f["key_algorithm"], "key_size": f["key_bits"],
                                              "quantum_vulnerable": QUANTUM_VULNERABLE.get(f["key_algorithm"])}})
                elif f["kind"] == "certificate":
                    assets.append({**base, "oracle_id": f"{t}:{f['path']}", "asset_type": "certificate",
                                   "expect": {"path": f["path"], **cert_expect(f["certificate"], "")}})
                elif f["kind"] == "keystore":
                    assets.append({**base, "oracle_id": f"{t}:{f['path']}", "asset_type": "keystore",
                                   "expect": {"path": f["path"], "format": f["storetype"],
                                              "entries": [{k: x[k] for k in ("alias", "type", "key_algorithm", "key_bits",
                                                                             "signature_algorithm", "cert_sha256")}
                                                          for x in f["entries"]]}})
    elif kind == "listener":
        if e["role"] == "canary":
            for at in ("tls_endpoint", "open_port", "certificate"):
                mna.append({"asset_type": at, "location": loc})
    elif kind in ("postgres", "mysql"):
        tls_on = bool(e.get("tls", {}).get("certificates")) if kind == "mysql" else e.get("ssl") == "on"
        dt = {"oracle_id": f"{t}/tls", "asset_type": "database_tls", "location": loc,
              "expect": {"tls_enabled": tls_on}, "provenance": _prov(o, "config")}
        if tls_on and kind == "postgres":
            dt["expect"]["protocol_versions"] = sorted(PROTO[v] for v, on in e["tls"]["versions"].items() if on)
        assets.append(dt)
        if tls_on:
            for i, c in enumerate(e["tls"]["certificates"]):
                assets.append({"oracle_id": f"{t}/cert[{i}]", "asset_type": "certificate", "location": loc,
                               "join": "fingerprint_sha256", "expect": cert_expect(c, ""),
                               "provenance": _prov(o, "certificates")})
        auth = {"oracle_id": f"{t}/auth", "asset_type": "database_user_auth", "location": loc, "expect": {},
                "provenance": _prov(o, "config")}
        assets.append(auth)
    elif kind == "softhsm":
        for tok in e["tokens"]:
            public = {x["label"]: x for x in tok["objects"] if x["class"] == "Public Key"}
            for obj in tok["objects"]:
                if obj["class"] == "Public Key":
                    continue
                bits = obj["bits"]
                if bits is None and obj["class"] == "Private Key":
                    # pkcs11-tool prints the size on the Public Key line only; a key pair shares it.
                    bits = (public.get(obj["label"]) or {}).get("bits")
                exp = {"algorithm": obj["key_type"], "key_size": bits, "extractable": obj["extractable"]}
                if obj["key_type"] in QUANTUM_VULNERABLE:
                    exp["quantum_vulnerable"] = QUANTUM_VULNERABLE[obj["key_type"]]
                assets.append({"oracle_id": f"{t}/{tok['label']}/{obj['label']}/{obj['class']}",
                               "asset_type": "managed_key", "location": tok["label"], "expect": exp,
                               "provenance": _prov(o, "objects")})
    for a in assets:
        if PLANTED_CODES.get(t) and a["oracle_id"] in (f"{t}/ssh", f"{t}/auth"):
            a["codes_include"] = PLANTED_CODES[t]
        if kf:
            a["known_fail"] = kf
        a["expect"] = {k: v for k, v in a["expect"].items()}
    return assets, mna


def run_oracle(facts: list[dict], step: str, generated_at: str, commit: str, wave: str, sources: dict) -> dict:
    targets = []
    facts_dir = "oracle/facts" if step == "run1" else f"oracle/{step}/facts"
    for o in facts:
        assets, mna = assets_for(o)
        entry = {"target_id": o["target"], "address": o.get("address"), "source": sources.get(o["target"]),
                 "world": o["world"], "assets": assets, "must_not_appear": mna, "selfcheck_ref": o["target"],
                 "facts": f"{facts_dir}/{o['target']}.json"}
        if o["world"] == "open":
            entry["extras_ceiling"] = 80
        if o["kind"] == "code":
            entry["benchmark"] = {"cases": f"oracle/facts/{o['target']}.json", "labels": "the benchmark's own xlsx"}
        targets.append(entry)
    return {"schema": SCHEMA_RUN, "run_step": step, "generated_at": generated_at,
            "generator": {"name": "gen.py", "commit": commit, "wave": wave}, "quantum_vulnerable_source": QV_SOURCE,
            "targets": targets, "ranges": ranges_for(facts), "deferred": deferred()}


def never_scan_names(facts: list[dict]) -> list[str]:
    return [n for o in facts if o["kind"] == "listener" and o["expect"]["role"] == "canary"
            for n in o["aliases"][:1] if n.startswith("cbom-e2e")]


def ranges_for(facts: list[dict]) -> list[dict]:
    """Every range a lab network source scans (CB-01 INTERFACES v7 #1): each usable host address is a target's
    address, an empty address (no lab container holds it, so nothing answers on any port) or a never-scan address.
    A never-scan address may also be a target (the canary listener carries must_not_appear rows)."""
    sources, _ = sources_for(facts)
    taken = {o["address"] for o in facts if o.get("address")}
    names = set(never_scan_names(facts))
    never = {o["address"] for o in facts if o.get("address") and names & set(o.get("aliases") or [])}
    out = []
    for s in sources:
        if s["kind"] != "network":
            continue
        for cidr in s["ranges"]:
            hosts = [str(h) for h in ipaddress.ip_network(cidr).hosts()]
            out.append({"source": s["name"], "cidr": cidr, "empty_addresses": [h for h in hosts if h not in taken],
                        "never_scan": [h for h in hosts if h in never]})
    return out


DRIFT_CODE = {"TLSv1.0": "PROTO_TLS10", "TLSv1.1": "PROTO_TLS11"}


def drift(run1: dict[str, dict], run2: dict[str, dict], changes: list[dict]) -> list[dict]:
    """The G13/G13b drift rows, from the run-1 and run-2 facts and the change set (pure: the self-check rebuilds it)."""
    out: list[dict] = []
    for ch in changes:
        tid = ch["target"]
        if ch["change"] == "disable_version":
            o = run2[tid]
            out.append({"change": "resolved", "code": DRIFT_CODE[ch["version"]], "location": f"{o['address']}:{o['port']}"})
        elif ch["change"] == "reissue_cert":
            o = run2[tid]
            loc = f"{o['address']}:{o['port']}"
            out += [{"change": "cert_renewed", "location": loc,
                     "old_sha256": run1[tid]["expect"]["certificates"][0]["sha256"],
                     "new_sha256": o["expect"]["certificates"][0]["sha256"]},
                    {"change": "resolved", "code": "CERT_EXPIRED", "location": loc}]
        elif ch["change"] == "remove_file":
            full = f"/srv/cbom-lab/{ch['path']}"
            gone = next(f for f in run1[tid]["expect"]["files"] if f["path"] == full)
            out.append({"change": "removed_asset", "asset_type": gone["kind"], "location": run1[tid]["address"],
                        "path": full})
        elif ch["change"] == "start":
            o = run2[tid]
            out.append({"change": "new_asset", "asset_type": "tls_endpoint", "location": f"{o['address']}:{o['port']}"})
    return out


def load_facts(run_dir: Path, step: str) -> list[dict]:
    fdir = run_dir / "oracle" / ("facts" if step == "run1" else f"{step}/facts")
    idx = json.loads((fdir / "index.json").read_text())
    return [json.loads((run_dir / t["facts"]).read_text()) for t in idx["targets"]]


def rebuild_run(run_dir: Path, step: str) -> dict:
    """oracle/<step>.json as the generator would write it from oracle/facts (the self-check's consistency check)."""
    import labspec
    facts = load_facts(run_dir, step)
    current = json.loads((run_dir / "oracle" / f"{step}.json").read_text())
    gen = current.get("generator") or {}
    _, by_target = sources_for(facts)
    out = run_oracle(facts, step, current.get("generated_at", ""), gen.get("commit"), gen.get("wave"), by_target)
    if step != "run1":
        run1 = {o["target"]: o for o in load_facts(run_dir, "run1")}
        out["drift"] = drift(run1, {o["target"]: o for o in facts}, labspec.RUN2_CHANGES)
        out["changes"] = labspec.RUN2_CHANGES
    return out


def _diff_paths(a, b, path: str, out: list[str], limit: int = 20) -> None:
    if len(out) >= limit or a == b:
        return
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b), key=str):
            _diff_paths(a.get(k), b.get(k), f"{path}.{k}", out, limit)
    elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        for i, (x, y) in enumerate(zip(a, b)):
            key = x.get("oracle_id") if isinstance(x, dict) and x.get("oracle_id") else i
            _diff_paths(x, y, f"{path}[{key}]", out, limit)
    else:
        out.append(path)


def oracle_diff(current: dict, rebuilt: dict) -> dict[str, list[str]]:
    """Differences between the run file and its rebuild, by target id ("" = top level); generated_at is ignored."""
    out: dict[str, list[str]] = {}
    top = [k for k in sorted(set(current) | set(rebuilt)) if k not in ("generated_at", "targets")
           and current.get(k) != rebuilt.get(k)]
    if top:
        out[""] = top
    ta = {t.get("target_id"): t for t in current.get("targets") or []}
    tb = {t.get("target_id"): t for t in rebuilt.get("targets") or []}
    for tid in sorted(set(ta) | set(tb), key=str):
        paths: list[str] = []
        _diff_paths(ta.get(tid), tb.get(tid), str(tid), paths)
        if paths:
            out[str(tid)] = paths
    return out


def sources_for(facts: list[dict]) -> tuple[list[dict], dict]:
    """The sources a customer types in the UI (lab.json `sources`) and target -> source name."""
    import labspec
    ids = {o["target"]: o for o in facts}
    by_target: dict = {}
    sources = []

    def inside(o: dict, cidr: str) -> bool:
        return bool(o.get("address")) and ipaddress.ip_address(o["address"]) in ipaddress.ip_network(cidr)

    # Range members are found by address, so a wave target inside a range (sshd-psp .28, run 2's z08 .25 and
    # control-tls .34) belongs to the range's source like the core targets.
    zoo = [o["target"] for o in facts if o["kind"] in ("tls", "ssh") and inside(o, labspec.ZOO_RANGE)]
    if zoo:
        sni = sorted({n for o in facts if o["kind"] == "tls" for n in o["expect"].get("sni_names", [])})
        sources.append({"name": "S-zoo", "kind": "network", "ranges": [labspec.ZOO_RANGE], "sni": sni})
        by_target.update({t: "S-zoo" for t in zoo})
    canary_range = [o for o in facts if inside(o, labspec.CANARY_RANGE)]
    if "canary" in ids and len(canary_range) > 1:
        sources.append({"name": "S-canary", "kind": "linux_servers",
                        "targets": sorted((o["address"] for o in canary_range), key=ipaddress.ip_address), "ports": [443]})
        sources.append({"name": "R-canary", "kind": "network", "ranges": [labspec.CANARY_RANGE]})
        by_target.update({o["target"]: "S-canary" for o in canary_range})
    if "idn-punycode" in ids:
        sources.append({"name": "S-idn", "kind": "linux_servers", "targets": ["faß.lab"], "ports": [443],
                        "expect_resolves_to": ids["idn-punycode"]["address"]})
        by_target.update({"idn-punycode": "S-idn", "idn-fass": "S-idn"})
    if "host" in ids:
        sources.append({"name": "S-host", "kind": "linux_servers", "targets": [ids["host"]["address"]],
                        "login": "zs-cbom", "auth": "node key (CB-05 installs the node's public key)"})
        by_target["host"] = "S-host"
    for o in facts:
        if o["kind"] in ("postgres", "mysql"):
            name = f"DB-{o['target']}"
            reader = "cbom_reader"
            sources.append({"name": name, "kind": "database", "engine": o["kind"], "address": o["address"],
                            "port": o["port"], "user": reader, "secret_ref": f"{o['target']}-{reader}",
                            "ca_pem": "lab/ca.pem", "require_tls": o["kind"] == "postgres" and o["expect"].get("ssl") == "on"})
            by_target[o["target"]] = name
        if o["kind"] == "softhsm":
            sources.append({"name": "HSM-softhsm", "kind": "hsm_pkcs11", "module": "libsofthsm2.so",
                            "token_label": o["expect"]["tokens"][0]["label"],
                            "secret_ref": f"softhsm-{o['expect']['tokens'][0]['label']}-pin",
                            "token_dir": "lab/targets/softhsm/tokens"})
            by_target[o["target"]] = "HSM-softhsm"
    return sources, by_target


def lab_json(facts: list[dict], generated_at: str, commit: str, wave: str, network: dict, node_ip: str) -> dict:
    sources, _ = sources_for(facts)
    targets, listeners, hosts = [], [], {}
    for o in facts:
        if not o.get("address"):
            continue
        if o["kind"] == "listener":
            listeners.append({"name": o["target"], "role": o["expect"]["role"], "address": o["address"],
                              "names": o["aliases"], "ports": [o["port"]], "container": o["container"],
                              "log": f"lab/listeners/{o['target']}.jsonl",
                              "lab_log": f"lab/listeners/{o['target']}.lab.jsonl"})
            continue
        targets.append({"target_id": o["target"], "container": o["container"], "address": o["address"],
                        "names": o["aliases"], "ports": [o["port"]], "kind": o["kind"], "profile": o["profile"]})
        if o["kind"] == "host":
            hosts[o["target"]] = {"address": o["address"], "login": "zs-cbom", "container": o["container"],
                                  "forcecommand_log": "lab/forcecommand.log"}
    return {"schema": SCHEMA_LAB, "network": network["name"], "subnet": network["subnet"], "node_ip": node_ip,
            "generated_at": generated_at, "generator": {"commit": commit, "wave": wave}, "ca_pem": "lab/ca.pem",
            "targets": targets, "listeners": listeners, "hosts": hosts, "sources": sources, "deferred": deferred(),
            "authoritative_command_log": "lab/forcecommand.authoritative.jsonl (from the cb02-host container log)",
            "never_scan": never_scan_names(facts),
            "lab_addresses": lab_addresses()}


def lab_addresses() -> list[str]:
    """The lab's own sources (self-check, psp burst): never product traffic; listener logs keep them out."""
    import labspec
    return list(labspec.LAB_SOURCES)


def deferred() -> list[dict]:
    """Lab parts this build does not provide (labspec.DEFERRED): the gate turns each into NOT-RUN rows with this
    reason, so a missing target never passes or fails by accident."""
    import labspec
    return [{**d, "deferred": True, "issue_draft": labspec.DEFERRED_DRAFT, "issue": labspec.DEFERRED_ISSUE}
            for d in labspec.DEFERRED]


def canaries_json(canaries: list[dict]) -> dict:
    return {"schema": SCHEMA_CANARIES, "canaries": canaries}


def write_all(run: Path, facts: list[dict], canaries: list[dict], *, step: str, generated_at: str, commit: str,
              wave: str, network: dict, node_ip: str) -> None:
    _, by_target = sources_for(facts)
    (run / "oracle").mkdir(parents=True, exist_ok=True)
    (run / "lab").mkdir(parents=True, exist_ok=True)
    (run / "oracle" / f"{step}.json").write_text(json.dumps(
        run_oracle(facts, step, generated_at, commit, wave, by_target), indent=1, sort_keys=True, ensure_ascii=False) + "\n")
    lab_path = run / "lab" / "lab.json"
    lab_path.write_text(json.dumps(lab_json(facts, generated_at, commit, wave, network, node_ip), indent=1,
                                   sort_keys=True, ensure_ascii=False) + "\n")
    cpath = run / "oracle" / "canaries.json"
    cpath.write_text(json.dumps(canaries_json(canaries), indent=1) + "\n")
    cpath.chmod(0o600)


# O-5 frozen oracle: sha256 over the SHA256SUMS text of every file under oracle/ (sorted by path).
def oracle_files(run_dir: Path) -> list[Path]:
    root = run_dir / "oracle"
    return sorted(p for p in root.rglob("*") if p.is_file() and p.name != "SHA256SUMS")


def oracle_sums(run_dir: Path) -> str:
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(run_dir / 'oracle')}"
             for p in oracle_files(run_dir)]
    return "\n".join(lines) + "\n"


def oracle_hash(run_dir: Path) -> str:
    """O-5: sha256 over the oracle's SHA256SUMS text (every file under oracle/, sorted by path)."""
    return hashlib.sha256(oracle_sums(run_dir).encode()).hexdigest()
