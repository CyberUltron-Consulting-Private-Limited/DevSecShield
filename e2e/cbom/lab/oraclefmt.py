"""Turn the CB-02 per-target facts into the files CB-01 judges with (cbom/INTERFACES.md v1 §4, §5, §8 and the
CB-02 v2 section): oracle/run<k>.json, lab/lab.json and oracle/canaries.json.

Pure functions over dicts (no I/O except `write_all`), standard library only, no product imports (rule O-1).
Field names and normal forms are CB-01's (§6): TLSv1 for TLS 1.0, NIST curve names, IANA group names, UTC ISO times.
"""
from __future__ import annotations

import hashlib
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
QV_SOURCE = "NIST IR 8547 ipd (2024-11) sections 3-4, https://doi.org/10.6028/NIST.IR.8547.ipd"

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
        a = {"oracle_id": f"{t}/tls", "asset_type": "tls_endpoint", "location": loc, "expect": ep,
             "provenance": _prov(o, "versions")}
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
                                  "macs": e["macs"],
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
            for obj in tok["objects"]:
                if obj["class"] == "Public Key":
                    continue
                exp = {"algorithm": obj["key_type"], "key_size": obj["bits"], "extractable": obj["extractable"]}
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
    for o in facts:
        assets, mna = assets_for(o)
        entry = {"target_id": o["target"], "address": o.get("address"), "source": sources.get(o["target"]),
                 "world": o["world"], "assets": assets, "must_not_appear": mna, "selfcheck_ref": o["target"],
                 "facts": f"oracle/facts/{o['target']}.json"}
        if o["world"] == "open":
            entry["extras_ceiling"] = 80
        if o["kind"] == "code":
            entry["benchmark"] = {"cases": f"oracle/facts/{o['target']}.json", "labels": "the benchmark's own xlsx"}
        targets.append(entry)
    return {"schema": SCHEMA_RUN, "run_step": step, "generated_at": generated_at,
            "generator": {"name": "gen.py", "commit": commit, "wave": wave}, "quantum_vulnerable_source": QV_SOURCE,
            "targets": targets, "deferred": deferred()}


def sources_for(facts: list[dict]) -> tuple[list[dict], dict]:
    """The sources a customer types in the UI (lab.json `sources`) and target -> source name."""
    ids = {o["target"]: o for o in facts}
    by_target: dict = {}
    sources = []
    zoo = [o["target"] for o in facts if o["kind"] in ("tls", "ssh") and o["profile"] == "core"]
    if zoo:
        sni = sorted({n for o in facts if o["kind"] == "tls" for n in o["expect"].get("sni_names", [])})
        sources.append({"name": "S-zoo", "kind": "network", "ranges": ["10.231.0.16/28"], "sni": sni})
        by_target.update({t: "S-zoo" for t in zoo})
    if "canary" in ids and "control" in ids:
        sources.append({"name": "S-canary", "kind": "linux_servers", "targets": [ids["canary"]["address"],
                        ids["control"]["address"]], "ports": [443]})
        sources.append({"name": "R-canary", "kind": "network", "ranges": ["10.231.0.32/30"]})
        by_target.update(canary="S-canary", control="S-canary")
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
                              "log": f"lab/listeners/{o['target']}.jsonl"})
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
            "never_scan": [n for o in facts if o["kind"] == "listener" and o["expect"]["role"] == "canary"
                           for n in o["aliases"][:1] if n.startswith("cbom-e2e")]}


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
