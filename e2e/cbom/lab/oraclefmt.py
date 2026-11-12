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

# Quantum vulnerability by key family, transcribed from NIST IR 8547 (final, 2026-10-27, "Transition to
# Post-Quantum Cryptography Standards"): §2.1.1-2.1.2 (signatures and SP 800-56A/B key establishment "are vulnerable
# to Shor's Algorithm on a cryptanalytically relevant quantum computer"), §4.1.1 Table 2 (quantum-vulnerable digital
# signatures: ECDSA, EdDSA, RSA) and §4.1.2 Table 4 (quantum-vulnerable key establishment: finite-field DH/MQV,
# elliptic-curve DH/MQV, RSA); the post-quantum replacements are Table 3 / FIPS 204 (ML-DSA) and Table 5 / FIPS 203
# (ML-KEM). DSA is not listed (the IR names no finite-field DSA), so the oracle states nothing for it. Symmetric keys
# are not listed as vulnerable either. Two-agent rule (O-9): this table needs an independent reviewer's sign-off.
QUANTUM_VULNERABLE = {"RSA": True, "EC": True, "ED25519": True, "ED448": True, "DH": True,
                      "ML-DSA-44": False, "ML-DSA-65": False, "ML-DSA-87": False,
                      "ML-KEM-512": False, "ML-KEM-768": False, "ML-KEM-1024": False}
QV_SOURCE = ("NIST IR 8547 (final, 2026-10-27), https://doi.org/10.6028/NIST.IR.8547: 2.1.1-2.1.2 (Shor), "
             "4.1.1 Table 2 (ECDSA, EdDSA, RSA) and 4.1.2 Table 4 (FFC/ECC DH and MQV, RSA) quantum-vulnerable; "
             "4.1.1 Table 3 / FIPS 204 (ML-DSA) and 4.1.2 Table 5 / FIPS 203 (ML-KEM) post-quantum. Endpoints: key "
             "exchange per the IANA TLS Supported Groups registry (tls-parameters-8, ML-KEM 512-514, hybrids 4585-4591, "
             "obsolete Kyber hybrids 25497-25498) and the IANA SSH Key Exchange Method Names registry (RFC 10042 "
             "mlkem768x25519-sha256, mlkem768nistp256-sha256, mlkem1024nistp384-sha384; RFC 9941 sntrup761x25519-sha512)")

# Endpoint key exchange (harvest now, decrypt later). An endpoint row is quantum_vulnerable when NO key exchange it
# accepts includes a post-quantum KEM; a server that also accepts a PQ hybrid is not (CB-01 INTERFACES v7 #2, CB-18's
# "hybrid" class). NIST IR 8547 §2.1.2 and §4.1.2 Table 4: ECDH, finite-field DH and RSA key transport are
# quantum-vulnerable; ML-KEM (FIPS 203, Table 5) is the replacement. TLS <= 1.2 has no PQ group, so it never makes an
# endpoint safe.
# Closed tables (INTERFACES v7.3): a name that is not here is never read as classical. The generator refuses it
# (tls_endpoint_qv / ssh_endpoint_qv raise) and the derivations from observations return None ("not derived").
# TLS: IANA "TLS Supported Groups" (tls-parameters-8.csv, captured 2026-11-12), every ECDHE/FFDHE/ML-KEM entry that
# is assigned and not reserved; True = the group includes a post-quantum KEM (ML-KEM per FIPS 203, or the
# pre-standard Kyber768 of the two obsolete hybrids).
TLS_GROUP_PQ = {"x25519": False, "x448": False, "secp256r1": False, "secp384r1": False, "secp521r1": False,
                "curveSM2": False, "ffdhe2048": False, "ffdhe3072": False, "ffdhe4096": False, "ffdhe6144": False,
                "ffdhe8192": False,
                "MLKEM512": True, "MLKEM768": True, "MLKEM1024": True,
                "SecP256r1MLKEM512": True, "MLKEM512X25519": True, "SecP256r1MLKEM768": True, "X25519MLKEM768": True,
                "SecP384r1MLKEM1024": True, "curveSM2MLKEM768": True, "MLKEM1024X448": True,
                "X25519Kyber768Draft00": True, "SecP256r1Kyber768Draft00": True}
TLS_GROUP_CODE = {"secp256r1": 23, "secp384r1": 24, "secp521r1": 25, "x25519": 29, "x448": 30, "curveSM2": 41,
                  "ffdhe2048": 256, "ffdhe3072": 257, "ffdhe4096": 258, "ffdhe6144": 259, "ffdhe8192": 260,
                  "MLKEM512": 512, "MLKEM768": 513, "MLKEM1024": 514,              # RFC-ietf-tls-mlkem
                  "SecP256r1MLKEM512": 4585, "MLKEM512X25519": 4586,              # draft-rosomakho-tls-ecdhe-mlkem512
                  "SecP256r1MLKEM768": 4587, "X25519MLKEM768": 4588, "SecP384r1MLKEM1024": 4589,   # RFC 10024
                  "curveSM2MLKEM768": 4590,                                        # draft-yang-tls-hybrid-sm2-mlkem
                  "MLKEM1024X448": 4591,                                           # draft-preussmattsson-tls-mlkem1024-x448
                  "X25519Kyber768Draft00": 25497, "SecP256r1Kyber768Draft00": 25498}  # obsolete (RFC 10024)
# SSH: IANA "Key Exchange Method Names" (ssh-parameters-16.csv, captured 2026-11-12) plus the OpenSSH private
# spellings in use (@openssh.com, @libssh.org). PQ: RFC 9941 (sntrup761), RFC 10042 §2.3 (ML-KEM hybrids, formerly
# draft-ietf-sshm-mlkem-hybrid-kex), draft-harrison-mlkem-ssh-01 (pure ML-KEM).
SSH_KEX_PQ = {"mlkem768x25519-sha256": True, "sntrup761x25519-sha512": True,
              "sntrup761x25519-sha512@openssh.com": True, "mlkem768nistp256-sha256": True,
              "mlkem1024nistp384-sha384": True, "mlkem512-sha256": True, "mlkem768-sha256": True,
              "mlkem1024-sha384": True,
              "curve25519-sha256": False, "curve25519-sha256@libssh.org": False, "curve448-sha512": False,
              "ecdh-sha2-nistp256": False, "ecdh-sha2-nistp384": False, "ecdh-sha2-nistp521": False,
              "diffie-hellman-group1-sha1": False, "diffie-hellman-group14-sha1": False,
              "diffie-hellman-group14-sha256": False, "diffie-hellman-group15-sha512": False,
              "diffie-hellman-group16-sha512": False, "diffie-hellman-group17-sha512": False,
              "diffie-hellman-group18-sha512": False, "diffie-hellman-group-exchange-sha1": False,
              "diffie-hellman-group-exchange-sha256": False, "rsa1024-sha1": False, "rsa2048-sha256": False}


def tls_group_pq(name: str) -> bool:
    """True when the IANA group includes a post-quantum KEM; an unknown name raises (never classical)."""
    if name not in TLS_GROUP_PQ:
        raise ValueError(f"TLS group {name!r} not classified in TLS_GROUP_PQ")
    return TLS_GROUP_PQ[name]


def ssh_kex_pq(name: str) -> bool:
    """True when the SSH key exchange method includes a post-quantum KEM; an unknown name raises."""
    if name not in SSH_KEX_PQ:
        raise ValueError(f"SSH key exchange {name!r} not classified in SSH_KEX_PQ")
    return SSH_KEX_PQ[name]


def tls_endpoint_qv(versions: dict, groups: list[str] | None) -> bool | None:
    """`versions` {"TLSv1.2": bool, ...}; `groups` the IANA names of the groups the server accepts (None: not pinned,
    so the oracle states nothing). Unknown names raise: the generator refuses an oracle it cannot classify."""
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


def derive_tls_qv(versions: dict, groups: list[str] | None) -> bool | None:
    """The same verdict from an observation: None ("not derived") when a group is unknown, never classical."""
    try:
        return tls_endpoint_qv(versions, groups)
    except ValueError:
        return None


def derive_ssh_qv(kex: list[str]) -> bool | None:
    try:
        return ssh_endpoint_qv(kex) if kex else None
    except ValueError:
        return None

# Planted weaknesses and the finding code the spec names for each (O-1: names from the spec, never from product
# output). A rule whose condition holds on an asset row puts the code in `codes_include`; a rule that applies to the
# row but does not hold puts it in `codes_exclude` (a false positive is judged too). The spec names no code for TLS 1.1
# or for CBC suites: the gate judges them through `protocol_versions` and `must_report` instead.
CODE_SOURCES = {
    "PROTO_TLS10": "DEVILS-ADVOCATE §4.3 G13 (z02 resolved PROTO_TLS10); INTERFACES v1 §5",
    "STATIC_RSA_KEX": "E2E-PLAN §D4 (TLS static-RSA key exchange, z03)",
    "CERT_EXPIRED": "DEVILS-ADVOCATE §4.2 z04 and §4.3 G13; E2E-PLAN §D2 (expired RSA-2048 certificate)",
    "RSA_LT_2048": "E2E-PLAN §D2 (RSA-1024 private key) and §D3 (RSA-1024 certificate); DEVILS-ADVOCATE CB-13 "
                   "(RSA-1024 SSH host key)",
    "CERT_SELF_SHA1": "E2E-PLAN §D2 (SHA-1 self-signed certificate)",
    "SSH_NO_PQ_KEX": "DEVILS-ADVOCATE §4.2 sshd-legacy; E2E-PLAN §D4 (legacy SSH)",
    "DB_MD5_ACCEPTED": "DEVILS-ADVOCATE §4.2 .41 postgres; E2E-PLAN §D2 (md5 HBA line)",
    "DB_NATIVE_PW": "E2E-PLAN §D2 (MySQL mysql_native_password user)",
    "KEY_EXTRACTABLE": "E2E-PLAN §D5 (SoftHSM AES-128 extractable)",
    "NO_PQ_KEX": "DEVILS-ADVOCATE §4.4 KF-3 (false NO_PQ_KEX on z05b): excluded wherever a PQ group is accepted",
}
# Future-risk codes (DEVILS-ADVOCATE §6: in_triage) set no impact floor of their own. Every other planted weakness
# must be a finding with an impact (impact_min "Low", i.e. not Info/none). The spec gives no severity per code, so
# no higher floor is asserted (calibration belongs to the Q-grade formula, O-2).
FUTURE_RISK_CODES = {"SSH_NO_PQ_KEX", "NO_PQ_KEX"}
IMPACT_FLOOR = "Low"
# Signature algorithms with SHA-1, by the names OpenSSL and Java print (RFC 3279 §2.2.1-2.2.3).
SHA1_SIGNATURES = {"sha1WithRSAEncryption", "ecdsa-with-SHA1", "dsaWithSHA1", "dsa_with_SHA1", "SHA1withRSA",
                   "SHA1withECDSA", "SHA1withDSA"}


def _same_name(a: str | None, b: str | None) -> bool:
    """RFC 4514 names compared with case-insensitive attribute types (as the self-check's labread.name_key)."""
    def key(n: str) -> str:
        return ",".join(p.split("=", 1)[0].strip().upper() + "=" + p.split("=", 1)[-1] for p in n.split(",") if p)
    return a is not None and b is not None and key(a) == key(b)


def weakness_codes(asset_type: str, e: dict, now: str | None, extra: dict | None = None) -> tuple[list[str], list[str]]:
    """(codes_include, codes_exclude) of one asset row from its own expect values (and the facts in `extra` for
    database authentication rows). `now` is the run's generation time (dates relative to the run)."""
    inc: list[str] = []
    exc: list[str] = []
    extra = extra or {}

    def rule(holds: bool | None, code: str) -> None:
        if holds is not None:
            (inc if holds else exc).append(code)

    if asset_type == "tls_endpoint":
        rule("TLSv1" in e.get("protocol_versions", []), "PROTO_TLS10")
        rule(any(s.startswith("TLS_RSA_WITH_") for s in e.get("cipher_suites", [])), "STATIC_RSA_KEX")
        if e.get("quantum_vulnerable") is False:
            exc.append("NO_PQ_KEX")
    elif asset_type == "certificate":
        na = e.get("not_after")
        rule(na < now if (na and now) else None, "CERT_EXPIRED")
        alg, bits = e.get("algorithm"), e.get("key_size")
        rule(None if alg == "RSA" and bits is None else (alg == "RSA" and bits < 2048), "RSA_LT_2048")
        rule(_same_name(e.get("subject"), e.get("issuer")) and e.get("signature_algorithm") in SHA1_SIGNATURES,
             "CERT_SELF_SHA1")
    elif asset_type == "private_key":
        alg, bits = e.get("algorithm"), e.get("key_size")
        rule(None if alg == "RSA" and bits is None else (alg == "RSA" and bits < 2048), "RSA_LT_2048")
    elif asset_type == "ssh_endpoint":
        rule(e.get("quantum_vulnerable"), "SSH_NO_PQ_KEX")
        rule(any(h.get("type") == "ssh-rsa" and (h.get("bits") or 0) < 2048 for h in e.get("host_keys", [])),
             "RSA_LT_2048")
    elif asset_type == "database_user_auth":
        if "hba" in extra:
            rule(any(r.get("method") == "md5" for r in extra["hba"]), "DB_MD5_ACCEPTED")
        if "users" in extra:
            rule("mysql_native_password" in extra["users"].values(), "DB_NATIVE_PW")
    elif asset_type == "managed_key":
        rule(e.get("extractable"), "KEY_EXTRACTABLE")
    return sorted(inc), sorted(exc)


def apply_codes(a: dict, now: str | None, extra: dict | None = None) -> None:
    inc, exc = weakness_codes(a["asset_type"], a["expect"], now, extra)
    for key, codes in (("codes_include", inc), ("codes_exclude", exc)):
        if codes:
            a[key] = codes
        else:
            a.pop(key, None)
    if set(inc) - FUTURE_RISK_CODES:
        a["impact_min"] = IMPACT_FLOOR

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


def assets_for(o: dict, now: str | None = None) -> tuple[list[dict], list[dict]]:
    """(assets, must_not_appear) for one facts file. `now` (the run's generation time) dates CERT_EXPIRED."""
    t, kind, e = o["target"], o["kind"], o["expect"]
    loc = f"{o['address']}:{o['port']}" if o.get("address") else None
    assets: list[dict] = []
    mna: list[dict] = []
    kf = KNOWN_FAIL.get(t)
    db_auth: dict = {}
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
        db_auth = {k: e[k] for k in ("hba", "users") if k in e}
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
        apply_codes(a, now, db_auth if a["asset_type"] == "database_user_auth" else None)
        if kf:
            a["known_fail"] = kf
        a["expect"] = {k: v for k, v in a["expect"].items()}
    return assets, mna


def run_oracle(facts: list[dict], step: str, generated_at: str, commit: str, wave: str, sources: dict) -> dict:
    targets = []
    facts_dir = "oracle/facts" if step == "run1" else f"oracle/{step}/facts"
    for o in facts:
        assets, mna = assets_for(o, generated_at)
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
            "codes_source": CODE_SOURCES,
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
