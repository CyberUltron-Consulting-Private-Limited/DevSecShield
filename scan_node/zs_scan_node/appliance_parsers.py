"""Parsers for appliance configurations read with read-only commands or API calls (pure functions, no I/O).

Each parser returns rows ``(asset_type, section, name, algorithm, key_size, facts)``.  Only the settings named here
are extracted; every other line (shared secrets, passwords, community strings) is never copied into a row.  Names are
normalised to the vocabulary the classifier uses for IKE (ikeprobe.py): DES, 3DES, AES-CBC-256, AES-GCM-16-256 ...;
MD5, SHA1, SHA2-256 ...; MODP-1024, ECP-256, CURVE25519 ...  Values a vendor applies by default but does not print are
NOT assumed: only configured values are judged (the IKE network probe measures the effective behaviour).

Syntax references (vendor documentation):
  Cisco IOS XE Security Configuration Guide, "Configuring Internet Key Exchange Version 2" (crypto ikev2 proposal:
    encryption/integrity/prf/group), "Configuring Internet Key Exchange for IPsec VPNs" (crypto isakmp policy: encr,
    hash, authentication, group; crypto isakmp aggressive-mode disable), Cisco IOS Security Command Reference
    (ip ssh version, ip ssh server algorithm, ip http secure-ciphersuite, ip http tls-version, crypto ipsec transform-set)
  Cisco ASA Series CLI Configuration Guide / Command Reference (ssl server-version, ssl cipher, ssl dh-group,
    crypto ikev1|ikev2 policy, crypto ikev1 am-disable, ssh version, ssh key-exchange group, ssh cipher)
  FortiOS CLI Reference (config system global: ssl-min-proto-version, admin-https-ssl-versions, strong-crypto,
    admin-ssh-v1; config vpn ipsec phase1-interface / phase2-interface: ike-version, mode, proposal, dhgrp, pfs)
  PAN-OS XML API and configuration schema (ike-crypto-profiles, ipsec-crypto-profiles, ike gateway protocol,
    ssl-tls-service-profile protocol-settings)
  F5 iControl REST API reference (/mgmt/tm/ltm/profile/client-ssl: ciphers, options; /mgmt/tm/sys/crypto/key:
    keyType, keySize, curveName, securityType)
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

Row = tuple[str, str, str, "str | None", "int | None", dict]

GROUP_NAMES = {1: "MODP-768", 2: "MODP-1024", 5: "MODP-1536", 14: "MODP-2048", 15: "MODP-3072", 16: "MODP-4096",
               17: "MODP-6144", 18: "MODP-8192", 19: "ECP-256", 20: "ECP-384", 21: "ECP-521", 22: "MODP-1024-S160",
               23: "MODP-2048-S224", 24: "MODP-2048-S256", 25: "ECP-192", 26: "ECP-224", 27: "BRAINPOOL-P224R1",
               28: "BRAINPOOL-P256R1", 29: "BRAINPOOL-P384R1", 30: "BRAINPOOL-P512R1", 31: "CURVE25519",
               32: "CURVE448"}
WEAK_TLS_TOKENS = re.compile(r"(?<![!\-+])\b(RC4|DES|3DES|DES-CBC3|EXP|EXPORT|NULL|ANULL|ENULL|MD5|LOW)\b", re.I)
MAX_ROWS = 400


def _group(value: str) -> str | None:
    m = re.fullmatch(r"(?:group|dh-group|dh)?(\d{1,2})", value.strip().lower())
    return GROUP_NAMES.get(int(m.group(1)), f"group {m.group(1)}") if m else None


def _hash(value: str) -> str | None:
    v = value.lower().replace("_", "-")
    table = {"md5": "MD5", "md596": "MD5", "sha": "SHA1", "sha1": "SHA1", "sha96": "SHA1", "sha256": "SHA2-256",
             "sha-256": "SHA2-256", "sha2-256": "SHA2-256", "sha384": "SHA2-384", "sha2-384": "SHA2-384",
             "sha512": "SHA2-512", "sha2-512": "SHA2-512", "null": "NULL"}
    return table.get(v)


def _cisco_encr(tokens: list[str]) -> list[str]:
    """'aes-cbc-256 3des' (IKEv2) or 'aes 256' / '3des' / 'des' (ISAKMP) or ASA 'aes-256' / 'aes-gcm-256'."""
    out = []
    i = 0
    while i < len(tokens):
        t = tokens[i].lower()
        nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
        if t in ("des", "3des"):
            out.append(t.upper())
        elif t == "aes" and nxt.isdigit():
            out.append(f"AES-CBC-{nxt}")
            i += 1
        elif t == "aes":
            out.append("AES-CBC-128")
        elif re.fullmatch(r"aes-(cbc-)?(128|192|256)", t):
            out.append(f"AES-CBC-{t.rsplit('-', 1)[1]}")
        elif re.fullmatch(r"aes-gcm(-(128|192|256))?", t):
            out.append(f"AES-GCM-16-{t.rsplit('-', 1)[1] if t[-1].isdigit() else '128'}")
        elif t not in ("", "null"):
            out.append(t.upper())
        i += 1
    return out


def _blocks(text: str, header: re.Pattern) -> list[tuple[re.Match, list[str]]]:
    """Cisco-style blocks: a header line and the indented lines under it."""
    out: list[tuple[re.Match, list[str]]] = []
    current: tuple[re.Match, list[str]] | None = None
    for line in text.splitlines():
        if not line.strip() or line.strip() == "!":
            continue
        m = header.match(line)
        if m:
            current = (m, [])
            out.append(current)
        elif line.startswith((" ", "\t")) and current is not None:
            current[1].append(line.strip())
        else:
            current = None
    return out


def _ike_row(vendor: str, section: str, version: int, **facts: Any) -> Row:
    clean = {k: v for k, v in facts.items() if v not in (None, [], "")}
    return ("appliance_config", section, section, (clean.get("encryption") or [None])[0], None,
            {"kind": "ike_policy", "vendor": vendor, "section": section, "version": version, **clean})


# ----------------------------------------------------------------------------- Cisco IOS / IOS XE
def parse_cisco_ios(outputs: dict[str, str]) -> list[Row]:
    rows: list[Row] = []
    base = "\n".join(outputs.values())
    vendor = "cisco_ios"
    # SSH server
    versions = [int(v) for v in re.findall(r"^ip ssh version (\d)\b", base, re.M)]
    ssh: dict[str, Any] = {"kind": "ssh", "vendor": vendor, "section": "ip ssh", "versions": versions}
    for key, kw in (("ciphers", "encryption"), ("macs", "mac"), ("kex", "kex")):
        m = re.search(rf"^ip ssh server algorithm {kw} (.+)$", base, re.M)
        if m:
            ssh[key] = m.group(1).split()
    dh_min = re.search(r"^ip ssh dh min size (\d+)", base, re.M)
    if dh_min:  # the smallest group the SSH server accepts in diffie-hellman-group-exchange
        ssh["dh_min_bits"] = int(dh_min.group(1))
    if versions or any(k in ssh for k in ("ciphers", "macs", "kex", "dh_min_bits")):
        rows.append(("appliance_config", "ip ssh", "SSH server", None, None, ssh))
    # HTTPS management
    m = re.search(r"^ip http secure-ciphersuite (.+)$", base, re.M)
    tls_versions = re.findall(r"^ip http tls-version (\S+)", base, re.M)
    if m or tls_versions or re.search(r"^ip http secure-server", base, re.M):
        ciphers = m.group(1).split() if m else []
        weak = [c for c in ciphers if re.search(r"(rc4|des|null|md5|exp)", c, re.I)]
        tls = {"kind": "tls", "vendor": vendor, "section": "ip http secure-server", "ciphers": ciphers,
               "weak_ciphers": weak}
        if tls_versions:
            tls["min_version"] = tls_versions[0].replace("TLSv", "TLSv")
        rows.append(("appliance_config", "ip http secure-server", "HTTPS management", None, None, tls))
    # IKEv2 proposals
    for m, body in _blocks(base, re.compile(r"^crypto ikev2 proposal (\S+)")):
        facts: dict[str, list[str]] = {"encryption": [], "integrity": [], "prf": [], "groups": []}
        for line in body:
            words = line.split()
            if words[0] == "encryption":
                facts["encryption"] += _cisco_encr(words[1:])
            elif words[0] in ("integrity", "prf"):
                facts[words[0]] += [h for h in (_hash(w) for w in words[1:]) if h]
            elif words[0] == "group":
                facts["groups"] += [g for g in (_group(w) for w in words[1:]) if g]
        rows.append(_ike_row(vendor, f"crypto ikev2 proposal {m.group(1)}", 2, **facts))
    # ISAKMP (IKEv1) policies: only configured values (IOS prints defaults of older releases as nothing)
    isakmp = _blocks(base, re.compile(r"^crypto isakmp policy (\d+)"))
    am_disabled = bool(re.search(r"^crypto isakmp aggressive-mode disable", base, re.M))
    for m, body in isakmp:
        facts = {"encryption": [], "integrity": [], "groups": [], "authentication": None}
        for line in body:
            words = line.split()
            if words[0] in ("encr", "encryption"):
                facts["encryption"] += _cisco_encr(words[1:])
            elif words[0] == "hash" and len(words) > 1:
                facts["integrity"] += [h for h in [_hash(words[1])] if h]
            elif words[0] == "group" and len(words) > 1:
                facts["groups"] += [g for g in [_group(words[1])] if g]
            elif words[0] == "authentication" and len(words) > 1:
                facts["authentication"] = words[1]
        psk = facts["authentication"] == "pre-share"
        rows.append(_ike_row(vendor, f"crypto isakmp policy {m.group(1)}", 1, **facts,
                             aggressive=True if (psk and not am_disabled) else None,
                             aggressive_reason="IOS answers Aggressive Mode unless 'crypto isakmp aggressive-mode "
                                               "disable' is configured" if (psk and not am_disabled) else None))
    # IPsec transform sets: crypto ipsec transform-set NAME esp-3des esp-md5-hmac
    for m in re.finditer(r"^crypto ipsec transform-set (\S+) (.+)$", base, re.M):
        enc, integ = [], []
        tokens = m.group(2).split()
        for i, t in enumerate(tokens):
            t = t.lower()
            if t in ("esp-des", "esp-3des", "esp-null"):
                enc.append(t[4:].upper())
            elif t.startswith("esp-aes") or t.startswith("esp-gcm"):
                bits = tokens[i + 1] if i + 1 < len(tokens) and tokens[i + 1].isdigit() else "128"
                enc.append(("AES-GCM-16-" if "gcm" in t else "AES-CBC-") + bits)
            elif t.endswith("-hmac"):
                integ += [h for h in [_hash(t[4:-5].replace("sha-", "sha"))] if h]
        rows.append(("appliance_config", f"crypto ipsec transform-set {m.group(1)}", m.group(1), None, None,
                     {"kind": "ipsec_policy", "vendor": vendor, "section": f"crypto ipsec transform-set {m.group(1)}",
                      "encryption": enc, "integrity": integ}))
    rows += parse_cisco_keys(outputs.get("show crypto key mypubkey rsa", ""), vendor)
    return rows[:MAX_ROWS]


def parse_cisco_keys(text: str, vendor: str) -> list[Row]:
    """'show crypto key mypubkey rsa' (IOS and ASA): key name and modulus size; the public key data is parsed to
    read the size when the size line is absent.  Public material only."""
    rows: list[Row] = []
    for chunk in re.split(r"(?m)^(?=Key name: )", text):
        m = re.match(r"Key name: (\S+)", chunk)
        if not m:
            continue
        name = m.group(1)
        size = None
        sm = re.search(r"Modulus Size \(bits\):\s*(\d+)", chunk)
        if sm:
            size = int(sm.group(1))
        else:
            hexdata = re.search(r"Key Data:\s*\n((?:\s+[0-9A-Fa-f ]+\n?)+)", chunk)
            if hexdata:
                try:
                    from cryptography.hazmat.primitives.serialization import load_der_public_key

                    key = load_der_public_key(bytes.fromhex(re.sub(r"\s+", "", hexdata.group(1))))
                    size = getattr(key, "key_size", None)
                except Exception:
                    size = None
        usage = re.search(r"Usage: (.+)", chunk)
        rows.append(("public_key", f"crypto key {name}", f"{name} (RSA key pair)", "RSA", size,
                     {"kind": "appliance_key", "vendor": vendor, "key_name": name, "key_alg": "RSA", "key_size": size,
                      "usage": usage.group(1).strip()[:60] if usage else None}))
    return rows


# ----------------------------------------------------------------------------- Cisco ASA
ASA_TLS = {"sslv3": "SSLv3", "tlsv1": "TLSv1.0", "tlsv1.1": "TLSv1.1", "tlsv1.2": "TLSv1.2", "tlsv1.3": "TLSv1.3",
           "dtlsv1": "TLSv1.1", "dtlsv1.2": "TLSv1.2"}


def parse_cisco_asa(outputs: dict[str, str]) -> list[Row]:
    rows: list[Row] = []
    base = "\n".join(outputs.values())
    vendor = "cisco_asa"
    m = re.search(r"^ssl server-version (\S+)", base, re.M)
    ciphers = re.findall(r"^ssl cipher (\S+) (\S+)(?: \"([^\"]*)\")?", base, re.M)
    if m or ciphers:
        weak = []
        for proto, level, custom in ciphers:
            if level in ("all", "low"):
                weak.append(f"{proto} {level}")
            elif level == "custom" and WEAK_TLS_TOKENS.search(custom or ""):
                weak += [c for c in (custom or "").split(":") if WEAK_TLS_TOKENS.search(c)][:6]
        tls: dict[str, Any] = {"kind": "tls", "vendor": vendor, "section": "ssl", "weak_ciphers": weak,
                               "cipher_levels": [f"{p} {lvl}" for p, lvl, _c in ciphers]}
        if m:
            tls["min_version"] = ASA_TLS.get(m.group(1).lower(), m.group(1))
        dh = re.search(r"^ssl dh-group (\S+)", base, re.M)
        if dh:
            tls["dh_group"] = dh.group(1)
            name = _group(dh.group(1))  # group2 -> MODP-1024 (the DHE group the ASA uses for TLS)
            if name:
                tls["dh_groups"] = [name]
        rows.append(("appliance_config", "ssl", "SSL/TLS (AnyConnect, ASDM)", None, None, tls))
    versions = [int(v) for v in re.findall(r"^ssh version (\d)\b", base, re.M)]
    kex = re.findall(r"^ssh key-exchange group (\S+)", base, re.M)
    if versions or kex:
        ssh = {"kind": "ssh", "vendor": vendor, "section": "ssh", "versions": versions}
        if kex:
            ssh["kex"] = [{"dh-group1-sha1": "diffie-hellman-group1-sha1", "dh-group14-sha1": "diffie-hellman-group14-sha1",
                           "dh-group14-sha256": "diffie-hellman-group14-sha256",
                           "ecdh-group19-sha256": "ecdh-sha2-nistp256"}.get(k, k) for k in kex]
        rows.append(("appliance_config", "ssh", "SSH server", None, None, ssh))
    ikev1_on = bool(re.search(r"^crypto ikev1 enable \S+", base, re.M))
    am_disabled = bool(re.search(r"^crypto ikev1 am-disable", base, re.M))
    for version in (1, 2):
        for m2, body in _blocks(base, re.compile(rf"^crypto ikev{version} policy (\d+)")):
            facts: dict[str, Any] = {"encryption": [], "integrity": [], "prf": [], "groups": [], "authentication": None}
            for line in body:
                words = line.split()
                if words[0] == "encryption":
                    facts["encryption"] += _cisco_encr(words[1:])
                elif words[0] in ("integrity", "hash"):
                    facts["integrity"] += [h for h in (_hash(w) for w in words[1:]) if h]
                elif words[0] == "prf":
                    facts["prf"] += [h for h in (_hash(w) for w in words[1:]) if h]
                elif words[0] == "group":
                    facts["groups"] += [g for g in (_group(w) for w in words[1:]) if g]
                elif words[0] == "authentication" and len(words) > 1:
                    facts["authentication"] = words[1]
            extra: dict[str, Any] = {}
            if version == 1:
                extra["active"] = ikev1_on
                if ikev1_on and facts["authentication"] == "pre-share" and not am_disabled:
                    extra["aggressive"] = True
                    extra["aggressive_reason"] = "the ASA answers Aggressive Mode unless 'crypto ikev1 am-disable' is set"
            rows.append(_ike_row(vendor, f"crypto ikev{version} policy {m2.group(1)}", version, **facts, **extra))
    rows += parse_cisco_keys(outputs.get("show crypto key mypubkey rsa", ""), vendor)
    return rows[:MAX_ROWS]


# ----------------------------------------------------------------------------- FortiOS
FORTI_TLS = {"sslv3": "SSLv3", "tlsv1": "TLSv1.0", "tlsv1-0": "TLSv1.0", "tlsv1-1": "TLSv1.1", "tlsv1-2": "TLSv1.2",
             "tlsv1-3": "TLSv1.3"}


def _forti_sets(text: str) -> list[tuple[str | None, dict[str, str]]]:
    """(edit name or None, {setting: value}) for each 'edit' block (or the whole 'config' block)."""
    out: list[tuple[str | None, dict[str, str]]] = []
    current: dict[str, str] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r'^edit "?([^"]+)"?$', line)
        if m:
            current = {}
            out.append((m.group(1), current))
            continue
        if line in ("next", "end"):
            current = None
            continue
        m = re.match(r"^set (\S+) (.+)$", line)
        if m:
            if current is None:
                current = {}
                out.append((None, current))
            current[m.group(1)] = m.group(2).strip()
    return out


def _forti_proposal(value: str) -> tuple[list[str], list[str], list[str]]:
    """'des-md5 3des-sha1 aes256-sha256 aes256gcm-prfsha384 chacha20poly1305-prfsha256' -> (enc, integ, prf)."""
    enc, integ, prf = [], [], []
    for p in value.split():
        e, _, h = p.lower().partition("-")
        m = re.fullmatch(r"aes(128|192|256)(gcm)?", e)
        if e in ("des", "3des"):
            enc.append(e.upper())
        elif m:
            enc.append(("AES-GCM-16-" if m.group(2) else "AES-CBC-") + m.group(1))
        elif e == "chacha20poly1305":
            enc.append("CHACHA20-POLY1305")
        elif e:
            enc.append(e.upper())
        if h.startswith("prf"):
            prf += [x for x in [_hash(h[3:])] if x]
        elif h:
            integ += [x for x in [_hash(h)] if x]
    return list(dict.fromkeys(enc)), list(dict.fromkeys(integ)), list(dict.fromkeys(prf))


def parse_fortios(outputs: dict[str, str]) -> list[Row]:
    rows: list[Row] = []
    vendor = "fortios"
    glob = {}
    for _name, sets in _forti_sets(outputs.get("show full-configuration system global", "")):
        glob.update(sets)
    if glob:
        protos = [FORTI_TLS.get(v.lower(), v) for v in glob.get("admin-https-ssl-versions", "").split()]
        tls: dict[str, Any] = {"kind": "tls", "vendor": vendor, "section": "system global (admin HTTPS)",
                               "protocols": protos}
        if glob.get("ssl-min-proto-version"):
            tls["min_version"] = FORTI_TLS.get(glob["ssl-min-proto-version"].lower(), glob["ssl-min-proto-version"])
        if glob.get("strong-crypto"):
            tls["strong_crypto"] = glob["strong-crypto"] == "enable"
        if glob.get("dh-params", "").isdigit():  # bits of the DH group for admin HTTPS / SSH (set dh-params 1024)
            tls["dh_bits"] = int(glob["dh-params"])
        rows.append(("appliance_config", "system global", "Administrative TLS", None, None, tls))
        if glob.get("admin-ssh-v1") == "enable":
            rows.append(("appliance_config", "system global ssh", "Administrative SSH", None, None,
                         {"kind": "ssh", "vendor": vendor, "section": "system global (admin SSH)", "versions": [1, 2]}))
    for name, sets in _forti_sets(outputs.get("show full-configuration vpn ipsec phase1-interface", "")):
        if not name:
            continue
        enc, integ, prf = _forti_proposal(sets.get("proposal", ""))
        version = 2 if sets.get("ike-version") == "2" else 1
        groups = [g for g in (_group(x) for x in sets.get("dhgrp", "").split()) if g]
        rows.append(_ike_row(vendor, f"vpn ipsec phase1-interface {name}", version, encryption=enc, integrity=integ,
                             prf=prf, groups=groups,
                             aggressive=True if version == 1 and sets.get("mode") == "aggressive" else None,
                             aggressive_reason="set mode aggressive" if version == 1 and sets.get("mode") == "aggressive"
                             else None, authentication=sets.get("authmethod")))
    for name, sets in _forti_sets(outputs.get("show full-configuration vpn ipsec phase2-interface", "")):
        if not name:
            continue
        enc, integ, _prf = _forti_proposal(sets.get("proposal", ""))
        pfs = [g for g in (_group(x) for x in sets.get("dhgrp", "").split()) if g] if sets.get("pfs") != "disable" else []
        rows.append(("appliance_config", f"vpn ipsec phase2-interface {name}", name, None, None,
                     {"kind": "ipsec_policy", "vendor": vendor, "section": f"vpn ipsec phase2-interface {name}",
                      "encryption": enc, "integrity": integ, "pfs_groups": pfs}))
    return rows[:MAX_ROWS]


# ----------------------------------------------------------------------------- PAN-OS (XML API)
PANOS_TLS = {"sslv3": "SSLv3", "tls1-0": "TLSv1.0", "tls1-1": "TLSv1.1", "tls1-2": "TLSv1.2", "tls1-3": "TLSv1.3"}
PANOS_ENC = {"des": "DES", "3des": "3DES", "aes-128-cbc": "AES-CBC-128", "aes-192-cbc": "AES-CBC-192",
             "aes-256-cbc": "AES-CBC-256", "aes-128-gcm": "AES-GCM-16-128", "aes-256-gcm": "AES-GCM-16-256",
             "null": "NULL"}


def _xml(text: str) -> ET.Element | None:
    if not text or "<!DOCTYPE" in text or "<!ENTITY" in text:  # no DTDs (entity expansion) from a device
        return None
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    return root if root.get("status") in (None, "success") else None


def _members(el: ET.Element | None, path: str) -> list[str]:
    if el is None:
        return []
    node = el.find(path)
    if node is None:
        return []
    members = [m.text.strip() for m in node.findall("member") if m.text]
    return members or ([node.text.strip()] if node.text and node.text.strip() else [])


def parse_panos(outputs: dict[str, str]) -> list[Row]:
    rows: list[Row] = []
    vendor = "panos"
    gateways = _xml(outputs.get("ike-gateways", ""))
    profile_use: dict[str, dict[str, Any]] = {}
    for gw in (gateways.iter("entry") if gateways is not None else []):
        if gw.find("protocol") is None:
            continue
        version = (gw.findtext("protocol/version") or "ikev1").strip()
        for v in ("ikev1", "ikev2"):
            prof = gw.findtext(f"protocol/{v}/ike-crypto-profile")
            if prof and (version == v or version == "ikev2-preferred" or (v == "ikev2" and version == "ikev2")):
                use = profile_use.setdefault(prof.strip(), {"versions": set(), "aggressive": False})
                use["versions"].add(1 if v == "ikev1" else 2)
                if v == "ikev1" and (gw.findtext("protocol/ikev1/exchange-mode") or "").strip() == "aggressive":
                    use["aggressive"] = True
    ike = _xml(outputs.get("ike-crypto-profiles", ""))
    for entry in (ike.iter("entry") if ike is not None else []):
        name = entry.get("name") or "?"
        if entry.find("encryption") is None:
            continue
        enc = [PANOS_ENC.get(x.lower(), x.upper()) for x in _members(entry, "encryption")]
        integ = [h for h in (_hash(x) for x in _members(entry, "hash")) if h]
        groups = [g for g in (_group(x.replace("group", "")) for x in _members(entry, "dh-group")) if g]
        use = profile_use.get(name, {"versions": {2}, "aggressive": False})
        for version in sorted(use["versions"]) or [2]:
            rows.append(_ike_row(vendor, f"ike-crypto-profile {name} (IKEv{version})", version, encryption=enc,
                                 integrity=integ, prf=integ if version == 2 else [], groups=groups,
                                 aggressive=True if version == 1 and use["aggressive"] else None,
                                 aggressive_reason="IKE gateway exchange-mode aggressive"
                                 if version == 1 and use["aggressive"] else None))
    ipsec = _xml(outputs.get("ipsec-crypto-profiles", ""))
    for entry in (ipsec.iter("entry") if ipsec is not None else []):
        if entry.find("esp") is None:
            continue
        name = entry.get("name") or "?"
        enc = [PANOS_ENC.get(x.lower(), x.upper()) for x in _members(entry, "esp/encryption")]
        integ = [h for h in (_hash(x) for x in _members(entry, "esp/authentication")) if h]
        pfs = [g for g in (_group(x.replace("group", "")) for x in _members(entry, "dh-group")) if g]
        rows.append(("appliance_config", f"ipsec-crypto-profile {name}", name, None, None,
                     {"kind": "ipsec_policy", "vendor": vendor, "section": f"ipsec-crypto-profile {name}",
                      "encryption": enc, "integrity": integ, "pfs_groups": pfs}))
    for key in ("ssl-tls-service-profiles-shared", "ssl-tls-service-profiles-vsys"):
        root = _xml(outputs.get(key, ""))
        for entry in (root.iter("entry") if root is not None else []):
            ps = entry.find("protocol-settings")
            if ps is None:
                continue
            name = entry.get("name") or "?"
            minv = (ps.findtext("min-version") or "").strip()
            weak = [tag.replace("enc-algo-", "").upper() for tag in ("enc-algo-3des", "enc-algo-rc4")
                    if (ps.findtext(tag) or "").strip() == "yes"]
            tls: dict[str, Any] = {"kind": "tls", "vendor": vendor, "section": f"ssl-tls-service-profile {name}",
                                   "weak_ciphers": weak}
            if minv:
                tls["min_version"] = PANOS_TLS.get(minv, minv)
            rows.append(("appliance_config", f"ssl-tls-service-profile {name}", name, None, None, tls))
    return rows[:MAX_ROWS]


# ----------------------------------------------------------------------------- F5 BIG-IP (iControl REST)
F5_PROTOCOL_KEYWORDS = (("SSLv3", "SSLv3"), ("TLSv1", "TLSv1.0"), ("TLSv1_1", "TLSv1.1"), ("TLSv1_2", "TLSv1.2"),
                        ("TLSv1_3", "TLSv1.3"))
F5_NO_OPTION = {"SSLv3": "no-sslv3", "TLSv1.0": "no-tlsv1", "TLSv1.1": "no-tlsv1.1", "TLSv1.2": "no-tlsv1.2",
                "TLSv1.3": "no-tlsv1.3"}


def _f5_protocols(tokens: list[str], options: list[str]) -> list[str]:
    """Protocol versions a client-ssl cipher string configures.  A listed protocol keyword enables it (F5 cipher
    rules: '!' removes, '-' deletes).  A string that starts with DEFAULT takes F5's DEFAULT cipher list, which holds
    TLS 1.2 suites on every supported BIG-IP release (BIG-IP System: SSL Administration, the DEFAULT cipher string),
    so TLS 1.2 is configured unless the string removes it or the profile sets 'no-tlsv1.2'.  Versions DEFAULT may also
    hold (1.0 / 1.1) are not assumed: only what is configured is judged.  A 'no-...' option switches a version off
    whatever the string says."""
    removed = {t[1:] for t in tokens if t.startswith(("!", "-"))}
    found = [v for tok, v in F5_PROTOCOL_KEYWORDS if tok in tokens and tok not in removed]
    if tokens and tokens[0].upper() == "DEFAULT" and "TLSv1_2" not in removed and "TLSv1.2" not in found:
        found.append("TLSv1.2")
    off = {o.lower() for o in options}
    order = [v for _tok, v in F5_PROTOCOL_KEYWORDS]
    return sorted((v for v in found if F5_NO_OPTION[v] not in off), key=order.index)


def parse_f5(outputs: dict[str, Any]) -> list[Row]:
    rows: list[Row] = []
    vendor = "f5_bigip"
    profiles = outputs.get("client-ssl") if isinstance(outputs.get("client-ssl"), dict) else {}
    for p in (profiles.get("items") or [])[:MAX_ROWS]:
        if not isinstance(p, dict):
            continue
        name = str(p.get("fullPath") or p.get("name") or "?")
        ciphers = str(p.get("ciphers") or "")
        options = [str(o) for o in p.get("options") or []] if isinstance(p.get("options"), list) else []
        tokens = [c for c in re.split(r"[:,\s]+", ciphers) if c]
        weak = [c for c in tokens if not c.startswith(("!", "-")) and WEAK_TLS_TOKENS.search(c)]
        protocols = _f5_protocols(tokens, options)
        rows.append(("appliance_config", f"client-ssl {name}", name, None, None,
                     {"kind": "tls", "vendor": vendor, "section": f"client-ssl profile {name}", "ciphers": ciphers[:300],
                      "cipher_group": p.get("cipherGroup"), "options": options[:30], "weak_ciphers": weak[:10],
                      "protocols": protocols}))
    keys = outputs.get("crypto-key") if isinstance(outputs.get("crypto-key"), dict) else {}
    for k in (keys.get("items") or [])[:MAX_ROWS]:
        if not isinstance(k, dict):
            continue
        ktype = str(k.get("keyType") or "")
        alg = "RSA" if ktype.startswith("rsa") else "EC" if ktype.startswith("ec") else "DSA" if ktype.startswith("dsa") \
            else ktype.upper() or None
        size = k.get("keySize") if isinstance(k.get("keySize"), int) else None
        name = str(k.get("fullPath") or k.get("name") or "?")
        rows.append(("private_key", f"sys crypto key {name}", name, alg, size,
                     {"kind": "appliance_key", "vendor": vendor, "key_name": name, "key_alg": alg, "key_size": size,
                      "curve": k.get("curveName"), "security_type": k.get("securityType"),
                      "store": "F5 BIG-IP key store"}))
    return rows


PARSERS = {"cisco_ios": parse_cisco_ios, "cisco_asa": parse_cisco_asa, "fortios": parse_fortios, "panos": parse_panos,
           "f5_bigip": parse_f5}
VENDOR_LABELS = {"cisco_ios": "Cisco IOS", "cisco_asa": "Cisco ASA", "fortios": "FortiOS", "panos": "PAN-OS",
                 "f5_bigip": "F5 BIG-IP"}
