"""Classifier rules for the scan-node network package (WP7): IKE/VPN endpoints, OT endpoints (OPC UA, Modbus),
appliance configuration rows (Cisco IOS/ASA, FortiOS, PAN-OS, F5) and service-mesh objects (Istio DestinationRule,
Linkerd Server).  Codes are explained in scripts/crypto_kb/kb_ext/node_net.py."""
from __future__ import annotations

import re
from typing import Any

from backend.utilities.cbom_sources import classify as C

# Names as the node reports them (zs_scan_node/ikeprobe.py) and as the appliance parsers normalise them.
WEAK_ENCR = re.compile(r"^(DES|DES-IV64|3DES|BLOWFISH|IDEA|CAST|NULL)(-\d+)?$", re.I)
WEAK_INTEG = re.compile(r"^(HMAC-)?(MD5|SHA1)(-\d+)?$|^(DES-MAC|KPDK-MD5)$", re.I)
WEAK_GROUPS_HIGH = {"MODP-768", "MODP-1024", "MODP-1024-S160", "ECP-192"}
WEAK_GROUPS = WEAK_GROUPS_HIGH | {"MODP-1536", "MODP-2048-S224", "MODP-2048-S256"}


def _state_names(state: Any) -> list[str]:
    """Accepted members of a weak class; 'one of X, Y' when the gateway accepted the class but the budget did not
    allow attributing the member."""
    if not isinstance(state, dict):
        return []
    names = [str(n) for n in state.get("accepted") or []]
    if not names and state.get("any_of"):
        names = ["one of " + "/".join(str(n) for n in state["any_of"][:4])]
    return names


def _ike_lists(facts: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
    enc: list[str] = []
    integ: list[str] = []
    dh: list[str] = []
    v2 = facts.get("ikev2") if isinstance(facts.get("ikev2"), dict) else {}
    v1 = facts.get("ikev1") if isinstance(facts.get("ikev1"), dict) else {}
    for side, keys in ((v2, ("encryption", "integrity", "prf", "group")), (v1, ("encryption", "hash", None, "group"))):
        chosen = side.get("chosen") if isinstance(side.get("chosen"), dict) else {}
        if WEAK_ENCR.match(str(chosen.get("encryption") or "")):
            enc.append(str(chosen["encryption"]))
        for k in keys[1:3]:
            if k and WEAK_INTEG.match(str(chosen.get(k) or "")):
                integ.append(("PRF " if k == "prf" else "") + str(chosen[k]))
        if str(chosen.get("group") or "") in WEAK_GROUPS:
            dh.append(str(chosen["group"]))
    weak2 = v2.get("weak") if isinstance(v2.get("weak"), dict) else {}
    enc += _state_names(weak2.get("encryption"))
    integ += _state_names(weak2.get("integrity")) + ["PRF " + n for n in _state_names(weak2.get("prf"))]
    dh += _state_names(weak2.get("dh"))
    weak1 = v1.get("weak") if isinstance(v1.get("weak"), dict) else {}
    enc += [f"{n} (IKEv1)" for n in _state_names(weak1.get("encryption"))]
    integ += [f"{n} (IKEv1)" for n in _state_names(weak1.get("hash"))]
    dh += [f"{n} (IKEv1)" for n in _state_names(weak1.get("group"))]
    dedupe = lambda items: list(dict.fromkeys(items))  # noqa: E731 - keep the order, drop repeats
    return dedupe(enc), dedupe(integ), dedupe(dh)


def _weak_findings(out: Any, enc: list[str], integ: list[str], dh: list[str], what: str) -> None:
    if enc:
        out.add("IKE_WEAK_ENCR", "High", f"{what} accepts weak IKE encryption ({', '.join(enc[:5])})")
    if integ:
        out.add("IKE_WEAK_INTEG", "Medium", f"{what} accepts MD5/SHA-1 in IKE ({', '.join(integ[:5])})")
    if dh:
        high = any(g.split(" ")[0] in WEAK_GROUPS_HIGH or g.startswith("one of") for g in dh)
        out.add("IKE_WEAK_DH", "High" if high else "Medium",
                f"{what} accepts weak Diffie-Hellman groups ({', '.join(dh[:5])})")


def ike_rule(out: Any, facts: dict[str, Any], algorithm: Any, key_size: Any, now: Any) -> bool | None:
    v2 = facts.get("ikev2") if isinstance(facts.get("ikev2"), dict) else {}
    v1 = facts.get("ikev1") if isinstance(facts.get("ikev1"), dict) else {}
    what = "VPN gateway"
    _weak_findings(out, *_ike_lists(facts), what)
    if v1.get("accepts"):
        out.add("IKEV1_ENABLED", "Medium", f"{what} accepts IKEv1 (deprecated by RFC 9395)")
    if v1.get("aggressive") is True:
        auth = str(v1.get("aggressive_auth") or "")
        out.add("IKE_AGGRESSIVE", "High", f"{what} answers IKEv1 Aggressive Mode"
                + (" with a hash of the pre-shared key (crackable offline)" if "PSK" in auth else ""))
    v2_usable = bool(v2.get("supported")) and v2.get("proposals_accepted") is not False
    pq = (v2.get("pq") or {}).get("supported") if isinstance(v2.get("pq"), dict) else None
    if pq is True:
        return False  # ML-KEM hybrid accepted (RFC 9370)
    if pq is False or (not v2_usable and v1.get("accepts")):
        out.add("IKE_NO_PQ", "Low", f"{what} has no post-quantum (ML-KEM) key exchange"
                + ("" if v2_usable else " (IKEv1 only)"))
        return True
    return None  # not tested (fragile mode, or a second IKE port of the same gateway): no verdict


def ot_rule(out: Any, facts: dict[str, Any], algorithm: Any, key_size: Any, now: Any) -> bool | None:
    service = str(facts.get("service") or "")
    if service == "modbus":
        out.add("MODBUS_PLAINTEXT", "High", "Modbus/TCP port accepts connections: the protocol has no encryption or "
                                            "authentication (anyone who reaches it can read and write registers)")
        return None
    if service != "opcua":
        return None
    eps = [e for e in facts.get("endpoints") or [] if isinstance(e, dict)]
    none_eps = [e for e in eps if e.get("security_mode") == "None" or e.get("security_policy") in ("None", None)]
    if none_eps:
        out.add("OPCUA_NONE_POLICY", "High", "OPC UA server offers an endpoint without security (SecurityPolicy None)")
    deprecated = sorted({str(e.get("security_policy")) for e in eps if e.get("security_policy") in ("Basic128Rsa15",
                                                                                                     "Basic256")})
    if deprecated:
        out.add("OPCUA_DEPRECATED_POLICY", "Medium", f"OPC UA server offers deprecated security policies "
                                                     f"({', '.join(deprecated)}: SHA-1, RSA PKCS#1 v1.5)")
    anon = [e for e in eps if any((t or {}).get("type") == "Anonymous" for t in e.get("user_tokens") or [])]
    if anon:
        on_none = any(e in none_eps for e in anon)
        out.add("OPCUA_ANON", "High" if on_none else "Medium",
                "OPC UA server accepts anonymous users" + (" on an endpoint without security" if on_none else ""))
    plain = [e for e in eps for t in e.get("user_tokens") or []
             if (t or {}).get("type") == "UserName" and (t.get("security_policy") or e.get("security_policy") or "None")
             == "None" and e.get("security_mode") != "SignAndEncrypt"]
    if plain:
        out.add("OPCUA_USERNAME_PLAINTEXT", "High", "OPC UA user names and passwords can be sent unencrypted "
                                                    "(UserName token without encryption on an unencrypted endpoint)")
    return True if any(e.get("security_policy") not in ("None", None) for e in eps) else None


def mesh_destination_rule(out: Any, facts: dict[str, Any], algorithm: Any, key_size: Any, now: Any) -> bool | None:
    off = []
    if str(facts.get("tls_mode") or "").upper() == "DISABLE":
        off.append("all ports")
    for scope_key, label in (("port_tls_modes", "port"), ("subset_tls_modes", "subset")):
        modes = facts.get(scope_key) if isinstance(facts.get(scope_key), dict) else {}
        off += [f"{label} {k}" for k, m in modes.items() if str(m).upper() == "DISABLE"]
    if off:
        out.add("MESH_DR_TLS_DISABLED", "High", f"Istio DestinationRule for {facts.get('host') or 'a host'} disables TLS "
                                                f"({', '.join(off[:6])}): sidecars send plaintext")
    return None


def mesh_server_rule(out: Any, facts: dict[str, Any], algorithm: Any, key_size: Any, now: Any) -> bool | None:
    reasons = [str(r) for r in facts.get("unauthenticated_by") or []]
    if facts.get("unauthenticated") and reasons:
        out.add("LINKERD_UNAUTHENTICATED_SERVER", "Medium",
                f"Linkerd Server {facts.get('namespace')}/{facts.get('name')} (port {facts.get('port')}) allows "
                f"clients without a mesh identity: {'; '.join(reasons[:3])}")
    return None


def appliance_rule(out: Any, facts: dict[str, Any], algorithm: Any, key_size: Any, now: Any) -> bool | None:
    kind = str(facts.get("kind") or "")
    vendor = str(facts.get("vendor_label") or facts.get("vendor") or "Appliance")
    what = f"{vendor} {facts.get('section') or kind}".strip()
    if kind == "ike_policy":
        enc = [n for n in facts.get("encryption") or [] if WEAK_ENCR.match(str(n))]
        integ = [n for n in facts.get("integrity") or [] if WEAK_INTEG.match(str(n))]
        integ += ["PRF " + n for n in facts.get("prf") or [] if WEAK_INTEG.match(str(n))]
        dh = [g for g in facts.get("groups") or [] if g in WEAK_GROUPS]
        _weak_findings(out, enc, integ, dh, what)
        if facts.get("version") == 1 and facts.get("active", True):
            out.add("IKEV1_ENABLED", "Medium", f"{what} configures IKEv1 (deprecated by RFC 9395)")
        if facts.get("aggressive") is True:
            out.add("IKE_AGGRESSIVE", "High", f"{what}: IKEv1 Aggressive Mode is allowed"
                    + (f" ({facts.get('aggressive_reason')})" if facts.get("aggressive_reason") else ""))
        if facts.get("pq") is False:
            out.add("IKE_NO_PQ", "Low", f"{what} has no post-quantum (ML-KEM) key exchange")
        return True
    if kind == "ipsec_policy":
        weak = [n for n in facts.get("encryption") or [] if WEAK_ENCR.match(str(n))]
        weak += [n for n in facts.get("integrity") or [] if WEAK_INTEG.match(str(n))]
        weak += [f"PFS {g}" for g in facts.get("pfs_groups") or [] if g in WEAK_GROUPS]
        if weak:
            out.add("IPSEC_WEAK_TRANSFORM", "Medium", f"{what} allows weak ESP transforms ({', '.join(weak[:5])})")
        return None
    if kind == "ssh":
        versions = [int(v) for v in facts.get("versions") or [] if str(v).isdigit()]
        if 1 in versions:
            out.add("SSH_V1_ENABLED", "High", f"{what} allows SSH protocol version 1")
        if any(facts.get(k) for k in ("ciphers", "macs", "kex")):
            return C._ssh_rules(out, facts, what)
        return None
    if kind == "tls":
        C._tls_rules(out, {k: facts.get(k) for k in ("protocols", "min_version", "weak_ciphers")}, what)
        if facts.get("strong_crypto") is False:
            out.add("WEAK_CIPHER", "High", f"{what}: strong-crypto is disabled, so weak ciphers and hashes stay "
                                           "allowed for administrative TLS/SSH")
        return None
    return None


C.register("ike_endpoint", ike_rule, "protocol")
C.register("ot_endpoint", ot_rule, "protocol")
C.register("appliance_config", appliance_rule, "protocol")
C.register("k8s_mesh_destination", mesh_destination_rule, "other")
C.register("k8s_mesh_server", mesh_server_rule, "other")
