"""Turn the facts a collector reported into impact, quantum exposure and a finding.

Classification lives on the server so every node version is judged by the same rules, and so a node
cannot mark its own findings.  Impact uses the CBOM report vocabulary (Critical / High / Medium / Low);
``None`` means informational.  Each rule adds a code; the asset's impact is the worst one.
"""
from __future__ import annotations

import datetime as _dt
import json
import re
import threading
from typing import Any

from backend.utilities.cbom_sources import algid, crypto_kb
from backend.utilities.cbom_sources.common import log

IMPACTS = ("Critical", "High", "Medium", "Low")
_RANK = {name: i for i, name in enumerate(IMPACTS)}

ASSET_TYPES: set[str] = {
    "certificate", "private_key", "public_key", "keystore", "ssh_host_key", "ssh_server_config", "ssh_endpoint",
    "tls_endpoint", "crypto_library", "process_library", "disk_encryption", "os_crypto_policy", "database_tls",
    "database_config", "database_user_auth", "k8s_cluster", "k8s_tls_secret", "k8s_certificate", "k8s_ingress_tls",
    "k8s_mesh_policy", "kms_key", "cloud_secret", "storage_encryption", "load_balancer_tls", "cdn_tls", "api_tls",
    "cloud_ca", "iam_certificate", "identity_provider", "signing_key", "open_port", "coverage",
    "host_secret", "crypto_config",
}

CDX_TYPE = {
    **{t: "certificate" for t in ("certificate", "k8s_tls_secret", "iam_certificate", "cloud_ca")},
    **{t: "protocol" for t in ("tls_endpoint", "ssh_endpoint", "ssh_server_config", "database_tls", "load_balancer_tls",
                                "cdn_tls", "api_tls", "k8s_ingress_tls", "crypto_config")},
    **{t: "related-crypto-material" for t in ("private_key", "public_key", "keystore", "ssh_host_key", "kms_key",
                                               "cloud_secret", "signing_key", "k8s_certificate", "host_secret")},
    **{t: "library" for t in ("crypto_library", "process_library")},
}

# Extension rules. A feature module in classify_ext/ owns its asset types: it calls register() at import with a
# rule(out, facts, algorithm, key_size, now) that adds codes to `out` and returns the quantum verdict (True, False or
# None). Modules are imported at the bottom of this file, so ASSET_TYPES (a set shared with jobs.py) includes them.
EXT_RULES: dict[str, Any] = {}


def register(asset_type: str, rule: Any, cdx_type: str = "other") -> None:
    ASSET_TYPES.add(asset_type)
    EXT_RULES[asset_type] = rule
    CDX_TYPE[asset_type] = cdx_type


_WEAK_CIPHER_RE = re.compile(r"(^|[-_])(RC4|DES|3DES|DES-CBC3|NULL|EXPORT|EXP|ANON|ADH|AECDH|IDEA|SEED|RC2|MD5)([-_]|$)", re.I)


def _upper(text: Any) -> str:
    return str(text or "").upper().replace("_", "-")


def family(algorithm: Any) -> str | None:
    """Normalised public-key family of an algorithm identifier (RSA, EC, ED25519, PQ ...), or None.

    The identity comes from ``algid`` (the one table of algorithm identities shared with the scan node and the code
    lane): a dotted OID, a registry or cloud name, an alias, a post-quantum marker, then today's classical name rules
    with a token-bounded DSA (a post-quantum signature whose name ends in DSA is never DSA)."""
    return algid.family_label(algorithm)


def quantum_vulnerable(algorithm: Any) -> bool | None:
    """True when a large quantum computer breaks the public-key algorithm (Shor), False for post-quantum (pure, hybrid
    or composite), None when the identifier carries no public-key verdict (symmetric, hash, unknown)."""
    return algid.quantum_vulnerable(algorithm)


# Asset types that carry a key or certificate algorithm: an identifier on them that algid does not know is logged.
KEY_BEARING_TYPES = frozenset({"certificate", "k8s_tls_secret", "iam_certificate", "cloud_ca", "private_key",
                               "public_key", "ssh_host_key", "signing_key", "kms_key", "k8s_certificate",
                               "managed_key"})
_UNKNOWN_LIMIT = 1024  # distinct values logged per process; the set never grows past it
_unknown_seen: set[str] = set()
_unknown_lock = threading.Lock()


def note_unknown(asset_type: str, value: Any) -> None:
    """Log ``classify unknown identifier`` once per process for an identifier on a key-bearing asset that names no
    known algorithm (a private-arc OID, an enum value a newer SDK added).  Placeholders ("<NULL>", "Unknown OID") and
    known identifiers log nothing.  The value is quoted and cut to 64 characters, so it stays one greppable line."""
    if asset_type not in KEY_BEARING_TYPES or not isinstance(value, str) or algid.is_sentinel(value):
        return
    text = value.strip()
    if algid.resolve(text) is not None:
        return
    with _unknown_lock:
        if text in _unknown_seen or len(_unknown_seen) >= _UNKNOWN_LIMIT:
            return
        _unknown_seen.add(text)
    log("classify unknown identifier", type=asset_type, value=json.dumps(text[:64]))


# algid primitives (CycloneDX 1.6) of a key exchange: a post-quantum identifier in a key-exchange slot (a TLS group, an
# SSH kex method, an IKE group) is post-quantum key-exchange evidence only with one of these.  A post-quantum signature
# there (a lattice or hash-based signature, a signature OID) is no key exchange; every real PQ group and method is
# a KEM.
KEX_PRIMITIVES = frozenset({"kem", "key-agree"})


def kex_identity(value: Any, namespace: str | None = None) -> algid.Identity | None:
    """algid's identity of an identifier in a key-exchange slot: exact in ``namespace`` (tls_group, ssh_kex, ike_ke)
    first, then the generic lookup for a spelling the registry does not list (an oqs-provider name)."""
    if not isinstance(value, str):
        return None
    return (algid.resolve(value, namespace) if namespace else None) or algid.resolve(value)


def pq_key_exchange(value: Any, namespace: str | None = None) -> bool:
    """Whether an identifier in a key-exchange slot names a post-quantum key exchange: algid knows it as quantum safe
    or hybrid AND as a KEM or key agreement."""
    found = kex_identity(value, namespace)
    return found is not None and found.quantum in ("safe", "hybrid") and found.primitive in KEX_PRIMITIVES


def _group_vulnerable(group: Any) -> bool | None:
    """The quantum verdict of a TLS endpoint's negotiated group: False for a post-quantum key exchange, True for a
    classical group (P-256 names both an ECDSA and an ECDH curve, so a classical identifier is not checked for its
    primitive), None for an unknown identifier and for a post-quantum identifier that is no key exchange (a signature
    in the group slot proves nothing about the key exchange)."""
    found = kex_identity(group, "tls_group")
    if found is None or found.quantum is None:
        return None
    if found.quantum == "vulnerable":
        return True
    return False if found.primitive in KEX_PRIMITIVES else None


def pq_kex_evidence(facts: dict[str, Any]) -> bool | None:
    """Whether a TLS endpoint's facts show a post-quantum key exchange: True, False, or None when they say nothing.

    ``pq_group_supported`` (a cloud policy, or set before) is the answer when present.  Otherwise a ``pq_hybrid`` probe
    hit, or a negotiated or probed group that algid knows as a post-quantum (pure or hybrid) KEM or key agreement, is
    True: a node before CB-04 reported ``pq_hybrid: false`` next to a negotiated hybrid group when the server's
    certificate was post-quantum.  ``pq_hybrid: false`` with no such group is False; a post-quantum signature in a group
    slot is no such group.  Placeholder groups ("<NULL>") count as absent."""
    supported = facts.get("pq_group_supported")
    if isinstance(supported, bool):
        return supported
    if facts.get("pq_hybrid") is True:
        return True
    for key in ("negotiated_group", "pq_group", "group"):
        if pq_key_exchange(facts.get(key), "tls_group"):
            return True
    if facts.get("pq_hybrid") is False:
        return False
    return None


def cert_identity_input(algorithm: Any, facts: dict[str, Any]) -> Any:
    """The identifier a certificate's quantum verdict is judged by: the key's OID when the collector sent one, else
    its raw key algorithm when algid knows that as post-quantum (an AWS Private CA row stored before CB-04 says
    ``algorithm: ECDSA`` next to its post-quantum ``key_alg`` enum), else the stored algorithm as before.  A classical verdict
    never moves: only a post-quantum raw identifier is preferred over the stored name."""
    oid = facts.get("key_alg_oid")
    if isinstance(oid, str) and oid.strip():
        return oid
    key_alg = facts.get("key_alg")
    if key_alg and algid.quantum_vulnerable(key_alg) is False:
        return key_alg
    return algorithm or key_alg


def _parse_time(value: Any) -> _dt.datetime | None:
    if not value:
        return None
    try:
        moment = _dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if moment.tzinfo is not None:
        moment = moment.astimezone(_dt.timezone.utc).replace(tzinfo=None)
    return moment


class _Out:
    def __init__(self) -> None:
        self.codes: list[str] = []
        self.texts: list[tuple[int, str]] = []
        self.by_code: dict[str, str] = {}
        self.impacts: dict[str, str | None] = {}
        self.impact: str | None = None

    def add(self, code: str, impact: str | None, text: str) -> None:
        if code in self.codes:
            return
        self.codes.append(code)
        self.by_code[code] = text
        self.impacts[code] = impact
        rank = _RANK.get(impact, len(IMPACTS)) if impact else len(IMPACTS) + 1
        self.texts.append((rank, text))
        if impact and (self.impact is None or _RANK[impact] < _RANK[self.impact]):
            self.impact = impact

    def finding(self) -> str | None:
        if not self.texts:
            return None
        ordered = [text for _rank, text in sorted(self.texts, key=lambda item: item[0])]
        return "; ".join(dict.fromkeys(ordered))[:512]  # one sentence for codes that share it (TLS 1.0 and 1.1)


def _key_rules(out: _Out, algorithm: Any, size: Any, what: str) -> None:
    fam = family(algorithm)
    bits = size if isinstance(size, int) and size > 0 else None
    if fam == "RSA" and bits:
        if bits < 1024:
            out.add("RSA_LT_1024", "Critical", f"{what} uses RSA-{bits}, which can be factored today")
        elif bits < 2048:
            out.add("RSA_LT_2048", "High", f"{what} uses RSA-{bits}; the minimum is 2048 bits")
    elif fam == "DSA":
        out.add("DSA", "High", f"{what} uses DSA, which is deprecated")
    elif fam in ("EC", "ECDSA", "ECDH") and bits and bits < 224:
        out.add("EC_LT_224", "High", f"{what} uses a {bits}-bit curve")
    elif fam == "DH" and bits and bits < 2048:
        out.add("DH_LT_2048", "High", f"{what} uses {bits}-bit Diffie-Hellman")


def _cert_rules(out: _Out, facts: dict[str, Any], algorithm: Any, size: Any, now: _dt.datetime) -> None:
    not_after = _parse_time(facts.get("not_after"))
    if not_after is not None:
        days = (not_after - now).total_seconds() / 86400
        if days < 0:
            out.add("CERT_EXPIRED", "High", f"Certificate expired on {not_after.date().isoformat()}")
        elif days <= 30:
            out.add("CERT_EXPIRES_30D", "Medium", f"Certificate expires in {int(days)} days")
    sig = _upper(facts.get("sig_alg"))
    sha1 = "SHA1" in sig.replace("-", "")
    if "MD5" in sig or "MD2" in sig:
        out.add("SIG_MD5", "Critical", f"Certificate is signed with {facts.get('sig_alg')}")
    elif sha1 and not facts.get("self_signed"):
        out.add("SIG_SHA1", "High", f"Certificate is signed with {facts.get('sig_alg')}")
    # A self-signature is never verified by a client (the certificate is trusted, or pinned, as itself), so SHA-1 there
    # is not a forgery risk and is not SIG_SHA1; the text says so and asks for SHA-256 at the next re-issue.
    sha1_note = (f"its {facts.get('sig_alg')} self-signature is not checked by clients (they trust the certificate "
                 "itself), so it is deliberately not reported as a weak SHA-1 signature (SIG_SHA1); re-issue it with "
                 "SHA-256 so policies and scanners stop flagging it")
    if facts.get("self_signed") and not facts.get("is_ca") and facts.get("source") != "idp":
        # identity-provider signing certificates are self-signed by design (trust comes from metadata)
        out.add("CERT_SELF_SIGNED", "Low", "Self-signed certificate" + (f"; {sha1_note}" if sha1 else ""))
    elif facts.get("self_signed") and sha1:
        # a self-signed CA root or IdP signing certificate: informational only (no impact)
        what = "identity-provider signing certificate" if facts.get("source") == "idp" else "CA certificate"
        out.add("CERT_SELF_SHA1", None, f"Self-signed {what}: {sha1_note}")
    if facts.get("in_use") is False:
        out.add("CERT_UNUSED", "Low", "Certificate is not attached to any resource (orphaned)")
    _key_rules(out, algorithm or facts.get("key_alg"), size or facts.get("key_size"), "Certificate key")


_TLS_OLD = {"SSLV2": ("Critical", "SSLv2"), "SSLV3": ("Critical", "SSLv3"), "TLSV1.0": ("High", "TLS 1.0"),
            "TLSV1": ("High", "TLS 1.0"), "TLSV1.1": ("High", "TLS 1.1")}


def _norm_proto(value: Any) -> str:
    return _upper(value).replace(" ", "").replace("TLS1", "TLSV1").replace("SSL3", "SSLV3").replace("SSL2", "SSLV2")


def _tls_rules(out: _Out, facts: dict[str, Any], what: str) -> None:
    protocols = [_norm_proto(p) for p in facts.get("protocols") or []]
    for proto in protocols:
        if proto in _TLS_OLD:
            impact, label = _TLS_OLD[proto]
            out.add(f"PROTO_{label.replace(' ', '').replace('.', '')}", impact, f"{what} accepts {label}")
    if protocols and not any(p in ("TLSV1.2", "TLSV1.3") for p in protocols):
        out.add("NO_TLS12", "High", f"{what} supports neither TLS 1.2 nor TLS 1.3")
    weak = [c for c in facts.get("weak_ciphers") or [] if isinstance(c, str)]
    weak += [c for c in facts.get("ciphers") or [] if isinstance(c, str) and _WEAK_CIPHER_RE.search(c)]
    if weak:
        out.add("WEAK_CIPHER", "High", f"{what} accepts weak ciphers ({', '.join(sorted(set(weak))[:4])})")
    if facts.get("static_rsa_kex"):
        out.add("STATIC_RSA_KEX", "Medium", f"{what} accepts RSA key exchange without forward secrecy")
    if facts.get("cbc_only"):
        out.add("CBC_ONLY", "Medium", f"{what} only offers CBC cipher suites")
    elif facts.get("cbc_accepted"):
        out.add("CBC_ACCEPTED", "Low", f"{what} still accepts CBC-mode cipher suites")
    if facts.get("downgrade_exposed"):
        out.add("DOWNGRADE", "Medium", f"{what} can be downgraded to an older protocol version")
    if facts.get("fallback_scsv") is False and len(protocols) > 1:
        out.add("NO_FALLBACK_SCSV", "Medium", f"{what} does not reject protocol downgrades (TLS_FALLBACK_SCSV)")
    if (facts.get("plaintext_only") or facts.get("tls") is False) and str(facts.get("service") or "").lower() == "rdp":
        # seen from the network: the server negotiated Standard RDP Security, the same weakness the host check reports
        out.add("RDP_NO_TLS", "High", "Remote Desktop negotiates the legacy RDP security layer (no TLS)")
    elif facts.get("plaintext_only") or facts.get("tls") is False:
        out.add("NO_TLS", "High", f"{what} does not offer TLS")
    min_version = _norm_proto(facts.get("min_version"))
    if min_version in _TLS_OLD:
        impact, label = _TLS_OLD[min_version]
        out.add(f"MIN_{label.replace(' ', '').replace('.', '')}", impact, f"{what} allows {label} as the minimum version")
    group = facts.get("group") or facts.get("negotiated_group")
    if facts.get("pq_group_supported") is False or (facts.get("pq_group_supported") is None and group and _group_vulnerable(group)):
        out.add("NO_PQ_KEX", "Low", f"{what} has no post-quantum key exchange")


_SSH_WEAK = (
    (re.compile(r"(arcfour|3des|blowfish|cast128|^des(-cbc)?(@ssh\.com)?$|^idea-)", re.I), "SSH_WEAK_CIPHER", "High",
     "broken SSH ciphers"),
    (re.compile(r"(-cbc$|rijndael-cbc)", re.I), "SSH_CBC_CIPHER", "Medium", "CBC-mode SSH ciphers"),
    (re.compile(r"(hmac-md5|-96$)", re.I), "SSH_WEAK_MAC", "Medium", "weak or truncated SSH MACs"),
    (re.compile(r"^umac-64", re.I), "SSH_UMAC64", "Low", "64-bit UMAC tags"),
    (re.compile(r"^(diffie-hellman-group1-sha1|gss-group1-sha1-.*)$", re.I), "SSH_DH_GROUP1", "High",
     "1024-bit DH key exchange"),
    (re.compile(r"^(diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1|rsa1024-sha1|"
                r"gss-(group14|gex)-sha1-.*)$", re.I), "SSH_DH_SHA1", "Medium", "SHA-1 key exchange"),
    (re.compile(r"^(ssh-dss|x509v3-(ssh|sign)-dss)", re.I), "SSH_DSS", "High", "DSA host keys"),
    (re.compile(r"^(ssh-rsa|ssh-rsa-cert-v01@openssh\.com|x509v3-ssh-rsa|x509v3-sign-rsa)$", re.I), "SSH_RSA_SHA1",
     "Medium", "SHA-1 RSA signatures (ssh-rsa)"),
    (re.compile(r"^hmac-sha1(-etm@openssh\.com)?$", re.I), "SSH_HMAC_SHA1", "Low", "HMAC-SHA1"),
)
# Rules that read one algorithm list only: a ``none`` MAC is not a cipher (names: IANA SSH parameters).
_SSH_WEAK_IN_LIST = (
    ("ciphers", re.compile(r"^none$", re.IGNORECASE), "SSH_WEAK_CIPHER", "High", "broken SSH ciphers"),
    ("macs", re.compile(r"^none$", re.IGNORECASE), "SSH_WEAK_MAC", "Medium", "weak or truncated SSH MACs"),
)
_SSH_LISTS = {"ciphers": ("ciphers",), "macs": ("macs",), "kex": ("kex", "kexalgorithms"),
              "hostkey": ("hostkey_algorithms", "hostkeyalgorithms")}


def _ssh_list(facts: dict[str, Any], key: str) -> list[str]:
    value = facts.get(key)
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


def _ssh_rules(out: _Out, facts: dict[str, Any], what: str) -> bool | None:
    by_list = {name: [n for key in keys for n in _ssh_list(facts, key)] for name, keys in _SSH_LISTS.items()}
    rules = [(pattern, code, impact, label, None) for pattern, code, impact, label in _SSH_WEAK]
    rules += [(pattern, code, impact, label, only) for only, pattern, code, impact, label in _SSH_WEAK_IN_LIST]
    for pattern, code, impact, label, only in rules:
        names = by_list[only] if only else [n for names in by_list.values() for n in names]
        hits = sorted({n for n in names if pattern.search(n)})
        if hits:
            out.add(code, impact, f"{what} offers {label} ({', '.join(hits[:3])})")
    kex = facts.get("kex") or facts.get("kexalgorithms") or []
    kex = kex.split(",") if isinstance(kex, str) else kex
    if not kex:
        return None
    pq = any(pq_key_exchange(k, "ssh_kex") for k in kex)  # a post-quantum signature is no key exchange
    if not pq:
        out.add("SSH_NO_PQ_KEX", "Low", f"{what} has no post-quantum key exchange")
    return not pq


# SSH public-key type names (RFC 4253, 5656, 8709; OpenSSH certificates and FIDO keys) -> the family _key_rules reads
_SSH_KEY_FAMILY = (("ssh-rsa", "RSA"), ("rsa-sha2-", "RSA"), ("x509v3-ssh-rsa", "RSA"), ("x509v3-sign-rsa", "RSA"),
                   ("x509v3-rsa", "RSA"), ("ssh-dss", "DSA"), ("x509v3-ssh-dss", "DSA"), ("x509v3-sign-dss", "DSA"),
                   ("ecdsa-sha2-", "ECDSA"), ("sk-ecdsa-sha2-", "ECDSA"), ("x509v3-ecdsa-sha2-", "ECDSA"),
                   ("ssh-ed25519", "ED25519"), ("sk-ssh-ed25519", "ED25519"), ("ssh-ed448", "ED448"))


def _ssh_key_family(key_type: Any) -> Any:
    text = str(key_type or "")
    return next((fam for prefix, fam in _SSH_KEY_FAMILY if text.startswith(prefix)), key_type)


def _ssh_host_key_rules(out: _Out, facts: dict[str, Any], now: _dt.datetime) -> None:
    """Key-size rules for every host key the server holds (``host_keys``, CB-13), and for host certificates their
    validity, CA key and CA signature.  ``host_key`` (one key, older nodes) is judged as before."""
    host_key = facts.get("host_key") if isinstance(facts.get("host_key"), dict) else {}
    if host_key:
        _key_rules(out, host_key.get("key_type"), host_key.get("bits"), "SSH host key")
    for key in facts.get("host_keys") or []:
        if not isinstance(key, dict):
            continue
        name = str(key.get("type") or "")
        _key_rules(out, _ssh_key_family(key.get("key_type") or name), key.get("bits"), f"SSH host key {name}")
        cert = key.get("certificate")
        if not isinstance(cert, dict):
            continue
        what = f"SSH host certificate {name}"
        valid_before = _parse_time(cert.get("valid_before")) if cert.get("valid_before") != "forever" else None
        if valid_before is not None:
            days = (valid_before - now).total_seconds() / 86400
            if days < 0:
                out.add("CERT_EXPIRED", "High", f"{what} expired on {valid_before.date().isoformat()}")
            elif days <= 30:
                out.add("CERT_EXPIRES_30D", "Medium", f"{what} expires in {int(days)} days")
        ca = cert.get("ca") if isinstance(cert.get("ca"), dict) else {}
        if ca:
            _key_rules(out, _ssh_key_family(ca.get("type")), ca.get("bits"), f"{what}: CA key {ca.get('type')}")
        if str(cert.get("signature_algorithm") or "").lower() == "ssh-rsa":
            out.add("SIG_SHA1", "High", f"{what} is signed by its CA with ssh-rsa (SHA-1)")


def _normalise(asset_type: str, facts: dict[str, Any]) -> dict[str, Any]:
    """Map the scan node's fact names onto the ones the rules read (node facts stay as reported)."""
    out = dict(facts)
    if asset_type in ("tls_endpoint", "database_tls", "k8s_ingress_tls"):
        versions = facts.get("versions")
        if not out.get("protocols"):
            if isinstance(versions, dict):
                out["protocols"] = [name for name, offered in versions.items() if offered]
            elif isinstance(versions, list):
                out["protocols"] = versions
            elif facts.get("negotiated_version"):
                out["protocols"] = [facts["negotiated_version"]]
        weak = facts.get("weak_ciphers_accepted")
        if isinstance(weak, dict):
            out.setdefault("weak_ciphers", list(weak.get("obsolete") or []))
            out.setdefault("static_rsa_kex", bool(weak.get("static_rsa")))
            out.setdefault("cbc_accepted", bool(weak.get("cbc")))
        for key in ("group", "negotiated_group", "pq_group"):
            if algid.is_sentinel(out.get(key)):
                out[key] = None  # s_client prints "<NULL>" when no group was negotiated: no group, not an unknown one
        evidence = pq_kex_evidence(facts)
        if evidence is not None and "pq_group_supported" not in out:
            out["pq_group_supported"] = evidence
        if facts.get("tls") is False or facts.get("plaintext_only"):
            out["plaintext_only"] = True
    if asset_type == "ssh_endpoint":
        out.setdefault("ciphers", sorted(set((facts.get("ciphers_c2s") or []) + (facts.get("ciphers_s2c") or []))))
        out.setdefault("macs", sorted(set((facts.get("macs_c2s") or []) + (facts.get("macs_s2c") or []))))
        out.setdefault("hostkey_algorithms", facts.get("host_key_algs") or [])
    if asset_type == "os_crypto_policy" and "policy" not in out:
        out["policy"] = facts.get("crypto_policy")
    return out


_SCHANNEL = {"SSL 2.0": ("PROTO_SSLv2", "Critical"), "SSL 3.0": ("PROTO_SSLv3", "Critical"),
             "TLS 1.0": ("PROTO_TLS10", "High"), "TLS 1.1": ("PROTO_TLS11", "High")}


def _windows_rules(out: _Out, facts: dict[str, Any]) -> None:
    """SCHANNEL registry, enabled cipher suites and RDP security on a Windows host. Only settings that are
    explicitly on are flagged: a missing registry key means the OS default, which the network probe of the
    host's TLS ports measures directly."""
    schannel = facts.get("schannel_protocols")
    if isinstance(schannel, dict):
        for proto, sides in schannel.items():
            rule = _SCHANNEL.get(str(proto).strip())
            server = (sides or {}).get("server") if isinstance(sides, dict) else None
            if rule and isinstance(server, dict) and server.get("enabled") is True:
                out.add(rule[0], rule[1], f"SCHANNEL enables {proto} for servers (registry)")
    raw_suites = facts.get("cipher_suites")
    suites = [str(c) for c in raw_suites if isinstance(c, str)] if isinstance(raw_suites, list) else []
    weak = [c for c in suites if _WEAK_CIPHER_RE.search(c)]
    if weak:
        out.add("WEAK_CIPHER", "High", f"Windows enables weak cipher suites ({', '.join(sorted(set(weak))[:4])})")
    if any(c.upper().startswith("TLS_RSA_WITH_") for c in suites):
        out.add("STATIC_RSA_KEX", "Medium", "Windows enables RSA key exchange suites without forward secrecy")
    aead = any(("_GCM_" in c.upper() or "CHACHA20" in c.upper() or "_CCM" in c.upper()) for c in suites)
    if any("_CBC_" in c.upper() for c in suites):
        if aead:
            out.add("CBC_ACCEPTED", "Low", "Windows still enables CBC-mode cipher suites")
        else:
            out.add("CBC_ONLY", "Medium", "Windows enables only CBC-mode cipher suites (no AES-GCM or ChaCha20)")
    algos = facts.get("schannel_algorithms")
    if isinstance(algos, dict):
        on = [v for v in algos.values() if isinstance(v, dict) and v.get("enabled") is True]
        weak_ciphers = sorted({str(v.get("name")) for v in on if v.get("kind") == "Ciphers"
                               and re.search(r"\b(RC4|RC2|DES|NULL)\b", str(v.get("name")), re.I)})
        if weak_ciphers:
            out.add("WEAK_CIPHER", "High", f"SCHANNEL explicitly enables {', '.join(weak_ciphers[:4])} (registry)")
        if any(v.get("kind") == "Hashes" and str(v.get("name")).upper() == "MD5" for v in on):
            out.add("WEAK_CIPHER", "High", "SCHANNEL explicitly enables the MD5 hash for TLS (registry)")
        for v in algos.values():
            bits = v.get("server_min_key_bits") if isinstance(v, dict) else None
            if v.get("kind") == "KeyExchangeAlgorithms" and isinstance(bits, int) and 0 < bits < 2048 \
                    and "diffie" in str(v.get("name")).lower():
                out.add("DH_LT_2048", "Medium", f"SCHANNEL accepts Diffie-Hellman groups from {bits} bits (registry)")
    dotnet = facts.get("dotnet")
    if isinstance(dotnet, list):
        off = [d for d in dotnet if isinstance(d, dict) and d.get("framework") == "v4.0.30319"
               and d.get("sch_use_strong_crypto") == 0]
        if off:
            where = " and ".join("32-bit" if d.get("wow64") else "64-bit" for d in off)
            out.add("DOTNET_WEAK_TLS", "Medium", f".NET Framework 4.x SchUseStrongCrypto=0 ({where})")
    rdp = facts.get("rdp") if isinstance(facts.get("rdp"), dict) else {}
    if rdp.get("security_layer") == 0:
        out.add("RDP_NO_TLS", "High", "Remote Desktop uses the legacy RDP security layer (no TLS)")
    if rdp.get("nla") is False:
        out.add("RDP_NO_NLA", "Medium", "Remote Desktop accepts connections without Network Level Authentication")


_LEGACY_TLS = {"SSLV2": ("MIN_SSLv2", "PROTO_SSLv2"), "SSLV3": ("MIN_SSLv3", "PROTO_SSLv3"),
               "TLSV1": ("MIN_TLS10", "PROTO_TLS10"), "TLSV1.0": ("MIN_TLS10", "PROTO_TLS10"),
               "TLSV1.1": ("MIN_TLS11", "PROTO_TLS11")}
_WEAK_CIPHER_STRING = re.compile(r"@SECLEVEL=0|(?<![!-])\b(ALL|aNULL|eNULL|NULL|EXPORT|EXP|RC4|DES|3DES|MD5|LOW)\b")
_BAD_ENC = re.compile(r"^(des|des3|des-ede3|des-ede3-cbc|des-ede|des-ede-cbc|des-cbc|des-ecb|bf|bf-cbc|bf-ecb|rc4|rc4-40|rc2|rc2-cbc|"
                      r"cast|cast5|cast5-cbc|cast-cbc)$|-ecb$", re.I)


def _web_tls_fix(kind: str, facts: dict[str, Any], legacy: list[str]) -> str:
    """What a web server's legacy TLS setting is and exactly what to change: the file and line (scan node 1.x
    ``protocols_line``), the directive as written, the replacement and how to apply it.  Stock Ubuntu nginx.conf
    sets ``ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;`` in its http block."""
    path = str(facts.get("path") or "").strip()
    line = facts.get("protocols_line")
    where = (f"{path} line {line}" if isinstance(line, int) and line > 0 else path) or "its configuration"
    raw = str(facts.get("protocols_raw") or "").strip()
    if kind == "nginx":
        now = f" (ssl_protocols {raw};)" if raw else ""
        return (f"nginx enables {' and '.join(legacy)} in {where}{now}: change it to \"ssl_protocols TLSv1.2 "
                "TLSv1.3;\" (and in any server block that sets its own ssl_protocols), then run \"nginx -t\" and "
                "reload nginx (systemctl reload nginx)")
    now = f" (SSLProtocol {raw})" if raw else ""
    return (f"Apache enables {' and '.join(legacy)} in {where}{now}: change it to \"SSLProtocol -all +TLSv1.2 "
            "+TLSv1.3\" (\"SSLProtocol -all +TLSv1.2\" before Apache 2.4.37), then run \"apachectl configtest\" and "
            "reload Apache")


def _config_rules(out: _Out, facts: dict[str, Any]) -> None:
    """Service crypto overrides, web server TLS directives and openssl enc command lines read from a host."""
    kind = facts.get("kind")
    used = ", ".join(facts.get("used_by") or [])[:120]
    if kind == "openssl_conf":
        d = facts.get("directives") or {}
        minp = _upper((d.get("minprotocol") or {}).get("value"))
        if minp in _LEGACY_TLS:
            out.add(_LEGACY_TLS[minp][0], "High", f"OPENSSL_CONF of {used or 'a service'} sets MinProtocol = {minp}")
        cs = str((d.get("cipherstring") or {}).get("value") or "")
        if "@SECLEVEL=0" in cs.upper() or minp in _LEGACY_TLS:
            out.add("TLS_POLICY_OVERRIDE", "High", f"{used or 'A service'} overrides the OpenSSL policy"
                                                   f"{' (CipherString ' + cs + ')' if cs else ''}")
    elif kind == "java_security":
        d = facts.get("directives") or {}
        tls = d.get("jdk.tls.disabledalgorithms")
        if tls is not None and not str(tls.get("value") or "").strip():
            out.add("TLS_POLICY_OVERRIDE", "High", f"{used or 'A Java service'} empties jdk.tls.disabledAlgorithms: "
                                                   "SSLv3, TLS 1.0/1.1, RC4, 3DES and anonymous suites are accepted again")
    elif kind in ("nginx", "apache"):
        legacy = [(_LEGACY_TLS[_upper(p).lstrip("+")][1], str(p)) for p in facts.get("protocols") or []
                  if _upper(p).lstrip("+") in _LEGACY_TLS]
        text = _web_tls_fix(kind, facts, [proto for _code, proto in legacy]) if legacy else ""
        for code, _proto in legacy:
            out.add(code, "High", text)
        ciphers = str(facts.get("ciphers") or "")
        if ciphers and _WEAK_CIPHER_STRING.search(ciphers):
            out.add("WEAK_CIPHER", "High", f"{kind} cipher list allows weak suites ({ciphers[:60]})")
    elif kind == "openssl_cli":
        cipher = str(facts.get("cipher") or "")
        if cipher and _BAD_ENC.search(cipher):
            out.add("WEAK_CIPHER", "High", f"openssl {cipher} in {facts.get('file')}:{facts.get('line')}")
        if not facts.get("pbkdf2") and facts.get("decrypt") is not True:
            md = facts.get("md")
            out.add("OPENSSL_ENC_WEAK_KDF", "Medium", "openssl enc derives the key with EVP_BytesToKey"
                                                      f"{' -md ' + md if md else ''} (no -pbkdf2)")
        if facts.get("hardcoded_passphrase"):
            out.add("SECRET_IN_CONFIG", "High", f"Passphrase written on the openssl command line in {facts.get('file')}")


_EOL_OPENSSL = re.compile(r"^(openssl|libssl|libcrypto|compat-openssl|openssl-libs)", re.I)


def classify(asset_type: str, algorithm: Any, key_size: Any, protocol: Any, facts: dict[str, Any] | None,
             now: _dt.datetime | None = None) -> dict[str, Any]:
    facts = _normalise(asset_type, facts or {})
    now = now or _dt.datetime.utcnow()
    out = _Out()
    qv: bool | None = quantum_vulnerable(algorithm)
    what = {"tls_endpoint": "Endpoint", "database_tls": "Database", "load_balancer_tls": "Load balancer listener",
            "cdn_tls": "CDN distribution", "api_tls": "API domain", "k8s_ingress_tls": "Ingress"}.get(asset_type, "It")

    if asset_type in EXT_RULES:
        qv = EXT_RULES[asset_type](out, facts, algorithm, key_size, now)
    elif asset_type == "certificate" and facts.get("trust_store"):
        qv = None  # a CA bundle summary (one row per bundle) is inventory, not a finding
    elif asset_type in ("certificate", "k8s_tls_secret", "iam_certificate", "cloud_ca"):
        _cert_rules(out, facts, algorithm, key_size, now)
        identity = cert_identity_input(algorithm, facts)
        qv = quantum_vulnerable(identity)
        if qv is None:
            note_unknown(asset_type, identity)
    elif asset_type in ("private_key", "public_key", "ssh_host_key", "signing_key", "kms_key", "k8s_certificate"):
        _key_rules(out, algorithm, key_size, {"private_key": "Private key", "public_key": "Public key",
                                              "ssh_host_key": "SSH host key", "signing_key": "Signing key",
                                              "kms_key": "KMS key", "k8s_certificate": "Certificate request"}[asset_type])
        if asset_type == "private_key" and facts.get("embedded_in_document"):
            out.add("KEY_IN_DOCUMENT", "Medium", "Private key stored inside a non-key file")
        if asset_type == "private_key" and facts.get("plaintext_in_configmap"):
            out.add("KEY_IN_CONFIGMAP", "High", "Private key stored in plain text in a Kubernetes ConfigMap")
        if asset_type == "private_key" and facts.get("readable") and facts.get("encrypted") is False and facts.get("path"):
            out.add("KEY_READABLE", "Medium", "Unencrypted private key is readable without root")
        if asset_type == "private_key" and facts.get("encrypted") is False and facts.get("world_readable"):
            out.add("KEY_WORLD_READABLE", "High", "Unencrypted private key is readable by every user")
        if asset_type == "private_key" and facts.get("plaintext_in_cloud_config"):
            out.add("SECRET_IN_CONFIG", "High", f"Private key stored in plain text in {facts.get('store') or 'cloud configuration'}")
        if asset_type != "kms_key" and qv is None:
            note_unknown(asset_type, algorithm)
        if asset_type == "kms_key":
            if facts.get("rotation_enabled") is False and facts.get("key_spec") == "SYMMETRIC_DEFAULT" \
                    and facts.get("key_manager") == "CUSTOMER":
                out.add("KMS_NO_ROTATION", "Medium", "Customer-managed KMS key has automatic rotation off")
            if facts.get("key_state") == "PendingDeletion":
                out.add("KMS_PENDING_DELETION", "Low", "KMS key is pending deletion")
            if facts.get("key_spec") and facts.get("key_spec") != "SYMMETRIC_DEFAULT":
                spec = algid.aws("kms", "KeySpec", facts.get("key_spec"))
                qv = quantum_vulnerable(spec.name) if spec is not None else quantum_vulnerable(facts.get("key_spec"))
                if spec is None and qv is None:
                    note_unknown(asset_type, facts.get("key_spec"))
            elif facts.get("key_spec") == "SYMMETRIC_DEFAULT":
                qv = False
        if asset_type == "signing_key" and _upper(facts.get("signature_alg")).replace("-", "").endswith("SHA1"):
            out.add("SIG_SHA1", "High", f"Signing uses {facts.get('signature_alg')}")
        if asset_type == "k8s_certificate" and facts.get("not_after"):
            _cert_rules(out, facts, algorithm, key_size, now)
    elif asset_type in ("tls_endpoint", "database_tls", "load_balancer_tls", "cdn_tls", "api_tls", "k8s_ingress_tls"):
        _tls_rules(out, facts, what)
        group = facts.get("group") or facts.get("negotiated_group")
        if facts.get("pq_group_supported") is True:
            qv = False  # the server accepts a post-quantum hybrid when the client offers one
        elif group:
            qv = _group_vulnerable(group)
        elif facts.get("protocols") or facts.get("cipher"):
            qv = True
        if facts.get("http_listener"):
            out.add("PLAINTEXT_LISTENER", "Medium", f"{what} also serves plaintext HTTP")
    elif asset_type in ("ssh_endpoint", "ssh_server_config"):
        qv = _ssh_rules(out, facts, "SSH server")
        _ssh_host_key_rules(out, facts, now)
    elif asset_type in ("crypto_library", "process_library"):
        version = str(facts.get("version") or "")
        package = str(facts.get("name") or facts.get("package") or "")
        status = crypto_kb.library_status(package, version, today=now.date()) if version and package else None
        eol = (status or {}).get("eol") or {}
        if facts.get("eol"):
            out.add("LIB_EOL", "High", f"{facts.get('package') or algorithm or 'Library'} {facts.get('version') or ''} is end of life".strip())
        elif eol.get("passed"):
            out.add("LIB_EOL", "Medium", f"{package} {version}: upstream {status['library']} {eol['branch']} reached end of life "
                                         f"on {eol['date']}; confirm your OS vendor still ships fixes")
        elif not status and _EOL_OPENSSL.match(package) and re.match(r"^(\d+:)?1\.[01]\.", version):
            out.add("LIB_EOL", "Medium", f"{package} {version}: OpenSSL 1.x is end of life upstream; confirm vendor support")
        elif asset_type == "process_library" and not version:
            # A mapped library has no package version, but its soname pins the OpenSSL branch: libssl/libcrypto
            # .so.1.0 / .so.1.1 are OpenSSL 1.0.2 / 1.1.1, both past upstream end of life (often inside a container
            # image, where the host's package list never shows them).
            soname = re.search(r"lib(?:ssl|crypto)\.so\.(1\.[01])(?:\b|$)", str(facts.get("lib") or algorithm or ""))
            if soname:
                branch = {"1.0": "1.0.2", "1.1": "1.1.1"}[soname.group(1)]
                who = facts.get("process") or "a process"
                out.add("LIB_EOL", "Medium", f"{who} loads OpenSSL {branch} ({str(facts.get('lib')).rsplit('/', 1)[-1]}), "
                                             "which is end of life upstream; confirm the image or vendor still ships fixes")
        if status and status["cves"]:
            cves = status["cves"]
            out.add("LIB_KNOWN_CVE", "Low", f"{package} {version} is inside the published affected range of {len(cves)} "
                                            f"CVE(s) ({', '.join(cves[:3])}{', ...' if len(cves) > 3 else ''}); in triage "
                                            "until checked against the OS vendor's back-ported fixes")
        if facts.get("deleted"):
            out.add("LIB_DELETED_IN_USE", "Medium", "A running process still uses a deleted or replaced crypto library")
        if facts.get("statically_linked_crypto"):
            out.add("LIB_STATIC", "Low", "Crypto is linked into the binary; library patching will not reach it")
        qv = None
    elif asset_type == "disk_encryption" and facts.get("source") == "bitlocker":
        status_text = str(facts.get("status") or "").lower()
        method = str(facts.get("method") or algorithm or "").lower()
        if status_text == "fullydecrypted" or method in ("", "none"):
            out.add("DISK_UNENCRYPTED", "Medium", f"BitLocker volume {facts.get('mount') or ''} is not encrypted".replace("  ", " "))
            qv = None  # no cipher, so no quantum verdict (not "quantum-safe")
        else:
            if "xts" not in method and method.startswith("aes"):
                out.add("DISK_CBC", "Medium", f"BitLocker uses {facts.get('method')} (AES-CBC); use XTS-AES 256")
            if "128" in method and "xts" in method:
                out.add("DISK_XTS_128", "Low", f"BitLocker uses XTS-AES with a 128-bit key ({facts.get('method')})")
            if str(facts.get("protection") or "").lower() == "off" and status_text == "fullyencrypted":
                out.add("DISK_PROTECTION_OFF", "Medium", "BitLocker protection is suspended (the volume key is stored in the clear)")
            qv = False
    elif asset_type == "disk_encryption":
        cipher = _upper(facts.get("cipher") or algorithm)
        if facts.get("encrypted") is False:
            out.add("DISK_UNENCRYPTED", "Medium", "Volume is not encrypted")
        if "ESSIV" in cipher or ("CBC" in cipher and "XTS" not in cipher):
            out.add("DISK_CBC", "Medium", f"Volume uses {facts.get('cipher') or algorithm}; use aes-xts-plain64")
        if isinstance(key_size, int) and 0 < key_size < 256 and "XTS" in cipher:
            out.add("DISK_XTS_128", "Low", "AES-XTS with a 128-bit key")
        if facts.get("luks_version") == 1:
            out.add("LUKS1", "Low", "LUKS1 header (no Argon2 key derivation)")
        qv = None if facts.get("encrypted") is False else False
    elif asset_type == "os_crypto_policy":
        policy = _upper(facts.get("policy"))
        if policy.startswith("LEGACY"):
            out.add("POLICY_LEGACY", "High", "System crypto policy is LEGACY")
        _windows_rules(out, facts)
        qv = None
    elif asset_type == "database_config":
        if facts.get("ssl") is False or facts.get("tls_enabled") is False or facts.get("tls") is False:
            out.add("DB_NO_TLS", "High", "Database does not offer TLS")
        if facts.get("require_secure_transport") is False:
            out.add("DB_TLS_OPTIONAL", "Medium", "Database accepts unencrypted connections")
        if facts.get("auth_required") is False:
            out.add("DB_NO_AUTH", "High", "Database accepts connections without a password")
        if _upper(facts.get("password_encryption")) == "MD5":
            out.add("DB_MD5_DEFAULT", "Medium", "New passwords are stored as MD5 hashes")
        if facts.get("md5_auth_accepted"):  # RDS PostgreSQL rds.accepted_password_auth_method = md5+scram
            out.add("DB_MD5_ACCEPTED", "Medium", "The server still accepts md5 password authentication")
        if facts.get("engine") == "mysql" and facts.get("keyring_plugins") == [] and not facts.get("encrypted_tables"):
            out.add("DB_NO_TDE", "Low", "No tables are encrypted at rest (no keyring component)")
        if facts.get("tls_mode") in ("disabled", "allowTLS", "preferTLS"):
            out.add("DB_TLS_MODE", "High" if facts.get("tls_mode") == "disabled" else "Medium",
                    f"TLS mode is {facts.get('tls_mode')}")
        _tls_rules(out, {k: facts.get(k) for k in ("protocols", "min_version")}, "Database")
        qv = None
    elif asset_type == "database_user_auth":
        hba = facts.get("hba_methods") if isinstance(facts.get("hba_methods"), dict) else {}
        if hba.get("trust"):
            out.add("DB_TRUST", "High", f"{hba['trust']} HBA rule(s) let clients in without a password (trust)")
        if hba.get("password"):
            out.add("DB_CLEARTEXT_PW", "High", "An HBA rule sends passwords in clear text (password method)")
        # PostgreSQL login roles by stored password hash type (pg_authid, zs_role_password_types() or rds_tools);
        # roles without a password are skipped, rds_iam roles (IAM token sign-in on RDS) are named.
        roles = facts.get("role_hash_types") if isinstance(facts.get("role_hash_types"), dict) else {}
        iam = {str(r) for r in facts.get("iam_auth_roles") or []}

        def _names(found: list[str]) -> str:
            shown = ", ".join(f"{r} (rds_iam)" if r in iam else r for r in found[:10])
            return shown + (f" and {len(found) - 10} more" if len(found) > 10 else "")

        plain = sorted(str(r) for r, t in roles.items() if str(t).lower() == "other")
        md5_roles = sorted(str(r) for r, t in roles.items() if str(t).lower() == "md5")
        if plain:
            out.add("DB_PLAINTEXT_PW", "High", f"{len(plain)} login role(s) store a password that is neither an MD5 nor "
                                               f"a SCRAM hash (plain text): {_names(plain)}")
        weak = []
        # An md5 HBA rule authenticates a role whose password is stored as SCRAM with SCRAM (PostgreSQL docs, 21.5
        # Password Authentication): with password_encryption = scram-sha-256 and every login role's hash read as SCRAM
        # (or no password), the md5 rules negotiate nothing weaker.
        all_scram = bool(roles) and not plain and not md5_roles and \
            _upper(facts.get("password_encryption")) == "SCRAM-SHA-256"
        if hba.get("md5") and not all_scram:
            weak.append(f"{hba['md5']} HBA rule(s) use md5 authentication")
        if md5_roles:
            weak.append(f"{len(md5_roles)} login role(s) have MD5 password hashes: {_names(md5_roles)}")
        if weak:
            out.add("DB_WEAK_HASH", "Medium", "; ".join(weak))
        if _upper(facts.get("password_encryption")) == "MD5":
            out.add("DB_MD5_DEFAULT", "Medium", "New passwords are stored as MD5 hashes")
        plugins = facts.get("plugins") if isinstance(facts.get("plugins"), dict) else {}
        if plugins.get("mysql_native_password"):
            out.add("DB_NATIVE_PW", "Medium", f"{plugins['mysql_native_password']} account(s) use mysql_native_password (SHA-1)")
        if plugins.get("mysql_old_password"):
            out.add("DB_OLD_PASSWORD", "Critical", "Accounts use mysql_old_password")
        method = _upper(facts.get("method") or facts.get("plugin") or algorithm)
        if method in ("TRUST",):
            out.add("DB_TRUST", "Critical", "Database rule lets clients in without a password")
        elif method in ("MD5", "MYSQL-NATIVE-PASSWORD", "PASSWORD"):
            out.add("DB_WEAK_HASH", "Medium", f"Authentication uses {facts.get('method') or facts.get('plugin')}")
        elif method in ("MYSQL-OLD-PASSWORD",):
            out.add("DB_OLD_PASSWORD", "Critical", "Authentication uses mysql_old_password")
        qv = None
    elif asset_type == "k8s_mesh_policy":
        # The collector reports "mtls_mode" (older rows and other sources may say "mode").  UNSET inherits from the
        # namespace / mesh-wide policy, except on the mesh-wide policy itself, where Istio then applies PERMISSIVE.
        mode = _upper(facts.get("mtls_mode") or facts.get("mode"))
        ports = facts.get("port_modes") if isinstance(facts.get("port_modes"), dict) else {}
        off_ports = sorted(str(p) for p, m in ports.items() if _upper(m) == "DISABLE")
        open_ports = sorted(str(p) for p, m in ports.items() if _upper(m) == "PERMISSIVE")
        if mode == "DISABLE":
            out.add("MESH_MTLS_OFF", "High", "Mesh mTLS is disabled")
        elif off_ports:
            out.add("MESH_MTLS_OFF", "High", f"Mesh mTLS is disabled on port(s) {', '.join(off_ports[:10])}")
        if mode == "PERMISSIVE":
            out.add("MESH_MTLS_PERMISSIVE", "Medium", "Mesh mTLS is permissive (plaintext still accepted)")
        elif mode == "UNSET" and facts.get("scope") == "mesh":
            out.add("MESH_MTLS_PERMISSIVE", "Medium", ("No mesh-wide PeerAuthentication exists" if facts.get("implicit")
                                                       else "The mesh-wide PeerAuthentication leaves the mTLS mode unset")
                    + ", so Istio applies PERMISSIVE (plaintext still accepted)")
        elif open_ports:
            out.add("MESH_MTLS_PERMISSIVE", "Medium", f"Mesh mTLS is permissive on port(s) {', '.join(open_ports[:10])}")
        qv = None
    elif asset_type == "storage_encryption":
        if facts.get("encrypted") is False:
            out.add("STORAGE_UNENCRYPTED", "High", f"{facts.get('resource') or 'Storage'} is not encrypted at rest")
        if facts.get("tls_only_policy") is False:
            out.add("STORAGE_NO_TLS_ONLY", "Medium", "Bucket policy does not deny non-TLS requests")
        if facts.get("default_encryption") is False:
            out.add("EBS_DEFAULT_OFF", "Medium", "EBS encryption by default is off in this region")
        qv = False if facts.get("encrypted") else None
    elif asset_type == "cloud_secret":
        if facts.get("plaintext_in_cloud_config"):
            out.add("SECRET_IN_CONFIG", "High", f"{facts.get('variable') or 'A secret'} stored in plain text in "
                                                f"{facts.get('store') or 'cloud configuration'}")
        elif facts.get("service") == "ssm":
            if facts.get("parameter_type") == "String" and facts.get("secret_like_name"):
                out.add("SECRET_PLAINTEXT_PARAM", "High", "Secret-looking SSM parameter stored as a plain String")
        elif facts.get("rotation_enabled") is False:
            out.add("SECRET_NO_ROTATION", "Low", "Secret rotation is off")
        qv = None
    elif asset_type == "host_secret":
        bits = facts.get("key_bits")
        what = f"{bits}-bit key" if isinstance(bits, int) and bits else "secret"
        where = facts.get("store") or "a file"
        readable = " (world-readable file)" if facts.get("world_readable") else ""
        out.add("SECRET_IN_CONFIG", "High", f"{facts.get('name') or 'A'} {what} stored in plain text in {where}{readable}")
        qv = None
    elif asset_type == "crypto_config":
        _config_rules(out, facts)
        qv = None
    elif asset_type == "keystore":
        if _upper(facts.get("format") or facts.get("store_type")) == "JKS":
            out.add("KEYSTORE_JKS", "Low", "JKS keystore format (weak integrity protection); prefer PKCS#12")
        qv = None
    elif asset_type == "identity_provider":
        if facts.get("metadata_signed") is False and facts.get("kind") == "saml":
            out.add("SAML_METADATA_UNSIGNED", "Low", "SAML metadata is not signed")
        qv = None
    elif asset_type == "coverage":
        qv = None
        status = str(facts.get("status") or "")
        detail = str(facts.get("detail") or facts.get("check") or "")
        # a coverage row may name its fix (a GRANT, a function to install): keep it whole (the finding column holds 512)
        out.add(f"COVERAGE_{status.upper()}"[:32], None, f"Not collected: {detail}"[:500])
    elif asset_type in ("k8s_cluster", "open_port"):
        qv = None

    if qv and not any("NO_PQ" in code for code in out.codes) and asset_type != "coverage":  # NO_PQ_KEX, SSH_/IKE_NO_PQ
        out.add("QUANTUM_VULNERABLE", None, "Uses public-key cryptography that a quantum computer can break")
    return {"impact": out.impact, "quantum_vulnerable": qv, "finding_codes": out.codes, "finding": out.finding(),
            "cdx_type": CDX_TYPE.get(asset_type, "other"), "texts": out.by_code, "impacts": out.impacts}


# Import extension modules last (they call register()).
import importlib as _importlib  # noqa: E402
import pkgutil as _pkgutil  # noqa: E402

from backend.utilities.cbom_sources import classify_ext as _classify_ext  # noqa: E402

for _m in sorted(m.name for m in _pkgutil.iter_modules(_classify_ext.__path__)):
    _importlib.import_module(f"{_classify_ext.__name__}.{_m}")


def _rules_files() -> list[str]:
    """Every file whose content decides a verdict: this module, each classify_ext module, and every ``algid*.py``
    beside algid (the resolver and the generated tables it reads, algid_tables.py). Matching by name rather than
    listing the tables file means a later split of the tables cannot fall out of the digest; a test fails if algid
    ever imports a sibling module outside the pattern."""
    import os

    folder = os.path.dirname(_classify_ext.__file__)
    paths = [__file__] + [os.path.join(folder, f"{m}.py")
                          for m in sorted(m.name for m in _pkgutil.iter_modules(_classify_ext.__path__))]
    here = os.path.dirname(algid.__file__)
    paths += [os.path.join(here, name) for name in sorted(os.listdir(here))
              if name.startswith("algid") and name.endswith(".py")]
    return paths


def _rules_version() -> str:
    """A digest of the classification rules in force (``_rules_files``: the rules and the algorithm identities they
    read), so a run records exactly which rules judged it without anyone having to remember to bump a number. A
    table-only change (a regenerated algid_tables.py) changes it, so drift reads that run pair as a rule change and
    not as a change in the estate."""
    import hashlib

    digest = hashlib.sha256()
    for path in _rules_files():
        try:
            with open(path, "rb") as fh:
                digest.update(fh.read())
        except OSError:
            digest.update(path.encode("utf-8", "replace"))
    return "rules-" + digest.hexdigest()[:12]


CLASSIFIER_VERSION = _rules_version()


# ----------------------------------------------------------------------------- date-based rules, judged today
# Two rules read the calendar: a certificate's expiry (CERT_EXPIRED, CERT_EXPIRES_30D) and a library's upstream end
# of life from the knowledge base (LIB_EOL). A run stores its verdict as of its collection date, and that record is
# kept (drift and the OSCAL assessment compare runs by it). Every view of a run's findings (the asset list and its
# counts, the posture totals, the heat map, the migration waves, the asset panel and the CycloneDX export) shows the
# verdict judged TODAY instead, with the run's verdict beside it, so a library that reaches end of life after a run
# is a finding everywhere at once, not only in the panel, and not only after the next run.
CERT_DATED_TYPES = frozenset({"certificate", "k8s_tls_secret", "iam_certificate", "cloud_ca", "k8s_certificate"})
LIBRARY_DATED_TYPES = frozenset({"crypto_library", "process_library"})
DATED_TYPES = CERT_DATED_TYPES | LIBRARY_DATED_TYPES
_EXPIRY_WINDOW = _dt.timedelta(days=31)  # CERT_EXPIRES_30D looks 30 days ahead


def _date_may_matter(asset_type: str, facts: dict[str, Any], then: _dt.datetime, now: _dt.datetime) -> bool:
    """Cheap pre-check: can the date-based rules judge this asset differently ``now`` than ``then``?"""
    if asset_type in LIBRARY_DATED_TYPES:
        version = str(facts.get("version") or "")
        package = str(facts.get("name") or facts.get("package") or "")
        if not version or not package or facts.get("eol"):
            return False
        before = (crypto_kb.library_status(package, version, today=then.date()) or {}).get("eol") or {}
        after = (crypto_kb.library_status(package, version, today=now.date()) or {}).get("eol") or {}
        return bool(before.get("passed")) != bool(after.get("passed"))
    if asset_type in CERT_DATED_TYPES:
        not_after = _parse_time(facts.get("not_after"))
        return not_after is not None and (not_after - then <= _EXPIRY_WINDOW or not_after - now <= _EXPIRY_WINDOW)
    return False


# The codes a date-based rule adds or removes; everything else in a stored verdict is the run's.
DATE_CODES = frozenset({"CERT_EXPIRED", "CERT_EXPIRES_30D", "LIB_EOL"})


def _then_and_now(asset_type: str, algorithm: Any, key_size: Any, protocol: Any, facts: dict[str, Any] | None,
                  collected_at: _dt.datetime | None, now: _dt.datetime | None
                  ) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """(verdict on the collection date, verdict ``now``), both by the current rules, when a date-based rule judges
    the asset differently on the two dates; None when the stored verdict stands."""
    if asset_type not in DATED_TYPES or collected_at is None:
        return None
    facts = facts or {}
    now = now or _dt.datetime.utcnow()
    collected_at, now = (_parse_time(t.isoformat()) or t for t in (collected_at, now))  # naive UTC, as the rules use
    if not _date_may_matter(asset_type, facts, collected_at, now):
        return None
    then_v = classify(asset_type, algorithm, key_size, protocol, facts, collected_at)
    now_v = classify(asset_type, algorithm, key_size, protocol, facts, now)
    if (then_v["finding_codes"], then_v["impact"], then_v["finding"]) == \
            (now_v["finding_codes"], now_v["impact"], now_v["finding"]):
        return None
    return then_v, now_v


def verdict_today(asset_type: str, algorithm: Any, key_size: Any, protocol: Any, facts: dict[str, Any] | None,
                  collected_at: _dt.datetime | None, now: _dt.datetime | None = None) -> dict[str, Any] | None:
    """The verdict of a stored asset judged ``now`` when a date-based rule judges it differently than on its
    collection date; None when the stored verdict stands (no date-based rule applies, or nothing changed)."""
    pair = _then_and_now(asset_type, algorithm, key_size, protocol, facts, collected_at, now)
    return pair[1] if pair else None


def _worse(a: str | None, b: str | None) -> str | None:
    if a is None or (b is not None and _RANK.get(b, len(IMPACTS)) < _RANK.get(a, len(IMPACTS))):
        return b
    return a


def _date_delta(stored_codes: list[str], stored_impact: str | None, stored_finding: str | None,
                then_v: dict[str, Any], now_v: dict[str, Any]) -> dict[str, Any]:
    """The stored verdict with only the date-based codes moved from ``then_v`` to ``now_v``: the rules changed since
    the run, so every other code (an identity code such as QUANTUM_VULNERABLE) stays as the run judged it, next to the
    run's stored quantum verdict.  Impact: the worse of the stored one and the added date codes'."""
    then_dates = [c for c in then_v["finding_codes"] if c in DATE_CODES]
    now_dates = [c for c in now_v["finding_codes"] if c in DATE_CODES]
    removed = [c for c in then_dates if c not in now_dates]
    added = [c for c in now_dates if c not in then_dates and c not in stored_codes]
    codes = [c for c in stored_codes if c not in removed] + added
    gone = {then_v["texts"].get(c) for c in removed}
    kept = [part for part in (stored_finding or "").split("; ") if part and part not in gone]
    finding = "; ".join(dict.fromkeys([now_v["texts"][c] for c in added] + kept))[:512] or None
    impact = stored_impact  # the worst of the stored impact and the added date codes' impacts
    for code in added:
        impact = _worse(impact, now_v["impacts"].get(code))
    impacts = {c: then_v["impacts"][c] for c in codes if c in then_v["impacts"]}
    impacts.update({c: now_v["impacts"][c] for c in added})
    return {"impact": impact, "finding_codes": codes, "finding": finding, "impacts": impacts}


def shown(row: Any, now: _dt.datetime | None = None) -> dict[str, Any]:
    """What every view shows for a stored asset row: its stored verdict, or today's when a date-based rule changed
    it, with the run's verdict kept in ``as_of_run`` (None when nothing changed).

    When the rules changed since the run (re-judging the run date no longer gives the stored codes), only the
    date-based codes move; an old run never shows new identity codes next to its old quantum verdict."""
    now = now or _dt.datetime.utcnow()
    try:
        pair = _then_and_now(row.asset_type, row.algorithm, row.key_size, row.protocol, row.facts or {},
                             row.created_at, now)
    except Exception:  # an asset the current rules cannot read keeps its stored verdict
        pair = None
    codes = [c for c in row.finding_codes or [] if isinstance(c, str)]
    if pair is None:
        return {"impact": row.impact, "finding_codes": codes, "finding": row.finding, "impacts": None,
                "as_of_run": None}
    then_v, now_v = pair
    if set(then_v["finding_codes"]) == set(codes):
        today = now_v
    else:
        today = _date_delta(codes, row.impact, row.finding, then_v, now_v)
    return {"impact": today["impact"], "finding_codes": list(today["finding_codes"]), "finding": today["finding"],
            "impacts": today["impacts"],
            "as_of_run": {"date": row.created_at.date().isoformat(), "judged_on": now.date().isoformat(),
                          "impact": row.impact, "finding_codes": codes, "finding": row.finding}}
