"""Turn the facts a collector reported into impact, quantum exposure and a finding.

Classification lives on the server so every node version is judged by the same rules, and so a node
cannot mark its own findings.  Impact uses the CBOM report vocabulary (Critical / High / Medium / Low);
``None`` means informational.  Each rule adds a code; the asset's impact is the worst one.
"""
from __future__ import annotations

import datetime as _dt
import re
from typing import Any

from backend.utilities.cbom_sources import crypto_kb

IMPACTS = ("Critical", "High", "Medium", "Low")
_RANK = {name: i for i, name in enumerate(IMPACTS)}

ASSET_TYPES = (
    "certificate", "private_key", "public_key", "keystore", "ssh_host_key", "ssh_server_config", "ssh_endpoint",
    "tls_endpoint", "crypto_library", "process_library", "disk_encryption", "os_crypto_policy", "database_tls",
    "database_config", "database_user_auth", "k8s_cluster", "k8s_tls_secret", "k8s_certificate", "k8s_ingress_tls",
    "k8s_mesh_policy", "kms_key", "cloud_secret", "storage_encryption", "load_balancer_tls", "cdn_tls", "api_tls",
    "cloud_ca", "iam_certificate", "identity_provider", "signing_key", "open_port", "coverage",
)

CDX_TYPE = {
    **{t: "certificate" for t in ("certificate", "k8s_tls_secret", "iam_certificate", "cloud_ca")},
    **{t: "protocol" for t in ("tls_endpoint", "ssh_endpoint", "ssh_server_config", "database_tls", "load_balancer_tls",
                                "cdn_tls", "api_tls", "k8s_ingress_tls")},
    **{t: "related-crypto-material" for t in ("private_key", "public_key", "keystore", "ssh_host_key", "kms_key",
                                               "cloud_secret", "signing_key", "k8s_certificate")},
    **{t: "library" for t in ("crypto_library", "process_library")},
}

# Public-key families broken by a large quantum computer (Shor).
_QV_FAMILIES = ("RSA", "DSA", "DH", "ECDSA", "ECDH", "EC", "ED25519", "ED448", "X25519", "X448", "ECC", "SM2")
_PQ_MARKERS = ("MLKEM", "ML-KEM", "KYBER", "MLDSA", "ML-DSA", "SLHDSA", "SLH-DSA", "SPHINCS", "FALCON", "SNTRUP", "FRODO", "HQC")
_WEAK_CIPHER_RE = re.compile(r"(^|[-_])(RC4|DES|3DES|DES-CBC3|NULL|EXPORT|EXP|ANON|ADH|AECDH|IDEA|SEED|RC2|MD5)([-_]|$)", re.I)


def _upper(text: Any) -> str:
    return str(text or "").upper().replace("_", "-")


def family(algorithm: Any) -> str | None:
    """Normalised public-key family of an algorithm name (RSA, EC, ED25519 ...), or None."""
    text = _upper(algorithm)
    if not text:
        return None
    if any(marker in text.replace("-", "") or marker in text for marker in _PQ_MARKERS):
        return "PQ"
    for name in ("ED25519", "ED448", "X25519", "X448", "ECDSA", "ECDH", "DSA", "RSA", "SM2"):
        if name in text:
            return "DSA" if name == "DSA" and "ECDSA" not in text else name
    if text.startswith(("EC", "ID-EC", "PRIME256", "SECP", "P-256", "P-384", "P-521", "NIST")):
        return "EC"
    if text in ("DH", "DHE", "FFDHE") or text.startswith(("DH-", "FFDHE", "DIFFIE")):
        return "DH"
    return None


def quantum_vulnerable(algorithm: Any) -> bool | None:
    fam = family(algorithm)
    if fam is None:
        return None
    if fam == "PQ":
        return False
    return fam in _QV_FAMILIES


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
        return "; ".join(ordered)[:512]


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
    if "MD5" in sig or "MD2" in sig:
        out.add("SIG_MD5", "Critical", f"Certificate is signed with {facts.get('sig_alg')}")
    elif ("SHA1" in sig.replace("-", "") and not facts.get("self_signed")):
        out.add("SIG_SHA1", "High", f"Certificate is signed with {facts.get('sig_alg')}")
    if facts.get("self_signed") and not facts.get("is_ca") and facts.get("source") != "idp":
        # identity-provider signing certificates are self-signed by design (trust comes from metadata)
        out.add("CERT_SELF_SIGNED", "Low", "Self-signed certificate")
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
    if facts.get("plaintext_only") or facts.get("tls") is False:
        out.add("NO_TLS", "High", f"{what} does not offer TLS")
    min_version = _norm_proto(facts.get("min_version"))
    if min_version in _TLS_OLD:
        impact, label = _TLS_OLD[min_version]
        out.add(f"MIN_{label.replace(' ', '').replace('.', '')}", impact, f"{what} allows {label} as the minimum version")
    group = facts.get("group") or facts.get("negotiated_group")
    if facts.get("pq_group_supported") is False or (facts.get("pq_group_supported") is None and group and quantum_vulnerable(group)):
        out.add("NO_PQ_KEX", "Low", f"{what} has no post-quantum key exchange")


_SSH_WEAK = (
    (re.compile(r"(arcfour|3des|blowfish|cast128)", re.I), "SSH_WEAK_CIPHER", "High", "broken SSH ciphers"),
    (re.compile(r"(-cbc$|rijndael-cbc)", re.I), "SSH_CBC_CIPHER", "Medium", "CBC-mode SSH ciphers"),
    (re.compile(r"(hmac-md5|-96$)", re.I), "SSH_WEAK_MAC", "Medium", "weak or truncated SSH MACs"),
    (re.compile(r"^umac-64", re.I), "SSH_UMAC64", "Low", "64-bit UMAC tags"),
    (re.compile(r"^diffie-hellman-group1-sha1$", re.I), "SSH_DH_GROUP1", "High", "1024-bit DH key exchange"),
    (re.compile(r"^(diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)$", re.I), "SSH_DH_SHA1", "Medium", "SHA-1 key exchange"),
    (re.compile(r"^ssh-dss", re.I), "SSH_DSS", "High", "DSA host keys"),
    (re.compile(r"^ssh-rsa$", re.I), "SSH_RSA_SHA1", "Medium", "SHA-1 RSA signatures (ssh-rsa)"),
    (re.compile(r"^hmac-sha1(-etm@openssh\.com)?$", re.I), "SSH_HMAC_SHA1", "Low", "HMAC-SHA1"),
)


def _ssh_rules(out: _Out, facts: dict[str, Any], what: str) -> bool | None:
    names: list[str] = []
    for key in ("ciphers", "macs", "kex", "kexalgorithms", "hostkey_algorithms", "hostkeyalgorithms"):
        value = facts.get(key)
        if isinstance(value, str):
            names += [v.strip() for v in value.split(",") if v.strip()]
        elif isinstance(value, list):
            names += [str(v) for v in value]
    for pattern, code, impact, label in _SSH_WEAK:
        hits = sorted({n for n in names if pattern.search(n)})
        if hits:
            out.add(code, impact, f"{what} offers {label} ({', '.join(hits[:3])})")
    kex = facts.get("kex") or facts.get("kexalgorithms") or []
    kex = kex.split(",") if isinstance(kex, str) else kex
    if not kex:
        return None
    pq = any(quantum_vulnerable(k) is False for k in kex)
    if not pq:
        out.add("SSH_NO_PQ_KEX", "Low", f"{what} has no post-quantum key exchange")
    return not pq


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
        if facts.get("pq_hybrid") is not None and "pq_group_supported" not in out:
            out["pq_group_supported"] = bool(facts.get("pq_hybrid"))
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


_EOL_OPENSSL = re.compile(r"^(openssl|libssl|libcrypto|compat-openssl|openssl-libs)", re.I)


def classify(asset_type: str, algorithm: Any, key_size: Any, protocol: Any, facts: dict[str, Any] | None,
             now: _dt.datetime | None = None) -> dict[str, Any]:
    facts = _normalise(asset_type, facts or {})
    now = now or _dt.datetime.utcnow()
    out = _Out()
    qv: bool | None = quantum_vulnerable(algorithm)
    what = {"tls_endpoint": "Endpoint", "database_tls": "Database", "load_balancer_tls": "Load balancer listener",
            "cdn_tls": "CDN distribution", "api_tls": "API domain", "k8s_ingress_tls": "Ingress"}.get(asset_type, "It")

    if asset_type == "certificate" and facts.get("trust_store"):
        qv = None  # a CA bundle summary (one row per bundle) is inventory, not a finding
    elif asset_type in ("certificate", "k8s_tls_secret", "iam_certificate", "cloud_ca"):
        _cert_rules(out, facts, algorithm, key_size, now)
        qv = quantum_vulnerable(algorithm or facts.get("key_alg"))
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
        if asset_type == "kms_key":
            if facts.get("rotation_enabled") is False and facts.get("key_spec") == "SYMMETRIC_DEFAULT" \
                    and facts.get("key_manager") == "CUSTOMER":
                out.add("KMS_NO_ROTATION", "Medium", "Customer-managed KMS key has automatic rotation off")
            if facts.get("key_state") == "PendingDeletion":
                out.add("KMS_PENDING_DELETION", "Low", "KMS key is pending deletion")
            if facts.get("key_spec") and facts.get("key_spec") != "SYMMETRIC_DEFAULT":
                qv = quantum_vulnerable(facts.get("key_spec"))
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
            qv = quantum_vulnerable(group)
        elif facts.get("protocols") or facts.get("cipher"):
            qv = True
        if facts.get("http_listener"):
            out.add("PLAINTEXT_LISTENER", "Medium", f"{what} also serves plaintext HTTP")
    elif asset_type in ("ssh_endpoint", "ssh_server_config"):
        qv = _ssh_rules(out, facts, "SSH server")
        host_key = facts.get("host_key") if isinstance(facts.get("host_key"), dict) else {}
        if host_key:
            _key_rules(out, host_key.get("key_type"), host_key.get("bits"), "SSH host key")
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
        if hba.get("md5"):
            out.add("DB_WEAK_HASH", "Medium", f"{hba['md5']} HBA rule(s) use md5 authentication")
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
        mode = _upper(facts.get("mode"))
        if mode == "DISABLE":
            out.add("MESH_MTLS_OFF", "High", "Mesh mTLS is disabled")
        elif mode == "PERMISSIVE":
            out.add("MESH_MTLS_PERMISSIVE", "Medium", "Mesh mTLS is permissive (plaintext still accepted)")
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
        if facts.get("service") == "ssm":
            if facts.get("parameter_type") == "String" and facts.get("secret_like_name"):
                out.add("SECRET_PLAINTEXT_PARAM", "High", "Secret-looking SSM parameter stored as a plain String")
        elif facts.get("rotation_enabled") is False:
            out.add("SECRET_NO_ROTATION", "Low", "Secret rotation is off")
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
        out.add(f"COVERAGE_{status.upper()}"[:32], None, f"Not collected: {detail}"[:200])
    elif asset_type in ("k8s_cluster", "open_port"):
        qv = None

    if qv and not any(code.startswith(("NO_PQ", "SSH_NO_PQ")) for code in out.codes) and asset_type != "coverage":
        out.add("QUANTUM_VULNERABLE", None, "Uses public-key cryptography that a quantum computer can break")
    return {"impact": out.impact, "quantum_vulnerable": qv, "finding_codes": out.codes, "finding": out.finding(),
            "cdx_type": CDX_TYPE.get(asset_type, "other"), "texts": out.by_code, "impacts": out.impacts}
