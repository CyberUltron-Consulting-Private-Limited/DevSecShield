"""The one field map: how each judged field is read from each view, and how values are normalised.

Views (all keyed by the product's asset id):
  api     an item of GET /{team}/cbom/sources/runs/{run}/assets (the customer's own token, every page)
  db      a row of db/assets.csv (read-only SELECT on cbomcollectedasset, facts and finding_codes as JSON)
  export  a CycloneDX component of the downloaded run CBOM (bom-ref ``zs-asset-<id>``)
  ui      a row the flow read from the Results table DOM (``data-testid=run-asset-<id>``)

The API is the reference for the view joins: it is what the product serves. The database holds the run's own
verdict (impact, finding, codes) while the API and export show today's (a date-based rule may have changed it since);
``as_of_run`` on the API item carries the run's verdict, so DB is compared with that when present.

Normalisation is for oracle comparisons only (O-2/O-4): view joins compare exact values. The tables below are
transcribed from the standards (NIST CSOR OIDs, SEC 2 / FIPS 186 curve names, IANA TLS registries), never from
product code (O-1).
"""
from __future__ import annotations

import base64
import json
import re
from typing import Any, Callable

from .rundir import iso, parse_ts

MISSING = object()  # the view does not carry the field at all (for the export: FAIL(export-missing))

# --------------------------------------------------------------------------------------------------- normalisation
# NIST CSOR, "Computer Security Objects Register", algorithm OIDs (2.16.840.1.101.3.4.3.x signatures, .4.4.x KEM).
NIST_OIDS = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44", "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
    "2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128S", "2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128F",
    "2.16.840.1.101.3.4.3.22": "SLH-DSA-SHA2-192S", "2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-192F",
    "2.16.840.1.101.3.4.3.24": "SLH-DSA-SHA2-256S", "2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-256F",
    "2.16.840.1.101.3.4.3.26": "SLH-DSA-SHAKE-128S", "2.16.840.1.101.3.4.3.27": "SLH-DSA-SHAKE-128F",
    "2.16.840.1.101.3.4.3.28": "SLH-DSA-SHAKE-192S", "2.16.840.1.101.3.4.3.29": "SLH-DSA-SHAKE-192F",
    "2.16.840.1.101.3.4.3.30": "SLH-DSA-SHAKE-256S", "2.16.840.1.101.3.4.3.31": "SLH-DSA-SHAKE-256F",
    "2.16.840.1.101.3.4.4.1": "ML-KEM-512", "2.16.840.1.101.3.4.4.2": "ML-KEM-768",
    "2.16.840.1.101.3.4.4.3": "ML-KEM-1024",
    # RFC 8017 / RFC 5480 / RFC 8410
    "1.2.840.113549.1.1.1": "RSA", "1.2.840.10045.2.1": "EC", "1.3.101.112": "ED25519", "1.3.101.113": "ED448",
    "1.2.840.10040.4.1": "DSA",
}
ALG_ALIASES = {
    "rsa": "RSA", "rsaencryption": "RSA", "rsassa-pss": "RSA", "rsa-pss": "RSA",
    "ec": "EC", "ecdsa": "EC", "id-ecpublickey": "EC", "ecc": "EC",
    "ed25519": "ED25519", "ed448": "ED448", "dsa": "DSA", "x25519": "X25519", "x448": "X448",
}
# SEC 2 v2 / FIPS 186-5 / RFC 8422 names for the same curves
CURVES = {"secp256r1": "P-256", "prime256v1": "P-256", "p-256": "P-256", "p256": "P-256", "nistp256": "P-256",
          "secp384r1": "P-384", "p-384": "P-384", "p384": "P-384", "nistp384": "P-384",
          "secp521r1": "P-521", "p-521": "P-521", "p521": "P-521", "nistp521": "P-521",
          "x25519": "X25519", "ed25519": "ED25519"}
VERSIONS = {"tlsv1": "TLSv1", "tls1": "TLSv1", "tls1.0": "TLSv1", "tlsv1.0": "TLSv1", "tls1_0": "TLSv1",
            "tlsv1.1": "TLSv1.1", "tls1.1": "TLSv1.1", "tls1_1": "TLSv1.1",
            "tlsv1.2": "TLSv1.2", "tls1.2": "TLSv1.2", "tls1_2": "TLSv1.2",
            "tlsv1.3": "TLSv1.3", "tls1.3": "TLSv1.3", "tls1_3": "TLSv1.3",
            "sslv3": "SSLv3", "ssl3": "SSLv3", "sslv2": "SSLv2", "ssh2": "SSHv2", "sshv2": "SSHv2", "ssh-2.0": "SSHv2"}
# IANA "TLS Supported Groups": the registry names, with the common OpenSSL spellings mapped onto them
GROUPS = {"prime256v1": "secp256r1", "p-256": "secp256r1", "p256": "secp256r1",
          "p-384": "secp384r1", "p384": "secp384r1", "p-521": "secp521r1", "p521": "secp521r1",
          "x25519mlkem768": "X25519MLKEM768", "secp256r1mlkem768": "SecP256r1MLKEM768",
          "secp384r1mlkem1024": "SecP384r1MLKEM1024", "mlkem512": "MLKEM512", "mlkem768": "MLKEM768",
          "mlkem1024": "MLKEM1024", "x25519": "x25519", "x448": "x448"}
# OpenSSL's names for TLS <= 1.2 suites -> the IANA "TLS Cipher Suites" registry names (OpenSSL ciphers(1) manual,
# "TLS v1.0/v1.2 cipher suites" tables). TLS 1.3 suites already carry their IANA names.
OPENSSL_SUITES = {
    "ECDHE-RSA-AES128-SHA": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "ECDHE-RSA-AES256-SHA": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "ECDHE-ECDSA-AES128-SHA": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "ECDHE-ECDSA-AES256-SHA": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "ECDHE-RSA-AES128-SHA256": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "ECDHE-RSA-AES256-SHA384": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "ECDHE-RSA-CHACHA20-POLY1305": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "AES128-SHA": "TLS_RSA_WITH_AES_128_CBC_SHA", "AES256-SHA": "TLS_RSA_WITH_AES_256_CBC_SHA",
    "AES128-SHA256": "TLS_RSA_WITH_AES_128_CBC_SHA256", "AES256-SHA256": "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "AES128-GCM-SHA256": "TLS_RSA_WITH_AES_128_GCM_SHA256", "AES256-GCM-SHA384": "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "DHE-RSA-AES128-SHA": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "DHE-RSA-AES256-SHA": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    "DHE-RSA-AES128-GCM-SHA256": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "DHE-RSA-AES256-GCM-SHA384": "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "DES-CBC3-SHA": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "ECDHE-RSA-DES-CBC3-SHA": "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "RC4-SHA": "TLS_RSA_WITH_RC4_128_SHA", "RC4-MD5": "TLS_RSA_WITH_RC4_128_MD5",
}


def norm_suites(values: Any) -> list[str] | None:
    if values in (None, ""):
        return None
    if not isinstance(values, list):
        values = [values]
    return sorted({OPENSSL_SUITES.get(str(v).strip(), str(v).strip()) for v in values if v})


# Keys where the product reports a SAMPLE (the negotiated choice plus its probes), not an enumeration: the oracle
# checks that what the product reports is non-empty and accepted by the server (subset), not that it lists them all.
SAMPLED = {"cipher_suites", "groups"}

IMPACT_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, None: 4}


def norm_alg(value: Any) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    if text in NIST_OIDS:
        return NIST_OIDS[text]
    low = text.lower()
    if low in ALG_ALIASES:
        return ALG_ALIASES[low]
    if re.match(r"^(ml-dsa|ml-kem|slh-dsa)", low):
        return text.upper()
    return text.upper()


def norm_curve(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return CURVES.get(str(value).strip().lower(), str(value).strip())


def norm_version(value: Any) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    return VERSIONS.get(text.lower().replace(" ", ""), text)


def norm_versions(values: Any) -> list[str] | None:
    if values in (None, ""):
        return None
    if isinstance(values, dict):  # {"TLSv1.0": true, "TLSv1.3": false}: the versions the server accepted
        values = [k for k, v in values.items() if v is True]
    if isinstance(values, str):
        values = [v for v in re.split(r"[,\s]+", values) if v]
    return sorted({v for v in (norm_version(x) for x in values) if v})


def norm_group(value: Any) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    return GROUPS.get(text.lower(), text)


def norm_groups(values: Any) -> list[str] | None:
    if values in (None, ""):
        return None
    if isinstance(values, str):
        values = [v for v in re.split(r"[,:\s]+", values) if v]
    return sorted({g for g in (norm_group(v) for v in values) if g})


def norm_time(value: Any) -> str | None:
    ts = parse_ts(value)
    return iso(ts) if ts else (None if value in (None, "") else str(value))


def norm_dn(value: Any) -> list[tuple[str, str]] | None:
    """A distinguished name as a sorted multiset of (TYPE, value): order and spacing differ between RFC 4514 writers."""
    if value in (None, ""):
        return None
    parts = re.split(r"(?<!\\)[,/+]", str(value))
    out = []
    for part in parts:
        if "=" not in part:
            continue
        key, _, val = part.partition("=")
        key = {"commonname": "CN", "organizationname": "O", "countryname": "C", "organizationalunitname": "OU",
               "localityname": "L", "stateorprovincename": "ST"}.get(key.strip().lower(), key.strip().upper())
        out.append((key, val.strip().replace("\\,", ",")))
    return sorted(out)


def norm_bool(value: Any) -> bool | None:
    if isinstance(value, bool) or value is None:
        return value
    text = str(value).strip().lower()
    if text in ("true", "t", "1", "yes", "vulnerable"):
        return True
    if text in ("false", "f", "0", "no", "safe"):
        return False
    return None  # "", "unknown", "—"


def norm_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(str(value).strip())
    except ValueError:
        return None


def norm_codes(values: Any) -> list[str]:
    if values in (None, ""):
        return []
    if isinstance(values, str):
        try:
            values = json.loads(values)
        except ValueError:
            values = [values]
    return sorted(str(v) for v in values if isinstance(v, (str, int)))


# RFC 8308 (ext-info-c/-s) and OpenSSH's strict-KEX marker (PROTOCOL, kex-strict-*) are signalling pseudo-algorithms,
# not key exchanges: a server lists them in KEXINIT, an sshd_config does not
SSH_PSEUDO = re.compile(r"^(ext-info-[cs]|kex-strict-[cs]-v00@openssh\.com)$")


def norm_ssh_list(values: Any) -> list[str] | None:
    if values in (None, ""):
        return None
    if isinstance(values, str):
        values = [v for v in values.split(",") if v]
    return sorted({str(v).strip() for v in values if v and not SSH_PSEUDO.match(str(v).strip())})


def _ssh_fp(value: Any) -> str:
    """An SSH key fingerprint as lower-case hex: OpenSSH's "SHA256:<base64>" or plain hex."""
    text = str(value or "").strip()
    if text.upper().startswith("SHA256:"):
        raw = text[7:]
        return base64.b64decode(raw + "=" * (-len(raw) % 4)).hex()
    return re.sub(r"[^0-9a-f]", "", text.lower())


def norm_host_keys(values: Any) -> list[tuple[str, int | None, str]] | None:
    if values in (None, ""):
        return None
    if isinstance(values, dict):
        values = [values]
    out = []
    for v in values:
        if not isinstance(v, dict) or v.get("error"):
            continue
        out.append((str(v.get("type") or v.get("key_type") or ""), norm_int(v.get("bits")),
                    _ssh_fp(v.get("fingerprint_sha256") or v.get("fingerprint"))))
    return sorted(out)


def norm_entries(values: Any) -> list[tuple[str, str, str, int | None]] | None:
    if values in (None, ""):
        return None
    return sorted((str(e.get("alias", "")).lower(), str(e.get("type", "")).lower(),
                   str(norm_alg(e.get("key_algorithm")) or ""), norm_int(e.get("key_bits") or e.get("key_size")))
                  for e in values if isinstance(e, dict))


ORACLE_NORMALISERS: dict[str, Callable[[Any], Any]] = {
    "algorithm": norm_alg, "key_size": norm_int, "curve": norm_curve, "signature_algorithm": lambda v: (
        None if v in (None, "") else str(v).strip().lower().replace("_", "-")),
    "protocol": lambda v: None if v in (None, "") else str(v).strip().lower(),
    "protocol_versions": norm_versions, "groups": norm_groups,
    "cipher_suites": norm_suites,
    "not_before": norm_time, "not_after": norm_time, "subject": norm_dn, "issuer": norm_dn,
    "serial": lambda v: None if v in (None, "") else str(v).lower().lstrip("0") or "0",
    "fingerprint_sha256": lambda v: None if v in (None, "") else re.sub(r"[^0-9a-f]", "", str(v).lower()),
    "quantum_vulnerable": norm_bool, "pqc_class": lambda v: None if v in (None, "") else str(v).strip().lower(),
    "format": lambda v: None if v in (None, "") else str(v).strip().lower(), "path": lambda v: v,
    "kex_algorithms": norm_ssh_list, "host_key_algorithms": norm_ssh_list, "ciphers": norm_ssh_list,
    "macs": norm_ssh_list, "host_keys": norm_host_keys, "entries": norm_entries, "tls_enabled": norm_bool,
}

# ------------------------------------------------------------------------------------------------- view readers
def _facts(item: dict[str, Any]) -> dict[str, Any]:
    facts = item.get("facts")
    if isinstance(facts, str):
        try:
            facts = json.loads(facts) if facts else {}
        except ValueError:
            facts = {}
    return facts if isinstance(facts, dict) else {}


def props(component: dict[str, Any]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for prop in component.get("properties") or []:
        out.setdefault(str(prop.get("name")), []).append(prop.get("value"))
    return out


def _prop(name: str) -> Callable[[dict[str, Any]], Any]:
    def read(component: dict[str, Any]) -> Any:
        values = props(component).get(name)
        return MISSING if values is None else values[0]
    return read


def _crypto(component: dict[str, Any]) -> dict[str, Any]:
    return component.get("cryptoProperties") or {}


def _cert(component: dict[str, Any], key: str) -> Any:
    cert = _crypto(component).get("certificateProperties")
    if cert is None or key not in cert:
        return MISSING
    return cert[key]


def _export_key_size(component: dict[str, Any]) -> Any:
    p = props(component)
    if "zs:key_size" in p:
        return p["zs:key_size"][0]
    crypto = _crypto(component)
    rcm = crypto.get("relatedCryptoMaterialProperties") or {}
    if "size" in rcm:
        return rcm["size"]
    alg = crypto.get("algorithmProperties") or {}
    if "parameterSetIdentifier" in alg:
        return alg["parameterSetIdentifier"]
    return MISSING


def _export_versions(component: dict[str, Any]) -> Any:
    proto = _crypto(component).get("protocolProperties")
    if proto is None or "version" not in proto:
        return MISSING
    return [v for v in str(proto["version"]).split(",") if v]


def _export_ciphers(component: dict[str, Any]) -> Any:
    proto = _crypto(component).get("protocolProperties")
    if proto is None or "cipherSuites" not in proto:
        return MISSING
    return [c.get("name") for c in proto["cipherSuites"]]


def _export_protocol_type(component: dict[str, Any]) -> Any:
    proto = _crypto(component).get("protocolProperties")
    if proto is None or "type" not in proto:
        return MISSING
    return proto["type"]


def protocol_family(value: Any) -> str | None:
    """How the export is allowed to carry the product's protocol (CycloneDX protocolProperties.type)."""
    if value in (None, ""):
        return None
    low = str(value).lower()
    if low.startswith("ssh"):
        return "ssh"
    if "tls" in low or "ssl" in low or low in ("https", "ldaps", "imaps", "pop3s", "smtps", "ftps", "rdp", "tds",
                                                "starttls", "postgres", "mysql"):
        return "tls"
    return "other"


def _versions_of(facts: dict[str, Any], item: dict[str, Any]) -> Any:
    for key in ("protocols", "accepted_versions", "versions"):
        value = facts.get(key)
        if isinstance(value, dict):  # the node's {"TLSv1.0": true, ...}: the versions the server accepted
            return sorted(k for k, v in value.items() if v is True) or None
        if value:
            return value
    banner = str(facts.get("banner") or "")
    if banner.startswith(("SSH-2.0-", "SSH-1.99-")):
        return ["SSHv2"]
    if facts.get("negotiated_version"):
        return [facts["negotiated_version"]]
    return [item["protocol"]] if item.get("protocol") and str(item["protocol"]).lower().startswith(("tls", "ssl")) else None


def _groups_of(facts: dict[str, Any]) -> Any:
    for key in ("groups", "supported_groups", "accepted_groups"):
        if facts.get(key):
            return facts[key]
    return [facts["negotiated_group"]] if facts.get("negotiated_group") else None


def _ciphers_of(facts: dict[str, Any]) -> Any:
    """TLS suites the product saw accepted: its list if it has one, else the negotiated suite plus the suites its
    weak-cipher probes found accepted (``weak_ciphers_accepted``: {"cbc": [...], "static_rsa": [...]})."""
    if facts.get("ciphers"):
        return facts["ciphers"]
    out = [facts[k] for k in ("cipher", "negotiated_cipher") if facts.get(k)][:1]
    weak = facts.get("weak_ciphers_accepted")
    if isinstance(weak, dict):
        out += [c for v in weak.values() if isinstance(v, list) for c in v]
    return sorted(set(out)) or None


def run_verdict(item: dict[str, Any], key: str) -> Any:
    """The run's own verdict for impact/finding/finding_codes: ``as_of_run`` when a date rule changed it since."""
    run = item.get("as_of_run") or None
    return run.get(key) if isinstance(run, dict) else item.get(key)


# field -> view -> reader. A reader returns MISSING when the view does not carry the field at all.
FIELDS: dict[str, dict[str, Callable[[dict[str, Any]], Any]]] = {
    "asset_type": {"api": lambda a: a.get("type"), "db": lambda r: r.get("asset_type"),
                   "export": _prop("zs:asset_type")},
    "location": {"api": lambda a: a.get("location"), "db": lambda r: r.get("location"),
                 "export": _prop("zs:location")},
    "target": {"api": lambda a: a.get("target") or "", "db": lambda r: r.get("target") or "",
               "export": _prop("zs:target")},
    "job_id": {"api": lambda a: a.get("job_id"), "db": lambda r: r.get("job_id"), "export": _prop("zs:job_id")},
    "source": {"api": lambda a: a.get("source_name") or "", "export": _prop("zs:source")},
    "algorithm": {"api": lambda a: a.get("algorithm"), "db": lambda r: r.get("algorithm"),
                  "export": _prop("zs:algorithm")},
    "key_size": {"api": lambda a: a.get("key_size"), "db": lambda r: r.get("key_size"), "export": _export_key_size},
    "protocol": {"api": lambda a: a.get("protocol"), "db": lambda r: r.get("protocol"),
                 "export": _export_protocol_type},
    "quantum_vulnerable": {"api": lambda a: a.get("quantum_vulnerable"), "db": lambda r: r.get("quantum_vulnerable"),
                           "export": _prop("zs:quantum_vulnerable")},
    "impact": {"api": lambda a: a.get("impact"), "db": lambda r: r.get("impact"), "export": _prop("zs:impact")},
    "finding": {"api": lambda a: a.get("finding"), "db": lambda r: r.get("finding"), "export": _prop("zs:finding")},
    "finding_codes": {"api": lambda a: a.get("finding_codes"), "db": lambda r: r.get("finding_codes"),
                      "export": lambda c: props(c).get("zs:finding_code", [])},
    "curve": {"api": lambda a: _first(_facts(a), "curve", "crv"), "db": lambda r: _first(_facts(r), "curve", "crv"),
              "export": _prop("zs:curve")},
    "signature_algorithm": {"api": lambda a: _first(_facts(a), "sig_alg", "signature_alg", "signature_algorithm"),
                            "db": lambda r: _first(_facts(r), "sig_alg", "signature_alg", "signature_algorithm"),
                            "export": _prop("zs:signature_algorithm")},
    "not_before": {"api": lambda a: _facts(a).get("not_before"), "db": lambda r: _facts(r).get("not_before"),
                   "export": lambda c: _cert(c, "notValidBefore")},
    "not_after": {"api": lambda a: _facts(a).get("not_after"), "db": lambda r: _facts(r).get("not_after"),
                  "export": lambda c: _cert(c, "notValidAfter")},
    "subject": {"api": lambda a: _facts(a).get("subject"), "db": lambda r: _facts(r).get("subject"),
                "export": lambda c: _cert(c, "subjectName")},
    "issuer": {"api": lambda a: _facts(a).get("issuer"), "db": lambda r: _facts(r).get("issuer"),
               "export": lambda c: _cert(c, "issuerName")},
    "protocol_versions": {"api": lambda a: _versions_of(_facts(a), a), "db": lambda r: _versions_of(_facts(r), r),
                          "export": _export_versions},
    "cipher_suites": {"api": lambda a: _ciphers_of(_facts(a)), "db": lambda r: _ciphers_of(_facts(r)),
                      "export": _export_ciphers},
    "groups": {"api": lambda a: _groups_of(_facts(a)), "db": lambda r: _groups_of(_facts(r)),
               "export": _prop("zs:groups")},
}


def _first(facts: dict[str, Any], *keys: str) -> Any:
    """The first fact present under any of the names collectors use (CB-06 v1 §2 reads the same aliases)."""
    for key in keys:
        if facts.get(key) not in (None, ""):
            return facts[key]
    return None


def _both(facts: dict[str, Any], *keys: str) -> Any:
    vals = [v for k in keys for v in (facts.get(k) or [])]
    return vals or None


# read from the product for the oracle only: the export has no field for them (CycloneDX 1.6 protocolProperties
# carries no SSH algorithm lists); export completeness for SSH is CB-06's to define
ORACLE_ONLY: dict[str, Callable[[dict[str, Any]], Any]] = {
    "kex_algorithms": lambda a: _facts(a).get("kex"),
    "host_key_algorithms": lambda a: _facts(a).get("host_key_algs"),
    "ciphers": lambda a: _both(_facts(a), "ciphers_s2c", "ciphers_c2s"),
    "macs": lambda a: _both(_facts(a), "macs_s2c", "macs_c2s"),
    "host_keys": lambda a: _facts(a).get("host_keys") or _facts(a).get("host_key"),
    "entries": lambda a: _facts(a).get("entries"),
    "tls_enabled": lambda a: next((_facts(a)[k] for k in ("tls", "ssl", "tls_enabled") if k in _facts(a)), None),
}
# carried by the export for every component whatever the API says (O-7; CB-06 adds them): judged for presence in the
# join, and for value against the oracle (pqc_class)
EXPORT_ALWAYS = {"pqc_class": "zs:pqc_class"}
PROVENANCE_PROPS = ("zs:collector", "zs:node_id", "zs:node_build", "zs:job_id", "zs:attempt", "zs:method",
                    "zs:collected_at", "zs:signed")
# what the DB stores for these is the run's verdict; the API/export show today's (see module doc)
RUN_VERDICT_FIELDS = {"impact", "finding", "finding_codes"}

# how each view's raw value is made comparable with the API's raw value (exact semantics, no oracle normalising)
def _same_scalar(v: Any) -> Any:
    return None if v in (None, "") else str(v)


VIEW_EQ: dict[str, Callable[[Any], Any]] = {
    "key_size": norm_int, "job_id": norm_int, "quantum_vulnerable": norm_bool, "finding_codes": norm_codes,
    "protocol_versions": lambda v: None if v in (None, "", []) else sorted(str(x) for x in (
        v if isinstance(v, list) else str(v).split(","))),
    "cipher_suites": lambda v: None if v in (None, "", []) else sorted(str(x) for x in (
        v if isinstance(v, list) else [v])),
    "groups": lambda v: None if v in (None, "", []) else sorted(str(x) for x in (
        v if isinstance(v, list) else re.split(r"[,\s]+", str(v)))),
    "impact": lambda v: None if v in (None, "", "Info", "none") else str(v),
}


def view_value(field: str, view: str, record: dict[str, Any]) -> Any:
    reader = FIELDS.get(field, {}).get(view)
    if reader is None:
        return MISSING
    return reader(record)


def view_eq(field: str, value: Any) -> Any:
    return VIEW_EQ.get(field, _same_scalar)(value)


# ----------------------------------------------------------------------------------------------------- UI rows
# How the Results table renders an API item (RunResults.tsx): impact badge ("Info" when none), the type label, the
# location (+ target when it differs), "<algorithm or protocol or —>[ <key size>]", the finding, and the quantum text.
# PRODUCT COPY, JOIN-ONLY: TYPE_LABELS and ui_expected transcribe the product's own rendering so the UI <-> API
# self-consistency join can compare cells. They must never feed an oracle value (O-1 covers oracle values); a product
# change to the copy fails the join closed, which is the intent.
TYPE_LABELS = {
    "certificate": "Certificate", "private_key": "Private key", "public_key": "Public key", "keystore": "Keystore",
    "ssh_host_key": "SSH host key", "ssh_server_config": "SSH server config", "ssh_endpoint": "SSH endpoint",
    "tls_endpoint": "TLS endpoint", "crypto_library": "Crypto library", "process_library": "Process library",
    "disk_encryption": "Disk encryption", "os_crypto_policy": "OS crypto policy", "database_tls": "Database TLS",
    "database_config": "Database settings", "database_user_auth": "Database authentication",
    "k8s_cluster": "Kubernetes cluster", "k8s_tls_secret": "Kubernetes TLS secret",
    "k8s_certificate": "cert-manager certificate", "k8s_ingress_tls": "Ingress TLS",
    "k8s_mesh_policy": "Mesh mTLS policy", "kms_key": "KMS key", "cloud_secret": "Cloud secret",
    "host_secret": "Secret in a service or script", "crypto_config": "Crypto configuration",
    "storage_encryption": "Storage encryption", "load_balancer_tls": "Load balancer TLS", "cdn_tls": "CDN TLS",
    "api_tls": "API TLS", "cloud_ca": "Certificate authority", "iam_certificate": "IAM certificate",
    "identity_provider": "Identity provider", "signing_key": "Signing key", "open_port": "Open port",
    "coverage": "Not collected",
}
UI_FIELDS = ("asset_type", "impact", "location", "algorithm_cell", "finding", "quantum_vulnerable")


def ui_expected(field: str, api: dict[str, Any]) -> Any:
    if field == "asset_type":
        return TYPE_LABELS.get(api.get("type"), api.get("type"))
    if field == "impact":
        return api.get("impact") or "Info"
    if field == "location":
        return api.get("location") or "—"
    if field == "algorithm_cell":
        head = api.get("algorithm") or api.get("protocol") or "—"
        return f"{head} {api['key_size']}" if api.get("key_size") else head
    if field == "finding":
        return api.get("finding") or "—"
    if field == "quantum_vulnerable":
        qv = api.get("quantum_vulnerable")
        return "Vulnerable" if qv is True else "Safe" if qv is False else "—"
    raise KeyError(field)


def ui_observed(field: str, row: dict[str, Any]) -> Any:
    if row.get("reader") == ATTR_READER:
        return ui_from_attrs(field, row)
    key = {"asset_type": "type", "algorithm_cell": "algorithm", "quantum_vulnerable": "quantum"}.get(field, field)
    value = row.get(key, MISSING)
    return value.strip() if isinstance(value, str) else value


# CB-38: the unified results page (/{team}/cbom/runs/{run}/results) carries each row's values as data attributes
# (data-impact, -type, -location, -target, -algorithm, -key-size, -finding, -quantum, -status) instead of fixed
# column positions. The gate reads those raw values (``reader: "data-attributes"``); they are rendered here exactly as
# ui_expected renders the API item, so the same cell comparison holds for both readers.
ATTR_READER = "data-attributes"
_ATTR_QUANTUM = {"vulnerable": "Vulnerable", "safe": "Safe"}


def ui_from_attrs(field: str, row: dict[str, Any]) -> Any:
    def raw(key: str) -> Any:
        value = row.get(key, MISSING)
        return value.strip() if isinstance(value, str) else value
    if field == "asset_type":
        t = raw("type")
        return t if t is MISSING else TYPE_LABELS.get(t, t)
    if field == "impact":
        v = raw("impact")
        return v if v is MISSING else (v or "Info")
    if field == "location":
        v = raw("location")
        return v if v is MISSING else (v or "—")
    if field == "algorithm_cell":
        head, size = raw("algorithm"), raw("key_size")
        if head is MISSING:
            return MISSING
        head = head or "—"
        return f"{head} {size}" if size not in (MISSING, None, "") else head
    if field == "finding":
        v = raw("finding")
        return v if v is MISSING else (v or "—")
    if field == "quantum_vulnerable":
        v = raw("quantum")
        return v if v is MISSING else _ATTR_QUANTUM.get(v, "—")
    raise KeyError(field)
