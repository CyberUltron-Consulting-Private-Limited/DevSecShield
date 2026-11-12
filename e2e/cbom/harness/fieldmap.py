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


ORACLE_NORMALISERS: dict[str, Callable[[Any], Any]] = {
    "algorithm": norm_alg, "key_size": norm_int, "curve": norm_curve, "signature_algorithm": lambda v: (
        None if v in (None, "") else str(v).strip().lower().replace("_", "-")),
    "protocol": lambda v: None if v in (None, "") else str(v).strip().lower(),
    "protocol_versions": norm_versions, "groups": norm_groups,
    "cipher_suites": lambda v: None if v in (None, "") else sorted(str(x) for x in (v if isinstance(v, list) else [v])),
    "not_before": norm_time, "not_after": norm_time, "subject": norm_dn, "issuer": norm_dn,
    "serial": lambda v: None if v in (None, "") else str(v).lower().lstrip("0") or "0",
    "fingerprint_sha256": lambda v: None if v in (None, "") else re.sub(r"[^0-9a-f]", "", str(v).lower()),
    "quantum_vulnerable": norm_bool, "pqc_class": lambda v: None if v in (None, "") else str(v).strip().lower(),
    "format": lambda v: None if v in (None, "") else str(v).strip().lower(), "path": lambda v: v,
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
        if facts.get(key):
            return facts[key]
    if facts.get("negotiated_version"):
        return [facts["negotiated_version"]]
    return [item["protocol"]] if item.get("protocol") and str(item["protocol"]).lower().startswith(("tls", "ssl")) else None


def _groups_of(facts: dict[str, Any]) -> Any:
    for key in ("groups", "supported_groups", "accepted_groups"):
        if facts.get(key):
            return facts[key]
    return [facts["negotiated_group"]] if facts.get("negotiated_group") else None


def _ciphers_of(facts: dict[str, Any]) -> Any:
    if facts.get("ciphers"):
        return facts["ciphers"]
    for key in ("cipher", "negotiated_cipher"):
        if facts.get(key):
            return [facts[key]]
    return None


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
    "curve": {"api": lambda a: _facts(a).get("curve"), "db": lambda r: _facts(r).get("curve"),
              "export": _prop("zs:curve")},
    "signature_algorithm": {"api": lambda a: _facts(a).get("sig_alg"), "db": lambda r: _facts(r).get("sig_alg"),
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
    key = {"asset_type": "type", "algorithm_cell": "algorithm", "quantum_vulnerable": "quantum"}.get(field, field)
    value = row.get(key, MISSING)
    return value.strip() if isinstance(value, str) else value
