"""Build crypto_kb.json from hand-written text (kb_text.py) and fetched, verified sources.

Inputs:
  kb_text.py                 finding entries, remediation, proof-of-exposure commands (hand-written)
  kb_compliance.py           turns sources/compliance.json into OWASP tables and regulatory references
  sources/nvd_cves.json      NVD API 2.0 records (description, CVSS, CWE, CPE ranges), fetched by nvd_fetch.py
  sources/cna_<CVE>.json     CVE records from cveawg.mitre.org for CVEs NVD has not analysed (CNA ranges)
  sources/cwe_names.json     MITRE CWE names (cwe-api.mitre.org)
  sources/compliance.json    OWASP 2021/2025 categories with mapped CWEs, NIST, CNSA 2.0, CERT-In, SEBI, RBI quotes

The output is deterministic (sorted keys, no timestamps besides the version you pass) so the file can be diffed and
signed. The build fails on any reference that is not backed by a source file.
Usage: python build_kb.py <version> <out.json>   (see README.md; the version must sort after the shipped one)
"""
from __future__ import annotations

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import kb_compliance  # noqa: E402
import kb_text  # noqa: E402
import importlib  # noqa: E402

# Extension modules (kb_ext/<area>.py) register their entries with kb_text.entry() at import and may export
# NODE_CODES / CODE_CODES lists. One module per feature area keeps parallel work from editing the same lines.
_EXT_DIR = os.path.join(HERE, "kb_ext")
EXT_NODE_CODES: list[str] = []
EXT_CODE_CODES: list[str] = []
if os.path.isdir(_EXT_DIR):
    sys.path.insert(0, _EXT_DIR)
    for _name in sorted(f[:-3] for f in os.listdir(_EXT_DIR) if f.endswith(".py") and not f.startswith("_")):
        _mod = importlib.import_module(_name)
        EXT_NODE_CODES += list(getattr(_mod, "NODE_CODES", ()))
        EXT_CODE_CODES += list(getattr(_mod, "CODE_CODES", ()))

SRC = os.path.join(HERE, "sources")
NVD = json.load(open(os.path.join(SRC, "nvd_cves.json")))
CWE = json.load(open(os.path.join(SRC, "cwe_names.json")))
RESEARCH = os.path.join(SRC, "compliance.json")

# OWASP Top 10:2021 labels exactly as the product's enum spells them (RabbitMQ/worker/helpers/context/enums.py).
OWASP_2021 = {
    "access": ("BROKEN_ACCESS_CONTROL", "A01:2021 - Broken Access Control"),
    "crypto": ("CRYPTOGRAPHIC_FAILURES", "A02:2021 - Cryptographic Failures"),
    "misconfig": ("SECURITY_MISCONFIGURATION", "A05:2021 - Security Misconfiguration"),
    "components": ("VULNERABLE_AND_OUTDATED_COMPONENTS", "A06:2021 - Vulnerable and Outdated Components"),
    "auth": ("IDENTIFICATION_AND_AUTHENTICATION_FAILURES", "A07:2021 - Identification and Authentication Failures"),
    "integrity": ("SOFTWARE_AND_DATA_INTEGRITY_FAILURES", "A08:2021 - Software and Data Integrity Failures"),
}
# Legacy per-row compliance_controls the code-scan dashboard aggregates (enum name -> display label).
LEGACY_CONTROLS = {
    "crypto": {"ISO27001_A10_CRYPTOGRAPHY": "ISO 27001 - A.10 Cryptography",
               "NIST80053_SC": "NIST 800-53 - System and Communications Protection"},
    "misconfig": {"NIST80053_CM": "NIST 800-53 - Configuration Management"},
    "access": {"ISO27001_A9_ACCESS_CONTROL": "ISO 27001 - A.9 Access Control", "NIST80053_AC": "NIST 800-53 - Access Control"},
    "auth": {"NIST80053_IA": "NIST 800-53 - Identification and Authentication"},
    "components": {"NIST80053_SI": "NIST 800-53 - System and Information Integrity"},
    "integrity": {"NIST80053_SI": "NIST 800-53 - System and Information Integrity"},
}

# Codes the server-side classifier emits for scan-node runs (backend/utilities/cbom_sources/classify.py).
NODE_CODES = """PROTO_SSLv2 PROTO_SSLv3 PROTO_TLS10 PROTO_TLS11 MIN_SSLv2 MIN_SSLv3 MIN_TLS10 MIN_TLS11 NO_TLS12 WEAK_CIPHER
STATIC_RSA_KEX CBC_ONLY CBC_ACCEPTED DOWNGRADE NO_FALLBACK_SCSV NO_TLS NO_PQ_KEX PLAINTEXT_LISTENER CERT_EXPIRED
CERT_EXPIRES_30D CERT_SELF_SIGNED CERT_UNUSED SIG_MD5 SIG_SHA1 RSA_LT_1024 RSA_LT_2048 EC_LT_224 DH_LT_2048 DSA
KEY_WORLD_READABLE KEY_READABLE KEY_IN_DOCUMENT KEY_IN_CONFIGMAP KEYSTORE_JKS SSH_WEAK_CIPHER SSH_CBC_CIPHER SSH_WEAK_MAC
SSH_UMAC64 SSH_DH_GROUP1 SSH_DH_SHA1 SSH_DSS SSH_RSA_SHA1 SSH_HMAC_SHA1 SSH_NO_PQ_KEX DB_TRUST DB_NO_AUTH DB_WEAK_HASH
DB_MD5_DEFAULT DB_CLEARTEXT_PW DB_NATIVE_PW DB_OLD_PASSWORD DB_NO_TDE DB_NO_TLS DB_TLS_OPTIONAL DB_TLS_MODE
DISK_UNENCRYPTED DISK_CBC DISK_XTS_128 LUKS1 DISK_PROTECTION_OFF LIB_EOL LIB_DELETED_IN_USE LIB_STATIC LIB_KNOWN_CVE
POLICY_LEGACY DOTNET_WEAK_TLS SECRET_IN_CONFIG TLS_POLICY_OVERRIDE OPENSSL_ENC_WEAK_KDF KMS_NO_ROTATION KMS_PENDING_DELETION SECRET_NO_ROTATION SECRET_PLAINTEXT_PARAM STORAGE_UNENCRYPTED STORAGE_NO_TLS_ONLY
EBS_DEFAULT_OFF SAML_METADATA_UNSIGNED MESH_MTLS_OFF MESH_MTLS_PERMISSIVE QUANTUM_VULNERABLE RDP_NO_TLS RDP_NO_NLA""".split()
# Codes the code-scan engine (aibom) emits, including the posture catalog.
CODE_CODES = """WEAK_ALGORITHM WEAK_KEY_SIZE WEAK_CIPHER_MODE WEAK_PADDING WEAK_RNG STATIC_IV REUSED_NONCE HARDCODED_KEY
WEAK_PROTOCOL WEAK_CIPHER_SUITE WEAK_CERTIFICATE_KEY WEAK_CERTIFICATE_SIGNATURE SELF_SIGNED_LEAF EXPIRED_CERTIFICATE
CERT_NEAR_EXPIRY CUSTOM_CRYPTO QUANTUM_VULNERABLE VULNERABLE_CRYPTO_LIBRARY KMS_KEY_ROTATION_DISABLED
KMS_KEY_DELETION_UNPROTECTED KMS_KEY_POLICY_PUBLIC UNENCRYPTED_AT_REST UNENCRYPTED_IN_TRANSIT PLAINTEXT_LISTENER
TLS_VERIFICATION_DISABLED DOWNGRADE_PROTECTION_MISSING KNOWN_TLS_VULNERABILITY AT_REST_ENCRYPTION_WEAK""".split()
NODE_CODES += [c for c in EXT_NODE_CODES if c not in NODE_CODES]
CODE_CODES += [c for c in EXT_CODE_CODES if c not in CODE_CODES]

# Same code, different meaning in source code: override the parts that differ.
CODE_OVERRIDES = {
    "PLAINTEXT_LISTENER": {
        "title": "Plaintext listener declared in configuration",
        "description": "A server or service configuration declares a listener without TLS (for example `listen 80` without a redirect, or a plaintext broker port).",
        "verify": [{"label": "Show the listener", "command": "grep -n -i 'listen\\|port' '{path}'"}],
    },
    "KMS_KEY_ROTATION_DISABLED": {
        "title": "KMS key rotation off in infrastructure code",
        "description": "Infrastructure code declares a customer-managed symmetric KMS key without automatic rotation (enable_key_rotation missing or false).",
        "remediation": {"summary": "Set enable_key_rotation = true on the aws_kms_key (or EnableKeyRotation: true in CloudFormation).", "steps": []},
        "verify": [{"label": "Show the key definition", "command": "grep -n -i 'enable_key_rotation\\|EnableKeyRotation' '{path}'"}],
    },
    "QUANTUM_VULNERABLE": {"verify": [{"label": "Show the call site", "command": "grep -n -i '{name}' '{path}'"}]},
    "DOWNGRADE_PROTECTION_MISSING": {"verify": [{"label": "Re-run the downgrade check", "command": "testssl.sh --fallback {host}:{port}"}]},
}

# OpenSSL upstream end-of-life dates (openssl-library.org/policies/releasestrat and endoflife.date/openssl, checked
# 2026-10-31). Branch -> date the upstream project stops fixing it.
OPENSSL_EOL = {"0.9.8": "2015-12-31", "1.0.0": "2015-12-31", "1.0.1": "2016-12-31", "1.0.2": "2019-12-31",
               "1.1.0": "2019-09-11", "1.1.1": "2023-09-11", "3.0": "2026-09-07", "3.1": "2025-03-14",
               "3.2": "2025-11-23", "3.3": "2026-04-09", "3.4": "2026-10-22", "3.5": "2030-04-08", "3.6": "2026-11-01",
               "4.0": "2027-05-14", "4.1": "2027-11-23"}
EOL_SOURCES = ["https://openssl-library.org/policies/releasestrat/index.html", "https://endoflife.date/openssl"]

# Package names (dpkg / rpm) per upstream library.
LIBRARY_PACKAGES = {
    "openssl": ["openssl", "libssl3", "libssl3t64", "libssl1.1", "libssl1.0.0", "libssl1.0.2", "openssl-libs",
                "openssl1.1", "compat-openssl11", "compat-openssl10", "libcrypto3", "libssl"],
    "openssh": ["openssh-server", "openssh-client", "openssh", "openssh-clients"],
    "gnutls": ["gnutls", "libgnutls30", "libgnutls30t64", "libgnutls28", "gnutls-utils"],
    "libgcrypt": ["libgcrypt", "libgcrypt20", "libgcrypt11"],
}
CNA_PRODUCT = {"openssl": ("OpenSSL", "OpenSSL")}
CPE_PRODUCT = {"openssl": "openssl:openssl", "openssh": "openbsd:openssh", "gnutls": "gnu:gnutls",
               "libgcrypt": "gnupg:libgcrypt"}


def fail(msg: str) -> None:
    raise SystemExit(f"KB build failed: {msg}")


def cve_record(cid: str) -> dict:
    rec = NVD.get(cid)
    if rec is None:
        fail(f"{cid} is not in nvd_cves.json")
    cvss = rec.get("cvss") or {}
    return {"id": cid, "published": rec.get("published"), "summary": rec["description"].strip(),
            "cvss": {"version": cvss.get("version"), "score": cvss.get("score"), "vector": cvss.get("vector"),
                     "severity": cvss.get("severity")} if cvss else None,
            "cwe": [c for c in rec.get("cwe") or [] if c.startswith("CWE-")],
            "url": f"https://nvd.nist.gov/vuln/detail/{cid}"}


def library_rules() -> dict:
    out: dict[str, dict] = {}
    for lib, product in CPE_PRODUCT.items():
        ranges = []
        for cid in sorted(NVD):
            for cpe in NVD[cid].get("cpes") or []:
                crit = cpe.get("criteria", "")
                if f":a:{product}:" not in crit:
                    continue
                parts = crit.split(":")
                version, update = parts[5], parts[6]
                rng = {k: cpe[k] for k in ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding",
                                            "versionEndExcluding") if cpe.get(k)}
                if version not in ("*", "-"):
                    if re.search(r"\.el\d|ubuntu|deb", version):
                        continue  # a vendor build pinned by NVD, not an upstream version
                    rng = {"exact": version + (update if update not in ("*", "-") and update.startswith("p") else "")}
                if not rng:
                    continue
                ranges.append({"cve": cid, **rng})
        # CVEs NVD has not analysed yet: use the affected ranges the CNA (the library project) published in the
        # CVE record itself, fetched from cveawg.mitre.org into cna_<id>.json.
        nvd_covered = {r["cve"] for r in ranges}
        for fname in sorted(os.listdir(SRC)):
            if not (fname.startswith("cna_") and fname.endswith(".json")):
                continue
            rec = json.load(open(os.path.join(SRC, fname)))
            cid = rec["cveMetadata"]["cveId"]
            if cid in nvd_covered or cid not in NVD:
                continue
            for aff in rec["containers"]["cna"].get("affected") or []:
                if CNA_PRODUCT.get(lib) != (aff.get("vendor"), aff.get("product")) and \
                        CNA_PRODUCT.get(lib, (None, None))[1] != aff.get("product"):
                    continue
                for v in aff.get("versions") or []:
                    if v.get("status") == "affected" and v.get("version") and v.get("lessThan"):
                        ranges.append({"cve": cid, "versionStartIncluding": v["version"],
                                       "versionEndExcluding": v["lessThan"], "source": "cna"})
        out[lib] = {"packages": LIBRARY_PACKAGES[lib], "cpe": product, "ranges": ranges}
    out["openssl"]["eol"] = OPENSSL_EOL
    out["openssl"]["eol_sources"] = EOL_SOURCES
    return out


def load_research() -> dict | None:
    if not os.path.exists(RESEARCH):
        return None
    return json.load(open(RESEARCH))


def build(version: str) -> dict:
    research = load_research()
    entries = kb_text.E
    for code in set(NODE_CODES) | set(CODE_CODES):
        if code not in entries:
            fail(f"no entry for {code}")
    used_cves: set[str] = set()
    used_cwes: set[str] = set()

    def finish(code: str, raw: dict, override: dict | None = None) -> dict:
        e = {**raw, **(override or {})}
        for key in ("title", "category", "default_impact", "description", "attack", "cwe", "owasp", "remediation",
                    "verify"):
            if key not in e:
                fail(f"{code} misses {key}")
        if e["default_impact"] not in ("Critical", "High", "Medium", "Low"):
            fail(f"{code} impact {e['default_impact']}")
        for cwe in e["cwe"]:
            if cwe not in CWE:
                fail(f"{code}: {cwe} has no verified name")
            used_cwes.add(cwe)
        cves = list(e.get("cves") or [])
        for rule in e.get("summary_rules") or []:
            re.compile(rule["match"])
            if not rule.get("summary") or set(rule) - {"match", "summary", "steps"}:
                fail(f"{code}: summary rule {rule.get('match')} needs a summary and only match/summary/steps")
            for step in rule.get("steps") or []:
                if set(step) != {"platform", "how"}:
                    fail(f"{code}: summary rule step {step} needs platform and how")
        for rule in e.get("cve_rules") or []:
            re.compile(rule["match"])
            cves += rule["cves"]
        for cid in cves:
            cve_record(cid)
            used_cves.add(cid)
        for tag in e["owasp"]:
            if tag not in OWASP_2021:
                fail(f"{code}: unknown OWASP tag {tag}")
        for cmd in e["verify"]:
            if set(cmd) != {"label", "command"}:
                fail(f"{code}: verify entry keys {sorted(cmd)}")
            for ph in re.findall(r"\{(\w+)\}", cmd["command"]):
                if ph not in ("host", "port", "path", "name", "location", "resource", "line"):
                    fail(f"{code}: unknown placeholder {ph}")
        return {
            "title": e["title"], "category": e["category"], "default_impact": e["default_impact"],
            "description": e["description"], "attack": e["attack"], "cwe": e["cwe"],
            "owasp": e["owasp"], "cves": e.get("cves") or [], "cve_rules": e.get("cve_rules") or [],
            "pqc": e.get("pqc"), "standards": e.get("standards") or [], "compliance": e.get("compliance") or [],
            "remediation": {"summary": e["remediation"]["summary"], "steps": e["remediation"].get("steps") or []},
            "summary_rules": e.get("summary_rules") or [],
            "verify": e["verify"], "references": e.get("references") or [],
        }

    node = {code: finish(code, entries[code]) for code in sorted(NODE_CODES)}
    code_ns = {code: finish(code, entries[code], CODE_OVERRIDES.get(code)) for code in sorted(CODE_CODES)}

    if not research:
        fail("research/compliance.json is required (OWASP mapped CWEs and regulatory references)")
    owasp_tables = kb_compliance.owasp_tables(research)
    compliance = kb_compliance.refs(research)
    for section in (node, code_ns):
        for code, e in section.items():
            e["owasp_2021"] = _owasp(e, owasp_tables["2021"], kb_compliance.TAG_2021)
            e["owasp_2025"] = _owasp(e, owasp_tables["2025"], kb_compliance.TAG_2025)
            for key in e["compliance"]:
                if key not in compliance:
                    fail(f"{code}: unknown compliance key {key}")
    owasp = {year: {k: {"id": v["id"], "name": v["name"], "label": v["label"], "source": v["source"]}
                    for k, v in table.items()} for year, table in owasp_tables.items()}
    sources: dict = {
        "cve": "NVD CVE API 2.0 (services.nvd.nist.gov/rest/json/cves/2.0), fetched 2026-10-31",
        "cwe": "MITRE CWE REST API (cwe-api.mitre.org), fetched 2026-10-31",
        "openssl_eol": EOL_SOURCES,
        "owasp": "Category pages and their 'List of Mapped CWEs' on top10.owasp.org (2021 and 2025), fetched 2026-10-31",
        "compliance": "Clause text quoted from the primary documents linked on each reference, fetched 2026-10-31",
    }
    return {
        "schema": 1,
        "kb_version": version,
        "sources": sources,
        "owasp": owasp,
        "legacy_controls": LEGACY_CONTROLS,
        "cwe": {c: CWE[c] for c in sorted(used_cwes)},
        "cves": {c: cve_record(c) for c in sorted(used_cves | lib_cves())},
        "findings": {"node": node, "code": code_ns},
        "libraries": library_rules(),
        "compliance": compliance,
        "pqc_context": kb_compliance.pqc_context(research),
    }


def _owasp(entry: dict, table: dict, tag_ids: dict) -> list[dict]:
    """Categories whose official mapped-CWE list holds one of the entry's CWEs, then the entry's own category tags."""
    out: list[dict] = []
    for cid, row in sorted(table.items()):
        hits = [c for c in entry["cwe"] if c in row["mapped_cwes"]]
        if hits:
            out.append({"id": cid, "label": row["label"], "basis": f"{', '.join(hits)} is in OWASP's mapped CWE list"})
    for tag in entry["owasp"]:
        cid = tag_ids[tag]
        if all(o["id"] != cid for o in out):
            out.append({"id": cid, "label": table[cid]["label"], "basis": "category of the finding"})
    return out


def lib_cves() -> set[str]:
    return {r["cve"] for lib in library_rules().values() for r in lib["ranges"]}


if __name__ == "__main__":
    version, out = sys.argv[1], sys.argv[2]
    kb = build(version)
    text = json.dumps(kb, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(text)
    n = len(kb["findings"]["node"]) + len(kb["findings"]["code"])
    print(f"wrote {out}: {n} entries, {len(kb['cves'])} CVEs, {len(kb['cwe'])} CWEs, {len(text)} bytes")
    for lib, rules in kb["libraries"].items():
        print(f"  {lib}: {len(rules['ranges'])} version ranges")
