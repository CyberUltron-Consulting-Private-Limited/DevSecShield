"""#269: the compliance mapping cites, for each finding, only the clauses that finding breaks.

Before #269 every finding code mapped to a whole compliance *area* (``"SSH_CBC_CIPHER": ["algorithms"]``) and
inherited every clause of it, so a CBC cipher, a SHA-1 key exchange and HMAC-SHA1 were cited under NIST "PKCS#1 v1.5
padding disallowed", "three-key TDEA disallowed" and "SHA-1 signature generation disallowed". Now each code carries
its own clauses, and clauses that depend on the algorithm (TDEA, SHA-1 signatures, PKCS#1 v1.5, 112-bit) are added
only when the asset's evidence names it.

``ALLOW`` is the reviewed allow-list: for every knowledge-base finding code, the only clauses it may ever be cited
under (with any evidence). It was generated once from the clause table and reviewed against each clause's text; a new
code fails ``test_allow_list_names_every_kb_code`` until someone reviews it here. The title guards below re-check the
three clauses #269 names independently of the list.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from backend.utilities.cbom_sources import crypto_kb

# clause aliases -> (framework, clause id) exactly as the knowledge base and the results page show them
NIST_SHA1_SIG = ("NIST", "SP 800-131A Rev. 2, Sec. 9 Table 8 (SHA-1)")
NIST_TDEA = ("NIST", "SP 800-131A Rev. 2, Sec. 2 Table 1 (TDEA)")
NIST_PKCS1 = ("NIST", "SP 800-131A Rev. 2, Sec. 6 Table 5")
NIST_112 = ("NIST", "SP 800-131A Rev. 2, Tables 2, 4, 5 (below 112-bit security)")
NIST_IR8547 = ("NIST", "IR 8547 (final, 2026)")
CNSA2 = ("NSA CNSA 2.0", "CNSA 2.0 FAQ (April 2024)")
CERTIN_8422 = ("CERT-In", "BOM Guidelines v2.0, 8.4.2.2")
CERTIN_8416 = ("CERT-In", "BOM Guidelines v2.0, 8.4.1.6")
CERTIN_851 = ("CERT-In", "BOM Guidelines v2.0, 8.5.1")
CERTIN_617 = ("CERT-In", "Guidelines for Government Entities (2023), 6.1.7")
CERTIN_627 = ("CERT-In", "Guidelines for Government Entities (2023), 6.2.7")
CERTIN_71 = ("CERT-In", "Guidelines for Government Entities (2023), 7.1")
CERTIN_457 = ("CERT-In", "Guidelines for Government Entities (2023), 4.5.7")
RBI_16 = ("RBI", "Master Direction on IT Governance (2023), para 16 Cryptographic controls")
RBI_140 = ("RBI", "Commercial Banks Cybersecurity Directions 2026, para 140")
RBI_106 = ("RBI", "Commercial Banks Cybersecurity Directions 2026, para 106")
# FIX-A3: NBFCs (RBI NBFC Directions 2026 para 118, cryptographic controls; transmission channels, not data at rest)
RBI_118 = ("RBI", "NBFC Cybersecurity, Technology: Risk, Resilience and Assurance Framework Directions 2026, para 118")
SEBI_PRDS1 = ("SEBI CSCRF", "PR.DS Standard 1")
SEBI_PRDS_1A = ("SEBI CSCRF", "PR.DS.S1-S3 guideline 1.a")
SEBI_S4_5 = ("SEBI CSCRF", "PR.DS.S4 item 5")
SEBI_H5 = ("SEBI CSCRF", "Annexure-H item 5")
SEBI_I = ("SEBI CSCRF", "Annexure-I Data Transport Security")
SEBI_BOX7 = ("SEBI CSCRF", "Box Item 7: Cybersecurity and Quantum Computing")
SEBI_RA2 = ("SEBI CSCRF", "ID.RA Standard 2")

ALLOW: dict[str, dict[str, set[tuple[str, str]]]] = {
    "node": {
        "CA_ALLOWS_ANY_NAME": set(),
        "CA_ALLOWS_WEAK_KEY": {NIST_112, RBI_140, RBI_16, RBI_118},
        "CA_LONG_VALIDITY": set(),
        "CA_TEMPLATE_WRITABLE": set(),
        "CA_WEAK_SIGNING": {CERTIN_8422, NIST_SHA1_SIG, RBI_140, RBI_16, RBI_118},
        "CBC_ACCEPTED": {CERTIN_8422, RBI_140, RBI_16, RBI_118},
        "CBC_ONLY": {CERTIN_8422, RBI_140, RBI_16, RBI_118},
        "CERT_EXPIRED": {CERTIN_617, SEBI_S4_5},
        "CERT_CHAIN_EXTRA_EXPIRED": set(),
        "CERT_EXPIRES_30D": {SEBI_S4_5},
        "CERT_NOT_YET_VALID": {CERTIN_617},
        "CERT_REVOKED": {CERTIN_617},
        "CERT_SELF_SHA1": set(),
        "CERT_SELF_SIGNED": {CERTIN_617},
        "CERT_UNEXPECTED_CA": set(),
        "CERT_UNUSED": set(),
        "CHAIN_INCOMPLETE": {CERTIN_8422},
        "CERT_WILDCARD_SPRAWL": set(),
        "DB_10G_VERIFIER": {RBI_140, RBI_16, RBI_118},
        "DB_CLEARTEXT_PW": {CERTIN_627, RBI_106, SEBI_I, SEBI_PRDS1, RBI_118},
        "DB_EOL_VERSION": set(),
        "DB_LEGACY_NNE": {CERTIN_627},
        "DB_LEGACY_PW_HASH": {RBI_140, RBI_16, RBI_118},
        "DB_LOGIN_NO_POLICY": set(),
        "DB_MD5_ACCEPTED": {RBI_140, RBI_16, RBI_118},
        "DB_MD5_DEFAULT": {RBI_140, RBI_16, RBI_118},
        "DB_NATIVE_PW": {RBI_140, RBI_16, RBI_118},
        "DB_NO_AUTH": set(),
        "DB_NO_TDE": set(),
        "DB_NO_TLS": {CERTIN_627, RBI_106, SEBI_I, SEBI_PRDS1, RBI_118},
        "DB_OLD_PASSWORD": {RBI_140, RBI_16, RBI_118},
        "DB_PLAINTEXT_PW": {CERTIN_71, RBI_106, SEBI_PRDS1, SEBI_PRDS_1A},
        "DB_TDE_OFF": set(),
        "DB_TLS_MODE": {CERTIN_627, RBI_106, SEBI_I, SEBI_PRDS1, RBI_118},
        "DB_TLS_OPTIONAL": {CERTIN_627, RBI_106, SEBI_I, SEBI_PRDS1, RBI_118},
        "DB_TRUST": set(),
        "DB_WEAK_HASH": {RBI_140, RBI_16, RBI_118},
        "DH_LT_2048": {NIST_112, RBI_140, RBI_16, RBI_118},
        "DISK_CBC": set(),
        "DISK_PROTECTION_OFF": {CERTIN_71, RBI_106, SEBI_PRDS1, SEBI_PRDS_1A},
        "DISK_UNENCRYPTED": {CERTIN_71, RBI_106, SEBI_PRDS1, SEBI_PRDS_1A},
        "DISK_XTS_128": {CNSA2},
        "DOTNET_WEAK_TLS": {CERTIN_8422, RBI_140, RBI_16, SEBI_I, RBI_118},
        "DOWNGRADE": {CERTIN_8422},
        "DSA": {RBI_140, RBI_16, RBI_118},
        "EBS_DEFAULT_OFF": set(),
        "EC_LT_224": {NIST_112, RBI_140, RBI_16, RBI_118},
        "GLUE_CATALOG_UNENCRYPTED": {CERTIN_71, RBI_106, SEBI_PRDS1, SEBI_PRDS_1A},
        "GLUE_JDBC_NO_TLS": {CERTIN_627, RBI_106, SEBI_I, SEBI_PRDS1, RBI_118},
        "GLUE_PLAINTEXT_PASSWORD": {CERTIN_71, RBI_106, SEBI_PRDS1, SEBI_PRDS_1A},
        "IKEV1_ENABLED": {CERTIN_8422, RBI_140, RBI_16, RBI_118},
        "IKE_AGGRESSIVE": {CERTIN_8422, RBI_140, RBI_16, RBI_118},
        "IKE_NO_PQ": {CERTIN_851, CNSA2, NIST_IR8547, SEBI_BOX7, SEBI_RA2},
        "IKE_WEAK_DH": {CERTIN_8422, NIST_112, RBI_140, RBI_16, RBI_118},
        "IKE_WEAK_ENCR": {CERTIN_8422, NIST_TDEA, RBI_140, RBI_16, SEBI_H5, RBI_118},
        "IKE_WEAK_INTEG": {CERTIN_8422, RBI_140, RBI_16, RBI_118},
        "IPSEC_WEAK_TRANSFORM": {CERTIN_8422, NIST_112, NIST_TDEA, RBI_140, RBI_16, SEBI_H5, RBI_118},
        "KEYSTORE_JKS": {SEBI_H5},
        "KEY_COMPROMISED": set(),
        "KEY_EXTRACTABLE": {SEBI_H5},
        "KEY_IN_CONFIGMAP": {SEBI_H5},
        "KEY_IN_DOCUMENT": {SEBI_H5},
        "KEY_NO_ROTATION": set(),
        "KEY_PLAINTEXT_EXPORT": {SEBI_H5},
        "KEY_READABLE": {SEBI_H5},
        "KEY_WEAK_SYMMETRIC": {NIST_TDEA, RBI_140, RBI_16, SEBI_H5, RBI_118},
        "KEY_WORLD_READABLE": {SEBI_H5},
        "KMS_KEY_MATERIAL_EXPIRES": set(),
        "KMS_KEY_NO_MATERIAL": set(),
        "KMS_NO_ROTATION": set(),
        "KMS_PENDING_DELETION": set(),
        "KV_NO_PURGE_PROTECTION": set(),
        "KV_PUBLIC_NETWORK": set(),
        "KV_SOFT_DELETE_OFF": set(),
        "LIB_DELETED_IN_USE": set(),
        "LIB_EOL": set(),
        "LIB_KNOWN_CVE": {CERTIN_8416},
        "LIB_STATIC": set(),
        "LINKERD_UNAUTHENTICATED_SERVER": {CERTIN_627, RBI_106, SEBI_I, SEBI_PRDS1, RBI_118},
        "LUKS1": set(),
        "MESH_DR_TLS_DISABLED": {CERTIN_627, RBI_106, SEBI_I, SEBI_PRDS1, RBI_118},
        "MESH_MTLS_OFF": {CERTIN_627, RBI_106, SEBI_I, SEBI_PRDS1, RBI_118},
        "MESH_MTLS_PERMISSIVE": {CERTIN_627, RBI_106, SEBI_I, SEBI_PRDS1, RBI_118},
        "MIN_SSLv2": {CERTIN_8422, RBI_140, RBI_16, SEBI_I, RBI_118},
        "MIN_SSLv3": {CERTIN_8422, RBI_140, RBI_16, SEBI_I, RBI_118},
        "MIN_TLS10": {CERTIN_8422, RBI_140, RBI_16, SEBI_I, RBI_118},
        "MIN_TLS11": {CERTIN_8422, RBI_140, RBI_16, SEBI_I, RBI_118},
        "MODBUS_PLAINTEXT": {CERTIN_627, RBI_106, SEBI_I, SEBI_PRDS1, RBI_118},
        "NO_FALLBACK_SCSV": {CERTIN_8422},
        "NO_PQ_KEX": {CERTIN_851, CNSA2, NIST_IR8547, SEBI_BOX7, SEBI_RA2},
        "NO_TLS": {CERTIN_627, RBI_106, SEBI_I, SEBI_PRDS1, RBI_118},
        "NO_TLS12": {CERTIN_8422, RBI_140, RBI_16, SEBI_I, RBI_118},
        "OPCUA_ANON": set(),
        "OPCUA_DEPRECATED_POLICY": {CERTIN_8422, NIST_PKCS1, NIST_SHA1_SIG, RBI_140, RBI_16, RBI_118},
        "OPCUA_NONE_POLICY": {CERTIN_627, RBI_106, SEBI_I, SEBI_PRDS1, RBI_118},
        "OPCUA_USERNAME_PLAINTEXT": {CERTIN_627, RBI_106, SEBI_I, SEBI_PRDS1, RBI_118},
        "OPENSSL_ENC_WEAK_KDF": {RBI_140, RBI_16, RBI_118},
        "PLAINTEXT_LISTENER": {CERTIN_627, RBI_106, SEBI_I, SEBI_PRDS1, RBI_118},
        "POLICY_LEGACY": {CERTIN_8422, NIST_SHA1_SIG, RBI_140, RBI_16, RBI_118},
        "PROTO_SSLv2": {CERTIN_8422, RBI_140, RBI_16, SEBI_I, RBI_118},
        "PROTO_SSLv3": {CERTIN_8422, RBI_140, RBI_16, SEBI_I, RBI_118},
        "PROTO_TLS10": {CERTIN_8422, RBI_140, RBI_16, SEBI_I, RBI_118},
        "PROTO_TLS11": {CERTIN_8422, RBI_140, RBI_16, SEBI_I, RBI_118},
        "QUANTUM_VULNERABLE": {CERTIN_851, CNSA2, NIST_IR8547, SEBI_BOX7, SEBI_RA2},
        "RDP_NO_NLA": set(),
        "RDP_NO_TLS": {CERTIN_457, CERTIN_627, RBI_106, SEBI_I, SEBI_PRDS1, RBI_118},
        "RSA_LT_1024": {NIST_112, RBI_140, RBI_16, RBI_118},
        "RSA_LT_2048": {NIST_112, RBI_140, RBI_16, RBI_118},
        "SAML_METADATA_UNSIGNED": set(),
        "SECRET_IN_CONFIG": {SEBI_H5},
        "SECRET_NO_ROTATION": set(),
        "SECRET_PLAINTEXT_PARAM": {CERTIN_71, RBI_106, SEBI_PRDS1, SEBI_PRDS_1A},
        "SIG_MD5": {CERTIN_617, CERTIN_8422, RBI_140, RBI_16, RBI_118},
        "SIG_SHA1": {CERTIN_617, CERTIN_8422, NIST_SHA1_SIG, RBI_140, RBI_16, RBI_118},
        "SSH_CBC_CIPHER": {CERTIN_8422, NIST_TDEA, RBI_140, RBI_16, SEBI_H5, RBI_118},
        "SSH_DH_GROUP1": {CERTIN_8422, NIST_112, NIST_SHA1_SIG, RBI_140, RBI_16, RBI_118},
        "SSH_DH_SHA1": {CERTIN_8422, NIST_SHA1_SIG, RBI_140, RBI_16, RBI_118},
        "SSH_DSS": {CERTIN_8422, NIST_112, RBI_140, RBI_16, RBI_118},
        "SSH_HMAC_SHA1": set(),
        "SSH_NO_PQ_KEX": {CERTIN_851, CNSA2, NIST_IR8547, SEBI_BOX7, SEBI_RA2},
        "SSH_RSA_SHA1": {CERTIN_8422, NIST_SHA1_SIG, RBI_140, RBI_16, RBI_118},
        "SSH_UMAC64": set(),
        "SSH_V1_ENABLED": {CERTIN_457, CERTIN_8422, RBI_140, RBI_16, RBI_118},
        "SSH_WEAK_CIPHER": {CERTIN_8422, NIST_TDEA, RBI_140, RBI_16, SEBI_H5, RBI_118},
        "SSH_WEAK_MAC": {CERTIN_8422, RBI_140, RBI_16, RBI_118},
        "STATIC_RSA_KEX": {CERTIN_8422, CERTIN_851, CNSA2, NIST_IR8547, NIST_PKCS1, RBI_140, RBI_16, SEBI_BOX7, SEBI_RA2, RBI_118},
        "STORAGE_NO_TLS_ONLY": {CERTIN_627, RBI_106, SEBI_I, SEBI_PRDS1, RBI_118},
        "STORAGE_UNENCRYPTED": {CERTIN_71, RBI_106, SEBI_PRDS1, SEBI_PRDS_1A},
        "TLS_POLICY_OVERRIDE": {CERTIN_8422, RBI_140, RBI_16, SEBI_I, RBI_118},
        "WEAK_CIPHER": {CERTIN_8422, NIST_TDEA, RBI_140, RBI_16, SEBI_H5, RBI_118},
        # CB-34: EXPORT and NULL suites are never strong encryption (SEBI H5); anonymous ones may use AES
        "TLS_EXPORT_CIPHER": {CERTIN_8422, RBI_140, RBI_16, SEBI_H5, RBI_118},
        "TLS_NULL_CIPHER": {CERTIN_8422, RBI_140, RBI_16, SEBI_H5, RBI_118},
        "TLS_ANON_CIPHER": {CERTIN_8422, RBI_140, RBI_16, RBI_118},
    },
    "code": {
        "AT_REST_ENCRYPTION_WEAK": {SEBI_PRDS1, SEBI_PRDS_1A},
        "CERT_NEAR_EXPIRY": {SEBI_S4_5},
        "CERT_SELF_SIGNED": {CERTIN_617},
        "CUSTOM_CRYPTO": {RBI_140, RBI_16, SEBI_H5, RBI_118},
        "DOWNGRADE_PROTECTION_MISSING": {CERTIN_8422},
        "EOL_BASE_IMAGE": set(),
        "EOL_CRYPTO_LIBRARY": set(),
        "EXPIRED_CERTIFICATE": {CERTIN_617, SEBI_S4_5},
        "HARDCODED_KEY": {SEBI_H5},
        "KMS_KEY_DELETION_UNPROTECTED": set(),
        "KMS_KEY_POLICY_PUBLIC": {SEBI_H5},
        "KMS_KEY_ROTATION_DISABLED": set(),
        "KNOWN_TLS_VULNERABILITY": {CERTIN_8416, CERTIN_8422, RBI_140, RBI_16, RBI_118},
        "LIBRARY_CVE_RANGE": {CERTIN_8416},
        "PLAINTEXT_LISTENER": {CERTIN_627, RBI_106, SEBI_I, SEBI_PRDS1, RBI_118},
        "PROVIDER_MANAGED_KEY": set(),
        "QUANTUM_VULNERABLE": {CERTIN_851, CNSA2, NIST_IR8547, SEBI_BOX7, SEBI_RA2},
        "REUSED_NONCE": {RBI_140, RBI_16, RBI_118},
        "SELF_SIGNED_LEAF": {CERTIN_617},
        "STATIC_IV": {RBI_140, RBI_16, RBI_118},
        # CB-27: a constant PBE salt, a PBE iteration count below 1,000 (configurations, like STATIC_IV)
        "STATIC_SALT": {RBI_140, RBI_16, RBI_118},
        "TLS_VERIFICATION_DISABLED": {CERTIN_627, CERTIN_8422},
        "UNENCRYPTED_AT_REST": {CERTIN_71, RBI_106, SEBI_PRDS1, SEBI_PRDS_1A},
        "UNENCRYPTED_IN_TRANSIT": {CERTIN_627, RBI_106, SEBI_I, SEBI_PRDS1, RBI_118},
        "VULNERABLE_CRYPTO_LIBRARY": {CERTIN_8416},
        "WEAK_ALGORITHM": {NIST_112, NIST_SHA1_SIG, NIST_TDEA, RBI_140, RBI_16, SEBI_H5, RBI_118},
        "WEAK_CERTIFICATE_KEY": {NIST_112, RBI_140, RBI_16, RBI_118},
        "WEAK_CERTIFICATE_SIGNATURE": {CERTIN_617, NIST_SHA1_SIG, RBI_140, RBI_16, RBI_118},
        "WEAK_CIPHER_MODE": {RBI_140, RBI_16, RBI_118},
        "WEAK_CIPHER_SUITE": {CERTIN_8422, NIST_TDEA, RBI_140, RBI_16, SEBI_H5, RBI_118},
        "WEAK_KDF_ITERATIONS": {RBI_140, RBI_16, RBI_118},
        "WEAK_KEY_SIZE": {NIST_112, RBI_140, RBI_16, RBI_118},
        "WEAK_PADDING": {NIST_PKCS1, RBI_140, RBI_16, RBI_118},
        "WEAK_PROTOCOL": {CERTIN_8422, RBI_140, RBI_16, SEBI_I, RBI_118},
        # CB-28: RSA public exponent 3 (FIPS 186-5)
        "WEAK_RSA_EXPONENT": {RBI_140, RBI_16, RBI_118},
        "WEAK_RNG": {RBI_140, RBI_16, RBI_118},
    },
}

TDEA_CODES = {"SSH_CBC_CIPHER", "SSH_WEAK_CIPHER", "WEAK_CIPHER", "KEY_WEAK_SYMMETRIC", "IKE_WEAK_ENCR",
              "IPSEC_WEAK_TRANSFORM", "WEAK_CIPHER_SUITE", "WEAK_ALGORITHM"}
PKCS1_CODES = {"WEAK_PADDING", "STATIC_RSA_KEX", "OPCUA_DEPRECATED_POLICY"}
SHA1_SIGNATURE_CODES = {"SIG_SHA1", "SSH_RSA_SHA1", "SSH_DH_SHA1", "SSH_DH_GROUP1", "CA_WEAK_SIGNING",
                        "WEAK_CERTIFICATE_SIGNATURE", "OPCUA_DEPRECATED_POLICY", "POLICY_LEGACY", "WEAK_ALGORITHM"}

# evidence that names every algorithm a clause rule looks for, plus each rule's own example (read from the table)
PROBES = ["", "aes128-cbc, aes256-cbc", "3des-cbc", "TLS_RSA_WITH_3DES_EDE_CBC_SHA DES-CBC3-SHA Triple DES DESede",
          "RC4-SHA NULL EXPORT", "sha1WithRSAEncryption SHA-1 ssh-rsa", "Basic128Rsa15 Basic256", "HMAC-MD5 MD5",
          "RSA-1024 MODP-1024 ECP-192", "TLSv1.0 SSLv3", "private key password", "hmac-sha1 diffie-hellman-group14-sha1"]
_TABLE = json.loads((ROOT / "scripts/crypto_kb/sources/compliance_clauses.json").read_text())
PROBES += sorted({r["example"] for ns in ("node", "code") for row in _TABLE[ns].values() for r in row["rules"]})
NO_3DES = [p for p in PROBES if not any(t in p.lower() for t in ("3des", "des-cbc3", "triple", "desede", "des-ede",
                                                                 "tdea", "des3", "des2"))]


@pytest.fixture(autouse=True)
def _fresh_kb(monkeypatch):
    for name in ("CBOM_KB_BUNDLE", "CBOM_KB_BUNDLE_SIG", "CBOM_KB_PUBKEYS"):
        monkeypatch.delenv(name, raising=False)
    crypto_kb.load.cache_clear()
    yield
    crypto_kb.load.cache_clear()


def _refs(namespace: str, code: str, evidence: str) -> list[dict]:
    """The clauses the finding detail (the KB panel, the AI grounding) cites for one code and one asset's evidence."""
    out = crypto_kb.render(namespace, [code], evidence=evidence, title=evidence)
    assert len(out) == 1, (namespace, code)
    return out[0]["compliance"]


def _cited(namespace: str, code: str, evidence: str) -> set[tuple[str, str]]:
    return {(ref["framework"], ref["id"]) for ref in _refs(namespace, code, evidence)}


def _decided(namespace: str, code: str, evidence: str) -> set[tuple[str, str]]:
    """Cited on the evidence (not "cited for review" because no algorithm was recorded)."""
    return {(ref["framework"], ref["id"]) for ref in _refs(namespace, code, evidence)
            if ref.get("evidence") != "not_recorded"}


def _codes():
    return [(ns, code) for ns in ("node", "code") for code in sorted(crypto_kb.load()["findings"][ns])]


def test_allow_list_names_every_kb_code():
    for ns in ("node", "code"):
        assert set(ALLOW[ns]) == set(crypto_kb.load()["findings"][ns]), ns


@pytest.mark.parametrize("namespace,code", _codes())
def test_every_code_cites_only_allow_listed_clauses(namespace, code):
    allowed = ALLOW[namespace][code]
    for evidence in PROBES:
        extra = _cited(namespace, code, evidence) - allowed
        assert not extra, (namespace, code, evidence, sorted(extra))


def test_issue_269_ssh_findings_cite_only_what_they_break():
    cbc, dh, hmac = ("aes128-cbc, aes256-cbc", "diffie-hellman-group14-sha1", "hmac-sha1")
    nist = {NIST_SHA1_SIG, NIST_TDEA, NIST_PKCS1, NIST_112}
    assert _cited("node", "SSH_CBC_CIPHER", f"SSH server offers CBC-mode SSH ciphers ({cbc})") == {CERTIN_8422, RBI_16,
                                                                                                   RBI_140, RBI_118}
    assert _cited("node", "SSH_DH_SHA1", f"SSH server offers SHA-1 key exchange ({dh})") & nist == {NIST_SHA1_SIG}
    assert _cited("node", "SSH_HMAC_SHA1", f"SSH server offers HMAC-SHA1 ({hmac})") == set()
    # 3des-cbc is CBC *and* TDEA: only then is the TDEA clause cited
    assert NIST_TDEA in _cited("node", "SSH_CBC_CIPHER", "SSH server offers CBC-mode SSH ciphers (3des-cbc, aes128-cbc)")


@pytest.mark.parametrize("namespace,code", _codes())
def test_tdea_pkcs1_and_sha1_signature_clauses_only_where_they_apply(namespace, code):
    for evidence in PROBES:
        cited = _decided(namespace, code, evidence)
        if NIST_TDEA in cited:
            assert code in TDEA_CODES and evidence not in NO_3DES, (code, evidence)
        if NIST_PKCS1 in cited:
            assert code in PKCS1_CODES, (code, evidence)
        if NIST_SHA1_SIG in cited:
            assert code in SHA1_SIGNATURE_CODES, (code, evidence)
    # HMAC-SHA1 stays acceptable under SP 800-131A: nothing that is only about HMAC-SHA1 cites a NIST clause
    if code in ("SSH_HMAC_SHA1", "IKE_WEAK_INTEG", "IPSEC_WEAK_TRANSFORM"):
        assert not {c for c in _cited(namespace, code, "HMAC-SHA1 hmac-sha1") if c[0] == "NIST"}


def test_a_framework_a_finding_does_not_break_is_not_cited():
    # a finding that breaks no clause of a framework appears under no clause of it
    assert {c[0] for c in _cited("node", "PROTO_TLS10", "TLS 1.0 accepted")} == {"CERT-In", "RBI", "SEBI CSCRF"}
    assert CERTIN_617 not in _cited("node", "PROTO_TLS10", "")  # a valid certificate is not about the TLS version
    assert _cited("node", "RSA_LT_2048", "RSA-1024") == {NIST_112, RBI_16, RBI_140, RBI_118}
    assert _cited("node", "DISK_XTS_128", "") == {CNSA2}  # AES-128: CNSA 2.0 only, not the public-key PQC clauses
    assert _cited("node", "KMS_NO_ROTATION", "") == set()


# ------------------------------------------------------------------------------------------- through the run API
from test_cbom_posture import _store
from test_cbom_sources_api import api, world  # noqa: F401  (shared fixtures)

SSH_SERVERS = [
    {"type": "ssh_endpoint", "target": f"10.30.0.{i}", "location": f"10.30.0.{i}:22",
     "facts": {"kex": ["curve25519-sha256", "diffie-hellman-group14-sha1"], "hostkey_algorithms": ["ssh-ed25519"],
               "ciphers": ["aes128-ctr", "aes128-cbc", "aes256-cbc"], "macs": ["hmac-sha2-256", "hmac-sha1"]}}
    for i in (1, 2)
] + [{"type": "ssh_endpoint", "target": "10.30.0.3", "location": "10.30.0.3:22",
      "facts": {"kex": ["curve25519-sha256"], "hostkey_algorithms": ["ssh-ed25519"],
                "ciphers": ["aes128-ctr", "3des-cbc"], "macs": ["hmac-sha2-256"]}}]


def test_run_compliance_mapping_for_ssh_servers(api, world):  # noqa: F811  (pytest fixtures)
    """The run of #269: SSH servers with CBC ciphers, DH-SHA1 and HMAC-SHA1 (plus one with 3des-cbc)."""
    engine, _ = world
    _src, run = _store(api, engine, SSH_SERVERS)
    posture = api("GET", f"/1/cbom/sources/runs/{run['id']}/posture").json()["posture"]
    shown = {(fw["framework"], c["id"]): (c["assets"], set(c["codes"])) for fw in posture["compliance"]
             for c in fw["clauses"]}
    assert NIST_PKCS1 not in shown
    assert shown[NIST_SHA1_SIG] == (2, {"SSH_DH_SHA1"})
    assert shown[NIST_TDEA] == (1, {"SSH_CBC_CIPHER", "SSH_WEAK_CIPHER"})  # only the 3des-cbc server
    assert shown[CERTIN_8422] == (3, {"SSH_CBC_CIPHER", "SSH_DH_SHA1", "SSH_WEAK_CIPHER"})
    assert shown[SEBI_H5] == (1, {"SSH_CBC_CIPHER", "SSH_WEAK_CIPHER"})
    assert not any("SSH_HMAC_SHA1" in codes for _n, codes in shown.values())
    # the results page shows the same clauses, assets and codes
    results = api("GET", f"/1/cbom/sources/runs/{run['id']}/results").json()["compliance"]["frameworks"]
    alias = {"CNSA 2.0": "NSA CNSA 2.0"}
    page = {(alias.get(fw["framework"], fw["framework"]), c["clause"]): (c["assets"], set(c["codes"]))
            for fw in results for c in fw["clauses"]}
    assert {k: v for k, v in page.items() if k in shown} == {k: v for k, v in shown.items() if k in page}
    assert NIST_PKCS1 not in page and page[NIST_SHA1_SIG] == (2, {"SSH_DH_SHA1"})
