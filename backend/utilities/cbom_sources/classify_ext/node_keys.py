"""Rules for keys, key stores, database encryption and certificate authorities read by the scan node (WP6).

Asset types: managed_key (HSM/PKCS#11, KMIP, Vault transit, SQL Server key objects), key_store (HSM token, KMIP server,
Vault transit mount, Oracle TDE keystore), db_encryption (TDE per database / tablespace / column), db_login_policy
(how logins store their passwords), db_crypto_policy (transport encryption policy of SQL Server and Oracle),
ca_authority (an internal CA's signing setup) and ca_template (what a CA lets requesters obtain).  Codes are
described in scripts/crypto_kb/kb_ext/node_keys.py.
"""
from __future__ import annotations

import re
from typing import Any

from backend.utilities.cbom_sources import classify as C

# broken or deprecated symmetric ciphers: single DES (56-bit), 2/3-key Triple DES (64-bit block, NIST SP 800-131A
# Rev. 2 disallows encryption since 2023), RC4 (RFC 7465), RC2, DESX, Skipjack, Blowfish/IDEA/CAST5 (64-bit block)
_WEAK_SYMMETRIC = re.compile(r"(^|[^A-Z0-9])(DES|DES2|DES3|3DES|3DES112|3DES168|TDEA|TRIPLE[-_ ]?DES(?:[-_ ]?\dKEY)?|"
                             r"DESX|DES40|RC4(?:[-_]\d+)?|RC2|SKIPJACK|BLOWFISH|IDEA|CAST5|CAST128)($|[^A-Z0-9])", re.I)
_SYMMETRIC = re.compile(r"^(AES|CHACHA|CAMELLIA|ARIA|SEED|SM4|GENERIC[-_]SECRET|HMAC|TWOFISH|GOST)", re.I)
_CLASS_WORD = {"private": "Private key", "secret": "Secret key", "public": "Public key", "secret_data": "Secret",
               "certificate": "Certificate key", "split": "Key share"}
TLS_PUBLIC_MAX_DAYS = 398  # CA/Browser Forum Baseline Requirements, 6.3.2 (subscriber certificates from 2020-09-01)


def _alg_text(algorithm: Any, facts: dict[str, Any]) -> str:
    return " ".join(str(x) for x in (algorithm, facts.get("algorithm_desc"), facts.get("key_type")) if x)


def weak_symmetric(text: str) -> str | None:
    m = _WEAK_SYMMETRIC.search(str(text or ""))
    return m.group(2).upper() if m else None


def _is_symmetric(text: str) -> bool:
    return bool(_SYMMETRIC.match(str(text or "").strip())) or weak_symmetric(text) is not None


def _where(facts: dict[str, Any]) -> str:
    return {"pkcs11": "in the HSM", "kmip": "on the KMIP server", "vault_transit": "in Vault transit",
            "mssql": "in SQL Server", "oracle": "in Oracle"}.get(str(facts.get("store") or ""), "")


def managed_key(out, facts: dict[str, Any], algorithm: Any, key_size: Any, now) -> bool | None:
    text = _alg_text(algorithm, facts)
    what = _CLASS_WORD.get(str(facts.get("key_class") or ""), "Key")
    where = _where(facts)
    weak = weak_symmetric(text)
    if weak:
        out.add("KEY_WEAK_SYMMETRIC", "High", f"{what} {where} uses {weak}, a broken or deprecated cipher".replace("  ", " "))
    if facts.get("role") == "Always Encrypted column master key" or not _is_symmetric(text):
        C._key_rules(out, algorithm or facts.get("key_type"), key_size, f"{what} {where}".strip())
    klass = str(facts.get("key_class") or "")
    # PKCS#11 only: in an HSM a key is meant to stay inside, so CKA_SENSITIVE/CKA_EXTRACTABLE say whether it can
    # leave.  A KMIP server exists to hand keys to its clients (Sensitive defaults to false and Extractable to true
    # in KMIP 1.4/2.0), so the same attributes there are normal operation, not a finding.
    if facts.get("store") != "pkcs11":
        pass
    elif klass in ("private", "secret") and facts.get("sensitive") is False:
        out.add("KEY_PLAINTEXT_EXPORT", "High", f"{what} {where} can be read out in plain text (CKA_SENSITIVE is "
                                                "false)".replace("  ", " "))
    elif klass in ("private", "secret") and facts.get("extractable") is True:
        out.add("KEY_EXTRACTABLE", "Medium", f"{what} {where} can be wrapped and exported (extractable)".replace("  ", " "))
    if facts.get("store") == "vault_transit":
        if facts.get("exportable") is True:
            out.add("KEY_PLAINTEXT_EXPORT", "High", "Vault transit key is exportable: its versions can be read out in "
                                                    "plain text with the export endpoint")
        if facts.get("allow_plaintext_backup") is True:
            out.add("KEY_PLAINTEXT_EXPORT", "High", "Vault transit key allows a plaintext backup of its key material")
        period = facts.get("auto_rotate_period_s")
        if isinstance(period, (int, float)) and period == 0:
            out.add("KEY_NO_ROTATION", "Low", "Vault transit key has no automatic rotation (auto_rotate_period 0)")
    state = str(facts.get("state") or facts.get("key_state") or "")
    if state == "Compromised":
        out.add("KEY_COMPROMISED", "High", f"{what} {where} is marked compromised but is still stored".replace("  ", " "))
    if _is_symmetric(text):
        return None if weak else False
    return C.quantum_vulnerable(algorithm or facts.get("key_type"))


def key_store(out, facts: dict[str, Any], algorithm: Any, key_size: Any, now) -> bool | None:
    return None  # inventory (vendor, model, firmware, protocol versions, keystore state)


def db_encryption(out, facts: dict[str, Any], algorithm: Any, key_size: Any, now) -> bool | None:
    what = {"database": "Database", "tablespace": "Tablespace", "column": "Column"}.get(str(facts.get("scope")), "Data")
    if facts.get("encrypted") is False:
        out.add("DB_TDE_OFF", "Low", f"{what} {facts.get('database') or facts.get('tablespace') or ''} is not encrypted at "
                                     "rest (Transparent Data Encryption is off)".replace("  ", " "))
        return None
    weak = weak_symmetric(_alg_text(algorithm, facts))
    if weak:
        out.add("KEY_WEAK_SYMMETRIC", "High", f"{what} is encrypted with {weak}, a deprecated cipher")
    return False


def _names(found: list[str]) -> str:
    return ", ".join(found[:10]) + (f" and {len(found) - 10} more" if len(found) > 10 else "")


def db_login_policy(out, facts: dict[str, Any], algorithm: Any, key_size: Any, now) -> bool | None:
    if facts.get("engine") == "oracle":
        users = [u for u in facts.get("users") or [] if isinstance(u, dict)]
        tenG = sorted(str(u.get("name")) for u in users if "10G" in str(u.get("password_versions") or "").upper())
        elevenG = sorted(str(u.get("name")) for u in users if "11G" in str(u.get("password_versions") or "").upper()
                         and str(u.get("name")) not in tenG)
        if tenG:
            out.add("DB_10G_VERIFIER", "High", f"{len(tenG)} user(s) keep the 10G password verifier (DES-based, case-"
                                               f"insensitive): {_names(tenG)}")
        if elevenG:
            out.add("DB_LEGACY_PW_HASH", "Medium", f"{len(elevenG)} user(s) keep the 11G password verifier (salted "
                                                   f"SHA-1): {_names(elevenG)}")
        return None
    logins = [x for x in facts.get("logins") or [] if isinstance(x, dict)]
    sha1 = sorted(str(x.get("name")) for x in logins if x.get("hash_version") == 1)
    if sha1:
        out.add("DB_LEGACY_PW_HASH", "Medium", f"{len(sha1)} SQL login(s) still have a SHA-1 password hash from before "
                                               f"SQL Server 2012: {_names(sha1)}")
    no_policy = sorted(str(x.get("name")) for x in logins if x.get("policy_checked") is False and not x.get("disabled"))
    if no_policy:
        out.add("DB_LOGIN_NO_POLICY", "Low", f"{len(no_policy)} enabled SQL login(s) skip the Windows password policy "
                                             f"(CHECK_POLICY = OFF): {_names(no_policy)}")
    return None


def db_crypto_policy(out, facts: dict[str, Any], algorithm: Any, key_size: Any, now) -> bool | None:
    if facts.get("engine") == "mssql":
        if facts.get("tls") and facts.get("force_encryption") is False:
            out.add("DB_TLS_OPTIONAL", "Medium", "SQL Server does not force encryption: clients that do not ask for it "
                                                 "get TLS for the login only and send queries and results in clear text")
        return None
    if facts.get("native_encryption_required"):
        out.add("DB_LEGACY_NNE", "Medium", "The server requires Oracle native network encryption (NNE), whose key "
                                           "exchange does not authenticate the server, instead of TLS")
    if facts.get("version_unsupported"):
        out.add("DB_EOL_VERSION", "High", "Oracle Database older than 12.1: past Oracle's extended support, no "
                                          "security fixes")
    weak = sorted({w for w in (weak_symmetric(a) for a in facts.get("sessions_nne_algorithms") or []) if w})
    if weak:
        out.add("WEAK_CIPHER", "High", f"Sessions use Oracle native network encryption with {', '.join(weak)}")
    return None


_SHA1 = re.compile(r"SHA-?1(?!\d)|SHA1WITH|MD5|MD2", re.I)


def _weak_hash(text: Any) -> str | None:
    m = _SHA1.search(str(text or ""))
    if not m:
        return None
    return "MD5" if "MD" in m.group(0).upper() else "SHA-1"


def ca_authority(out, facts: dict[str, Any], algorithm: Any, key_size: Any, now) -> bool | None:
    weak = _weak_hash(facts.get("hash_algorithm") or facts.get("signature_algorithm"))
    if weak:
        out.add("CA_WEAK_SIGNING", "Critical" if weak == "MD5" else "High",
                f"The CA signs certificates and CRLs with {weak} ({facts.get('hash_algorithm') or facts.get('signature_algorithm')})")
    if facts.get("san_from_request_attributes") is True:
        out.add("CA_ALLOWS_ANY_NAME", "High", "The CA takes subject alternative names from request attributes "
                                              "(EDITF_ATTRIBUTESUBJECTALTNAME2) for every template (AD CS ESC6 pattern)")
    C._key_rules(out, algorithm or facts.get("key_type"), key_size, "CA key")
    return C.quantum_vulnerable(algorithm or facts.get("key_type"))


def _days(seconds: Any) -> float | None:
    return seconds / 86400 if isinstance(seconds, (int, float)) and seconds > 0 else None


def ca_template(out, facts: dict[str, Any], algorithm: Any, key_size: Any, now) -> bool | None:
    name = facts.get("name") or "template"
    key_type = str(facts.get("key_type") or algorithm or "").upper()
    bits = facts.get("key_bits") if isinstance(facts.get("key_bits"), int) else key_size
    if isinstance(bits, int) and bits > 0:
        if "RSA" in key_type and bits < 2048:
            out.add("CA_ALLOWS_WEAK_KEY", "Critical" if bits < 1024 else "High", f"{name} issues certificates for RSA-{bits} keys")
        elif key_type.startswith("EC") and bits < 224:
            out.add("CA_ALLOWS_WEAK_KEY", "High", f"{name} issues certificates for {bits}-bit EC keys")
    weak = _weak_hash(facts.get("signature_hash") or facts.get("signature_algorithm"))
    if weak:
        out.add("CA_WEAK_SIGNING", "Critical" if weak == "MD5" else "High", f"{name} signs issued certificates with {weak}")
    if facts.get("allow_any_name") is True:
        out.add("CA_ALLOWS_ANY_NAME", "Medium", f"{name} issues certificates for any name the requester asks for "
                                                "(allow_any_name)")
    elif facts.get("enrollee_supplies_subject") is True and facts.get("client_auth") is True:
        out.add("CA_ALLOWS_ANY_NAME", "High", f"{name} lets the requester choose the subject of a client-authentication "
                                              "certificate (ENROLLEE_SUPPLIES_SUBJECT), so it can be used to sign in as "
                                              "another user (AD CS ESC1 pattern)")
    days = _days(facts.get("max_ttl_s"))
    if days and days > TLS_PUBLIC_MAX_DAYS and facts.get("server_auth", True):
        out.add("CA_LONG_VALIDITY", "Low", f"{name} issues certificates valid for up to {int(days)} days (more than "
                                           f"{TLS_PUBLIC_MAX_DAYS})")
    if not key_type or key_type in ("ANY",):
        return None
    return C.quantum_vulnerable(key_type)


C.register("managed_key", managed_key, "related-crypto-material")
C.register("key_store", key_store, "other")
C.register("db_encryption", db_encryption, "other")
C.register("db_login_policy", db_login_policy, "other")
C.register("db_crypto_policy", db_crypto_policy, "protocol")
C.register("ca_authority", ca_authority, "other")
C.register("ca_template", ca_template, "other")
