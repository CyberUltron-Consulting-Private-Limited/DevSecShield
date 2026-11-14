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

from backend.utilities.cbom_sources import algid
from backend.utilities.cbom_sources import classify as C

# broken or deprecated symmetric ciphers: single DES (56-bit), 2/3-key Triple DES (64-bit block, NIST SP 800-131A
# Rev. 2 disallows encryption since 2023), RC4 (RFC 7465), RC2, DESX, Skipjack, Blowfish/IDEA/CAST5 (64-bit block)
_WEAK_SYMMETRIC = re.compile(r"(^|[^A-Z0-9])(DES|DES2|DES3|3DES|3DES112|3DES168|TDEA|TRIPLE[-_ ]?DES(?:[-_ ]?\dKEY)?|"
                             r"DESX|DES40|RC4(?:[-_]\d+)?|RC2|SKIPJACK|BLOWFISH|IDEA|CAST5|CAST128)($|[^A-Z0-9])", re.I)
_SYMMETRIC = re.compile(r"^(AES|CHACHA|CAMELLIA|ARIA|SEED|SM4|GENERIC[-_]SECRET|HMAC|TWOFISH|GOST)", re.I)
# algid primitives (CycloneDX 1.6) of a public-key algorithm: such a key is never judged as a symmetric one, whatever
# its name starts with (GOST R 34.10-2012 is an elliptic-curve signature; GOST 28147-89 is a block cipher)
_ASYMMETRIC_PRIMITIVES = frozenset({"signature", "kem", "key-agree", "pke"})
_CLASS_WORD = {"private": "Private key", "secret": "Secret key", "public": "Public key", "secret_data": "Secret",
               "certificate": "Certificate key", "split": "Key share"}
# Internal CAs (AD CS templates, Vault PKI roles, EJBCA profiles) are not bound by the CA/Browser Forum's 398 days,
# which applies to publicly trusted certificates only.  Apple platforms (iOS 13 / macOS 10.15 and later) refuse TLS
# server certificates valid for more than 825 days even when they chain to an enterprise root (Apple HT210176), so
# that is the limit an internal server-certificate template is judged against.  CA templates are not judged.
INTERNAL_TLS_MAX_DAYS = 825

# Template enrollment and write rights (scan node: zs_scan_node/collectors/ca.py template_acl) are SDDL aliases or
# SIDs.  Low-privileged: principals every user or computer of the domain is in.  Privileged: principals that already
# control the domain or the CA, for whom a template adds nothing.  Everyone else is a named group or account.
_LOW_PRIV = {"WD": "Everyone", "AU": "Authenticated Users", "AN": "Anonymous", "IU": "Interactive users",
             "NU": "Network logon users", "BU": "Users", "BG": "Guests", "DU": "Domain Users", "DG": "Domain Guests",
             "DC": "Domain Computers"}
_LOW_RID = {"513": "Domain Users", "514": "Domain Guests", "515": "Domain Computers"}
_PRIVILEGED = {"BA", "SY", "ED", "DA", "DD", "EA", "SA", "CA", "RO", "LA", "CO", "PS"}
_PRIVILEGED_RID = {"498", "500", "512", "516", "517", "518", "519", "521"}
_DOMAIN_SID = re.compile(r"^S-1-5-21-\d+-\d+-\d+-(\d+)$")


def _principal_kind(principal: str) -> tuple[str, str]:
    """('low' | 'privileged' | 'other', display name) of an SDDL alias or SID from a template's DACL."""
    p = str(principal)
    m = _DOMAIN_SID.match(p)
    if p in _LOW_PRIV:
        return "low", _LOW_PRIV[p]
    if m and m.group(1) in _LOW_RID:
        return "low", _LOW_RID[m.group(1)]
    if p in _PRIVILEGED or (m and m.group(1) in _PRIVILEGED_RID):
        return "privileged", p
    return "other", p


def _split_principals(principals: Any) -> tuple[list[str], list[str]]:
    """(low-privileged display names, other principals) of a template right; privileged principals are dropped."""
    low, other = [], []
    for p in principals if isinstance(principals, list) else []:
        kind, label = _principal_kind(p)
        if kind == "low" and label not in low:
            low.append(label)
        elif kind == "other":
            other.append(label)
    return low, other


def _alg_text(algorithm: Any, facts: dict[str, Any]) -> str:
    return " ".join(str(x) for x in (algorithm, facts.get("algorithm_desc"), facts.get("key_type")) if x)


def weak_symmetric(text: str) -> str | None:
    m = _WEAK_SYMMETRIC.search(str(text or ""))
    return m.group(2).upper() if m else None


def _is_symmetric(text: str, identifier: Any = None) -> bool:
    """Whether a key is symmetric: algid's primitive for ``identifier`` first, then the name patterns of ``text``."""
    found = algid.resolve(identifier) if identifier else None
    if found is not None and found.primitive in _ASYMMETRIC_PRIMITIVES:
        return False
    return bool(_SYMMETRIC.match(str(text or "").strip())) or weak_symmetric(text) is not None


def _where(facts: dict[str, Any]) -> str:
    return {"pkcs11": "in the HSM", "kmip": "on the KMIP server", "vault_transit": "in Vault transit",
            "mssql": "in SQL Server", "oracle": "in Oracle"}.get(str(facts.get("store") or ""), "")


def managed_key(out, facts: dict[str, Any], algorithm: Any, key_size: Any, now) -> bool | None:
    text = _alg_text(algorithm, facts)
    identifier = algorithm or facts.get("key_type")
    symmetric = _is_symmetric(text, identifier)
    what = _CLASS_WORD.get(str(facts.get("key_class") or ""), "Key")
    where = _where(facts)
    weak = weak_symmetric(text)
    if weak:
        out.add("KEY_WEAK_SYMMETRIC", "High", f"{what} {where} uses {weak}, a broken or deprecated cipher".replace("  ", " "))
    if facts.get("role") == "Always Encrypted column master key" or not symmetric:
        C._key_rules(out, identifier, key_size, f"{what} {where}".strip())
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
            # the same finding as a cloud KMS key without rotation (AWS, Google Cloud, Azure Key Vault): same code and
            # severity wherever the key lives (C9); the text names the Vault setting
            out.add("KMS_NO_ROTATION", "Medium", C.VAULT_NO_ROTATION_TEXT)
    state = str(facts.get("state") or facts.get("key_state") or "")
    if state == "Compromised":
        out.add("KEY_COMPROMISED", "High", f"{what} {where} is marked compromised but is still stored".replace("  ", " "))
    if symmetric:
        return None if weak else False
    qv = C.quantum_vulnerable(identifier)
    if qv is None:
        C.note_unknown("managed_key", identifier)
    return qv


def key_store(out, facts: dict[str, Any], algorithm: Any, key_size: Any, now) -> bool | None:
    return None  # inventory (vendor, model, firmware, protocol versions, keystore state)


def db_encryption(out, facts: dict[str, Any], algorithm: Any, key_size: Any, now) -> bool | None:
    what = {"database": "Database", "tablespace": "Tablespace", "column": "Column"}.get(str(facts.get("scope")), "Data")
    if facts.get("encrypted") is False:
        # Only database-level encryption is visible from inside the database: the volume or the managed service
        # (BitLocker, LUKS, RDS storage encryption) may still encrypt the files, which this row cannot see.
        out.add("DB_TDE_OFF", "Low", f"{what} {facts.get('database') or facts.get('tablespace') or ''} has no "
                                     "database-level encryption (Transparent Data Encryption is off): its data files "
                                     "rely on volume or storage encryption, which is not visible from the database, "
                                     "and copied files or backups are readable unless encrypted "
                                     "separately".replace("  ", " "))
        return None
    weak = weak_symmetric(_alg_text(algorithm, facts))
    if weak:
        out.add("KEY_WEAK_SYMMETRIC", "High", f"{what} is encrypted with {weak}, a deprecated cipher")
    return False


def _names(found: list[str]) -> str:
    return ", ".join(found[:10]) + (f" and {len(found) - 10} more" if len(found) > 10 else "")


def db_login_policy(out, facts: dict[str, Any], algorithm: Any, key_size: Any, now) -> bool | None:
    if facts.get("engine") == "oracle":
        users = [u for u in C.fact_list(facts.get("users")) if isinstance(u, dict)]
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
    logins = [x for x in C.fact_list(facts.get("logins")) if isinstance(x, dict)]
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
    weak = sorted({w for w in (weak_symmetric(a) for a in C.fact_list(facts.get("sessions_nne_algorithms"))) if w})
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
        esc6 = ("The CA takes subject alternative names from request attributes (EDITF_ATTRIBUTESUBJECTALTNAME2) for "
                "every template (AD CS ESC6 pattern)")
        disabled = facts.get("sid_extension_disabled")
        if disabled is False:
            # KB5014754: the CA writes the requester's SID into the certificate and domain controllers (May 2022 and
            # later updates) refuse a certificate whose SID is not the account it names, so ESC6 alone no longer
            # signs in to Active Directory as someone else.
            out.add("CA_ALLOWS_ANY_NAME", "Medium", f"{esc6}. The CA adds the requester's SID, so domain controllers "
                                                    "with the KB5014754 updates refuse such certificates for Active "
                                                    "Directory sign-in; services that map certificates by name (VPN, "
                                                    "802.1X, web sign-in) still accept them")
        else:
            out.add("CA_ALLOWS_ANY_NAME", "High", esc6 + (
                ". The CA also leaves the SID security extension out of its certificates (DisableExtensionList, "
                "ESC16), so domain controllers cannot tell whose certificate it is and anyone who may enroll can "
                "sign in as another user" if disabled else
                "; whether domain controllers refuse such certificates (KB5014754 strong mapping) depends on the CA "
                "adding the SID security extension, which this scan node version did not read"))
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
    acl_read = facts.get("acl_status") == "read"
    if facts.get("allow_any_name") is True:
        out.add("CA_ALLOWS_ANY_NAME", "Medium", f"{name} issues certificates for any name the requester asks for "
                                                "(allow_any_name)")
    elif facts.get("enrollee_supplies_subject") is True and facts.get("client_auth") is True:
        # ESC1 needs a requester who is not already an administrator: the template's enrollment rights decide it.
        chosen = (f"{name} lets the requester choose the subject of a certificate that can sign in "
                  "(ENROLLEE_SUPPLIES_SUBJECT with client authentication or any purpose)")
        low, other = _split_principals(facts.get("enroll_principals"))
        if not acl_read:
            out.add("CA_ALLOWS_ANY_NAME", "Medium", f"{chosen}; who may enroll was not read (scan node version or "
                                                    "template security not readable): review its enrollment rights, "
                                                    "it is the AD CS ESC1 path if non-administrators may enroll")
        elif low:
            out.add("CA_ALLOWS_ANY_NAME", "High", f"{chosen}, and {', '.join(low)} may enroll: any of them can sign in "
                                                  "as another user, a domain administrator included (AD CS ESC1)")
        elif other:
            out.add("CA_ALLOWS_ANY_NAME", "Medium", f"{chosen}; enrollment is limited to {len(other)} group(s) or "
                                                    f"account(s) that are not built-in administrators ({_names(other)}): "
                                                    "each member can sign in as another user (AD CS ESC1 pattern)")
        # enrollment limited to Domain / Enterprise Admins and similar (the SubCA default): no escalation path
    if acl_read:
        low, _other = _split_principals(facts.get("write_principals"))
        if low:
            out.add("CA_TEMPLATE_WRITABLE", "High", f"{', '.join(low)} may change {name} (full control, write, "
                                                    "owner or permission rights on the template): they can make it "
                                                    "issue sign-in certificates for any user (AD CS ESC4)")
    days = _days(facts.get("max_ttl_s"))
    if days and days > INTERNAL_TLS_MAX_DAYS and facts.get("server_auth", True) and not facts.get("is_ca"):
        out.add("CA_LONG_VALIDITY", "Low", f"{name} issues server certificates valid for up to {int(days)} days, more "
                                           f"than the {INTERNAL_TLS_MAX_DAYS} days Apple platforms accept from any "
                                           "CA, enterprise roots included")
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
