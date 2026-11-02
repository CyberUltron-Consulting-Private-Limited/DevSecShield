"""Knowledge-base entries for the scan-node keys, HSM, KMIP, database-encryption and CA package (WP6)."""
import kb_text

V_PKCS11 = [{"label": "Key attributes on the token (pkcs11-tool from OpenSC; prints attributes, never values)",
             "command": "pkcs11-tool --module <library.so> --login --list-objects --type secrkey"}]
V_KMIP = [{"label": "Attributes of the object (PyKMIP client on a workstation that holds a KMIP client certificate)",
           "command": "python3 -c \"from kmip.pie.client import ProxyKmipClient as C; c=C(hostname='{host}', port={port}, "
                      "cert='client.pem', key='client.key', ca='ca.pem'); c.open(); print(c.get_attributes('<uid>')); "
                      "c.close()\""}]
V_TRANSIT = [{"label": "Transit key settings (read-only token)", "command": "vault read transit/keys/{name}"}]
V_MSSQL_KEYS = [{"label": "Key algorithms in the database (read-only login)",
                 "command": "sqlcmd -S {host},{port} -N -Q \"SELECT name, algorithm_desc, key_length FROM sys.symmetric_keys; "
                            "SELECT DB_NAME(database_id), encryption_state, key_algorithm, key_length FROM "
                            "sys.dm_database_encryption_keys\""}]
V_ORACLE_USERS = [{"label": "Password verifier versions (SELECT_CATALOG_ROLE)",
                   "command": "sqlplus -s <login>@//{host}:{port}/<service> <<< \"SELECT username, password_versions FROM "
                              "dba_users WHERE password_versions LIKE '%10G%' OR password_versions LIKE '%11G%';\""}]
V_ORACLE_TDE = [{"label": "Tablespace encryption (SELECT_CATALOG_ROLE)",
                 "command": "sqlplus -s <login>@//{host}:{port}/<service> <<< \"SELECT tablespace_name, encrypted FROM "
                            "dba_tablespaces; SELECT * FROM v$encrypted_tablespaces;\""}]
V_ADCS = [{"label": "Hash algorithm the CA signs with (on the CA server)", "command": "certutil -getreg ca\\csp\\CNGHashAlgorithm"},
          {"label": "Certificate templates published on the CA", "command": "certutil -catemplates"}]
V_VAULT_PKI = [{"label": "PKI role settings (read-only token)", "command": "vault read <pki-mount>/roles/{name}"}]
V_EJBCA = [{"label": "Certificate authorities (client certificate authentication)",
            "command": "curl --cert client.pem --key client.key https://{host}:{port}/ejbca/ejbca-rest-api/v1/ca"}]

kb_text.entry(
    "KEY_WEAK_SYMMETRIC", title="Key uses a broken or deprecated cipher", category="key", default_impact="High",
    description="A stored key (in an HSM, a KMIP server, Vault or a database) is a DES, Triple DES, RC4, RC2, Blowfish, "
                "IDEA or CAST5 key, or data is encrypted with one.",
    attack="Single DES keys are brute-forced in hours; Triple DES and the other 64-bit block ciphers leak plaintext on "
           "long-lived keys (Sweet32, CVE-2016-2183); RC4 output is biased.",
    cwe=["CWE-327", "CWE-326"], owasp=["crypto"], cves=["CVE-2016-2183"],
    standards=["NIST SP 800-131A Rev. 2 (Triple DES encryption disallowed after 2023)", "RFC 7465 (prohibits RC4 in TLS)"],
    compliance=["algorithms", "key_mgmt"],
    remediation={"summary": "Generate an AES-256 replacement, re-encrypt (or re-wrap) what the old key protects, then "
                            "deactivate and destroy the old key.",
                 "steps": [{"platform": "SQL Server", "how": "ALTER MASTER KEY REGENERATE WITH ENCRYPTION BY PASSWORD = "
                                                            "'<new>' (database master keys made before 2012 are TRIPLE_DES); "
                                                            "ALTER DATABASE ENCRYPTION KEY REGENERATE WITH ALGORITHM = AES_256"},
                           {"platform": "Oracle", "how": "ALTER TABLESPACE <ts> ENCRYPTION ONLINE USING 'AES256' REKEY"},
                           {"platform": "HSM / KMIP", "how": "Create an AES-256 key, re-wrap or re-encrypt with it, then "
                                                             "revoke and destroy the legacy key"}]},
    verify=V_PKCS11 + V_MSSQL_KEYS, references=["https://sweet32.info/",
                                                "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final"])
kb_text.entry(
    "KEY_PLAINTEXT_EXPORT", title="Key can be read out in plain text", category="key", default_impact="High",
    description="A private or secret key can leave its key manager unprotected: an HSM object with CKA_SENSITIVE false, "
                "or a Vault transit key that is exportable or allows a plaintext backup.",
    attack="Anyone who can use the key (an application token, an HSM user, a Vault policy with export rights) can copy "
           "its value; the key then works outside the HSM or Vault, without audit and after revocation.",
    cwe=["CWE-320", "CWE-522"], owasp=["crypto"], cves=[],
    standards=["PKCS #11 v3.0 (CKA_SENSITIVE, CKA_EXTRACTABLE)", "NIST SP 800-57 Part 1 Rev. 5, 6.2 (key protection)"],
    compliance=["key_mgmt"],
    remediation={"summary": "Re-create the key as sensitive and non-exportable and move its users to the new key; "
                            "the flags cannot be turned back on for a key that was already exposed.",
                 "steps": [{"platform": "PKCS#11", "how": "Generate the key with CKA_SENSITIVE=TRUE, CKA_EXTRACTABLE=FALSE"},
                           {"platform": "Vault transit", "how": "exportable and allow_plaintext_backup cannot be disabled once "
                                                               "set: create a new key with both false, rewrap data "
                                                               "(vault write transit/rewrap/<key>) and delete the old one"}]},
    verify=V_PKCS11 + V_TRANSIT, references=["https://developer.hashicorp.com/vault/api-docs/secret/transit",
                                              "https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html"])
kb_text.entry(
    "KEY_EXTRACTABLE", title="Key can be exported from the HSM", category="key", default_impact="Medium",
    description="A private or secret key has CKA_EXTRACTABLE (or KMIP Extractable) set, so it can be wrapped and taken "
                "out of the HSM or key manager.",
    attack="A user of the token can wrap the key under a key they control and unwrap it elsewhere; the HSM then no "
           "longer is the only place the key exists.",
    cwe=["CWE-320"], owasp=["crypto"], cves=[], standards=["PKCS #11 v3.0 (CKA_EXTRACTABLE)"], compliance=["key_mgmt"],
    remediation={"summary": "Keep keys that never need to leave the HSM non-extractable (CKA_EXTRACTABLE=FALSE); where "
                            "backup needs wrapping, allow it only with CKA_WRAP_WITH_TRUSTED and a trusted wrapping key.",
                 "steps": []},
    verify=V_PKCS11 + V_KMIP, references=["https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html"])
kb_text.entry(
    "KEY_COMPROMISED", title="Key marked compromised is still stored", category="key", default_impact="High",
    description="The key manager lists the key in the KMIP Compromised state: someone recorded that its value may be "
                "known to others, and it still exists.",
    attack="Data or signatures protected by the key may be read or forged; a compromised key that can still be used "
           "for processing keeps the exposure open.",
    cwe=["CWE-324", "CWE-320"], owasp=["crypto"], cves=[], standards=["KMIP 1.4 / 2.0 (State: Compromised)",
                                                                    "NIST SP 800-57 Part 1 Rev. 5, 8.3"],
    compliance=["key_mgmt"],
    remediation={"summary": "Re-encrypt or re-sign everything protected by the key with a new key, then destroy it.",
                 "steps": []},
    verify=V_KMIP, references=["https://docs.oasis-open.org/kmip/kmip-spec/v2.0/kmip-spec-v2.0.html"])
kb_text.entry(
    "KEY_NO_ROTATION", title="Key has no automatic rotation", category="key", default_impact="Low",
    description="A Vault transit key has auto_rotate_period 0, so new key versions are made only by hand.",
    attack="A key version that never changes protects more data for longer; a leak of it exposes everything encrypted "
           "since it was created.",
    cwe=["CWE-324"], owasp=["crypto"], cves=[], standards=["NIST SP 800-57 Part 1 Rev. 5 (cryptoperiods)"],
    compliance=["key_mgmt"],
    remediation={"summary": "vault write transit/keys/<key>/config auto_rotate_period=90d (and set min_decryption_version "
                            "after rewrapping old data).", "steps": []},
    verify=V_TRANSIT, references=["https://developer.hashicorp.com/vault/api-docs/secret/transit"])
kb_text.entry(
    "DB_TDE_OFF", title="Database not encrypted at rest", category="database", default_impact="Low",
    description="A SQL Server database or an Oracle tablespace is not protected by Transparent Data Encryption.",
    attack="Data files, backups, snapshots and replicas expose the data to anyone who copies them.",
    cwe=["CWE-311"], owasp=["crypto"], cves=[], standards=[], compliance=["at_rest"],
    remediation={"summary": "Turn on Transparent Data Encryption with AES-256.",
                 "steps": [{"platform": "SQL Server", "how": "CREATE DATABASE ENCRYPTION KEY WITH ALGORITHM = AES_256 "
                                                            "ENCRYPTION BY SERVER CERTIFICATE <cert>; ALTER DATABASE <db> "
                                                            "SET ENCRYPTION ON (back up the certificate first)"},
                           {"platform": "Oracle", "how": "ALTER TABLESPACE <ts> ENCRYPTION ONLINE USING 'AES256' ENCRYPT"}]},
    verify=V_MSSQL_KEYS + V_ORACLE_TDE,
    references=["https://learn.microsoft.com/sql/relational-databases/security/encryption/transparent-data-encryption"])
kb_text.entry(
    "DB_LEGACY_PW_HASH", title="Logins keep a legacy password hash", category="database", default_impact="Medium",
    description="Logins store their password with a SHA-1 based hash: SQL Server logins whose hash is still version 1 "
                "(from before SQL Server 2012), or Oracle users with the 11G verifier.",
    attack="Salted SHA-1 is fast to brute-force once the hashes leak (a backup, a replica, a privileged account).",
    cwe=["CWE-916", "CWE-328"], owasp=["crypto", "auth"], cves=[], standards=[], compliance=["auth"],
    remediation={"summary": "Have each listed login set a new password, so it is stored with the current hash.",
                 "steps": [{"platform": "SQL Server", "how": "ALTER LOGIN <login> WITH PASSWORD = '<new>' (stored as "
                                                            "SHA-512, hash version 2)"},
                           {"platform": "Oracle", "how": "Set SQLNET.ALLOWED_LOGON_VERSION_SERVER = 12a in sqlnet.ora, "
                                                        "then ALTER USER <user> IDENTIFIED BY <new> so only the 12C "
                                                        "verifier remains"}]},
    verify=V_ORACLE_USERS,
    references=["https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/configuring-authentication.html"])
kb_text.entry(
    "DB_10G_VERIFIER", title="Oracle users keep the 10G password verifier", category="database", default_impact="High",
    description="Oracle users still have the 10G password verifier, a DES-based, case-insensitive hash.",
    attack="The 10G verifier is cracked quickly from a stolen hash, and its presence lets old clients use the weak "
           "logon protocol.",
    cwe=["CWE-916", "CWE-328", "CWE-327"], owasp=["crypto", "auth"], cves=[], standards=[], compliance=["auth"],
    remediation={"summary": "Set SQLNET.ALLOWED_LOGON_VERSION_SERVER = 12a (or at least 12), then reset each listed "
                            "user's password so only the 12C verifier is kept.", "steps": []},
    verify=V_ORACLE_USERS,
    references=["https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/configuring-authentication.html"])
kb_text.entry(
    "DB_LOGIN_NO_POLICY", title="SQL logins skip the password policy", category="database", default_impact="Low",
    description="Enabled SQL Server logins have CHECK_POLICY = OFF: Windows password complexity and lockout do not "
                "apply to them.",
    attack="Short or common passwords and unlimited guessing against those logins.",
    cwe=["CWE-287"], owasp=["auth"], cves=[], standards=[], compliance=["auth"],
    remediation={"summary": "ALTER LOGIN <login> WITH CHECK_POLICY = ON, CHECK_EXPIRATION = ON (or use Windows / "
                            "Entra authentication).", "steps": []},
    verify=[{"label": "Logins without the policy", "command": "sqlcmd -S {host},{port} -N -Q \"SELECT name FROM "
                                                              "sys.sql_logins WHERE is_policy_checked = 0 AND is_disabled = 0\""}],
    references=["https://learn.microsoft.com/sql/relational-databases/security/password-policy"])
kb_text.entry(
    "DB_LEGACY_NNE", title="Oracle requires native network encryption instead of TLS", category="database",
    default_impact="Medium",
    description="The listener insists on Oracle Native Network Encryption (SQLNET.ENCRYPTION_SERVER = REQUIRED) for "
                "TCP connections. NNE negotiates keys without verifying a server certificate; Oracle recommends TLS.",
    attack="Without certificate verification a client cannot tell the real database from an impostor on the path; NNE "
           "also needed the July 2021 CPU fixes (CVE-2021-2351) and still allows SHA-1 integrity for old clients.",
    cwe=["CWE-295", "CWE-757"], owasp=["crypto"], cves=[],
    standards=["Oracle Database Security Guide 23ai: Choosing between NNE and TLS"], compliance=["in_transit"],
    remediation={"summary": "Configure a TCPS listener with a CA-issued certificate, move clients to TLS and then stop "
                            "requiring NNE.", "steps": []},
    verify=[{"label": "Does the listener offer TLS?", "command": "openssl s_client -connect {host}:{port} </dev/null"}],
    references=["https://docs.oracle.com/en/database/oracle/oracle-database/23/dbseg/nne-vs-tls.html",
                "https://nvd.nist.gov/vuln/detail/CVE-2021-2351"])
kb_text.entry(
    "DB_EOL_VERSION", title="Database release past end of support", category="database", default_impact="High",
    description="The Oracle Database release is older than 12.1; every such release is past Oracle's extended support "
                "and receives no security fixes.",
    attack="Known vulnerabilities, including in authentication and network encryption, stay unpatched.",
    cwe=["CWE-1104"], owasp=["components"], cves=[], standards=[], compliance=["components"],
    remediation={"summary": "Upgrade to a supported release (19c or later).", "steps": []},
    verify=[{"label": "Release banner", "command": "sqlplus -s <login>@//{host}:{port}/<service> <<< \"SELECT banner FROM v$version;\""}],
    references=["https://www.oracle.com/us/support/library/lifetime-support-technology-069183.pdf"])
kb_text.entry(
    "CA_WEAK_SIGNING", title="Certificate authority signs with SHA-1 or MD5", category="certificate",
    default_impact="High",
    description="An internal CA (AD CS, EJBCA, Vault) or one of its templates signs certificates and CRLs with SHA-1 or "
                "MD5.",
    attack="Chosen-prefix collisions let an attacker get a harmless request signed and reuse the signature on a forged "
           "certificate (SHA-1: SHAmbles 2020; MD5: the 2008 rogue CA).",
    cwe=["CWE-327", "CWE-328"], owasp=["crypto"], cves=[], standards=["NIST SP 800-131A Rev. 2 (SHA-1 signature generation disallowed)"],
    compliance=["algorithms", "certificates"],
    remediation={"summary": "Switch the CA to SHA-256 and re-issue certificates.",
                 "steps": [{"platform": "AD CS", "how": "certutil -setreg ca\\csp\\CNGHashAlgorithm SHA256; "
                                                       "restart-service certsvc"}]},
    verify=V_ADCS + V_EJBCA, references=["https://sha-mbles.github.io/"])
kb_text.entry(
    "CA_ALLOWS_WEAK_KEY", title="CA issues certificates for weak keys", category="certificate", default_impact="High",
    description="A certificate template, Vault PKI role or EJBCA profile accepts RSA keys under 2048 bits or EC keys "
                "under 224 bits.",
    attack="Certificates for factorable keys let an attacker derive the private key from the public certificate and "
           "impersonate the holder.",
    cwe=["CWE-326"], owasp=["crypto"], cves=[], standards=["NIST SP 800-131A Rev. 2 (112-bit minimum)"],
    compliance=["keysize", "certificates"],
    remediation={"summary": "Raise the template's minimum key size to RSA 2048 (or 3072) / P-256 and re-issue affected "
                            "certificates.", "steps": []},
    verify=V_ADCS + V_VAULT_PKI, references=["https://csrc.nist.gov/pubs/sp/800/131/a/r2/final"])
kb_text.entry(
    "CA_ALLOWS_ANY_NAME", title="CA issues certificates for names the requester chooses", category="certificate",
    default_impact="Medium",
    description="A Vault PKI role has allow_any_name, or an AD CS template with client authentication lets the enrollee "
                "supply the subject (ENROLLEE_SUPPLIES_SUBJECT).",
    attack="Anyone allowed to request from it can obtain a certificate for another server or user and impersonate it; "
           "in AD CS this is the ESC1 privilege-escalation path to domain administrator.",
    cwe=["CWE-284", "CWE-295"], owasp=["access", "auth"], cves=[], standards=[], compliance=["certificates", "auth"],
    remediation={"summary": "Restrict names (allowed_domains, allow_subdomains in Vault; build the subject from Active "
                            "Directory and require manager approval in AD CS) and limit who may enroll.", "steps": []},
    verify=V_ADCS + V_VAULT_PKI, references=["https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf"])
kb_text.entry(
    "CA_LONG_VALIDITY", title="CA issues long-lived certificates", category="certificate", default_impact="Low",
    description="A template or role issues server certificates valid for more than 398 days.",
    attack="A leaked key stays usable for longer, and certificates outlive the algorithms and owners they were made for.",
    cwe=["CWE-324"], owasp=["crypto"], cves=[], standards=["CA/Browser Forum Baseline Requirements 6.3.2 (398 days)"],
    compliance=["certificates"],
    remediation={"summary": "Lower the role's max_ttl or the template's validity to 397 days or less and automate "
                            "renewal.", "steps": []},
    verify=V_VAULT_PKI, references=["https://cabforum.org/working-groups/server/baseline-requirements/"])

NODE_CODES = ["KEY_WEAK_SYMMETRIC", "KEY_PLAINTEXT_EXPORT", "KEY_EXTRACTABLE", "KEY_COMPROMISED", "KEY_NO_ROTATION",
              "DB_TDE_OFF", "DB_LEGACY_PW_HASH", "DB_10G_VERIFIER", "DB_LOGIN_NO_POLICY", "DB_LEGACY_NNE",
              "DB_EOL_VERSION", "CA_WEAK_SIGNING", "CA_ALLOWS_WEAK_KEY", "CA_ALLOWS_ANY_NAME", "CA_LONG_VALIDITY"]
