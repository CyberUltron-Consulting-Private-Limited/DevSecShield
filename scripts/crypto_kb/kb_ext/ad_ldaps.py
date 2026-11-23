"""Active Directory finding codes (FIX-B3): Kerberos encryption types, domain functional level, krbtgt key age.

Rules: backend/utilities/cbom_sources/classify_ext/ad.py.  Facts: the scan node's read-only LDAPS / StartTLS collector
(scan_node/zs_scan_node/collectors/active_directory.py).
"""
import kb_text

V_ENCTYPES = [{"label": "Encryption types set on the account (RSAT, read-only)",
               "command": "Get-ADObject -Filter \"sAMAccountName -eq '{name}'\" -Properties msDS-SupportedEncryptionTypes,"
                          "userAccountControl | Select-Object Name,msDS-SupportedEncryptionTypes,userAccountControl"},
              {"label": "Tickets actually issued with RC4 or DES (on a domain controller: Kerberos service ticket events)",
               "command": "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4769} -MaxEvents 2000 | Where-Object "
                          "{ $_.Properties[5].Value -in 0x1,0x3,0x17,0x18 } | Select-Object TimeCreated,"
                          "@{n='Service';e={$_.Properties[2].Value}}"}]
V_DOMAIN = [{"label": "Domain and forest functional levels (RSAT, read-only)",
             "command": "Get-ADDomain | Select-Object DNSRoot,DomainMode; Get-ADForest | Select-Object ForestMode"}]
V_KRBTGT = [{"label": "When the krbtgt password was last set (RSAT, read-only)",
             "command": "Get-ADUser krbtgt -Properties PasswordLastSet,msDS-KeyVersionNumber | Select-Object "
                        "PasswordLastSet,msDS-KeyVersionNumber"}]
ENCTYPE_STEPS = [
    {"platform": "Active Directory", "how": "Find the accounts in the inventory, confirm their services support AES "
                                            "(Windows Server 2008 and later, current Java, MIT and Heimdal clients do), "
                                            "then set msDS-SupportedEncryptionTypes to 0x18 (AES128 + AES256): "
                                            "Set-ADUser <account> -KerberosEncryptionType AES128,AES256 (or "
                                            "Set-ADComputer / Set-ADServiceAccount)"},
    {"platform": "Active Directory", "how": "Reset the account's password once after the change, so AES keys exist "
                                            "for accounts whose password predates the domain's AES support"},
    {"platform": "Group Policy", "how": "Computer Configuration > Windows Settings > Security Settings > Local "
                                        "Policies > Security Options > Network security: Configure encryption types "
                                        "allowed for Kerberos: AES128_HMAC_SHA1, AES256_HMAC_SHA1 (and Future "
                                        "encryption types), first on member servers, then on the domain controllers"},
]

kb_text.entry(
    "KERBEROS_DES_ENABLED", title="Kerberos DES encryption allowed", category="protocol", default_impact="High",
    description="The account's msDS-SupportedEncryptionTypes includes DES-CBC-CRC or DES-CBC-MD5, or its "
                "userAccountControl has USE_DES_KEY_ONLY: the domain controller may issue Kerberos tickets for it "
                "encrypted with single DES (56-bit keys).",
    attack="A ticket encrypted with single DES is brute-forced offline in hours on commodity hardware, which yields "
           "the account's key and lets an attacker forge service tickets to it (silver tickets) or read its traffic.",
    cwe=["CWE-327", "CWE-326"], owasp=["crypto", "auth"], cves=[],
    standards=["RFC 6649 (deprecates DES, RC4-HMAC-EXP and other weak Kerberos enctypes)",
               "NIST SP 800-131A Rev. 2 (DES disallowed)"],
    compliance=["algorithms", "auth"],
    remediation={"summary": "Remove the DES bits and USE_DES_KEY_ONLY; allow AES only on the account and in the "
                            "domain's Kerberos encryption type policy.", "steps": ENCTYPE_STEPS},
    verify=V_ENCTYPES,
    references=["https://www.rfc-editor.org/rfc/rfc6649",
                "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos"])
kb_text.entry(
    "KERBEROS_RC4_ONLY", title="Kerberos account gets RC4 tickets and no AES", category="protocol", default_impact="High",
    description="The account's msDS-SupportedEncryptionTypes lists RC4-HMAC and no AES encryption type: every service "
                "ticket for it is encrypted with RC4-HMAC, whose key is the account's unsalted NT hash. (An account "
                "without the attribute gets the domain controller's default instead: KERBEROS_ENCTYPES_DEFAULT.)",
    attack="Any domain user can request a service ticket for an account with an SPN and crack it offline "
           "(Kerberoasting); RC4 tickets are far cheaper to crack than AES ones because the key is the NT hash with "
           "no salt and no key-derivation iterations.",
    cwe=["CWE-327", "CWE-916"], owasp=["crypto", "auth"], cves=[],
    standards=["RFC 8429 (deprecates RC4-HMAC in Kerberos)", "RFC 7465 (prohibits RC4 in TLS)"],
    compliance=["algorithms", "auth"],
    remediation={"summary": "Set the account to AES only (msDS-SupportedEncryptionTypes 0x18), reset its password, "
                            "and use a group managed service account (gMSA) with a long random password where the "
                            "service allows it.", "steps": ENCTYPE_STEPS},
    verify=V_ENCTYPES,
    references=["https://www.rfc-editor.org/rfc/rfc8429",
                "https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos"])
kb_text.entry(
    "KERBEROS_ENCTYPES_DEFAULT", title="Kerberos account uses the domain controller's default encryption types",
    category="protocol", default_impact="Low",
    description="The account has no msDS-SupportedEncryptionTypes, so the domain controller decides which encryption "
                "type its service tickets use. Since Microsoft's April 2026 update for CVE-2026-20833 (KB5073381) a "
                "patched domain controller assumes AES-SHA1 only (0x18) for such an account unless the registry value "
                "DefaultDomainSupportedEncTypes enables RC4; an older domain controller issues RC4-HMAC tickets. Both "
                "are domain controller settings that LDAP cannot read, so the account's ticket encryption is unknown.",
    attack="If the domain controllers predate the April 2026 update, or DefaultDomainSupportedEncTypes enables RC4, "
           "any domain user can request an RC4 service ticket for the account and crack it offline (Kerberoasting); "
           "on patched domain controllers an account whose password predates AES support gets no ticket at all.",
    cwe=["CWE-327", "CWE-1188"], owasp=["crypto", "auth"], cves=[],
    standards=["RFC 8429 (deprecates RC4-HMAC in Kerberos)",
               "Microsoft KB5073381 (CVE-2026-20833): KDC default encryption types from April 2026"],
    compliance=["algorithms", "auth"],
    remediation={"summary": "Make the account's encryption types explicit (msDS-SupportedEncryptionTypes 0x18, AES "
                            "only) once its service supports AES, and confirm every domain controller has the April "
                            "2026 update and no DefaultDomainSupportedEncTypes value that enables RC4.",
                 "steps": ENCTYPE_STEPS + [
                     {"platform": "Domain controllers", "how": "Read HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc "
                                                               "DefaultDomainSupportedEncTypes on each DC (absent "
                                                               "means the KDC default) and check the System log for "
                                                               "KDCSVC events 201-209 (RC4 use and blocks)"}]},
    verify=V_ENCTYPES + [{"label": "The DC's explicit default, if any (on each domain controller)",
                          "command": "Get-ItemProperty -Path HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Kdc "
                                     "-Name DefaultDomainSupportedEncTypes -ErrorAction SilentlyContinue"}],
    references=["https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc",
                "https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos"])
kb_text.entry(
    "KERBEROS_RC4_ENABLED", title="Kerberos RC4 still allowed beside AES", category="protocol", default_impact="Medium",
    description="The account allows AES and also RC4-HMAC (msDS-SupportedEncryptionTypes includes 0x4), so a client "
                "or an attacker that asks for RC4 still gets an RC4-encrypted ticket.",
    attack="An attacker requesting a service ticket can ask for RC4 only and receive one that is cheap to crack "
           "offline (Kerberoasting with RC4 downgrade), even though legitimate clients use AES.",
    cwe=["CWE-327", "CWE-757"], owasp=["crypto", "auth"], cves=[],
    standards=["RFC 8429 (deprecates RC4-HMAC in Kerberos)"],
    compliance=["algorithms", "auth"],
    remediation={"summary": "Remove RC4 from the account (msDS-SupportedEncryptionTypes 0x18) once its clients are "
                            "known to use AES; watch event 4769 for RC4 tickets (0x17) first.", "steps": ENCTYPE_STEPS},
    verify=V_ENCTYPES,
    references=["https://www.rfc-editor.org/rfc/rfc8429",
                "https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos"])
kb_text.entry(
    "AD_FUNCTIONAL_LEVEL_LEGACY", title="Active Directory domain functional level is old", category="protocol",
    default_impact="Medium",
    description="The domain functional level is below Windows Server 2016. Below Windows Server 2008 the krbtgt "
                "account cannot hold AES keys at all, so every ticket-granting ticket is RC4 or DES; up to 2012 R2 "
                "newer Kerberos protections (Protected Users' AES-only rule, claims and compound authentication, "
                "Kerberos armoring by default) are not available domain-wide.",
    attack="An attacker who obtains or cracks the krbtgt or a service key can forge tickets (golden or silver "
           "tickets); with weak ticket encryption that key is easier to obtain, and the missing protections leave "
           "privileged accounts open to credential theft and delegation abuse.",
    cwe=["CWE-327", "CWE-1104"], owasp=["crypto", "misconfig"], cves=[],
    standards=["Microsoft Active Directory functional levels (Windows Server 2016 and later supported)"],
    compliance=["algorithms"],
    remediation={"summary": "Retire domain controllers older than Windows Server 2016, then raise the domain and "
                            "forest functional levels.", "steps": [
        {"platform": "Active Directory", "how": "Set-ADDomainMode -Identity <domain> -DomainMode Windows2016Domain; "
                                                "Set-ADForestMode -Identity <forest> -ForestMode Windows2016Forest"}]},
    verify=V_DOMAIN,
    references=["https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels"])
kb_text.entry(
    "KRBTGT_KEY_OLD", title="krbtgt key not rotated for more than 180 days", category="key", default_impact="Medium",
    description="The krbtgt account's password, from which the keys that sign and encrypt every ticket-granting "
                "ticket in the domain are derived, was last set more than 180 days ago.",
    attack="A krbtgt key stolen at any time since it was last set (from a backup, a compromised domain controller "
           "or a DCSync) still lets the attacker forge ticket-granting tickets for any account (golden tickets) "
           "until the password is reset twice.",
    cwe=["CWE-324", "CWE-320"], owasp=["crypto", "auth"], cves=[],
    standards=["Microsoft guidance: reset the krbtgt password regularly, twice with replication in between"],
    compliance=["key_mgmt"],
    remediation={"summary": "Reset the krbtgt password twice, waiting for replication (and the maximum ticket "
                            "lifetime) between the two resets.", "steps": [
        {"platform": "Active Directory", "how": "Use Microsoft's New-KrbtgtKeys.ps1 (simulation mode first), or "
                                                "Set-ADAccountPassword krbtgt -Reset twice, 10 or more hours apart"}]},
    verify=V_KRBTGT,
    references=["https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password"])

NODE_CODES = ["KERBEROS_DES_ENABLED", "KERBEROS_RC4_ONLY", "KERBEROS_RC4_ENABLED", "KERBEROS_ENCTYPES_DEFAULT", "AD_FUNCTIONAL_LEVEL_LEGACY",
              "KRBTGT_KEY_OLD"]
