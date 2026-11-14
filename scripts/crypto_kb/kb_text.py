"""Hand-written knowledge-base text: remediation blocks, proof-of-exposure commands and per-code entries.

Facts with an external source (CVE details, CWE names, compliance clauses, OWASP categories, EOL dates) are NOT typed
here: build_kb.py pulls them from the fetched source files and refuses to build if one is missing.
Placeholders in commands: {host} {port} {path} {name} {location} {resource}.
"""

# ----------------------------------------------------------------------------- shared remediation blocks
TLS_MIN12 = [
    {"platform": "nginx", "how": "ssl_protocols TLSv1.2 TLSv1.3;  (in the server or http block, then `nginx -t && systemctl reload nginx`)"},
    {"platform": "Apache httpd", "how": "SSLProtocol -all +TLSv1.2 +TLSv1.3"},
    {"platform": "HAProxy", "how": "ssl-default-bind-options ssl-min-ver TLSv1.2  (global section)"},
    {"platform": "Windows / IIS (SCHANNEL)", "how": "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\<SSL 2.0|SSL 3.0|TLS 1.0|TLS 1.1>\\Server  Enabled=0, DisabledByDefault=1 (DWORD), then reboot"},
    {"platform": "Java (JSSE)", "how": "Add SSLv3, TLSv1, TLSv1.1 to jdk.tls.disabledAlgorithms in $JAVA_HOME/conf/security/java.security"},
    {"platform": "Tomcat", "how": "sslEnabledProtocols=\"TLSv1.2+TLSv1.3\" on the <SSLHostConfig>"},
    {"platform": "Postfix", "how": "smtpd_tls_mandatory_protocols = >=TLSv1.2 and smtpd_tls_protocols = >=TLSv1.2"},
    {"platform": "OpenSSL system default", "how": "MinProtocol = TLSv1.2 under [system_default_sect] in openssl.cnf; on RHEL/AL2023 run `update-crypto-policies --set DEFAULT`"},
    {"platform": "AWS load balancer / CloudFront", "how": "Choose a TLS 1.2+ security policy (for example ELBSecurityPolicy-TLS13-1-2-2021-06) and a TLSv1.2_2021 CloudFront minimum protocol"},
]
TLS_CIPHERS = [
    {"platform": "nginx", "how": "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;  (TLS 1.3 suites are AEAD-only already)"},
    {"platform": "Apache httpd", "how": "SSLCipherSuite with the same AEAD + ECDHE list, and SSLHonorCipherOrder off"},
    {"platform": "Windows / IIS (SCHANNEL)", "how": "Disable-TlsCipherSuite for every *_RC4_*, *_3DES_*, *_DES_*, *_NULL_*, *_EXPORT_* and non-ECDHE RSA suite; or set the SSL Cipher Suite Order group policy"},
    {"platform": "Java (JSSE)", "how": "Add RC4, DES, 3DES_EDE_CBC, anon, NULL, EXPORT to jdk.tls.disabledAlgorithms"},
    {"platform": "OpenSSL-based services", "how": "CipherString = DEFAULT@SECLEVEL=2 in openssl.cnf removes RC4, 3DES, EXPORT and NULL suites"},
]
SSH_HARDEN = [
    {"platform": "OpenSSH sshd", "how": "In /etc/ssh/sshd_config set Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr; MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com; KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org; HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256 — then `sshd -t && systemctl reload sshd`. Keep only the KEX names your OpenSSH version supports (`ssh -Q kex`)."},
    {"platform": "RHEL / AL2023 crypto policies", "how": "`update-crypto-policies --set DEFAULT` (never LEGACY); sshd follows the system policy"},
]
CERT_REISSUE = [
    {"platform": "Any CA", "how": "Re-issue the certificate with an RSA-3072 or ECDSA P-256/P-384 key and a SHA-256/384 signature, deploy it, then revoke the old one"},
    {"platform": "OpenSSL CSR", "how": "openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -sha256 -nodes -keyout new.key -out new.csr -subj \"/CN={host}\""},
    {"platform": "AWS ACM", "how": "Request an ACM certificate with RSA_2048+ or EC_prime256v1 key algorithm and re-associate the listener"},
]
PQC_HYBRID = [
    {"platform": "OpenSSL 3.5+ (nginx, Apache, HAProxy)", "how": "Offer the hybrid group first: nginx `ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;` (needs an OpenSSL 3.5+ build)"},
    {"platform": "OpenSSH", "how": "Prefer mlkem768x25519-sha256 / sntrup761x25519-sha512@openssh.com in KexAlgorithms (OpenSSH 9.9+ / 9.0+)"},
    {"platform": "Plan", "how": "Inventory the systems that protect data needed beyond your CRQC horizon (see the Mosca score) and migrate those first"},
]
DB_TLS = {
    "postgres": "postgresql.conf: ssl = on, ssl_min_protocol_version = 'TLSv1.2'; pg_hba.conf: use hostssl (not host) for every remote rule",
    "mysql": "my.cnf: require_secure_transport = ON, tls_version = TLSv1.2,TLSv1.3",
    "redis": "redis.conf: port 0, tls-port 6379, tls-protocols \"TLSv1.2 TLSv1.3\", tls-cert-file / tls-key-file / tls-ca-cert-file",
    "mongodb": "mongod.conf: net.tls.mode: requireTLS, net.tls.disabledProtocols: TLS1_0,TLS1_1",
}

# ----------------------------------------------------------------------------- proof-of-exposure commands (read-only)
V_TLS_PROTO = [
    {"label": "Protocol versions the server accepts", "command": "nmap --script ssl-enum-ciphers -p {port} {host}"},
    {"label": "Same check with testssl.sh", "command": "testssl.sh --protocols {host}:{port}"},
]
V_TLS10 = V_TLS_PROTO + [{"label": "Handshake at the old version (OpenSSL 1.1.1+/3.x)", "command": "openssl s_client -connect {host}:{port} -tls1 -cipher 'DEFAULT@SECLEVEL=0' </dev/null 2>&1 | grep -E 'Protocol|Cipher'"}]
V_TLS11 = V_TLS_PROTO + [{"label": "Handshake at TLS 1.1", "command": "openssl s_client -connect {host}:{port} -tls1_1 -cipher 'DEFAULT@SECLEVEL=0' </dev/null 2>&1 | grep -E 'Protocol|Cipher'"}]
V_CIPHERS = [
    {"label": "Every cipher suite per protocol, graded", "command": "nmap --script ssl-enum-ciphers -p {port} {host}"},
    {"label": "Try the weak suites explicitly", "command": "openssl s_client -connect {host}:{port} -tls1_2 -cipher 'RC4:3DES:DES:NULL:EXPORT:@SECLEVEL=0' </dev/null 2>&1 | grep -E 'Cipher|alert'"},
]
V_CERT_REMOTE = [{"label": "Certificate the endpoint presents", "command": "openssl s_client -connect {host}:{port} -servername {host} </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -text | grep -E 'Subject:|Issuer:|Not After|Signature Algorithm|Public-Key'"}]
V_CERT_FILE = [{"label": "Inspect the certificate file", "command": "openssl x509 -in '{path}' -noout -subject -dates -text | grep -E 'Subject:|Not After|Signature Algorithm|Public-Key'"}]
V_SSH = [
    {"label": "Algorithms the SSH server offers (no login)", "command": "nmap --script ssh2-enum-algos -p {port} {host}"},
    {"label": "Same with ssh-audit", "command": "ssh-audit -p {port} {host}"},
]
V_KEYFILE = [
    {"label": "Owner and permissions of the key file", "command": "ls -l '{path}'"},
    {"label": "Key type and size without printing the key", "command": "openssl pkey -in '{path}' -pubout 2>/dev/null | openssl pkey -pubin -noout -text | head -1"},
]
V_PG = [{"label": "Server TLS and password settings (as the read-only login)", "command": "psql \"host={host} port={port} sslmode=require\" -c \"SELECT name, setting FROM pg_settings WHERE name IN ('ssl','ssl_min_protocol_version','password_encryption')\" -c \"SELECT line_number, type, database, user_name, auth_method FROM pg_hba_file_rules\""}]
V_MYSQL = [{"label": "TLS and plugin settings", "command": "mysql -h {host} -P {port} --ssl-mode=REQUIRED -e \"SHOW GLOBAL VARIABLES WHERE Variable_name IN ('require_secure_transport','tls_version','default_table_encryption'); SELECT user, host, plugin FROM mysql.user\""}]
V_DB_TLS = [{"label": "Does the port offer TLS?", "command": "nmap --script ssl-enum-ciphers -p {port} {host}"}]

# ----------------------------------------------------------------------------- per-code entries
# cves: ids only (details come from nvd_cves.json). compliance: framework keys resolved in build_kb.py.
E = {}


def entry(code, **kw):
    E[code] = kw


# --- TLS protocol versions
entry("PROTO_SSLv2", title="SSLv2 accepted", category="protocol", default_impact="Critical",
      description="The endpoint still negotiates SSL 2.0, which has been prohibited since 2011 (RFC 6176).",
      attack="An attacker who records traffic can use the SSLv2 support to decrypt even TLS sessions that share the server's RSA key (DROWN).",
      cwe=["CWE-327", "CWE-757"], owasp=["crypto", "misconfig"], cves=["CVE-2016-0800", "CVE-2016-0703"],
      standards=["RFC 6176 (prohibits SSL 2.0)", "NIST SP 800-52 Rev. 2"], compliance=["tls_min"],
      remediation={"summary": "Turn off SSLv2 and SSLv3 everywhere the same key is used, and allow only TLS 1.2 and 1.3.", "steps": TLS_MIN12},
      verify=V_TLS_PROTO, references=["https://drownattack.com/"])
entry("PROTO_SSLv3", title="SSLv3 accepted", category="protocol", default_impact="Critical",
      description="The endpoint still negotiates SSL 3.0, deprecated by RFC 7568 because of the POODLE padding-oracle attack.",
      attack="An on-path attacker forces a fallback to SSLv3 and recovers secrets such as session cookies one byte at a time (POODLE).",
      cwe=["CWE-327", "CWE-757"], owasp=["crypto", "misconfig"], cves=["CVE-2014-3566"],
      standards=["RFC 7568 (deprecates SSL 3.0)", "NIST SP 800-52 Rev. 2"], compliance=["tls_min"],
      remediation={"summary": "Disable SSLv3 and allow only TLS 1.2 and 1.3.", "steps": TLS_MIN12},
      verify=V_TLS_PROTO, references=["https://www.openssl.org/~bodo/ssl-poodle.pdf"])
entry("PROTO_TLS10", title="TLS 1.0 accepted", category="protocol", default_impact="High",
      description="The endpoint accepts TLS 1.0, which RFC 8996 deprecated in 2021. It relies on SHA-1/MD5 in the handshake and CBC constructions with known attacks.",
      attack="A client that can be downgraded to TLS 1.0 is exposed to BEAST-style CBC attacks and to weak handshake hashes; regulators treat TLS 1.0 as a failed control.",
      cwe=["CWE-327", "CWE-757"], owasp=["crypto", "misconfig"], cves=["CVE-2011-3389"],
      standards=["RFC 8996 (deprecates TLS 1.0 and 1.1)", "NIST SP 800-52 Rev. 2", "PCI DSS v4.0 (strong cryptography)"], compliance=["tls_min"],
      remediation={"summary": "Allow TLS 1.2 and 1.3 only. Check old clients first with the endpoint's access logs.", "steps": TLS_MIN12},
      verify=V_TLS10, references=["https://www.rfc-editor.org/rfc/rfc8996"])
entry("PROTO_TLS11", title="TLS 1.1 accepted", category="protocol", default_impact="High",
      description="The endpoint accepts TLS 1.1, deprecated by RFC 8996 together with TLS 1.0.",
      attack="TLS 1.1 still uses MD5/SHA-1 in the handshake PRF and offers no AEAD ciphers; it keeps clients on a downgrade path.",
      cwe=["CWE-327", "CWE-757"], owasp=["crypto", "misconfig"], cves=[],
      standards=["RFC 8996 (deprecates TLS 1.0 and 1.1)", "NIST SP 800-52 Rev. 2"], compliance=["tls_min"],
      remediation={"summary": "Allow TLS 1.2 and 1.3 only.", "steps": TLS_MIN12},
      verify=V_TLS11, references=["https://www.rfc-editor.org/rfc/rfc8996"])
for old, new in (("MIN_SSLv2", "PROTO_SSLv2"), ("MIN_SSLv3", "PROTO_SSLv3"), ("MIN_TLS10", "PROTO_TLS10"), ("MIN_TLS11", "PROTO_TLS11")):
    E[old] = dict(E[new], title=E[new]["title"].replace("accepted", "allowed as the minimum version"),
                  description="The configured minimum protocol version still allows a deprecated version. " + E[new]["description"])
entry("NO_TLS12", title="Neither TLS 1.2 nor TLS 1.3 offered", category="protocol", default_impact="High",
      description="The endpoint only speaks deprecated protocol versions, so every connection uses broken or weak cryptography.",
      attack="Every session to this endpoint can be attacked with the weaknesses of the old protocol; modern clients will fail to connect.",
      cwe=["CWE-327", "CWE-326"], owasp=["crypto", "misconfig"], cves=[],
      standards=["NIST SP 800-52 Rev. 2", "RFC 9325 (BCP 195)"], compliance=["tls_min"],
      remediation={"summary": "Upgrade the TLS stack (or the appliance firmware) and enable TLS 1.2 and 1.3.", "steps": TLS_MIN12},
      verify=V_TLS_PROTO, references=["https://www.rfc-editor.org/rfc/rfc9325"])
entry("NO_TLS", title="Service does not offer TLS", category="protocol", default_impact="High",
      description="The service accepts plaintext connections only, so credentials and data cross the network unencrypted.",
      attack="Anyone on the network path can read or modify the traffic, including passwords sent at login.",
      cwe=["CWE-319"], owasp=["crypto"], cves=[], standards=["NIST SP 800-52 Rev. 2"], compliance=["in_transit"],
      remediation={"summary": "Enable TLS on the service (or put it behind a TLS terminator) and refuse plaintext.", "steps": TLS_MIN12},
      verify=V_DB_TLS, references=[])
entry("PLAINTEXT_LISTENER", title="Plaintext listener alongside TLS", category="protocol", default_impact="Medium",
      description="The host also serves the same application over plaintext HTTP.",
      attack="Users or clients that land on the plaintext port send cookies and credentials in clear text; SSL-stripping attacks rely on this.",
      cwe=["CWE-319"], owasp=["crypto", "misconfig"], cves=[], standards=["RFC 6797 (HSTS)"], compliance=["in_transit"],
      remediation={"summary": "Redirect plaintext to HTTPS with a 301 and send Strict-Transport-Security, or close the plaintext port.", "steps": [
          {"platform": "nginx", "how": "server { listen 80; return 301 https://$host$request_uri; } and add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"}]},
      verify=[{"label": "Does the plaintext port answer?", "command": "curl -sI http://{host}/ | head -5"}], references=["https://www.rfc-editor.org/rfc/rfc6797"])

# --- cipher suites and handshake
entry("WEAK_CIPHER", title="Weak cipher suites accepted", category="cipher", default_impact="High",
      description="The endpoint accepts cipher suites that use RC4, single or triple DES, NULL encryption, anonymous key exchange or EXPORT-grade keys.",
      attack="Depending on the suite: RC4 biases leak plaintext; 64-bit block ciphers (3DES) allow SWEET32 birthday attacks on long sessions; EXPORT suites can be factored or broken in real time (FREAK, Logjam); anonymous suites give no server authentication at all.",
      cwe=["CWE-327", "CWE-326"], owasp=["crypto", "misconfig"], cves=[],
      cve_rules=[{"match": "(?<![a-z0-9])(?:a?rc4|arcfour)(?![0-9])", "cves": ["CVE-2013-2566", "CVE-2015-2808"]},
                 {"match": "3DES|DES-CBC3|DES_EDE|\\bDES\\b|DES-CBC", "cves": ["CVE-2016-2183"]},
                 {"match": "(?<![a-z])exp(?:ort)?(?![a-z])", "cves": ["CVE-2015-0204", "CVE-2015-4000"]}],
      standards=["RFC 7465 (prohibits RC4)", "NIST SP 800-131A Rev. 2", "NIST SP 800-52 Rev. 2"], compliance=["algorithms"],
      remediation={"summary": "Offer only ECDHE key exchange with AEAD ciphers (AES-GCM, ChaCha20-Poly1305).", "steps": TLS_CIPHERS},
      verify=V_CIPHERS, references=["https://sweet32.info/", "https://weakdh.org/"])
entry("STATIC_RSA_KEX", title="RSA key exchange without forward secrecy", category="cipher", default_impact="Medium",
      description="The endpoint accepts TLS_RSA_* suites, where the session key is encrypted with the server's long-term RSA key.",
      attack="Anyone who records traffic today and later obtains the server key (theft, legal demand or a future quantum computer) can decrypt every recorded session. Static RSA is also the precondition for Bleichenbacher/ROBOT padding oracles.",
      cwe=["CWE-327", "CWE-780"], owasp=["crypto"], cves=[], pqc="quantum-broken",
      standards=["RFC 9325 (BCP 195) prefers ECDHE", "NIST SP 800-52 Rev. 2"], compliance=["algorithms", "pqc"],
      remediation={"summary": "Remove TLS_RSA_* suites so every session uses ECDHE (forward secrecy).", "steps": TLS_CIPHERS},
      verify=V_CIPHERS, references=["https://robotattack.org/"])
entry("CBC_ONLY", title="Only CBC-mode cipher suites", category="cipher", default_impact="Medium",
      description="Every suite the endpoint offers uses CBC mode with HMAC (MAC-then-encrypt).",
      attack="MAC-then-encrypt CBC suites have a long history of padding-oracle and timing attacks (Lucky Thirteen and successors).",
      cwe=["CWE-327"], owasp=["crypto"], cves=["CVE-2013-0169"],
      standards=["RFC 9325 (BCP 195)"], compliance=["algorithms"],
      remediation={"summary": "Add AES-GCM / ChaCha20-Poly1305 suites and TLS 1.3, then drop the CBC suites.", "steps": TLS_CIPHERS},
      verify=V_CIPHERS, references=[])
entry("CBC_ACCEPTED", title="CBC-mode cipher suites still accepted", category="cipher", default_impact="Low",
      description="AEAD suites are offered, but CBC suites are still accepted for older clients.",
      attack="A client limited to CBC suites falls back to MAC-then-encrypt constructions with known timing side channels.",
      cwe=["CWE-327"], owasp=["crypto"], cves=[], standards=["RFC 9325 (BCP 195)"], compliance=["algorithms"],
      remediation={"summary": "Drop CBC suites once no client needs them.", "steps": TLS_CIPHERS}, verify=V_CIPHERS, references=[])
entry("DOWNGRADE", title="Protocol downgrade possible", category="protocol", default_impact="Medium",
      description="The endpoint can be pushed to an older protocol version than the client and server both support.",
      attack="An on-path attacker interferes with the handshake so both sides settle on the weakest common version, then uses that version's weaknesses.",
      cwe=["CWE-757"], owasp=["crypto"], cves=[], standards=["RFC 7507 (TLS_FALLBACK_SCSV)", "RFC 8446 (TLS 1.3 downgrade protection)"],
      compliance=["tls_min"], remediation={"summary": "Remove the old versions entirely; enable TLS 1.3, whose downgrade sentinel protects modern clients.", "steps": TLS_MIN12},
      verify=V_TLS_PROTO, references=["https://www.rfc-editor.org/rfc/rfc7507"])
entry("NO_FALLBACK_SCSV", title="TLS_FALLBACK_SCSV not honoured", category="protocol", default_impact="Medium",
      description="The server does not reject a fallback handshake that carries TLS_FALLBACK_SCSV.",
      attack="Clients that retry at a lower version after an injected failure can be walked down to the oldest version the server allows (POODLE-style downgrade).",
      cwe=["CWE-757"], owasp=["crypto"], cves=["CVE-2014-3566"], standards=["RFC 7507"], compliance=["tls_min"],
      remediation={"summary": "Upgrade the TLS library (OpenSSL 1.0.1j+ supports SCSV) or remove the old protocol versions.", "steps": TLS_MIN12},
      verify=[{"label": "Send a fallback handshake", "command": "openssl s_client -connect {host}:{port} -tls1_1 -fallback_scsv -cipher 'DEFAULT@SECLEVEL=0' </dev/null 2>&1 | grep -E 'alert|Protocol'"}],
      references=["https://www.rfc-editor.org/rfc/rfc7507"])
entry("NO_PQ_KEX", title="No post-quantum key exchange", category="pqc", default_impact="Low",
      description="The endpoint negotiates classical ECDHE/DHE only; no hybrid ML-KEM group (such as X25519MLKEM768) is offered.",
      attack="Traffic recorded today can be decrypted once a cryptographically relevant quantum computer exists (harvest now, decrypt later). This matters for data that must stay confidential beyond that horizon.",
      cwe=["CWE-327"], owasp=["crypto"], cves=[], pqc="quantum-broken",
      standards=["FIPS 203 (ML-KEM)", "NIST IR 8547"], compliance=["pqc"],
      remediation={"summary": "Offer a hybrid ML-KEM group first where the TLS stack supports it.", "steps": PQC_HYBRID},
      verify=[{"label": "Which group the server picks", "command": "openssl s_client -connect {host}:{port} -groups X25519MLKEM768:X25519 </dev/null 2>&1 | grep -iE 'group|Server Temp Key'"}],
      references=["https://csrc.nist.gov/pubs/fips/203/final"])
entry("SSH_NO_PQ_KEX", title="SSH has no post-quantum key exchange", category="pqc", default_impact="Low",
      description="The SSH server offers only classical key exchange (curve25519, ECDH, DH).",
      attack="Recorded SSH sessions (including file transfers and secrets typed into them) become readable once a large quantum computer exists.",
      cwe=["CWE-327"], owasp=["crypto"], cves=[], pqc="quantum-broken", standards=["FIPS 203 (ML-KEM)", "NIST IR 8547"], compliance=["pqc"],
      remediation={"summary": "Upgrade OpenSSH and prefer mlkem768x25519-sha256 or sntrup761x25519-sha512@openssh.com.", "steps": [SSH_HARDEN[0], PQC_HYBRID[1]]},
      verify=V_SSH, references=["https://www.openssh.com/pq.html"])

# --- SSH algorithms
entry("SSH_WEAK_CIPHER", title="Broken SSH ciphers offered", category="ssh", default_impact="High",
      description="The SSH server offers arcfour, 3DES, Blowfish or CAST128.",
      attack="RC4 keystream biases and 64-bit block ciphers (SWEET32) expose long-lived sessions; these ciphers exist only for compatibility with very old clients.",
      cwe=["CWE-327"], owasp=["crypto", "misconfig"], cves=[],
      cve_rules=[{"match": "3des|blowfish|cast128", "cves": ["CVE-2016-2183"]}],
      standards=["RFC 9142 (SSH key exchange guidance)", "NIST SP 800-131A Rev. 2"], compliance=["algorithms"],
      remediation={"summary": "Remove them from Ciphers.", "steps": SSH_HARDEN}, verify=V_SSH, references=[])
entry("SSH_CBC_CIPHER", title="CBC-mode SSH ciphers offered", category="ssh", default_impact="Medium",
      description="The SSH server offers *-cbc ciphers.",
      attack="CBC mode in SSH allows plaintext-recovery attacks (CVE-2008-5161) and, with Encrypt-then-MAC, the Terrapin prefix-truncation attack.",
      cwe=["CWE-327"], owasp=["crypto"], cves=["CVE-2008-5161", "CVE-2023-48795"],
      standards=["RFC 4344"], compliance=["algorithms"],
      remediation={"summary": "Use AES-GCM, ChaCha20-Poly1305 or AES-CTR only, and upgrade OpenSSH to 9.6+ for Terrapin's strict key exchange.", "steps": SSH_HARDEN},
      verify=V_SSH, references=["https://terrapin-attack.com/"])
entry("SSH_WEAK_MAC", title="Weak or truncated SSH MACs", category="ssh", default_impact="Medium",
      description="The SSH server offers hmac-md5 or truncated (-96) MACs.",
      attack="MD5 and 96-bit truncated tags weaken message integrity; they exist only for legacy clients.",
      cwe=["CWE-328", "CWE-327"], owasp=["crypto"], cves=[], standards=["RFC 6668"], compliance=["algorithms"],
      remediation={"summary": "Offer only hmac-sha2-256/512 (preferably the -etm@openssh.com variants).", "steps": SSH_HARDEN}, verify=V_SSH, references=[])
entry("SSH_UMAC64", title="64-bit UMAC tags", category="ssh", default_impact="Low",
      description="The SSH server offers umac-64 MACs, whose 64-bit tags are short for long-lived sessions.",
      attack="A short tag raises the chance of a successful forgery over very long sessions.", cwe=["CWE-327"], owasp=["crypto"], cves=[],
      standards=[], compliance=["algorithms"], remediation={"summary": "Prefer umac-128-etm or hmac-sha2-256-etm.", "steps": SSH_HARDEN}, verify=V_SSH, references=[])
entry("SSH_HMAC_SHA1", title="HMAC-SHA1 offered", category="ssh", default_impact="Low",
      description="The SSH server offers HMAC-SHA1. HMAC-SHA1 is not broken, but SHA-1 is being retired and better options exist.",
      attack="No practical attack today; it is a crypto-agility and compliance gap.", cwe=["CWE-328"], owasp=["crypto"], cves=[],
      standards=["NIST SP 800-131A Rev. 2"], compliance=["algorithms"], remediation={"summary": "Prefer hmac-sha2-256-etm@openssh.com.", "steps": SSH_HARDEN}, verify=V_SSH, references=[])
entry("SSH_DH_GROUP1", title="1024-bit Diffie-Hellman key exchange", category="ssh", default_impact="High",
      description="The SSH server offers diffie-hellman-group1-sha1 (1024-bit MODP group, SHA-1).",
      attack="1024-bit DH over a widely shared group is within reach of well-resourced attackers who precompute for that group (the Logjam research).",
      cwe=["CWE-326", "CWE-327"], owasp=["crypto"], cves=[], pqc="quantum-broken",
      standards=["RFC 9142 (marks group1 as MUST NOT)"], compliance=["algorithms", "keysize"],
      remediation={"summary": "Remove diffie-hellman-group1-sha1 from KexAlgorithms.", "steps": SSH_HARDEN}, verify=V_SSH, references=["https://weakdh.org/"])
entry("SSH_DH_SHA1", title="SHA-1 based SSH key exchange", category="ssh", default_impact="Medium",
      description="The SSH server offers diffie-hellman-group14-sha1 or group-exchange-sha1.",
      attack="SHA-1 in the key exchange hash weakens the session's integrity guarantees; RFC 9142 recommends against these methods.",
      cwe=["CWE-328"], owasp=["crypto"], cves=[], pqc="quantum-broken", standards=["RFC 9142"], compliance=["algorithms"],
      remediation={"summary": "Use curve25519-sha256 / diffie-hellman-group16-sha512 or a hybrid PQ method.", "steps": SSH_HARDEN}, verify=V_SSH, references=[])
entry("SSH_DSS", title="DSA host keys", category="ssh", default_impact="High",
      description="The SSH server offers ssh-dss host keys (1024-bit DSA). OpenSSH removed DSA support.",
      attack="1024-bit DSA is below the 112-bit security floor; a forged host key lets an attacker impersonate the server.",
      cwe=["CWE-326", "CWE-327"], owasp=["crypto"], cves=[], pqc="quantum-broken", standards=["FIPS 186-5 (DSA no longer approved for signing)"],
      compliance=["algorithms", "keysize"], remediation={"summary": "Remove the DSA host key and HostKey line; use ssh-ed25519 or rsa-sha2-512.", "steps": SSH_HARDEN}, verify=V_SSH, references=[])
entry("SSH_RSA_SHA1", title="ssh-rsa (SHA-1) signatures offered", category="ssh", default_impact="Medium",
      description="The SSH server offers the ssh-rsa signature scheme, which signs with SHA-1. OpenSSH disabled it by default in 8.8.",
      attack="SHA-1 chosen-prefix collisions are practical, which undermines signatures made with it.",
      cwe=["CWE-328", "CWE-327"], owasp=["crypto"], cves=["CVE-2005-4900"], pqc="quantum-broken", standards=["RFC 8332 (rsa-sha2-256/512)"],
      compliance=["algorithms"], remediation={"summary": "Offer rsa-sha2-256/512 and ssh-ed25519 only.", "steps": SSH_HARDEN}, verify=V_SSH, references=["https://sha-mbles.github.io/"])

# --- certificates and keys
entry("SIG_MD5", title="Certificate signed with MD5", category="certificate", default_impact="Critical",
      description="The certificate's signature uses MD5 (or MD2), for which practical collision attacks exist.",
      attack="Chosen-prefix MD5 collisions have been used to forge a rogue CA certificate; a forged certificate impersonates the service.",
      cwe=["CWE-328", "CWE-327"], owasp=["crypto"], cves=["CVE-2004-2761"], standards=["NIST SP 800-131A Rev. 2"], compliance=["algorithms", "certificates"],
      remediation={"summary": "Re-issue with a SHA-256 or stronger signature.", "steps": CERT_REISSUE}, verify=V_CERT_REMOTE + V_CERT_FILE,
      references=["https://www.win.tue.nl/hashclash/rogue-ca/"])
entry("SIG_SHA1", title="Certificate signed with SHA-1", category="certificate", default_impact="High",
      description="The certificate's signature uses SHA-1, which is no longer acceptable for digital signatures.",
      attack="SHA-1 chosen-prefix collisions are practical (SHA-1 is a Shambles, 2020), so a CA signing with SHA-1 can be tricked into vouching for an attacker's key.",
      cwe=["CWE-328", "CWE-327"], owasp=["crypto"], cves=["CVE-2005-4900"], standards=["NIST SP 800-131A Rev. 2"], compliance=["algorithms", "certificates"],
      remediation={"summary": "Re-issue with a SHA-256 or stronger signature.", "steps": CERT_REISSUE}, verify=V_CERT_REMOTE + V_CERT_FILE,
      references=["https://sha-mbles.github.io/"])
entry("RSA_LT_1024", title="RSA key below 1024 bits", category="key", default_impact="Critical",
      description="The RSA key is smaller than 1024 bits.", attack="Keys of this size can be factored with public tools on commodity hardware, which yields the private key.",
      cwe=["CWE-326"], owasp=["crypto"], cves=[], pqc="quantum-broken", standards=["NIST SP 800-131A Rev. 2"], compliance=["keysize"],
      remediation={"summary": "Replace the key with RSA-3072 or ECDSA P-256 and re-issue anything signed with it.", "steps": CERT_REISSUE}, verify=V_CERT_REMOTE + V_KEYFILE, references=[])
entry("RSA_LT_2048", title="RSA key below 2048 bits", category="key", default_impact="High",
      description="The RSA key is smaller than 2048 bits (below 112-bit security).",
      attack="RSA-1024 is within reach of well-funded attackers and is disallowed for new use; a recovered key lets an attacker impersonate or decrypt.",
      cwe=["CWE-326"], owasp=["crypto"], cves=[], pqc="quantum-broken", standards=["NIST SP 800-131A Rev. 2"], compliance=["keysize"],
      remediation={"summary": "Replace with RSA-3072 or ECDSA P-256 (and plan the move to ML-DSA / ML-KEM).", "steps": CERT_REISSUE}, verify=V_CERT_REMOTE + V_KEYFILE, references=[])
entry("EC_LT_224", title="Elliptic curve below 224 bits", category="key", default_impact="High",
      description="The elliptic-curve key uses a curve smaller than 224 bits.", attack="Small curves fall below the 112-bit security floor.",
      cwe=["CWE-326"], owasp=["crypto"], cves=[], pqc="quantum-broken", standards=["NIST SP 800-186"], compliance=["keysize"],
      remediation={"summary": "Use P-256, P-384, X25519 or Ed25519.", "steps": CERT_REISSUE}, verify=V_CERT_REMOTE + V_KEYFILE, references=[])
entry("DH_LT_2048", title="Diffie-Hellman below 2048 bits", category="key", default_impact="High",
      description="The server's Diffie-Hellman group is smaller than 2048 bits.",
      attack="Common 1024-bit and export-grade groups can be broken by precomputation (Logjam); recorded sessions can then be decrypted.",
      cwe=["CWE-326"], owasp=["crypto"], cves=["CVE-2015-4000"], pqc="quantum-broken", standards=["NIST SP 800-131A Rev. 2", "RFC 7919"],
      compliance=["keysize"], remediation={"summary": "Prefer ECDHE; if DHE is required use ffdhe2048+ (RFC 7919) groups.", "steps": TLS_CIPHERS},
      verify=V_CIPHERS, references=["https://weakdh.org/"])
entry("DSA", title="DSA key", category="key", default_impact="High", description="The key or certificate uses DSA, which FIPS 186-5 no longer approves for generating signatures.",
      attack="DSA is fragile (a biased or repeated nonce leaks the private key) and is being removed from major stacks.",
      cwe=["CWE-327"], owasp=["crypto"], cves=[], pqc="quantum-broken", standards=["FIPS 186-5"], compliance=["algorithms"],
      remediation={"summary": "Move to ECDSA/Ed25519 (and ML-DSA when your stack supports it).", "steps": CERT_REISSUE}, verify=V_KEYFILE, references=[])
entry("CERT_EXPIRED", title="Certificate expired", category="certificate", default_impact="High",
      description="The certificate's validity period has ended.",
      attack="Clients either fail closed (an outage) or are configured to ignore validation errors, which removes protection against impersonation.",
      cwe=["CWE-298", "CWE-324"], owasp=["crypto", "misconfig"], cves=[], standards=[], compliance=["certificates"],
      remediation={"summary": "Renew and deploy a new certificate; automate renewal (ACME, ACM, cert-manager).", "steps": CERT_REISSUE},
      verify=V_CERT_REMOTE + V_CERT_FILE, references=[])
entry("CERT_EXPIRES_30D", title="Certificate expires within 30 days", category="certificate", default_impact="Medium",
      description="The certificate expires soon.", attack="An unplanned expiry causes an outage or pushes teams to disable validation.",
      cwe=["CWE-298"], owasp=["misconfig"], cves=[], standards=[], compliance=["certificates"],
      remediation={"summary": "Renew now and automate renewal.", "steps": CERT_REISSUE}, verify=V_CERT_REMOTE + V_CERT_FILE, references=[])
entry("CERT_SELF_SIGNED", title="Self-signed certificate", category="certificate", default_impact="Low",
      description="The certificate is signed by its own key rather than a CA the clients trust.",
      attack="Clients must either pin it or skip validation; skipped validation allows man-in-the-middle impersonation.",
      cwe=["CWE-295"], owasp=["crypto", "auth"], cves=[], standards=[], compliance=["certificates"],
      remediation={"summary": "Issue it from your internal or public CA and distribute that CA to clients.", "steps": CERT_REISSUE}, verify=V_CERT_REMOTE + V_CERT_FILE, references=[])
entry("CERT_UNUSED", title="Certificate not attached to any resource", category="certificate", default_impact="Low",
      description="The certificate exists in a store or CA inventory but is not deployed anywhere (orphaned). Not raised for a certificate that was never issued, an AWS Private CA (PRIVATE) certificate, a certificate whose key was exported, or an ACME-issued one: those are used or managed outside what the store can see.",
      attack="Orphaned certificates with live private keys are unmanaged credentials: if the key leaks, the certificate can still be used to impersonate the name.",
      cwe=["CWE-320"], owasp=["crypto"], cves=[], standards=["NIST SP 800-57 Part 1"], compliance=["key_mgmt"],
      remediation={"summary": "Delete or revoke certificates nobody owns.", "steps": [{"platform": "AWS ACM", "how": "aws acm delete-certificate --certificate-arn {resource}"}]},
      verify=[{"label": "Where the certificate is used", "command": "aws acm describe-certificate --certificate-arn {resource} --query Certificate.InUseBy"}], references=[])
entry("KEY_WORLD_READABLE", title="Private key readable by every user", category="key", default_impact="High",
      description="An unencrypted private key file is readable by every local account.",
      attack="Any local user or compromised service account can copy the key and impersonate or decrypt for the service that owns it.",
      cwe=["CWE-732", "CWE-522"], owasp=["crypto", "access"], cves=[], standards=["NIST SP 800-57 Part 1"], compliance=["key_mgmt"],
      remediation={"summary": "Restrict the file to its service account and rotate the key, because it may already have been copied.", "steps": [
          {"platform": "Linux", "how": "chown <service>:<service> '{path}' && chmod 600 '{path}'; then re-issue the certificate with a new key"}]},
      verify=V_KEYFILE, references=[])
entry("KEY_READABLE", title="Private key readable without root", category="key", default_impact="Medium",
      description="An unencrypted private key file is readable by the scanner's unprivileged account.",
      attack="Any account with the same access can copy the key.", cwe=["CWE-732"], owasp=["crypto", "access"], cves=[],
      standards=["NIST SP 800-57 Part 1"], compliance=["key_mgmt"],
      remediation={"summary": "Make the key readable only by the service that uses it (mode 600).", "steps": [{"platform": "Linux", "how": "chmod 600 '{path}' && chown <service> '{path}'"}]},
      verify=V_KEYFILE, references=[])
entry("KEY_IN_DOCUMENT", title="Private key inside a non-key file", category="key", default_impact="Medium",
      description="A PEM private key is embedded in a document, script or configuration file.",
      attack="Keys pasted into documents spread through backups, tickets and repositories and are rarely rotated.",
      cwe=["CWE-312", "CWE-321"], owasp=["crypto"], cves=[], standards=["NIST SP 800-57 Part 1"], compliance=["key_mgmt"],
      remediation={"summary": "Move the key to a key store or secrets manager, delete it from the document and rotate it.", "steps": []},
      verify=[{"label": "Find the key block without printing it", "command": "grep -n 'PRIVATE KEY-----' '{path}'"}], references=[])
entry("KEY_IN_CONFIGMAP", title="Private key in a Kubernetes ConfigMap", category="kubernetes", default_impact="High",
      description="A PEM private key is stored in plain text in a ConfigMap, which is not meant for secrets.",
      attack="Anyone who can read ConfigMaps in the namespace (often far more people and controllers than can read Secrets) gets the private key.",
      cwe=["CWE-312", "CWE-522"], owasp=["crypto", "access"], cves=[], standards=["NIST SP 800-57 Part 1"], compliance=["key_mgmt"],
      remediation={"summary": "Move it to a kubernetes.io/tls Secret (or an external secret store), restrict RBAC, enable Secret encryption at rest, then rotate the key.", "steps": [
          {"platform": "kubectl", "how": "kubectl create secret tls <name> --cert=tls.crt --key=tls.key -n <namespace>; then remove the key from the ConfigMap"}]},
      verify=[{"label": "Which keys the ConfigMap holds (names only)", "command": "kubectl get configmap -n <namespace> <name> -o jsonpath='{.data}' | grep -c 'PRIVATE KEY'"}], references=[])
entry("KEYSTORE_JKS", title="JKS keystore format", category="key", default_impact="Low",
      description="A Java KeyStore in the legacy JKS format, whose integrity protection is weak.",
      attack="JKS protects private keys with a weak proprietary scheme; a stolen keystore is easier to brute-force than PKCS#12.",
      cwe=["CWE-327"], owasp=["crypto"], cves=[], standards=[], compliance=["key_mgmt"],
      remediation={"summary": "Convert to PKCS#12.", "steps": [{"platform": "keytool", "how": "keytool -importkeystore -srckeystore '{path}' -destkeystore new.p12 -deststoretype pkcs12"}]},
      verify=[{"label": "Keystore type", "command": "keytool -list -keystore '{path}' -storepass:env STOREPASS | head -3"}], references=[])
entry("QUANTUM_VULNERABLE", title="Quantum-vulnerable algorithm", category="pqc", default_impact="Low",
      description="The asset relies on RSA, elliptic-curve or Diffie-Hellman cryptography, which Shor's algorithm breaks on a large quantum computer.",
      attack="Data encrypted with these keys can be recorded now and decrypted later (harvest now, decrypt later); signatures can be forged once such a computer exists.",
      cwe=["CWE-327"], owasp=["crypto"], cves=[], pqc="quantum-broken", standards=["NIST IR 8547", "FIPS 203/204/205"], compliance=["pqc"],
      remediation={"summary": "Add it to the PQC migration plan; prioritise by the Mosca score.", "steps": PQC_HYBRID}, verify=[], references=["https://csrc.nist.gov/pubs/ir/8547/ipd"])

# --- host crypto configuration
entry("POLICY_LEGACY", title="System crypto policy is LEGACY", category="host", default_impact="High",
      description="The host-wide crypto policy (RHEL, Fedora, Amazon Linux) is set to LEGACY, which re-enables TLS 1.0/1.1, SHA-1 and small keys for every service.",
      attack="Every service that follows the system policy (OpenSSL, GnuTLS, NSS, OpenSSH, Java) accepts legacy algorithms at once.",
      cwe=["CWE-327", "CWE-1188"], owasp=["crypto", "misconfig"], cves=[], standards=["NIST SP 800-131A Rev. 2"], compliance=["algorithms"],
      remediation={"summary": "Set the policy to DEFAULT (or FUTURE) and reload services.", "steps": [{"platform": "RHEL / AL2023", "how": "update-crypto-policies --set DEFAULT && reboot"}]},
      verify=[{"label": "Current policy", "command": "update-crypto-policies --show"}], references=[])
entry("DOTNET_WEAK_TLS", title=".NET Framework strong cryptography is disabled", category="host", default_impact="Medium",
      description="SchUseStrongCrypto is 0 for .NET Framework 4.x on this Windows host, so .NET applications that do not pick their own protocol may still offer SSL 3.0 and TLS 1.0 and accept RC4 suites.",
      attack="A man-in-the-middle can downgrade connections made by .NET applications (web service clients, LOB apps) to TLS 1.0 or SSL 3.0 and attack the weaker protocol (POODLE, BEAST, RC4 biases).",
      cwe=["CWE-327", "CWE-757"], owasp=["crypto", "misconfig"], cves=["CVE-2014-3566"], standards=["NIST SP 800-52 Rev. 2"], compliance=["tls_min"],
      remediation={"summary": "Set SchUseStrongCrypto=1 and SystemDefaultTlsVersions=1 for .NET Framework 4.x (64-bit and WOW6432Node), then restart the applications.", "steps": [
          {"platform": "Windows (PowerShell, elevated)", "how": "foreach ($k in 'HKLM:\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319','HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\.NETFramework\\v4.0.30319') { Set-ItemProperty $k SchUseStrongCrypto 1 -Type DWord; Set-ItemProperty $k SystemDefaultTlsVersions 1 -Type DWord }"},
          {"platform": "Group Policy", "how": "Deploy the same two DWORD values with Group Policy Preferences > Registry"}]},
      verify=[{"label": "Current values", "command": "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319' | Select-Object SchUseStrongCrypto,SystemDefaultTlsVersions"}],
      references=["https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls"])
entry("SECRET_IN_CONFIG", title="Key or passphrase in plain text in a service, script or cloud configuration", category="host", default_impact="High",
      description="An encryption key, private key or passphrase is written in clear text in a service definition (systemd Environment=), a cron job or a script, or in cloud configuration (a Lambda environment variable, an ECS task definition environment entry, EC2 user data), where anyone who can read the file or the configuration (often every local user, or any principal with read-only Describe/List access) or its backups can copy it.",
      attack="Read the unit file, crontab or script (or `systemctl show`, which any local user may run) and use the key to decrypt the data it protects; it also travels with every backup and configuration-management copy.",
      cwe=["CWE-798", "CWE-312"], owasp=["crypto", "misconfig"], cves=[], standards=["NIST SP 800-57 Part 1 Rev. 5 (key protection)"], compliance=["key_mgmt"],
      remediation={"summary": "Move the value to a secret store and give it to the service at run time; rotate it, because the old value is exposed.", "steps": [
          {"platform": "systemd", "how": "Use LoadCredential= / LoadCredentialEncrypted= (systemd-creds encrypt) or an EnvironmentFile= readable only by root and the service user (chmod 600), then systemctl daemon-reload && systemctl restart <unit>"},
          {"platform": "cron / scripts", "how": "Read the passphrase from a root-only file (openssl enc ... -pass file:/etc/<app>/backup.pass) or from the secret manager; never put it on the command line, where ps shows it"},
          {"platform": "AWS (Lambda / ECS / EC2 user data)", "how": "Store the value in Secrets Manager or an SSM SecureString; in ECS reference it from the container's secrets (valueFrom) instead of environment; in Lambda read it at run time with the SDK or the Parameters and Secrets extension; in user data fetch it at boot with the instance role (aws secretsmanager get-secret-value) instead of embedding it"},
          {"platform": "Rotation", "how": "Generate a new key, re-encrypt the data, then revoke the old value everywhere it was copied"}]},
      verify=[{"label": "Which units carry secrets", "command": "systemctl show --type=service --state=running -p Id -p Environment '*' | grep -iE 'key|secret|pass|token'"},
              {"label": "Who can read the unit", "command": "stat -c '%a %U %G %n' /etc/systemd/system/*.service"},
              {"label": "Lambda variable names (not values)", "command": "aws lambda get-function-configuration --function-name <fn> --query 'keys(Environment.Variables)'"},
              {"label": "ECS environment names", "command": "aws ecs describe-task-definition --task-definition <family:rev> --query 'taskDefinition.containerDefinitions[].environment[].name'"}],
      references=["https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#Credentials"])
entry("TLS_POLICY_OVERRIDE", title="A service overrides the crypto policy to allow legacy algorithms", category="host", default_impact="High",
      description="A per-service OpenSSL configuration (OPENSSL_CONF with SECLEVEL=0 or MinProtocol below TLS 1.2) or a Java security override (empty jdk.tls.disabledAlgorithms) re-enables protocols and algorithms the system policy forbids, for that service only, where a host-level check does not see it.",
      attack="The service accepts SSL 3.0 / TLS 1.0, RC4, 3DES, export or anonymous suites and small keys again, so an on-path attacker can downgrade and attack its connections (POODLE, BEAST, Sweet32, Logjam).",
      cwe=["CWE-327", "CWE-757"], owasp=["crypto", "misconfig"], cves=["CVE-2014-3566", "CVE-2016-2183"], standards=["NIST SP 800-52 Rev. 2"], compliance=["tls_min"],
      remediation={"summary": "Remove the override so the service follows the system policy, or set it to TLS 1.2+ with SECLEVEL 2 and a non-empty disabled-algorithms list.", "steps": [
          {"platform": "OpenSSL (OPENSSL_CONF)", "how": "In the [system_default_sect] of the override: MinProtocol = TLSv1.2 and CipherString = DEFAULT@SECLEVEL=2; or drop OPENSSL_CONF from the unit"},
          {"platform": "Java", "how": "Remove -Djava.security.properties=..., or keep jdk.tls.disabledAlgorithms = SSLv3, TLSv1, TLSv1.1, RC4, DES, MD5withRSA, DH keySize < 1024, EC keySize < 224, 3DES_EDE_CBC, anon, NULL"},
          {"platform": "systemd", "how": "systemctl daemon-reload && systemctl restart <unit>"}]},
      verify=[{"label": "Effective OpenSSL settings for the service", "command": "systemctl show -p Environment <unit>; grep -nE 'MinProtocol|CipherString' <openssl.cnf>"},
              {"label": "Java override", "command": "systemctl show -p ExecStart <unit> | grep -o 'java.security.properties=[^ ]*'"}],
      references=["https://docs.openssl.org/3.0/man3/SSL_CTX_set_security_level/", "https://www.java.com/en/configure_crypto.html"])
entry("OPENSSL_ENC_WEAK_KDF", title="openssl enc derives the key from a passphrase with one MD5/SHA-256 round", category="host", default_impact="Medium",
      description="An `openssl enc` call without -pbkdf2 derives the key with EVP_BytesToKey (a single MD5 or SHA-256 round, plus -md md5 here), so the passphrase can be brute-forced at billions of guesses per second, and without -pbkdf2 the ciphertext also carries no authentication.",
      attack="Take an encrypted backup and run a GPU password cracker against the passphrase; a weak cipher (DES/3DES/RC4) makes even a strong passphrase weaker.",
      cwe=["CWE-916", "CWE-327"], owasp=["crypto"], cves=[], standards=["NIST SP 800-132 (PBKDF)"], compliance=["algorithms"],
      remediation={"summary": "Use -aes-256-cbc with -pbkdf2 -iter 600000 (or age / gpg --symmetric with a long passphrase) and read the passphrase from a root-only file.", "steps": [
          {"platform": "openssl 1.1.1+", "how": "openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -pass file:/etc/<app>/backup.pass -in in -out in.enc"},
          {"platform": "Better", "how": "age -p / age -r <recipient> (authenticated encryption), or gpg --symmetric --cipher-algo AES256 --s2k-count 65011712"}]},
      verify=[{"label": "Find openssl enc calls", "command": "grep -rnE 'openssl[[:space:]]+enc' /etc/cron.d /etc/crontab /usr/local/bin"}],
      references=["https://docs.openssl.org/3.0/man1/openssl-enc/"])
entry("LIB_EOL", title="End-of-life crypto library", category="library", default_impact="High",
      description="The crypto library version is past its upstream end of support, so new vulnerabilities are not fixed upstream.",
      attack="Unpatched library flaws (memory corruption, side channels) stay exploitable; check whether your OS vendor still backports fixes.",
      cwe=["CWE-1104", "CWE-1395"], owasp=["components"], cves=[], standards=[], compliance=["components"],
      remediation={"summary": "Upgrade to a supported release (OpenSSL 3.5 LTS) or confirm the OS vendor's extended support.", "steps": [
          {"platform": "Ubuntu/Debian", "how": "apt-get update && apt-get install --only-upgrade openssl libssl3"},
          {"platform": "RHEL/AL2023", "how": "dnf upgrade openssl openssl-libs"}]},
      verify=[{"label": "Installed version", "command": "openssl version -a | head -2"}], references=["https://openssl-library.org/policies/releasestrat/index.html"])
entry("LIB_DELETED_IN_USE", title="Process still uses a deleted crypto library", category="library", default_impact="Medium",
      description="A running process has an old crypto library mapped that was deleted or replaced by a package upgrade.",
      attack="The patch is installed on disk but not running: the process is still exposed to the flaws the upgrade fixed.",
      cwe=["CWE-1395"], owasp=["components"], cves=[], standards=[], compliance=["components"],
      remediation={"summary": "Restart the process (or the host) so it loads the patched library.", "steps": [{"platform": "Linux", "how": "systemctl restart <service>; `needrestart -r l` lists every affected service"}]},
      verify=[{"label": "Processes mapping deleted libraries", "command": "sudo grep -l '(deleted)' /proc/*/maps 2>/dev/null | xargs -r grep -H 'libcrypto\\|libssl' | grep deleted"}], references=[])
entry("LIB_STATIC", title="Crypto statically linked", category="library", default_impact="Low",
      description="The binary carries its own copy of a crypto library.", attack="OS library updates do not reach it; it must be rebuilt to get fixes.",
      cwe=["CWE-1329"], owasp=["components"], cves=[], standards=[], compliance=["components"],
      remediation={"summary": "Track the embedded version and rebuild when it is vulnerable.", "steps": []}, verify=[], references=[])
entry("DISK_UNENCRYPTED", title="Volume not encrypted", category="disk", default_impact="Medium", description="The block device holds a filesystem with no encryption layer.",
      attack="A stolen disk, snapshot or decommissioned drive exposes all data on it.", cwe=["CWE-311"], owasp=["crypto"], cves=[], standards=[], compliance=["at_rest"],
      remediation={"summary": "Encrypt the volume (LUKS2 on Linux, BitLocker on Windows, provider encryption in the cloud).", "steps": []},
      verify=[{"label": "Block devices and encryption layers", "command": "lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT"}], references=[])
entry("DISK_CBC", title="Disk encryption in CBC mode", category="disk", default_impact="Medium", description="The dm-crypt volume uses a CBC mode cipher instead of XTS.",
      attack="CBC with predictable IVs allows watermarking and malleability attacks on disk blocks.", cwe=["CWE-329", "CWE-327"], owasp=["crypto"], cves=[], standards=["NIST SP 800-38E (XTS-AES)"],
      compliance=["at_rest"], remediation={"summary": "Re-encrypt with aes-xts-plain64 and a 512-bit key (cryptsetup reencrypt).", "steps": []},
      verify=[{"label": "dm-crypt cipher", "command": "sudo dmsetup table --target crypt"}], references=[])
entry("DISK_XTS_128", title="AES-XTS with a 128-bit key", category="disk", default_impact="Low", description="The volume uses AES-128 in XTS mode (a 256-bit XTS key).",
      attack="AES-128 is still secure today; under Grover's algorithm its margin drops, so long-lived data prefers AES-256.", cwe=["CWE-326"], owasp=["crypto"], cves=[],
      pqc="grover-weakened", standards=["CNSA 2.0 (AES-256)"], compliance=["at_rest", "pqc"],
      remediation={"summary": "Use aes-xts-plain64 with a 512-bit key for new volumes.", "steps": []}, verify=[{"label": "dm-crypt cipher", "command": "sudo dmsetup table --target crypt"}], references=[])
entry("LUKS1", title="LUKS1 header", category="disk", default_impact="Low", description="The volume uses the LUKS1 format (PBKDF2 key slots).",
      attack="PBKDF2 key slots are cheaper to brute-force than LUKS2's Argon2id if the passphrase is weak.", cwe=["CWE-916"], owasp=["crypto"], cves=[], standards=[],
      compliance=["at_rest"], remediation={"summary": "Convert to LUKS2 (cryptsetup convert --type luks2) and re-add key slots with Argon2id.", "steps": []},
      verify=[{"label": "LUKS version", "command": "sudo cryptsetup luksDump /dev/<device> | head -3"}], references=[])

# --- databases
entry("DB_NO_TLS", title="Database does not offer TLS", category="database", default_impact="High", description="The database accepts only plaintext connections.",
      attack="Queries, results and (for some auth methods) passwords cross the network in clear text.", cwe=["CWE-319"], owasp=["crypto"], cves=[], standards=[], compliance=["in_transit"],
      remediation={"summary": "Enable TLS on the server and require it.", "steps": [{"platform": k, "how": v} for k, v in DB_TLS.items()]}, verify=V_DB_TLS, references=[])
entry("DB_TLS_OPTIONAL", title="Database also accepts unencrypted connections", category="database", default_impact="Medium", description="TLS is offered but not required.",
      attack="Clients that do not ask for TLS (or are downgraded) send data and credentials in clear text.", cwe=["CWE-319", "CWE-757"], owasp=["crypto", "misconfig"], cves=[], standards=[],
      compliance=["in_transit"], remediation={"summary": "Require TLS for every remote connection.", "steps": [{"platform": k, "how": v} for k, v in DB_TLS.items()]}, verify=V_DB_TLS, references=[])
entry("DB_TLS_MODE", title="Weak database TLS mode", category="database", default_impact="Medium", description="The database's TLS mode allows plaintext or skips client checks.",
      attack="Clients can connect without TLS.", cwe=["CWE-319"], owasp=["crypto", "misconfig"], cves=[], standards=[], compliance=["in_transit"],
      remediation={"summary": "Use requireTLS / require_secure_transport.", "steps": [{"platform": k, "how": v} for k, v in DB_TLS.items()]}, verify=V_DB_TLS, references=[])
entry("DB_TRUST", title="Database lets clients in without a password", category="database", default_impact="Critical",
      description="An HBA rule (PostgreSQL trust) admits matching clients with no authentication.", attack="Anyone who can reach the port from a matching address logs in as any role the rule allows.",
      cwe=["CWE-306", "CWE-287"], owasp=["auth", "misconfig"], cves=[], standards=[], compliance=["auth"],
      remediation={"summary": "Replace trust with scram-sha-256 (hostssl) in pg_hba.conf and reload.", "steps": [{"platform": "postgres", "how": "hostssl all all <cidr> scram-sha-256; then SELECT pg_reload_conf();"}]},
      verify=V_PG, references=[])
entry("DB_NO_AUTH", title="Database accepts connections without a password", category="database", default_impact="High", description="The server allows unauthenticated access.",
      attack="Anyone who can reach the port can read or change data.", cwe=["CWE-306"], owasp=["auth", "misconfig"], cves=[], standards=[], compliance=["auth"],
      remediation={"summary": "Enable authentication (requirepass/ACL users for Redis, security.authorization for MongoDB).", "steps": []}, verify=V_DB_TLS, references=[])
entry("DB_CLEARTEXT_PW", title="Passwords sent in clear text", category="database", default_impact="High", description="An HBA rule uses the 'password' method, which sends the password unhashed.",
      attack="On a non-TLS connection anyone on the path reads the password.", cwe=["CWE-319", "CWE-522"], owasp=["crypto", "auth"], cves=[], standards=[], compliance=["auth", "in_transit"],
      remediation={"summary": "Use scram-sha-256 with hostssl.", "steps": [{"platform": "postgres", "how": "Change the rule's method to scram-sha-256 and its type to hostssl"}]}, verify=V_PG, references=[])
entry("DB_WEAK_HASH", title="Weak password hashing (MD5)", category="database", default_impact="Medium",
      description="Authentication rules or stored hashes use MD5, which PostgreSQL has deprecated in favour of SCRAM-SHA-256.",
      attack="An MD5 hash (salted only with the user name) can be replayed as the password itself and is cheap to brute-force.", cwe=["CWE-916", "CWE-328"], owasp=["crypto", "auth"], cves=[],
      standards=["RFC 7677 (SCRAM-SHA-256)"], compliance=["auth"],
      remediation={"summary": "Set password_encryption = scram-sha-256, have users reset their passwords, then change md5 rules to scram-sha-256.", "steps": []}, verify=V_PG, references=[])
entry("DB_MD5_DEFAULT", title="New passwords stored as MD5", category="database", default_impact="Medium", description="password_encryption is md5, so every new or changed password is stored as an MD5 hash.",
      attack="An MD5 password hash (salted only with the user name) can be replayed as the password itself and is cheap to brute-force once read from the database or a backup.", cwe=["CWE-916", "CWE-328"], owasp=["crypto", "auth"], cves=[], standards=["RFC 7677"], compliance=["auth"],
      remediation={"summary": "ALTER SYSTEM SET password_encryption = 'scram-sha-256'; SELECT pg_reload_conf(); then reset passwords.", "steps": []}, verify=V_PG, references=[])
entry("DB_NATIVE_PW", title="mysql_native_password accounts", category="database", default_impact="Medium",
      description="Accounts authenticate with mysql_native_password, a SHA-1 based plugin deprecated in MySQL 8.0 and disabled by default in 8.4.",
      attack="The stored double-SHA-1 hash is fast to brute-force if the mysql.user table leaks.", cwe=["CWE-916", "CWE-328"], owasp=["crypto", "auth"], cves=[], standards=[], compliance=["auth"],
      remediation={"summary": "ALTER USER '<user>'@'<host>' IDENTIFIED WITH caching_sha2_password BY '<new password>';", "steps": []}, verify=V_MYSQL, references=[])
entry("DB_OLD_PASSWORD", title="mysql_old_password accounts", category="database", default_impact="Critical", description="Accounts use the pre-4.1 password hash, which is trivially broken.",
      attack="The hash can be cracked instantly.", cwe=["CWE-916", "CWE-328"], owasp=["crypto", "auth"], cves=[], standards=[], compliance=["auth"],
      remediation={"summary": "Re-create the accounts with caching_sha2_password.", "steps": []}, verify=V_MYSQL, references=[])
entry("DB_NO_TDE", title="No tables encrypted at rest", category="database", default_impact="Low", description="No InnoDB tables are encrypted and no keyring component is loaded.",
      attack="Data files, backups and replicas expose table contents to anyone who copies them.", cwe=["CWE-311"], owasp=["crypto"], cves=[], standards=[], compliance=["at_rest"],
      remediation={"summary": "Load a keyring component and set default_table_encryption = ON, then ALTER TABLE ... ENCRYPTION='Y' for sensitive tables.", "steps": []}, verify=V_MYSQL, references=[])

# --- Kubernetes and mesh
entry("MESH_MTLS_OFF", title="Service mesh mTLS disabled", category="kubernetes", default_impact="High", description="A PeerAuthentication policy turns mutual TLS off.",
      attack="Pod-to-pod traffic is plaintext and unauthenticated inside the cluster.", cwe=["CWE-319", "CWE-306"], owasp=["crypto", "misconfig"], cves=[], standards=[], compliance=["in_transit"],
      remediation={"summary": "Set mtls.mode: STRICT on the namespace or mesh-wide PeerAuthentication.", "steps": []},
      verify=[{"label": "Mesh policies", "command": "kubectl get peerauthentication -A -o yaml | grep -A1 mtls"}], references=[])
entry("MESH_MTLS_PERMISSIVE", title="Service mesh mTLS permissive", category="kubernetes", default_impact="Medium", description="mTLS is PERMISSIVE, so plaintext is still accepted.",
      attack="Workloads outside the mesh (or a downgraded client) talk plaintext.", cwe=["CWE-319"], owasp=["crypto", "misconfig"], cves=[], standards=[], compliance=["in_transit"],
      remediation={"summary": "Move to STRICT once every client has a sidecar.", "steps": []}, verify=[{"label": "Mesh policies", "command": "kubectl get peerauthentication -A"}], references=[])

# --- cloud
entry("KMS_NO_ROTATION", title="KMS key rotation off", category="cloud", default_impact="Medium", description="A customer-managed symmetric KMS key whose material AWS KMS generated has automatic rotation disabled. Keys with imported material or in a custom key store cannot rotate automatically and are not reported; a multi-Region replica takes its rotation from its primary key.",
      attack="A key that never rotates protects more data for longer, so any compromise exposes more.", cwe=["CWE-324", "CWE-320"], owasp=["crypto"], cves=[], standards=["NIST SP 800-57 Part 1 (cryptoperiods)"],
      compliance=["key_mgmt"], remediation={"summary": "aws kms enable-key-rotation --key-id {resource}", "steps": []},
      verify=[{"label": "Rotation status", "command": "aws kms get-key-rotation-status --key-id {resource}"}], references=[])
entry("KMS_PENDING_DELETION", title="KMS key pending deletion", category="cloud", default_impact="Low", description="The KMS key is scheduled for deletion.",
      attack="Data still encrypted under it becomes unrecoverable when the key is deleted.", cwe=["CWE-320"], owasp=["crypto"], cves=[], standards=[], compliance=["key_mgmt"],
      remediation={"summary": "Cancel deletion if anything still uses it: aws kms cancel-key-deletion --key-id {resource}", "steps": []},
      verify=[{"label": "Key state", "command": "aws kms describe-key --key-id {resource} --query KeyMetadata.KeyState"}], references=[])
entry("KMS_KEY_MATERIAL_EXPIRES", title="Imported KMS key material expires soon", category="cloud", default_impact="Medium",
      description="A KMS key with imported key material (origin EXTERNAL) has material that expires within 30 days, or has expired. When the current material expires, AWS KMS deletes it and the key stops working until material is imported again.",
      attack="Not an attack path: an outage. Every encrypt and decrypt call under the key fails once its material expires, and data encrypted under it cannot be read until the same material is re-imported.",
      cwe=["CWE-320"], owasp=["crypto"], cves=[], standards=["NIST SP 800-57 Part 1 (cryptoperiods)"], compliance=["key_mgmt"],
      remediation={"summary": "Re-import the same key material with a later expiry (or no expiry) before it expires.", "steps": [
          {"platform": "AWS KMS", "how": "aws kms get-parameters-for-import --key-id {resource} --wrapping-algorithm RSAES_OAEP_SHA_256 --wrapping-key-spec RSA_4096, wrap the same material, then aws kms import-key-material --key-id {resource} --encrypted-key-material fileb://material.bin --import-token fileb://token.bin --expiration-model KEY_MATERIAL_DOES_NOT_EXPIRE"}]},
      verify=[{"label": "Expiry of each material", "command": "aws kms list-key-rotations --key-id {resource} --include-key-material ALL_KEY_MATERIAL"}], references=[])
entry("KMS_KEY_NO_MATERIAL", title="KMS key has no usable imported material", category="cloud", default_impact="Medium",
      description="A KMS key with imported key material (origin EXTERNAL) is in the PendingImport state: its material was never imported, expired or was deleted, so the key cannot encrypt or decrypt.",
      attack="Not an attack path: an outage. Anything that encrypts or decrypts under the key fails, and data encrypted under it cannot be read until the same material is imported again.",
      cwe=["CWE-320"], owasp=["crypto"], cves=[], standards=[], compliance=["key_mgmt"],
      remediation={"summary": "Import the key material again (the same material, to read existing data), or schedule the key's deletion if nothing uses it.", "steps": [
          {"platform": "AWS KMS", "how": "aws kms get-parameters-for-import --key-id {resource} --wrapping-algorithm RSAES_OAEP_SHA_256 --wrapping-key-spec RSA_4096, wrap the material, then aws kms import-key-material --key-id {resource} --key-material-id <id from the finding> --encrypted-key-material fileb://material.bin --import-token fileb://token.bin"}]},
      verify=[{"label": "Key state", "command": "aws kms describe-key --key-id {resource} --query KeyMetadata.KeyState"}], references=[])
entry("SECRET_NO_ROTATION", title="Secret rotation off", category="cloud", default_impact="Low", description="A Secrets Manager secret has no rotation configured.",
      attack="A leaked secret stays valid indefinitely.", cwe=["CWE-324"], owasp=["crypto"], cves=[], standards=[], compliance=["key_mgmt"],
      remediation={"summary": "Configure rotation with a rotation Lambda.", "steps": []}, verify=[{"label": "Rotation", "command": "aws secretsmanager describe-secret --secret-id {resource} --query RotationEnabled"}], references=[])
entry("SECRET_PLAINTEXT_PARAM", title="Secret stored as a plain String parameter", category="cloud", default_impact="High",
      description="An SSM Parameter Store entry whose name marks it as a key, password, token or certificate key is a plain String, not a SecureString: its value is stored and returned unencrypted.",
      attack="Anyone with ssm:GetParameter (or read access to CloudTrail data events, backups or logs that echo it) reads the secret in clear text; KMS key policies and audit of decryption do not apply.",
      cwe=["CWE-312"], owasp=["crypto", "misconfig"], cves=[], standards=[], compliance=["key_mgmt", "at_rest"],
      remediation={"summary": "Recreate the parameter as a SecureString encrypted with a customer-managed KMS key, rotate the secret, and restrict ssm:GetParameter to the workloads that need it.",
                   "steps": [{"platform": "AWS CLI", "how": "aws ssm put-parameter --name {name} --type SecureString --key-id <kms-key> --overwrite --value <new secret>"}]},
      verify=[{"label": "Parameter type (metadata only)", "command": "aws ssm describe-parameters --parameter-filters Key=Name,Values={name} --query Parameters[].Type"}], references=[])
entry("STORAGE_UNENCRYPTED", title="Storage not encrypted at rest", category="cloud", default_impact="High", description="The storage resource has no default encryption.",
      attack="Snapshots, copies and misconfigured access expose the data unencrypted.", cwe=["CWE-311"], owasp=["crypto"], cves=[], standards=[], compliance=["at_rest"],
      remediation={"summary": "Enable default encryption (SSE-KMS) and re-encrypt existing data.", "steps": []}, verify=[], references=[])
entry("STORAGE_NO_TLS_ONLY", title="Bucket allows non-TLS requests", category="cloud", default_impact="Medium", description="The bucket policy does not deny requests made without TLS (aws:SecureTransport).",
      attack="Clients that use plain HTTP endpoints send data and signed requests in clear text.", cwe=["CWE-319"], owasp=["crypto", "misconfig"], cves=[], standards=[], compliance=["in_transit"],
      remediation={"summary": "Add a Deny statement with Condition {\"Bool\": {\"aws:SecureTransport\": \"false\"}}.", "steps": []},
      verify=[{"label": "Bucket policy", "command": "aws s3api get-bucket-policy --bucket {name}"}], references=[])
entry("EBS_DEFAULT_OFF", title="EBS encryption by default is off", category="cloud", default_impact="Medium", description="New EBS volumes in this region are not encrypted unless someone asks.",
      attack="Unencrypted volumes and their snapshots expose data.", cwe=["CWE-311", "CWE-1188"], owasp=["crypto", "misconfig"], cves=[], standards=[], compliance=["at_rest"],
      remediation={"summary": "aws ec2 enable-ebs-encryption-by-default --region <region>", "steps": []},
      verify=[{"label": "Default", "command": "aws ec2 get-ebs-encryption-by-default"}], references=[])
entry("SAML_METADATA_UNSIGNED", title="SAML metadata not signed", category="identity", default_impact="Low", description="The identity provider's SAML metadata document carries no signature.",
      attack="A tampered metadata document (on an untrusted channel) could swap in an attacker's signing certificate.", cwe=["CWE-347"], owasp=["integrity"], cves=[], standards=[], compliance=["certificates"],
      remediation={"summary": "Publish signed metadata or exchange it over an authenticated channel and pin the signing certificate.", "steps": []}, verify=[], references=[])


# --- code-scan (aibom) codes
entry("WEAK_ALGORITHM", title="Weak algorithm in code", category="code", default_impact="High",
      description="The code uses a broken or deprecated algorithm (for example MD5, SHA-1, DES, 3DES, RC4, Blowfish).",
      attack="Depending on the algorithm: hash collisions forge signatures or integrity checks; weak ciphers let recorded data be decrypted.",
      cwe=["CWE-327", "CWE-328"], owasp=["crypto"], cves=[],
      cve_rules=[{"match": "MD5", "cves": ["CVE-2004-2761"]}, {"match": "SHA-?1\\b|SHA1", "cves": ["CVE-2005-4900"]},
                 {"match": "(?<![a-z0-9])(?:a?rc4|arcfour)(?![0-9])", "cves": ["CVE-2013-2566"]}, {"match": "3DES|TRIPLEDES|DESEDE|\\bDES\\b", "cves": ["CVE-2016-2183"]}],
      standards=["NIST SP 800-131A Rev. 2"], compliance=["algorithms"],
      summary_rules=[{"match": "RSA|DSA|\\bDH\\b|Diffie", "summary": "Use RSA-3072 or larger (or ECDSA P-256 / X25519) now, and plan the post-quantum move to ML-KEM / ML-DSA.",
                      "steps": [{"platform": "Python", "how": "rsa.generate_private_key(public_exponent=65537, key_size=3072) or ec.generate_private_key(ec.SECP256R1()); X25519PrivateKey.generate() for key agreement"},
                                {"platform": "Java", "how": "KeyPairGenerator.getInstance(\"RSA\").initialize(3072) or KeyPairGenerator.getInstance(\"EC\") with new ECGenParameterSpec(\"secp256r1\")"},
                                {"platform": "Node.js", "how": "crypto.generateKeyPairSync('rsa', { modulusLength: 3072 }) or crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' })"},
                                {"platform": "Go", "how": "rsa.GenerateKey(rand.Reader, 3072) or ecdsa.GenerateKey(elliptic.P256(), rand.Reader); crypto/ecdh X25519 for key agreement"},
                                {"platform": "OpenSSL", "how": "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 (or -algorithm EC -pkeyopt ec_paramgen_curve:P-256)"}]},
                     {"match": "MD5|MD4|SHA-?1\\b|SHA1", "summary": "Use SHA-256 or SHA-3 (and Argon2id, scrypt or PBKDF2 for password hashing).",
                      "steps": [{"platform": "Python", "how": "hashlib.sha256(...); hashlib.scrypt(...) or argon2-cffi for passwords"},
                                {"platform": "Java", "how": "MessageDigest.getInstance(\"SHA-256\"); PBKDF2WithHmacSHA256 or Argon2 (Bouncy Castle) for passwords"},
                                {"platform": "Node.js", "how": "crypto.createHash('sha256'); crypto.scryptSync(...) for passwords"},
                                {"platform": "Go", "how": "crypto/sha256; golang.org/x/crypto/argon2 for passwords"}]},
                     {"match": "DES|RC4|RC2|ARC4|Blowfish|IDEA", "summary": "Use AES-256-GCM or ChaCha20-Poly1305.",
                      "steps": [{"platform": "Python", "how": "cryptography.hazmat.primitives.ciphers.aead.AESGCM(key) with a random 12-byte nonce per message"},
                                {"platform": "Java", "how": "Cipher.getInstance(\"AES/GCM/NoPadding\") with a fresh 12-byte IV and GCMParameterSpec(128, iv)"},
                                {"platform": "Node.js", "how": "crypto.createCipheriv('aes-256-gcm', key, iv) with a fresh 12-byte iv"},
                                {"platform": "Go", "how": "cipher.NewGCM(aes.NewCipher(key)) with a fresh nonce from crypto/rand"}]}],
      remediation={"summary": "Use SHA-256/SHA-3 for hashing, AES-GCM or ChaCha20-Poly1305 for encryption, and Argon2id/scrypt/PBKDF2 for passwords.", "steps": [
          {"platform": "Python", "how": "hashlib.sha256(...) ; cryptography.hazmat.primitives.ciphers.aead.AESGCM(key)"},
          {"platform": "Java", "how": "MessageDigest.getInstance(\"SHA-256\"); Cipher.getInstance(\"AES/GCM/NoPadding\")"},
          {"platform": "Node.js", "how": "crypto.createHash('sha256'); crypto.createCipheriv('aes-256-gcm', key, iv)"},
          {"platform": "Go", "how": "crypto/sha256; crypto/cipher.NewGCM(aes.NewCipher(key))"}]},
      verify=[{"label": "Show the call site", "command": "grep -n -i '{name}' '{path}'"}], references=[])
entry("WEAK_KEY_SIZE", title="Key size too small", category="code", default_impact="High", description="The code generates or uses a key below the minimum size (RSA/DSA/DH < 2048, EC < 224, symmetric < 128).",
      attack="Small keys can be brute-forced or factored.", cwe=["CWE-326"], owasp=["crypto"], cves=[], standards=["NIST SP 800-131A Rev. 2"], compliance=["keysize"],
      remediation={"summary": "Use RSA-3072, P-256/P-384 or X25519, and 256-bit symmetric keys.", "steps": []}, verify=[{"label": "Show the call site", "command": "grep -n -i '{name}' '{path}'"}], references=[])
entry("WEAK_CIPHER_MODE", title="Insecure cipher mode (ECB)", category="code", default_impact="High",
      description="A block cipher is used in ECB mode (often implicitly, e.g. Java's Cipher.getInstance(\"AES\")).",
      attack="ECB encrypts equal blocks to equal ciphertext, leaking patterns and allowing block cut-and-paste.", cwe=["CWE-327"], owasp=["crypto"], cves=[], standards=["NIST SP 800-38A"],
      compliance=["algorithms"], remediation={"summary": "Use an AEAD mode: AES/GCM/NoPadding with a unique 96-bit nonce per message.", "steps": []},
      verify=[{"label": "Show the call site", "command": "grep -n -i 'ECB\\|getInstance(\"AES\")' '{path}'"}], references=[])
entry("WEAK_PADDING", title="RSA encryption without OAEP", category="code", default_impact="High",
      description="RSA encryption uses PKCS#1 v1.5 or no padding.", attack="PKCS#1 v1.5 encryption is open to Bleichenbacher-style padding oracles (ROBOT).",
      cwe=["CWE-780"], owasp=["crypto"], cves=[], pqc="quantum-broken", standards=["RFC 8017 (RSA-OAEP)"], compliance=["algorithms"],
      remediation={"summary": "Use RSA-OAEP with SHA-256 (or better, a KEM such as ECDH/ML-KEM).", "steps": []}, verify=[{"label": "Show the call site", "command": "grep -n -i 'PKCS1\\|NoPadding' '{path}'"}],
      references=["https://robotattack.org/"])
entry("WEAK_RNG", title="Non-cryptographic random generator for key material", category="code", default_impact="High",
      description="A key, IV, nonce or salt comes from a general-purpose PRNG (Math.random, random.random, java.util.Random, rand()).",
      attack="These generators are predictable; an attacker who sees some outputs can reconstruct the key or token.", cwe=["CWE-338", "CWE-330"], owasp=["crypto"], cves=[], standards=["NIST SP 800-90A"],
      compliance=["key_mgmt"], remediation={"summary": "Use the OS CSPRNG: secrets / os.urandom, SecureRandom, crypto.randomBytes, crypto/rand.", "steps": []},
      verify=[{"label": "Show the call site", "command": "grep -n -i 'random' '{path}'"}], references=[])
entry("STATIC_IV", title="Static or predictable IV / nonce", category="code", default_impact="High", description="A constant or predictable IV or nonce reaches a cipher.",
      attack="With CBC, a predictable IV enables chosen-plaintext attacks; with GCM/CTR, a repeated nonce leaks the XOR of plaintexts and the authentication key.",
      cwe=["CWE-329", "CWE-1204"], owasp=["crypto"], cves=[], standards=["NIST SP 800-38D"], compliance=["algorithms"],
      remediation={"summary": "Generate a fresh random IV/nonce per message and store it with the ciphertext.", "steps": []}, verify=[{"label": "Show the call site", "command": "grep -n -i 'iv\\|nonce' '{path}'"}], references=[])
entry("REUSED_NONCE", title="Nonce reused across encryptions", category="code", default_impact="Critical", description="The same IV/nonce protects more than one encryption under the same key.",
      attack="For AES-GCM or ChaCha20-Poly1305, nonce reuse reveals the XOR of the plaintexts and lets an attacker forge messages.", cwe=["CWE-323"], owasp=["crypto"], cves=[], standards=["NIST SP 800-38D"],
      compliance=["algorithms"], remediation={"summary": "Use a unique nonce per encryption (random 96-bit or a counter), or AES-GCM-SIV.", "steps": []}, verify=[{"label": "Show the call site", "command": "grep -n -i 'nonce\\|iv' '{path}'"}], references=[])
entry("HARDCODED_KEY", title="Hard-coded key in source", category="code", default_impact="Critical", description="A cryptographic key is embedded as a literal in the source code.",
      attack="Anyone with the code (repository, image, decompiled binary) has the key and can decrypt or forge everything it protects.", cwe=["CWE-321", "CWE-798"], owasp=["crypto"], cves=[],
      standards=["NIST SP 800-57 Part 1"], compliance=["key_mgmt"],
      remediation={"summary": "Move the key to a KMS or secrets manager, load it at run time, and rotate it (the old one is compromised).", "steps": []},
      verify=[{"label": "Show the line", "command": "sed -n '{line}p' '{path}'"}], references=[])
entry("CUSTOM_CRYPTO", title="Custom cryptography", category="code", default_impact="High", description="The code implements its own cipher or hash construction (XOR loops, hand-rolled S-boxes, toy Feistel networks).",
      attack="Home-made primitives are almost always breakable with basic cryptanalysis.", cwe=["CWE-327", "CWE-1240"], owasp=["crypto"], cves=[], standards=[], compliance=["algorithms"],
      remediation={"summary": "Replace it with a vetted library primitive (AES-GCM, ChaCha20-Poly1305, SHA-256).", "steps": []}, verify=[{"label": "Show the code", "command": "sed -n '{line},+20p' '{path}'"}], references=[])
entry("WEAK_PROTOCOL", title="Weak protocol version configured", category="code", default_impact="High", description="The code or configuration allows SSLv3, TLS 1.0/1.1, SSH-1 or IKEv1.",
      attack="Wherever this configuration is deployed, an attacker in the network path can force or exploit the old protocol: SSLv3 falls to POODLE, TLS 1.0 to BEAST-style CBC attacks, SSH-1 to known insertion and hijacking attacks, and IKEv1 aggressive mode exposes a pre-shared-key hash that can be cracked offline.", cwe=["CWE-327", "CWE-757"], owasp=["crypto", "misconfig"], cves=[],
      cve_rules=[{"match": "SSLv3|SSL3", "cves": ["CVE-2014-3566"]}, {"match": "SSLv2|SSL2", "cves": ["CVE-2016-0800"]}, {"match": "\\bTLS ?v?1(?:[._]0)?\\b(?![._][1-3])", "cves": ["CVE-2011-3389"]}],
      standards=["RFC 8996"], compliance=["tls_min"], remediation={"summary": "Set the minimum to TLS 1.2.", "steps": TLS_MIN12}, verify=[{"label": "Show the line", "command": "grep -n -i 'tls\\|ssl' '{path}'"}], references=[])
entry("WEAK_CIPHER_SUITE", title="Weak cipher suite or SSH/IKE algorithm configured", category="code", default_impact="High",
      description="Configuration allows RC4, 3DES, NULL, anonymous or EXPORT suites, or legacy SSH/IKE algorithms.",
      attack="Wherever this configuration is deployed: RC4 biases leak plaintext; 64-bit block ciphers (3DES) allow SWEET32 birthday attacks on long sessions; EXPORT suites can be broken in real time (FREAK, Logjam); anonymous suites give no server authentication.", cwe=["CWE-327"], owasp=["crypto", "misconfig"], cves=[],
      cve_rules=[{"match": "(?<![a-z0-9])(?:a?rc4|arcfour)(?![0-9])", "cves": ["CVE-2013-2566"]}, {"match": "3DES|DES-CBC3", "cves": ["CVE-2016-2183"]}, {"match": "(?<![a-z])exp(?:ort)?(?![a-z])", "cves": ["CVE-2015-0204", "CVE-2015-4000"]}],
      standards=["RFC 7465"], compliance=["algorithms"], remediation={"summary": "Allow only ECDHE + AEAD suites.", "steps": TLS_CIPHERS}, verify=[{"label": "Show the line", "command": "grep -n -i 'cipher' '{path}'"}], references=[])
entry("WEAK_CERTIFICATE_SIGNATURE", title="Certificate signed with a broken hash", category="certificate", default_impact="High", description="A certificate in the code base is signed with MD5 or SHA-1.",
      attack="MD5 and SHA-1 chosen-prefix collisions are practical (a rogue CA certificate was forged with MD5; SHA-1 is a Shambles, 2020), so a signature made with them can be forged to vouch for an attacker's key.", cwe=["CWE-328"], owasp=["crypto"], cves=[], cve_rules=[{"match": "md5", "cves": ["CVE-2004-2761"]}, {"match": "sha1|SHA-1", "cves": ["CVE-2005-4900"]}],
      standards=["NIST SP 800-131A Rev. 2"], compliance=["certificates"], remediation={"summary": "Re-issue with SHA-256.", "steps": CERT_REISSUE}, verify=V_CERT_FILE, references=[])
entry("WEAK_CERTIFICATE_KEY", title="Certificate key too small", category="certificate", default_impact="High", description="A certificate's public key is below 2048-bit RSA / 224-bit EC.",
      attack="RSA keys under 2048 bits are within reach of well-funded attackers and are disallowed for new use; a recovered private key lets an attacker impersonate the service or decrypt traffic it protected.", cwe=["CWE-326"], owasp=["crypto"], cves=[], pqc="quantum-broken", standards=["NIST SP 800-131A Rev. 2"], compliance=["keysize", "certificates"],
      remediation={"summary": "Re-issue with RSA-3072 or ECDSA P-256.", "steps": CERT_REISSUE}, verify=V_CERT_FILE, references=[])
entry("SELF_SIGNED_LEAF", title="Self-signed leaf certificate", category="certificate", default_impact="Low", description="A leaf certificate (CA:FALSE) is self-signed.",
      attack="Clients must pin the certificate or skip validation; code that skips validation accepts any certificate, which allows man-in-the-middle impersonation.", cwe=["CWE-295"], owasp=["crypto", "auth"], cves=[], standards=[], compliance=["certificates"],
      remediation={"summary": "Issue it from a CA.", "steps": CERT_REISSUE}, verify=V_CERT_FILE, references=[])
entry("EXPIRED_CERTIFICATE", title="Expired certificate in code base", category="certificate", default_impact="High", description="A certificate shipped with the code has expired.",
      attack="Clients either fail closed (an outage) or are configured to ignore validation errors, which removes protection against impersonation.", cwe=["CWE-298"], owasp=["crypto", "misconfig"], cves=[], standards=[], compliance=["certificates"],
      remediation={"summary": "Replace it and automate renewal.", "steps": CERT_REISSUE}, verify=V_CERT_FILE, references=[])
entry("CERT_NEAR_EXPIRY", title="Certificate near expiry", category="certificate", default_impact="Medium", description="A certificate shipped with the code expires soon.",
      attack="An unplanned expiry causes an outage or pushes teams to disable certificate validation in a hurry.", cwe=["CWE-298"], owasp=["misconfig"], cves=[], standards=[], compliance=["certificates"],
      remediation={"summary": "Renew it.", "steps": CERT_REISSUE}, verify=V_CERT_FILE, references=[])
entry("VULNERABLE_CRYPTO_LIBRARY", title="Vulnerable crypto library version", category="library", default_impact="High",
      description="A manifest or lockfile pins a crypto library version with a published advisory.", attack="Attackers use the published advisory for the version in use against any code path that calls the affected function; each CVE below names the function and the fixed version.", cwe=["CWE-1395"], owasp=["components"], cves=[],
      standards=[], compliance=["components"], remediation={"summary": "Upgrade to the fixed version named in the advisory.", "steps": []},
      verify=[{"label": "Show the pinned version", "command": "grep -n '{name}' '{path}'"}], references=[])
entry("KMS_KEY_ROTATION_DISABLED", **{k: v for k, v in E["KMS_NO_ROTATION"].items()})
entry("KMS_KEY_DELETION_UNPROTECTED", title="Key vault purge protection off", category="cloud", default_impact="Low",
      description="An Azure Key Vault or Managed HSM declared in infrastructure code has purge protection disabled or omitted.",
      attack="Without purge protection a deleted vault or key can be permanently purged during the retention period, so an insider or compromised principal can destroy keys and make the data they protect unrecoverable.",
      cwe=["CWE-320"], owasp=["crypto", "misconfig"], cves=[], standards=[], compliance=["key_mgmt"],
      remediation={"summary": "Set purge_protection_enabled = true (it cannot be turned off again once enabled).", "steps": [
          {"platform": "Terraform (azurerm)", "how": "purge_protection_enabled = true on azurerm_key_vault / azurerm_key_vault_managed_hardware_security_module"},
          {"platform": "Azure CLI", "how": "az keyvault update --name {name} --enable-purge-protection true"}]},
      verify=[{"label": "Purge protection setting", "command": "az keyvault show --name {name} --query properties.enablePurgeProtection"}], references=[])
entry("KMS_KEY_POLICY_PUBLIC", title="KMS key policy open to everyone", category="cloud", default_impact="High",
      description="A KMS key policy grants access to a wildcard principal without a restricting condition.",
      attack="Any AWS principal (in any account) allowed by the policy can use or manage the key, and so decrypt data protected by it.",
      cwe=["CWE-732", "CWE-284"], owasp=["access", "crypto"], cves=[], standards=[], compliance=["key_mgmt"],
      remediation={"summary": "Replace \"Principal\": \"*\" with the specific account or role ARNs, or add a restricting condition such as aws:PrincipalOrgID.", "steps": []},
      verify=[{"label": "Key policy", "command": "aws kms get-key-policy --key-id {resource} --policy-name default --output text"}], references=[])
entry("UNENCRYPTED_AT_REST", title="Data store not encrypted at rest", category="config", default_impact="High",
      description="Infrastructure or service configuration declares a data store (volume, bucket, database, cache, queue) without encryption at rest.",
      attack="Copies of the data (snapshots, backups, replicas, decommissioned disks) are readable by whoever obtains them.",
      cwe=["CWE-311", "CWE-312"], owasp=["crypto"], cves=[], standards=[], compliance=["at_rest"],
      remediation={"summary": "Turn on encryption at rest for the resource, preferably with a customer-managed key.", "steps": [
          {"platform": "Terraform (AWS)", "how": "encrypted = true / storage_encrypted = true / server_side_encryption_configuration { ... sse_algorithm = \"aws:kms\" }"},
          {"platform": "Terraform (Azure)", "how": "Enable infrastructure encryption / customer-managed keys on the storage account or database"}]},
      verify=[{"label": "Show the resource definition", "command": "grep -n -i 'encrypt' '{path}'"}], references=[])
entry("UNENCRYPTED_IN_TRANSIT", title="Connection not encrypted in transit", category="config", default_impact="High",
      description="Configuration declares a connection or listener without TLS (for example a database URL with sslmode=disable, a plaintext broker listener or an HTTP-only load balancer).",
      attack="Anyone on the network path can read or change the traffic, including credentials.",
      cwe=["CWE-319"], owasp=["crypto"], cves=[], standards=["NIST SP 800-52 Rev. 2"], compliance=["in_transit"],
      remediation={"summary": "Enable TLS on the listener or connection and require it.", "steps": TLS_MIN12[:3] + [{"platform": k, "how": v} for k, v in DB_TLS.items()]},
      verify=[{"label": "Show the setting", "command": "grep -n -i 'ssl\\|tls\\|http:' '{path}'"}], references=[])
entry("TLS_VERIFICATION_DISABLED", title="TLS certificate verification disabled", category="config", default_impact="High",
      description="A client turns off certificate or host-name verification (for example verify=False, InsecureSkipVerify, rejectUnauthorized: false, sslmode=require without a CA).",
      attack="An on-path attacker presents any certificate and the client accepts it, so the attacker can read and change the encrypted traffic (man-in-the-middle).",
      cwe=["CWE-295"], owasp=["auth", "crypto"], cves=[], standards=[], compliance=["in_transit", "certificates"],
      remediation={"summary": "Keep verification on and give the client the right CA bundle instead of disabling checks.", "steps": [
          {"platform": "Python requests/httpx", "how": "verify='/path/to/ca.pem' (never verify=False)"},
          {"platform": "Go", "how": "Remove InsecureSkipVerify; set tls.Config{RootCAs: pool}"},
          {"platform": "Node.js", "how": "Remove rejectUnauthorized: false / NODE_TLS_REJECT_UNAUTHORIZED=0; pass ca: fs.readFileSync(...)"},
          {"platform": "PostgreSQL clients", "how": "sslmode=verify-full with sslrootcert"}]},
      verify=[{"label": "Show the setting", "command": "grep -n -i 'verify\\|insecure\\|reject' '{path}'"}], references=[])
entry("DOWNGRADE_PROTECTION_MISSING", **dict(E["NO_FALLBACK_SCSV"], title="Downgrade protection missing",
      description="An imported TLS scan result reports that the endpoint does not protect against protocol downgrade (TLS_FALLBACK_SCSV)."))
entry("KNOWN_TLS_VULNERABILITY", title="Known TLS vulnerability reported", category="protocol", default_impact="High",
      description="An imported TLS scanner result (testssl.sh, sslyze or similar) reports a named TLS vulnerability on the endpoint.",
      attack="Depends on the vulnerability: Heartbleed leaks server memory including private keys; POODLE and BEAST recover plaintext; ROBOT decrypts RSA key exchange; CRIME and BREACH recover secrets through compression; insecure renegotiation lets an attacker inject requests.",
      cwe=["CWE-327"], owasp=["crypto", "components"], cves=[],
      cve_rules=[{"match": "HEARTBLEED", "cves": ["CVE-2014-0160"]}, {"match": "POODLE", "cves": ["CVE-2014-3566"]},
                 {"match": "\\bBEAST\\b", "cves": ["CVE-2011-3389"]}, {"match": "LUCKY13|LUCKY-13", "cves": ["CVE-2013-0169"]},
                 {"match": "\\bCRIME\\b", "cves": ["CVE-2012-4929"]}, {"match": "\\breneg(?:otiation)?\\b", "cves": ["CVE-2009-3555"]},
                 {"match": "SWEET32", "cves": ["CVE-2016-2183"]}, {"match": "\\bDROWN\\b", "cves": ["CVE-2016-0800"]},
                 {"match": "\\bFREAK\\b", "cves": ["CVE-2015-0204"]}, {"match": "LOGJAM", "cves": ["CVE-2015-4000"]},
                 {"match": "\\bCCS\\b", "cves": ["CVE-2014-0224"]}],
      standards=["RFC 9325 (BCP 195)"], compliance=["components", "tls_min"],
      remediation={"summary": "Patch the TLS library or appliance and remove the protocol features the vulnerability needs (old versions, CBC, RSA key exchange, compression, insecure renegotiation).", "steps": TLS_MIN12[:2] + TLS_CIPHERS[:2]},
      verify=[{"label": "Re-run the named checks", "command": "testssl.sh --vulnerable {host}:{port}"}], references=["https://heartbleed.com/", "https://robotattack.org/"])
entry("AT_REST_ENCRYPTION_WEAK", title="Weak at-rest encryption setting", category="config", default_impact="Medium",
      description="Configuration enables encryption at rest with a weak setting (for example a legacy cipher or a provider-managed default where a customer key is required).",
      attack="Weak or legacy at-rest encryption gives less protection to copied data and keys.",
      cwe=["CWE-326", "CWE-327"], owasp=["crypto"], cves=[], standards=["NIST SP 800-131A Rev. 2"], compliance=["at_rest"],
      remediation={"summary": "Use AES-256 (GCM or XTS) with a customer-managed key.", "steps": []},
      verify=[{"label": "Show the setting", "command": "grep -n -i 'encrypt\\|cipher' '{path}'"}], references=[])

# --- Windows (SCHANNEL / RDP / BitLocker) and library CVEs
entry("RDP_NO_TLS", title="RDP uses the legacy RDP security layer", category="windows", default_impact="High",
      description="Remote Desktop is configured with SecurityLayer 0 (RDP Security), so sessions are not protected by TLS and the server is not authenticated by a certificate.",
      attack="The legacy RDP security layer is open to man-in-the-middle attacks: an attacker on the path can impersonate the server and capture the credentials typed into the session.",
      cwe=["CWE-319", "CWE-327"], owasp=["crypto", "misconfig"], cves=[], standards=[], compliance=["in_transit"],
      remediation={"summary": "Require TLS for RDP and enable Network Level Authentication.", "steps": [
          {"platform": "Group Policy", "how": "Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security: 'Require use of specific security layer for remote (RDP) connections' = SSL"},
          {"platform": "PowerShell", "how": "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name SecurityLayer -Value 2"}]},
      verify=[{"label": "Current RDP settings", "command": "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' | Select-Object SecurityLayer,MinEncryptionLevel,UserAuthentication"},
              {"label": "Protocols on port 3389 from the network", "command": "nmap --script rdp-enum-encryption -p 3389 {host}"}], references=[])
entry("RDP_NO_NLA", title="RDP Network Level Authentication off", category="windows", default_impact="Medium",
      description="Remote Desktop accepts connections without Network Level Authentication (UserAuthentication = 0).",
      attack="Without NLA the server builds a full session before the user authenticates, which exposes the logon screen and pre-authentication code to anyone who can reach the port.",
      cwe=["CWE-306"], owasp=["auth", "misconfig"], cves=[], standards=[], compliance=["auth"],
      remediation={"summary": "Require NLA.", "steps": [
          {"platform": "Group Policy", "how": "'Require user authentication for remote connections by using Network Level Authentication' = Enabled"},
          {"platform": "PowerShell", "how": "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1"}]},
      verify=[{"label": "NLA setting", "command": "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp').UserAuthentication"}], references=[])
entry("DISK_PROTECTION_OFF", title="BitLocker protection suspended", category="disk", default_impact="Medium",
      description="The volume is encrypted but BitLocker protection is off (suspended), so the volume key is stored unprotected on the disk.",
      attack="Anyone with the disk can read the data, because the key that decrypts it is stored in the clear while protection is suspended.",
      cwe=["CWE-311", "CWE-312"], owasp=["crypto"], cves=[], standards=[], compliance=["at_rest"],
      remediation={"summary": "Resume protection: Resume-BitLocker -MountPoint '<drive>'", "steps": []},
      verify=[{"label": "Volume status", "command": "Get-BitLockerVolume | Select-Object MountPoint,VolumeStatus,EncryptionMethod,ProtectionStatus"}], references=[])
entry("LIB_KNOWN_CVE", title="Crypto library version in a published CVE range", category="library", default_impact="Low",
      description="The installed version of this crypto library falls inside the affected version range NVD publishes for one or more CVEs.",
      attack="See each CVE. A version match is not proof of exposure: Linux distributions back-port fixes without changing the upstream version number, so each CVE is reported as 'in triage' until you confirm it against your vendor's advisory.",
      cwe=["CWE-1395"], owasp=["components"], cves=[], standards=[], compliance=["components"],
      remediation={"summary": "Install your OS vendor's security updates for the package (or upgrade an upstream build to a fixed release), then restart the services that load it.", "steps": [
          {"platform": "Ubuntu/Debian", "how": "apt-get update && apt-get install --only-upgrade <package>; check https://ubuntu.com/security/cves or https://security-tracker.debian.org for the CVE"},
          {"platform": "RHEL/AL2023", "how": "dnf upgrade <package>; check `dnf updateinfo list --cve <CVE-ID>` (or `rpm -q --changelog <package> | grep <CVE-ID>`)"}]},
      verify=[{"label": "Installed version and back-ported fixes (Debian/Ubuntu)", "command": "dpkg -s {name} | grep Version; zgrep -i 'CVE-' /usr/share/doc/{name}/changelog.Debian.gz | head"},
              {"label": "Installed version and back-ported fixes (RHEL family)", "command": "rpm -q {name}; rpm -q --changelog {name} | grep -i cve | head"}], references=[])
