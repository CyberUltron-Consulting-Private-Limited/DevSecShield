"""CB-34 legacy TLS: the three cipher-suite classes a scan-node probe can find accepted whose impact is worse than the
other weak suites (WEAK_CIPHER): EXPORT-grade keys, NULL encryption and anonymous key exchange. A server that accepts
one also gets WEAK_CIPHER, which names every weak suite; these codes carry the class's own impact and fix."""

from kb_text import TLS_CIPHERS, entry

NODE_CODES = ["TLS_EXPORT_CIPHER", "TLS_NULL_CIPHER", "TLS_ANON_CIPHER"]

V_SUITES = [
    {"label": "Every cipher suite per protocol, graded", "command": "nmap --script ssl-enum-ciphers -p {port} {host}"},
]

entry(
    "TLS_EXPORT_CIPHER",
    title="EXPORT-grade cipher suites accepted",
    category="cipher",
    default_impact="Critical",
    description=(
        "The endpoint accepts EXPORT cipher suites (TLS_*_EXPORT_*): 40- or 56-bit encryption and 512-bit RSA or DH "
        "key exchange, made weak on purpose for 1990s export rules."
    ),
    attack=(
        "An on-path attacker downgrades a connection to an EXPORT suite (FREAK for RSA, Logjam for DH), factors the "
        "512-bit key or breaks the 512-bit group in hours, then reads and changes the traffic, even of clients that "
        "never asked for EXPORT."
    ),
    cwe=["CWE-327", "CWE-326"],
    owasp=["crypto", "misconfig"],
    cves=["CVE-2015-0204", "CVE-2015-4000"],
    standards=["RFC 5246 (TLS 1.2 forbids EXPORT suites)", "NIST SP 800-52 Rev. 2"],
    compliance=["algorithms"],
    remediation={"summary": "Remove every EXPORT suite (add !EXPORT to the OpenSSL cipher string) and offer only "
                            "ECDHE key exchange with AEAD ciphers.", "steps": TLS_CIPHERS},
    verify=V_SUITES + [{"label": "Try an EXPORT suite (needs an OpenSSL that still builds them, such as 1.0.2)",
                        "command": "openssl s_client -connect {host}:{port} -cipher EXPORT </dev/null 2>&1 | "
                                   "grep -E 'Cipher|alert'"}],
    references=["https://freakattack.com/", "https://weakdh.org/"],
)

entry(
    "TLS_NULL_CIPHER",
    title="NULL-encryption cipher suites accepted",
    category="cipher",
    default_impact="Critical",
    description=(
        "The endpoint accepts cipher suites with NULL encryption (TLS_*_WITH_NULL_*): the session is authenticated "
        "and integrity-checked, but every byte travels in clear text."
    ),
    attack=(
        "Anyone on the network path reads the whole session, credentials included, once client and server agree on "
        "a NULL suite; an attacker who can influence the client's offer or the server's order forces that choice."
    ),
    cwe=["CWE-319", "CWE-327"],
    owasp=["crypto", "misconfig"],
    cves=[],
    standards=["NIST SP 800-52 Rev. 2", "RFC 9325 (BCP 195)"],
    compliance=["algorithms", "in_transit"],
    remediation={"summary": "Remove every NULL suite (add !eNULL to the OpenSSL cipher string) and offer only "
                            "ECDHE key exchange with AEAD ciphers.", "steps": TLS_CIPHERS},
    verify=V_SUITES + [{"label": "Try a NULL suite", "command": "openssl s_client -connect {host}:{port} -cipher "
                                                               "'eNULL:@SECLEVEL=0' </dev/null 2>&1 | grep -E "
                                                               "'Cipher|alert'"}],
    references=["https://www.rfc-editor.org/rfc/rfc9325"],
)

entry(
    "TLS_ANON_CIPHER",
    title="Anonymous (unauthenticated) cipher suites accepted",
    category="cipher",
    default_impact="High",
    description=(
        "The endpoint accepts anonymous key-exchange suites (TLS_DH_anon_*, TLS_ECDH_anon_*): no certificate is sent "
        "and the server is never authenticated."
    ),
    attack=(
        "An active man in the middle completes one anonymous handshake with the client and another with the server, "
        "then reads and changes everything in between; nothing in the protocol can detect it."
    ),
    cwe=["CWE-287", "CWE-327"],
    owasp=["crypto", "auth"],
    cves=[],
    standards=["NIST SP 800-52 Rev. 2", "RFC 9325 (BCP 195)"],
    compliance=["algorithms"],
    remediation={"summary": "Remove every anonymous suite (add !aNULL to the OpenSSL cipher string) and offer only "
                            "ECDHE key exchange with AEAD ciphers and a certificate.", "steps": TLS_CIPHERS},
    verify=V_SUITES + [{"label": "Try an anonymous suite", "command": "openssl s_client -connect {host}:{port} -cipher "
                                                                     "'aNULL:@SECLEVEL=0' </dev/null 2>&1 | grep -E "
                                                                     "'Cipher|alert'"}],
    references=["https://www.rfc-editor.org/rfc/rfc9325"],
)
