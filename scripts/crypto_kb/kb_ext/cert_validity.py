"""Certificate validity and chain finding codes (CB-17).

Rules: backend/utilities/cbom_sources/classify.py (_expiry_rules, _chain_rules), from facts every certificate
collector sends (not_before / not_after) and the chain facts the scan node adds to each served certificate
(certparse.chain_links: chain_issuer, chain_top, chain_extra; aia_ca_issuers).  Keystore entries (JKS, PKCS#12) and
every certificate of a Kubernetes TLS secret are certificates of their own, judged by the same rules.
"""
from kb_text import CERT_REISSUE, V_CERT_FILE, V_CERT_REMOTE, entry

V_CHAIN = [{"label": "Every certificate the server sends, with subject (s:) and issuer (i:)",
            "command": "openssl s_client -connect {host}:{port} -servername {host} -showcerts </dev/null 2>/dev/null | "
                       "grep -E '^ *[0-9]+ s:|^ +i:|NotAfter'"},
           {"label": "Does the chain verify against the system roots?",
            "command": "openssl s_client -connect {host}:{port} -servername {host} -verify_return_error </dev/null "
                       "2>&1 | grep -E 'Verify return code|verify error'"}]
CHAIN_FIX = [
    {"platform": "nginx", "how": "ssl_certificate must point to the full chain file (leaf first, then each intermediate; "
                                 "no root): cat leaf.pem intermediate.pem > fullchain.pem"},
    {"platform": "Apache httpd 2.4.8+", "how": "SSLCertificateFile with the leaf followed by its intermediates"},
    {"platform": "Kubernetes (cert-manager, ingress)", "how": "tls.crt holds the leaf followed by its intermediates; "
                                                              "cert-manager writes this when the Issuer returns the chain"},
    {"platform": "Java (Tomcat, keytool)", "how": "Import the CA reply with its chain: keytool -importcert -trustcacerts "
                                                  "-alias server -file fullchain.pem -keystore server.p12"},
]

NODE_CODES = ["CERT_NOT_YET_VALID", "CERT_CHAIN_EXTRA_EXPIRED", "CHAIN_INCOMPLETE"]

entry("CERT_NOT_YET_VALID", title="Certificate not valid yet", category="certificate", default_impact="Medium",
      description="The certificate's validity period starts in the future (notBefore is more than a day after the "
                  "time it was judged, so clock skew and time zones never flag a fresh certificate).",
      attack="A server that presents it fails every client that checks dates, and teams under pressure respond by "
             "turning validation off. A certificate staged on disk ahead of a planned switch is expected: check that "
             "nothing serves it before its start date.",
      cwe=["CWE-298"], owasp=["misconfig"], cves=[], standards=["RFC 5280 (4.1.2.5 validity)"],
      compliance=["certificates"],
      remediation={"summary": "Do not serve it before its start date; if it was issued with a wrong date (a CA or "
                              "host clock error), re-issue it.", "steps": CERT_REISSUE},
      verify=V_CERT_REMOTE + V_CERT_FILE, references=["https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5"])
entry("CERT_CHAIN_EXTRA_EXPIRED", title="Expired extra certificate in the served chain", category="certificate",
      default_impact="Low",
      description="The server sends an expired cross-signed CA certificate above its intermediate. Clients that trust "
                  "the cross-signed CA as a root (its subject and key are a root of the scan node's trust store, or "
                  "the chain also holds that root) build a valid path without it, so this is not the expired "
                  "certificate outage that CERT_EXPIRED reports (the 2021 DST Root CA X3 / ISRG Root X1 case).",
      attack="Modern clients ignore it. Old clients that relied on the cross-sign, and some TLS libraries that do not "
             "look for an alternative path (OpenSSL 1.0.x), fail the connection.",
      cwe=["CWE-298", "CWE-296"], owasp=["misconfig"], cves=[], standards=["RFC 5280", "RFC 4158 (path building)"],
      compliance=["certificates"],
      remediation={"summary": "Remove the expired cross-sign from the chain the server sends (serve the leaf and its "
                              "intermediates only); keep it only for clients you know need it.", "steps": CHAIN_FIX},
      verify=V_CHAIN, references=["https://letsencrypt.org/docs/dst-root-ca-x3-expiration-september-2021/"])
entry("CHAIN_INCOMPLETE", title="Incomplete certificate chain", category="certificate", default_impact="Medium",
      description="The server does not send a certificate its chain needs: either a certificate above the leaf is not "
                  "the issuer of the one below it (a gap), or the leaf is sent alone while its CA publishes the "
                  "issuing certificate for download (AIA caIssuers), i.e. an intermediate. The issuer is not a root "
                  "of the scan node's trust store. A top CA certificate whose root is not sent is never reported: "
                  "servers should not send roots.",
      attack="Browsers that cache or download intermediates connect; other clients (curl, Java, Go, mobile apps, IoT, "
             "API consumers) fail, and the usual reaction is to switch certificate validation off, which allows "
             "impersonation.",
      cwe=["CWE-296", "CWE-295"], owasp=["crypto", "misconfig"], cves=[], standards=["RFC 8446 (4.4.2)", "RFC 5246 (7.4.2)"],
      compliance=["certificates"],
      remediation={"summary": "Serve the full chain: the leaf followed by every intermediate up to (not including) "
                              "the root.", "steps": CHAIN_FIX},
      verify=V_CHAIN, references=["https://www.rfc-editor.org/rfc/rfc8446#section-4.4.2"])
