"""Outputs (WP9): the informational note for a self-signed CA root or identity-provider certificate signed with SHA-1.

A self-signature is never verified by a client: the root (or the IdP's signing certificate) is trusted as itself,
from the trust store or the federation metadata. SHA-1 in that signature is therefore not a forgery risk and the
classifier does not raise SIG_SHA1 for it; this code records the fact without an impact, and says to re-issue with
SHA-256 at the next renewal so policies and scanners stop flagging it. A self-signed LEAF with SHA-1 keeps
CERT_SELF_SIGNED (Low), whose per-asset text carries the same explanation.
"""
from kb_text import V_CERT_FILE, V_CERT_REMOTE, entry

entry("CERT_SELF_SHA1", title="SHA-1 self-signature on a CA or identity-provider certificate (informational)",
      category="certificate", default_impact="Low",
      description="A self-signed CA root or identity-provider signing certificate signs itself with SHA-1. Clients "
                  "never check a self-signature: they trust the certificate itself (trust store or federation "
                  "metadata), so this is not a forgery risk. Certificates it issues, or assertions it signs, are "
                  "checked separately.",
      attack="None through the self-signature itself. Policy engines and scanners that flag every SHA-1 signature "
             "will keep reporting it, and some clients refuse SHA-1 anywhere in a chain.",
      cwe=["CWE-328"], owasp=["crypto"], cves=[],
      standards=["NIST SP 800-131A Rev. 2 (SHA-1 for digital signature generation is disallowed)",
                 "RFC 5280 section 6.1 (trust anchors are not verified by signature)"],
      compliance=["certificates"],
      remediation={"summary": "Re-issue the root or signing certificate with SHA-256 at its next renewal and "
                              "distribute the new one.",
                   "steps": [{"platform": "OpenSSL", "how": "openssl req -x509 -new -sha256 -key <key> -days 3650 "
                                                           "-out <new-root.pem> -subj '<same subject>'"}]},
      verify=V_CERT_REMOTE + V_CERT_FILE, references=["https://www.rfc-editor.org/rfc/rfc5280#section-6.1"])

NODE_CODES = ["CERT_SELF_SHA1"]
