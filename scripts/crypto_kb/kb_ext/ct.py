"""Certificate Transparency discovery finding codes (CT track).

Rules: backend/utilities/cbom_sources/classify.py (_cert_rules), from facts written by ct_collect.py: the team's expected
certificate authorities (issuer_expected), the provider's revocation status (revoked), and live wildcard certificates
per name (wildcard_sprawl).  Expiry, weak keys and SHA-1 reuse CERT_EXPIRED, CERT_EXPIRES_30D, RSA_LT_*, EC_LT_224,
DSA, SIG_SHA1 and SIG_MD5.
"""
from kb_text import CERT_REISSUE, V_CERT_REMOTE, entry

V_CT_SEARCH = [{"label": "Every logged certificate for the name (Cert Spotter, unexpired; no key needed for a few queries)",
                "command": "curl -s 'https://api.certspotter.com/v1/issuances?domain={name}&include_subdomains=true"
                           "&match_wildcards=true&expand=dns_names&expand=issuer&expand=revocation' | "
                           "jq -r '.[] | [.not_before, .not_after, .issuer.friendly_name, .revoked, (.dns_names|join(\" \"))] | @tsv'"},
               {"label": "The same name in crt.sh (best effort: often slow or 502)",
                "command": "curl -s 'https://crt.sh/?q={name}&output=json&exclude=expired&deduplicate=Y' | "
                           "jq -r '.[] | [.not_before, .not_after, .issuer_name, .name_value] | @tsv'"}]
V_CAA = [{"label": "CAs allowed to issue for the name (CAA)", "command": "dig +short CAA {name}"}]

NODE_CODES = ["CERT_UNEXPECTED_CA", "CERT_REVOKED", "CERT_WILDCARD_SPRAWL"]

entry("CERT_UNEXPECTED_CA", title="Certificate from a CA the team does not use", category="certificate",
      default_impact="Medium",
      description="Certificate Transparency logs hold a certificate for one of the team's domains issued by a certificate "
                  "authority that is not in the team's list of expected CAs.",
      attack="A certificate from an unexpected CA is either shadow IT (a team or vendor buying certificates outside the "
             "process, often unmanaged and left to expire) or mis-issuance: someone who could pass that CA's domain "
             "validation can impersonate the name to every browser.",
      cwe=["CWE-295", "CWE-345"], owasp=["crypto", "misconfig"], cves=[], standards=["RFC 6962", "RFC 8659 (CAA)"],
      compliance=["certificates"],
      remediation={"summary": "Find who requested it. If it is legitimate, add the CA to the expected list; if not, ask the CA "
                              "to revoke it and publish CAA records that allow only your CAs.", "steps": [
          {"platform": "DNS", "how": "Publish CAA records naming only your CAs, e.g. example.com. CAA 0 issue \"letsencrypt.org\""},
          {"platform": "Any CA", "how": "Report mis-issuance to the CA's problem-reporting address (Cert Spotter shows it per issuance)"},
          {"platform": "ZeroShield", "how": "Cloud & Identity > Certificate Transparency: add the CA to the expected issuers if it is approved"}]},
      verify=V_CT_SEARCH + V_CAA, references=["https://www.rfc-editor.org/rfc/rfc8659"])
entry("CERT_REVOKED", title="Certificate revoked", category="certificate", default_impact="Low",
      description="The certificate is logged in Certificate Transparency and its CA reports it as revoked.",
      attack="Revocation is usually the right outcome (a replaced or compromised key). It becomes a problem if a server still "
             "presents the certificate: clients that check revocation refuse the connection, and clients that do not are "
             "exposed if the key was compromised.",
      cwe=["CWE-295"], owasp=["crypto"], cves=[], standards=["RFC 5280"], compliance=["certificates"],
      remediation={"summary": "Make sure no server still presents it; if the revocation was for key compromise, rotate the key "
                              "everywhere it was used.", "steps": CERT_REISSUE},
      verify=V_CERT_REMOTE + V_CT_SEARCH, references=["https://www.rfc-editor.org/rfc/rfc5280#section-5.3.1"])
entry("CERT_WILDCARD_SPRAWL", title="Many live wildcard certificates for one name", category="certificate",
      default_impact="Low",
      description="More than three unexpired, unrevoked wildcard certificates cover the same name. Every copy of a wildcard "
                  "key can impersonate every subdomain, so each extra certificate is another place the key lives.",
      attack="A wildcard key copied to many servers, vendors or CDNs is only as safe as the weakest of them; one leak "
             "allows impersonating every subdomain, including ones that never used the certificate.",
      cwe=["CWE-1104", "CWE-320"], owasp=["crypto", "misconfig"], cves=[], standards=["NIST SP 800-57 Part 1"],
      compliance=["key_mgmt"],
      remediation={"summary": "Replace wildcards with per-service certificates where you can (ACME makes this cheap), keep "
                              "one owner per wildcard, and revoke the ones nobody uses.", "steps": [
          {"platform": "ACME / cert-manager", "how": "Issue a certificate per host name instead of *.{name}"},
          {"platform": "Any CA", "how": "Revoke wildcard certificates no deployed server presents"}]},
      verify=V_CT_SEARCH, references=[])
