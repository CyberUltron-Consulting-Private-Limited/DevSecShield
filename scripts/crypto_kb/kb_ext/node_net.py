"""Knowledge-base entries for the scan-node network package (WP7): IKE/VPN gateways, OT protocols (OPC UA, Modbus),
appliance configurations and service-mesh policy (Istio DestinationRule, Linkerd Server authorizations)."""
import kb_text
from kb_text import SSH_HARDEN

IKE_FIX = [
    {"platform": "strongSwan (swanctl.conf)", "how": "proposals = aes256gcm16-prfsha384-ecp384-ke1_mlkem768, aes256gcm16-prfsha256-x25519 (strongSwan 6 for ke1_mlkem768); remove 3des, des, md5, sha1, modp768/1024/1536; version = 2"},
    {"platform": "Cisco IOS XE", "how": "crypto ikev2 proposal P1 / encryption aes-gcm-256 / prf sha384 / group 20 21 ; remove 3des/des, md5/sha1 and groups 1/2/5 from every proposal; replace crypto isakmp policies with IKEv2"},
    {"platform": "Cisco ASA", "how": "crypto ikev2 policy 10 / encryption aes-gcm-256 / integrity null / group 20 21 / prf sha384 ; no crypto ikev1 enable <interface> once peers moved to IKEv2"},
    {"platform": "FortiOS", "how": "config vpn ipsec phase1-interface / edit <name> / set ike-version 2 / set proposal aes256gcm-prfsha384 / set dhgrp 20 21 / end"},
    {"platform": "PAN-OS", "how": "Network > Network Profiles > IKE Crypto: encryption aes-256-gcm, hash (prf) sha384, DH group20/group21; IKE Gateway: IKEv2 only mode"},
]
V_IKE = [
    {"label": "IKEv2 proposals the gateway accepts (sends IKE_SA_INIT only)", "command": "ike-scan --ikev2 -M {host}"},
    {"label": "IKEv1 Main Mode transforms (first message only)", "command": "ike-scan -M --trans=5,2,1,2 {host}"},
]
OT_SEGMENT = {"platform": "Network", "how": "Keep OT protocols in a dedicated zone (IEC 62443 zones and conduits); allow only the engineering stations and HMIs that need them"}

kb_text.entry(
    "IKE_WEAK_ENCR", title="VPN gateway accepts weak IKE encryption", category="protocol", default_impact="High",
    description="The IKE gateway accepts DES, 3DES or Blowfish to protect its IKE SA. These 64-bit block ciphers are "
                "deprecated for IKE (RFC 8247: DES MUST NOT, 3DES SHOULD NOT; RFC 9395 deprecates Blowfish).",
    attack="A peer (or an on-path attacker steering the negotiation) can get the IKE SA keyed with a cipher whose block "
           "size allows birthday attacks on long-lived SAs (SWEET32) and, for single DES, brute force of the key.",
    cwe=["CWE-327", "CWE-326"], owasp=["crypto", "misconfig"], cves=[],
    cve_rules=[{"match": "3des|blowfish", "cves": ["CVE-2016-2183"]}],
    standards=["RFC 8247 (IKEv2 algorithm requirements)", "RFC 9395 (deprecates IKEv1 and obsolete IKEv2 algorithms)",
               "NIST SP 800-77 Rev. 1"], compliance=["algorithms"],
    remediation={"summary": "Remove DES, 3DES and Blowfish from every IKE proposal; use AES-GCM (or AES-CBC with "
                            "HMAC-SHA-2) with 128 or 256-bit keys.", "steps": IKE_FIX},
    verify=V_IKE, references=["https://www.rfc-editor.org/rfc/rfc8247", "https://www.rfc-editor.org/rfc/rfc9395"])

kb_text.entry(
    "IKE_WEAK_INTEG", title="VPN gateway accepts MD5 or SHA-1 in IKE", category="protocol", default_impact="Medium",
    description="The IKE gateway accepts HMAC-MD5 or HMAC-SHA-1 as the IKE integrity algorithm or PRF (or MD5/SHA-1 "
                "as the IKEv1 hash). RFC 8247 makes HMAC-MD5 MUST NOT (reported Medium) and keeps HMAC-SHA-1 as "
                "MUST-, still required for interoperability but expected to be downgraded, so HMAC-SHA-1 alone is "
                "reported Low: HMAC does not depend on SHA-1's collision resistance.",
    attack="MD5 no longer meets current security margins; keeping it lets a downgraded negotiation key and "
           "authenticate the IKE SA with a primitive RFC 8247 forbids. HMAC-SHA-1 is not broken, but it is on its "
           "way out and auditors following NIST SP 800-131A ask for SHA-2.",
    cwe=["CWE-327", "CWE-328"], owasp=["crypto", "misconfig"], cves=[],
    standards=["RFC 8247 (IKEv2 algorithm requirements)", "NIST SP 800-131A Rev. 2"], compliance=["algorithms"],
    remediation={"summary": "Use HMAC-SHA-256/384/512 (or an AEAD cipher) and a SHA-2 PRF in every IKE proposal.",
                 "steps": IKE_FIX},
    verify=V_IKE, references=["https://www.rfc-editor.org/rfc/rfc8247"])

kb_text.entry(
    "IKE_WEAK_DH", title="VPN gateway accepts weak Diffie-Hellman groups", category="protocol", default_impact="High",
    description="The IKE gateway accepts MODP groups below 2048 bits (groups 1, 2, 5), the RFC 5114 groups 22-24 or "
                "the 192-bit ECP group 25 for the IKE key exchange.",
    attack="768 and 1024-bit discrete logarithms are within reach of well-resourced attackers (Logjam showed the "
           "precomputation for common 1024-bit primes); recorded IKE exchanges keyed with them can be decrypted, "
           "and so can the IPsec keys derived from them.",
    cwe=["CWE-326", "CWE-327"], owasp=["crypto", "misconfig"], cves=[],
    standards=["RFC 8247 section 2.4 (groups 1 MUST NOT; 2, 5, 22-24 SHOULD NOT)", "NIST SP 800-56A Rev. 3"],
    compliance=["keysize"],
    remediation={"summary": "Offer only group 19/20/21 (ECP), 31 (Curve25519) or MODP 2048+ (14, 15, 16), and use "
                            "the same groups for PFS in the child SAs.", "steps": IKE_FIX},
    verify=V_IKE, references=["https://www.rfc-editor.org/rfc/rfc8247", "https://weakdh.org/"])

kb_text.entry(
    "IKEV1_ENABLED", title="VPN gateway still accepts IKEv1", category="protocol", default_impact="Medium",
    description="The gateway accepted an IKEv1 (ISAKMP) Main Mode proposal. RFC 9395 deprecates IKEv1: it has no "
                "post-quantum option, weaker DoS protection and a history of PSK and fragmentation attacks.",
    attack="IKEv1 keeps legacy algorithms and modes (Aggressive Mode, XAUTH) reachable; attacks on its PSK handling "
           "and re-used keys across IKEv1 and IKEv2 (Bleichenbacher-style, 2018) only need the gateway to answer it.",
    cwe=["CWE-327", "CWE-757"], owasp=["crypto", "misconfig"], cves=[],
    standards=["RFC 9395 (deprecates IKEv1)", "NIST SP 800-77 Rev. 1"], compliance=["algorithms"],
    remediation={"summary": "Move every peer to IKEv2 and turn IKEv1 off on the gateway.", "steps": IKE_FIX},
    verify=[{"label": "Does the gateway answer IKEv1 Main Mode?", "command": "ike-scan -M {host}"}],
    references=["https://www.rfc-editor.org/rfc/rfc9395"])

kb_text.entry(
    "IKE_AGGRESSIVE", title="IKEv1 Aggressive Mode answered", category="protocol", default_impact="High",
    description="The gateway answered an IKEv1 Aggressive Mode request. With a pre-shared key, the answer carries a "
                "hash keyed with the PSK that anyone can request without authenticating.",
    attack="An attacker sends one Aggressive Mode request, receives HASH_R and cracks the pre-shared key offline "
           "(psk-crack, hashcat mode 5300/5400); with the PSK (and a group name) they can impersonate the gateway or "
           "connect as a client.",
    cwe=["CWE-522", "CWE-916", "CWE-327"], owasp=["crypto", "auth"], cves=[],
    standards=["RFC 2409 section 5 (Aggressive Mode exposes identities)", "RFC 9395"], compliance=["auth"],
    remediation={"summary": "Disable Aggressive Mode (Cisco: crypto isakmp aggressive-mode disable / crypto ikev1 "
                            "am-disable; FortiOS: set mode main); move to IKEv2 with certificates.", "steps": IKE_FIX},
    verify=[{"label": "Aggressive Mode answer (no credential needed; the hash is printed, keep it private)",
             "command": "ike-scan -M -A --id=vpn {host}"}],
    references=["https://www.rfc-editor.org/rfc/rfc2409", "https://www.rfc-editor.org/rfc/rfc9395"])

kb_text.entry(
    "IKE_NO_PQ", title="VPN gateway has no post-quantum key exchange", category="pqc", default_impact="Low",
    description="The gateway negotiates IKE with classical Diffie-Hellman only: it did not accept an ML-KEM "
                "additional key exchange (RFC 9370), or it speaks only IKEv1, which has none.",
    attack="IPsec traffic recorded today can be decrypted once a cryptographically relevant quantum computer can "
           "solve the recorded key exchanges (harvest now, decrypt later).",
    cwe=["CWE-327"], owasp=["crypto"], cves=[], pqc="quantum-broken",
    standards=["RFC 9370 (multiple key exchanges in IKEv2)", "FIPS 203 (ML-KEM)", "NIST IR 8547"], compliance=["pqc"],
    remediation={"summary": "Add an ML-KEM additional key exchange to the IKEv2 proposals where the gateway supports "
                            "it (strongSwan 6: ke1_mlkem768), keeping the classical group for the hybrid.",
                 "steps": [IKE_FIX[0]]},
    verify=[{"label": "Offer ML-KEM-768 as ADDKE1 (strongSwan 6 initiator)",
             "command": "swanctl --initiate --child <child> (with proposals = aes256gcm16-prfsha384-x25519-ke1_mlkem768)"}],
    references=["https://www.rfc-editor.org/rfc/rfc9370", "https://csrc.nist.gov/pubs/fips/203/final"])

kb_text.entry(
    "IPSEC_WEAK_TRANSFORM", title="Weak IPsec (ESP) transform configured", category="protocol",
    default_impact="Medium",
    description="An appliance's IPsec (ESP) proposal or crypto profile lists DES, 3DES, NULL encryption, MD5 or "
                "SHA-1 integrity, or a weak PFS group for the child SAs that carry the traffic. RFC 8221 makes "
                "HMAC-MD5 MUST NOT and keeps HMAC-SHA-1-96 as MUST- (allowed, expected to be phased out), so a "
                "proposal whose only weakness is HMAC-SHA-1 is reported Low.",
    attack="The child SA protects the actual data: a weak cipher, MD5 MAC or small PFS group there exposes the "
           "tunnelled traffic even when the IKE SA itself is strong; HMAC-SHA-1 is not broken but is being retired.",
    cwe=["CWE-327", "CWE-326"], owasp=["crypto", "misconfig"], cves=[],
    cve_rules=[{"match": "3des|blowfish", "cves": ["CVE-2016-2183"]}],
    standards=["RFC 8221 (ESP algorithm requirements)", "NIST SP 800-77 Rev. 1"], compliance=["algorithms"],
    remediation={"summary": "Use AES-GCM (or AES-CBC with HMAC-SHA-256+) for ESP and group 19/20/21/31 or 14+ for PFS.",
                 "steps": IKE_FIX},
    verify=[{"label": "The appliance's IPsec proposals (read-only)", "command": "show running-config | section crypto ipsec"}],
    references=["https://www.rfc-editor.org/rfc/rfc8221"])

kb_text.entry(
    "OPCUA_NONE_POLICY", title="OPC UA endpoint without security", category="protocol", default_impact="High",
    description="The OPC UA server offers an endpoint with SecurityPolicy None (MessageSecurityMode None): messages "
                "are neither signed nor encrypted.",
    attack="Anyone on the OT network reads process values and, if the address space is writable, changes set points "
           "or calls methods; the messages can also be modified in transit.",
    cwe=["CWE-319", "CWE-306"], owasp=["crypto", "misconfig"], cves=[],
    standards=["OPC UA Part 2 (Security Model)", "OPC UA Part 7 (Profiles)", "IEC 62443-3-3 SR 4.1"],
    compliance=["in_transit"],
    remediation={"summary": "Disable the None endpoint; offer Basic256Sha256 or Aes256_Sha256_RsaPss with "
                            "SignAndEncrypt only.", "steps": [
        {"platform": "OPC UA server configuration", "how": "Remove the None security policy (and Sign-only modes) from the server's endpoint list; keep SignAndEncrypt with Basic256Sha256 / Aes128_Sha256_RsaOaep / Aes256_Sha256_RsaPss"},
        OT_SEGMENT]},
    verify=[{"label": "Endpoints and security policies (Discovery service, no login)",
             "command": "uadiscover -u opc.tcp://{host}:{port}  (pip install asyncua)"}],
    references=["https://reference.opcfoundation.org/Core/Part2/v105/docs/"])

kb_text.entry(
    "OPCUA_DEPRECATED_POLICY", title="OPC UA deprecated security policy offered", category="protocol",
    default_impact="Medium",
    description="The OPC UA server offers Basic128Rsa15 or Basic256, deprecated in OPC UA 1.04 because they rely on "
                "SHA-1 signatures and (Basic128Rsa15) RSA PKCS#1 v1.5 key transport.",
    attack="A client that can be steered to the deprecated policy gets SHA-1 signatures and, with Basic128Rsa15, an "
           "RSA padding-oracle surface (Bleichenbacher) on the secure channel.",
    cwe=["CWE-327", "CWE-328"], owasp=["crypto", "misconfig"], cves=[],
    standards=["OPC UA Part 7 (Basic128Rsa15 and Basic256 deprecated)"], compliance=["algorithms"],
    remediation={"summary": "Remove Basic128Rsa15 and Basic256; offer Basic256Sha256, Aes128_Sha256_RsaOaep or "
                            "Aes256_Sha256_RsaPss.", "steps": [OT_SEGMENT]},
    verify=[{"label": "Endpoints and security policies", "command": "uadiscover -u opc.tcp://{host}:{port}  (pip install asyncua)"}],
    references=["https://reference.opcfoundation.org/Core/Part7/v105/docs/"])

kb_text.entry(
    "OPCUA_ANON", title="OPC UA accepts anonymous users", category="protocol", default_impact="Medium",
    description="An OPC UA endpoint lists an Anonymous user token policy: a session can be activated without any "
                "user identity.",
    attack="Anyone who can open a secure channel (and, on a None endpoint, anyone at all) browses and, depending on "
           "the server's permissions, reads or writes process data without a user name.",
    cwe=["CWE-306", "CWE-287"], owasp=["auth", "misconfig"], cves=[],
    standards=["OPC UA Part 4 (ActivateSession, user identity tokens)", "IEC 62443-3-3 SR 1.1"], compliance=["auth"],
    remediation={"summary": "Remove the Anonymous token policy; require user name (over an encrypted channel) or "
                            "X.509 user certificates.", "steps": [OT_SEGMENT]},
    verify=[{"label": "User token policies per endpoint", "command": "uadiscover -u opc.tcp://{host}:{port}  (pip install asyncua)"}],
    references=["https://reference.opcfoundation.org/Core/Part4/v105/docs/"])

kb_text.entry(
    "OPCUA_USERNAME_PLAINTEXT", title="OPC UA passwords sent in clear text", category="protocol",
    default_impact="High",
    description="An endpoint without message encryption offers a UserName token whose security policy is None, so the "
                "password is sent unencrypted.",
    attack="A passive listener on the OT network collects user names and passwords at every login and reuses them on "
           "this and other systems.",
    cwe=["CWE-319", "CWE-522"], owasp=["crypto", "auth"], cves=[],
    standards=["OPC UA Part 4 section 7.41 (UserNameIdentityToken encryption)"], compliance=["auth", "in_transit"],
    remediation={"summary": "Offer UserName tokens only on SignAndEncrypt endpoints, or give the token policy its own "
                            "security policy (Basic256Sha256) so the password is encrypted.", "steps": [OT_SEGMENT]},
    verify=[{"label": "User token policies per endpoint", "command": "uadiscover -u opc.tcp://{host}:{port}  (pip install asyncua)"}],
    references=["https://reference.opcfoundation.org/Core/Part4/v105/docs/"])

kb_text.entry(
    "MODBUS_PLAINTEXT", title="Modbus/TCP reachable (no encryption or authentication)", category="protocol",
    default_impact="High",
    description="The Modbus/TCP port (502) accepts connections. Modbus/TCP has no encryption and no authentication; "
                "the secure variant is Modbus/TCP Security over TLS on port 802.",
    attack="Anyone who reaches the port reads registers and coils and can write them (function codes 5, 6, 15, 16), "
           "changing set points or switching outputs of the device.",
    cwe=["CWE-319", "CWE-306"], owasp=["crypto", "auth"], cves=[],
    standards=["Modbus/TCP Security Protocol Specification (TLS, port 802)", "IEC 62443-3-3 SR 1.1 and SR 4.1"],
    compliance=["in_transit", "auth"],
    remediation={"summary": "Move to Modbus/TCP Security (mutual TLS on 802) where the device supports it; otherwise "
                            "restrict 502 to the controlling stations through an OT firewall.", "steps": [OT_SEGMENT]},
    verify=[{"label": "Does the port accept a TCP connection? (sends no Modbus request)", "command": "nc -vz -w 3 {host} {port}"}],
    references=["https://www.modbus.org/specs.php"])

kb_text.entry(
    "MESH_DR_TLS_DISABLED", title="Istio DestinationRule disables TLS", category="kubernetes", default_impact="High",
    description="An Istio DestinationRule sets trafficPolicy.tls.mode DISABLE (for the host, a port or a subset), so "
                "sidecars send plaintext to that destination instead of using mesh mTLS (High). For a host outside "
                "the cluster (a DNS name that is not a Kubernetes service, such as a managed database endpoint) the "
                "sidecar does not originate TLS by default either and the application usually does its own TLS, "
                "which passes through unchanged, so that case is Low: verify the application connects with TLS.",
    attack="Traffic to an in-mesh destination crosses the network unencrypted and unauthenticated; anyone on the path "
           "(a compromised node, a mirror port) reads and changes it. Toward an external host this happens only if "
           "the application itself connects without TLS.",
    cwe=["CWE-319"], owasp=["crypto", "misconfig"], cves=[], standards=["Istio security best practices"],
    compliance=["in_transit"],
    remediation={"summary": "Remove the DISABLE mode (or set ISTIO_MUTUAL for in-mesh hosts, SIMPLE/MUTUAL for "
                            "external TLS hosts).", "steps": [
        {"platform": "Istio", "how": "kubectl edit destinationrule <name> -n <namespace>: trafficPolicy.tls.mode: ISTIO_MUTUAL (also under portLevelSettings and subsets)"}]},
    verify=[{"label": "DestinationRules that disable TLS", "command": "kubectl get destinationrules -A -o yaml | grep -n -B12 'mode: DISABLE'"}],
    references=["https://istio.io/latest/docs/reference/config/networking/destination-rule/"])

kb_text.entry(
    "LINKERD_UNAUTHENTICATED_SERVER", title="Linkerd Server allows unauthenticated clients", category="kubernetes",
    default_impact="Medium",
    description="A Linkerd Server accepts clients without a mesh TLS identity: its accessPolicy is all- or "
                "cluster-unauthenticated, or a ServerAuthorization / AuthorizationPolicy grants unauthenticated or "
                "network-only access.",
    attack="Any pod (meshed or not) or address in the allowed networks reaches the workload without mTLS, so traffic "
           "can be plaintext and callers are not identified.",
    cwe=["CWE-306", "CWE-319"], owasp=["auth", "misconfig"], cves=[], standards=["Linkerd authorization policy"],
    compliance=["auth", "in_transit"],
    remediation={"summary": "Set accessPolicy: deny (or all-authenticated) and grant access with AuthorizationPolicies "
                            "that reference MeshTLSAuthentication identities.", "steps": [
        {"platform": "Linkerd", "how": "kubectl edit server <name> -n <namespace>: spec.accessPolicy: deny ; then add AuthorizationPolicy objects whose requiredAuthenticationRefs name a MeshTLSAuthentication"}]},
    verify=[{"label": "Servers and their authorizations", "command": "kubectl get servers.policy.linkerd.io,serverauthorizations.policy.linkerd.io,authorizationpolicies.policy.linkerd.io -A -o wide"}],
    references=["https://linkerd.io/2-edge/reference/authorization-policy/"])

kb_text.entry(
    "SSH_V1_ENABLED", title="SSH protocol version 1 enabled on an appliance", category="ssh", default_impact="High",
    description="The appliance configuration allows SSH protocol 1 (for example 'ip ssh version 1' or 'ssh version 1'), "
                "a design that has been broken for two decades.",
    attack="SSH-1 sessions can be hijacked and decrypted (CRC-32 compensation attack, weak integrity); a client that "
           "falls back to it exposes administrator credentials.",
    cwe=["CWE-327", "CWE-757"], owasp=["crypto", "misconfig"], cves=[], standards=["RFC 4253 (SSH-2 transport)"],
    compliance=["algorithms"],
    remediation={"summary": "Allow SSH version 2 only (Cisco IOS: ip ssh version 2; ASA: ssh version 2).",
                 "steps": [SSH_HARDEN[0]]},
    verify=[{"label": "Protocol versions the server announces", "command": "ssh -v -o BatchMode=yes -p {port} {host} exit 2>&1 | grep -i 'remote protocol version'"}],
    references=["https://www.rfc-editor.org/rfc/rfc4253"])

NODE_CODES = ["IKE_WEAK_ENCR", "IKE_WEAK_INTEG", "IKE_WEAK_DH", "IKEV1_ENABLED", "IKE_AGGRESSIVE", "IKE_NO_PQ",
              "IPSEC_WEAK_TRANSFORM", "OPCUA_NONE_POLICY", "OPCUA_DEPRECATED_POLICY", "OPCUA_ANON",
              "OPCUA_USERNAME_PLAINTEXT", "MODBUS_PLAINTEXT", "MESH_DR_TLS_DISABLED", "LINKERD_UNAUTHENTICATED_SERVER",
              "SSH_V1_ENABLED"]
