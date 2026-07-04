"""C13 fixture — a MODERN TLS version (1.2) that still offers weak cipher suites.

The protocol *version* is strong (TLS 1.2), so the ONLY finding on this asset is
``WEAK_CIPHER_SUITE`` — isolating the C13 cipher-suite predicate from the C5
``WEAK_PROTOCOL`` (version) check. Every suite below is a named break:
  * RC4          — RFC 7465 (biased keystream);
  * 3DES         — SWEET32 (CVE-2016-2183, 64-bit block);
  * NULL         — no encryption;
  * EXPORT/DES40 — FREAK/Logjam (CVE-2015-0204 / CVE-2015-4000);
  * ADH / AECDH  — anonymous key exchange (unauthenticated → MITM).
"""
import ssl

# IANA suite names (captured by the protocol scanner's IANA cipher regex).
WEAK_SUITES = [
    "TLS_RSA_WITH_RC4_128_MD5",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_NULL_SHA",
    "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
]


def make_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Version floor is MODERN — TLS 1.2 — so crypto:strength is strong.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # OpenSSL cipher string with anonymous (unauthenticated) key exchange.
    ctx.set_ciphers("ADH-AES256-SHA:AECDH-AES128-SHA")
    return ctx
