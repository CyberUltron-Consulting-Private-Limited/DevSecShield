"""Protocol lane — a deliberately weak TLS configuration (TLS 1.0).

The CBOM protocol scanner (C3) must surface this as a TLS protocol asset at
version 1.0 and flag it weak (TLS < 1.2). Labeled in expected_crypto.json.
"""
import ssl

# WEAK: pins the protocol floor to TLS 1.0.
TLS_MIN_VERSION = "TLSv1.0"
TLS_CIPHERS = "ECDHE-RSA-AES128-SHA"  # SHA-1 MAC, legacy suite


def make_weak_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # WEAK: explicitly allow TLS 1.0 (below the TLS 1.2 floor).
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.set_ciphers(TLS_CIPHERS)
    return ctx
