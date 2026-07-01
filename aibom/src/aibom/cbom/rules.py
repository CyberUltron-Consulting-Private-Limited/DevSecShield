"""Crypto detection knowledge — reconciled from the worker ``cbom_agent``.

This is the faithful port of the worker agent's ``crypto_rules.py`` detection
corpus (algorithm tables, language patterns, normalization, ambiguous-token
gating) into the aibom/ lane, plus the per-usage **parametrization** extraction
(key size / mode / curve) the worker lacked — the piece the CBOM ground-truth
oracle (``tests/fixtures/synthetic-crypto-app/expected_crypto.json``) demands to
distinguish RSA-2048 from RSA-1024 and AES-GCM from AES-ECB.

Nothing here scores or serializes (lane discipline): it only maps source tokens
to normalized crypto-asset facts. The scanner (``scanners/algorithm_scan.py``)
turns these facts into ``crypto_asset`` components.
"""

from __future__ import annotations

import re

# --------------------------------------------------------------------------- #
# Language detection (port: LANGUAGE_EXTENSIONS)
# --------------------------------------------------------------------------- #

LANGUAGE_EXTENSIONS: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".java": "java",
    ".kt": "java",
    ".kts": "java",
    ".scala": "java",
    ".go": "go",
    ".c": "c",
    ".h": "c",
    ".cpp": "c",
    ".cc": "c",
    ".cxx": "c",
    ".hpp": "c",
    ".rb": "ruby",
    ".rs": "rust",
    ".php": "php",
    ".phtml": "php",
}

# --------------------------------------------------------------------------- #
# Algorithm strength tables (port: WEAK_ALGORITHMS / STANDARD_ALGORITHMS).
# ``primitive`` is the CycloneDX 1.6 cryptographic primitive enum value
# (block-cipher | stream-cipher | hash | pke | signature | mac | kdf | drbg |
# key-agree | kem | ae | xof | combiner | other | unknown). ``quantum_vulnerable``
# is true for asymmetric primitives broken by Shor's algorithm (RSA/ECC/DH).
# --------------------------------------------------------------------------- #

# (primitive, strength, quantum_vulnerable, default_key_size)
_WEAK = "weak"
_MOD = "moderate"
_STRONG = "strong"

WEAK_ALGORITHMS: dict[str, dict] = {
    "md5": {"primitive": "hash", "strength": _WEAK, "quantum_vulnerable": False},
    "md4": {"primitive": "hash", "strength": _WEAK, "quantum_vulnerable": False},
    "sha1": {"primitive": "hash", "strength": _WEAK, "quantum_vulnerable": False},
    "des": {"primitive": "block-cipher", "strength": _WEAK,
            "quantum_vulnerable": False, "key_size": 56},
    "3des": {"primitive": "block-cipher", "strength": _MOD,
             "quantum_vulnerable": False, "key_size": 168},
    "rc2": {"primitive": "block-cipher", "strength": _WEAK,
            "quantum_vulnerable": False},
    "rc4": {"primitive": "stream-cipher", "strength": _WEAK,
            "quantum_vulnerable": False},
    "blowfish": {"primitive": "block-cipher", "strength": _MOD,
                 "quantum_vulnerable": False},
    "rsa-512": {"primitive": "pke", "strength": _WEAK,
                "quantum_vulnerable": True, "key_size": 512},
    "rsa-1024": {"primitive": "pke", "strength": _WEAK,
                 "quantum_vulnerable": True, "key_size": 1024},
}

STANDARD_ALGORITHMS: dict[str, dict] = {
    "sha256": {"primitive": "hash", "strength": _STRONG, "quantum_vulnerable": False},
    "sha384": {"primitive": "hash", "strength": _STRONG, "quantum_vulnerable": False},
    "sha512": {"primitive": "hash", "strength": _STRONG, "quantum_vulnerable": False},
    "sha3_256": {"primitive": "hash", "strength": _STRONG, "quantum_vulnerable": False},
    "sha3_384": {"primitive": "hash", "strength": _STRONG, "quantum_vulnerable": False},
    "sha3_512": {"primitive": "hash", "strength": _STRONG, "quantum_vulnerable": False},
    "blake2b": {"primitive": "hash", "strength": _STRONG, "quantum_vulnerable": False},
    "blake2s": {"primitive": "hash", "strength": _STRONG, "quantum_vulnerable": False},
    "aes": {"primitive": "block-cipher", "strength": _STRONG,
            "quantum_vulnerable": False},
    "aes-128": {"primitive": "block-cipher", "strength": _STRONG,
                "quantum_vulnerable": False, "key_size": 128},
    "aes-192": {"primitive": "block-cipher", "strength": _STRONG,
                "quantum_vulnerable": False, "key_size": 192},
    "aes-256": {"primitive": "block-cipher", "strength": _STRONG,
                "quantum_vulnerable": False, "key_size": 256},
    "chacha20": {"primitive": "stream-cipher", "strength": _STRONG,
                 "quantum_vulnerable": False},
    "chacha20-poly1305": {"primitive": "ae", "strength": _STRONG,
                          "quantum_vulnerable": False},
    "rsa": {"primitive": "pke", "strength": _STRONG, "quantum_vulnerable": True},
    "rsa-2048": {"primitive": "pke", "strength": _STRONG,
                 "quantum_vulnerable": True, "key_size": 2048},
    "rsa-4096": {"primitive": "pke", "strength": _STRONG,
                 "quantum_vulnerable": True, "key_size": 4096},
    "ecdsa": {"primitive": "signature", "strength": _STRONG,
              "quantum_vulnerable": True},
    "ed25519": {"primitive": "signature", "strength": _STRONG,
                "quantum_vulnerable": True},
    "ed448": {"primitive": "signature", "strength": _STRONG,
              "quantum_vulnerable": True},
    "x25519": {"primitive": "key-agree", "strength": _STRONG,
               "quantum_vulnerable": True},
    "dh": {"primitive": "key-agree", "strength": _STRONG, "quantum_vulnerable": True},
    "ecdh": {"primitive": "key-agree", "strength": _STRONG,
             "quantum_vulnerable": True},
    "dsa": {"primitive": "signature", "strength": _MOD, "quantum_vulnerable": True},
    "pbkdf2": {"primitive": "kdf", "strength": _STRONG, "quantum_vulnerable": False},
    "scrypt": {"primitive": "kdf", "strength": _STRONG, "quantum_vulnerable": False},
    "argon2": {"primitive": "kdf", "strength": _STRONG, "quantum_vulnerable": False},
    "bcrypt": {"primitive": "kdf", "strength": _STRONG, "quantum_vulnerable": False},
    "hkdf": {"primitive": "kdf", "strength": _STRONG, "quantum_vulnerable": False},
    "hmac": {"primitive": "mac", "strength": _STRONG, "quantum_vulnerable": False},
    "cmac": {"primitive": "mac", "strength": _STRONG, "quantum_vulnerable": False},
    "poly1305": {"primitive": "mac", "strength": _STRONG, "quantum_vulnerable": False},
    # PQC (quantum-safe migration targets)
    "kyber": {"primitive": "kem", "strength": _STRONG, "quantum_vulnerable": False},
    "dilithium": {"primitive": "signature", "strength": _STRONG,
                  "quantum_vulnerable": False},
    "sphincs+": {"primitive": "signature", "strength": _STRONG,
                 "quantum_vulnerable": False},
    "falcon": {"primitive": "signature", "strength": _STRONG,
               "quantum_vulnerable": False},
}


def algo_info(key: str) -> dict | None:
    """Strength/primitive record for a canonical algorithm key (or None)."""
    return WEAK_ALGORITHMS.get(key) or STANDARD_ALGORITHMS.get(key)


# --------------------------------------------------------------------------- #
# Display normalization (port: ALGORITHM_NORMALIZE)
# --------------------------------------------------------------------------- #

ALGORITHM_NORMALIZE: dict[str, str] = {
    "md5": "MD5", "md4": "MD4", "sha1": "SHA-1",
    "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512",
    "sha3_256": "SHA3-256", "sha3_384": "SHA3-384", "sha3_512": "SHA3-512",
    "blake2b": "BLAKE2b", "blake2s": "BLAKE2s",
    "aes": "AES", "aes-128": "AES-128", "aes-192": "AES-192", "aes-256": "AES-256",
    "des": "DES", "3des": "3DES", "blowfish": "Blowfish", "rc2": "RC2", "rc4": "RC4",
    "chacha20": "ChaCha20", "chacha20-poly1305": "ChaCha20-Poly1305",
    "rsa": "RSA", "rsa-512": "RSA-512", "rsa-1024": "RSA-1024",
    "rsa-2048": "RSA-2048", "rsa-4096": "RSA-4096",
    "ecdsa": "ECDSA", "ed25519": "Ed25519", "ed448": "Ed448", "x25519": "X25519",
    "dh": "Diffie-Hellman", "ecdh": "ECDH", "dsa": "DSA",
    "pbkdf2": "PBKDF2", "scrypt": "scrypt", "argon2": "Argon2", "bcrypt": "bcrypt",
    "hkdf": "HKDF", "hmac": "HMAC", "cmac": "CMAC", "poly1305": "Poly1305",
    "kyber": "CRYSTALS-Kyber", "dilithium": "CRYSTALS-Dilithium",
    "sphincs+": "SPHINCS+", "falcon": "FALCON",
}

# Whole-token aliases -> canonical algorithm key (port: LITERAL_ALGO_ALIASES).
LITERAL_ALGO_ALIASES: dict[str, str] = {
    "md5": "md5", "md4": "md4", "sha1": "sha1",
    "sha224": "sha256", "sha256": "sha256", "sha384": "sha384", "sha512": "sha512",
    "sha3": "sha3_256", "sha3256": "sha3_256", "sha3384": "sha3_384",
    "sha3512": "sha3_512", "blake2b": "blake2b", "blake2s": "blake2s",
    "aes": "aes", "aes128": "aes-128", "aes192": "aes-192", "aes256": "aes-256",
    "aesgcm": "aes-256", "rijndael": "aes",
    "des": "des", "3des": "3des", "desede": "3des", "tripledes": "3des",
    "rc4": "rc4", "arc4": "rc4", "rc2": "rc2", "blowfish": "blowfish",
    "chacha20": "chacha20", "chacha20poly1305": "chacha20-poly1305",
    "poly1305": "poly1305",
    "rsa": "rsa", "rsa512": "rsa-512", "rsa1024": "rsa-1024",
    "rsa2048": "rsa-2048", "rsa4096": "rsa-4096",
    "ecdsa": "ecdsa", "ed25519": "ed25519", "ed448": "ed448", "x25519": "x25519",
    "ecdh": "ecdh", "diffiehellman": "dh", "dsa": "dsa",
    "hmac": "hmac", "cmac": "cmac",
    "pbkdf2": "pbkdf2", "scrypt": "scrypt", "bcrypt": "bcrypt",
    "argon2": "argon2", "hkdf": "hkdf",
    "kyber": "kyber", "mlkem": "kyber", "dilithium": "dilithium",
    "mldsa": "dilithium", "sphincs": "sphincs+", "slhdsa": "sphincs+",
    "falcon": "falcon",
}

# JWT "alg" header values -> component algorithm keys (port: JWT_ALG_MAP).
JWT_ALG_MAP: dict[str, list[str]] = {
    "hs256": ["hmac", "sha256"], "hs384": ["hmac", "sha384"],
    "hs512": ["hmac", "sha512"],
    "rs256": ["rsa", "sha256"], "rs384": ["rsa", "sha384"],
    "rs512": ["rsa", "sha512"],
    "ps256": ["rsa", "sha256"], "ps384": ["rsa", "sha384"],
    "ps512": ["rsa", "sha512"],
    "es256": ["ecdsa", "sha256"], "es384": ["ecdsa", "sha384"],
    "es512": ["ecdsa", "sha512"], "es256k": ["ecdsa", "sha256"],
    "eddsa": ["ed25519"],
}

# Short tokens that are also common non-crypto identifiers (port: AMBIGUOUS_TOKENS).
AMBIGUOUS_TOKENS = frozenset(
    {"des", "3des", "rsa", "aes", "dsa", "rc2", "rc4", "tls", "ssl", "md4",
     "falcon", "rijndael"}
)

# Crypto-context signals used to disambiguate ambiguous tokens on import / dotted
# call lines (port: CRYPTO_CONTEXT_HINTS / CRYPTO_METHOD_HINTS).
CRYPTO_CONTEXT_HINTS = frozenset(
    {
        "pqcrypto", "liboqs", "oqs", "pqclean", "openquantumsafe",
        "cryptography", "crypto.", "cryptodome", "pycrypto", "nacl", "pynacl",
        "openssl", "libsodium", "sodium", "bouncycastle",
        "crypto/", "golang.org/x/crypto", "ring", "rustls", "sodiumoxide",
        "phpseclib", "tweetnacl", "node-forge", "forge", "crypto-js", "cryptojs",
        "elliptic", "sshpk", "javax.crypto", "java.security", "javax.net.ssl",
        "hashlib", "hazmat", "mbedtls", "wolfssl", "gnutls", "secrets",
        "subtle", "webcrypto",
    }
)
CRYPTO_METHOD_HINTS = frozenset(
    {
        "newcipher", "newgcm", "generatekey", "generate_private_key",
        "encryptoaep", "decryptoaep", "newcbcencrypter", "newcbcdecrypter",
        "newctr", "newcfbencrypter", "newofb", "newcfbdecrypter",
        "signpkcs1v15", "verifypkcs1v15", "loadx509keypair",
        "createcipheriv", "createdecipheriv", "createsign", "createverify",
    }
)

# --------------------------------------------------------------------------- #
# Crypto-LIBRARY detection. Maps a declared dependency name or an imported
# module root to a normalized crypto-library label. Reconciled from the worker's
# LANGUAGE_PATTERNS import rules; used by the C1 "library" half of the scanner.
# --------------------------------------------------------------------------- #

# requirements.txt / package name -> normalized crypto-library label.
CRYPTO_LIBRARY_PACKAGES: dict[str, str] = {
    "cryptography": "pyca/cryptography",
    "pyopenssl": "pyOpenSSL",
    "pycryptodome": "PyCryptodome",
    "pycryptodomex": "PyCryptodome",
    "pynacl": "PyNaCl",
    "bcrypt": "bcrypt",
    "argon2-cffi": "argon2-cffi",
    "passlib": "passlib",
    "pyjwt": "PyJWT",
    "python-jose": "python-jose",
    "ecdsa": "python-ecdsa",
}

# imported module root -> normalized crypto-library label (stdlib + 3rd-party).
CRYPTO_IMPORT_MODULES: dict[str, str] = {
    "hashlib": "hashlib (stdlib)",
    "ssl": "ssl (stdlib)",
    "secrets": "secrets (stdlib)",
    "hmac": "hmac (stdlib)",
    "cryptography": "pyca/cryptography",
    "openssl": "pyOpenSSL",
    "crypto": "PyCryptodome",
    "cryptodome": "PyCryptodome",
    "nacl": "PyNaCl",
    "jwt": "PyJWT",
    "jose": "python-jose",
    # Go (C2) — stdlib crypto/* import roots + golang.org/x/crypto.
    "crypto/aes": "Go crypto (stdlib)",
    "crypto/des": "Go crypto (stdlib)",
    "crypto/rc4": "Go crypto (stdlib)",
    "crypto/rsa": "Go crypto (stdlib)",
    "crypto/ecdsa": "Go crypto (stdlib)",
    "crypto/ed25519": "Go crypto (stdlib)",
    "crypto/elliptic": "Go crypto (stdlib)",
    "crypto/tls": "Go crypto (stdlib)",
    "crypto/x509": "Go crypto (stdlib)",
    "golang.org/x/crypto": "golang.org/x/crypto",
    # Java (C2) — JCA/JCE import roots + Bouncy Castle.
    "javax.crypto": "JCA/JCE (javax.crypto)",
    "java.security": "JCA/JCE (java.security)",
    "org.bouncycastle": "Bouncy Castle",
    "bouncycastle": "Bouncy Castle",
}

# --------------------------------------------------------------------------- #
# Parametrization extraction (THE ADDED PIECE). Pulls key size / mode / curve
# out of the same source line the algorithm was detected on, so a usage resolves
# to RSA-2048 vs RSA-1024 and AES-GCM vs AES-ECB rather than a flat "RSA"/"AES".
# --------------------------------------------------------------------------- #

_KEY_SIZE_RE = re.compile(
    r"key[_-]?size\s*=\s*(\d{3,5})|"          # key_size=2048
    r"\b(?:bits?|length)\s*=\s*(\d{3,5})|"     # length=2048
    r"\b(512|1024|2048|3072|4096|7680)\b"      # bare modulus size
)
# Block-cipher / AEAD mode of operation.
_MODE_RE = re.compile(
    r"\bmodes?\.\s*(GCM|CBC|ECB|CTR|CFB|OFB|XTS|CCM)\b|"     # pyca: modes.GCM(
    r"\bMODE_(GCM|CBC|ECB|CTR|CFB|OFB|XTS|CCM)\b|"           # PyCryptodome
    r"/(GCM|CBC|ECB|CTR|CFB|OFB)/|"                          # java "AES/GCM/.."
    r"-(GCM|CBC|ECB|CTR|CFB|OFB)\b",                         # name suffix
    re.IGNORECASE,
)
# Named elliptic curve.
_CURVE_RE = re.compile(
    r"\b(SECP256R1|SECP384R1|SECP521R1|SECP256K1|PRIME256V1|"
    r"P-?256|P-?384|P-?521|Curve25519|Ed25519|X25519|BrainpoolP\d+)\b",
    re.IGNORECASE,
)
# AES key size implied by the symmetric KEY-length argument is NOT reliably on
# the line, so AES variants are distinguished by MODE (above), per the oracle.


def extract_key_size(line: str) -> int | None:
    """Parse an explicit asymmetric/symmetric key size from ``line`` (or None)."""
    m = _KEY_SIZE_RE.search(line)
    if not m:
        return None
    for g in m.groups():
        if g:
            return int(g)
    return None


def extract_mode(line: str) -> str | None:
    """Parse a block-cipher mode of operation from ``line`` (or None)."""
    m = _MODE_RE.search(line)
    if not m:
        return None
    for g in m.groups():
        if g:
            return g.upper()
    return None


def extract_curve(line: str) -> str | None:
    """Parse a named elliptic curve from ``line`` (or None)."""
    m = _CURVE_RE.search(line)
    return m.group(1) if m else None


__all__ = [
    "LANGUAGE_EXTENSIONS",
    "WEAK_ALGORITHMS",
    "STANDARD_ALGORITHMS",
    "ALGORITHM_NORMALIZE",
    "LITERAL_ALGO_ALIASES",
    "JWT_ALG_MAP",
    "AMBIGUOUS_TOKENS",
    "CRYPTO_CONTEXT_HINTS",
    "CRYPTO_METHOD_HINTS",
    "CRYPTO_LIBRARY_PACKAGES",
    "CRYPTO_IMPORT_MODULES",
    "algo_info",
    "extract_key_size",
    "extract_mode",
    "extract_curve",
]
