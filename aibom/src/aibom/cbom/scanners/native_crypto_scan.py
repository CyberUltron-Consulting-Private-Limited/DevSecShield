"""CBOM scanner (C3): a **JS/TS + C/C++ + Rust + .NET** crypto-API scanner that
extends the C1/C2 detection-rule model (the entry-point symbol fixes the
primitive *context*; the call arguments / algorithm-object fields supply the
parameters) to the four language families the upstream Sonar-Cryptography engine
does *not* cover — clean-room (ledger row 4 / rows 78-90: we studied the
*behavior* of each per-library API→asset map from public API docs — MDN
WebCrypto, Node ``crypto``, the OpenSSL EVP manuals, RustCrypto/ring crate docs,
and the .NET ``System.Security.Cryptography`` reference — and wrote our own
original resolver; no DSL, no copied detection rules).

None of these languages has a stdlib parser available to the product (and
shipping a third-party grammar would break the no-vendored-tooling rule), so —
exactly like C2 — this scanner is an original **call-expression extractor**: it
strips comments (keeping string literals, since Node/OpenSSL cipher *specs* live
in them), follows simple intra-file variable bindings, and resolves each crypto
entry-point's algorithm + key size + mode + curve + padding the same way C1/C2
do. The symbol/binding skeleton is language-agnostic; only the per-language
front-end differs.

Library → asset maps implemented here (the R2 per-library corpus, rows 86-90):

* **Node.js ``crypto``** (``.js/.ts/.mjs/.cjs`` …) — ``createHash('sha256')``,
  ``createHmac``, ``createCipheriv('aes-256-gcm', …)`` (the OpenSSL cipher spec
  string carries algorithm + key size + mode), ``createSign('RSA-SHA256')``,
  ``generateKeyPair('rsa', {modulusLength: 2048})`` / ``('ec', {namedCurve})``,
  ``createDiffieHellman``.
* **WebCrypto** (``crypto.subtle``) — the algorithm object's ``name`` field
  (``AES-GCM`` / ``RSA-OAEP`` / ``ECDSA`` / ``ECDH`` / ``RSASSA-PKCS1-v1_5`` /
  ``RSA-PSS`` / ``HMAC`` / ``PBKDF2`` / ``HKDF`` / ``Ed25519`` / ``X25519``),
  plus ``namedCurve`` / ``modulusLength`` / ``hash``, and
  ``subtle.digest('SHA-256', …)``.
* **OpenSSL / BoringSSL** (C/C++) — the ``EVP_<algo>_<bits>_<mode>`` cipher fn
  family (name-encoded algo+size+mode), the ``EVP_<hash>`` digest family + the
  legacy ``SHA256_Init`` / ``MD5_Init`` calls, ``RSA_generate_key_ex`` /
  ``EVP_RSA_gen`` key size, and ``EC_KEY_new_by_curve_name(NID_…)`` curve.
* **RustCrypto + ring** (Rust) — CamelCase RustCrypto types (``Aes256Gcm``,
  ``ChaCha20Poly1305``, ``Sha256``, ``RsaPrivateKey``, ``Ed25519``, ``p256``,
  ``Hmac`` …) with ``RsaPrivateKey::new(rng, 2048)`` size, and ring's SCREAMING
  constants (``AES_256_GCM``, ``CHACHA20_POLY1305``, ``SHA256``,
  ``ED25519``, ``ECDSA_P256_SHA256``, ``RSA_PKCS1_…``).
* **.NET ``System.Security.Cryptography``** (``.cs``) — ``Aes.Create()`` /
  ``AesGcm`` / ``TripleDES`` / ``DES`` / ``RC2``, ``RSA.Create(2048)`` /
  ``RSACryptoServiceProvider``, ``ECDsa.Create`` / ``ECDiffieHellman`` (+
  ``ECCurve.NamedCurves.nistP256``), the ``SHA256.Create`` / ``new SHA256…``
  digest classes, ``HMACSHA256``, ``Rfc2898DeriveBytes`` (PBKDF2), plus
  ``CipherMode`` / ``RSAEncryptionPadding`` bound to same-file symmetric / RSA
  assets.

Lane discipline (EMIT only): one ``crypto_asset`` (assetType=algorithm) per
distinct (algorithm+params, file) usage, with ``crypto:detectedBy`` (the library
that fixed the context), ``crypto:detectionContext`` (the primitive role),
``crypto:detectionMethod=call-expr`` and ``crypto:confidence``. Weak-flagging is
C6, PQC grading is C7, the CycloneDX serialization is C9. To stay additive the
scanner emits the SAME ``crypto-algo-{name}-{file}`` bom-refs the regex scanner
(order 10) would, runs *before* it (order 9), and the regex pass defers to any
ref already present (``ctx.has_ref``); the pipeline also de-dups by bom-ref.
``.cs`` is not in the regex scanner's language set, so .NET is C3-only.
"""

from __future__ import annotations

import re
from pathlib import Path

from aibom.cbom.registry import cbom_register
from aibom.cbom.rules import algo_info
from aibom.cbom.scanners.algorithm_scan import _slug
from aibom.cbom.scanners.jvm_go_crypto_scan import (
    _Asset,
    _build,
    _canon,
    _dedup,
    _iter_files,
    _strip_comments,
)
from aibom.model.component import CryptoAssetComponent
from aibom.scan.registry import ScanContext, Scanner

_JS_EXT = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"})
_C_EXT = frozenset({".c", ".h", ".cpp", ".cc", ".cxx", ".hpp"})
_RUST_EXT = frozenset({".rs"})
_DOTNET_EXT = frozenset({".cs"})

# Library labels (crypto:detectedBy).
_NODE = "Node.js crypto"
_WEBCRYPTO = "WebCrypto (SubtleCrypto)"
_OPENSSL = "OpenSSL/BoringSSL (C/C++)"
_RUSTCRYPTO = "RustCrypto"
_RING = "ring (Rust)"
_DOTNET = ".NET System.Security.Cryptography"

_MODE_TOKENS = frozenset(
    {"gcm", "cbc", "ecb", "ctr", "cfb", "ofb", "xts", "ccm"}
)
_KEY_SIZES = frozenset({56, 128, 168, 192, 256, 512, 1024, 2048, 3072, 4096})


# --------------------------------------------------------------------------- #
# Shared: parse an OpenSSL-style cipher spec (Node ``aes-256-gcm`` / EVP
# ``aes_256_gcm``) into (algo key, key size, mode). Returns None if the leading
# token is not a known cipher.
# --------------------------------------------------------------------------- #

# Known cipher leading-tokens → canonical key. Tokens NOT listed (camellia,
# aria, sm4, cast5, idea, seed …) are intentionally absent — they are not in our
# strength tables, so ``_build`` would reject them anyway; omitting them keeps
# this map to what we actually inventory.
_CIPHER_ALGO_TOK: dict[str, str] = {
    "aes": "aes", "des": "des", "des3": "3des", "3des": "3des",
    "rc4": "rc4", "rc2": "rc2", "bf": "blowfish", "blowfish": "blowfish",
    "chacha20": "chacha20",
}


def _parse_cipher_spec(name: str) -> tuple[str, int | None, str | None] | None:
    toks = [t for t in re.split(r"[-_]", name.lower()) if t]
    if not toks:
        return None
    # AEAD: chacha20-poly1305 / xchacha20-poly1305 → one combined asset.
    if "poly1305" in toks and toks[0] in ("chacha20", "xchacha20"):
        return ("chacha20-poly1305", None, None)
    size: int | None = None
    mode: str | None = None
    body: list[str] = []
    for t in toks:
        if t in _MODE_TOKENS:
            mode = t.upper()
        elif t.isdigit() and int(t) in _KEY_SIZES:
            size = int(t)
        else:
            body.append(t)
    if not body:
        return None
    algo_tok = body[0]
    if algo_tok == "des" and len(body) > 1 and body[1] in ("ede3", "ede", "ede2"):
        key: str | None = "3des"
    elif algo_tok in _CIPHER_ALGO_TOK:
        key = _CIPHER_ALGO_TOK[algo_tok]
    else:
        key = _canon(algo_tok)
    if not key:
        return None
    return (key, size, mode)


def _add(assets: list[_Asset], key: str | None, role: str, lib: str, loc: str,
         *, size: int | None = None, mode: str | None = None,
         curve: str | None = None, padding: str | None = None) -> None:
    if not key:
        return
    a = _build(key, role, lib, loc, key_size=size, mode=mode, curve=curve)
    if a:
        if padding:
            a.padding = padding
        assets.append(a)


# --------------------------------------------------------------------------- #
# JS / TS — Node.js ``crypto`` + WebCrypto
# --------------------------------------------------------------------------- #

_JS_IMPORT = re.compile(
    r"require\(\s*['\"](?:node:)?crypto['\"]\s*\)|"
    r"from\s+['\"](?:node:)?crypto['\"]|"
    r"import\s+['\"](?:node:)?crypto['\"]|"
    r"crypto\.subtle|\bSubtleCrypto\b|\bwebcrypto\b"
)
_JS_HASH = re.compile(r"\bcreateHash\s*\(\s*['\"]([\w-]+)['\"]")
_JS_HMAC = re.compile(r"\bcreateHmac\s*\(")
_JS_CIPHER = re.compile(
    r"\bcreate(?:Cipheriv|Cipher|Decipheriv|Decipher)\s*\(\s*['\"]([\w-]+)['\"]"
)
_JS_SIGN = re.compile(r"\bcreate(?:Sign|Verify)\s*\(\s*['\"]([\w-]+)['\"]")
_JS_KEYPAIR = re.compile(r"\bgenerateKeyPair(?:Sync)?\s*\(\s*['\"](\w+)['\"]")
_JS_DH = re.compile(r"\bcreateDiffieHellman\s*\(")
_JS_MODLEN = re.compile(r"\bmodulusLength\s*:\s*(\d{3,5})")
_JS_NAMEDCURVE = re.compile(r"\bnamedCurve\s*:\s*['\"]([\w-]+)['\"]")
# WebCrypto algorithm-object ``name`` field + direct ``subtle.digest('SHA-256')``.
_JS_WC_NAME = re.compile(r"\bname\s*:\s*['\"]([\w-]+)['\"]")
_JS_WC_DIGEST = re.compile(r"\bsubtle\s*\.\s*digest\s*\(\s*['\"]([\w-]+)['\"]")

# WebCrypto algorithm ``name`` → (algo key, role, mode, padding).
_WEBCRYPTO_NAMES: dict[str, tuple[str, str, str | None, str | None]] = {
    "aes-gcm": ("aes", "cipher", "GCM", None),
    "aes-cbc": ("aes", "cipher", "CBC", None),
    "aes-ctr": ("aes", "cipher", "CTR", None),
    "aes-kw": ("aes", "cipher", None, None),
    "rsa-oaep": ("rsa", "pke", None, "OAEP"),
    "rsa-pss": ("rsa", "signature", None, "PSS"),
    "rsassa-pkcs1-v1_5": ("rsa", "signature", None, "PKCS1-v1_5"),
    "ecdsa": ("ecdsa", "signature", None, None),
    "ecdh": ("ecdh", "key-agree", None, None),
    "ed25519": ("ed25519", "signature", None, None),
    "x25519": ("x25519", "key-agree", None, None),
    "hmac": ("hmac", "mac", None, None),
    "pbkdf2": ("pbkdf2", "kdf", None, None),
    "hkdf": ("hkdf", "kdf", None, None),
}
_CURVE_NORMALIZE: dict[str, str] = {
    "p-256": "SECP256R1", "p-384": "SECP384R1", "p-521": "SECP521R1",
    "p256": "SECP256R1", "p384": "SECP384R1", "p521": "SECP521R1",
    "secp256k1": "SECP256K1",
}


def _js_sig_key(spec: str) -> str | None:
    low = spec.lower()
    if "rsa" in low:
        return "rsa"
    if "ecdsa" in low or low.startswith("ec"):
        return "ecdsa"
    if "dsa" in low:
        return "dsa"
    return None


def _scan_js(text: str, rel: str, assets: list[_Asset]) -> None:
    curve = None
    cm = _JS_NAMEDCURVE.search(text)
    if cm:
        curve = _CURVE_NORMALIZE.get(cm.group(1).lower())
    modlen = None
    mm = _JS_MODLEN.search(text)
    if mm:
        modlen = int(mm.group(1))

    for m in _JS_HASH.finditer(text):
        _add(assets, _canon(m.group(1)), "digest", _NODE, rel)
    if _JS_HMAC.search(text):
        _add(assets, "hmac", "mac", _NODE, rel)
    for m in _JS_CIPHER.finditer(text):
        parsed = _parse_cipher_spec(m.group(1))
        if parsed:
            key, size, mode = parsed
            _add(assets, key, "cipher", _NODE, rel, size=size, mode=mode)
    for m in _JS_SIGN.finditer(text):
        _add(assets, _js_sig_key(m.group(1)), "signature", _NODE, rel)
    for m in _JS_KEYPAIR.finditer(text):
        typ = m.group(1).lower()
        if typ == "rsa":
            _add(assets, "rsa", "pke", _NODE, rel, size=modlen)
        elif typ in ("ec", "ecdsa"):
            _add(assets, "ecdsa", "signature", _NODE, rel, curve=curve)
        elif typ in ("ed25519", "ed448", "x25519", "dsa", "dh"):
            role = "key-agree" if typ in ("x25519", "dh") else "signature"
            _add(assets, typ if typ != "dh" else "dh", role, _NODE, rel)
    if _JS_DH.search(text):
        _add(assets, "dh", "key-agree", _NODE, rel)

    # WebCrypto.
    for m in _JS_WC_DIGEST.finditer(text):
        _add(assets, _canon(m.group(1)), "digest", _WEBCRYPTO, rel)
    for m in _JS_WC_NAME.finditer(text):
        spec = _WEBCRYPTO_NAMES.get(m.group(1).lower())
        if not spec:
            continue
        key, role, mode, padding = spec
        size = modlen if key == "rsa" else None
        crv = curve if key in ("ecdsa", "ecdh") else None
        _add(assets, key, role, _WEBCRYPTO, rel,
             size=size, mode=mode, curve=crv, padding=padding)


# --------------------------------------------------------------------------- #
# C / C++ — OpenSSL / BoringSSL
# --------------------------------------------------------------------------- #

_C_IMPORT = re.compile(r"#\s*include\s*[<\"]openssl/|\bEVP_[a-z]|\bRSA_generate")
_C_EVP_CIPHER = re.compile(
    r"\bEVP_(aes|des_ede3|des|rc4|rc2|bf|chacha20)_?(\d+)?_?"
    r"(gcm|cbc|ctr|cfb|ofb|ecb|xts|ccm)?(?:_?(poly1305))?\s*\("
)
_C_EVP_DIGEST = re.compile(
    r"\bEVP_(md5|sha1|sha224|sha256|sha384|sha512|sha3_256|sha3_384|"
    r"sha3_512|blake2b512|blake2s256)\s*\("
)
_C_LEGACY_DIGEST = re.compile(
    r"\b(MD5|SHA1|SHA224|SHA256|SHA384|SHA512)_(?:Init|Update|Final)\s*\("
)
_C_RSA_GEN = re.compile(
    r"\b(?:RSA_generate_key(?:_ex)?|EVP_RSA_gen)\s*\("
)
_C_RSA_BITS = re.compile(
    r"EVP_RSA_gen\s*\(\s*(\d{3,5})|"
    r"set_rsa_keygen_bits\s*\(\s*\w+\s*,\s*(\d{3,5})|"
    r"RSA_generate_key_ex\s*\(\s*[^,]+,\s*(\d{3,5})|"
    r"RSA_generate_key\s*\(\s*(\d{3,5})"
)
_C_EC = re.compile(
    r"(?:EC_KEY_new_by_curve_name|set_ec_paramgen_curve_nid)\s*"
    r"\(\s*(?:\w+\s*,\s*)?(NID_\w+)"
)
_C_HMAC = re.compile(r"\bHMAC(?:_Init(?:_ex)?|_Update|_Final)?\s*\(")
_C_DES = re.compile(r"\bDES_(?:set_key|ecb_encrypt|ncbc_encrypt|cbc_encrypt)\b")
_C_RC4 = re.compile(r"\bRC4(?:_set_key)?\s*\(")

_C_CIPHER_KEY: dict[str, str] = {
    "aes": "aes", "des": "des", "des_ede3": "3des",
    "rc4": "rc4", "rc2": "rc2", "bf": "blowfish", "chacha20": "chacha20",
}
_NID_CURVE: dict[str, str] = {
    "NID_X9_62_prime256v1": "SECP256R1", "NID_secp384r1": "SECP384R1",
    "NID_secp521r1": "SECP521R1", "NID_secp256k1": "SECP256K1",
    "NID_secp224r1": "SECP224R1",
}


def _scan_c(text: str, rel: str, assets: list[_Asset]) -> None:
    for m in _C_EVP_CIPHER.finditer(text):
        base, bits, mode, poly = m.groups()
        if poly == "poly1305" and base == "chacha20":
            _add(assets, "chacha20-poly1305", "ae", _OPENSSL, rel)
            continue
        key = _C_CIPHER_KEY.get(base)
        size = int(bits) if bits else None
        _add(assets, key, "cipher", _OPENSSL, rel,
             size=size, mode=mode.upper() if mode else None)
    for m in _C_EVP_DIGEST.finditer(text):
        tok = m.group(1)
        key = {"blake2b512": "blake2b", "blake2s256": "blake2s"}.get(
            tok, _canon(tok) or tok
        )
        _add(assets, key, "digest", _OPENSSL, rel)
    for m in _C_LEGACY_DIGEST.finditer(text):
        _add(assets, _canon(m.group(1)), "digest", _OPENSSL, rel)
    if _C_RSA_GEN.search(text):
        size = None
        bm = _C_RSA_BITS.search(text)
        if bm:
            size = next((int(g) for g in bm.groups() if g), None)
        _add(assets, "rsa", "pke", _OPENSSL, rel, size=size)
    for m in _C_EC.finditer(text):
        curve = _NID_CURVE.get(m.group(1))
        _add(assets, "ecdsa", "signature", _OPENSSL, rel, curve=curve)
    if _C_HMAC.search(text):
        _add(assets, "hmac", "mac", _OPENSSL, rel)
    if _C_DES.search(text):
        _add(assets, "des", "cipher", _OPENSSL, rel)
    if _C_RC4.search(text):
        _add(assets, "rc4", "cipher", _OPENSSL, rel)


# --------------------------------------------------------------------------- #
# Rust — RustCrypto + ring
# --------------------------------------------------------------------------- #

_RS_IMPORT = re.compile(
    r"\buse\s+(?:aes|aes_gcm|chacha20poly1305|sha2|sha1|md5|md-5|rsa|"
    r"ed25519|ed25519_dalek|p256|p384|k256|hmac|ring|argon2|scrypt|"
    r"pbkdf2|bcrypt|blake2|sha3|ecdsa)\b|\bring::"
)
_RS_AESGCM = re.compile(r"\bAes(128|192|256)Gcm(?:Siv)?\b")
_RS_AES = re.compile(r"\bAes(128|192|256)\b")
_RS_CHACHA_AE = re.compile(r"\bX?ChaCha20Poly1305\b")
_RS_CHACHA = re.compile(r"\bChaCha20\b(?!Poly)")
_RS_DIGEST = re.compile(
    r"\b(Sha512|Sha384|Sha256|Sha224|Sha1|Md5|Sha3_256|Sha3_512|"
    r"Blake2b|Blake2s)\b"
)
_RS_RSA = re.compile(r"\bRsaP(?:rivate|ublic)Key\b|\bRsa::")
_RS_RSA_BITS = re.compile(r"RsaPrivateKey::new\s*\([^,]*,\s*(\d{3,5})")
_RS_ED = re.compile(r"\bed25519_dalek\b|\bEd25519\b")
_RS_P = re.compile(r"\b(p256|p384|k256)::|\bNistP(256|384)\b")
_RS_HMAC = re.compile(r"\bHmac\b")
_RS_KDF = re.compile(r"\b(argon2|scrypt|pbkdf2|bcrypt)\b")
# ring SCREAMING constants.
_RS_RING_AEAD = re.compile(r"\b(AES_128_GCM|AES_256_GCM|CHACHA20_POLY1305)\b")
_RS_RING_DIGEST = re.compile(
    r"\b(SHA256|SHA384|SHA512|SHA1_FOR_LEGACY_USE_ONLY)\b"
)
_RS_RING_SIG = re.compile(
    r"\b(ED25519|ECDSA_P256_SHA256\w*|ECDSA_P384_SHA384\w*|RSA_PKCS1_\w+)\b"
)

_RS_DIGEST_KEY: dict[str, str] = {
    "sha512": "sha512", "sha384": "sha384", "sha256": "sha256",
    "sha224": "sha256", "sha1": "sha1", "md5": "md5",
    "sha3_256": "sha3_256", "sha3_512": "sha3_512",
    "blake2b": "blake2b", "blake2s": "blake2s",
}


def _scan_rust(text: str, rel: str, assets: list[_Asset]) -> None:
    has_ring = "ring::" in text

    # RustCrypto CamelCase.
    for m in _RS_AESGCM.finditer(text):
        _add(assets, "aes", "ae", _RUSTCRYPTO, rel,
             size=int(m.group(1)), mode="GCM")
    for m in _RS_AES.finditer(text):
        _add(assets, "aes", "cipher", _RUSTCRYPTO, rel, size=int(m.group(1)))
    if _RS_CHACHA_AE.search(text):
        _add(assets, "chacha20-poly1305", "ae", _RUSTCRYPTO, rel)
    if _RS_CHACHA.search(text):
        _add(assets, "chacha20", "cipher", _RUSTCRYPTO, rel)
    for m in _RS_DIGEST.finditer(text):
        _add(assets, _RS_DIGEST_KEY.get(m.group(1).lower()),
             "digest", _RUSTCRYPTO, rel)
    if _RS_RSA.search(text):
        bm = _RS_RSA_BITS.search(text)
        _add(assets, "rsa", "pke", _RUSTCRYPTO, rel,
             size=int(bm.group(1)) if bm else None)
    if _RS_ED.search(text):
        _add(assets, "ed25519", "signature", _RUSTCRYPTO, rel)
    for m in _RS_P.finditer(text):
        tok = (m.group(1) or f"p{m.group(2)}").lower()
        curve = {"p256": "SECP256R1", "p384": "SECP384R1",
                 "k256": "SECP256K1"}.get(tok)
        _add(assets, "ecdsa", "signature", _RUSTCRYPTO, rel, curve=curve)
    if _RS_HMAC.search(text):
        _add(assets, "hmac", "mac", _RUSTCRYPTO, rel)
    for m in _RS_KDF.finditer(text):
        _add(assets, _canon(m.group(1)) or m.group(1).lower(),
             "kdf", _RUSTCRYPTO, rel)

    # ring SCREAMING constants (only when ring is imported, to avoid matching a
    # user's unrelated ``SHA256`` constant).
    if not has_ring:
        return
    for m in _RS_RING_AEAD.finditer(text):
        tok = m.group(1)
        if tok == "CHACHA20_POLY1305":
            _add(assets, "chacha20-poly1305", "ae", _RING, rel)
        else:
            _add(assets, "aes", "ae", _RING, rel,
                 size=int(tok.split("_")[1]), mode="GCM")
    for m in _RS_RING_DIGEST.finditer(text):
        tok = m.group(1)
        key = "sha1" if tok.startswith("SHA1") else _canon(tok)
        _add(assets, key, "digest", _RING, rel)
    for m in _RS_RING_SIG.finditer(text):
        tok = m.group(1)
        if tok == "ED25519":
            _add(assets, "ed25519", "signature", _RING, rel)
        elif tok.startswith("ECDSA_P256"):
            _add(assets, "ecdsa", "signature", _RING, rel, curve="SECP256R1")
        elif tok.startswith("ECDSA_P384"):
            _add(assets, "ecdsa", "signature", _RING, rel, curve="SECP384R1")
        elif tok.startswith("RSA_PKCS1"):
            _add(assets, "rsa", "signature", _RING, rel, padding="PKCS1-v1_5")


# --------------------------------------------------------------------------- #
# .NET — System.Security.Cryptography
# --------------------------------------------------------------------------- #

_CS_IMPORT = re.compile(r"System\s*\.\s*Security\s*\.\s*Cryptography")
_CS_AESGCM = re.compile(r"\bAesGcm\b")
_CS_AESCCM = re.compile(r"\bAesCcm\b")
_CS_AES = re.compile(
    r"\bAes(?:Managed|CryptoServiceProvider|Cng)?\s*\.\s*Create\b|"
    r"\bnew\s+Aes(?:Managed|CryptoServiceProvider)\b"
)
_CS_3DES = re.compile(r"\bTripleDES(?:CryptoServiceProvider|Cng)?\b")
_CS_DES = re.compile(
    r"\bDES\s*\.\s*Create\b|\bnew\s+DESCryptoServiceProvider\b"
)
_CS_RC2 = re.compile(r"\bRC2(?:CryptoServiceProvider)?\s*\.\s*Create\b|"
                     r"\bnew\s+RC2CryptoServiceProvider\b")
_CS_RSA = re.compile(
    r"\bRSA\s*\.\s*Create\b|\bnew\s+RSACryptoServiceProvider\b|"
    r"\bnew\s+RSACng\b|\bRSACryptoServiceProvider\b"
)
_CS_RSA_BITS = re.compile(
    r"RSA\s*\.\s*Create\s*\(\s*(\d{3,5})|"
    r"new\s+RSACryptoServiceProvider\s*\(\s*(\d{3,5})|"
    r"KeySize\s*=\s*(\d{3,5})"
)
_CS_ECDSA = re.compile(r"\bECDsa(?:Cng)?\s*\.\s*Create\b|\bnew\s+ECDsaCng\b")
_CS_ECDH = re.compile(
    r"\bECDiffieHellman(?:Cng)?\s*\.\s*Create\b|\bnew\s+ECDiffieHellmanCng\b"
)
_CS_DSA = re.compile(r"\bDSA(?:Cng)?\s*\.\s*Create\b|"
                     r"\bnew\s+DSACryptoServiceProvider\b")
_CS_DIGEST = re.compile(
    r"\b(MD5|SHA1|SHA256|SHA384|SHA512)(?:Managed|CryptoServiceProvider|Cng)?"
    r"\s*\.\s*Create\b|"
    r"\bnew\s+(MD5|SHA1|SHA256|SHA384|SHA512)"
    r"(?:Managed|CryptoServiceProvider|Cng)?\s*\("
)
_CS_HMAC = re.compile(r"\bHMAC(?:MD5|SHA1|SHA256|SHA384|SHA512)\b|\bnew\s+HMAC")
_CS_PBKDF2 = re.compile(r"\bRfc2898DeriveBytes\b")
_CS_CURVE = re.compile(
    r"ECCurve\s*\.\s*NamedCurves\s*\.\s*(nistP256|nistP384|nistP521)"
)
_CS_MODE = re.compile(r"CipherMode\s*\.\s*(CBC|ECB|CTR|CFB|OFB)")
_CS_RSA_PAD = re.compile(r"RSAEncryptionPadding\s*\.\s*(Oaep\w*|Pkcs1)")

_CS_NIST_CURVE: dict[str, str] = {
    "nistp256": "SECP256R1", "nistp384": "SECP384R1", "nistp521": "SECP521R1",
}


def _scan_dotnet(text: str, rel: str, assets: list[_Asset]) -> None:
    size = None
    bm = _CS_RSA_BITS.search(text)
    if bm:
        size = next((int(g) for g in bm.groups() if g), None)
    curve = None
    cm = _CS_CURVE.search(text)
    if cm:
        curve = _CS_NIST_CURVE.get(cm.group(1).lower())
    file_mode = None
    mm = _CS_MODE.search(text)
    if mm:
        file_mode = mm.group(1).upper()
    rsa_padding = None
    pm = _CS_RSA_PAD.search(text)
    if pm:
        rsa_padding = "OAEP" if pm.group(1).lower().startswith("oaep") else "PKCS1-v1_5"

    if _CS_AESGCM.search(text):
        _add(assets, "aes", "ae", _DOTNET, rel, mode="GCM")
    if _CS_AESCCM.search(text):
        _add(assets, "aes", "ae", _DOTNET, rel, mode="CCM")
    if _CS_AES.search(text):
        _add(assets, "aes", "cipher", _DOTNET, rel, mode=file_mode)
    if _CS_3DES.search(text):
        _add(assets, "3des", "cipher", _DOTNET, rel, mode=file_mode)
    if _CS_DES.search(text):
        _add(assets, "des", "cipher", _DOTNET, rel, mode=file_mode)
    if _CS_RC2.search(text):
        _add(assets, "rc2", "cipher", _DOTNET, rel)
    if _CS_RSA.search(text):
        _add(assets, "rsa", "pke", _DOTNET, rel, size=size, padding=rsa_padding)
    if _CS_ECDSA.search(text):
        _add(assets, "ecdsa", "signature", _DOTNET, rel, curve=curve)
    if _CS_ECDH.search(text):
        _add(assets, "ecdh", "key-agree", _DOTNET, rel, curve=curve)
    if _CS_DSA.search(text):
        _add(assets, "dsa", "signature", _DOTNET, rel)
    for m in _CS_DIGEST.finditer(text):
        tok = m.group(1) or m.group(2)
        _add(assets, _canon(tok), "digest", _DOTNET, rel)
    if _CS_HMAC.search(text):
        _add(assets, "hmac", "mac", _DOTNET, rel)
    if _CS_PBKDF2.search(text):
        _add(assets, "pbkdf2", "kdf", _DOTNET, rel)


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #


def _run(root: Path, exts: frozenset[str], gate: re.Pattern[str],
         fn, all_assets: list[_Asset]) -> None:
    for path in _iter_files(root, exts):
        try:
            raw = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not gate.search(raw):
            continue
        text = _strip_comments(raw)
        rel = path.relative_to(root).as_posix()
        assets: list[_Asset] = []
        fn(text, rel, assets)
        all_assets.extend(assets)


@cbom_register
class NativeCryptoScanner(Scanner):
    """JS/TS + C/C++ + Rust + .NET crypto-API scanner (C3). Runs before the
    regex scanner (``order`` 9 < 10) so its argument-bound components own the
    bom-ref when refs collide (JS/C/Rust are in the regex scanner's language
    set); ``.cs`` is C3-exclusive. Distinct file extensions from C1 (Python-AST,
    order 8) and C2 (Java/Go, order 9), so it never perturbs them."""

    name = "crypto_native"
    order = 9
    level = 1

    def scan(self, ctx: ScanContext) -> None:
        all_assets: list[_Asset] = []
        _run(ctx.root, _JS_EXT, _JS_IMPORT, _scan_js, all_assets)
        _run(ctx.root, _C_EXT, _C_IMPORT, _scan_c, all_assets)
        _run(ctx.root, _RUST_EXT, _RS_IMPORT, _scan_rust, all_assets)
        _run(ctx.root, _DOTNET_EXT, _CS_IMPORT, _scan_dotnet, all_assets)

        for asset in _dedup(all_assets):
            info = algo_info(asset._refined) or {}
            props: dict[str, str] = {
                "crypto:assetType": "algorithm",
                "crypto:primitive": asset.primitive,
                "crypto:detectedBy": asset.library,
                "crypto:detectionContext": asset.context,
                "crypto:detectionMethod": "call-expr",
                "crypto:confidence": "high",
                "discovery:source": asset.location,
            }
            if "strength" in info:
                props["crypto:strength"] = info["strength"]
            props["crypto:quantumVulnerable"] = str(
                bool(info.get("quantum_vulnerable", False))
            ).lower()
            if asset.resolved_size:
                props["crypto:keySize"] = str(asset.resolved_size)
            if asset.mode:
                props["crypto:mode"] = asset.mode
            if asset.curve:
                props["crypto:curve"] = asset.curve
            if asset.padding:
                props["crypto:padding"] = asset.padding
            ref = f"crypto-algo-{_slug(asset.name)}-{_slug(asset.location)}"
            if ctx.has_ref(ref):
                continue
            ctx.add_component(
                CryptoAssetComponent(
                    bom_ref=ref,
                    name=asset.name,
                    properties=props,
                )
            )
            # Reserve the de-sized ref the order-10 line-regex scanner would emit
            # for the same usage (it matches ``AES-256`` but cannot fold the 256
            # into a key size, so it produces the coarser ``AES-GCM``). Reserving
            # it makes that pass defer via ``has_ref`` — the same deferral C1/C2
            # get for free when the names already collide.
            coarse = re.sub(r"-(?:\d{2,4})(?=-|$)", "", asset.name)
            if coarse != asset.name:
                ctx.reserved_refs.add(
                    f"crypto-algo-{_slug(coarse)}-{_slug(asset.location)}"
                )


__all__ = ["NativeCryptoScanner"]
