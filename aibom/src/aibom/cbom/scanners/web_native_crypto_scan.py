"""CBOM scanner (C3): a **JS/TS + C/C++ + Rust + .NET** crypto-API scanner that
extends the C2 call-expression model (entry-point symbol fixes the primitive
*context*; the call arguments supply the parameters) to the four remaining
languages of the R2 per-library matrix — clean-room (ledger rows 4 / 11–13,
public API docs only: MDN WebCrypto, Node `crypto`, OpenSSL EVP, RustCrypto /
ring, .NET ``System.Security.Cryptography``; no DSL / no copied detection rules).

Like C2, none of these languages has a stdlib parser available to the product
(and vendoring a third-party grammar would break the no-OSS-tooling rule), so
this is an original **call-expression extractor**: it strips comments (keeping
string literals — Node/OpenSSL pack ``algo-keysize-mode`` into one literal),
follows simple intra-file variable bindings, and resolves algorithm + key size +
mode + curve + padding the same way C1/C2 do.

Library → asset maps implemented here (the R2 corpus rows 86–90):

* **Node ``crypto``** — ``createCipheriv('aes-256-gcm',…)`` (the literal carries
  algorithm + key size + mode), ``createHash/createHmac/createSign``,
  ``generateKeyPair('rsa',{modulusLength})`` / ``('ec',{namedCurve})``,
  ``pbkdf2``/``scrypt``.
* **WebCrypto** (``crypto.subtle``) — algorithm by the ``{name:"AES-GCM"|
  "RSA-OAEP"|"ECDSA"|…}`` field (+ ``namedCurve``/``modulusLength``) and the
  ``subtle.digest('SHA-256')`` string.
* **OpenSSL** (C/C++) — ``EVP_aes_256_gcm()`` / ``EVP_sha384()`` /
  ``EVP_des_ede3_cbc()`` (the EVP fn name packs algo + key size + mode),
  ``SHA*_Init``, ``EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072)``,
  ``EC_KEY_new_by_curve_name(NID_secp384r1)``, ``HMAC*``.
* **Rust** — **ring** module constants (``aead::AES_256_GCM``, ``digest::SHA256``,
  ``signature::ED25519`` / ``ECDSA_P384_*``, ``hmac::HMAC_*``, ``pbkdf2::*``) and
  **RustCrypto** types (``Aes256Gcm``, ``ChaCha20Poly1305``, ``Sha256``/``Sha1``,
  ``Hmac::<Sha256>``, ``RsaPrivateKey``).
* **.NET** ``System.Security.Cryptography`` — ``Aes.Create()`` / ``new AesGcm`` /
  ``RijndaelManaged``, ``TripleDES``/``DES``/``RC2`` providers, ``SHA*.Create``/
  ``*Managed``, ``new HMAC*``, ``RSA.Create(2048)`` / ``new
  RSACryptoServiceProvider(2048)`` (+ ``.KeySize``), ``ECDsa.Create(ECCurve.
  NamedCurves.nistP384)``, ``new Rfc2898DeriveBytes`` → PBKDF2, with the cipher
  ``CipherMode`` / ``.KeySize`` bound to its AES variable across statements.

Lane discipline (EMIT only): one ``crypto_asset`` (assetType=algorithm) per
distinct (algorithm+params, file) usage, with ``crypto:detectedBy`` (the library
that fixed the context), ``crypto:detectionContext`` (the primitive role),
``crypto:detectionMethod=call-expr`` and ``crypto:confidence``. Weak-flagging is
C6, PQC grading is C7, the CycloneDX serialization is C9. To stay additive the
display names match the regex scanner's (parity via ``_display_name``) so the
SAME ``crypto-algo-{name}-{file}`` bom-ref is emitted; this scanner runs *before*
the regex pass (order 9 < 10), which then defers to any ref already present
(``ctx.has_ref``); the pipeline also de-dups by bom-ref. A key size parsed from a
symmetric ``algo-keysize-mode`` literal (AES) is carried in the ``crypto:keySize``
*property* only — never folded into the name — to preserve that ref parity
(``aes-256-gcm`` → name ``AES-GCM`` + keySize 256, matching the regex scanner).
"""

from __future__ import annotations

import re

from aibom.cbom.registry import cbom_register
from aibom.cbom.rules import ALGORITHM_NORMALIZE, algo_info
from aibom.cbom.scanners.algorithm_scan import _display_name, _refine_key, _slug
from aibom.cbom.scanners.jvm_go_crypto_scan import (
    _MODES,
    _canon,
    _iter_files,
    _strip_comments,
)
from aibom.model.component import CryptoAssetComponent
from aibom.scan.registry import ScanContext, Scanner

# Library labels (crypto:detectedBy).
_NODE = "Node crypto (Node.js)"
_WEBCRYPTO = "WebCrypto API"
_OPENSSL = "OpenSSL (C/C++)"
_RING = "ring (Rust)"
_RUSTCRYPTO = "RustCrypto"
_DOTNET = ".NET System.Security.Cryptography"

_JS_EXT = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"})
_C_EXT = frozenset({".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hxx"})
_RUST_EXT = frozenset({".rs"})
_DOTNET_EXT = frozenset({".cs"})

# Import / usage gates (precision — only scan files that actually touch the lib).
_JS_GATE = re.compile(
    r"require\(\s*['\"](?:node:)?crypto['\"]"
    r"|from\s+['\"](?:node:)?crypto['\"]"
    r"|crypto\.subtle"
    r"|\bsubtle\."
    r"|window\.crypto"
)
_C_GATE = re.compile(r"#\s*include\s*[<\"]openssl/|\bEVP_[A-Za-z]|\bHMAC_CTX\b")
_RUST_GATE = re.compile(
    r"\bring::|\b(?:aead|digest|signature|hmac|pbkdf2)::"
    r"|\bAes(?:128|192|256)Gcm\b|\bChaCha20Poly1305\b"
    r"|\bSha(?:1|224|256|384|512)\b|\bMd5\b|\bRsaPrivateKey\b"
)
_DOTNET_GATE = re.compile(r"System\.Security\.Cryptography")

# Curve normalization to the SECP* spelling C2 emits (parity across scanners).
_CURVE_NORM: dict[str, str] = {
    "p256": "SECP256R1", "p-256": "SECP256R1", "prime256v1": "SECP256R1",
    "nistp256": "SECP256R1", "secp256r1": "SECP256R1",
    "p384": "SECP384R1", "p-384": "SECP384R1",
    "nistp384": "SECP384R1", "secp384r1": "SECP384R1",
    "p521": "SECP521R1", "p-521": "SECP521R1",
    "nistp521": "SECP521R1", "secp521r1": "SECP521R1",
    "secp256k1": "SECP256K1", "p256k1": "SECP256K1",
}


def _norm_curve(token: str) -> str | None:
    return _CURVE_NORM.get(re.sub(r"[\s_]", "", token).lower())


class _Asset:
    """A resolved crypto-API usage. ``name_size`` is folded into the display name
    (asymmetric sizes, mirroring the regex scanner); ``prop_size`` is carried in
    the ``crypto:keySize`` property ONLY (symmetric sizes parsed from an
    ``aes-256-gcm`` literal — folding them would break ref parity with regex)."""

    __slots__ = ("key", "name_size", "prop_size", "mode", "curve", "padding",
                 "context", "library", "location")

    def __init__(self, key, context, library, location, *, name_size=None,
                 prop_size=None, mode=None, curve=None, padding=None):
        self.key = key
        self.name_size = name_size
        self.prop_size = prop_size
        self.mode = mode
        self.curve = curve
        self.padding = padding
        self.context = context
        self.library = library
        self.location = location

    @property
    def _refined(self) -> str:
        return _refine_key(self.key, self.name_size)

    @property
    def name(self) -> str:
        return _display_name(self._refined, self.name_size, self.mode)

    @property
    def keysize(self) -> int | None:
        return (self.name_size or self.prop_size
                or (algo_info(self._refined) or {}).get("key_size"))

    @property
    def primitive(self) -> str:
        return (algo_info(self._refined) or {}).get("primitive", self.context)


def _mk(key: str | None, context: str, library: str, location: str, *,
        name_size: int | None = None, prop_size: int | None = None,
        mode: str | None = None, curve: str | None = None,
        padding: str | None = None) -> _Asset | None:
    if not key:
        return None
    refined = _refine_key(key, name_size)
    if not (ALGORITHM_NORMALIZE.get(refined) or algo_info(refined)):
        return None  # never inventory an unknown token
    # A mode of operation only qualifies a symmetric primitive.
    if mode and (algo_info(refined) or {}).get("primitive") not in (
        "block-cipher", "stream-cipher", "ae"
    ):
        mode = None
    return _Asset(key, context, library, location, name_size=name_size,
                  prop_size=prop_size, mode=mode, curve=curve, padding=padding)


# --------------------------------------------------------------------------- #
# Shared: parse an OpenSSL/Node-style cipher spec (dash or underscore separated)
# into (algorithm key, symmetric key size, mode). ``aes-256-gcm`` / ``aes_256_gcm``
# / ``des-ede3-cbc`` / ``rc4`` / ``chacha20-poly1305``.
# --------------------------------------------------------------------------- #


def _classify_cipher_spec(spec: str) -> tuple[str, int | None, str | None] | None:
    s = spec.lower()
    parts = re.split(r"[-_]", s)
    fam = parts[0]
    if "ede3" in s or "des3" in s or fam in ("3des", "desede", "tripledes"):
        key: str | None = "3des"
    elif fam == "des":
        key = "des"
    elif fam == "aes":
        key = "aes"
    elif fam in ("rc4", "arc4", "arcfour"):
        key = "rc4"
    elif fam == "rc2":
        key = "rc2"
    elif fam in ("bf", "blowfish"):
        key = "blowfish"
    elif fam.startswith("chacha20"):
        key = "chacha20-poly1305" if "poly1305" in s else "chacha20"
    else:
        key = _canon(fam)
    if not key:
        return None
    size = next((int(p) for p in parts if p in ("128", "192", "256")), None)
    mode = next((p.upper() for p in parts if p.upper() in _MODES), None)
    return key, size, mode


# --------------------------------------------------------------------------- #
# JS / TS — Node crypto + WebCrypto
# --------------------------------------------------------------------------- #

_JS_CIPHERIV = re.compile(r"\bcreate(?:De)?[Cc]ipheriv?\s*\(\s*['\"]([\w-]+)['\"]")
_JS_HASH = re.compile(r"\bcreateHash\s*\(\s*['\"]([\w-]+)['\"]")
_JS_HMAC = re.compile(r"\bcreateHmac\s*\(")
_JS_SIGN = re.compile(r"\bcreate(?:Sign|Verify)\s*\(\s*['\"]([\w-]+)['\"]")
_JS_KEYPAIR = re.compile(
    r"\bgenerateKeyPair(?:Sync)?\s*\(\s*['\"](rsa|rsa-pss|ec|ed25519|ed448"
    r"|x25519|dh|dsa)['\"]"
)
_JS_KDF = re.compile(r"\b(pbkdf2|scrypt)(?:Sync)?\s*\(")
_JS_MODULUS = re.compile(r"modulusLength\s*:\s*(\d{3,5})")
_JS_NAMEDCURVE = re.compile(r"namedCurve\s*:\s*['\"]([\w-]+)['\"]")
_JS_DIGEST = re.compile(r"\bsubtle\.digest\s*\(\s*['\"]([\w-]+)['\"]")
_JS_NAME = re.compile(r"\bname\s*:\s*['\"]([A-Za-z0-9][\w-]+)['\"]")

# WebCrypto algorithm identifier -> (algorithm key, context role, mode, padding).
_WEBCRYPTO_ALGOS: dict[str, tuple[str, str, str | None, str | None]] = {
    "AES-GCM": ("aes", "cipher", "GCM", None),
    "AES-CBC": ("aes", "cipher", "CBC", None),
    "AES-CTR": ("aes", "cipher", "CTR", None),
    "AES-KW": ("aes", "cipher", None, None),
    "RSA-OAEP": ("rsa", "pke", None, "OAEP"),
    "RSASSA-PKCS1-V1_5": ("rsa", "signature", None, "PKCS1-v1.5"),
    "RSA-PSS": ("rsa", "signature", None, "PSS"),
    "ECDSA": ("ecdsa", "signature", None, None),
    "ECDH": ("ecdh", "key-agree", None, None),
    "ED25519": ("ed25519", "signature", None, None),
    "HMAC": ("hmac", "mac", None, None),
    "PBKDF2": ("pbkdf2", "kdf", None, None),
    "HKDF": ("hkdf", "kdf", None, None),
}


def _scan_js(text: str, rel: str, assets: list[_Asset]) -> None:
    has_subtle = "subtle" in text

    # Node: cipher algorithm strings carry algo + key size + mode.
    for m in _JS_CIPHERIV.finditer(text):
        cspec = _classify_cipher_spec(m.group(1))
        if cspec:
            ckey, csize, cmode = cspec
            a = _mk(ckey, "cipher", _NODE, rel, prop_size=csize, mode=cmode)
            if a:
                assets.append(a)

    for m in _JS_HASH.finditer(text):
        a = _mk(_canon(m.group(1)), "digest", _NODE, rel)
        if a:
            assets.append(a)

    if _JS_HMAC.search(text):
        assets.append(_Asset("hmac", "mac", _NODE, rel))

    for m in _JS_SIGN.finditer(text):
        sign_spec = m.group(1).lower()
        sign_key: str | None = (
            "ecdsa" if "ecdsa" in sign_spec
            else ("rsa" if "rsa" in sign_spec else None)
        )
        if sign_key is None:
            sign_key = _canon(sign_spec.split("-")[-1])
        a = _mk(sign_key, "signature", _NODE, rel)
        if a:
            assets.append(a)

    for m in _JS_KEYPAIR.finditer(text):
        kind = m.group(1).lower()
        window = text[m.end():m.end() + 240]
        if kind in ("rsa", "rsa-pss"):
            sm = _JS_MODULUS.search(window)
            size = int(sm.group(1)) if sm else None
            a = _mk("rsa", "pke", _NODE, rel, name_size=size, prop_size=size)
        elif kind == "ec":
            cm = _JS_NAMEDCURVE.search(window)
            curve = _norm_curve(cm.group(1)) if cm else None
            a = _mk("ecdsa", "signature", _NODE, rel, curve=curve)
        else:
            a = _mk(_canon(kind), "pke", _NODE, rel)
        if a:
            assets.append(a)

    for m in _JS_KDF.finditer(text):
        a = _mk(m.group(1).lower(), "kdf", _NODE, rel)
        if a:
            assets.append(a)

    if not has_subtle:
        return

    # WebCrypto: digest by string, everything else by the {name:"…"} field.
    for m in _JS_DIGEST.finditer(text):
        a = _mk(_canon(m.group(1)), "digest", _WEBCRYPTO, rel)
        if a:
            assets.append(a)

    for m in _JS_NAME.finditer(text):
        wc = _WEBCRYPTO_ALGOS.get(m.group(1).upper())
        if not wc:
            continue
        key, role, mode, padding = wc
        window = text[m.end():m.end() + 200]
        curve = None
        name_size = None
        if key in ("ecdsa", "ecdh"):
            cm = _JS_NAMEDCURVE.search(window)
            if cm:
                curve = _norm_curve(cm.group(1))
        if key == "rsa":
            sm = _JS_MODULUS.search(window)
            if sm:
                name_size = int(sm.group(1))
        a = _mk(key, role, _WEBCRYPTO, rel, name_size=name_size,
                prop_size=name_size, mode=mode, curve=curve, padding=padding)
        if a:
            assets.append(a)


# --------------------------------------------------------------------------- #
# C / C++ — OpenSSL EVP
# --------------------------------------------------------------------------- #

_C_DIGEST_FAMILIES = frozenset(
    {"md4", "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3",
     "blake2b", "blake2s", "ripemd160"}
)
_EVP_CALL = re.compile(r"\bEVP_([a-z0-9_]+)\s*\(")
_C_SHA_INIT = re.compile(r"\b(SHA1|SHA224|SHA256|SHA384|SHA512|MD5|MD4)_Init\b")
_C_RSA_BITS = re.compile(
    r"\bEVP_PKEY_CTX_set_rsa_keygen_bits\s*\([^,]+,\s*(\d{3,5})"
    r"|\bRSA_generate_key(?:_ex)?\s*\(\s*(?:[^,]+,\s*)?(\d{3,5})"
)
_C_EC_CURVE = re.compile(
    r"\bEC_KEY_new_by_curve_name\s*\(\s*NID_(\w+)"
    r"|\bEVP_PKEY_CTX_set_ec_paramgen_curve_nid\s*\([^,]+,\s*NID_(\w+)"
)
_C_HMAC = re.compile(r"\bHMAC(?:_Init(?:_ex)?|_Update|_Final|_CTX_new)?\s*\(")

# OpenSSL NID curve suffix -> normalized curve.
_C_NID_CURVE: dict[str, str] = {
    "secp224r1": "SECP224R1", "secp256r1": "SECP256R1", "secp384r1": "SECP384R1",
    "secp521r1": "SECP521R1", "secp256k1": "SECP256K1",
    "x9_62_prime256v1": "SECP256R1", "prime256v1": "SECP256R1",
}


def _scan_c(text: str, rel: str, assets: list[_Asset]) -> None:
    for m in _EVP_CALL.finditer(text):
        spec = m.group(1)
        fam = spec.split("_")[0]
        if fam in _C_DIGEST_FAMILIES:
            a = _mk(_canon(spec.replace("_", "")) or _canon(fam),
                    "digest", _OPENSSL, rel)
            if a:
                assets.append(a)
            continue
        if fam in ("aes", "des", "rc4", "rc2", "bf", "chacha20", "blowfish"):
            cls = _classify_cipher_spec(spec)
            if cls:
                key, size, mode = cls
                a = _mk(key, "cipher", _OPENSSL, rel, prop_size=size, mode=mode)
                if a:
                    assets.append(a)

    for m in _C_SHA_INIT.finditer(text):
        a = _mk(_canon(m.group(1)), "digest", _OPENSSL, rel)
        if a:
            assets.append(a)

    for m in _C_RSA_BITS.finditer(text):
        bits = m.group(1) or m.group(2)
        size = int(bits) if bits else None
        a = _mk("rsa", "pke", _OPENSSL, rel, name_size=size, prop_size=size)
        if a:
            assets.append(a)

    for m in _C_EC_CURVE.finditer(text):
        nid = (m.group(1) or m.group(2) or "").lower()
        curve = _C_NID_CURVE.get(nid)
        a = _mk("ecdsa", "signature", _OPENSSL, rel, curve=curve)
        if a:
            assets.append(a)

    if _C_HMAC.search(text):
        assets.append(_Asset("hmac", "mac", _OPENSSL, rel))


# --------------------------------------------------------------------------- #
# Rust — ring (module constants) + RustCrypto (types)
# --------------------------------------------------------------------------- #

_RUST_RING_AEAD = re.compile(
    r"\baead::(AES_128_GCM|AES_192_GCM|AES_256_GCM|CHACHA20_POLY1305)\b"
)
_RUST_RING_DIGEST = re.compile(
    r"\bdigest::(SHA1_FOR_LEGACY_USE_ONLY|SHA256|SHA384|SHA512|SHA512_256)\b"
)
_RUST_RING_SIG = re.compile(
    r"\bsignature::(ED25519|ECDSA_P256[\w]*|ECDSA_P384[\w]*|ECDSA_P521[\w]*"
    r"|RSA_[\w]+)\b"
)
_RUST_RING_HMAC = re.compile(r"\bhmac::(?:HMAC_\w+|Key\b)")
_RUST_RING_PBKDF2 = re.compile(r"\bpbkdf2::(?:PBKDF2_\w+|derive\b)")

_RUST_RC_AEAD = re.compile(r"\bAes(128|192|256)Gcm(?:Siv)?\b|\bChaCha20Poly1305\b")
_RUST_RC_DIGEST = re.compile(r"\b(Sha224|Sha256|Sha384|Sha512|Sha1|Md5)\b")
_RUST_RC_HMAC = re.compile(r"\bHmac\s*::\s*<")
_RUST_RC_RSA = re.compile(r"\bRsa(?:PrivateKey|PublicKey)\b")


def _scan_rust(text: str, rel: str, assets: list[_Asset]) -> None:
    # ring — module-path constants.
    for m in _RUST_RING_AEAD.finditer(text):
        cls = _classify_cipher_spec(m.group(1))
        if cls:
            rkey, rsize, rmode = cls
            a = _mk(rkey, "cipher", _RING, rel, prop_size=rsize, mode=rmode)
            if a:
                assets.append(a)
    for m in _RUST_RING_DIGEST.finditer(text):
        tok = m.group(1)
        dkey = "sha1" if tok.startswith("SHA1") else _canon(tok)
        a = _mk(dkey, "digest", _RING, rel)
        if a:
            assets.append(a)
    for m in _RUST_RING_SIG.finditer(text):
        tok = m.group(1)
        if tok == "ED25519":
            a = _mk("ed25519", "signature", _RING, rel)
        elif tok.startswith("ECDSA"):
            cm = re.search(r"P(256|384|521)", tok)
            curve = _norm_curve(f"p{cm.group(1)}") if cm else None
            a = _mk("ecdsa", "signature", _RING, rel, curve=curve)
        else:  # RSA_*
            a = _mk("rsa", "signature", _RING, rel)
        if a:
            assets.append(a)
    if _RUST_RING_HMAC.search(text):
        assets.append(_Asset("hmac", "mac", _RING, rel))
    if _RUST_RING_PBKDF2.search(text):
        assets.append(_Asset("pbkdf2", "kdf", _RING, rel))

    # RustCrypto — type names (``Aes256Gcm`` / ``ChaCha20Poly1305`` — no
    # separators, so the size comes from the regex group, not the spec splitter).
    for m in _RUST_RC_AEAD.finditer(text):
        if m.group(1):  # Aes{128,192,256}Gcm[Siv]
            a = _mk("aes", "cipher", _RUSTCRYPTO, rel,
                    prop_size=int(m.group(1)), mode="GCM")
        else:  # ChaCha20Poly1305
            a = _mk("chacha20-poly1305", "ae", _RUSTCRYPTO, rel)
        if a:
            assets.append(a)
    for m in _RUST_RC_DIGEST.finditer(text):
        a = _mk(_canon(m.group(1)), "digest", _RUSTCRYPTO, rel)
        if a:
            assets.append(a)
    if _RUST_RC_HMAC.search(text):
        assets.append(_Asset("hmac", "mac", _RUSTCRYPTO, rel))
    if _RUST_RC_RSA.search(text):
        assets.append(_Asset("rsa", "pke", _RUSTCRYPTO, rel))


# --------------------------------------------------------------------------- #
# .NET — System.Security.Cryptography
# --------------------------------------------------------------------------- #

_NET_AES_VAR = re.compile(
    r"(?:(\w+)\s*=\s*)?(?:Aes\.Create\s*\(\s*\)|new\s+Aes(?:Managed"
    r"|CryptoServiceProvider)?\s*\(|new\s+RijndaelManaged\s*\()"
)
_NET_AESGCM = re.compile(r"\bnew\s+AesGcm\s*\(")
_NET_KEYSIZE = re.compile(r"(\w+)\.KeySize\s*=\s*(\d{2,5})")
_NET_MODE = re.compile(r"(\w+)\.Mode\s*=\s*CipherMode\.(\w+)")
_NET_3DES = re.compile(
    r"\bnew\s+TripleDES(?:CryptoServiceProvider)?\s*\(|\bTripleDES\.Create\s*\("
)
_NET_DES = re.compile(r"\bnew\s+DESCryptoServiceProvider\s*\(|\bDES\.Create\s*\(")
_NET_RC2 = re.compile(r"\bnew\s+RC2CryptoServiceProvider\s*\(|\bRC2\.Create\s*\(")
_NET_DIGEST = re.compile(
    r"\b(SHA1|SHA256|SHA384|SHA512|MD5)\s*\.\s*(?:Create|HashData)\b"
    r"|\bnew\s+(SHA1|SHA256|SHA384|SHA512|MD5)Managed\b"
)
_NET_HMAC = re.compile(r"\bnew\s+HMAC(?:SHA1|SHA256|SHA384|SHA512|MD5)\s*\(")
_NET_RSA = re.compile(
    r"\bRSA\.Create\s*\(\s*(\d{3,5})?\s*\)"
    r"|\bnew\s+RSACryptoServiceProvider\s*\(\s*(\d{3,5})?"
)
_NET_EC = re.compile(
    r"\bECDsa\.Create\s*\(\s*ECCurve\.NamedCurves\.(\w+)"
)
_NET_PBKDF2 = re.compile(r"\bnew\s+Rfc2898DeriveBytes\s*\(")


def _scan_dotnet(text: str, rel: str, assets: list[_Asset]) -> None:
    keysizes = {m.group(1): int(m.group(2)) for m in _NET_KEYSIZE.finditer(text)}
    modes = {m.group(1): m.group(2).upper() for m in _NET_MODE.finditer(text)}

    for m in _NET_AES_VAR.finditer(text):
        var = m.group(1)
        size = keysizes.get(var) if var else None
        mode = modes.get(var) if var else None
        a = _mk("aes", "cipher", _DOTNET, rel, prop_size=size, mode=mode)
        if a:
            assets.append(a)
    if _NET_AESGCM.search(text):
        a = _mk("aes", "cipher", _DOTNET, rel, mode="GCM")
        if a:
            assets.append(a)
    if _NET_3DES.search(text):
        assets.append(_Asset("3des", "cipher", _DOTNET, rel))
    if _NET_DES.search(text):
        assets.append(_Asset("des", "cipher", _DOTNET, rel))
    if _NET_RC2.search(text):
        assets.append(_Asset("rc2", "cipher", _DOTNET, rel))

    for m in _NET_DIGEST.finditer(text):
        a = _mk(_canon(m.group(1) or m.group(2)), "digest", _DOTNET, rel)
        if a:
            assets.append(a)
    if _NET_HMAC.search(text):
        assets.append(_Asset("hmac", "mac", _DOTNET, rel))

    for m in _NET_RSA.finditer(text):
        bits = m.group(1) or m.group(2)
        size = int(bits) if bits else None
        a = _mk("rsa", "pke", _DOTNET, rel, name_size=size, prop_size=size)
        if a:
            assets.append(a)

    for m in _NET_EC.finditer(text):
        a = _mk("ecdsa", "signature", _DOTNET, rel,
                curve=_norm_curve(m.group(1)))
        if a:
            assets.append(a)

    if _NET_PBKDF2.search(text):
        assets.append(_Asset("pbkdf2", "kdf", _DOTNET, rel))


# --------------------------------------------------------------------------- #
# File iteration + emission
# --------------------------------------------------------------------------- #


def _dedup(assets: list[_Asset]) -> list[_Asset]:
    seen: dict[tuple[str, str], _Asset] = {}
    for a in assets:
        ident = (a.name, a.location)
        if ident not in seen:
            seen[ident] = a
    return sorted(seen.values(), key=lambda a: (a.name, a.location))


_LANG_PIPELINE: tuple[tuple[frozenset[str], re.Pattern[str], object], ...] = (
    (_JS_EXT, _JS_GATE, _scan_js),
    (_C_EXT, _C_GATE, _scan_c),
    (_RUST_EXT, _RUST_GATE, _scan_rust),
    (_DOTNET_EXT, _DOTNET_GATE, _scan_dotnet),
)


@cbom_register
class WebNativeCryptoScanner(Scanner):
    """JS/TS + C/C++ + Rust + .NET crypto-API scanner (C3). Runs before the regex
    scanner (``order`` 9 < 10) so its argument-bound components own the bom-ref
    when refs collide; shares ``order`` 9 with the Java/Go scanner but never
    touches the same file extensions."""

    name = "crypto_web_native"
    order = 9
    level = 1

    def scan(self, ctx: ScanContext) -> None:
        all_assets: list[_Asset] = []
        for exts, gate, fn in _LANG_PIPELINE:
            for path in _iter_files(ctx.root, exts):
                try:
                    raw = path.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                if not gate.search(raw):
                    continue
                text = _strip_comments(raw)
                rel = path.relative_to(ctx.root).as_posix()
                assets: list[_Asset] = []
                fn(text, rel, assets)  # type: ignore[operator]
                all_assets.extend(a for a in assets if a is not None)

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
            if asset.keysize:
                props["crypto:keySize"] = str(asset.keysize)
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


__all__ = ["WebNativeCryptoScanner"]
