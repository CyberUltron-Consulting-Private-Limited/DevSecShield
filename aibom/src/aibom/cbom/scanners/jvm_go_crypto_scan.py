"""CBOM scanner (C2): a **Java + Go** crypto-API scanner that extends the C1
detection-rule model (entry-point symbol fixes the primitive *context*, the call
arguments supply the parameters) to the two other languages IBM CBOMkit's
Sonar-Cryptography engine covers — clean-room (ledger rows 1/4/11: we studied the
*behavior* of the per-library API→asset map from public API docs and wrote our
own original resolver; no DSL / no copied detection rules).

Python has a true ``ast`` module so C1 parses a real tree. Java/Go do not have a
stdlib parser available to the product (and shipping a third-party grammar would
break the no-vendored-tooling rule), so this scanner uses an original
**call-expression extractor**: it strips comments, follows simple intra-file
variable bindings, and resolves each crypto entry-point's algorithm + key size +
mode + curve + padding the same way C1 does — the symbol resolution + argument
binding skeleton is language-agnostic; only the per-language front-end differs.

Library → asset maps implemented here (the R2 per-library corpus):

* **JCA/JCE** (Java) — ``Cipher/MessageDigest/Signature/Mac/KeyGenerator/
  KeyPairGenerator/SecretKeyFactory.getInstance("<spec>")``; the transformation
  string ``algo/mode/padding`` is split, the standard signature name
  ``SHA256withRSA`` resolves to its signature algorithm, and the key size is
  bound from a ``<var>.initialize(<int>)`` on the generator variable.
* **BouncyCastle** (Java) — engine classes (``AESEngine``/``DESedeEngine``/
  ``RSAEngine``/``ChaCha7539Engine`` …), block-mode wrappers
  (``CBCBlockCipher``/``GCMBlockCipher`` …, which wrap an engine via a nested
  ``new``), digests (``SHA256Digest`` …), and signers (``Ed25519Signer`` …).
* **Go stdlib + x/crypto** — ``aes/des/rc4.New*Cipher``, ``rsa/ecdsa/ed25519/
  dsa.GenerateKey`` (key size from ``rsa.GenerateKey(rand, 2048)``, curve from
  ``ecdsa.GenerateKey(elliptic.P256(), …)``), ``sha256/sha512/sha1/md5`` digests,
  ``hmac.New``, ``cipher.NewGCM/NewCBCEncrypter/…`` mode wrappers (bound to the
  block created by ``aes.NewCipher`` via the shared variable), and
  ``golang.org/x/crypto/{chacha20poly1305,bcrypt,argon2,scrypt,pbkdf2}``.

Lane discipline (EMIT only): one ``crypto_asset`` (assetType=algorithm) per
distinct (algorithm+params, file) usage, with ``crypto:detectedBy`` (the library
that fixed the context), ``crypto:detectionContext`` (the primitive role),
``crypto:detectionMethod=call-expr`` and ``crypto:confidence``. Weak-flagging is
C6, PQC grading is C7, the CycloneDX serialization is C9. To stay additive this
scanner emits the SAME ``crypto-algo-{name}-{file}`` bom-refs the regex scanner
(order 10) would, runs *before* it (order 9), and the regex pass defers to any
ref already present (``ctx.has_ref``); the pipeline also de-dups by bom-ref.
"""

from __future__ import annotations

import re
from pathlib import Path

from aibom.cbom.registry import cbom_register
from aibom.cbom.rules import (
    ALGORITHM_NORMALIZE,
    LITERAL_ALGO_ALIASES,
    algo_info,
)
from aibom.cbom.scanners.algorithm_scan import _display_name, _refine_key, _slug
from aibom.model.component import CryptoAssetComponent
from aibom.scan.registry import ScanContext, Scanner

_IGNORE_DIRS = frozenset(
    {
        ".git", ".venv", "venv", "env", "node_modules", "__pycache__",
        "dist", "build", ".next", ".nuxt", "target", "vendor", ".tox",
        ".mypy_cache", ".pytest_cache",
    }
)
_MAX_BYTES = 2_000_000

_JAVA_EXT = frozenset({".java", ".kt", ".kts", ".scala"})
_GO_EXT = frozenset({".go"})

# Library labels (crypto:detectedBy).
_JCA = "JCA/JCE (Java)"
_BC = "BouncyCastle (Java)"
_GO_STD = "Go crypto (stdlib)"
_GO_X = "golang.org/x/crypto"

_MODES = frozenset({"GCM", "CBC", "ECB", "CTR", "CFB", "OFB", "XTS", "CCM"})
_NONCE_MODES = frozenset({"GCM", "CTR", "CCM"})

# Comment stripping (keep string literals — JCA transformation strings live in
# them). Block comments are blanked whole (preserving line count); ``//`` line
# comments are dropped per line.
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_LINE_COMMENT = re.compile(r"//.*$", re.M)


def _strip_comments(text: str) -> str:
    text = _BLOCK_COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)
    return _LINE_COMMENT.sub("", text)


# --------------------------------------------------------------------------- #
# Shared asset record + builder (parity with the regex/AST scanners so refs
# collide and de-dup cleanly).
# --------------------------------------------------------------------------- #


class _Asset:
    # ``explicit_size`` is the key size found on the SOURCE (the only one folded
    # into the display name, mirroring the regex/AST scanners); the resolved
    # size (explicit or the algorithm table's default) goes in the property only.
    __slots__ = ("key", "explicit_size", "mode", "curve", "padding", "context",
                 "library", "location")

    def __init__(self, key, explicit_size, mode, curve, context, library, location):
        self.key = key
        self.explicit_size = explicit_size
        self.mode = mode
        self.curve = curve
        self.padding: str | None = None
        self.context = context
        self.library = library
        self.location = location

    @property
    def _refined(self) -> str:
        return _refine_key(self.key, self.explicit_size)

    @property
    def name(self) -> str:
        return _display_name(self._refined, self.explicit_size, self.mode)

    @property
    def resolved_size(self) -> int | None:
        return self.explicit_size or (algo_info(self._refined) or {}).get("key_size")

    @property
    def primitive(self) -> str:
        info = algo_info(self._refined) or {}
        return info.get("primitive", self.context)


def _canon(token: str) -> str | None:
    """Normalize a raw algorithm token (``DESede``, ``AES``, ``ARCFOUR``) to a
    canonical key, or None if it is not a known crypto algorithm."""
    key = re.sub(r"[\s\-_]", "", token).lower()
    canon = LITERAL_ALGO_ALIASES.get(key)
    if canon:
        return canon
    if token.lower() == "arcfour":
        return "rc4"
    return None


def _build(key: str, ctx_role: str, library: str, location: str,
           key_size: int | None = None, mode: str | None = None,
           curve: str | None = None) -> _Asset | None:
    refined = _refine_key(key, key_size)
    if not (ALGORITHM_NORMALIZE.get(refined) or algo_info(refined)):
        return None  # never inventory an unknown token
    return _Asset(key, key_size, mode, curve, ctx_role, library, location)


# --------------------------------------------------------------------------- #
# Java — JCA/JCE
# --------------------------------------------------------------------------- #

# getInstance class -> primitive-context role.
_JCA_CONTEXT: dict[str, str] = {
    "Cipher": "cipher",
    "MessageDigest": "digest",
    "Signature": "signature",
    "Mac": "mac",
    "KeyGenerator": "cipher",
    "KeyPairGenerator": "pke",
    "SecretKeyFactory": "kdf",
}
_JCA_GETINSTANCE = re.compile(
    r"(?:(\w+)\s*=\s*)?"
    r"(?:[\w.]+\.)?"
    r"(Cipher|MessageDigest|Signature|Mac|KeyGenerator|KeyPairGenerator"
    r"|SecretKeyFactory)\s*\.\s*getInstance\s*\(\s*\"([^\"]+)\""
)
_JCA_INITIALIZE = re.compile(r"(\w+)\s*\.\s*(?:initialize|init)\s*\(\s*(\d{2,5})")
_SIGNATURE_NAME = re.compile(r"^(?:\w+)with(\w+)$", re.IGNORECASE)


def _jca_signature_key(spec: str) -> str | None:
    """``SHA256withRSA`` -> rsa; ``SHA384withECDSA`` -> ecdsa; ``Ed25519`` -> ed."""
    m = _SIGNATURE_NAME.match(spec)
    if m:
        algo = m.group(1)
        if algo.lower() in ("rsaandmgf1", "rsassa", "rsa"):
            return "rsa"
        return _canon(algo)
    return _canon(spec)


def _scan_java_jca(text: str, rel: str, assets: list[_Asset]) -> None:
    sizes: dict[str, int] = {}
    for m in _JCA_INITIALIZE.finditer(text):
        sizes.setdefault(m.group(1), int(m.group(2)))

    for m in _JCA_GETINSTANCE.finditer(text):
        var, cls, spec = m.group(1), m.group(2), m.group(3)
        role = _JCA_CONTEXT[cls]
        explicit = sizes.get(var) if var else None

        if cls == "Signature":
            key = _jca_signature_key(spec)
            if key:
                a = _build(key, "signature", _JCA, rel)
                if a:
                    assets.append(a)
            continue
        if cls == "Mac":
            assets.append(_Asset("hmac", None, None, None, "mac", _JCA, rel))
            continue
        if cls == "SecretKeyFactory":
            if "pbkdf2" in spec.lower():
                assets.append(_Asset("pbkdf2", None, None, None, "kdf", _JCA, rel))
            continue

        # Cipher / KeyGenerator / KeyPairGenerator: spec may be a transformation.
        parts = [p.strip() for p in spec.split("/")]
        key = _canon(parts[0])
        if not key:
            continue
        mode = None
        padding = None
        if cls == "Cipher" and len(parts) >= 2:
            cand = parts[1].upper()
            # A mode only qualifies a symmetric cipher; RSA's "ECB" field is a
            # JCA misnomer, not a real mode of operation, so it is not attached.
            symmetric = (algo_info(key) or {}).get("primitive") in (
                "block-cipher", "stream-cipher", "ae"
            )
            if cand in _MODES and symmetric:
                mode = cand
            if len(parts) >= 3 and parts[2]:
                padding = parts[2]
        a = _build(key, role, _JCA, rel, key_size=explicit, mode=mode)
        if a:
            a.padding = padding
            assets.append(a)


# --------------------------------------------------------------------------- #
# Java — BouncyCastle
# --------------------------------------------------------------------------- #

_BC_ENGINE: dict[str, str] = {
    "AESEngine": "aes", "AESFastEngine": "aes", "AESLightEngine": "aes",
    "DESedeEngine": "3des", "DESEngine": "des",
    "RSAEngine": "rsa", "RSABlindedEngine": "rsa",
    "ChaCha7539Engine": "chacha20", "ChaChaEngine": "chacha20",
    "Salsa20Engine": "chacha20",
    "BlowfishEngine": "blowfish", "RC4Engine": "rc4",
    "RC2Engine": "rc2",
}
_BC_MODE: dict[str, str] = {
    "CBCBlockCipher": "CBC", "GCMBlockCipher": "GCM", "CFBBlockCipher": "CFB",
    "OFBBlockCipher": "OFB", "SICBlockCipher": "CTR", "CTRBlockCipher": "CTR",
}
_BC_DIGEST: dict[str, str] = {
    "MD5Digest": "md5", "SHA1Digest": "sha1", "SHA256Digest": "sha256",
    "SHA384Digest": "sha384", "SHA512Digest": "sha512",
    "SHA3Digest": "sha3_256", "Blake2bDigest": "blake2b", "Blake2sDigest": "blake2s",
}
_BC_SIGNER: dict[str, str] = {
    "Ed25519Signer": "ed25519", "Ed448Signer": "ed448",
    "RSADigestSigner": "rsa", "DSADigestSigner": "dsa", "ECDSASigner": "ecdsa",
}

# A mode wrapper that nests an engine: ``new GCMBlockCipher(new AESEngine())``.
_BC_MODE_WRAP = re.compile(
    r"new\s+(" + "|".join(_BC_MODE) + r")\s*\(\s*new\s+(\w+)\s*\("
)
_BC_NEW = re.compile(r"new\s+(\w+)\s*\(")


def _scan_java_bc(text: str, rel: str, assets: list[_Asset]) -> None:
    consumed: set[int] = set()
    # Mode wrappers first (they consume the nested engine's span).
    for m in _BC_MODE_WRAP.finditer(text):
        mode = _BC_MODE[m.group(1)]
        engine_key = _BC_ENGINE.get(m.group(2))
        if engine_key:
            consumed.add(m.start(2))
            a = _build(engine_key, "cipher", _BC, rel, mode=mode)
            if a:
                assets.append(a)
    # Standalone engines / digests / signers.
    for m in _BC_NEW.finditer(text):
        cls = m.group(1)
        if m.start(1) in consumed:
            continue
        if cls in _BC_ENGINE:
            a = _build(_BC_ENGINE[cls], "cipher", _BC, rel)
        elif cls in _BC_DIGEST:
            a = _build(_BC_DIGEST[cls], "digest", _BC, rel)
        elif cls in _BC_SIGNER:
            a = _build(_BC_SIGNER[cls], "signature", _BC, rel)
        elif cls == "HMac":
            a = _Asset("hmac", None, None, None, "mac", _BC, rel)
        else:
            continue
        if a:
            assets.append(a)


# --------------------------------------------------------------------------- #
# Go — stdlib crypto + golang.org/x/crypto
# --------------------------------------------------------------------------- #

# package.func -> (algo key, context, library). Funcs not listed for a package
# fall through to the package default.
_GO_CIPHER_PKG: dict[str, str] = {"aes": "aes", "des": "des", "rc4": "rc4"}
_GO_DIGEST_PKG: dict[str, str] = {
    "md5": "md5", "sha1": "sha1", "sha256": "sha256", "sha512": "sha512",
}
_GO_KEYGEN_PKG: dict[str, tuple[str, str]] = {
    "rsa": ("rsa", "pke"), "ecdsa": ("ecdsa", "signature"),
    "ed25519": ("ed25519", "signature"), "dsa": ("dsa", "signature"),
}
_GO_X_PKG: dict[str, tuple[str, str]] = {
    "chacha20poly1305": ("chacha20-poly1305", "ae"),
    "bcrypt": ("bcrypt", "kdf"), "argon2": ("argon2", "kdf"),
    "scrypt": ("scrypt", "kdf"), "pbkdf2": ("pbkdf2", "kdf"),
}
_GO_MODE_FN: dict[str, str] = {
    "NewGCM": "GCM", "NewCBCEncrypter": "CBC", "NewCBCDecrypter": "CBC",
    "NewCTR": "CTR", "NewCFBEncrypter": "CFB", "NewCFBDecrypter": "CFB",
    "NewOFB": "OFB",
}
_GO_CURVE: dict[str, str] = {
    "P224": "SECP224R1", "P256": "SECP256R1", "P384": "SECP384R1",
    "P521": "SECP521R1",
}

# ``block, err := aes.NewCipher(key)`` — capture LHS var + block algorithm.
_GO_BLOCK = re.compile(
    r"(\w+)\s*(?:,\s*\w+\s*)?:?=\s*(aes|des|rc4)\.(New\w*Cipher)\s*\("
)
_GO_MODE_CALL = re.compile(r"cipher\.(New\w+)\s*\(\s*(\w+)")
_GO_DIGEST_CALL = re.compile(r"\b(md5|sha1|sha256|sha512)\.(?:New|Sum\d*)\s*\(")
_GO_KEYGEN_CALL = re.compile(
    r"\b(rsa|ecdsa|ed25519|dsa)\.Generate(?:Key|MultiPrimeKey)\s*\(([^)]*)"
)
_GO_HMAC_CALL = re.compile(r"\bhmac\.New\s*\(")
_GO_X_CALL = re.compile(
    r"\b(chacha20poly1305|bcrypt|argon2|scrypt|pbkdf2)\.\w+\s*\("
)
_GO_RSA_SIZE = re.compile(r"\b(512|1024|2048|3072|4096)\b")


def _scan_go(text: str, rel: str, assets: list[_Asset]) -> None:
    # Record each block constructor's source position + variable so a later mode
    # wrapper binds to the NEAREST preceding block of the same name (functions
    # commonly reuse the name ``block`` — position disambiguates them).
    blocks: list[tuple[int, str, _Asset]] = []
    for m in _GO_BLOCK.finditer(text):
        var, pkg, fn = m.group(1), m.group(2), m.group(3)
        key = "3des" if "TripleDES" in fn else _GO_CIPHER_PKG[pkg]
        a = _build(key, "cipher", _GO_STD, rel)
        if a:
            assets.append(a)
            blocks.append((m.start(), var, a))

    # Mode wrappers bound to the nearest preceding block variable.
    for m in _GO_MODE_CALL.finditer(text):
        fn, var = m.group(1), m.group(2)
        mode = _GO_MODE_FN.get(fn)
        if not mode:
            continue
        candidates = [(pos, a) for (pos, v, a) in blocks
                      if v == var and pos < m.start()]
        if candidates:
            _, a = max(candidates, key=lambda t: t[0])
            if a.mode is None:
                a.mode = mode

    for m in _GO_DIGEST_CALL.finditer(text):
        a = _build(_GO_DIGEST_PKG[m.group(1)], "digest", _GO_STD, rel)
        if a:
            assets.append(a)

    for m in _GO_KEYGEN_CALL.finditer(text):
        pkg, args = m.group(1), m.group(2)
        key, role = _GO_KEYGEN_PKG[pkg]
        key_size = None
        curve = None
        if pkg == "rsa":
            sm = _GO_RSA_SIZE.search(args)
            if sm:
                key_size = int(sm.group(1))
        elif pkg == "ecdsa":
            cm = re.search(r"elliptic\.(P224|P256|P384|P521)", args)
            if cm:
                curve = _GO_CURVE[cm.group(1)]
        a = _build(key, role, _GO_STD, rel, key_size=key_size, curve=curve)
        if a:
            assets.append(a)

    if _GO_HMAC_CALL.search(text):
        assets.append(_Asset("hmac", None, None, None, "mac", _GO_STD, rel))

    for m in _GO_X_CALL.finditer(text):
        key, role = _GO_X_PKG[m.group(1)]
        a = _build(key, role, _GO_X, rel)
        if a:
            assets.append(a)


# --------------------------------------------------------------------------- #
# Import gates (precision) + file iteration
# --------------------------------------------------------------------------- #

_JAVA_IMPORT = re.compile(
    r"\b(?:javax\.crypto|java\.security|javax\.net\.ssl|org\.bouncycastle)\b"
)
_GO_IMPORT = re.compile(r'"(?:crypto/|golang\.org/x/crypto)')


def _iter_files(root: Path, exts: frozenset[str]):
    for p in sorted(root.rglob("*")):
        if any(part in _IGNORE_DIRS for part in p.relative_to(root).parts):
            continue
        if not p.is_file() or p.suffix.lower() not in exts:
            continue
        try:
            if p.stat().st_size > _MAX_BYTES:
                continue
        except OSError:
            continue
        yield p


def _dedup(assets: list[_Asset]) -> list[_Asset]:
    seen: dict[tuple[str, str], _Asset] = {}
    for a in assets:
        ident = (a.name, a.location)
        if ident not in seen:
            seen[ident] = a
    return sorted(seen.values(), key=lambda a: (a.name, a.location))


@cbom_register
class JvmGoCryptoScanner(Scanner):
    """Java + Go crypto-API scanner (C2). Runs before the regex scanner
    (``order`` 9 < 10) so its argument-bound components own the bom-ref when
    refs collide; after the Python-AST scanner (order 8), which it never touches
    (different file extensions)."""

    name = "crypto_jvm_go"
    order = 9
    level = 1

    def scan(self, ctx: ScanContext) -> None:
        all_assets: list[_Asset] = []

        for path in _iter_files(ctx.root, _JAVA_EXT):
            try:
                raw = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if not _JAVA_IMPORT.search(raw):
                continue
            text = _strip_comments(raw)
            rel = path.relative_to(ctx.root).as_posix()
            assets: list[_Asset] = []
            _scan_java_jca(text, rel, assets)
            _scan_java_bc(text, rel, assets)
            all_assets.extend(assets)

        for path in _iter_files(ctx.root, _GO_EXT):
            try:
                raw = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if not _GO_IMPORT.search(raw):
                continue
            text = _strip_comments(raw)
            rel = path.relative_to(ctx.root).as_posix()
            assets = []
            _scan_go(text, rel, assets)
            all_assets.extend(assets)

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


__all__ = ["JvmGoCryptoScanner"]
