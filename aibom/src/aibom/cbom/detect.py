"""Clean-room crypto-API **detection-rule model** (C1) — the keystone the CBOM
lane's algorithm detection runs on.

Studied from the *behavior* of PQCA/IBM sonar-cryptography's staged
``DetectionRuleBuilder`` DSL (object-type -> method -> ordered params -> context)
and re-expressed as OUR OWN declarative data structure — a frozen
:class:`CryptoRule` record keyed by ``(lang, library, receiver, method,
ordered arg_roles)``. **No OSS source was read-and-pasted**; this is an original
design (provenance: ``docs/cbom-research/LEDGER.md`` R1/R2 rows).

What it adds over the previous flat ``(key, line-regex)`` corpus:

* **Receiver + method binding** — ``algorithms.AES(...)`` is bound to the pyca
  cipher API, not a bare ``AES`` token on any line, so detection carries the API
  that produced it (a step toward per-library asset maps in C2/C3).
* **Ordered argument roles** — a rule declares which resolvers apply to a matched
  call's arguments (``KEY_SIZE``, ``MODE``, ``CURVE``, ``PADDING``,
  ``LITERAL_KEY``), so ``rsa.generate_private_key(key_size=2048)`` resolves the
  parameter set from the call, not a same-line digit hunt.
* **Data-flow-lite symbol table** — a bounded intra-file, last-assignment-wins
  pass binds ``name = <int | os.urandom(n) | modes.X | curve>`` so a size/mode
  assigned on one line resolves a usage on another (``bits = 2048`` ->
  ``rsa.generate_private_key(key_size=bits)`` -> RSA-2048). Our own pass — not a
  full AST, no control-flow, no network.
* **Padding capture** — ``padding.OAEP`` / ``PKCS1v15`` / ``PSS`` emit a
  ``crypto:padding`` fact (the arg-role C6's weak-padding predicate later reads).

Matching is a bounded **3-step per file** (deterministic, offline): prose-strip +
call-split -> data-flow-lite symbol table -> rule apply. The per-language rule
TABLES are ours; C1 ships the Python table, C2 adds Java+Go, C3 adds
JS/C-C++/Rust/.NET. The previous literal/parametrized-token patterns are kept as a
merged *literal lane* so recall never regresses — a receiver rule and a literal
match on the same line for the same algorithm coalesce into one fact.

Lane discipline: this module only turns source tokens into normalized crypto
*facts* (:class:`Detection`). It scores nothing, flags nothing, serializes
nothing — :mod:`aibom.cbom.scanners.algorithm_scan` turns facts into components.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from aibom.cbom.rules import (
    LITERAL_ALGO_ALIASES,
    algo_info,
    extract_curve,
    extract_key_size,
    extract_mode,
)

# --------------------------------------------------------------------------- #
# Argument roles — the ordered resolvers a rule binds to a matched call's args.
# --------------------------------------------------------------------------- #
ROLE_KEY_SIZE = "KEY_SIZE"
ROLE_MODE = "MODE"
ROLE_CURVE = "CURVE"
ROLE_PADDING = "PADDING"
ROLE_LITERAL_KEY = "LITERAL_KEY"  # a bytes key whose length implies the key size

_VALID_ROLES = frozenset(
    {ROLE_KEY_SIZE, ROLE_MODE, ROLE_CURVE, ROLE_PADDING, ROLE_LITERAL_KEY}
)

# A never-matching default so the compiled-pattern fields are typed non-optional;
# __post_init__ replaces it with the real receiver/method pattern.
_NEVER = re.compile(r"(?!x)x")


@dataclass(frozen=True)
class CryptoRule:
    """One clean-room detection rule: a matched ``receiver.method(args)`` call
    binds to a ``crypto:`` fact, with ``arg_roles`` declaring which parameter
    resolvers apply to the call's arguments.

    ``key`` is the canonical algorithm key into :mod:`aibom.cbom.rules` tables
    (``algo_info`` is authoritative for primitive/strength). ``receiver`` and
    ``method`` are token patterns (word-boundary matched); ``receiver=None``
    matches a bare/free function call.
    """

    lang: str
    library: str
    receiver: str | None
    method: str
    key: str
    arg_roles: tuple[str, ...] = ()
    # Compiled patterns (populated in __post_init__; excluded from equality).
    method_re: re.Pattern[str] = field(default=_NEVER, compare=False, repr=False)
    receiver_re: re.Pattern[str] | None = field(default=None, compare=False, repr=False)

    def __post_init__(self) -> None:
        for role in self.arg_roles:
            if role not in _VALID_ROLES:
                raise ValueError(f"unknown arg_role {role!r} in rule for {self.key}")
        object.__setattr__(
            self, "method_re", re.compile(rf"\b{self.method}\b")
        )
        object.__setattr__(
            self,
            "receiver_re",
            re.compile(rf"(?<![A-Za-z0-9_]){self.receiver}(?![A-Za-z0-9_])")
            if self.receiver
            else None,
        )


@dataclass
class Detection:
    """A normalized crypto fact from one source line."""

    key: str
    line_no: int
    key_size: int | None = None
    mode: str | None = None
    curve: str | None = None
    padding: str | None = None
    library: str | None = None
    receiver_bound: bool = False  # True when a receiver+method rule matched


# --------------------------------------------------------------------------- #
# Python rule table (C1). Keyed to the pyca/cryptography + stdlib + PyCryptodome
# API surface. C2/C3 add the other ecosystems' tables under the same model.
# --------------------------------------------------------------------------- #
_PY = "python"
_PYCA = "pyca/cryptography"
_STDLIB = "hashlib (stdlib)"


def _hash_rule(method: str, key: str) -> CryptoRule:
    # hashlib.sha256(...) / hashes.SHA256() — receiver is the module, method the algo.
    return CryptoRule(_PY, _STDLIB, r"hashlib|hashes", method, key)


PYTHON_RULES: tuple[CryptoRule, ...] = (
    # --- hashes (hashlib.<h> and pyca hashes.<H>) ---
    _hash_rule(r"md5|MD5", "md5"),
    _hash_rule(r"sha1|SHA1", "sha1"),
    _hash_rule(r"sha224|SHA224|sha256|SHA256", "sha256"),
    _hash_rule(r"sha384|SHA384", "sha384"),
    _hash_rule(r"sha512|SHA512", "sha512"),
    _hash_rule(r"sha3_256|SHA3_256", "sha3_256"),
    _hash_rule(r"sha3_384|SHA3_384", "sha3_384"),
    _hash_rule(r"sha3_512|SHA3_512", "sha3_512"),
    _hash_rule(r"blake2b", "blake2b"),
    _hash_rule(r"blake2s", "blake2s"),
    # --- pyca symmetric cipher engines (algorithms.<X>) + mode/key-length roles ---
    CryptoRule(_PY, _PYCA, "algorithms", "AES", "aes", (ROLE_LITERAL_KEY, ROLE_MODE)),
    CryptoRule(_PY, _PYCA, "algorithms", "TripleDES", "3des", (ROLE_MODE,)),
    CryptoRule(_PY, _PYCA, "algorithms", "DES", "des", (ROLE_MODE,)),
    CryptoRule(_PY, _PYCA, "algorithms", "ARC4", "rc4", ()),
    CryptoRule(_PY, _PYCA, "algorithms", "Blowfish", "blowfish", (ROLE_MODE,)),
    CryptoRule(_PY, _PYCA, "algorithms", "ChaCha20", "chacha20", ()),
    # --- pyca asymmetric key generation (arg-role KEY_SIZE / CURVE) ---
    CryptoRule(_PY, _PYCA, "rsa", "generate_private_key", "rsa", (ROLE_KEY_SIZE,)),
    CryptoRule(_PY, _PYCA, "dsa", "generate_private_key", "dsa", (ROLE_KEY_SIZE,)),
    CryptoRule(_PY, _PYCA, "ec", "generate_private_key", "ecdsa", (ROLE_CURVE,)),
    CryptoRule(_PY, _PYCA, "ec", "derive_private_key", "ecdh", (ROLE_CURVE,)),
    CryptoRule(_PY, _PYCA, "ed25519", "Ed25519PrivateKey", "ed25519", ()),
    CryptoRule(_PY, _PYCA, "ed448", "Ed448PrivateKey", "ed448", ()),
    CryptoRule(_PY, _PYCA, "x25519", "X25519PrivateKey", "x25519", ()),
    # --- pyca RSA padding (arg-role PADDING; RSA-in-use => an RSA asset) ---
    CryptoRule(_PY, _PYCA, "padding", "OAEP|PKCS1v15|PSS", "rsa", (ROLE_PADDING,)),
    # --- KDF / MAC ---
    CryptoRule(_PY, _PYCA, None, "PBKDF2HMAC", "pbkdf2", ()),
    CryptoRule(_PY, _PYCA, None, "Scrypt", "scrypt", ()),
    CryptoRule(_PY, _PYCA, None, "HKDF", "hkdf", ()),
    CryptoRule(_PY, _STDLIB, "hmac", "HMAC|new", "hmac", ()),
)

# --------------------------------------------------------------------------- #
# Java rule table (C2). Two Java crypto surfaces:
#   * JCA/JCE — algorithm names are embedded in ``getInstance("...")`` /
#     ``"...withRSA"`` STRING arguments, so they are recovered by the language-
#     scoped literal lane :data:`JAVA_LITERALS` below (not a receiver binding).
#   * Bouncy Castle low-level API — concrete engine/digest/signer CLASSES
#     (``new AESEngine()``, ``new SHA256Digest()``, ``new Ed25519Signer()``),
#     matched here as free-constructor rules (``receiver=None``). These class
#     spellings are what the flat token corpus could not see.
# --------------------------------------------------------------------------- #
_JAVA = "java"
_BC = "Bouncy Castle"


def _bc_rule(method: str, key: str, roles: tuple[str, ...] = ()) -> CryptoRule:
    """A Bouncy Castle free-constructor rule (``new <Class>(...)``)."""
    return CryptoRule(_JAVA, _BC, None, method, key, roles)


JAVA_RULES: tuple[CryptoRule, ...] = (
    # --- BouncyCastle symmetric engines ---
    _bc_rule(r"(?:AESEngine|AESFastEngine|AESLightEngine)", "aes"),
    _bc_rule(r"DESEngine", "des"),
    _bc_rule(r"DESedeEngine", "3des"),
    _bc_rule(r"RC2Engine", "rc2"),
    _bc_rule(r"RC4Engine", "rc4"),
    _bc_rule(r"BlowfishEngine", "blowfish"),
    _bc_rule(r"(?:ChaChaEngine|ChaCha7539Engine)", "chacha20"),
    # --- BouncyCastle asymmetric engines ---
    _bc_rule(r"(?:RSAEngine|RSABlindedEngine)", "rsa"),
    # --- BouncyCastle digests ---
    _bc_rule(r"MD5Digest", "md5"),
    _bc_rule(r"SHA1Digest", "sha1"),
    _bc_rule(r"(?:SHA256Digest|SHA224Digest)", "sha256"),
    _bc_rule(r"SHA384Digest", "sha384"),
    _bc_rule(r"SHA512Digest", "sha512"),
    _bc_rule(r"(?:SHA3Digest|SHA3_256Digest)", "sha3_256"),
    _bc_rule(r"Blake2bDigest", "blake2b"),
    _bc_rule(r"Blake2sDigest", "blake2s"),
    # --- BouncyCastle signers / key-agreement / MAC ---
    _bc_rule(r"(?:Ed25519Signer|Ed25519KeyPairGenerator)", "ed25519"),
    _bc_rule(r"(?:Ed448Signer|Ed448KeyPairGenerator)", "ed448"),
    _bc_rule(r"ECDSASigner", "ecdsa"),
    _bc_rule(r"(?:X25519Agreement|X25519KeyPairGenerator)", "x25519"),
    _bc_rule(r"HMac", "hmac"),
    # --- BouncyCastle PQC (FIPS 203/204 spellings) ---
    _bc_rule(r"(?:MLKEMEngine|KyberEngine|MLKEMKeyPairGenerator)", "kyber"),
    _bc_rule(r"(?:MLDSAEngine|DilithiumEngine|MLDSAKeyPairGenerator)", "dilithium"),
    _bc_rule(r"(?:SLHDSAEngine|SPHINCSPlusEngine)", "sphincs+"),
)


# --------------------------------------------------------------------------- #
# Go rule table (C2). ``crypto/*`` stdlib is package.method-shaped
# (``aes.NewCipher``, ``rsa.GenerateKey(_, 2048)``, ``ecdsa.GenerateKey(P256)``);
# ``golang.org/x/crypto`` adds bcrypt/argon2/scrypt/chacha20poly1305/blake2*. The
# stdlib block-cipher constructors (``aes.NewCipher``/``des.NewCipher``) are the
# real gap — the token corpus never bound them (no ``AES(`` / ``getInstance``).
# Go decouples the mode (``cipher.NewGCM``) from the block cipher, so a Go asset
# is inventoried per PRIMITIVE (mode is left to a future cross-line pass).
# --------------------------------------------------------------------------- #
_GO = "go"
_GOSTD = "Go crypto (stdlib)"
_GOX = "golang.org/x/crypto"

GO_RULES: tuple[CryptoRule, ...] = (
    # --- stdlib block / stream ciphers ---
    CryptoRule(_GO, _GOSTD, "aes", "NewCipher", "aes", (ROLE_LITERAL_KEY,)),
    CryptoRule(_GO, _GOSTD, "des", "NewCipher", "des"),
    CryptoRule(_GO, _GOSTD, "des", "NewTripleDESCipher", "3des"),
    CryptoRule(_GO, _GOSTD, "rc4", "NewCipher", "rc4"),
    # --- stdlib hashes ---
    CryptoRule(_GO, _GOSTD, "md5", r"(?:New|Sum)", "md5"),
    CryptoRule(_GO, _GOSTD, "sha1", r"(?:New|Sum)", "sha1"),
    CryptoRule(_GO, _GOSTD, "sha256", r"(?:New|New224|Sum256|Sum224)", "sha256"),
    CryptoRule(_GO, _GOSTD, "sha512", r"(?:New|New384|Sum512|Sum384)", "sha512"),
    CryptoRule(_GO, _GOSTD, "sha3", r"(?:New256|New384|New512|Sum256)", "sha3_256"),
    # --- stdlib asymmetric ---
    CryptoRule(_GO, _GOSTD, "rsa", "GenerateKey", "rsa", (ROLE_KEY_SIZE,)),
    CryptoRule(_GO, _GOSTD, "dsa", r"(?:GenerateKey|GenerateParameters)", "dsa"),
    CryptoRule(_GO, _GOSTD, "ecdsa", "GenerateKey", "ecdsa", (ROLE_CURVE,)),
    CryptoRule(_GO, _GOSTD, "ed25519", r"(?:GenerateKey|NewKeyFromSeed)", "ed25519"),
    # --- golang.org/x/crypto ---
    CryptoRule(_GO, _GOX, "bcrypt",
               r"(?:GenerateFromPassword|CompareHashAndPassword)", "bcrypt"),
    CryptoRule(_GO, _GOX, "argon2", r"(?:IDKey|Key)", "argon2"),
    CryptoRule(_GO, _GOX, "scrypt", "Key", "scrypt"),
    CryptoRule(_GO, _GOX, "chacha20poly1305", r"(?:New|NewX)", "chacha20-poly1305"),
    CryptoRule(_GO, _GOX, "chacha20", "NewUnauthenticatedCipher", "chacha20"),
    CryptoRule(_GO, _GOX, "pbkdf2", "Key", "pbkdf2"),
    CryptoRule(_GO, _GOX, "hkdf", r"(?:New|Expand|Extract)", "hkdf"),
    CryptoRule(_GO, _GOX, "blake2b", r"(?:New256|New384|New512|New)", "blake2b"),
    CryptoRule(_GO, _GOX, "blake2s", r"(?:New256|New128|New)", "blake2s"),
)

RULES_BY_LANG: dict[str, tuple[CryptoRule, ...]] = {
    _PY: PYTHON_RULES,
    _JAVA: JAVA_RULES,
    _GO: GO_RULES,
}


# --------------------------------------------------------------------------- #
# Literal lane — the previous concrete-spelling + parametrized-literal corpus,
# kept so recall never regresses. A rule match and a literal match on the same
# line for the same algorithm coalesce into ONE fact (see :func:`detect_crypto`).
# --------------------------------------------------------------------------- #
_F = re.IGNORECASE
LITERAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("md5", re.compile(r"\bhashlib\.md5\b|\bMD5\b", _F)),
    ("sha1", re.compile(r"\bhashlib\.sha1\b|\bSHA-?1\b", _F)),
    ("sha256", re.compile(r"\bsha-?256\b", _F)),
    ("sha384", re.compile(r"\bsha-?384\b", _F)),
    ("sha512", re.compile(r"\bsha-?512\b", _F)),
    ("sha3_256", re.compile(r"\bsha3[_-]?256\b", _F)),
    ("blake2b", re.compile(r"\bblake2b\b", _F)),
    ("blake2s", re.compile(r"\bblake2s\b", _F)),
    ("3des", re.compile(r"\bTripleDES\b|\b3DES\b|\bDESede\b|\bMODE_DES3\b", _F)),
    ("des", re.compile(
        r"\balgorithms\.DES\b|\bDES_(?:set_key|ecb|cbc)\b|\bMODE_DES\b", _F)),
    ("rc4", re.compile(r"\bARC4\b|\bRC4\b", _F)),
    ("rc2", re.compile(r"\bRC2\b", _F)),
    ("blowfish", re.compile(r"\bBlowfish\b", _F)),
    ("aes", re.compile(
        r"\balgorithms\.AES\b|\bAESGCM\b|\bAESCCM\b|\bAES-?(?:128|192|256)\b"
        r"|\bAES\b(?=\s*[/(])|getInstance\(\s*['\"]AES", _F)),
    ("chacha20", re.compile(r"\bChaCha20\b", _F)),
    ("rsa", re.compile(
        r"\brsa\.generate_private_key\b|\bRSA\.generate\b|\bRSA-?(?:512|1024|2048|3072|4096)\b"
        r"|\bgenerateKeyPair\(\s*['\"]RSA|\bRSA_generate_key\b", _F)),
    ("ecdsa", re.compile(r"\bECDSA\b|\bec\.derive_private_key\b", _F)),
    ("ed25519", re.compile(r"\bEd25519\b", _F)),
    ("ed448", re.compile(r"\bEd448\b", _F)),
    ("x25519", re.compile(r"\bX25519\b", _F)),
    ("ecdh", re.compile(r"\bECDH\b", _F)),
    ("dh", re.compile(r"\bDiffieHellman\b|\bcreateDiffieHellman\b", _F)),
    ("dsa", re.compile(r"\bDSA\b", _F)),
    ("pbkdf2", re.compile(r"\bPBKDF2", _F)),
    ("scrypt", re.compile(r"\bscrypt\b", _F)),
    ("argon2", re.compile(r"\bargon2\b", _F)),
    ("bcrypt", re.compile(r"\bbcrypt\b", _F)),
    ("hkdf", re.compile(r"\bHKDF\b", _F)),
    ("hmac", re.compile(r"\bHMAC\b", _F)),
    ("kyber", re.compile(r"\bKyber\b|\bML-?KEM\b", _F)),
    ("dilithium", re.compile(r"\bDilithium\b|\bML-?DSA\b", _F)),
    ("sphincs+", re.compile(r"\bSPHINCS\+?\b|\bSLH-?DSA\b", _F)),
)


# --------------------------------------------------------------------------- #
# Language-scoped literal lanes (C2). JCA/JCE embeds the algorithm in a
# ``getInstance("...")`` / ``"...withRSA"`` STRING argument, so these Java-only
# spellings are matched by token — but ONLY on ``java`` sources, so they never
# perturb the frozen Python corpus (the global :data:`LITERAL_PATTERNS` above are
# unchanged). Same ``(key, pattern)`` shape as the global lane.
# --------------------------------------------------------------------------- #
JAVA_LITERALS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # JCA signature spellings "<digest>with<pke>" + getInstance("RSA"). No leading
    # \b: the spelling is preceded by a digit (``SHA256withRSA``), which is not a
    # word boundary — a leading \b would never fire.
    ("rsa", re.compile(r"with(?:RSA|RSAandMGF1)\b|getInstance\(\s*\"RSA", _F)),
    ("ecdsa", re.compile(r"withECDSA\b|getInstance\(\s*\"EC(?:DSA)?[\"/]", _F)),
    ("dsa", re.compile(r"withDSA\b|getInstance\(\s*\"DSA[\"/]", _F)),
    ("dh", re.compile(r"getInstance\(\s*\"(?:DH|DiffieHellman)\"", _F)),
    # getInstance("DES...") but NOT "DESede" (the latter is 3DES, matched below)
    ("des", re.compile(r"getInstance\(\s*\"DES(?:/|\")", _F)),
    ("3des", re.compile(r"getInstance\(\s*\"DESede", _F)),
    # JCA MAC spelling "HmacSHA256" / "HmacMD5"
    ("hmac", re.compile(r"\bHmac(?:SHA\d*|MD5)\b", _F)),
    ("pbkdf2", re.compile(r"\bPBKDF2With", _F)),
)

# --------------------------------------------------------------------------- #
# Language-scoped literal lanes for the four remaining R2 ecosystems (C3):
# JS/TS (Node ``crypto`` + WebCrypto), C/C++ (OpenSSL EVP), Rust (ring +
# RustCrypto), .NET (``System.Security.Cryptography``). These recover the
# ecosystem-specific spellings the GLOBAL literal lane structurally cannot see —
# WebCrypto's ``{name:"AES-GCM"}`` (no key-size digit), OpenSSL's underscore-
# packed ``EVP_aes_256_gcm`` / ``EVP_sha384`` (a ``_`` breaks ``\bSHA-?384\b``),
# RustCrypto's fused ``Aes256Gcm`` / ``ChaCha20Poly1305`` (no word boundary
# before the mode), and .NET's ``RSACryptoServiceProvider`` /
# ``TripleDESCryptoServiceProvider`` / ``Rfc2898DeriveBytes``. Each key is the
# CANONICAL algorithm key (a sized ``aes-256`` where the spelling encodes the
# length, so ``algo_info`` resolves the primitive and the display name carries
# the size); mode/curve still ride the per-line ``extract_mode``/``extract_curve``
# where the dash form supports it. Scoping to the language keeps the frozen
# Python corpus byte-identical (these lanes never run on Python).
# --------------------------------------------------------------------------- #
_JS = "javascript"
_C = "c"
_RUST = "rust"
_CSHARP = "csharp"

JS_LITERALS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # Node cipher spec strings carry algorithm + key size + mode in one literal
    # (``createCipheriv('aes-256-gcm', …)``); the sized key + the ``-gcm`` suffix
    # (read by extract_mode) resolve AES-256-GCM.
    ("aes-256", re.compile(r"['\"]aes-256-\w+['\"]", _F)),
    ("aes-192", re.compile(r"['\"]aes-192-\w+['\"]", _F)),
    ("aes-128", re.compile(r"['\"]aes-128-\w+['\"]", _F)),
    ("3des", re.compile(r"['\"]des-ede3-\w+['\"]|['\"]des3['\"]", _F)),
    # Node ``'des-cbc'`` but NOT the 3DES ``des-ede3`` spelling above.
    ("des", re.compile(r"['\"]des-(?:cbc|ecb|cfb|ofb)['\"]", _F)),
    # WebCrypto ``{name:"AES-GCM"|"AES-CBC"|…}`` — no size digit, mode via suffix.
    ("aes", re.compile(r"\bAES-(?:GCM|CBC|CTR|KW|CCM)\b", _F)),
    # WebCrypto RSA identifiers + Node ``generateKeyPair[Sync]('rsa',…)`` (the
    # ``Sync`` suffix breaks the global ``generateKeyPair\(`` anchor); size via the
    # bare modulus digit on the line.
    ("rsa", re.compile(
        r"\bRSA-OAEP\b|\bRSA-PSS\b|\bRSASSA-PKCS1"
        r"|generateKeyPair(?:Sync)?\s*\(\s*['\"]rsa", _F)),
    # Node ``generateKeyPair[Sync]('ec',…)`` — curve via the ``namedCurve`` string.
    ("ecdsa", re.compile(r"generateKeyPair(?:Sync)?\s*\(\s*['\"]ec['\"]", _F)),
    # Node ``createHmac(…)`` — ``\bHMAC\b`` never fires on ``createHmac``.
    ("hmac", re.compile(r"\bcreateHmac\b", _F)),
    # ``chacha20-poly1305`` AEAD (Node/WebCrypto spelling).
    ("chacha20-poly1305", re.compile(r"chacha20-poly1305", _F)),
    # Node legacy KEM/KA helper.
    ("dh", re.compile(r"\bcreateDiffieHellman\b", _F)),
)

C_LITERALS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # OpenSSL EVP cipher fns pack algorithm + key size + mode in the fn name.
    ("aes-256", re.compile(r"\bEVP_aes_256_\w+", _F)),
    ("aes-192", re.compile(r"\bEVP_aes_192_\w+", _F)),
    ("aes-128", re.compile(r"\bEVP_aes_128_\w+", _F)),
    ("3des", re.compile(r"\bEVP_des_ede3?_\w+", _F)),
    ("des", re.compile(r"\bEVP_des_(?:cbc|ecb|cfb|ofb)\b", _F)),
    ("rc4", re.compile(r"\bEVP_rc4\b", _F)),
    ("chacha20-poly1305", re.compile(r"\bEVP_chacha20_poly1305\b", _F)),
    # Digests: a ``_`` before the family breaks the global ``\bSHA-?384\b``.
    ("sha512", re.compile(r"\bEVP_sha512\b|\bSHA512_Init\b", _F)),
    ("sha384", re.compile(r"\bEVP_sha384\b|\bSHA384_Init\b", _F)),
    ("sha256", re.compile(r"\bEVP_sha256\b|\bSHA256_Init\b", _F)),
    ("sha1", re.compile(r"\bEVP_sha1\b|\bSHA1_Init\b", _F)),
    ("md5", re.compile(r"\bEVP_md5\b|\bMD5_Init\b", _F)),
    # RSA key generation (size via the bare modulus digit on the line). No leading
    # \b — ``EVP_PKEY_CTX_set_rsa_keygen_bits`` prefixes ``set`` with ``_``.
    ("rsa", re.compile(r"set_rsa_keygen_bits|\bRSA_generate_key(?:_ex)?\b", _F)),
    # EC key generation (curve carried in the NID_ token — coarse; no curve fold).
    ("ecdsa", re.compile(
        r"\bEC_KEY_new_by_curve_name\b|\bEVP_PKEY_CTX_set_ec_paramgen_curve", _F)),
    # ``HMAC``/``HMAC_Init`` — a trailing ``_`` breaks the global ``\bHMAC\b``.
    ("hmac", re.compile(r"\bHMAC", _F)),
)

RUST_LITERALS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # RustCrypto fused AEAD types + ring UPPER_SNAKE constants.
    ("aes-256", re.compile(r"\bAes256Gcm(?:Siv)?\b|\bAES_256_GCM\b", _F)),
    ("aes-192", re.compile(r"\bAes192Gcm\b|\bAES_192_GCM\b", _F)),
    ("aes-128", re.compile(r"\bAes128Gcm\b|\bAES_128_GCM\b", _F)),
    ("chacha20-poly1305",
     re.compile(r"\bChaCha20Poly1305\b|\bCHACHA20_POLY1305\b", _F)),
    # RustCrypto RSA + ring RSA signature schemes (global ``rsa`` lane misses both).
    ("rsa", re.compile(r"\bRsa(?:PrivateKey|PublicKey)\b|\bRSA_P(?:SS|KCS1)", _F)),
    # ring signature constants: ``ECDSA_P384_*`` — the ``_`` breaks ``\bECDSA\b``.
    ("ecdsa", re.compile(r"\bECDSA_P\d+", _F)),
    # ring ``hmac::HMAC_SHA256`` — a trailing ``_``/``::`` breaks the global lane.
    ("hmac", re.compile(r"\bhmac::|\bHMAC_SHA", _F)),
)

DOTNET_LITERALS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # AES providers (``Aes.Create`` / ``new AesGcm`` / ``RijndaelManaged``).
    ("aes", re.compile(
        r"\bAes\.Create\b|\bnew\s+Aes(?:Gcm|Managed|CryptoServiceProvider)?\b"
        r"|\bRijndaelManaged\b", _F)),
    # 3DES vs DES vs RC2 providers (a trailing ``Crypto…`` breaks the global lane).
    ("3des", re.compile(r"\bTripleDES", _F)),
    ("des", re.compile(
        r"(?<![A-Za-z])DESCryptoServiceProvider\b|(?<![A-Za-z])DES\.Create\b", _F)),
    ("rc2", re.compile(r"\bRC2CryptoServiceProvider\b|\bRC2\.Create\b", _F)),
    # RSA providers — key size via the bare modulus digit (``new RSA…(2048)``).
    ("rsa",
     re.compile(r"\bRSACryptoServiceProvider\b|\bRSA\.Create\b|\bRSAOpenSsl\b", _F)),
    # HMAC ``new HMACSHA256`` — a following ``SHA`` breaks the global ``\bHMAC\b``.
    ("hmac", re.compile(r"\bnew\s+HMAC|\bHMAC(?:SHA\d+|MD5)\b", _F)),
    # PBKDF2 under its .NET class name.
    ("pbkdf2", re.compile(r"\bRfc2898DeriveBytes\b", _F)),
)

LITERAL_BY_LANG: dict[str, tuple[tuple[str, re.Pattern[str]], ...]] = {
    _JAVA: JAVA_LITERALS,
    _JS: JS_LITERALS,
    _C: C_LITERALS,
    _RUST: RUST_LITERALS,
    _CSHARP: DOTNET_LITERALS,
}


# --------------------------------------------------------------------------- #
# Prose stripping (docstrings / block + line comments are never scanned).
# --------------------------------------------------------------------------- #
_TRIPLE_QUOTE = re.compile(r'""".*?"""|\'\'\'.*?\'\'\'', re.S)
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_PY_COMMENT = re.compile(r"#.*$")
_C_LINE_COMMENT = re.compile(r"//.*$")
# C#'s ``using`` is overloaded: ``using System.Security.Cryptography;`` is an
# import directive (a LIBRARY signal), but ``using (var aes = Aes.Create())`` is a
# real USAGE statement — the negative lookahead keeps the latter out of the
# import-skip so its crypto call is still scanned (C3).
_IMPORT_RE = re.compile(
    r"^\s*(?:import|from|require|use|using(?!\s*[(])|#include|require_once)\b", re.I
)
# A grouped-import path entry (Go ``import (\n  "crypto/aes"\n )``): a line that is
# only a path-like quoted string (optionally aliased). These are LIBRARY signals,
# not usage — scanning them would mint an info-less detection that precedes and
# shadows the real call site (e.g. "crypto/ecdsa" before ecdsa.GenerateKey(P256)).
_BARE_IMPORT_PATH = re.compile(r'^\s*(?:[A-Za-z_.]\w*\s+)?"[^"]*/[^"]*"\s*$')


def _blank(match: re.Match[str]) -> str:
    return re.sub(r"[^\n]", " ", match.group(0))


def strip_noncode(text: str) -> str:
    """Blank docstrings + C-style block comments (prose is never scanned)."""
    text = _TRIPLE_QUOTE.sub(_blank, text)
    text = _BLOCK_COMMENT.sub(_blank, text)
    return text


def _strip_line_comment(line: str, lang: str) -> str:
    if lang in ("python", "ruby"):
        return _PY_COMMENT.sub("", line)
    if lang in ("javascript", "java", "go", "c", "rust", "php", "csharp"):
        return _C_LINE_COMMENT.sub("", line)
    return line


# --------------------------------------------------------------------------- #
# Step 1 — shallow paren-balanced call splitter.
# --------------------------------------------------------------------------- #
_CALL_HEAD = re.compile(r"([A-Za-z_][\w.]*)\s*\(")


def split_calls(line: str) -> list[tuple[str, str]]:
    """Return ``(callee_chain, args)`` for each ``...name(args)`` call on a line.

    ``callee_chain`` is the full dotted callee (``ed25519.Ed25519PrivateKey`` for
    ``ed25519.Ed25519PrivateKey.generate(``); the trailing ``.generate`` is
    dropped so a rule's ``method`` token can match the constructor). ``args`` is
    the paren-balanced argument substring.
    """
    out: list[tuple[str, str]] = []
    for m in _CALL_HEAD.finditer(line):
        chain = m.group(1)
        open_idx = line.index("(", m.start(1))
        depth = 0
        j = open_idx
        while j < len(line):
            if line[j] == "(":
                depth += 1
            elif line[j] == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        args = line[open_idx + 1 : j]
        out.append((chain, args))
    return out


# --------------------------------------------------------------------------- #
# Step 2 — data-flow-lite symbol table (intra-file, last-assignment-wins).
# --------------------------------------------------------------------------- #
_ASSIGN_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*(.+?)\s*$")
_INT_RE = re.compile(r"^(\d{2,5})$")
_BYTES_LEN_RE = re.compile(
    r"(?:os\.)?urandom\(\s*(\d+)\s*\)"          # os.urandom(32)
    r"|token_bytes\(\s*(\d+)\s*\)"               # secrets.token_bytes(32)
    r"|(?:bytes|bytearray)\(\s*(\d+)\s*\)"       # bytes(32)
)


@dataclass
class _Symbol:
    key_size: int | None = None
    mode: str | None = None
    curve: str | None = None


def build_symbols(lines: list[str]) -> dict[str, _Symbol]:
    """One pass binding ``name -> {key_size|mode|curve}`` (last write wins)."""
    table: dict[str, _Symbol] = {}
    for raw in lines:
        m = _ASSIGN_RE.match(raw)
        if not m:
            continue
        name, rhs = m.group(1), m.group(2)
        sym = _Symbol()
        im = _INT_RE.match(rhs)
        if im:
            sym.key_size = int(im.group(1))
        else:
            bm = _BYTES_LEN_RE.search(rhs)
            if bm:
                nbytes = next(g for g in bm.groups() if g)
                sym.key_size = int(nbytes) * 8  # byte length -> bit key size
        sym.mode = extract_mode(rhs)
        sym.curve = extract_curve(rhs)
        if sym.key_size is not None or sym.mode or sym.curve:
            table[name] = sym  # only bind names that carry a crypto-relevant value
    return table


# --------------------------------------------------------------------------- #
# Step 3 — argument-role resolution.
# --------------------------------------------------------------------------- #
_KW_SIZE_RE = re.compile(
    r"(?:key_?size|bits|length|modulus_?length|n)\s*=\s*([A-Za-z_]\w*|\d{2,5})", _F
)
_POS_IDENT_RE = re.compile(r"^\s*([A-Za-z_]\w*)")


def _resolve_key_size(
    args: str, line: str, symbols: dict[str, _Symbol]
) -> int | None:
    """KEY_SIZE role: kwarg (``key_size=..``) -> symbol -> same-line digit."""
    m = _KW_SIZE_RE.search(args)
    if m:
        val = m.group(1)
        if val.isdigit():
            return int(val)
        sym = symbols.get(val)
        if sym and sym.key_size is not None:
            return sym.key_size
    return extract_key_size(line)


def _resolve_literal_key_size(
    args: str, symbols: dict[str, _Symbol]
) -> int | None:
    """LITERAL_KEY role: the first positional bytes-key arg's length -> key size
    (``algorithms.AES(key)`` where ``key = os.urandom(32)`` -> 256)."""
    m = _POS_IDENT_RE.match(args)
    if not m:
        return None
    sym = symbols.get(m.group(1))
    if sym and sym.key_size in (128, 192, 256):
        return sym.key_size
    return None


def _resolve_curve(args: str, line: str) -> str | None:
    return extract_curve(args) or extract_curve(line)


_PADDING_RE = re.compile(r"\b(OAEP|PKCS1v15|PSS)\b")


def _resolve_padding(chain: str, line: str) -> str | None:
    m = _PADDING_RE.search(chain) or _PADDING_RE.search(line)
    return m.group(1).lower() if m else None


def _apply_rule(
    rule: CryptoRule,
    chain: str,
    args: str,
    line: str,
    symbols: dict[str, _Symbol],
) -> Detection:
    det = Detection(key=rule.key, line_no=0, library=rule.library, receiver_bound=True)
    for role in rule.arg_roles:
        if role == ROLE_KEY_SIZE:
            det.key_size = _resolve_key_size(args, line, symbols)
        elif role == ROLE_LITERAL_KEY:
            det.key_size = _resolve_literal_key_size(args, symbols)
        elif role == ROLE_MODE:
            det.mode = extract_mode(line)
        elif role == ROLE_CURVE:
            det.curve = _resolve_curve(args, line)
        elif role == ROLE_PADDING:
            det.padding = _resolve_padding(chain, line)
    return det


def _merge(into: Detection, other: Detection) -> None:
    """Coalesce two same-key detections on one line — non-empty params win."""
    into.key_size = into.key_size or other.key_size
    into.mode = into.mode or other.mode
    into.curve = into.curve or other.curve
    into.padding = into.padding or other.padding
    into.library = into.library or other.library
    into.receiver_bound = into.receiver_bound or other.receiver_bound


def detect_crypto(text: str, lang: str) -> list[Detection]:
    """Detect crypto usage in one source file's ``text`` (of language ``lang``).

    Runs the bounded 3-step match: prose-strip + call-split -> data-flow-lite
    symbol table -> rule apply (receiver+method+arg-roles) merged with the literal
    lane. Returns one :class:`Detection` per distinct algorithm per line.
    """
    stripped = strip_noncode(text)
    raw_lines = stripped.splitlines()
    work_lines = [_strip_line_comment(ln, lang) for ln in raw_lines]
    symbols = build_symbols(work_lines)
    rules = RULES_BY_LANG.get(lang, ())

    out: list[Detection] = []
    for line_no, work in enumerate(work_lines, start=1):
        line = work.strip()
        if not line or _IMPORT_RE.search(line) or _BARE_IMPORT_PATH.match(work):
            continue  # imports are LIBRARY signals, handled by the scanner
        per_line: dict[str, Detection] = {}

        # --- receiver+method rule lane ---
        calls = split_calls(line)
        for rule in rules:
            if rule.receiver_re is not None and not rule.receiver_re.search(line):
                continue
            for chain, args in calls:
                if not rule.method_re.search(chain):
                    continue
                det = _apply_rule(rule, chain, args, line, symbols)
                det.line_no = line_no
                if rule.key in per_line:
                    _merge(per_line[rule.key], det)
                else:
                    per_line[rule.key] = det
                break  # one detection per rule per line

        # --- literal lane (recall floor) ---
        explicit_ks = extract_key_size(line)
        mode = extract_mode(line)
        curve = extract_curve(line)
        for key, pat in (*LITERAL_PATTERNS, *LITERAL_BY_LANG.get(lang, ())):
            if not pat.search(line):
                continue
            lit = Detection(
                key=key,
                line_no=line_no,
                key_size=explicit_ks,
                mode=mode,
                curve=curve,
            )
            if key in per_line:
                _merge(per_line[key], lit)
            else:
                per_line[key] = lit

        out.extend(per_line.values())
    return out


# Convenience: aliases that map a bare literal token to a canonical key (used by
# downstream normalization; re-exported for callers that resolve JWT/alg tokens).
def canonical_key(token: str) -> str | None:
    """Map a lowercased bare token (``aes256``, ``rsa2048``) to a canonical key."""
    key = LITERAL_ALGO_ALIASES.get(re.sub(r"[^a-z0-9]", "", token.lower()))
    if key and algo_info(key):
        return key
    return key


__all__ = [
    "CryptoRule",
    "Detection",
    "PYTHON_RULES",
    "JAVA_RULES",
    "GO_RULES",
    "RULES_BY_LANG",
    "LITERAL_PATTERNS",
    "JAVA_LITERALS",
    "JS_LITERALS",
    "C_LITERALS",
    "RUST_LITERALS",
    "DOTNET_LITERALS",
    "LITERAL_BY_LANG",
    "detect_crypto",
    "split_calls",
    "build_symbols",
    "strip_noncode",
    "canonical_key",
    "ROLE_KEY_SIZE",
    "ROLE_MODE",
    "ROLE_CURVE",
    "ROLE_PADDING",
    "ROLE_LITERAL_KEY",
]
