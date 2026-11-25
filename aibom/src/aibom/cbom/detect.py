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
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from aibom.cbom.powershell import POWERSHELL_LITERALS
from aibom.cbom.rules import (
    LITERAL_ALGO_ALIASES,
    PQC_PARAM_SETS,
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
# The crypto OPERATION the matched call performs (encrypt/decrypt vs sign/verify).
# It is not a positional argument but the enclosing method context — resolved from
# the source line the same way ROLE_MODE reads ``extract_mode(line)``. C16 uses it
# to tell an RSA *encryption* (where PKCS#1 v1.5 padding is a Bleichenbacher break)
# apart from an RSA *signature* (where PKCS#1 v1.5 is FIPS-approved).
ROLE_OPERATION = "OPERATION"

_VALID_ROLES = frozenset(
    {ROLE_KEY_SIZE, ROLE_MODE, ROLE_CURVE, ROLE_PADDING, ROLE_LITERAL_KEY,
     ROLE_OPERATION}
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
    # Construction qualifier folded into the display name (``AESWrapEngine`` ->
    # ``AES-KW``); the canonical ``key`` keeps the algorithm's strength record.
    variant: str | None = None
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
    operation: str | None = None  # "encrypt" | "sign" | None (see ROLE_OPERATION)
    # PQC parameter set (ML-KEM-768 -> "768", ML-DSA-87 -> "87", ...): retained so
    # the C7 grader can map the set to its NIST security category. None when the
    # spelling carries no set (``new MLKEMEngine(0)``). Distinct from ``key_size``
    # (a bit length) — a PQC set identifier is a category label, not a bit count.
    parameter: str | None = None
    library: str | None = None
    receiver_bound: bool = False  # True when a receiver+method rule matched
    # Construction qualifier named by the source next to the algorithm: the HMAC /
    # PBKDF2 hash (``HmacSHA256`` -> ``SHA256``, ``PBKDF2WithHmacSHA512`` ->
    # ``HMAC-SHA512``) or AES key wrap (``KW``). Folded into the display name only.
    variant: str | None = None
    # Only a key specification named the algorithm (Java ``new SecretKeySpec(k, "AES")``): the key of a cipher
    # used elsewhere in the file, not a separate usage (see :func:`_drop_subsumed_key_specs`).
    key_spec_only: bool = False
    # Where the algorithm name was spelled when it is not on this line: a constant defined in another file
    # (``Cipher.getInstance(Algs.CIPHER)`` -> ``Algs.java:3``), as ``path:line``.
    defined_at: str | None = None
    # The composite this hash is only a parameter of on this line (``SHA1withRSA`` -> rsa,
    # ``PBKDF2HMAC(algorithm=hashes.SHA256())`` -> pbkdf2): not a hashing of its own (see :func:`_mark_inner`).
    inner_of: str | None = None
    # What the hash is to that composite when it is not the digest the composite signs or MACs: ``"oaep"`` for the
    # hash of RSA-OAEP encryption (and its MGF1), which rests on no collision resistance.
    inner_role: str | None = None
    # The algorithm is inferred, not read: ``Cipher.getInstance(<String parameter>)`` bound to the only cipher
    # transformation configured for the module (``defined_at`` names that configuration line).
    inferred: bool = False
    # A settings value (a dict / object property, a record or class field default):
    # the setting's name; ``config_read_at`` names the crypto call that reads it
    # (``path:line``, or ``line`` in the same file); a setting no crypto call is
    # proven to read is kept as a low-confidence asset (PR #500 review 6061095673).
    config_binding: str | None = None
    config_read_at: str | None = None
    low_confidence: bool = False


# --------------------------------------------------------------------------- #
# Python rule table (C1). Keyed to the pyca/cryptography + stdlib + PyCryptodome
# API surface. C2/C3 add the other ecosystems' tables under the same model.
# --------------------------------------------------------------------------- #
_PY = "python"
_PYCRYPTODOME = "pycryptodome"
_PYCA = "pyca/cryptography"
_STDLIB = "hashlib (stdlib)"


def _hash_rules(method: str, key: str) -> tuple[CryptoRule, CryptoRule]:
    # hashlib.sha256(...) is the standard library's; hashes.SHA256() is pyca
    # cryptography's (``PBKDF2HMAC(algorithm=hashes.SHA256())``), so the library that
    # provides the digest is the one the call names (review of #491 m2).
    return (
        CryptoRule(_PY, _STDLIB, r"hashlib", method, key),
        CryptoRule(_PY, _PYCA, r"hashes", method, key),
    )


PYTHON_RULES: tuple[CryptoRule, ...] = (
    # --- hashes (hashlib.<h> and pyca hashes.<H>) ---
    *_hash_rules(r"md5|MD5", "md5"),
    *_hash_rules(r"sha1|SHA1", "sha1"),
    *_hash_rules(r"sha224|SHA224|sha256|SHA256", "sha256"),
    *_hash_rules(r"sha384|SHA384", "sha384"),
    *_hash_rules(r"sha512|SHA512", "sha512"),
    *_hash_rules(r"sha3_256|SHA3_256", "sha3_256"),
    *_hash_rules(r"sha3_384|SHA3_384", "sha3_384"),
    *_hash_rules(r"sha3_512|SHA3_512", "sha3_512"),
    *_hash_rules(r"blake2b", "blake2b"),
    *_hash_rules(r"blake2s", "blake2s"),
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
    # --- pyca RSA padding (arg-roles PADDING + OPERATION; RSA-in-use => an RSA
    #     asset). OPERATION separates an RSA encrypt (``pub.encrypt(m, PKCS1v15())``
    #     — a Bleichenbacher break) from an RSA sign (``priv.sign(m, PKCS1v15())`` —
    #     FIPS-approved), which C16's weak-padding predicate needs. ---
    CryptoRule(_PY, _PYCA, "padding", "OAEP|PKCS1v15|PSS", "rsa",
               (ROLE_PADDING, ROLE_OPERATION)),
    # --- KDF / MAC ---
    CryptoRule(_PY, _PYCA, None, "PBKDF2HMAC", "pbkdf2", ()),
    CryptoRule(_PY, _PYCA, None, "Scrypt", "scrypt", ()),
    CryptoRule(_PY, _PYCA, None, "HKDF", "hkdf", ()),
    CryptoRule(_PY, _STDLIB, "hmac", "HMAC|new", "hmac", ()),
    # Fernet (pyca ``cryptography.fernet``): AES-128-CBC + HMAC-SHA256 under one 256-bit key (the Fernet spec);
    # the key's source (a literal or the environment) is the misuse lane's question, not this one.
    CryptoRule(_PY, _PYCA, None, r"(?:Fernet|MultiFernet)", "fernet", ()),
    # --- PyCryptodome / PyCrypto: <Cipher>.new(key, <Cipher>.MODE_x, ...), RSA/DSA/ECC.generate(...) ---
    # (the AST lane covers pyca + hashlib only; without these, AES.new(k, AES.MODE_ECB) produced no row)
    CryptoRule(_PY, _PYCRYPTODOME, "AES", "new", "aes", (ROLE_MODE,)),
    CryptoRule(_PY, _PYCRYPTODOME, "DES3", "new", "3des", (ROLE_MODE,)),
    CryptoRule(_PY, _PYCRYPTODOME, "DES", "new", "des", (ROLE_MODE,)),
    CryptoRule(_PY, _PYCRYPTODOME, "ARC4", "new", "rc4", ()),
    CryptoRule(_PY, _PYCRYPTODOME, "ARC2", "new", "rc2", (ROLE_MODE,)),
    CryptoRule(_PY, _PYCRYPTODOME, "Blowfish", "new", "blowfish", (ROLE_MODE,)),
    CryptoRule(_PY, _PYCRYPTODOME, "ChaCha20", "new", "chacha20", ()),
    CryptoRule(_PY, _PYCRYPTODOME, "ChaCha20_Poly1305", "new", "chacha20-poly1305", ()),
    CryptoRule(_PY, _PYCRYPTODOME, "RSA", "generate", "rsa", (ROLE_KEY_SIZE,)),
    CryptoRule(_PY, _PYCRYPTODOME, "DSA", "generate", "dsa", (ROLE_KEY_SIZE,)),
    CryptoRule(_PY, _PYCRYPTODOME, "ECC", "generate", "ecdsa", (ROLE_CURVE,)),
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


def _bc_rule(method: str, key: str, roles: tuple[str, ...] = (),
             variant: str | None = None) -> CryptoRule:
    """A Bouncy Castle free-constructor rule (``new <Class>(...)``)."""
    return CryptoRule(_JAVA, _BC, None, method, key, roles, variant)


JAVA_RULES: tuple[CryptoRule, ...] = (
    # --- BouncyCastle symmetric engines (MODE: the block-mode wrapper the engine
    #     is nested in, ``new CBCBlockCipher(new DESedeEngine())`` -> 3DES-CBC) ---
    _bc_rule(r"(?:AESEngine|AESFastEngine|AESLightEngine)", "aes", (ROLE_MODE,)),
    # RFC 3394 / RFC 5649 AES key wrap (JWE A*KW, ECDH-ES+A*KW).
    _bc_rule(r"AESWrapEngine", "aes", variant="KW"),
    _bc_rule(r"AESWrapPadEngine", "aes", variant="KWP"),
    _bc_rule(r"ElGamalEngine", "elgamal"),
    # --- BouncyCastle KDFs (SP 800-56A Concatenation KDF, JWE ECDH-ES) ---
    _bc_rule(r"ConcatenationKDFGenerator", "concat-kdf"),
    _bc_rule(r"DESEngine", "des", (ROLE_MODE,)),
    _bc_rule(r"DESedeEngine", "3des", (ROLE_MODE,)),
    _bc_rule(r"RC2Engine", "rc2", (ROLE_MODE,)),
    _bc_rule(r"RC4Engine", "rc4"),
    _bc_rule(r"BlowfishEngine", "blowfish", (ROLE_MODE,)),
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


# Bouncy Castle block-mode wrapper around an engine on the same line:
# ``new GCMBlockCipher(new AESEngine())`` / ``GCMBlockCipher.newInstance(AESEngine.newInstance())``.
# SIC is Bouncy Castle's name for CTR.
_BC_MODE_WRAP = re.compile(
    r"\b(CBC|GCM|CFB|OFB|SIC|CTR|CCM)BlockCipher\b(?:\s*\.\s*newInstance)?\s*\(\s*(?:new\s+)?\w+Engine\b"
)


def _bc_wrapper_mode(line: str) -> str | None:
    m = _BC_MODE_WRAP.search(line)
    if not m:
        return None
    return "CTR" if m.group(1) == "SIC" else m.group(1)


# --------------------------------------------------------------------------- #
# Go rule table (C2). ``crypto/*`` stdlib is package.method-shaped
# (``aes.NewCipher``, ``rsa.GenerateKey(_, 2048)``, ``ecdsa.GenerateKey(P256)``);
# ``golang.org/x/crypto`` adds bcrypt/argon2/scrypt/chacha20poly1305/blake2*. The
# stdlib block-cipher constructors (``aes.NewCipher``/``des.NewCipher``) are the
# real gap — the token corpus never bound them (no ``AES(`` / ``getInstance``).
# Go decouples the mode (``cipher.NewGCM(block)``) from the block cipher
# (``block, err := aes.NewCipher(key)``); :func:`_bind_go_modes` joins them through
# the block variable after the per-line pass.
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
    CryptoRule(_GO, _GOSTD, "hmac", "New", "hmac"),
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
    # RC2 the cipher, not a release candidate: the bare token is case-sensitive and
    # never a version suffix ("1.0.0-RC2", "struts:1.1:rc2", "2.0.RC2"); lowercase
    # only as a cipher spec ("rc2-cbc", 'rc2'), never a variable such as ``rc2``.
    ("rc2", re.compile(
        r"(?<![-.:/\w])RC2\b(?![-.]\d)"
        r"|(?i:\brc2-(?:cbc|ecb|cfb|ofb|40|64|128)\b|(?<=[\"'])rc2(?=[\"'/]))")),
    ("blowfish", re.compile(r"\bBlowfish\b", _F)),
    # pyca's AESGCM / AESCCM class names are matched case-sensitively: an identifier such as Go's
    # ``func aesGCM(`` is not a use of AES.
    ("aes", re.compile(
        r"\balgorithms\.AES\b|(?-i:\bAES(?:GCM|CCM)\b)|\bAES-?(?:128|192|256)\b"
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
    # Plain DSA, but NOT the "DSA" inside PQC "ML-DSA" / "SLH-DSA" (a hyphen or
    # letter before "DSA" is the PQC form, graded separately as dilithium/sphincs).
    ("dsa", re.compile(r"(?<![-\w])DSA\b", _F)),
    ("pbkdf2", re.compile(r"\bPBKDF2", _F)),
    # Node ``crypto.scryptSync`` too. scrypt / argon2 / bcrypt are plain words that UI
    # labels and config keys use
    # ("Scrypt Tier", ``kdf: "scrypt"``): these three count only in a call or API
    # context (``_api_word_hits``).
    ("scrypt", re.compile(r"\bscrypt(?:Sync)?\b", _F)),
    ("argon2", re.compile(r"\bargon2\b", _F)),
    ("bcrypt", re.compile(r"\bbcrypt\b", _F)),
    ("hkdf", re.compile(r"\bHKDF\b", _F)),
    ("hmac", re.compile(r"\bHMAC\b", _F)),
    # Hybrid / composite KEX FIRST (fused ``X25519MLKEM768``): the leading \b of
    # the bare X25519 / ML-KEM patterns can't fire inside the fused token (no word
    # boundary before ``MLKEM``), but matching hybrid up front documents intent.
    ("hybrid", re.compile(
        r"\b(?:X25519|X448|SecP256r1|SecP384r1|P256|P384)"
        r"(?:MLKEM|Kyber)\d{3,4}\b", _F)),
    # PQC KEM / signatures. The fused sized spellings (``MLKEM768``/``MLDSA87``)
    # have no word boundary after ``KEM``/``DSA``, so an explicit ``MLKEM\d`` /
    # ``MLDSA\d`` alternative is needed alongside the dashed ``ML-KEM`` form.
    ("kyber", re.compile(r"\bKyber\d*\b|\bML-?KEM\b|\bMLKEM\d{3,4}\b", _F)),
    ("dilithium", re.compile(r"\bDilithium\d*\b|\bML-?DSA\b|\bMLDSA\d{2,3}\b", _F)),
    ("sphincs+", re.compile(r"\bSPHINCS\+?\d*\b|\bSLH-?DSA\b|\bSLHDSA\d{3}\b", _F)),
    # FN-DSA / FALCON — sized only (bare "falcon" is an AMBIGUOUS_TOKENS word).
    ("falcon", re.compile(r"\bFALCON[-_]?(?:512|1024)\b", _F)),
    # Stateful-hash signatures (SP 800-208 / CNSA 2.0). XMSS/XMSS^MT, LMS, HSS as
    # standalone uppercase tokens — crypto-specific enough at word boundaries.
    ("xmss", re.compile(r"\bXMSS(?:\^?MT)?\b", _F)),
    ("lms", re.compile(r"\bLMS\b", _F)),
    # Case-sensitive: a lowercase ``hss`` is an identifier (``HttpSessionsSite hss``).
    ("hss", re.compile(r"\bHSS\b")),
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
    # MGF1 inside RSA-OAEP / RSA-PSS: the "MGF1" argument of OAEPParameterSpec /
    # PSSParameterSpec, an MGF1ParameterSpec, or a "...AndMGF1Padding" /
    # "...withRSAandMGF1" standard name.
    ("mgf1", re.compile(r"[\"']MGF1[\"']|\bMGF1ParameterSpec\b|andMGF1", _F)),
    # Bouncy Castle DigestFactory.createSHA256() (``createSHA256`` has no word
    # boundary before SHA, so the global hash lane never sees it).
    ("sha256", re.compile(r"\bDigestFactory\s*\.\s*createSHA(?:224|256)\b")),
    ("sha384", re.compile(r"\bDigestFactory\s*\.\s*createSHA384\b")),
    ("sha512", re.compile(r"\bDigestFactory\s*\.\s*createSHA512\b")),
    ("sha1", re.compile(r"\bDigestFactory\s*\.\s*createSHA1\b")),
    ("md5", re.compile(r"\bDigestFactory\s*\.\s*createMD5\b")),
    ("sha3_256", re.compile(r"\bDigestFactory\s*\.\s*createSHA3_256\b")),
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
    # Node ``publicEncrypt({ padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' }, …)``.
    ("rsa", re.compile(r"\bRSA_PKCS1_OAEP_PADDING\b")),
    # node-forge ``forge.pki.rsa.generateKeyPair({ bits: 1024 })`` — size via the ``bits`` digit on the line.
    ("rsa", re.compile(r"\bpki\.rsa\.generateKeyPair\b")),
    # Node ``createSign('RSA-SHA256')`` / ``createVerify('RSA-SHA1')``: the signature names RSA explicitly
    # (a bare ``'SHA256'`` takes its key type from the key and names no algorithm).
    ("rsa", re.compile(r"\bcreate(?:Sign|Verify)\s*\(\s*['\"]RSA-(?:SHA|MD5)", _F)),
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
    # ring ``digest::SHA1_FOR_LEGACY_USE_ONLY`` — the ``_`` breaks the global ``\bSHA-?1\b``.
    ("sha1", re.compile(r"\bSHA1_FOR_LEGACY_USE_ONLY\b")),
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
    # Hash provider classes (``new SHA1Managed()``, ``new MD5CryptoServiceProvider()``, ``SHA256Cng``): the class
    # suffix leaves no word boundary after the family, so the global ``\bMD5\b`` / ``\bSHA-?1\b`` never fire.
    ("md5", re.compile(r"\bMD5(?:CryptoServiceProvider|Cng)\b", _F)),
    ("sha1", re.compile(r"\bSHA1(?:Managed|CryptoServiceProvider|Cng)\b", _F)),
    ("sha256", re.compile(r"\bSHA256(?:Managed|CryptoServiceProvider|Cng)\b", _F)),
    ("sha384", re.compile(r"\bSHA384(?:Managed|CryptoServiceProvider|Cng)\b", _F)),
    ("sha512", re.compile(r"\bSHA512(?:Managed|CryptoServiceProvider|Cng)\b", _F)),
)

# OpenSSL EVP cipher names passed as a string: PHP ``openssl_encrypt($d, 'des-ecb', …)`` and Ruby
# ``OpenSSL::Cipher.new('des-ede3-cbc')``. AES / RC4 / RC2 spellings (``'aes-128-ecb'``, ``'rc4'``) already hit the
# global lane; DES, 3DES and Blowfish names only exist in this quoted form. A bare ``'bf'`` / ``'des'`` string is
# not matched (too generic outside an OpenSSL call); the mode rides the ``-ecb`` / ``-cbc`` suffix (extract_mode).
OPENSSL_NAME_LITERALS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("3des", re.compile(r"['\"](?:des-ede3?(?:-(?:cbc|ecb|cfb1?|cfb8|ofb))?|des3)['\"]", _F)),
    ("des", re.compile(r"['\"]des-(?:cbc|ecb|cfb1?|cfb8|ofb)['\"]", _F)),
    ("blowfish", re.compile(r"['\"]bf-(?:cbc|ecb|cfb|ofb)['\"]", _F)),
)

# Perl ``Digest::MD5`` / ``Digest::SHA`` function interface (``md5_hex($x)``): the ``_hex`` suffix leaves no word
# boundary after the family, so the global lane never sees it.
PERL_LITERALS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("md5", re.compile(r"\bmd5(?:_hex|_base64)?\s*\(|\bDigest::MD5\s*->\s*new\b")),
    ("sha1", re.compile(r"\bsha1(?:_hex|_base64)?\s*\(")),
    ("sha256", re.compile(r"\bsha256(?:_hex|_base64)?\s*\(")),
    ("sha512", re.compile(r"\bsha512(?:_hex|_base64)?\s*\(")),
)

# SQL engines: MySQL ``AES_ENCRYPT()`` / ``DES_ENCRYPT()``, pgcrypto ``encrypt(data, key, 'des')`` (the cipher type
# is the quoted third argument), SQL Server ``CREATE SYMMETRIC KEY … ALGORITHM = TRIPLE_DES``.
_PGCRYPTO = r"\b(?:en|de)crypt(?:_iv)?\s*\(.*['\"]{}(?:-(?:cbc|ecb))?(?:/pad:\w+)?['\"]"
SQL_LITERALS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aes", re.compile(r"\bAES_(?:EN|DE)CRYPT\s*\(|" + _PGCRYPTO.format("aes"), _F)),
    ("des", re.compile(r"\bDES_(?:EN|DE)CRYPT\s*\(|" + _PGCRYPTO.format("des") + r"|\bALGORITHM\s*=\s*DESX?\b", _F)),
    ("3des", re.compile(_PGCRYPTO.format("3des") + r"|\bTRIPLE_DES(?:_3KEY)?\b", _F)),
    ("blowfish", re.compile(_PGCRYPTO.format("bf"), _F)),
    ("rc4", re.compile(r"\bALGORITHM\s*=\s*RC4(?:_128)?\b", _F)),
)

# ``openssl`` command lines (shell scripts, Dockerfile ``RUN``): ``openssl enc -des3``, ``openssl des-ede3-cbc``,
# ``-bf-cbc``. ``-aes-128-ecb`` and ``-rc4`` already hit the global lane.
SHELL_LITERALS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("3des", re.compile(r"\bopenssl\s+(?:enc\s+(?:\S+\s+)*?)?-?(?:des3|des-ede3?(?:-\w+)?)(?=\s|$)")),
    ("des", re.compile(r"\bopenssl\s+(?:enc\s+(?:\S+\s+)*?)?-?des(?:-(?:cbc|ecb|cfb|ofb))?(?=\s|$)")),
    ("blowfish", re.compile(r"\bopenssl\s+(?:enc\s+(?:\S+\s+)*?)?-?bf(?:-(?:cbc|ecb|cfb|ofb))?(?=\s|$)")),
)

_PHP = "php"
_RUBY = "ruby"
_PERL = "perl"
_SQL = "sql"
_SHELL = "shell"
_VBNET = "vbnet"

# Modes the global ``extract_mode`` cannot read because the spelling has no ``-``/``/`` separator: OpenSSL's
# ``EVP_aes_128_ecb`` / ``EVP_des_ede3_cbc``, RustCrypto ``Aes256Gcm`` / ring ``AES_256_GCM`` and the
# ``cbc::Encryptor`` / ``ecb::Encryptor`` modules, .NET ``AesGcm`` / ``AesCcm``.
_LANG_MODE: dict[str, re.Pattern[str]] = {
    _C: re.compile(
        r"\bEVP_(?:aes_\d{3}|des_ede3?|des|bf|rc2|camellia_\d{3}|aria_\d{3}|sm4)_"
        r"(gcm|cbc|ecb|ctr|cfb(?:1|8|64|128)?|ofb|ccm|xts)\b", _F),
    _RUST: re.compile(
        r"\bAes(?:128|192|256)(Gcm|Ccm)(?:Siv)?\b|\bAES_(?:128|192|256)_(GCM)\b|\b(cbc|ecb|ctr|cfb|ofb)::(?:En|De)cryptor\b"),
    _CSHARP: re.compile(r"\bAes(Gcm|Ccm)\b"),
}


def _lang_mode(line: str, lang: str) -> str | None:
    pat = _LANG_MODE.get(lang)
    m = pat.search(line) if pat else None
    if not m:
        return None
    mode = next(g for g in m.groups() if g).upper()
    return "CFB" if mode.startswith("CFB") else mode


# WebCrypto RSA algorithm names carry the padding scheme (``{name: "RSA-OAEP"}``), as does Node's padding constant.
_WEBCRYPTO_PADDING = (("RSA-OAEP", "oaep"), ("RSA_PKCS1_OAEP_PADDING", "oaep"), ("RSA-PSS", "pss"),
                      ("RSASSA-PKCS1", "pkcs1v15"))


_C_CIPHER_LIST_ARG = re.compile(
    r"(\bSSL(?:_CTX)?_set_cipher_list\s*\(\s*[^,()]+,\s*\")([^\"\\]*)")


def _blank_list(m: re.Match[str]) -> str:
    return m.group(1) + " " * len(m.group(2))


def _lang_padding(line: str, lang: str, key: str) -> str | None:
    if lang != _JS or key != "rsa":
        return None
    up = line.upper()
    return next((pad for token, pad in _WEBCRYPTO_PADDING if token in up), None)


LITERAL_BY_LANG: dict[str, tuple[tuple[str, re.Pattern[str]], ...]] = {
    _JAVA: JAVA_LITERALS,
    _JS: JS_LITERALS,
    _C: C_LITERALS,
    _RUST: RUST_LITERALS,
    _CSHARP: DOTNET_LITERALS,
    _VBNET: DOTNET_LITERALS,
    _PHP: OPENSSL_NAME_LITERALS,
    _RUBY: OPENSSL_NAME_LITERALS,
    _PERL: PERL_LITERALS,
    _SQL: SQL_LITERALS,
    _SHELL: SHELL_LITERALS,
    # PowerShell calls the .NET classes, plus the SecureString cmdlets' AES (aibom.cbom.powershell)
    "powershell": DOTNET_LITERALS + POWERSHELL_LITERALS,
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
# real USAGE statement — the negative lookahead keeps the latter (and a C# 8
# ``using var h = new SHA1Cng();`` declaration) out of the import-skip so its
# crypto call is still scanned (C3).
_IMPORT_RE = re.compile(
    r"^\s*(?:import|from|require|use|using(?!\s*[(]|\s+var\b)|#include|require_once)\b", re.I
)
# A grouped-import path entry (Go ``import (\n  "crypto/aes"\n )``): a line that is
# only a path-like quoted string (optionally aliased). These are LIBRARY signals,
# not usage — scanning them would mint an info-less detection that precedes and
# shadows the real call site (e.g. "crypto/ecdsa" before ecdsa.GenerateKey(P256)).
_BARE_IMPORT_PATH = re.compile(r'^\s*(?:[A-Za-z_.]\w*\s+)?"[^"]*/[^"]*"\s*$')
# A package declaration (Java/Kotlin/Scala ``package org.x.crypto.ed25519;``, Go ``package ed25519``, Perl
# ``package Crypt::DES;``) names a namespace, not a usage.
_PACKAGE_DECL = re.compile(r"^\s*package\s+[\w.:]+\s*;?\s*$")


def _blank(match: re.Match[str]) -> str:
    return re.sub(r"[^\n]", " ", match.group(0))


def strip_noncode(text: str) -> str:
    """Blank docstrings + C-style block comments (prose is never scanned)."""
    text = _TRIPLE_QUOTE.sub(_blank, text)
    text = _BLOCK_COMMENT.sub(_blank, text)
    return text


_HASH_COMMENT = re.compile(r"(?:^|(?<=\s))#.*$")       # shell / Perl: ``$#`` / ``${#v}`` are not comments
_SQL_COMMENT = re.compile(r"--.*$")
_PHP_HASH_COMMENT = re.compile(r"(?:^|(?<=\s))#(?!\[).*$")
_VB_COMMENT = re.compile(r"^((?:[^\"']|\"[^\"]*\")*)'.*$")  # VB ``'`` comment outside a "string"


def _strip_line_comment(line: str, lang: str) -> str:
    if lang in ("python", "ruby"):
        return _PY_COMMENT.sub("", line)
    if lang in ("javascript", "java", "go", "c", "rust", "csharp", "swift"):
        return _C_LINE_COMMENT.sub("", line)
    if lang in (_SHELL, _PERL, "powershell"):
        return _HASH_COMMENT.sub("", line)
    if lang == _PHP:  # ``//`` and ``#`` (not a PHP 8 ``#[Attribute]``)
        return _PHP_HASH_COMMENT.sub("", _C_LINE_COMMENT.sub("", line))
    if lang == _SQL:
        return _SQL_COMMENT.sub("", line)
    if lang == _VBNET:
        if re.match(r"^\s*REM\b", line, re.I):
            return ""
        return _VB_COMMENT.sub(r"\1", line)
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


# The crypto operation is read off the enclosing call on the line: a
# ``.encrypt(`` / ``.decrypt(`` receiver marks encryption, ``.sign(`` /
# ``.verify(`` marks a signature. Only an UNAMBIGUOUS line (exactly one family
# present) yields an operation — a line mentioning both, or neither, stays None so
# a downstream weak-padding check can only fire on proven encryption.
_OP_ENCRYPT_RE = re.compile(r"\.(?:encrypt|decrypt)\b", _F)
_OP_SIGN_RE = re.compile(r"\.(?:sign|verify)\b", _F)


def _resolve_operation(line: str) -> str | None:
    enc = bool(_OP_ENCRYPT_RE.search(line))
    sig = bool(_OP_SIGN_RE.search(line))
    if enc and not sig:
        return "encrypt"
    if sig and not enc:
        return "sign"
    return None


def _apply_rule(
    rule: CryptoRule,
    chain: str,
    args: str,
    line: str,
    symbols: dict[str, _Symbol],
) -> Detection:
    det = Detection(key=rule.key, line_no=0, library=rule.library, receiver_bound=True,
                    variant=rule.variant)
    for role in rule.arg_roles:
        if role == ROLE_KEY_SIZE:
            det.key_size = _resolve_key_size(args, line, symbols)
        elif role == ROLE_LITERAL_KEY:
            det.key_size = _resolve_literal_key_size(args, symbols)
        elif role == ROLE_MODE:
            det.mode = extract_mode(line) or (
                _bc_wrapper_mode(line) if rule.lang == _JAVA else None
            )
        elif role == ROLE_CURVE:
            det.curve = _resolve_curve(args, line)
        elif role == ROLE_PADDING:
            det.padding = _resolve_padding(chain, line)
        elif role == ROLE_OPERATION:
            det.operation = _resolve_operation(line)
    return det


# PQC parameter-set extraction (C7). Each family's set is captured from the line
# it appears on, anchored to the family token so an unrelated digit is never
# mistaken for a set. ``hybrid`` reuses the ML-KEM extractor (the parameter is the
# ML-KEM component's set). Only a member of ``PQC_PARAM_SETS[key]`` is accepted.
_PQC_PARAM_RE: dict[str, re.Pattern[str]] = {
    "kyber": re.compile(r"(?:Kyber|ML-?KEM)[-_]?(\d{3,4})", _F),
    "dilithium": re.compile(r"(?:Dilithium|ML-?DSA)[-_]?(\d{2,3})", _F),
    "sphincs+": re.compile(r"(?:SPHINCS\+?|SLH-?DSA)[-_]?(\d{3})", _F),
    "falcon": re.compile(r"FALCON[-_]?(\d{3,4})", _F),
    "hybrid": re.compile(r"(?:Kyber|ML-?KEM)[-_]?(\d{3,4})", _F),
}


def extract_pqc_parameter(line: str, key: str) -> str | None:
    """The NIST parameter set for a PQC ``key`` on ``line`` (or None)."""
    pat = _PQC_PARAM_RE.get(key)
    if pat is None:
        return None
    m = pat.search(line)
    if not m:
        return None
    param = m.group(1)
    return param if param in PQC_PARAM_SETS.get(key, frozenset()) else None


def _merge(into: Detection, other: Detection) -> None:
    """Coalesce two same-key detections on one line — non-empty params win."""
    into.key_size = into.key_size or other.key_size
    into.mode = into.mode or other.mode
    into.curve = into.curve or other.curve
    into.padding = into.padding or other.padding
    into.operation = into.operation or other.operation
    into.parameter = into.parameter or other.parameter
    into.library = into.library or other.library
    into.receiver_bound = into.receiver_bound or other.receiver_bound
    into.variant = into.variant or other.variant
    into.key_spec_only = into.key_spec_only and other.key_spec_only
    into.defined_at = into.defined_at or other.defined_at
    into.inner_of = into.inner_of if into.inner_of == other.inner_of else None
    into.inner_role = into.inner_role if into.inner_role == other.inner_role else None
    into.inferred = into.inferred and other.inferred


# Composites a hash can be a parameter of: a MAC / KDF / mask function, or a signature named with its digest.
_COMPOSITE_KEYS = ("hmac", "pbkdf2", "hkdf", "mgf1", "concat-kdf")
_SIGNATURE_KEYS = ("rsa", "ecdsa", "dsa")
_SIGNATURE_SPEC = re.compile(r"with(?:RSA|ECDSA|DSA|PLAIN-ECDSA|RSAandMGF1)\b|\bPSS\b", re.I)
# RSA-OAEP encryption names its hash too (pyca ``padding.OAEP(algorithm=hashes.SHA1())``, WebCrypto
# ``{name: "RSA-OAEP", hash: "SHA-1"}``, Node ``RSA_PKCS1_OAEP_PADDING`` + ``oaepHash``): a parameter of the
# encryption, not a signature digest.
_OAEP_SPEC = re.compile(r"OAEP", re.I)
# A direct hashing call (``hashlib.sha256(data)``, ``MessageDigest.getInstance("SHA-1")``, ``createHash('md5')``)
# is a hash usage of its own even next to a composite.
_DIRECT_HASH_CALL = re.compile(
    r"\bhashlib\.\w+\s*\(|\bMessageDigest\s*\.\s*getInstance|\bcreateHash\s*\(|\bhashes\.Hash\s*\(", re.I
)


def _mark_inner(per_line: dict[str, Detection], line: str) -> None:
    """A hash on a line that builds a composite (HMAC, PBKDF2, HKDF, MGF1, a ``<digest>with<pk>`` signature, a PSS
    padding, an RSA-OAEP encryption) and that is not hashed directly there is that composite's parameter. The hash
    of an OAEP encryption is marked as such (``inner_role="oaep"``): it is not a digest the RSA key signs."""
    composite = next((k for k in _COMPOSITE_KEYS if k in per_line), None)
    role = None
    if composite is None and _SIGNATURE_SPEC.search(line):
        composite = next((k for k in _SIGNATURE_KEYS if k in per_line), None)
    if composite is None and "rsa" in per_line and _OAEP_SPEC.search(line):
        composite, role = "rsa", "oaep"
    if composite is None or _DIRECT_HASH_CALL.search(line):
        return
    for key, det in per_line.items():
        if key != composite and (algo_info(key) or {}).get("primitive") == "hash":
            det.inner_of = composite
            det.inner_role = role


def _symmetric(key: str) -> bool:
    return (algo_info(key) or {}).get("primitive") in _SYMMETRIC_PRIMITIVES


def _drop_subsumed_key_specs(dets: list[Detection]) -> list[Detection]:
    """``new SecretKeySpec(key, "AES")`` next to ``Cipher.getInstance("AES/CBC/PKCS5Padding")`` is the key of that
    cipher: one AES usage, not a second bare ``AES`` row beside ``AES-CBC``. A key spec stays a row when nothing
    else in the file uses its algorithm.

    A cipher key spec whose algorithm is only inferred (a field default a setter overrides) in a file whose cipher
    the code names (``Cipher.getInstance("AES/GCM/NoPadding")``) is that cipher's key too: a JCA cipher rejects a
    key of another algorithm, so the default is not what runs."""
    used = {d.key for d in dets if not d.key_spec_only}
    named_cipher = any(_symmetric(d.key) and d.receiver_bound and not d.key_spec_only and not d.inferred
                       for d in dets)
    return [d for d in dets if not (d.key_spec_only and (d.key in used or (
        d.inferred and named_cipher and _symmetric(d.key))))]


# A canonical key that encodes its size (``aes-256``), and the bare family key it refines.
_SIZED_KEY = re.compile(r"^([a-z0-9]+)-(\d{2,5})$")


def _merge_sized_into_coarse(per_line: dict[str, Detection]) -> None:
    """One call, one asset: ``createCipheriv('aes-256-gcm')`` hits both the sized lane key (``aes-256``) and the
    bare family key (``aes``, from ``\\bAES-256\\b`` without a size the line extractor can read). The bare
    detection is the SAME usage, so it folds into the sized one instead of becoming a second, coarser
    ``AES-GCM`` row next to ``AES-256-GCM``. A bare detection with a different explicit size stays separate."""
    for sized in [k for k in per_line if _SIZED_KEY.match(k)]:
        m = _SIZED_KEY.match(sized)
        assert m is not None
        coarse = per_line.get(m.group(1))
        if coarse is None or coarse.key_size not in (None, int(m.group(2))):
            continue
        _merge(per_line[sized], coarse)
        del per_line[m.group(1)]


# One alternative per quote character, so a backslash can only be consumed as an escape pair. The shared form
# (?:\\.|(?!\1).)* let a run of backslashes split two ways at every position and backtracked exponentially: one
# configure-script line of backslashes hung the scans of DependencyCheck and keycloak.
_STR_LIT = re.compile(r'"(?:\\.|[^"\\])*"' r"|'(?:\\.|[^'\\])*'" r"|`(?:\\.|[^`\\])*`")
_MAX_STRING_SCAN = 8000  # longer lines are generated or minified; string-level rewriting skips them
_JSX_TEXT = re.compile(r">([^<>{}]*)<")
_WORD = re.compile(r"[A-Za-z]{3,}")


def _is_prose(body: str) -> bool:
    words = body.split()
    return len(words) >= 3 and len(_WORD.findall(body)) >= 2 and not re.search(r"[/=;{}()]", body)


# --------------------------------------------------------------------------- #
# Labels and configuration words (staging QA Q2-02). In Kotlin / Java and JS / TS
# a string literal with whitespace in it is a label, a message or a template
# ("Scrypt Tier (GPU-Proof)", `Scrypt (${mb}MB RAM) + AES-256-GCM AEAD`), never an
# API argument: JCA, Node, WebCrypto and JWT names have no spaces ("AES/GCM/
# NoPadding", 'aes-256-gcm', "RSA-OAEP"). A command line passed to a shell
# ("openssl enc -des3 ...") or a SQL statement keeps its words.
# --------------------------------------------------------------------------- #
_LABEL_LANGS = frozenset({_JAVA, _JS})
_COMMAND_STRING = re.compile(
    r"^\s*(?:openssl|ssh-keygen|keytool|gpg|certutil|select|insert|update|create)\b",
    re.I,
)


def _is_label(body: str) -> bool:
    return bool(re.search(r"\s", body.strip())) and not _COMMAND_STRING.match(body)


# A string shown to the user: the value of a UI text property (Compose ``text =
# "AES-256-GCM"``, DOM
# ``el.textContent = "..."``, ``title: '...'``) or the argument of a UI / log call
# (``Text("...")``,
# ``console.log("...")``). It names an algorithm without using it, also without spaces.
_UI_TEXT_BEFORE = re.compile(
    r"(?:\b(?:text|label|title|subtitle|description|message|contentDescription|placeholder|tooltip|hint|caption"
    r"|textContent|innerText|innerHTML|statusMessage)\s*[:=]\s*"
    r"|\b(?:Text|makeText|alert|println|print|setText|showToast|toast|addAuditLog|updateStatus)\s*\(\s*"
    r"|\b(?:console|Log|log|logger|Timber)\s*\.\s*\w+\s*\(\s*)$")


def blank_labels(line: str, lang: str) -> str:
    """``line`` with label strings (see above) blanked, in the Kotlin / Java and JS / TS
    lanes only."""
    if lang not in _LABEL_LANGS or len(line) > _MAX_STRING_SCAN:
        return line

    def blank(m: re.Match[str]) -> str:
        lit = m.group(0)
        shown = _is_label(lit[1:-1]) or _UI_TEXT_BEFORE.search(line[:m.start()])
        return lit[0] + " " * (len(lit) - 2) + lit[-1] if shown else lit

    return _STR_LIT.sub(blank, line)


# Words that name a password KDF in labels and settings as often as in code. A hit
# counts only where the code
# calls or reaches the API: ``hashlib.scrypt(``, ``Scrypt.scrypt(``,
# ``crypto.scryptSync(``, ``bcrypt.hashpw(``,
# ``argon2.PasswordHasher``, ``SCrypt.generate(``, ``scrypt::scrypt(``, ``new SCrypt``;
# or where the bare name is the
# argument of a hashing call (passlib ``CryptContext(schemes=["bcrypt"])``). A settings
# value (``kdf: "scrypt"``,
# ``put("kdf", "scrypt")``) or a label is not a use of the algorithm.
_API_WORD_KEYS = frozenset({"scrypt", "argon2", "bcrypt"})
_API_AFTER = re.compile(r"^\s*(?:\(|\.|::)")
_API_BEFORE = re.compile(r"(?:\.|::|\bnew\s+)$")
_HASHING_CALLEE = re.compile(
    r"crypt|hash|kdf|derive|password|getInstance|CryptContext", re.I
)


def _blank_strings(line: str) -> str:
    return _STR_LIT.sub(
        lambda m: m.group(0)[0] + " " * (len(m.group(0)) - 2) + m.group(0)[-1], line
    )


def _api_word_hit(pat: re.Pattern[str], line: str) -> bool:
    """Whether ``pat`` (one of the ``_API_WORD_KEYS`` patterns) names the algorithm in
    an API context on ``line``."""
    if len(line) > _MAX_STRING_SCAN:
        return any(_api_word_hit(pat, w) for w in _windows(line))
    code = _blank_strings(line)
    for m in pat.finditer(code):
        if _API_AFTER.match(code[m.end():]) or _API_BEFORE.search(code[:m.start()]):
            return True
    for lit in _STR_LIT.finditer(line):
        body = lit.group(0)[1:-1].strip()
        if not pat.fullmatch(body):
            continue
        callee = re.search(r"([A-Za-z_][\w.]*)\s*\((?:[^()]*)$", line[:lit.start()])
        if callee and _HASHING_CALLEE.search(callee.group(1)):
            return True
    return False


# Sizes a bare number on the line may give (``RSA 2048``): only public-key families,
# whose modulus or parameter
# set is often a separate argument. A symmetric cipher, hash, MAC or KDF never takes its
# size from an unrelated
# integer (``KeyProfile("Key 10", 32, 512, ...)``: 512 MB of memory is no AES-512,
# staging QA Q2-02).
_SIZE_FROM_NAME = {
    "aes": (128, 192, 256),
    "camellia": (128, 192, 256),
    "aria": (128, 192, 256),
}  # valid sizes
_KEYWORD_SIZE = re.compile(
    r"key[_-]?size\s*=\s*(\d{3,5})|\b(?:bits?|length)\s*=\s*(\d{3,5})", re.I
)
_NO_BARE_SIZE = frozenset(
    {
        "aes",
        "camellia",
        "aria",
        "des",
        "3des",
        "rc4",
        "rc2",
        "blowfish",
        "chacha20",
        "chacha20-poly1305",
        "hmac",
        "pbkdf2",
        "scrypt",
        "argon2",
        "bcrypt",
        "hkdf",
        "md5",
        "sha1",
        "sha256",
        "sha384",
        "sha512",
        "sha3_256",
        "blake2b",
        "blake2s",
    }
)


def _literal_key_size(key: str, line: str, explicit: int | None) -> int | None:
    """The key size a literal-lane hit on ``line`` states for ``key``."""
    sized = _SIZED_KEY.match(key)
    if sized:
        return int(sized.group(2))
    allowed = _SIZE_FROM_NAME.get(key)
    if (
        allowed is not None
    ):  # the name's own size ("AES-256") is read where the asset is named, not here
        kw = _KEYWORD_SIZE.search(line)
        size = int(next(g for g in kw.groups() if g)) if kw else None
        return size if size in allowed else None
    if key in _NO_BARE_SIZE:
        kw = _KEYWORD_SIZE.search(line)
        return int(next(g for g in kw.groups() if g)) if kw else None
    return explicit


# --------------------------------------------------------------------------- #
# Configuration literals (PR #500 takeover; review 6061095673). A string literal
# that names an algorithm is judged by its shape:
#
# * a SETTING (a dict / object property, a record or class field default, an
#   argument of the file's own settings record) is never dropped: it is an asset.
#   When a crypto call anywhere in the project reads the setting's name
#   (``Cipher.getInstance(cfg.spec)``, ``hashlib.new(CONFIG['digest'])``) the
#   asset names that call (``config_read_at``); when no read is proven it is kept
#   as a low-confidence asset, so recall never falls below the literal lane's;
# * a MENTION (a label or message, a comparison, argparse ``choices``, a
#   ``case`` / ``when`` label, a TypeScript union member, an Enum member) names
#   an algorithm without passing it anywhere: configuration evidence, not an
#   asset, unless the Enum member / choice is read by a crypto call;
# * anything else (a call argument, a statement constant, an allow- or deny-list)
#   keeps the rules it had.
#
# Crypto calls are recognised by identifier tokens (``createCipheriv`` -> create,
# cipheriv; never a substring: ``assign`` is no ``sign``).
# --------------------------------------------------------------------------- #
_CONFIG_LANGS = frozenset({_PY, _JAVA, _JS})
_CRYPTO_TOKENS = frozenset({
    "crypt", "crypto", "cryptography", "encrypt", "decrypt", "encryptor",
    "decryptor", "cipher", "ciphers", "cipheriv", "decipheriv", "hash", "hashes",
    "hashlib", "hmac", "mac", "digest", "kdf", "derive", "pbkdf2", "pbkdf", "scrypt",
    "argon2", "bcrypt", "sign", "signer", "signature", "verify", "verifier", "jwt",
    "jws", "jwe", "jose", "ssl", "tls", "keygen", "keypair", "keyfactory", "keyspec",
    "secretkey", "secretkeyspec", "keygenerator", "keypairgenerator", "aes", "rsa",
    "ecdsa", "ecdh", "fernet", "subtle", "openssl", "getinstance", "messagedigest",
    "pyjwt", "nacl", "sodium", "importkey", "exportkey", "generatekey", "derivekey",
    "derivebits", "wrapkey", "unwrapkey",
})
_SEGMENT_ONLY = frozenset({"crypto", "cryptography"})
_DECL_LINE = re.compile(
    r"^\s*(?:@\w+\s+)*(?:(?:data|private|public|protected|internal|open|abstract|"
    r"static|final|async|export|override)\s+)*(?:class|fun|def|function|record|enum)\b"
)
_TOKEN_SPLIT = re.compile(r"[A-Z]+(?=[A-Z][a-z0-9])|[A-Z]?[a-z0-9]+|[A-Z]+")


def _is_crypto_callee(chain: str | None) -> bool:
    """Whether a callee chain names a crypto API, by identifier tokens: each dotted /
    underscored segment, its camelCase words and adjacent word pairs."""
    if not chain:
        return False
    for seg in re.split(r"[._\s]+", chain):
        if not seg:
            continue
        low = seg.lower()
        if low in _CRYPTO_TOKENS:
            return True
        words = [w.lower() for w in _TOKEN_SPLIT.findall(seg)]
        # "crypto" names a crypto API only as a whole segment (``crypto.subtle``),
        # not as a word of an app's own type (``CryptoCfg(...)``)
        if any(w in _CRYPTO_TOKENS and w not in _SEGMENT_ONLY for w in words):
            return True
        if any(a + b in _CRYPTO_TOKENS for a, b in zip(words, words[1:], strict=False)):
            return True
    return False


_LIBRARY_CONFIG_KEYS = frozenset({
    "alg", "algorithm", "algorithms", "jwt_algorithm", "signing_algorithm",
    "hash_algorithm", "hashalg", "digestmod", "hashfunc", "ciphers",
    "cipher_suites", "ciphersuites", "ssl_ciphers", "ssl_cipher", "tls_ciphers",
    "password_hashers", "schemes", "transformation", "kex", "kexalgorithms",
    "macs", "hostkeyalgorithms", "signature_algorithm", "sigalgs", "curve",
    "curves", "ecdh_curve",
})
_JS_LIBRARY_CONFIG_KEYS = frozenset({"name", "hash", "namedcurve"})
_DECL_PAREN = re.compile(
    r"(?:\bdef\s+\w+|\bfun\s+[\w.<>]+|\bclass\s+\w+(?:<[^>]*>)?|\bconstructor"
    r"|\bfunction\s*\w*|\binit)\s*$"
)
_BINDING = re.compile(
    r"""(?:["'`]([A-Za-z_][\w.-]*)["'`]|\b([A-Za-z_]\w*))"""
    r"""\s*(?::\s*[\w.<>?\[\], ]+?\s*)?(?:(?<![=!<>])=(?![=>])|:(?!:))\s*$"""
)
_WORD_ID = re.compile(r"[A-Za-z_]\w*")
_READ_CHAIN = re.compile(r"(?<![\w.])[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*")
_VALUE_ATTRS = frozenset({"value", "name"})
_SUBSCRIPT_KEY = re.compile(
    r"""([A-Za-z_]\w*)\s*\[\s*["']([A-Za-z_][\w.-]*)["']\s*\]"""
)
_ASSIGN_LHS = re.compile(
    r"^\s*(?:(?:val|var|const|let|final|private|static|public)\s+)*"
    r"[\w.\[\]\"', ]+?(?::\s*[\w.<>?\[\], ]+?)?\s*(?<![=!<>+*/-])=(?![=>])"
)
_CALL_CHAIN = re.compile(r"[A-Za-z_][\w.]*\s*\(")
_NOT_A_SETTING = re.compile(r"\s*(?:return|yield|throw|raise|assert)\b")
_CASE_LABEL = re.compile(
    r"^\s*case\b"
    r"|^\s*[\"'`][^\"'`]*[\"'`]\s*(?:,\s*[\"'`][^\"'`]*[\"'`]\s*)*->"
)
_TS_TYPE = re.compile(r"^\s*(?:export\s+)?type\s+([A-Za-z_]\w*)(?:<[^>]*>)?\s*=")
_COMPARE_BEFORE = re.compile(r"([A-Za-z_][\w.\[\]'\"]*)?\s*(?:===|!==|==|!=|<>)\s*$")
_COMPARE_AFTER = re.compile(
    r"^\s*(?:(?:===|!==|==|!=)\s*([A-Za-z_][\w.]*)?|\.(?:equals|equalsIgnoreCase|contentEquals)\s*\()"
)
_UNION_BAR = re.compile(r"(?:^|[^|])\|\s*$")
_UNION_AFTER = re.compile(r"^\s*\|(?!\|)")
_Frame = tuple[str, bool, "str | None"]  # bracket, declaration / block, key / callee
_ENUM_BRACE = re.compile(r"\benum\b[^{;]*$")
_ENUM_KEY = "__enum__"
# A record type the file declares (Kotlin ``data class``, Java ``record``, a Python
# ``@dataclass`` / NamedTuple / pydantic model): constructing one fills app settings.
_RECORD_DECL = re.compile(
    r"\b(?:data\s+class|record)\s+([A-Z]\w*)\s*[(<]"
    r"|\bclass\s+([A-Z]\w*)\s*\((?:[\w.]*\.)?(?:NamedTuple|BaseModel|TypedDict"
    r"|BaseSettings)\)"
)
_DATACLASS_DECO = re.compile(r"^\s*@(?:dataclasses\.)?dataclass\b")
_PY_CLASS = re.compile(r"^\s*class\s+([A-Z]\w*)\b")
_CALLEE = re.compile(r"([A-Za-z_][\w.]*)\s*$")
_EXPR_BRACE = re.compile(r"(?:[=:(,\[?]|\breturn|=>)\s*$")
_NOT_CALLEES = frozenset({
    "if", "for", "while", "switch", "catch", "return", "in", "and", "or", "not",
    "await", "yield", "function", "lambda", "elif", "when", "match",
})


def crypto_read_sites(lines: list[str]) -> list[tuple[str, int, str | None]]:
    """``(name, line, qualifier)`` for each name a crypto call reads in a file: the
    call's arguments, a comprehension's source, an attribute or a subscript key, with
    the object it is read from (``Cipher.getInstance(cfg.spec)`` -> ``("spec", n,
    "cfg")``; ``hashlib.new(CONFIG['digest'])`` -> ``("digest", n, "CONFIG")``;
    ``hashlib.new(Hash.WEAK.value)`` -> ``("weak", n, "Hash")``). Names are lower-cased,
    qualifiers keep their case. Not the assigned name (``cipher = Fernet(k)``) nor a
    callee / receiver; a dotted read names its attribute, so ``Cipher.ENCRYPT_MODE``
    reads no setting called "cipher"."""
    sites: list[tuple[str, int, str | None]] = []
    for n, line in enumerate(lines, start=1):
        if "(" not in line or len(line) > _MAX_STRING_SCAN:
            continue
        if _DECL_LINE.match(line):
            line = _after_params(line)  # a declaration's parameter list is no call
        if not any(_is_crypto_callee(c) for c, _a in split_calls(_blank_strings(line))):
            continue
        raw = _ASSIGN_LHS.sub("", line, count=1)
        code = _CALL_CHAIN.sub("(", _ASSIGN_LHS.sub("", _blank_strings(line), count=1))
        for m in _READ_CHAIN.finditer(code):
            parts = [p.strip() for p in m.group(0).split(".")]
            if len(parts) > 1 and parts[-1].lower() in _VALUE_ATTRS:
                parts = parts[:-1]  # ``Hash.WEAK.value`` / ``.name`` read the member
            sites.append((parts[-1].lower(), n, parts[0] if len(parts) > 1 else None))
        for m in _SUBSCRIPT_KEY.finditer(raw):
            sites.append((m.group(2).lower(), n, m.group(1)))
        for lit in _STR_LIT.finditer(raw):
            body = lit.group(0)[1:-1]
            if re.fullmatch(r"[A-Za-z_][\w.-]*", body):
                sites.append((body.lower(), n, None))
    return sites


def crypto_reads(lines: list[str]) -> dict[str, int]:
    """Lower-cased names a crypto call reads in a file -> the first line that reads it
    (:func:`crypto_read_sites`)."""
    reads: dict[str, int] = {}
    for name, line, _q in crypto_read_sites(lines):
        reads.setdefault(name, line)
    return reads


def _after_params(line: str) -> str:
    """A declaration line from just after its parameter list (a one-line body
    ``function h(d) { return crypto.createHash(cfg.digest) }`` keeps its calls)."""
    code = _blank_strings(line)
    start = code.find("(")
    depth = 0
    for i in range(max(start, 0), len(code)):
        if code[i] == "(":
            depth += 1
        elif code[i] == ")":
            depth -= 1
            if depth == 0:
                return " " * (i + 1) + line[i + 1:]
    return ""


def _crypto_refs(lines: list[str]) -> set[str]:
    return set(crypto_reads(lines))


def _innermost_call(stack: list[_Frame]) -> str | None:
    return next((b for ch, decl, b in reversed(stack) if ch == "(" and not decl), None)


_PY_CLASS_LINE = re.compile(r"^class\s+([A-Za-z_]\w*)(\s*\(([^)]*)\))?")
_PY_ENUM_BASE = re.compile(r"\b(?:Enum|IntEnum|StrEnum|Flag|IntFlag)\b")
_PY_FIELD = re.compile(r"^([A-Za-z_]\w*)\s*(?::[^=]*)?(?<![=!<>])=(?!=)")


def _class_fields(
    raw: list[str], stack_at: list[list[_Frame]]
) -> dict[int, tuple[str, bool, str]]:
    """Line index -> (field name, in an Enum, class name), for each
    ``name[: type] = ...`` line directly in a Python class body (not in a method).
    Indentation decides the body."""
    out: dict[int, tuple[str, bool, str]] = {}
    classes: list[list[Any]] = []  # [class indent, body indent, is an Enum, name]
    for idx, line in enumerate(raw):
        text = line.strip()
        if not text or text.startswith(("#", "@")) or stack_at[idx]:
            continue  # blank, comment, decorator, or a bracket continuation
        indent = len(line) - len(line.lstrip())
        while classes and indent <= int(classes[-1][0] or 0):
            classes.pop()
        if classes and classes[-1][1] is None:
            classes[-1][1] = indent
        if classes and indent == classes[-1][1]:
            m = _PY_FIELD.match(text)
            if m:
                out[idx] = (m.group(1).lower(), bool(classes[-1][2]), classes[-1][3])
        cls = _PY_CLASS_LINE.match(text)
        if cls:
            enum = bool(cls.group(3) and _PY_ENUM_BASE.search(cls.group(3)))
            classes.append([indent, None, enum, cls.group(1)])
    return out


def py_class_constants(raw: list[str]) -> dict[str, str]:
    """``NAME -> quoted literal`` of Python class attributes set once to a plain
    string literal (``ALG = "HS256"``), so ``self.ALG`` / ``cls.ALG`` / ``Cls.ALG``
    can be read as that literal."""
    flat = [ln.strip() for ln in raw]
    stack_at: list[list[_Frame]] = []
    depth: list[_Frame] = []
    for line in flat:
        stack_at.append(list(depth))
        if len(line) <= _MAX_STRING_SCAN:
            _ConfigLiterals._walk(line, _blank_strings(line), depth, len(line))
    seen: dict[str, set[str]] = {}
    for idx in _class_fields(raw, stack_at):
        m = _PY_CONST.match(flat[idx])
        if m:
            seen.setdefault(m.group(1), set()).add(m.group(2))
    return {n: next(iter(v)) for n, v in seen.items() if len(v) == 1}


_PY_CONST = re.compile(
    r"""^([A-Za-z_]\w*)\s*(?::[^=]*)?=\s*((["'])[^"'\\]{1,80}\3)\s*$"""
)


# Code carried in a Python string (a JS snippet, a shell line) or pasted with its
# string escapes (``\"cipher\": \"AES-256-GCM\"``, EncDec server.py:379): its
# calls are not Python calls and its names are no use.
_EVIDENCE_NAME = re.compile(
    r"\b(?:AES|3DES|DES|RC4|RC2|Blowfish|ChaCha20|MD5|MD4|SHA-?(?:1|224|256|384|512)"
    r"|SHA3-\d+|HMAC|PBKDF2|scrypt|Argon2|bcrypt|RSA|ECDSA|ECDH|Ed25519|X25519"
    r"|HS256|RS256|ES256)\b",
    re.I,
)
_NESTED_QUOTE = re.compile(r"""^"[^"]*'[^']*'|^'[^']*"[^"]*"|\\["']""")
_CODE_CHARS = re.compile(r"[(){};]|=>")


def _py_embedded_code(body: str) -> bool:
    """Whether a Python string literal's body is code in another language."""
    inner = body[1:-1]
    return bool(_CODE_CHARS.search(inner)) and bool(
        _NESTED_QUOTE.search(body) or re.search(r"""\w\(\s*['"]""", inner)
    )


def py_escaped_span(line: str) -> tuple[int, int] | None:
    """The span of text pasted with its string escapes (``\\"cipher\\": \\"AES\\"``):
    from the first to the last backslash-escaped quote OUTSIDE every string literal.
    A trailing line-continuation backslash is no escape, and an escaped quote inside
    a literal (``b"k=\\"v\\""``) is the literal's own."""
    code = _blank_strings(line).rstrip()
    if code.endswith("\\"):
        code = code[:-1]
    hits = [m.start() for m in re.finditer(r"""\\["']""", code)]
    if not hits:
        return None
    return hits[0], hits[-1] + 2


def _record_types(lines: list[str]) -> set[str]:
    out: set[str] = set()
    deco = False
    for line in lines:
        m = _RECORD_DECL.search(line)
        if m:
            out.add(m.group(1) or m.group(2))
        cls = _PY_CLASS.match(line)
        if cls and deco:
            out.add(cls.group(1))
        deco = bool(_DATACLASS_DECO.match(line)) or (deco and not line.strip())
    return out


def _binding_raw(text: str) -> str | None:
    m = _BINDING.search(text)
    if not m:
        return None
    return (m.group(1) or m.group(2) or "") or None


def _binding_before(text: str) -> str | None:
    raw = _binding_raw(text)
    return raw.lower() if raw else None


_ADD_ARGUMENT = re.compile(
    r"""add_argument\(\s*(?:["']-[\w-]*["']\s*,\s*)?["']--?([\w-]+)["']"""
)
_CHOICES = re.compile(r"\bchoices\s*=\s*[\[(]?\s*$")


def _dest(line: str) -> str | None:
    """The argparse destination of an ``add_argument("--hash-algo", ...)`` line."""
    m = _ADD_ARGUMENT.search(line)
    return m.group(1).replace("-", "_").lower() if m else None


SETTING = "setting"
MENTION = "mention"


class _ConfigLiterals:
    """How each string literal of a file is judged (above)."""

    def __init__(
        self,
        lines: list[str],
        lang: str,
        raw: list[str] | None = None,
        project_reads: Any = None,
    ) -> None:
        self.lang = lang
        self.sites = crypto_read_sites(lines)
        self.reads: dict[str, int] = {}
        for name, n, _q in self.sites:
            self.reads.setdefault(name, n)
        # a ``prove(binding, owners) -> "path:line" | None`` of the other files of the
        # project (algorithm_scan), or a plain name -> location map (unit tests)
        self.project_reads = project_reads or {}
        js_keys = _JS_LIBRARY_CONFIG_KEYS if lang == _JS else frozenset()
        self.keys = _LIBRARY_CONFIG_KEYS | js_keys
        self.records = _record_types(lines)
        # the bracket stack at the start of each line
        self.stack_at: list[list[_Frame]] = []
        stack: list[_Frame] = []
        for line in lines:
            self.stack_at.append(list(stack))
            if len(line) <= _MAX_STRING_SCAN:
                self._walk(line, _blank_strings(line), stack, len(line))
        self.class_fields = (
            _class_fields(raw, self.stack_at) if lang == _PY and raw else {}
        )

    def read_at(
        self,
        binding: str | None,
        owners: Sequence[str] = (),
        *,
        qualified: bool = False,
    ) -> str | None:
        """Where a crypto call reads ``binding``: ``"<line>"`` in this file, else
        ``"<path>:<line>"`` in another file LINKED to this one (it imports it, or
        names one of ``owners``: the dict / object / class the setting belongs to),
        else None. ``qualified``: in this file too, only a read through one of
        ``owners`` (``settings.cipher`` for ``Object.assign(settings, {...})``)."""
        if not binding:
            return None
        for name, n, qualifier in self.sites:
            via_owner = bool(qualifier and qualifier in owners)
            if name == binding and (not qualified or via_owner):
                return str(n)
        if callable(self.project_reads):
            found = self.project_reads(binding, tuple(owners))
            return str(found) if found else None
        return self.project_reads.get(binding)

    def _flows(self, binding: str | None, owners: Sequence[str] = ()) -> bool:
        if not binding:
            return False
        return binding in self.keys or self.read_at(binding, owners) is not None

    @staticmethod
    def _walk(raw: str, code: str, stack: list[_Frame], upto: int) -> None:
        for i, ch in enumerate(code[:upto]):
            if ch in "([{":
                decl = ch == "(" and bool(_DECL_PAREN.search(code[:i]))
                if ch == "(":
                    callee = _CALLEE.search(code[:i])
                    # the whole callee chain (``crypto.subtle.importKey``): its last
                    # segment names the method, the rest the API it belongs to
                    key = callee.group(1) if callee else None
                    last = key.rsplit(".", 1)[-1] if key else None
                    # a grouping paren (``(function () { ... })()``, ``x = (a, b)``)
                    # passes nothing to a call
                    decl = decl or last is None or last in _NOT_CALLEES
                elif ch == "{" and _ENUM_BRACE.search(code[:i]):
                    key, decl = _ENUM_KEY, True  # an enum body
                else:
                    key = _binding_raw(raw[:i])
                    # a brace after ``)`` / a name / ``else`` / ``->`` opens a block
                    # (a method, class or lambda body), not an object literal: the
                    # bindings in it are statements
                    decl = ch == "{" and not _EXPR_BRACE.search(code[:i])
                stack.append((ch, decl, key))
            elif ch in ")]}" and stack:
                stack.pop()

    def _record_setting(self, stack: list[_Frame]) -> bool:
        """Whether the innermost call is the constructor of a record type this file
        declares (not a crypto API)."""
        callee = _innermost_call(stack)
        last = callee.rsplit(".", 1)[-1] if callee else None
        return bool(last and last in self.records and not _is_crypto_callee(callee))

    def judge(self, line_idx: int, line: str) -> list[Judged]:
        """``(start, end, binding, SETTING | MENTION, owners)`` for the literals of
        ``line`` that are settings or mentions (see above); other literals are not
        listed. ``owners`` are the symbols the setting belongs to (the dict, object,
        record or class), for the linked-read rule of :meth:`read_at`."""
        if (
            self.lang not in _CONFIG_LANGS
            or len(line) > _MAX_STRING_SCAN
            or not any(q in line for q in "\"'`")
        ):
            return []
        statement = bool(_NOT_A_SETTING.match(line))
        case_label = bool(_CASE_LABEL.match(line))
        ts_type = _TS_TYPE.match(line) if self.lang == _JS else None
        code = _blank_strings(line)
        out: list[Judged] = []
        field = self.class_fields.get(line_idx)
        for lit in _STR_LIT.finditer(line):
            span = (lit.start(), lit.end())
            stack = list(self.stack_at[line_idx])
            self._walk(line, code, stack, lit.start())
            callee = _innermost_call(stack)
            in_crypto_call = any(
                _is_crypto_callee(b) for ch, d, b in stack if ch == "(" and not d
            )
            owners = tuple(b for _c, _d, b in stack if b and b != _ENUM_KEY)
            before, after = code[:lit.start()], code[lit.end():]
            if field is not None:
                name, enum, cls = field
                if in_crypto_call:
                    continue
                if enum:  # an Enum member: a mention, unless a crypto call reads it
                    if not self._flows(name, (cls,)):
                        out.append((*span, name, MENTION, (cls,)))
                    continue
                out.append((*span, name, SETTING, (cls,)))
                continue
            if in_crypto_call:
                continue  # inside a crypto call's arguments: it flows into the call
            if self.lang == _PY and _is_label(lit.group(0)[1:-1]):
                # a label or message (whitespace in it): ``{"backend": "AES-256 ..."}``
                outer = next((b for _c, _d, b in reversed(stack) if b), None)
                out.append((*span, (outer or "label").lower(), MENTION, owners))
                continue
            cmp_before = _COMPARE_BEFORE.search(before)
            cmp_after = _COMPARE_AFTER.match(after)
            if cmp_before or cmp_after:
                other = (cmp_before and cmp_before.group(1)) or (
                    cmp_after and cmp_after.group(1)
                )
                out.append((*span, (other or "comparison").lower(), MENTION, owners))
                continue
            if _membership(code, lit.start(), lit.end(), stack):
                # an inline allow / deny check: ``['md5', 'sha1'].includes(alg)``,
                # ``alg in ('md5', 'sha1')``, ``List.of("MD5").contains(alg)``
                out.append((*span, "membership", MENTION, owners))
                continue
            if case_label and re.match(r"^\s*case\b[^:]*$", before):
                out.append((*span, "case", MENTION, owners))
                continue
            if case_label and "->" in after:
                out.append((*span, "when", MENTION, owners))
                continue
            if ts_type or (
                self.lang == _JS
                and (_UNION_BAR.search(before) or _UNION_AFTER.match(after))
            ):
                name = ts_type.group(1).lower() if ts_type else "type"
                out.append((*span, name, MENTION, owners))
                continue
            enum_frame = any(b == _ENUM_KEY for _c, _d, b in stack)
            callee = callee.rsplit(".", 1)[-1] if callee else None
            if enum_frame and callee and callee[:1].isupper():
                # an enum constant's argument (``DES("DES/ECB")``)
                if not self._flows(callee.lower(), owners):
                    out.append((*span, callee.lower(), MENTION, owners))
                continue
            container = next(
                (b for c, _d, b in reversed(stack) if c in "[{(" and b), None
            )
            if (container or "").lower() == "choices" or _CHOICES.search(before):
                dest = _dest(line) or "choices"
                if not self._flows(dest, owners):
                    out.append((*span, dest, MENTION, owners))
                continue
            if not stack or statement:
                continue  # a statement, not a setting inside a container
            calls = [b for ch, decl, b in stack if ch == "(" and not decl]
            direct = stack[-1][0] == "(" and not stack[-1][1]
            if direct and self._record_setting(stack):
                # an argument of the file's own settings record (``KeyProfile(...,
                # "AES-256-GCM", ...)``)
                record = (calls[-1] or "").rsplit(".", 1)[-1]
                out.append((*span, record.lower(), SETTING, (record,)))
                continue
            if direct:
                continue  # a direct argument of a call: the call may use it
            cut = max(before.rfind(c) for c in "([{,") + 1 if before else 0
            own = _binding_before(line[cut:lit.start()])
            top = stack[-1]
            scalar = own is not None and (
                (top[0] == "{" and not top[1]) or (top[0] == "(" and top[1])
            )
            if not scalar or own is None:
                continue
            if calls and not self._record_setting(stack):
                # an object handed to a call that is no crypto API
                # (``Object.assign(settings, { cipher: ... })``): a setting only when
                # a crypto call reads it through the call's target
                target = _call_target(line, calls[-1])
                if target and self.read_at(own, (target,), qualified=True):
                    out.append((*span, own, SETTING, (target,)))
                else:
                    out.append((*span, own, MENTION, owners))
                continue
            out.append((*span, own, SETTING, owners))
        return out


Judged = tuple[int, int, str, str, tuple[str, ...]]
_MEMBER_AFTER = re.compile(
    r"^\s*\.\s*(?:includes|indexOf|contains|containsKey|has|count)\s*\("
)
_IN_BEFORE = re.compile(r"\b(?:not\s+)?in\s*$")
_LIST_FACTORY = re.compile(
    r"\b(?:List|Set|Arrays|ImmutableSet|ImmutableList)\s*\.\s*(?:of|asList|copyOf)\s*$"
)


def _membership(code: str, start: int, end: int, stack: list[_Frame]) -> bool:
    """Whether the literal sits in an inline container that is only tested for
    membership: followed by ``.includes(`` / ``.contains(`` / ``.has(`` (also as
    ``List.of(...)`` / ``Set.of(...)`` / ``Arrays.asList(...)``), or preceded by
    ``in`` / ``not in``."""
    if not stack:
        return False
    depth, close = 0, None
    for i in range(end, len(code)):
        ch = code[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                close = i
                break
            depth -= 1
    if close is None:
        return False
    depth, opened = 0, None
    for i in range(start - 1, -1, -1):
        ch = code[i]
        if ch in ")]}":
            depth += 1
        elif ch in "([{":
            if depth == 0:
                opened = i
                break
            depth -= 1
    if opened is None:
        return False
    head = code[:opened]
    # a paren is a container only as ``List.of(`` / ``Set.of(`` / ``Arrays.asList(``
    # or a tuple after ``in``
    factory = _LIST_FACTORY.search(head) or _IN_BEFORE.search(head)
    if code[opened] == "(" and not factory:
        return False
    return bool(_MEMBER_AFTER.match(code[close + 1:]) or _IN_BEFORE.search(head))


def _call_target(line: str, callee: str | None) -> str | None:
    """The first argument of ``callee(`` on ``line`` when it is a plain name."""
    if not callee:
        return None
    m = re.search(rf"\b{re.escape(callee)}\s*\(\s*([A-Za-z_][\w.]*)\s*,", line)
    return m.group(1).rsplit(".", 1)[-1] if m else None


def blank_prose(line: str, lang: str) -> str:
    """``line`` with prose-like string literals (and JSX text in JS/TS) replaced by spaces of the same length."""
    def blank(m: re.Match) -> str:
        lit = m.group(0)
        return lit[0] + " " * (len(lit) - 2) + lit[-1] if _is_prose(lit[1:-1]) else lit

    if len(line) > _MAX_STRING_SCAN:
        return "".join(blank_prose(w, lang) for w in _windows(line))
    out = _STR_LIT.sub(blank, line)
    if lang == "javascript" and "<" in out:
        out = _JSX_TEXT.sub(lambda m: ">" + " " * len(m.group(1)) + "<" if _is_prose(m.group(1)) else m.group(0), out)
    return out


# --------------------------------------------------------------------------- #
# Java JCA/JCE argument lane. The literal lane only sees an algorithm when its
# spelling is distinctive on the line; JCA hides it in an ARGUMENT: a same-file
# ``static final String`` constant (``Cipher.getInstance(SYM_CIPHER)``), a bare
# ambiguous token inside an API call (``new SecretKeySpec(k, "AES")``,
# ``KeyFactory.getInstance("EdDSA")``), or a literal passed through a one-line
# helper (``keyFactory("RSA")`` -> ``KeyFactory.getInstance(alg)``). This lane
# resolves those arguments against the JCA standard-name table, and also splits
# the composite standard names (``SHA256withDSA`` -> DSA + SHA-256,
# ``HmacSHA256`` -> HMAC-SHA256, ``PBKDF2WithHmacSHA512`` -> PBKDF2-HMAC-SHA512).
# API-bound only: a bare "AES" outside these calls is never a detection.
# --------------------------------------------------------------------------- #
_JCA_LIB = "JCA/JCE (Java)"
_JCA_CLASSES = (
    "Cipher", "MessageDigest", "Signature", "Mac", "KeyGenerator",
    "KeyPairGenerator", "SecretKeyFactory", "KeyFactory", "KeyAgreement",
)
# A file only gets the API-bound lane when it imports (or fully qualifies) the JCA.
_JCA_FILE = re.compile(r"\b(?:javax\.crypto|java\.security)\b")
# An argument: a string literal, or a (this.|Class.)identifier followed by , or ).
_JAVA_ARG = (
    r'(?:"(?P<lit>[^"\\\s]{1,80})"'
    r"|(?P<ident>(?:this\.)?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)(?=\s*[,)]))"
)
_JCA_CALL = re.compile(
    r"\b(?P<cls>" + "|".join(_JCA_CLASSES) + r")\s*\.\s*getInstance\s*\(\s*" + _JAVA_ARG
)
_SECRET_KEY_SPEC = re.compile(r"\bnew\s+SecretKeySpec\s*\(")
# Same-file string constants: Java ``[modifiers] String NAME = "value";`` and Kotlin
# ``[const] val NAME[: String] = "value"``. The value must look like a standard
# name (no spaces) — never prose.
_JAVA_STR_DECL = re.compile(r'\bString\s+([A-Za-z_]\w*)\s*=\s*"([^"\\\s]{1,80})"\s*[;,)]')
_KT_STR_DECL = re.compile(r'\bval\s+([A-Za-z_]\w*)\s*(?::\s*String\s*)?=\s*"([^"\\\s$]{1,80})"')
# ``String alias = OTHER_CONSTANT;`` (one hop).
_JAVA_ALIAS_DECL = re.compile(r"\bString\s+([A-Za-z_]\w*)\s*=\s*([A-Za-z_][\w.]*)\s*;")
# Every declaration / parameter / write of a name (single-assignment check).
_ANY_STR_DECL = re.compile(r"\b(?:String|val|var)\s+([A-Za-z_]\w*)\b")
_KT_TYPED_PARAM = re.compile(r"(?<!val )(?<!var )\b([A-Za-z_]\w*)\s*:\s*String\b")
_ANY_ASSIGN = re.compile(r"(?<!\w)([A-Za-z_]\w*)\s*\+?=(?!=)")
_JAVA_CLASS_DECL = re.compile(r"\b(?:class|interface|enum|object)\s+([A-Z]\w*)")
# A helper whose single String parameter feeds a JCA getInstance in its body.
_JAVA_HELPER_DECL = re.compile(
    r"\b([a-z_]\w*)\s*\(\s*(?:final\s+)?String\s+([A-Za-z_]\w*)\s*\)\s*"
    r"(?:throws\s+[\w.,\s]+)?\{"
)
_HELPER_BODY_LINES = 30

# Standard-name pieces.
_HMAC_NAME = re.compile(r"^Hmac(?P<d>.+)$", re.I)
_PBKDF2_NAME = re.compile(r"^PBKDF2WithHmac(?P<d>.+)$", re.I)
_SIG_NAME = re.compile(
    r"^(?P<d>[A-Za-z0-9-]+?)with(?P<pk>[A-Za-z0-9-]+?)(?P<mgf>andMGF1)?"
    r"(?:in\w+Format)?(?:/PSS)?$", re.I)
_HASH_LABEL = re.compile(r"^(?:SHA(?:1|224|256|384|512)(?:/(?:224|256))?|SHA3-(?:224|256|384|512)|MD5)$", re.I)
_AES_SIZED = re.compile(r"^AES_(128|192|256)$", re.I)
_AES_WRAP = re.compile(r"^AESWrap(?P<pad>Pad)?(?:_(?P<size>128|192|256))?$", re.I)
# JCA standard names the shared alias table does not carry.
_JCA_EXTRA_KEYS = {
    "arcfour": "rc4", "eddsa": "eddsa", "elgamal": "elgamal", "ec": "ecdsa",
    "dh": "dh", "rsassapss": "rsa",
}
_SYMMETRIC_PRIMITIVES = ("block-cipher", "stream-cipher", "ae")


def _jca_key(token: str) -> str | None:
    """Canonical key for a JCA standard-name token (``DESede`` -> 3des)."""
    flat = re.sub(r"[\s\-_]", "", token).lower()
    key = _JCA_EXTRA_KEYS.get(flat) or LITERAL_ALGO_ALIASES.get(flat)
    return key if key and algo_info(key) else None


def _hash_key(token: str) -> str | None:
    if token.upper() == "SHA":  # JCA alias of SHA-1
        return "sha1"
    key = _jca_key(token)
    return key if key and (algo_info(key) or {}).get("primitive") == "hash" else None


def _hmac_variant(digest: str) -> str | None:
    return digest.upper() if _HASH_LABEL.match(digest) else None


def _signature_assets(spec: str) -> list[tuple[str, str | None, str | None, int | None]]:
    """``SHA256withRSA`` -> RSA + SHA-256 (+ MGF1 for ``...andMGF1``)."""
    m = _SIG_NAME.match(spec)
    if not m:
        return []
    pk = m.group("pk").upper()
    pk_key: str | None
    if "ECDSA" in pk:
        pk_key = "ecdsa"
    elif pk in ("RSA", "RSASSA-PSS", "RSAENCRYPTION"):  # sha256WithRSAEncryption (X.509)
        pk_key = "rsa"
    else:
        pk_key = _jca_key(pk)
    if pk_key is None:
        return []
    out: list[tuple[str, str | None, str | None, int | None]] = [(pk_key, None, None, None)]
    digest = _hash_key(m.group("d"))
    if digest:
        out.append((digest, None, None, None))
    if m.group("mgf"):
        out.append(("mgf1", None, None, None))
    return out


def jca_assets(cls: str, spec: str) -> list[tuple[str, str | None, str | None, int | None]]:
    """``(key, variant, mode, key_size)`` for a JCA ``<cls>.getInstance(spec)``.

    ``cls`` is the JCA engine class (``Cipher``, ``Mac`` ...) or ``SecretKeySpec``
    for a key spec's algorithm argument. Unknown names resolve to nothing.
    """
    spec = spec.strip()
    if not spec:
        return []
    if cls == "Signature":
        assets = _signature_assets(spec)
        if assets:
            return assets
        key = _jca_key(spec)
        return [(key, None, None, None)] if key else []
    hm = _HMAC_NAME.match(spec)
    if cls in ("Mac", "KeyGenerator", "SecretKeySpec") and hm:
        return [("hmac", _hmac_variant(hm.group("d")), None, None)]
    pm = _PBKDF2_NAME.match(spec)
    if cls in ("SecretKeyFactory", "SecretKeySpec") and pm:
        digest = _hmac_variant(pm.group("d"))
        return [("pbkdf2", f"HMAC-{digest}" if digest else None, None, None)]
    if cls == "MessageDigest":
        key = _hash_key(spec)
        return [(key, None, None, None)] if key else []
    if cls == "Mac":
        up = spec.upper()
        if up.endswith("CMAC"):
            return [("cmac", None, None, None)]
        key = _jca_key(spec)
        return [(key, None, None, None)] if key in ("poly1305", "hmac") else []
    # Cipher / KeyGenerator / KeyPairGenerator / KeyFactory / KeyAgreement /
    # SecretKeyFactory / SecretKeySpec: a transformation or a bare algorithm name.
    parts = [p.strip() for p in spec.split("/")]
    algo = parts[0]
    sized = _AES_SIZED.match(algo)
    wrap = _AES_WRAP.match(algo)
    variant: str | None = None
    size: int | None = None
    if sized:
        key, size = "aes", int(sized.group(1))
    elif wrap:
        key = "aes"
        variant = "KWP" if wrap.group("pad") else "KW"
        size = int(wrap.group("size")) if wrap.group("size") else None
    else:
        key = _jca_key(algo)
    if key is None or (cls == "SecretKeySpec" and key in ("rsa", "dsa", "ecdsa", "dh")):
        return []
    mode = None
    if cls == "Cipher" and len(parts) >= 2 and variant is None:
        cand = parts[1].upper()
        if cand in ("GCM", "CBC", "ECB", "CTR", "CFB", "OFB", "XTS", "CCM") and \
                (algo_info(key) or {}).get("primitive") in _SYMMETRIC_PRIMITIVES:
            mode = cand
    out = [(key, variant, mode, size)]
    if cls == "Cipher" and len(parts) >= 3 and "MGF1" in parts[2].upper():
        out.append(("mgf1", None, None, None))
    return out


class _JavaContext:
    """Per-file facts the JCA argument lane resolves against."""

    __slots__ = ("jca", "consts", "classes", "helpers", "gen_sizes", "external", "code", "defaults")

    def __init__(self, lines: list[str], external: Mapping[str, Any] | None = None) -> None:
        code = "\n".join(lines)  # comments already stripped
        self.code = code
        self.jca = bool(_JCA_FILE.search(code))
        self.classes = set(_JAVA_CLASS_DECL.findall(code))
        self.consts = _string_constants(code)
        # fields with a default a setter may override (``String alg = "AES"`` + ``this.alg = alg``): inferred
        self.defaults = _field_defaults(code, self.consts) if self.jca else {}
        # constants of other project files this file names (``Algs.CIPHER``, a static import): name -> Definition
        self.external: Mapping[str, Any] = external or {}
        self.helpers = _jca_helpers(lines) if self.jca else {}
        self.gen_sizes = _generator_sizes(lines) if self.jca else {}


# ``KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");`` ... ``kpg.initialize(2048);`` — the key size
# is set on the generator variable in a later statement. Bound forward from the getInstance line to the first
# ``<var>.initialize(<int>)`` / ``<var>.init(<int>)``, stopping when the variable is reassigned.
_JCA_GEN_DECL = re.compile(
    r"\b([A-Za-z_]\w*)\s*=\s*(?:[\w.]+\.)?(?:KeyPairGenerator|KeyGenerator)\s*\.\s*getInstance\s*\("
)
_GEN_SIZE_WINDOW = 40


def _generator_sizes(lines: list[str]) -> dict[int, int]:
    """getInstance line number (1-based) -> the key size its generator variable is initialised with."""
    out: dict[int, int] = {}
    for i, line in enumerate(lines):
        for decl in _JCA_GEN_DECL.finditer(line):
            var = re.escape(decl.group(1))
            init = re.compile(rf"(?<![\w.]){var}\s*\.\s*(?:initialize|init)\s*\(\s*(\d{{2,5}})\b")
            reassigned = re.compile(rf"(?<![\w.]){var}\s*=(?!=)")
            for j in range(i, min(len(lines), i + _GEN_SIZE_WINDOW)):
                seg = lines[j][decl.end():] if j == i else lines[j]
                m = init.search(seg)
                if m:
                    out.setdefault(i + 1, int(m.group(1)))
                    break
                if j > i and reassigned.search(seg):
                    break
    return out


def _string_constants(code: str) -> dict[str, str]:
    """Single-assignment same-file String constants (``NAME -> value``).

    A name declared more than once (a parameter or local of the same name, two
    inner classes) or assigned anywhere else (a setter) is dropped: its value at
    the call site is not provable from the file.
    """
    values: dict[str, set[str]] = {}
    for m in (*_JAVA_STR_DECL.finditer(code), *_KT_STR_DECL.finditer(code)):
        values.setdefault(m.group(1), set()).add(m.group(2))
    if not values:
        return _spring_defaults(code, {})
    aliases = {m.group(1): m.group(2) for m in _JAVA_ALIAS_DECL.finditer(code)}
    # One pass each (not one regex per name): declarations of a String / val / var
    # named X (incl. parameters ``String X`` / Kotlin ``X: String``) and writes ``X =``.
    decls = Counter(m.group(1) for m in _ANY_STR_DECL.finditer(code))
    decls.update(m.group(1) for m in _KT_TYPED_PARAM.finditer(code))
    assigns = Counter(m.group(1) for m in _ANY_ASSIGN.finditer(code))

    def single(name: str) -> bool:
        return decls[name] == 1 and assigns[name] == 1

    out = {n: next(iter(v)) for n, v in values.items() if len(v) == 1 and single(n)}
    for name, target in aliases.items():
        target = target.rsplit(".", 1)[-1]
        if name not in out and target in out and single(name):
            out[name] = out[target]
    return _spring_defaults(code, out)


def _spring_defaults(code: str, out: dict[str, str]) -> dict[str, str]:
    """Spring ``@Value("${crypto.alg:DES/ECB/PKCS5Padding}") private String alg;``:
    the property's default is the field's value unless the deployment overrides it
    (review 6061095673); a field written anywhere in the file is not provable."""
    for m in _SPRING_VALUE_DEFAULT.finditer(code):
        default, name = m.group(1).strip(), m.group(2) or m.group(3)
        written = re.search(rf"(?<![\w.]){re.escape(name)}\s*=(?!=)", code)
        if default and name not in out and not written:
            out[name] = default
    return out


_SPRING_VALUE_DEFAULT = re.compile(
    r'@Value\(\s*"\\?\$\{[^:}"]+:([^}"]{1,80})\}"\s*\)\s*'
    r"(?:(?:private|protected|public|final|static|lateinit|internal)\s+)*"
    r"(?:String\s+([A-Za-z_]\w*)\s*;|(?:var|val)\s+([A-Za-z_]\w*)\s*:\s*String)"
)


_JAVA_FIELD_DEFAULT = re.compile(
    r'\b(?:private|protected|public)\s+String\s+([A-Za-z_]\w*)\s*=\s*"([^"\\\s]{1,80})"\s*;'
)


def _field_defaults(code: str, consts: dict[str, str]) -> dict[str, str]:
    """String fields with a literal default that are otherwise only set by a setter (``this.f = f;``, the value
    a caller passes): the default is the algorithm unless something configures another one."""
    out: dict[str, str] = {}
    for m in _JAVA_FIELD_DEFAULT.finditer(code):
        name, value = m.group(1), m.group(2)
        if name in consts or name in out:
            continue
        if len(re.findall(rf"\bString\s+{re.escape(name)}\s*=", code)) != 1:
            continue  # declared with a value twice (two classes): not provable
        writes = [w.strip() for w in re.findall(rf"(?<![\w.])(?:this\.)?{re.escape(name)}\s*=(?!=)\s*([^;]*);", code)]
        others = [w for w in writes if w != f'"{value}"']
        if len(writes) - len(others) == 1 and all(re.fullmatch(r"[A-Za-z_]\w*", w) for w in others):
            out[name] = value
    return out


def _jca_helpers(lines: list[str]) -> dict[str, tuple[str, int]]:
    """Same-file helpers ``name(String p) { ... X.getInstance(p) ... }`` -> (X, decl line)."""
    out: dict[str, tuple[str, int]] = {}
    for i, line in enumerate(lines):
        m = _JAVA_HELPER_DECL.search(line)
        if not m or m.group(1) in ("if", "for", "while", "switch", "catch", "synchronized"):
            continue
        name, param = m.group(1), m.group(2)
        depth = 0
        for j in range(i, min(len(lines), i + _HELPER_BODY_LINES)):
            seg = lines[j][m.end() - 1:] if j == i else lines[j]
            for call in _JCA_CALL.finditer(seg):
                if call.group("ident") == param:
                    out.setdefault(name, (call.group("cls"), i + 1))
            depth += seg.count("{") - seg.count("}")
            if depth <= 0:
                break  # end of the helper body
    return out


def _call_args(line: str, open_idx: int) -> list[str]:
    """Top-level comma-split arguments of the call whose ``(`` is at ``open_idx``."""
    depth = 0
    cur: list[str] = []
    args: list[str] = []
    in_str = False
    for ch in line[open_idx:]:
        if ch == '"' and (not cur or cur[-1] != "\\"):
            in_str = not in_str
        if not in_str:
            if ch == "(":
                depth += 1
                if depth == 1:
                    continue
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    args.append("".join(cur).strip())
                    return args
            elif ch == "," and depth == 1:
                args.append("".join(cur).strip())
                cur = []
                continue
        cur.append(ch)
    return []  # call continues on the next line: not resolvable here


def _resolve_java_arg(lit: str | None, ident: str | None, ctx: _JavaContext) -> str | None:
    return _resolve_java_arg_where(lit, ident, ctx)[0]


def _inferred_arg(cls: str, ident: str | None, ctx: _JavaContext) -> tuple[str, str | None] | None:
    """(value, ``path:line`` or None) for an argument no constant resolves, inferred: for a key specification
    (``new SecretKeySpec(k, encryptionAlgorithm)``) a field's default that only a setter overrides, and for
    ``Cipher.getInstance(<String parameter>)`` the module's one configured cipher transformation (the value comes
    from the caller, typically configuration). An engine call on a settable field stays unresolved."""
    if not ident:
        return None
    name = ident[5:] if ident.startswith("this.") else ident
    if cls == "SecretKeySpec" and name in ctx.defaults:
        return ctx.defaults[name], None
    guess = ctx.external.get("@config:Cipher")
    if cls != "Cipher" or guess is None or "." in name or name in ctx.consts:
        return None
    if re.search(rf"[(,]\s*(?:final\s+)?String\s+{re.escape(name)}\s*[,)]", ctx.code):
        return guess.value, guess.where
    return None


def _resolve_java_arg_where(
    lit: str | None, ident: str | None, ctx: _JavaContext
) -> tuple[str | None, str | None]:
    """The argument's value, and ``path:line`` when it is a constant of another project file."""
    if lit is not None:
        return lit, None
    if not ident:
        return None, None
    name = ident[5:] if ident.startswith("this.") else ident
    if "." in name:
        qualifier, short = name.rsplit(".", 1)
        if qualifier not in ctx.classes:
            ext = ctx.external.get(name)
            return (ext.value, ext.where) if ext is not None else (None, None)
        name = short
    if name in ctx.consts:
        return ctx.consts[name], None
    ext = ctx.external.get(name)  # ``import static ...Algs.CIPHER``
    return (ext.value, ext.where) if ext is not None else (None, None)


# Bouncy Castle ``new HMac(new SHA256Digest())``: the nested digest is the HMAC hash.
_BC_HMAC = re.compile(r"\bnew\s+HMac\s*\(\s*new\s+(SHA(?:1|224|256|384|512)|MD5)Digest\s*\(")
# Keys whose variant is a parameter of one construction (the HMAC / PRF hash).
_FOLDABLE_VARIANT_KEYS = ("hmac", "pbkdf2")


def _fold_variants(dets: list[Detection]) -> None:
    """A file that names exactly ONE variant of a construction (only HmacSHA256) is
    using that variant; its other, unqualified mentions of the construction (an
    ``HMAC`` identifier, an ``"hmac"`` id string) take the variant instead of
    becoming a second, coarser ``HMAC`` row next to ``HMAC-SHA256``. A file with
    several variants keeps its unqualified mentions as they are (ambiguous)."""
    for key in _FOLDABLE_VARIANT_KEYS:
        variants = {d.variant for d in dets if d.key == key and d.variant}
        if len(variants) != 1:
            continue
        variant = next(iter(variants))
        for d in dets:
            if d.key == key and not d.variant:
                d.variant = variant


_ARG_TOKEN = re.compile(r'^(?:"(?P<lit>[^"\\\s]{1,80})"|(?P<ident>(?:this\.)?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?))$')
# Self-describing JCA composite names: "<digest>with<pk>", "Hmac<digest>",
# "PBKDF2WithHmac<digest>" (the digest prefix keeps "doSomethingWithRSA" out).
_COMPOSITE_LIT = re.compile(
    r'"((?:SHA|MD[245]|NONE|RIPEMD)[A-Za-z0-9-]*?with[A-Za-z0-9-]+'
    r'|Hmac(?:SHA|MD5)[A-Za-z0-9-]*|PBKDF2WithHmac(?:SHA|MD5)[A-Za-z0-9-]*)"', re.I)


_GENERATOR_SIZED_PRIMITIVES = ("pke", "block-cipher", "stream-cipher", "signature", "key-agree")


def _java_jca_lane(line: str, line_no: int, ctx: _JavaContext) -> list[Detection]:
    found: list[tuple[str, str | None, str | None, int | None]] = []
    key_specs: list[tuple[str, str | None, str | None, int | None]] = []
    paddings: dict[str, str] = {}
    where: dict[str, str] = {}  # key -> the other file that spells its algorithm name
    inferred: set[str] = set()
    if ctx.jca:
        for m in _JCA_CALL.finditer(line):
            spec, defined = _resolve_java_arg_where(m.group("lit"), m.group("ident"), ctx)
            guess = None if spec else _inferred_arg(m.group("cls"), m.group("ident"), ctx)
            if guess is not None:
                spec, defined = guess
            if not spec:
                continue
            assets = jca_assets(m.group("cls"), spec)
            for asset in assets:
                if defined:
                    where.setdefault(asset[0], defined)
                if guess is not None:
                    inferred.add(asset[0])
            gen_size = ctx.gen_sizes.get(line_no)
            if gen_size and m.group("cls") in ("KeyPairGenerator", "KeyGenerator"):
                assets = [
                    (k, v, md, sz or (gen_size if (algo_info(k) or {}).get("primitive")
                                      in _GENERATOR_SIZED_PRIMITIVES else None))
                    for k, v, md, sz in assets
                ]
            parts = spec.split("/")
            if m.group("cls") == "Cipher" and assets and len(parts) >= 3 and parts[2].strip():
                # the transformation's padding ("AES/GCM/NoPadding", "RSA/ECB/OAEPWith...Padding"), verbatim
                paddings.setdefault(assets[0][0], parts[2].strip())
            found.extend(assets)
        for m in _SECRET_KEY_SPEC.finditer(line):
            args = _call_args(line, m.end() - 1)
            if len(args) >= 2:
                am = _ARG_TOKEN.match(args[-1])
                spec, defined = _resolve_java_arg_where(am.group("lit"), am.group("ident"), ctx) if am \
                    else (None, None)
                guess = None if spec or not am else _inferred_arg("SecretKeySpec", am.group("ident"), ctx)
                if guess is not None:
                    spec, defined = guess
                if spec:
                    specs = jca_assets("SecretKeySpec", spec)
                    key_specs.extend(specs)
                    for asset in specs:
                        if defined:
                            where.setdefault(asset[0], defined)
                        if guess is not None:
                            inferred.add(asset[0])
        for helper, (cls, decl_line) in ctx.helpers.items():
            if line_no == decl_line:
                continue
            for m in re.finditer(rf'(?:(?<![\w.])|(?<=this\.)){helper}\s*\(\s*"([^"\\\s]{{1,80}})"\s*\)', line):
                found.extend(jca_assets(cls, m.group(1)))
    for m in _BC_HMAC.finditer(line):
        found.append(("hmac", m.group(1).upper(), None, None))
    # Self-describing composite standard names anywhere in a string literal (a
    # constant, a ``return "SHA256withRSA";`` mapping): split into their parts.
    for m in _COMPOSITE_LIT.finditer(line):
        name = m.group(1)
        if _HMAC_NAME.match(name):
            found.extend(jca_assets("Mac", name))
        elif _PBKDF2_NAME.match(name):
            found.extend(jca_assets("SecretKeyFactory", name))
        else:
            found.extend(_signature_assets(name))
    out: list[Detection] = []
    for key, variant, mode, size in found:
        out.append(Detection(key=key, line_no=line_no, key_size=size, mode=mode,
                             padding=paddings.get(key), variant=variant, library=_JCA_LIB,
                             receiver_bound=True, defined_at=where.get(key), inferred=key in inferred))
    for key, variant, mode, size in key_specs:
        out.append(Detection(key=key, line_no=line_no, key_size=size, mode=mode, variant=variant,
                             library=_JCA_LIB, receiver_bound=True, key_spec_only=True,
                             defined_at=where.get(key), inferred=key in inferred))
    return out


# A long run of bare string-list elements (``'md5',`` one per line) in which crypto
# names are a small minority is a keyword / autocomplete table (SQL function names,
# IntelliSense word lists), not crypto usage: such lines are not scanned. A short
# list (``['sha256', 'sha384']``) or a mostly-crypto one (a cipher-suite list) is.
_BARE_ELEMENT = re.compile(r"""^\s*(["'])[A-Za-z0-9_.$-]{1,64}\1\s*,?\s*$""")
_KEYWORD_RUN_MIN = 12
_KEYWORD_RUN_MAX_CRYPTO_SHARE = 0.25


def _keyword_list_lines(lines: list[str], lang: str) -> set[int]:
    patterns = (*LITERAL_PATTERNS, *LITERAL_BY_LANG.get(lang, ()))
    out: set[int] = set()
    run: list[int] = []
    for idx in range(len(lines) + 1):
        if idx < len(lines) and _BARE_ELEMENT.match(lines[idx]):
            run.append(idx)
            continue
        if len(run) >= _KEYWORD_RUN_MIN:
            crypto = sum(1 for i in run if any(p.search(lines[i]) for _, p in patterns))
            if crypto <= _KEYWORD_RUN_MAX_CRYPTO_SHARE * len(run):
                out.update(i + 1 for i in run)  # 1-based line numbers
        run = []
    return out


# --------------------------------------------------------------------------- #
# Deny-lists. A collection literal of algorithm names (``WEAK = frozenset({"MD5", "SHA1"})``, Java
# ``Set.of("DES", "RC4")``, JS ``['md5', 'sha1']``) that the file only ever tests membership in, to reject what is
# in it (``if name in WEAK: raise``, ``if (FORBIDDEN.contains(a)) throw``), is a policy: none of its names reaches
# a crypto API. Its lines are not scanned. The list stays a usage when any reference is something else (iterated,
# passed to a call), when the membership test accepts what is in it (an allow-list: ``if name not in ALLOWED:
# raise`` lets MD5 through), and when nothing in the file references it (no evidence either way).
# --------------------------------------------------------------------------- #
_COLLECTION_DECL = re.compile(
    r"^\s*(?:[A-Za-z_][\w.]*(?:<[^=;<>]*(?:<[^=;<>]*>[^=;<>]*)*>)?(?:\[\s*\])?\s+)*"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*(?::[^=]*)?(?<![=!<>])=(?!=)\s*(?P<rhs>(?:new\s+)?[\w.]*(?:<[^=;<>]*>)?"
    r"(?:\[\s*\])?\s*[\[({].*)$"
)
_POLICY_LINE_MAX = 2000  # a longer line is generated or minified: no declaration is read from it
# What a literal collection may hold besides its string elements: constructor / factory words, type arguments,
# booleans (``{"md5": True}``), punctuation.
_COLLECTION_WORDS = re.compile(
    r"\b(?:frozenset|set|tuple|list|Set|List|of|copyOf|Arrays|asList|ImmutableSet|ImmutableList|Collections|"
    r"unmodifiableSet|unmodifiableList|Stream|new|HashSet|TreeSet|LinkedHashSet|ArrayList|String|string|str|"
    r"Object|freeze|setOf|listOf|arrayOf|mutableSetOf|hashSetOf|Array|from|true|false|True|False)\b")
_COLLECTION_REST = re.compile(r"^[\s,()\[\]{}<>:;.]*$")
_POLICY_SPAN = 64
_MEMBER_BEFORE = re.compile(r"\bin\s+(?:[\w$]+\.)?$")
_MEMBER_AFTER = re.compile(r"^\s*\.\s*(?:contains|includes|has|containsKey|__contains__)\s*\(")
_NEGATED_BEFORE = re.compile(r"(?:\bnot\s+in|!)\s*(?:[\w$]+\.)?$")
_REJECTS = re.compile(
    r"\b(?:raise|throw)\b|\breturn\s+(?:false|False|null|None|nil|undefined)\b|\b(?:abort|die|panic|reject)\s*\(")
_CONDITIONAL = re.compile(r"\b(?:if|elif|unless|when)\b")
_DENY_WORDS = frozenset({
    "weak", "insecure", "forbidden", "forbid", "disallowed", "disallow", "deny", "denied", "denylist",
    "blocklist", "blacklist", "blocked", "banned", "rejected", "reject", "unsafe", "broken", "deprecated",
    "prohibited", "unsupported", "illegal", "bad", "refused",
})
_NAME_WORDS = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")


_STR_OR_BRACKET = re.compile(_STR_LIT.pattern + r"|[()\[\]{}]")
_POLICY_CHARS = 8000  # a literal longer than this is data, not a policy list
_POLICY_DEPTH = 4
_IDENT = re.compile(r"[\w$]+")


def _collection_extent(lines: list[str], start: int, rhs_col: int) -> tuple[int, str] | None:
    """(last line index, text) of the bracketed literal that starts at ``lines[start][rhs_col:]``; brackets inside
    string elements do not count."""
    depth, size = 0, 0
    parts: list[str] = []
    for j in range(start, min(len(lines), start + _POLICY_SPAN)):
        seg = lines[j][rhs_col:] if j == start else lines[j]
        size += len(seg)
        if size > _POLICY_CHARS:
            return None
        for tok in _STR_OR_BRACKET.finditer(seg):
            ch = tok.group(0)
            if ch in "([{":
                depth += 1
                if depth > _POLICY_DEPTH:
                    return None  # ``new HashSet<>(Arrays.asList(...))`` is two deep: deeper is not a flat list
            elif ch in ")]}":
                depth -= 1
                if depth == 0:
                    parts.append(seg[: tok.end()])
                    return j, "\n".join(parts)
        parts.append(seg)
    return None


def _guarded(lines: list[str], idx: int, after: str) -> str | None:
    """What a membership test on ``lines[idx]`` guards: ``"reject"`` (raise / throw / return false right after
    it), ``"continue"`` (a condition whose branch does something else: a warning, then the work goes on), or None
    (not a condition: a ``return name in WEAK`` predicate, an assignment)."""
    if _REJECTS.search(after):
        return "reject"
    if not _CONDITIONAL.search(lines[idx]):
        return None
    for j in range(idx + 1, min(len(lines), idx + 4)):
        nxt = lines[j].strip()
        if nxt in ("", "{"):
            continue
        return "reject" if _REJECTS.match(nxt.lstrip("{ ")) else "continue"
    return "continue"


class _PolicyCandidate:
    __slots__ = ("decl", "col", "end", "members", "deny", "accept")

    def __init__(self, decl: int, col: int, end: int) -> None:
        self.decl, self.col, self.end = decl, col, end
        self.members = 0  # membership references; -1 once any other reference is seen
        self.deny = self.accept = False


def _policy_list_lines(lines: list[str], lang: str) -> set[int]:
    """1-based lines of the deny-list literals in ``lines`` (see the comment above)."""
    patterns = (*LITERAL_PATTERNS, *LITERAL_BY_LANG.get(lang, ()))
    cands: dict[str, _PolicyCandidate] = {}
    twice: set[str] = set()
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _COLLECTION_DECL.match(line) if "=" in line and len(line) <= _POLICY_LINE_MAX else None
        extent = _collection_extent(lines, i, m.start("rhs")) if m else None
        if m is None or extent is None:
            i += 1
            continue
        end, body = extent
        strings = _STR_LIT.findall(body)
        if strings and _COLLECTION_REST.match(_COLLECTION_WORDS.sub(" ", _STR_LIT.sub(" ", body))) and \
                any(p.search(s) for s in strings for _, p in patterns):
            name = m.group("name")
            if name in cands:
                twice.add(name)  # two lists of one name: which one a reference reads is not provable
            cands[name] = _PolicyCandidate(i, m.start("name"), end)
        i = end + 1
    for name in twice:
        del cands[name]
    if not cands:
        return set()
    # one pass over every identifier of the file: each reference of a candidate is a membership test or not
    for j, other in enumerate(lines):
        if len(cands) < 8 and not any(n in other for n in cands):
            continue  # cheap skip for the usual one or two lists
        for tok in _IDENT.finditer(other):  # maximal identifier runs: ``WEAK`` never matches inside ``WEAKER``
            cand = cands.get(tok.group(0))
            if cand is None or cand.members < 0 or (j == cand.decl and tok.start() == cand.col):
                continue
            before, after = other[: tok.start()], other[tok.end():]
            if not (_MEMBER_BEFORE.search(before) or _MEMBER_AFTER.match(after)):
                cand.members = -1  # iterated, passed, returned ...: its names may reach a crypto call
                continue
            cand.members += 1
            guard, negated = _guarded(lines, j, after), bool(_NEGATED_BEFORE.search(before))
            if guard == "reject":  # ``not in ALLOWED: raise`` accepts what is in the list
                cand.accept, cand.deny = cand.accept or negated, cand.deny or not negated
            elif guard == "continue" and not negated:
                cand.accept = True  # ``if alg in WEAK: log.warning(...)`` and the work goes on with it
    out: set[int] = set()
    for name, cand in cands.items():
        if cand.members <= 0 or cand.accept:
            continue
        if cand.deny or any(w.lower() in _DENY_WORDS for w in _NAME_WORDS.findall(name)):
            out.update(range(cand.decl + 1, cand.end + 2))
    return out


# --------------------------------------------------------------------------- #
# Constant folding (evasion-resistant spellings). An algorithm name glued from
# string pieces (``'md' + '5'``, PHP ``'des' . '-' . 'ecb'``), decoded from a
# base64 literal (``b64decode('bWQ1')``), reversed (``'bce-821-sea'.split('')
# .reverse().join('')``) or spelled as a Java char array names the algorithm
# exactly as the plain literal would. Each form is folded into ONE string literal
# in place (same line, so line numbers never move) and the lanes below judge the
# folded literal like any other: a folded value that is not an algorithm name
# raises nothing. Only literal-to-literal folds: a piece that is a runtime value
# is never guessed.
# --------------------------------------------------------------------------- #
# a quoted literal, one alternative per quote character (unambiguous, see _STR_LIT); {0} names its groups
_SQ = r'(?:"(?P<{0}d>(?:\\.|[^"\\])*)"' r"|'(?P<{0}s>(?:\\.|[^'\\])*)')"
_CONCAT_OPS = {"php": r"[.+]", "perl": r"\.", _VBNET: r"[&+]"}
_CONCAT_RE = {
    op: re.compile(_SQ.format("a") + r"\s*" + op + r"\s*" + _SQ.format("b"))
    for op in (*_CONCAT_OPS.values(), r"\+")
}


def _lit(m: re.Match[str], side: str) -> str:
    dq = m.group(side + "d")
    return dq if dq is not None else (m.group(side + "s") or "")
_B64_CALL = re.compile(
    r"(?:\bb64decode|\bbase64_decode|\batob|\bFromBase64String|\bdecodeBase64|\bBase64\.(?:decode|getDecoder\(\)\.decode))"
    r"\s*\(\s*b?([\"'])([A-Za-z0-9+/]{4,88}={0,2})\1\s*\)"
    r"|\bBuffer\.from\(\s*([\"'])([A-Za-z0-9+/]{4,88}={0,2})\3\s*,\s*[\"']base64[\"']\s*\)"
)
_REVERSED = re.compile(
    r"([\"'])([^\"'\\]{2,64})\1\s*\.\s*split\(\s*([\"'])\3\s*\)\s*\.\s*reverse\(\s*\)\s*\.\s*join\(\s*([\"'])\4\s*\)"
    r"|([\"'])([^\"'\\]{2,64})\5\s*\[\s*::\s*-1\s*\]"
    r"|\bstrrev\(\s*([\"'])([^\"'\\]{2,64})\7\s*\)"
)
_CHAR_ARRAY = re.compile(r"\bchar\s*\[\s*\]\s+([A-Za-z_]\w*)\s*=\s*\{((?:\s*'[^'\\]'\s*,?)+)\}")
_NEW_STRING_OF = re.compile(r"\bnew\s+String\s*\(\s*([A-Za-z_]\w*)\s*\)")
_PRINTABLE_NAME = re.compile(r"^[A-Za-z0-9 _./+-]{2,64}$")


def _quote(value: str) -> str:
    return f"'{value}'" if "'" not in value else f'"{value}"'


def _windows(line: str, size: int = _MAX_STRING_SCAN) -> list[str]:
    """A long (minified / generated) line cut after ``;`` statement ends into pieces of at most ``size`` characters
    where possible, so string-level rewriting still runs on it piece by piece (rejoined unchanged in length)."""
    out: list[str] = []
    start = 0
    while len(line) - start > size:
        cut = line.rfind(";", start, start + size)
        cut = start + size if cut <= start else cut + 1
        out.append(line[start:cut])
        start = cut
    out.append(line[start:])
    return out


def _fold_strings(line: str, lang: str) -> str:
    if "'" not in line and '"' not in line:
        return line
    if len(line) > _MAX_STRING_SCAN:
        return "".join(_fold_strings_window(w, lang) for w in _windows(line))
    return _fold_strings_window(line, lang)


def _fold_strings_window(line: str, lang: str) -> str:

    def b64(m: re.Match[str]) -> str:
        import base64
        import binascii

        raw = m.group(2) or m.group(4)
        try:
            val = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True).decode("ascii")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return m.group(0)
        return _quote(val) if _PRINTABLE_NAME.match(val) and re.search(r"[A-Za-z]", val) else m.group(0)

    def rev(m: re.Match[str]) -> str:
        val = m.group(2) or m.group(6) or m.group(8) or ""
        return _quote(val[::-1])

    line = _B64_CALL.sub(b64, line)
    line = _REVERSED.sub(rev, line)
    concat = _CONCAT_RE[_CONCAT_OPS.get(lang, r"\+")]
    for _ in range(16):  # 'a' + 'b' + 'c' folds left to right, one join per pass
        folded = concat.sub(lambda m: _quote(_lit(m, "a") + _lit(m, "b")), line, count=1)
        if folded == line:
            break
        line = folded
    return line


def _fold_java_arrays(line: str) -> str:
    """``char[] n = {'D','E','S'};`` -> ``String n = "DES";`` and ``new String(n)`` -> ``n``."""
    def chars(m: re.Match[str]) -> str:
        value = "".join(re.findall(r"'([^'\\])'", m.group(2)))
        return f'String {m.group(1)} = "{value}"'

    line = _CHAR_ARRAY.sub(chars, line)
    return _NEW_STRING_OF.sub(r"\1", line)


_JAVA_CONCAT = re.compile(r'(?:"[^"\\]*"|[A-Za-z_]\w*)(?:\s*\+\s*(?:"[^"\\]*"|[A-Za-z_]\w*))+')


def _fold_java_constants(line: str, consts: dict[str, str]) -> str:
    """``a + bb + c`` where every piece is a proven same-file String constant (or a literal) -> one literal."""
    if not consts or "+" not in line:
        return line

    def join(m: re.Match[str]) -> str:
        parts = [p.strip() for p in m.group(0).split("+")]
        out = []
        for p in parts:
            if p.startswith('"'):
                out.append(p[1:-1])
            elif p in consts:
                out.append(consts[p])
            else:
                return m.group(0)
        return '"' + "".join(out) + '"'

    return _JAVA_CONCAT.sub(join, line)


# Import aliases: Go ``import d "crypto/des"`` (``d.NewCipher``), Python ``from Crypto.Cipher import DES as d`` and
# ``d = importlib.import_module('Crypto.Cipher.DES')``. The alias is rewritten to the module's own name on the
# file's other lines, so the receiver rules see ``des.NewCipher`` / ``DES.new``.
_GO_ALIAS = re.compile(r'^\s*(?:import\s+)?([A-Za-z_]\w*)\s+"(?:crypto|golang\.org/x/crypto)/(?:[\w/]+/)?(\w+)"\s*$')
_PY_ALIAS = re.compile(
    r"^\s*(?:from\s+[\w.]+\s+)?import\s+(?:[\w]+\.)*(\w+)\s+as\s+([A-Za-z_]\w*)\s*$"
    r"|^\s*([A-Za-z_]\w*)\s*=\s*(?:importlib\.import_module|__import__)\(\s*[\"'](?:[\w]+\.)*(\w+)[\"'][^)]*\)\s*$"
)
_PY_CRYPTO_MODULES = frozenset({
    "AES", "DES", "DES3", "ARC4", "ARC2", "Blowfish", "CAST", "ChaCha20", "Salsa20", "MD5", "SHA1", "SHA256",
    "SHA512", "HMAC", "RSA", "DSA", "ECC", "PKCS1_v1_5", "PKCS1_OAEP", "hashlib", "hmac",
})


def _import_aliases(lines: list[str], lang: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in lines:
        if lang == _GO:
            m = _GO_ALIAS.match(line)
            if m and m.group(1) not in ("_", m.group(2)):
                out[m.group(1)] = m.group(2)
        elif lang == _PY:
            m = _PY_ALIAS.match(line)
            if not m:
                continue
            module, alias = (m.group(1), m.group(2)) if m.group(1) else (m.group(4), m.group(3))
            if module in _PY_CRYPTO_MODULES and alias != module:
                out[alias] = module
    return out


def _apply_aliases(line: str, aliases: dict[str, str]) -> str:
    for alias, module in aliases.items():
        line = re.sub(rf"(?<![\w.]){re.escape(alias)}\.", f"{module}.", line)
    return line


# --------------------------------------------------------------------------- #
# JWT ``alg`` header (JWA names). The algorithm a token is signed or verified with
# is a string option of the JWT call (jsonwebtoken ``{ algorithm: 'HS256' }`` /
# ``{ algorithms: ['RS256'] }``, jose ``{ alg: 'ES256' }``, PyJWT
# ``algorithm="HS256"`` / ``algorithms=[...]``, jjwt / Nimbus
# ``SignatureAlgorithm.HS256``). ``none`` (and PyJWT ``verify_signature: False``)
# means an unsigned / unverified token. File-gated on a JWT library so a generic
# ``algorithm: 'none'`` option elsewhere is never read as JWT.
# --------------------------------------------------------------------------- #
_JWT_FILE = re.compile(r"jsonwebtoken|\bjose\b|\bjwt\b|\bPyJWT\b|\bJwts\b|nimbusds|\bJWSAlgorithm\b", re.I)
_JWT_OPTION = re.compile(r"\b(?:algorithms?|alg)['\"]?\s*[:=]\s*(\[[^\]]*\]|['\"][A-Za-z0-9]{2,6}['\"])")
_JWT_ENUM = re.compile(r"\b(?:SignatureAlgorithm|JWSAlgorithm)\s*\.\s*(HS|RS|PS|ES)(256|384|512)\b|\bSignatureAlgorithm\s*\.\s*(NONE)\b")
_JWT_NO_VERIFY = re.compile(r"[\"']verify_signature[\"']\s*:\s*False\b")
_JWA = re.compile(r"^(?:(HS|RS|PS|ES)(256|384|512)|(EdDSA)|(none))$", re.I)


def _jwa_assets(alg: str) -> list[tuple[str, str | None]]:
    m = _JWA.match(alg)
    if not m:
        return []
    if m.group(4):
        return [("jwt-none", None)]
    if m.group(3):
        return [("ed25519", None)]
    fam, bits = m.group(1).upper(), m.group(2)
    digest = f"sha{bits}"
    if fam == "HS":
        return [("hmac", f"SHA{bits}")]
    return [({"RS": "rsa", "PS": "rsa", "ES": "ecdsa"}[fam], None), (digest, None)]


def _jwt_lane(line: str, line_no: int) -> list[Detection]:
    found: list[tuple[str, str | None]] = []
    for m in _JWT_OPTION.finditer(line):
        for alg in re.findall(r"['\"]([A-Za-z0-9]{2,6})['\"]", m.group(1)):
            found.extend(_jwa_assets(alg))
    for m in _JWT_ENUM.finditer(line):
        found.extend(_jwa_assets("none" if m.group(3) else m.group(1) + m.group(2)))
    if _JWT_NO_VERIFY.search(line):
        found.append(("jwt-none", None))
    return [Detection(key=k, line_no=line_no, variant=v, library="JWT", receiver_bound=True) for k, v in found]


# Go: ``block, err := aes.NewCipher(key)`` then ``cipher.NewGCM(block)`` — the mode lives on another statement,
# bound through the block variable to the NEAREST preceding constructor of that name in the same function.
_GO_BLOCK_DECL = re.compile(
    r"\b([A-Za-z_]\w*)\s*(?:,\s*[A-Za-z_]\w*\s*)?:?=\s*(aes|des)\.New(?:TripleDES)?Cipher\s*\("
)
_GO_MODE_CALL = re.compile(
    r"\bcipher\.(NewGCM(?:WithNonceSize|WithTagSize)?|NewCBCEncrypter|NewCBCDecrypter|NewCTR"
    r"|NewCFBEncrypter|NewCFBDecrypter|NewOFB)\s*\(\s*([A-Za-z_]\w*)"
)
_GO_FUNC = re.compile(r"^\s*func\b")
_GO_BLOCK_KEYS = ("aes", "des", "3des")


def _go_mode(fn: str) -> str:
    for prefix, mode in (("NewGCM", "GCM"), ("NewCBC", "CBC"), ("NewCTR", "CTR"), ("NewCFB", "CFB"),
                         ("NewOFB", "OFB")):
        if fn.startswith(prefix):
            return mode
    return "OTHER"


def _bind_go_modes(lines: list[str], dets: list[Detection]) -> None:
    by_line: dict[int, list[Detection]] = {}
    for det in dets:
        if det.key in _GO_BLOCK_KEYS:
            by_line.setdefault(det.line_no, []).append(det)
    if not by_line:
        return
    for idx, line in enumerate(lines):
        for call in _GO_MODE_CALL.finditer(line):
            var = call.group(2)
            for j in range(idx, -1, -1):
                if j < idx and _GO_FUNC.match(lines[j]):
                    break  # never bind across a function boundary
                decl = next((d for d in _GO_BLOCK_DECL.finditer(lines[j]) if d.group(1) == var), None)
                if decl is None:
                    continue
                for det in by_line.get(j + 1, []):
                    if det.mode is None:
                        det.mode = _go_mode(call.group(1))
                break


# .NET: ``var aes = Aes.Create();`` then ``aes.Mode = CipherMode.ECB;`` / ``aes.KeySize = 256;`` — mode and size
# are set on the instance in later statements, bound through the variable to its NEAREST preceding declaration.
_DOTNET_DECL = re.compile(
    r"\b([A-Za-z_]\w*)\s*=\s*(?:new\s+)?(Aes|AesManaged|AesCryptoServiceProvider|AesCng|RijndaelManaged|TripleDES"
    r"|TripleDESCryptoServiceProvider|TripleDESCng|DES|DESCryptoServiceProvider|RC2|RC2CryptoServiceProvider"
    r"|RSA|RSACryptoServiceProvider|RSACng)\b(?:\s*\.\s*Create)?\s*\("
)
_DOTNET_SET = re.compile(
    r"(?<![\w.])([A-Za-z_]\w*)\s*\.\s*(?:Mode\s*=\s*CipherMode\s*\.\s*(CBC|ECB|CFB|OFB|CTS)\b"
    r"|KeySize\s*=\s*(\d{2,5})\b)"
)
_DOTNET_SYMMETRIC_KEYS = ("aes", "3des", "des", "rc2")
_DOTNET_SIZED = {"aes": (128, 192, 256), "rsa": (512, 1024, 2048, 3072, 4096, 8192)}


def _bind_dotnet_settings(lines: list[str], dets: list[Detection]) -> None:
    by_line: dict[int, list[Detection]] = {}
    for det in dets:
        by_line.setdefault(det.line_no, []).append(det)
    for idx, line in enumerate(lines):
        for setting in _DOTNET_SET.finditer(line):
            var, mode, size = setting.group(1), setting.group(2), setting.group(3)
            for j in range(idx, -1, -1):
                if not any(d.group(1) == var for d in _DOTNET_DECL.finditer(lines[j])):
                    continue
                for det in by_line.get(j + 1, []):
                    if mode and det.key in _DOTNET_SYMMETRIC_KEYS and det.mode is None:
                        det.mode = "CBC" if mode == "CTS" else mode  # CTS is CBC with ciphertext stealing
                    if size and int(size) in _DOTNET_SIZED.get(det.key, ()) and det.key_size is None:
                        det.key_size = int(size)
                break


# Node ``generateKeyPair[Sync]('rsa', {\n  modulusLength: 2048, ...})`` — the options object spans lines.
_JS_KEYGEN = re.compile(r"\bgenerateKeyPair(?:Sync)?\s*\(\s*['\"](rsa|rsa-pss|ec)['\"]")
_JS_MODULUS = re.compile(r"\bmodulusLength\s*:\s*(\d{3,5})\b")
_JS_NAMED_CURVE = re.compile(r"\bnamedCurve\s*:\s*['\"]([\w-]+)['\"]")
_JS_OPTIONS_LINES = 15


def _bind_js_keygen_options(lines: list[str], dets: list[Detection]) -> None:
    for idx, line in enumerate(lines):
        call = _JS_KEYGEN.search(line)
        if not call:
            continue
        depth, span = 0, []
        for j in range(idx, min(len(lines), idx + _JS_OPTIONS_LINES)):
            seg = lines[j][call.start():] if j == idx else lines[j]
            span.append(seg)
            depth += seg.count("(") - seg.count(")")
            if depth <= 0:
                break
        options = "\n".join(span)
        size = _JS_MODULUS.search(options)
        curve = _JS_NAMED_CURVE.search(options)
        for det in dets:
            if det.line_no != idx + 1:
                continue
            if det.key == "rsa" and size and det.key_size is None:
                det.key_size = int(size.group(1))
            if det.key == "ecdsa" and curve and det.curve is None:
                det.curve = extract_curve(curve.group(1)) or curve.group(1)


# A name passed as a call argument (``hashlib.new(ALG, pw)``, ``f(x, algorithm=consts.ALG)``).
_PY_ARG_NAME = r"([(,=]\s*){}(\s*[,)])"
# A call whose arguments name an algorithm: a callee of a Python crypto module (``hashlib.new``, ``hmac.new``,
# ``hashes.Hash``, ``AES.new``, ``jwt.encode``) or a crypto constructor, and any call's argument named for one.
_PY_CRYPTO_CALLEE = re.compile(
    r"^(?:hashes|algorithms|modes|padding|jwt|Crypto|Cryptodome|pkcs1_15|pss|DSS|"
    + "|".join(sorted(_PY_CRYPTO_MODULES)) + r")(?:\.|$)"
    r"|(?:^|\.)(?:Cipher|Hash|HMAC|PBKDF2HMAC|Scrypt|HKDF|HKDFExpand|ConcatKDFHash|X963KDF|pbkdf2_hmac)$"
)
_PY_CRYPTO_KWARG = re.compile(
    r"^(?:algorithms?|alg|digestmod|digest|digest_?alg|hash_?name|hash_?alg|hashfunc|hash|cipher|mode)$", re.I)
_GETATTR_CRYPTO = re.compile(r"^\s*(?:hashlib|hashes|algorithms|modes)\s*,")


def _crypto_argument(line: str, at: int) -> bool:
    """Is the argument whose leading ``(`` / ``,`` / ``=`` is at ``line[at]`` read by a crypto call? A constant
    passed anywhere else (``raise UnsupportedDigest(REJECTED_DIGEST)``, ``log(ALG)``) names no usage."""
    if line[at] == "=":
        kw = re.search(r"([A-Za-z_]\w*)\s*$", line[:at])
        if kw and _PY_CRYPTO_KWARG.match(kw.group(1)):
            return True
    depth, j = 0, at if line[at] == "(" else at - 1
    while j >= 0:  # the unclosed ``(`` this argument sits in
        ch = line[j]
        if ch == ")":
            depth += 1
        elif ch == "(":
            if depth == 0:
                break
            depth -= 1
        j -= 1
    if j < 0:
        return False
    callee = re.search(r"([A-Za-z_][\w.]*)\s*$", line[:j])
    if callee is None:
        return False
    name = callee.group(1)
    return bool(_PY_CRYPTO_CALLEE.search(name)) or (name == "getattr" and bool(_GETATTR_CRYPTO.match(line[j + 1:])))


def _value_keys(value: str, lang: str) -> set[str]:
    """The algorithm keys a constant's value names on its own (``'md5'`` -> {md5})."""
    quoted = _quote(value)
    keys = {k for k, pat in (*LITERAL_PATTERNS, *LITERAL_BY_LANG.get(lang, ())) if pat.search(quoted)}
    alias = LITERAL_ALGO_ALIASES.get(re.sub(r"[^a-z0-9]", "", value.lower()))
    if alias:
        keys.add(alias)
    return keys


def _substitute_python_constants(
    work_lines: list[str], external: Mapping[str, Any]
) -> dict[int, list[Any]]:
    """Replace a constant imported from another project module, where a crypto call takes it as an argument, by
    its quoted value (``hashlib.new(ALG)`` -> ``hashlib.new('md5')``) so every lane reads the algorithm at the use
    site. Returns line number -> the definitions substituted there."""
    used: dict[int, list[Any]] = {}
    patterns = [(re.compile(_PY_ARG_NAME.format(re.escape(name))), d) for name, d in external.items()]
    for idx, line in enumerate(work_lines):
        if not line or "(" not in line or _IMPORT_RE.search(line.strip()):
            continue
        for pat, d in patterns:
            def sub(m: re.Match[str], v: str = d.value, src: str = line) -> str:
                if not _crypto_argument(src, m.start(1)):
                    return m.group(0)
                return f"{m.group(1)}{_quote(v)}{m.group(2)}"

            new = pat.sub(sub, line)
            if new != line:
                line = new
                used.setdefault(idx + 1, []).append(d)
        work_lines[idx] = line
    return used


# where crypto calls in OTHER files read a setting: ``prove(binding, owners)`` (the
# scanner's linked reads), or a plain name -> ``path:line`` map (unit tests)
ProjectProof = Mapping[str, str] | Callable[[str, tuple[str, ...]], str | None]


def _tag_settings(
    per_line: dict[str, Detection],
    settings: list[tuple[int, int, str, tuple[str, ...]]],
    lit_line: str,
    pats_by_key: Mapping[str, list[re.Pattern[str]]],
    config: _ConfigLiterals,
) -> None:
    """A detection the line names only inside a settings value carries the
    setting's name, and either the crypto call that reads it or low confidence."""
    rest = lit_line
    for start, end, _b, _o in settings:
        rest = rest[:start + 1] + " " * (end - start - 2) + rest[end - 1:]
    for det in per_line.values():
        pats = pats_by_key.get(det.key.split("-")[0], []) + pats_by_key.get(det.key, [])
        if det.receiver_bound or not pats or any(p.search(rest) for p in pats):
            continue  # named by a call, or outside the settings values
        for start, end, binding, owners in settings:
            body = lit_line[start:end]
            if any(p.search(body) for p in pats):
                det.config_binding = binding
                read = config.read_at(binding, owners)
                if read is None and binding in config.keys:
                    read = "library-key"
                det.config_read_at = read
                det.low_confidence = read is None
                break


def detect_crypto(
    text: str,
    lang: str,
    external: Mapping[str, Any] | None = None,
    config_evidence: list[dict[str, Any]] | None = None,
    project_reads: ProjectProof | None = None,
) -> list[Detection]:
    """Detect crypto usage in one source file's ``text`` (of language ``lang``).

    Runs the bounded 3-step match: prose-strip + call-split -> data-flow-lite
    symbol table -> rule apply (receiver+method+arg-roles) merged with the literal
    lane. Returns one :class:`Detection` per distinct algorithm per line.

    ``external`` maps the names this file uses that are constants of other project files
    (:meth:`aibom.cbom.project.ProjectIndex.scope_for`) to their definitions; a detection that reads one carries
    ``defined_at``.

    ``config_evidence``, when given, receives one
    ``{"line", "algorithm", "binding", "value"}`` per configuration literal that
    names an algorithm without using it (a label, a comparison, a case label, an
    Enum member: ``_ConfigLiterals``): not an asset. ``project_reads`` maps the names
    crypto calls read in OTHER project files to ``path:line`` (``crypto_reads``), so
    a setting read elsewhere is a proven asset.
    """
    stripped = strip_noncode(text)
    # Split on "\n" only: splitlines() also breaks on \f, \v, \x1c-\x1e, \x85, U+2028/9 and would shift
    # every reported line number after such a character (the occurrence pass uses the same rule).
    raw_lines = stripped.split("\n")
    work_lines = [_fold_strings(_strip_line_comment(ln, lang), lang) for ln in raw_lines]
    if lang == _JAVA:
        work_lines = [_fold_java_arrays(ln) for ln in work_lines]
    aliases = _import_aliases(work_lines, lang) if lang in (_GO, _PY) else {}
    if aliases:
        work_lines = [ln if _IMPORT_RE.search(ln.strip()) or _GO_ALIAS.match(ln) else _apply_aliases(ln, aliases)
                      for ln in work_lines]
    substituted: dict[int, list[Any]] = {}
    if external and lang == _PY:  # after the aliases, so ``hl.new(ALG)`` (``import hashlib as hl``) is a crypto call
        substituted = _substitute_python_constants(work_lines, external)
    symbols = build_symbols(work_lines)
    rules = RULES_BY_LANG.get(lang, ())
    java_ctx = _JavaContext(work_lines, external) if lang == _JAVA else None
    jwt_file = bool(_JWT_FILE.search(stripped)) and lang in (_PY, _JS, _JAVA)
    keyword_lines = _keyword_list_lines(work_lines, lang) | _policy_list_lines(work_lines, lang)
    config = (
        _ConfigLiterals(
            [ln.strip() for ln in work_lines], lang, work_lines, project_reads
        )
        if lang in _CONFIG_LANGS
        else None
    )
    if lang == _PY:
        # ``self.ALG`` / ``cls.ALG`` / ``Cls.ALG`` read a class attribute set to a
        # literal: the call that reads it sees the literal (``jwt.encode(...,
        # algorithm=self.ALG)``); the reads above were taken before this fold
        consts = py_class_constants(work_lines)
        if consts:
            names = "|".join(map(re.escape, consts))
            attr = re.compile(r"\b(?:self|cls|[A-Z]\w*)\.(" + names + r")\b")
            work_lines = [
                ln
                if _PY_CONST.match(ln.strip())
                else attr.sub(lambda m: consts[m.group(1)], ln)
                for ln in work_lines
            ]
    pats = (*LITERAL_PATTERNS, *LITERAL_BY_LANG.get(lang, ()))
    pats_by_key: dict[str, list[re.Pattern[str]]] = {}
    for k, pat in pats:
        pats_by_key.setdefault(k, []).append(pat)

    def _evidence(line_no: int, text: str, binding: str) -> None:
        if config_evidence is None or not text.strip():
            return
        named = [k for k, pat in pats if pat.search(text)]
        if not named:  # a value in another language's spelling ('AES-GCM', 'DES')
            hit = _EVIDENCE_NAME.search(text)
            named = [hit.group(0).lower()] if hit else []
        if named:
            config_evidence.append({"line": line_no, "algorithm": named[0],
                                    "binding": binding, "value": text.strip()[:80]})

    out: list[Detection] = []
    for line_no, work in enumerate(work_lines, start=1):
        line = work.strip()
        if not line or _IMPORT_RE.search(line) or _BARE_IMPORT_PATH.match(work) or _PACKAGE_DECL.match(work):
            continue  # imports are LIBRARY signals, handled by the scanner
        if line_no in keyword_lines:
            continue  # an element of a non-crypto keyword table, or of a deny-list
        if lang == _PY and len(line) <= _MAX_STRING_SCAN:
            esc = py_escaped_span(line)
            if esc is not None:
                # text pasted with its string escapes: no call, no use; only that
                # span is skipped (a real call on the line stays)
                _evidence(line_no, line[esc[0]:esc[1]], "escaped-code")
                line = line[:esc[0]] + " " * (esc[1] - esc[0]) + line[esc[1]:]
            embedded = [
                m for m in _STR_LIT.finditer(line) if _py_embedded_code(m.group(0))
            ]
            for m in reversed(embedded):
                _evidence(line_no, m.group(0)[1:-1], "embedded-code")
                gap = " " * (m.end() - m.start() - 2)
                line = line[:m.start() + 1] + gap + line[m.end() - 1:]
        per_line: dict[str, Detection] = {}

        # --- receiver+method rule lane ---
        calls = split_calls(line)
        quoted = any(q in line for q in "\"'`")
        if calls and quoted and len(line) <= _MAX_STRING_SCAN:
            # a "call" spelled inside a string literal ("Scrypt (Memory-Hard)") is text,
            # not a call
            in_code = {chain for chain, _args in split_calls(_blank_strings(line))}
            calls = [c for c in calls if c[0] in in_code]
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
        # Prose inside string literals / JSX text ("AES-256 encryption at rest", "MD5 is not allowed") names an
        # algorithm without using it: blank it for this lane only (API strings such as "AES/GCM/NoPadding" have
        # no spaces and stay).
        lit_line = blank_labels(blank_prose(line, lang), lang)
        settings: list[tuple[int, int, str, tuple[str, ...]]] = []
        if config is not None:
            for start, end, binding, kind, owners in config.judge(line_no - 1, line):
                if kind == SETTING:
                    settings.append((start, end, binding, owners))
                    continue
                if lit_line[start + 1:end - 1].strip():
                    _evidence(line_no, line[start + 1:end - 1], binding)
                blank = " " * (end - start - 2)
                lit_line = lit_line[:start + 1] + blank + lit_line[end - 1:]
                # an Enum member / enum constant is named like the algorithm too
                # (``MD5 = "md5"``, ``MD5("MD5")``): its name is no use either
                lit_line = re.sub(
                    rf"(?i)\b{re.escape(binding)}\b(?=\s*(?:[=(]|:\s*\w+\s*=))",
                    lambda m: " " * len(m.group(0)),
                    lit_line,
                    count=1,
                ) if re.fullmatch(r"\w+", binding) else lit_line
        if lang == _C and "_set_cipher_list" in lit_line:
            # CB-28: an OpenSSL cipher-list string is a TLS suite policy (the
            # protocol lane reads it, with ``!RC4`` / ``-3DES`` as removals), not a
            # use of each algorithm it names
            lit_line = _C_CIPHER_LIST_ARG.sub(_blank_list, lit_line)

        if jwt_file:
            for det in _jwt_lane(lit_line, line_no):
                if det.key in per_line:
                    _merge(per_line[det.key], det)
                else:
                    per_line[det.key] = det

        # --- Java JCA argument lane (constants, API-bound bare names, helpers) ---
        if java_ctx is not None:
            lit_line = _fold_java_constants(lit_line, java_ctx.consts)
            for det in _java_jca_lane(lit_line, line_no, java_ctx):
                if det.key in per_line:
                    _merge(per_line[det.key], det)
                else:
                    per_line[det.key] = det

        explicit_ks = extract_key_size(lit_line)
        mode = extract_mode(lit_line) or _lang_mode(lit_line, lang)
        curve = extract_curve(lit_line)
        for key, pat in (*LITERAL_PATTERNS, *LITERAL_BY_LANG.get(lang, ())):
            if not pat.search(lit_line):
                continue
            if key in _API_WORD_KEYS and not _api_word_hit(pat, lit_line):
                # a label or a settings value names the KDF; nothing calls it here
                continue
            lit = Detection(
                key=key,
                line_no=line_no,
                key_size=_literal_key_size(key, lit_line, explicit_ks),
                mode=mode,
                curve=curve,
                padding=_lang_padding(lit_line, lang, key),
                parameter=extract_pqc_parameter(line, key),
            )
            if key in per_line:
                _merge(per_line[key], lit)
            else:
                per_line[key] = lit

        _merge_sized_into_coarse(per_line)
        _mark_inner(per_line, line)
        if settings and config is not None:
            _tag_settings(per_line, settings, lit_line, pats_by_key, config)
        for d in substituted.get(line_no, ()):
            keys = _value_keys(d.value, lang)
            for det in per_line.values():
                if det.key in keys or det.key.split("-")[0] in keys:
                    det.defined_at = det.defined_at or d.where
        out.extend(per_line.values())
    if java_ctx is not None:
        _fold_variants(out)
        out = _drop_subsumed_key_specs(out)
    if lang == _GO:
        _bind_go_modes(work_lines, out)
    elif lang in (_CSHARP, _VBNET):
        _bind_dotnet_settings(work_lines, out)
    elif lang == _JS:
        _bind_js_keygen_options(work_lines, out)
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
    "extract_pqc_parameter",
    "ROLE_KEY_SIZE",
    "ROLE_MODE",
    "ROLE_CURVE",
    "ROLE_PADDING",
    "ROLE_LITERAL_KEY",
    "ROLE_OPERATION",
]
