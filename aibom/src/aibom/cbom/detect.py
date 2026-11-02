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
from dataclasses import dataclass, field

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


# --------------------------------------------------------------------------- #
# Python rule table (C1). Keyed to the pyca/cryptography + stdlib + PyCryptodome
# API surface. C2/C3 add the other ecosystems' tables under the same model.
# --------------------------------------------------------------------------- #
_PY = "python"
_PYCRYPTODOME = "pycryptodome"
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
    ("scrypt", re.compile(r"\bscrypt\b", _F)),
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


# WebCrypto RSA algorithm names carry the padding scheme (``{name: "RSA-OAEP"}``).
_WEBCRYPTO_PADDING = (("RSA-OAEP", "oaep"), ("RSA-PSS", "pss"), ("RSASSA-PKCS1", "pkcs1v15"))


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
    if lang in (_SHELL, _PERL):
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


def _drop_subsumed_key_specs(dets: list[Detection]) -> list[Detection]:
    """``new SecretKeySpec(key, "AES")`` next to ``Cipher.getInstance("AES/CBC/PKCS5Padding")`` is the key of that
    cipher: one AES usage, not a second bare ``AES`` row beside ``AES-CBC``. A key spec stays a row when nothing
    else in the file uses its algorithm."""
    used = {d.key for d in dets if not d.key_spec_only}
    return [d for d in dets if not (d.key_spec_only and d.key in used)]


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


def blank_prose(line: str, lang: str) -> str:
    """``line`` with prose-like string literals (and JSX text in JS/TS) replaced by spaces of the same length."""
    def blank(m: re.Match) -> str:
        lit = m.group(0)
        return lit[0] + " " * (len(lit) - 2) + lit[-1] if _is_prose(lit[1:-1]) else lit

    if len(line) > _MAX_STRING_SCAN:
        return line
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

    __slots__ = ("jca", "consts", "classes", "helpers", "gen_sizes")

    def __init__(self, lines: list[str]) -> None:
        code = "\n".join(lines)  # comments already stripped
        self.jca = bool(_JCA_FILE.search(code))
        self.classes = set(_JAVA_CLASS_DECL.findall(code))
        self.consts = _string_constants(code)
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
        return {}
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
    if lit is not None:
        return lit
    if not ident:
        return None
    name = ident[5:] if ident.startswith("this.") else ident
    if "." in name:
        qualifier, name = name.rsplit(".", 1)
        if qualifier not in ctx.classes:
            return None
    return ctx.consts.get(name)


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
    if ctx.jca:
        for m in _JCA_CALL.finditer(line):
            spec = _resolve_java_arg(m.group("lit"), m.group("ident"), ctx)
            if not spec:
                continue
            assets = jca_assets(m.group("cls"), spec)
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
                spec = _resolve_java_arg(am.group("lit"), am.group("ident"), ctx) if am else None
                if spec:
                    key_specs.extend(jca_assets("SecretKeySpec", spec))
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
                             receiver_bound=True))
    for key, variant, mode, size in key_specs:
        out.append(Detection(key=key, line_no=line_no, key_size=size, mode=mode, variant=variant,
                             library=_JCA_LIB, receiver_bound=True, key_spec_only=True))
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


def _fold_strings(line: str, lang: str) -> str:
    if ("'" not in line and '"' not in line) or len(line) > _MAX_STRING_SCAN:
        return line

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


def detect_crypto(text: str, lang: str) -> list[Detection]:
    """Detect crypto usage in one source file's ``text`` (of language ``lang``).

    Runs the bounded 3-step match: prose-strip + call-split -> data-flow-lite
    symbol table -> rule apply (receiver+method+arg-roles) merged with the literal
    lane. Returns one :class:`Detection` per distinct algorithm per line.
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
    symbols = build_symbols(work_lines)
    rules = RULES_BY_LANG.get(lang, ())
    java_ctx = _JavaContext(work_lines) if lang == _JAVA else None
    jwt_file = bool(_JWT_FILE.search(stripped)) and lang in (_PY, _JS, _JAVA)
    keyword_lines = _keyword_list_lines(work_lines, lang)

    out: list[Detection] = []
    for line_no, work in enumerate(work_lines, start=1):
        line = work.strip()
        if not line or _IMPORT_RE.search(line) or _BARE_IMPORT_PATH.match(work):
            continue  # imports are LIBRARY signals, handled by the scanner
        if line_no in keyword_lines:
            continue  # an element of a non-crypto keyword table
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
        # Prose inside string literals / JSX text ("AES-256 encryption at rest", "MD5 is not allowed") names an
        # algorithm without using it: blank it for this lane only (API strings such as "AES/GCM/NoPadding" have
        # no spaces and stay).
        lit_line = blank_prose(line, lang)

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
            lit = Detection(
                key=key,
                line_no=line_no,
                key_size=explicit_ks,
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
