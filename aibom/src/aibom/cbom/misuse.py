"""Clean-room crypto-material MISUSE detection (C6).

Source-level analysis of *how* crypto material (keys, IVs, nonces, salts,
tokens) is produced and used — the misuse the plain inventory lanes (C1
algorithm, C2 related-crypto-material) do not derive. It reconstructs a light,
intra-file view of each material binding and reports four high-confidence
misuses, each grounded in a public CWE (never copied from any OSS tool):

* **weak RNG for crypto material** (CWE-338) — a non-cryptographic PRNG
  (``random.*`` / ``Math.random`` / ``java.util.Random`` / C ``rand()`` /
  Go ``math/rand``) feeding a key/IV/nonce/salt/token, or feeding a cipher
  construction inline;
* **static IV** (CWE-329) — a constant/hardcoded IV or nonce literal reaching a
  cipher (a predictable IV defeats CBC/CTR semantic security);
* **reused nonce** (CWE-323) — the SAME constant IV/nonce symbol feeding two or
  more cipher constructions (catastrophic for GCM/CTR);
* **hardcoded key** (CWE-321) — a symmetric key embedded as a source literal.

Precision-first, deliberately clean-room: every detection is gated on (1) a
crypto CONTEXT in the file (a cipher construct or a crypto import — so a game's
``Math.random()`` is never flagged) AND (2) a crypto-material VARIABLE NAME or an
inline cipher argument AND (3) a constant-literal / weak-RNG binding. A secure
source (``os.urandom`` / ``secrets`` / ``crypto.randomBytes`` / ``SecureRandom``
/ Go ``crypto/rand``) is explicitly excluded, so good code raises nothing.

Lane discipline: this module only DETECTS facts. The C6 scanner
(:mod:`aibom.cbom.scanners.crypto_misuse_scan`) turns each fact into a
``related-crypto-material`` component carrying the misuse as ``crypto:`` props;
the pure predicate :func:`aibom.cbom.weakness.material_misuse_findings` reads
those props back into flags; the C8 scorer weights them. No copied OSS source.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# --------------------------------------------------------------------------- #
# Crypto-material variable-name vocabulary -> CycloneDX relatedCryptoMaterial
# type. Name-based (like C2's material lane), so it is language-agnostic.
# --------------------------------------------------------------------------- #
_IV_NAMES = frozenset(
    {
        "iv", "nonce", "initialization_vector", "initializationvector",
        "iv_bytes", "nonce_bytes", "ivbytes", "noncebytes", "init_vector",
        "initvector",
    }
)
_SALT_NAMES = frozenset({"salt", "salt_bytes", "saltbytes", "pwsalt"})
_KEY_NAMES = frozenset(
    {
        "key", "secret_key", "secretkey", "aes_key", "aeskey", "enc_key",
        "enckey", "encryption_key", "hmac_key", "hmackey", "mac_key", "secret",
        "session_key", "sessionkey", "master_key", "masterkey", "sym_key",
        "symkey", "cipher_key", "cipherkey",
    }
)
_TOKEN_NAMES = frozenset(
    {"token", "seed", "auth_token", "authtoken", "csrf_token", "session_token"}
)


def _material_kind(var: str) -> str | None:
    """Map a variable name to a CycloneDX material kind, or ``None`` if the name
    is not crypto material. Uses an explicit set plus a few unambiguous suffixes
    (``_iv`` / ``_nonce`` / ``_key`` / ``_salt`` / ``_token``) — deliberately
    conservative so ordinary identifiers (``monkey``, ``keyboard``) never match.
    """
    v = var.lower()
    if v in _IV_NAMES or v.endswith("_iv") or v.endswith("_nonce"):
        return "nonce" if "nonce" in v else "initialization-vector"
    if v in _SALT_NAMES or v.endswith("_salt"):
        return "salt"
    if v in _KEY_NAMES or v.endswith("_key"):
        return "secret-key"
    if v in _TOKEN_NAMES or v.endswith("_token"):
        return "token"
    return None


# --------------------------------------------------------------------------- #
# Binding classifiers.
# --------------------------------------------------------------------------- #
# Non-crypto PRNG APIs across languages (word-boundaried CALLS). A game's
# `Math.random()` is only reached after the material-name + crypto-context gate.
_WEAK_RNG_RE = re.compile(
    r"random\.(?:random|randint|randrange|randbytes|getrandbits|choice|shuffle|"
    r"uniform|sample)\s*\("            # Python stdlib random
    r"|numpy\.random\.|np\.random\."   # NumPy PRNG
    r"|Math\.random\s*\("              # JS
    r"|new\s+Random\s*\(|java\.util\.Random"  # Java
    r"|mt19937|std::rand\b"            # C++ Mersenne / std::rand
    r"|(?<![\w.])rand\s*\(|(?<![\w.])srand\s*\("  # C rand()/srand()
    r"|math/rand|(?<![\w.])mrand\.|rand\.Intn\s*\(",  # Go math/rand
    re.IGNORECASE,
)
# CSPRNGs — a binding that uses one of these is NEVER weak-RNG, even if it also
# mentions a `random`-rooted module (e.g. `random.SystemRandom`).
_SECURE_RNG_RE = re.compile(
    r"os\.urandom|secrets\.|SystemRandom|token_bytes|token_hex|getrandom"
    r"|randombytes|crypto\.randomBytes|SecureRandom|rand\.Read|crypto/rand"
    r"|/dev/urandom|RAND_bytes|RandomNumberGenerator",
    re.IGNORECASE,
)
# A pure constant literal RHS: a quoted str/bytes literal, a hex-decode, or a
# byte-array literal. ``{n,}`` lengths avoid trivial one/two-char literals.
_CONST_LIT_RE = re.compile(
    r"""^\s*(?:"""
    r"""b?["'][0-9A-Za-z+/=_\-]{6,}["']"""                 # b"..."/"..."
    r"""|(?:bytes\.fromhex|unhexlify)\(\s*["'][0-9a-fA-F]{8,}["']\s*\)"""  # hex
    r"""|new\s+byte\s*\[\s*\]\s*\{[^}]{6,}\}"""            # Java byte[]{...}
    r"""|\[\s*(?:0x[0-9a-fA-F]{2}\s*,?\s*){4,}\]"""        # [0x.., ...] array
    r""")\s*$""",
    re.IGNORECASE,
)
# Cipher / crypto CONTEXT tokens: presence anywhere in the file gates the whole
# file; presence on a line marks a cipher-construction USE (for reuse counting).
_CRYPTO_CTX_RE = re.compile(
    r"Cipher\s*\(|createCipheriv|createCipher|createHmac|EVP_[A-Za-z]"
    r"|modes\.[A-Za-z]|algorithms\.[A-Za-z]|IvParameterSpec|SecretKeySpec"
    r"|\bAES\b|\bDES\b|TripleDES|Blowfish|\bARC4\b|\bRC4\b|ChaCha20|Fernet"
    r"|AESGCM|\bGCM\b|\bCBC\b|\bCTR\b|javax\.crypto|Crypto\.Cipher"
    r"|from\s+cryptography|import\s+crypto|require\(\s*['\"]crypto|nacl\.|libsodium",
    re.IGNORECASE,
)
# A line that CONSTRUCTS a cipher with an IV/nonce (for reuse counting).
_CIPHER_USE_RE = re.compile(
    r"modes\.(?:CBC|CTR|GCM|OFB|CFB|CCM)|createCipheriv|IvParameterSpec"
    r"|\bGCM\b|\bCBC\b|\bCTR\b|Cipher\s*\(",
    re.IGNORECASE,
)
# name = rhs  (also Go `name :=`); rejects ==/<=/>=/!= comparisons.
_ASSIGN_RE = re.compile(
    r"([A-Za-z_$][\w$]*)\s*(?::=|(?<![=!<>])=(?!=))\s*(.+)"
)
# Trailing line comment, stripped before the anchored const-literal test. The
# leading ``\s`` avoids clipping a ``#``/``//`` inside a tight literal.
_PY_COMMENT_RE = re.compile(r"\s+#.*$")
_C_COMMENT_RE = re.compile(r"\s+//.*$")


def _strip_trailing_comment(rhs: str, lang: str) -> str:
    pat = _PY_COMMENT_RE if lang in ("python", "ruby", "shell") else _C_COMMENT_RE
    return pat.sub("", rhs).strip()


@dataclass
class MaterialMisuse:
    """One detected crypto-material misuse fact (pre-flag)."""

    kind: str                 # CycloneDX relatedCryptoMaterial type
    var: str | None           # source variable name (None for inline)
    line: int                 # 1-based source line
    hardcoded: bool = False   # constant literal binding
    static_iv: bool = False   # constant IV/nonce reaching a cipher
    reused: bool = False      # same static IV/nonce feeds >=2 ciphers
    weak_rng: str | None = None  # offending non-crypto PRNG token, else None


def _rng_token(rhs: str) -> str | None:
    """Return the weak-RNG API token in ``rhs`` (secure sources excluded)."""
    if _SECURE_RNG_RE.search(rhs):
        return None
    m = _WEAK_RNG_RE.search(rhs)
    if not m:
        return None
    return m.group(0).rstrip("(").strip()


def _count_cipher_uses(lines: list[str], var: str) -> int:
    """How many cipher-construction lines reference ``var`` as an argument."""
    word = re.compile(rf"(?<![\w.]){re.escape(var)}(?![\w])")
    n = 0
    for line in lines:
        if _CIPHER_USE_RE.search(line) and word.search(line):
            n += 1
    return n


def detect_material_misuse(text: str, lang: str) -> list[MaterialMisuse]:
    """Detect crypto-material misuse facts in one source file.

    Returns an empty list unless the file carries a crypto context — the
    load-bearing gate that keeps non-crypto randomness (a game die roll, a UI
    jitter) out of the crypto lane. ``lang`` is accepted for parity with the
    other detectors; the rule set is intentionally language-agnostic.
    """
    if not _CRYPTO_CTX_RE.search(text):
        return []

    lines = text.splitlines()
    facts: list[MaterialMisuse] = []
    seen_inline: set[int] = set()

    for idx, raw in enumerate(lines, start=1):
        m = _ASSIGN_RE.search(raw)
        if m:
            var = m.group(1)
            rhs = _strip_trailing_comment(m.group(2).strip(), lang)
            kind = _material_kind(var)
            if kind is not None:
                rng = _rng_token(rhs)
                if rng is not None:
                    facts.append(
                        MaterialMisuse(kind=kind, var=var, line=idx, weak_rng=rng)
                    )
                    continue
                if _CONST_LIT_RE.match(rhs):
                    if kind in ("initialization-vector", "nonce"):
                        uses = _count_cipher_uses(lines, var)
                        facts.append(
                            MaterialMisuse(
                                kind=kind, var=var, line=idx,
                                hardcoded=True, static_iv=uses >= 1,
                                reused=uses >= 2,
                            )
                        )
                    else:  # secret-key / salt / token constant literal
                        facts.append(
                            MaterialMisuse(
                                kind=kind, var=var, line=idx, hardcoded=True
                            )
                        )
                    continue

        # Inline weak RNG fed straight into a cipher construction on one line
        # (no named material var), e.g. `AES(random.randbytes(32))`.
        if (
            idx not in seen_inline
            and _CIPHER_USE_RE.search(raw)
            and (rng := _rng_token(raw)) is not None
        ):
            seen_inline.add(idx)
            facts.append(
                MaterialMisuse(
                    kind="secret-key", var=None, line=idx, weak_rng=rng
                )
            )
    return facts


__all__ = ["MaterialMisuse", "detect_material_misuse"]
