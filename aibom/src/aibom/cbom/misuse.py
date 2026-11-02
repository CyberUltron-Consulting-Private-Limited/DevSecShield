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
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

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
    r"|math/rand|(?<![\w.])mrand\.|rand\.Intn\s*\("  # Go math/rand
    r"|(?<![\w.>$])mt_rand\s*\(|(?<![\w.>$])lcg_value\s*\("  # PHP Mersenne Twister / LCG
    r"|\bRAND_pseudo_bytes\s*\(",       # OpenSSL: deprecated, not cryptographically strong
    re.IGNORECASE,
)
# OpenSSL's RAND_pseudo_bytes() is never a CSPRNG source (deprecated since 1.1.0 for exactly that reason), so a call
# is reported wherever it appears, not only when it feeds a material-named binding.
_ALWAYS_WEAK_RNG_RE = re.compile(r"\bRAND_pseudo_bytes\s*\(")
# A constant seed makes any PRNG, even SecureRandom's SHA1PRNG, replay the same stream (CWE-336):
# ``r.setSeed(123456789L)`` / ``setSeed("fixed".getBytes())`` in a file that uses SecureRandom.
_CONST_SEED_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*\.\s*setSeed\s*\(\s*(?:-?\d+[Ll]?|\"[^\"]*\"\s*\.\s*getBytes\s*\([^)]*\)|new\s+byte\s*\[\s*\]\s*\{[^}]*\})\s*\)"
)
_SECURE_RANDOM_RE = re.compile(r"\bSecureRandom\b")

# --------------------------------------------------------------------------- #
# Material produced by a FUNCTION: ``def token(): return random.choice(...)``,
# ``function token() { return Math.random()... }``, ``func Key(n int) []byte {
# ... b[i] = byte(rand.Intn(256)) ...; return b }``. The function NAME is the
# material-name gate (as a variable name is for a binding); the weak-RNG value
# must be what the function RETURNS (a ``return`` of the call, or a variable the
# call writes that is then returned). A UI helper (``jitter()``, ``shuffle()``,
# ``randomColor()``) has no material name and is never read.
# --------------------------------------------------------------------------- #
_FUNC_HEAD_RE = re.compile(
    r"^\s*(?:"
    r"def\s+(?:self\.)?(?P<py>[A-Za-z_]\w*[?!]?)\s*(?:\(|$)"                       # Python / Ruby
    r"|(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*&?\s*(?P<fn>[A-Za-z_$][\w$]*)\s*\("  # JS / PHP
    r"|(?:(?:public|private|protected|static|final|abstract)\s+)+function\s+&?(?P<php>\w+)\s*\("  # PHP method
    r"|(?:export\s+)?(?:const|let|var)\s+(?P<arrow>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?"
    r"(?:function\b|\([^)]*\)\s*(?::\s*[\w<>\[\]]+\s*)?=>|[A-Za-z_$][\w$]*\s*=>)"  # JS arrow / function expression
    r"|func\s+(?:\([^)]*\)\s*)?(?P<go>[A-Za-z_]\w*)\s*\("                          # Go
    r"|(?:(?:private|public|internal|override)\s+)*fun\s+(?P<kt>[A-Za-z_]\w*)\s*\("      # Kotlin
    r"|(?:(?:public|private|protected|internal|static|final|synchronized|override|virtual|async|unsafe)\s+)*"
    r"(?!(?:return|new|throw|else|await|yield|case|typeof|delete|echo|print|goto|if|while|for|switch|catch)\b)"
    r"[A-Za-z_][\w<>\[\],.?*]*\s+\**(?P<typed>[A-Za-z_]\w*)\s*\("
    r"(?:[^;=]*$|[^;={}]*\)\s*(?:throws\s+[\w.,\s]+)?\{)"                               # Java / C# / C / Kotlin
    r")"
)
# Material words a function name ENDS with (camelCase / snake_case words), and the material kind each produces.
_FUNC_MATERIAL = {
    "token": "token", "tokens": "token", "otp": "token", "nonce": "nonce", "iv": "initialization-vector",
    "salt": "salt", "secret": "secret-key", "password": "password", "passwd": "password", "pwd": "password",
    "passphrase": "password",
}
# ``...Key`` is only key material after a crypto qualifier (``secretKey``, ``generateKey``, ``aesKey``) or alone
# (``key()``, Go ``Key(n)``): ``cacheKey()`` / ``sortKey()`` / a React ``randomKey()`` list key are not secrets.
_KEY_QUALIFIERS = frozenset({
    "secret", "api", "enc", "encryption", "aes", "des", "hmac", "mac", "signing", "sign", "private", "master",
    "session", "crypto", "cipher", "generate", "gen", "new", "make", "create", "derive", "symmetric", "sym",
})
_SESSION_SUFFIX = frozenset({"id", "key", "token", "secret"})
_WORD_SPLIT = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")


def _function_material_kind(name: str) -> str | None:
    if name in ("k", "K"):  # ``def k(): return bytes.fromhex('...')`` (only literal-returning lanes read it)
        return "secret-key"
    words = [w.lower() for w in _WORD_SPLIT.findall(name.rstrip("?!"))]
    if not words:
        return None
    last = words[-1]
    if last in _FUNC_MATERIAL:
        return _FUNC_MATERIAL[last]
    if last == "key" and (len(words) == 1 or words[-2] in _KEY_QUALIFIERS):
        return "secret-key"
    if len(words) >= 2 and words[-2] == "session" and last in _SESSION_SUFFIX:
        return "token"
    return None


def _function_body(lines: list[str], head: int) -> range:
    """0-based line indexes of the body of the function whose header is ``lines[head]``."""
    header = lines[head]
    if "{" in header or (head + 1 < len(lines) and lines[head + 1].strip().startswith("{")):
        depth, started = 0, False
        for j in range(head, min(len(lines), head + 400)):
            for ch in lines[j]:
                if ch == "{":
                    depth += 1
                    started = True
                elif ch == "}":
                    depth -= 1
            if started and depth <= 0:
                return range(head, j + 1)
        return range(head, min(len(lines), head + 400))
    if re.search(r"=>\s*\S", header):  # expression-bodied arrow function
        return range(head, head + 1)
    indent = len(header) - len(header.lstrip())
    end = head + 1
    while end < len(lines):
        ln = lines[end]
        if ln.strip() and (len(ln) - len(ln.lstrip())) <= indent:
            break
        end += 1
    return range(head, end)


_ASSIGN_TARGET_RE = re.compile(r"([A-Za-z_$][\w$]*)\s*(?:\[[^\]]*\]\s*)?(?::=|\+=|(?<![=!<>])=(?!=))")


def _returned_rng_lines(lines: list[str], body: range) -> list[tuple[int, str]]:
    """(0-based line, rng token) for every weak-RNG call in ``body`` whose value the function returns."""
    out: list[tuple[int, str]] = []
    for i in body:
        line = lines[i]
        rng = _rng_token(line)
        if rng is None:
            continue
        m = _WEAK_RNG_RE.search(line)
        before = line[: m.start()] if m else line
        if re.search(r"\breturn\b", before) or (i == body.start and "=>" in before):
            out.append((i, rng))
            continue
        targets = [t.group(1) for t in _ASSIGN_TARGET_RE.finditer(before)]
        if not targets:
            continue
        var = targets[-1]
        word = re.compile(rf"\breturn\b[^;\n]*(?<![\w.$]){re.escape(var)}(?![\w$])")
        if any(word.search(lines[k]) for k in body if k > i) or word.search(line[m.end():] if m else ""):
            out.append((i, rng))
    return out


# A material-named function that RETURNS key bytes spelled in the source: a decoded literal (hex / base64), a byte
# array of 8+ bytes, or a plain string that looks like key material (16+ hex digits, or 16+ base64 characters with a
# digit) — a plain word (``return "username"`` from a sort-``key()``) is not key material.
_RETURNED_CONST_RE = re.compile(
    r"\breturn\s+(?:"
    r"b?[\"'](?:[0-9a-fA-F]{16,}|(?=[A-Za-z+/]*\d)[0-9A-Za-z+/]{16,}={0,2})[\"']\s*[;)]?\s*\}?\s*$"
    r"|(?:bytes\.fromhex|unhexlify|(?:base64\.)?b64decode|hex2bin|base64_decode)\(\s*b?[\"'][0-9A-Za-z+/]{16,}={0,2}[\"']\s*\)"
    r"|Buffer\.from\(\s*[\"'][0-9A-Za-z+/]{16,}={0,2}[\"']\s*,\s*[\"'](?:base64|hex)[\"']\s*\)"
    r"|\[\]byte\s*\{\s*(?:0x[0-9a-fA-F]{1,2}\s*,\s*){7,}"
    r"|new\s+byte\s*\[\s*\]\s*\{\s*(?:\(byte\)\s*)?(?:0x[0-9a-fA-F]{1,2}|-?\d{1,3})\s*(?:,\s*(?:\(byte\)\s*)?(?:0x[0-9a-fA-F]{1,2}|-?\d{1,3})\s*){7,}\}"
    r")"
)


# A key function that RETURNS the digest of a constant (``return hashlib.md5(b'corporate-pass').digest()``): the
# key is fixed by the source (a hardcoded key behind one hash), and the hash is its only derivation step.
_RETURNED_DIGEST_RE = re.compile(
    r"\breturn\s+(?:hashlib\.)?(?P<alg>md5|sha1|sha224|sha256|sha384|sha512)\(\s*b?[\"'][^\"'\n]{4,}[\"']\s*\)"
    r"\s*\.\s*(?:hex)?digest\(\s*\)",
    re.IGNORECASE,
)
_DIGEST_DISPLAY = {"md5": "MD5", "sha1": "SHA-1", "sha224": "SHA-224", "sha256": "SHA-256", "sha384": "SHA-384",
                   "sha512": "SHA-512"}


def _function_rng_facts(lines: list[str], lang: str = "") -> list[MaterialMisuse]:
    facts: list[MaterialMisuse] = []
    folded: list[str] | None = None if lang == "java" else lines  # Java constants folded on first need
    for idx, raw in enumerate(lines):
        m = _FUNC_HEAD_RE.match(raw)
        if not m:
            continue
        name = next(g for g in m.groups() if g)
        kind = _function_material_kind(name)
        if kind is None:
            continue
        body = _function_body(lines, idx)
        if name not in ("k", "K"):  # a one-letter name only counts with a literal value (below)
            for i, rng in _returned_rng_lines(lines, body):
                facts.append(MaterialMisuse(kind=kind, var=f"{name}()", line=i + 1, weak_rng=rng))
        if kind in ("secret-key", "salt", "initialization-vector", "nonce"):
            if folded is None:
                folded = _fold_java_lines(lines)
            for i in body:
                if _RETURNED_CONST_RE.search(folded[i]):
                    facts.append(MaterialMisuse(kind=kind, var=f"{name}()", line=i + 1, hardcoded=True))
                elif kind == "secret-key" and (dm := _RETURNED_DIGEST_RE.search(folded[i])):
                    facts.append(MaterialMisuse(kind=kind, var=f"{name}()", line=i + 1, hardcoded=True,
                                                derived_with=_DIGEST_DISPLAY[dm.group("alg").lower()]))
    return facts


def _fold_java_lines(lines: list[str]) -> list[str]:
    """Java lines with same-file String constant concatenations folded (``P1 + P2`` -> ``"0011...eeff"``)."""
    from aibom.cbom.detect import _fold_java_constants, _string_constants

    consts = _string_constants("\n".join(lines))
    return [_fold_java_constants(ln, consts) for ln in lines] if consts else lines
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
    derived_with: str | None = None  # the hash a hardcoded key is derived through (``MD5(constant)``)
    defined_at: str | None = None  # ``path:line`` of the configuration entry that holds the key value


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


def detect_material_misuse(
    text: str, lang: str, config_lookup: Callable[[str, str | None], Any] | None = None
) -> list[MaterialMisuse]:
    """Detect crypto-material misuse facts in one source file.

    The binding lane (a material-named VARIABLE) only runs when the file carries
    a crypto context — the load-bearing gate that keeps non-crypto randomness (a
    game die roll, a UI jitter) out of the crypto lane. Three narrower lanes need
    no file context because their own gate is already crypto-specific: a weak RNG
    a material-named FUNCTION returns (``token()``, ``generateSalt()``), OpenSSL's
    always-weak ``RAND_pseudo_bytes()``, and a constant ``setSeed`` on a
    SecureRandom. ``lang`` selects the comment syntax those lanes strip.

    Key material whose VALUE proves it (a decoded literal of 16+ bytes, a 128/192/256-bit hex string, a key
    function returning a literal or the digest of one, a key-named configuration entry the code reads, a key
    printed in a notebook output) is reported without the file gate. ``config_lookup(key, file_name)`` resolves a
    configuration entry (:meth:`aibom.cbom.project.ProjectIndex.config_value`).
    """
    facts = _binding_facts(text, lang) if _CRYPTO_CTX_RE.search(text) else []
    if lang == "powershell":  # a byte-literal key handed to a SecureString cmdlet
        from aibom.cbom.powershell import securestring_key_facts

        facts.extend(securestring_key_facts(text))
    covered = {f.line for f in facts}
    for fact in _context_free_facts(text, lang, config_lookup):
        if fact.line not in covered:
            covered.add(fact.line)
            facts.append(fact)
    return facts


def _context_free_facts(
    text: str, lang: str, config_lookup: Callable[[str, str | None], Any] | None = None
) -> list[MaterialMisuse]:
    from aibom.cbom.detect import _strip_line_comment, strip_noncode

    lines = [_strip_line_comment(ln, lang) for ln in strip_noncode(text).splitlines()]
    facts = _function_rng_facts(lines, lang)
    seen = {f.line for f in facts}
    for fact in (*_literal_key_facts(lines, lang), *_config_key_facts(lines, config_lookup),
                 *_notebook_output_facts(text)):
        if fact.line not in seen:
            seen.add(fact.line)
            facts.append(fact)
    for idx, line in enumerate(lines, start=1):
        if idx not in seen and _ALWAYS_WEAK_RNG_RE.search(line):
            seen.add(idx)
            facts.append(MaterialMisuse(kind="unknown", var=None, line=idx, weak_rng="RAND_pseudo_bytes"))
    if _SECURE_RANDOM_RE.search(text):
        for idx, line in enumerate(lines, start=1):
            m = _CONST_SEED_RE.search(line)
            if m and idx not in seen:
                seen.add(idx)
                facts.append(MaterialMisuse(kind="seed", var=m.group(1), line=idx, hardcoded=True,
                                            weak_rng="setSeed(constant)"))
    return sorted(facts, key=lambda f: f.line)


def _binding_facts(text: str, lang: str) -> list[MaterialMisuse]:
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


# --------------------------------------------------------------------------- #
# Key material proven by its VALUE (no crypto-context gate needed): the shape of the literal is the evidence.
# --------------------------------------------------------------------------- #
_HEX_KEY_RE = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{48}|[0-9a-fA-F]{64})$")
# A literal decoded into bytes in the binding itself: Python / Java / Go / Node decoders.
_DECODE_CALL_RE = re.compile(
    r"(?:(?:base64\.)?(?:urlsafe_|standard_)?b64decode|bytes\.fromhex|bytearray\.fromhex"
    r"|(?:binascii\.)?(?:unhexlify|a2b_hex|a2b_base64)|Hex\.decode(?:Hex)?|DatatypeConverter\.parse(?:Hex|Base64)Binary"
    r"|Base64\.(?:getDecoder|getUrlDecoder|getMimeDecoder)\(\)\.decode|Buffer\.from|hex\.DecodeString"
    r"|base64\.(?:Std|URL|RawStd|RawURL)Encoding\.DecodeString)\(\s*b?[\"']([A-Za-z0-9+/=_-]{16,})[\"']"
)
_STR_PIECE_RE = re.compile(r"""^\s*b?(["'])([^"'\\]*)\1\s*""")
# Names that end in ``key`` without being secret key material.
_NOT_SECRET_KEY = re.compile(
    r"cache|sort|primary|foreign|partition|idempoten|lookup|index|field|column|row|hash|etag|public|pub_|"
    r"dedup|unique|registry|object|bucket|redis|map_|dict|lock|group|routing|license|api_?key", re.I)


def _strict_key_name(var: str) -> bool:
    if var in ("k", "K"):
        return True
    return _material_kind(var) == "secret-key" and not _NOT_SECRET_KEY.search(var)


def _decoded_len(value: str) -> int:
    import base64
    import binascii

    if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", value):
        return len(value) // 2
    try:
        alt = b"-_" if ("-" in value or "_" in value) else None
        return len(base64.b64decode(value + "=" * (-len(value) % 4), altchars=alt, validate=True))
    except (binascii.Error, ValueError):
        return 0


def _hex_key_like(value: str) -> bool:
    """A 128/192/256-bit key spelled in hex, not a run of one digit."""
    return bool(_HEX_KEY_RE.match(value)) and len(set(value.lower())) >= 8


def _joined_literal(pieces: list[str]) -> str | None:
    """``b'0011' b'2233'`` (adjacent literals, Python implicit concatenation) -> ``'00112233'``."""
    text = " ".join(pieces).strip().rstrip(";").strip()
    out: list[str] = []
    while text:
        m = _STR_PIECE_RE.match(text)
        if not m:
            return None
        out.append(m.group(2))
        text = text[m.end():]
    return "".join(out) or None


_KEYISH_LINE = re.compile(r"(?i:key|secret)|\b[kK]\s*[:=]")


def _literal_key_facts(lines: list[str], lang: str) -> list[MaterialMisuse]:
    """A key-named binding (``KEY``, ``aes_key``, ``K``) whose value is a decoded literal of 16+ bytes, or a
    128/192/256-bit hex string (also split over adjacent literals or lines inside parentheses)."""
    facts: list[MaterialMisuse] = []
    idx = 0
    while idx < len(lines):
        raw = lines[idx]
        idx += 1
        if not _KEYISH_LINE.search(raw):
            continue  # every name this lane accepts contains "key" / "secret" or is ``k`` / ``K``
        m = _ASSIGN_RE.search(raw)
        if not m or not _strict_key_name(m.group(1)):
            continue
        rhs = m.group(2).strip()
        line_no = idx
        dec = _DECODE_CALL_RE.search(rhs)
        if dec:
            if _decoded_len(dec.group(1)) >= 16:
                facts.append(MaterialMisuse(kind="secret-key", var=m.group(1), line=line_no, hardcoded=True))
            continue
        rhs = re.sub(r"\.getBytes\([^)]*\)", "", rhs).rstrip(";").strip()
        pieces = [rhs]
        if rhs == "(":  # ``KEY = (\n b'0011'\n b'2233'\n)``: the value starts on the next line
            pieces = []
            j = idx
            while j < len(lines) and j < idx + 16 and lines[j].strip() not in (")", "),", ");"):
                pieces.append(lines[j])
                j += 1
            line_no = idx + 1
        value = _joined_literal(pieces)
        if value is not None and _hex_key_like(value):
            facts.append(MaterialMisuse(kind="secret-key", var=m.group(1), line=line_no, hardcoded=True))
    return facts


_CONFIG_FILE_LIT_RE = re.compile(r"""["']([\w./-]+\.(?:properties|ya?ml|ini|cfg|conf))["']""")
# a configuration key named in code: ``'aes.key='`` (a line prefix), ``getProperty("aes.key")``, ``"${aes.key}"``
_CONFIG_KEY_LIT_RE = re.compile(r"""["'](?:\$\{)?([A-Za-z][\w-]*(?:\.[\w-]+)+)\}?=?["']""")


def _config_key_facts(
    lines: list[str], config_lookup: Callable[[str, str | None], Any] | None
) -> list[MaterialMisuse]:
    """Code that reads a key-named configuration entry whose value is key material (``line.startswith('aes.key=')``
    on ``keys.properties``): the key is hardcoded in the repository, one file away."""
    if config_lookup is None:
        return []
    named = {m.group(1).rsplit("/", 1)[-1] for ln in lines for m in _CONFIG_FILE_LIT_RE.finditer(ln)}
    file_name = next(iter(named)) if len(named) == 1 else None
    facts: list[MaterialMisuse] = []
    for no, line in enumerate(lines, start=1):
        for m in _CONFIG_KEY_LIT_RE.finditer(line):
            key = m.group(1)
            last = key.rsplit(".", 1)[-1]
            if not (_strict_key_name(last) or _strict_key_name(key.replace(".", "_").replace("-", "_"))):
                continue
            d = config_lookup(key, file_name)
            if d is None or not (_hex_key_like(d.value) or _decoded_len(d.value) in (16, 24, 32)):
                continue
            facts.append(MaterialMisuse(kind="secret-key", var=key, line=no, hardcoded=True, defined_at=d.where))
            break
    return facts


# A key printed by a notebook cell (``AES key = 0011...``) in its saved output (see :mod:`aibom.cbom.notebook`).
_OUTPUT_KEY_RE = re.compile(
    r"\b(?:[A-Za-z0-9_-]+[ _-])?key\s*[=:]\s*['\"]?(?P<v>[0-9a-fA-F]{32,64}|[A-Za-z0-9+/_-]{22,86}={0,2})(?![\w+/=])",
    re.IGNORECASE,
)


def _notebook_output_facts(text: str) -> list[MaterialMisuse]:
    from aibom.cbom.notebook import OUTPUT_PREFIX

    if OUTPUT_PREFIX not in text:
        return []
    facts: list[MaterialMisuse] = []
    for no, line in enumerate(text.split("\n"), start=1):
        if not line.startswith(OUTPUT_PREFIX):
            continue
        m = _OUTPUT_KEY_RE.search(line)
        if m and (_hex_key_like(m.group("v")) or _decoded_len(m.group("v")) in (16, 24, 32)):
            facts.append(MaterialMisuse(kind="secret-key", var="notebook output", line=no, hardcoded=True))
    return facts


__all__ = ["MaterialMisuse", "detect_material_misuse"]
