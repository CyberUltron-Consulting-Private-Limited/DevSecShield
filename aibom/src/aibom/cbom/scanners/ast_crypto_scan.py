"""CBOM scanner (C1): a true **Python AST** crypto-API scanner with a data-driven
detection-rule model.

Where :mod:`aibom.cbom.scanners.algorithm_scan` matches crypto on a *single line*
with regular expressions, this scanner parses each ``.py`` file into an abstract
syntax tree and binds the algorithm + its parameters from the **call's arguments**
— the technique IBM CBOMkit's Sonar-Cryptography engine implements with a
detection-rule DSL + per-language AST translators (clean-room: we studied the
*behavior* of "the entry-point symbol fixes the primitive context, the arguments
supply the parameters" — ledger row 1 — and wrote our own original AST resolver,
copying no source/DSL).

The AST buys three things a flat line-regex cannot:

* **cross-statement value following** — ``bits = 3072`` then
  ``rsa.generate_private_key(key_size=bits)`` resolves to ``RSA-3072`` (the regex
  sees only the *name* ``bits``);
* **nested-call argument binding** — ``Cipher(algorithms.AES(k), modes.CBC(iv))``
  resolves AES + CBC + the IV literal from the nested calls, and ``padding.OAEP``
  passed to ``.encrypt(...)`` binds to the RSA asset in the same scope;
* **related-crypto-material from literals** — a literal IV / nonce / salt bound to
  a cipher mode or KDF is inventoried as a related-crypto-material asset.

Lane discipline (EMIT only — never score / flag-weight / serialize):

* one ``crypto_asset`` (assetType=algorithm) per distinct (algorithm+params, file)
  usage, with ``crypto:`` detail incl. ``crypto:detectedBy`` (the library that
  fixed the context), ``crypto:detectionContext`` (the primitive role) and
  ``crypto:confidence``;
* one ``crypto_asset`` (assetType=related-crypto-material) per literal IV / nonce /
  salt bound to a crypto call (``crypto:materialKind`` only — the STATIC_IV /
  MISSING_SALT *verdicts* are C6).

To stay additive, this scanner emits the SAME ``crypto-algo-{name}-{file}``
bom-refs as the regex scanner; the pipeline de-duplicates by bom-ref, keeping the
richer (argument-bound) component. Weak-flagging is C5/C6, PQC grading is C7, the
CycloneDX serialization is C4.
"""

from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path

from aibom.cbom.files import FileWalk, decode_text, file_walk, read_bytes
from aibom.cbom.project import project_index
from aibom.cbom.registry import cbom_register
from aibom.cbom.rules import ALGORITHM_NORMALIZE, algo_info
from aibom.cbom.scanners.algorithm_scan import _display_name, _refine_key, _slug
from aibom.cbom.weakness import kdf_call_grade
from aibom.model.component import CryptoAssetComponent
from aibom.scan.registry import ScanContext, Scanner


def read_text_safely(path: Path) -> str | None:
    raw = read_bytes(path)
    return None if raw is None else decode_text(raw)


# Crypto module roots whose presence (as an import) gates the AST rules — a
# precision guard so a local ``generate_private_key`` in a non-crypto file is
# never mistaken for a crypto-API call.
_CRYPTO_IMPORT_ROOTS = frozenset(
    {"cryptography", "hashlib", "hmac", "ssl", "secrets", "nacl",
     "jwt", "jose", "crypto", "cryptodome", "openssl", "argon2"}
)

# --------------------------------------------------------------------------- #
# The clean-room detection-rule corpus. Each entry maps a resolved call SYMBOL
# (the last 1-2 dotted segments of the callee) to a rule. The symbol fixes the
# primitive *context*; the call ARGUMENTS supply the parameters. This is the seed
# of the data-driven ``CryptoRule`` model C14 generalizes rules.py into.
# --------------------------------------------------------------------------- #

# Direct one-shot digest functions (hashlib top-level). symbol -> algo key.
_DIGEST: dict[str, str] = {
    "hashlib.md5": "md5", "md5": "md5",
    "hashlib.sha1": "sha1", "sha1": "sha1",
    "hashlib.sha256": "sha256", "sha256": "sha256",
    "hashlib.sha384": "sha384", "sha384": "sha384",
    "hashlib.sha512": "sha512", "sha512": "sha512",
    "hashlib.sha3_256": "sha3_256", "sha3_256": "sha3_256",
    "hashlib.blake2b": "blake2b", "blake2b": "blake2b",
    "hashlib.blake2s": "blake2s", "blake2s": "blake2s",
}
# Dynamic digest: hashlib.new("sha256") — the algorithm is the first STR arg.
_DIGEST_DYNAMIC: frozenset[str] = frozenset({"hashlib.new", "new"})

# Symmetric primitive constructors (pyca ``ciphers.algorithms.*``). These appear
# as the FIRST argument of a ``Cipher(...)`` combiner (then their mode is the 2nd
# argument), or — rarely — standalone. symbol -> algo key.
_CIPHER_ALGO: dict[str, str] = {
    "algorithms.AES": "aes", "AES": "aes",
    "algorithms.AES128": "aes-128", "algorithms.AES256": "aes-256",
    "algorithms.TripleDES": "3des", "TripleDES": "3des",
    "algorithms.DES": "des",
    "algorithms.ARC4": "rc4", "ARC4": "rc4",
    "algorithms.Blowfish": "blowfish", "Blowfish": "blowfish",
    "algorithms.ChaCha20": "chacha20", "ChaCha20": "chacha20",
}
# Block-cipher / AEAD mode constructors (pyca ``ciphers.modes.*``). symbol -> token.
_MODE: dict[str, str] = {
    "modes.GCM": "GCM", "GCM": "GCM",
    "modes.CBC": "CBC", "CBC": "CBC",
    "modes.ECB": "ECB", "ECB": "ECB",
    "modes.CTR": "CTR", "CTR": "CTR",
    "modes.CFB": "CFB", "CFB": "CFB",
    "modes.OFB": "OFB", "OFB": "OFB",
    "modes.XTS": "XTS", "XTS": "XTS",
}
# Modes that carry a nonce (AEAD/counter) vs an IV (chaining). Drives the
# related-crypto-material kind when the mode's first argument is a literal.
_NONCE_MODES = frozenset({"GCM", "CTR", "CCM"})

_CIPHER = frozenset({"Cipher"})

# Asymmetric / key-establishment generators. symbol -> (algo key, context,
# key_size kwarg | None, reads_curve_from_arg0).
_KEYGEN: dict[str, tuple[str, str, str | None, bool]] = {
    "rsa.generate_private_key": ("rsa", "pke", "key_size", False),
    "dsa.generate_private_key": ("dsa", "signature", "key_size", False),
    "ec.generate_private_key": ("ecdsa", "signature", None, True),
    "ec.derive_private_key": ("ecdsa", "signature", None, True),
    "dh.generate_parameters": ("dh", "key-agree", "key_size", False),
    "X25519PrivateKey.generate": ("x25519", "key-agree", None, False),
    "Ed25519PrivateKey.generate": ("ed25519", "signature", None, False),
    "Ed448PrivateKey.generate": ("ed448", "signature", None, False),
}
# Key-derivation functions. symbol -> (algo key, context). iterations / salt are
# pulled from the keyword arguments.
_KDF: dict[str, tuple[str, str]] = {
    "PBKDF2HMAC": ("pbkdf2", "kdf"),
    "Scrypt": ("scrypt", "kdf"),
    "HKDF": ("hkdf", "kdf"),
    "HKDFExpand": ("hkdf", "kdf"),
    "hashlib.pbkdf2_hmac": ("pbkdf2", "kdf"),
    "pbkdf2_hmac": ("pbkdf2", "kdf"),
    "hashlib.scrypt": ("scrypt", "kdf"),
    "argon2.PasswordHasher": ("argon2", "kdf"),
    "PasswordHasher": ("argon2", "kdf"),
    "low_level.hash_secret": ("argon2", "kdf"),
    "hash_secret": ("argon2", "kdf"),
    "low_level.hash_secret_raw": ("argon2", "kdf"),
    "hash_secret_raw": ("argon2", "kdf"),
}
# Where each KDF call takes its parameters: property -> (keyword, positional index
# or None). The values are captured as written (SOW D3: KDF parameters); a
# password-based KDF's literal salt is a STATIC_SALT finding.
_KDF_PARAMS: dict[str, dict[str, tuple[str, int | None]]] = {
    "PBKDF2HMAC": {
        "length": ("length", None),
        "salt": ("salt", None),
        "iterations": ("iterations", None),
    },
    "Scrypt": {
        "length": ("length", None),
        "salt": ("salt", None),
        "n": ("n", None),
        "r": ("r", None),
        "p": ("p", None),
    },
    "HKDF": {"length": ("length", None), "salt": ("salt", None)},
    "HKDFExpand": {"length": ("length", None)},
    "pbkdf2_hmac": {
        "prf": ("hash_name", 0),
        "salt": ("salt", 2),
        "iterations": ("iterations", 3),
        "length": ("dklen", 4),
    },
    "scrypt": {
        "salt": ("salt", None),
        "n": ("n", None),
        "r": ("r", None),
        "p": ("p", None),
        "length": ("dklen", None),
    },
    "PasswordHasher": {
        "time_cost": ("time_cost", 0),
        "memory_cost": ("memory_cost", 1),
        "parallelism": ("parallelism", 2),
        "length": ("hash_len", 3),
        "salt_length": ("salt_len", 4),
        "variant": ("type", 6),
    },
    "hash_secret": {
        "salt": ("salt", 1),
        "time_cost": ("time_cost", 2),
        "memory_cost": ("memory_cost", 3),
        "parallelism": ("parallelism", 4),
        "length": ("hash_len", 5),
        "variant": ("type", 6),
    },
    "hash_secret_raw": {
        "salt": ("salt", 1),
        "time_cost": ("time_cost", 2),
        "memory_cost": ("memory_cost", 3),
        "parallelism": ("parallelism", 4),
        "length": ("hash_len", 5),
        "variant": ("type", 6),
    },
}
# A fixed salt defeats a PASSWORD-based KDF (CWE-760); HKDF's salt is optional and
# may be fixed (RFC 5869 3.1).
_PASSWORD_KDFS = frozenset({"pbkdf2", "scrypt", "argon2"})
_PROP_OF = {
    "iterations": "crypto:iterations",
    "length": "crypto:kdfLength",
    "n": "crypto:scryptN",
    "r": "crypto:scryptR",
    "p": "crypto:scryptP",
    "time_cost": "crypto:argon2TimeCost",
    "memory_cost": "crypto:argon2MemoryCost",
    "parallelism": "crypto:argon2Parallelism",
    "salt_length": "crypto:saltLength",
    "variant": "crypto:argon2Variant",
    "prf": "crypto:kdfPrf",
}
# Message authentication. symbol -> algo key.
_MAC: dict[str, str] = {
    "hmac.new": "hmac", "HMAC": "hmac",
}
# Padding schemes. symbol -> (padding name, scope kind). 'asym' binds to a
# pke/signature asset in the same scope; 'block' binds to a block-cipher asset.
_PADDING: dict[str, tuple[str, str]] = {
    "padding.OAEP": ("OAEP", "asym"),
    "padding.PKCS1v15": ("PKCS1v15", "asym"),
    "padding.PSS": ("PSS", "asym"),
    "padding.PKCS7": ("PKCS7", "block"),
    "padding.ANSIX923": ("ANSIX923", "block"),
}

# Named elliptic curves (the constructor passed to ``ec.generate_private_key``).
_CURVES = frozenset(
    {"SECP256R1", "SECP384R1", "SECP521R1", "SECP256K1", "SECP192R1",
     "BrainpoolP256R1", "BrainpoolP384R1", "BrainpoolP512R1"}
)


# --------------------------------------------------------------------------- #
# AST helpers
# --------------------------------------------------------------------------- #


def _callee_path(func: ast.expr) -> list[str]:
    """Dotted identifier chain of a call's callee, e.g. ``algorithms.AES`` ->
    ``["algorithms", "AES"]`` (attribute access on a non-name base is ignored)."""
    parts: list[str] = []
    node: ast.expr = func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    parts.reverse()
    return parts


def _symbols(func: ast.expr) -> tuple[str, ...]:
    """Candidate match keys for a callee: the last two segments joined, then the
    last one — so ``a.b.modes.GCM`` matches both ``modes.GCM`` and ``GCM``."""
    parts = _callee_path(func)
    if not parts:
        return ()
    if len(parts) >= 2:
        return (".".join(parts[-2:]), parts[-1])
    return (parts[-1],)


def _rule(func: ast.expr, table: dict):
    for sym in _symbols(func):
        if sym in table:
            return table[sym]
    return None


def _in(func: ast.expr, names) -> bool:
    return any(sym in names for sym in _symbols(func))


# Constant folding is bounded by what it may BUILD, not only by its operands (second
# review of #491, M-A): one line of a scanned file must never make the scanner allocate
# a huge value. Nothing larger than these is folded (the expression stays unresolved).
_FOLD_INT_LIMIT = 1 << 64  # every folded int: abs(value) < 2**64
_FOLD_TEXT_LIMIT = 4096  # every folded str / bytes: at most 4096 characters (no salt,
# IV or key literal is longer)
_FOLD_MAX_DEPTH = 32  # nested operators per expression


def _literal_value(
    node: ast.expr | None, consts: dict[str, object], depth: int = 0
) -> object | None:
    """Resolve a node to a constant value, following simple ``b"x" * n`` /
    ``a + b`` / ``2**14`` / ``1 << 14`` literal arithmetic and module/function-level
    name bindings (the cross-statement following a line-regex cannot do). Returns
    None if not a compile-time literal, or when folding would exceed the bounds above
    (an int of 64 bits or more, text over 4096 characters, operators nested deeper
    than 32)."""
    if node is None:
        return None
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return consts.get(node.id)
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):  # ``consts.ALG`` (another module)
        return consts.get(f"{node.value.id}.{node.attr}")
    if isinstance(node, ast.BinOp) and isinstance(
        node.op, (ast.Mult, ast.Add, ast.Pow, ast.LShift)
    ):
        if depth >= _FOLD_MAX_DEPTH:
            return None
        left = _literal_value(node.left, consts, depth + 1)
        right = _literal_value(node.right, consts, depth + 1)
        if left is None or right is None:
            return None
        return _fold(node.op, left, right)
    return None


def _fold_int(value: object) -> int | None:
    """``value`` when it is a plain int (not bool) below 2**64, else None."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if abs(value) < _FOLD_INT_LIMIT else None


def _fold(op: ast.operator, left: object, right: object) -> object | None:
    """``left <op> right`` for an int or a str / bytes, only when the result stays
    within the folding bounds; every size is checked BEFORE the value is built."""
    a, b = _fold_int(left), _fold_int(right)
    if a is not None and b is not None:
        if isinstance(op, (ast.Pow, ast.LShift)):
            # ``n=2**14`` / ``1 << 14`` (the cryptography docs' scrypt cost): a shift
            # or exponent of 0..64 on a base below 2**64 is at most 4,096 bits
            if not 0 <= b <= 64:
                return None
            result = a**b if isinstance(op, ast.Pow) else a << b
        else:
            result = a * b if isinstance(op, ast.Mult) else a + b
        return result if abs(result) < _FOLD_INT_LIMIT else None
    if isinstance(op, ast.Mult):
        # ``b"x" * n`` or ``n * b"x"``
        text, count = (left, b) if b is not None else (right, a)
        if not isinstance(text, (str, bytes)) or count is None:
            return None
        if len(text) * max(count, 0) > _FOLD_TEXT_LIMIT:
            return None
        return text * count
    if isinstance(op, ast.Add):
        if isinstance(left, str) and isinstance(right, str):
            if len(left) + len(right) > _FOLD_TEXT_LIMIT:
                return None
            return left + right
        if isinstance(left, bytes) and isinstance(right, bytes):
            if len(left) + len(right) > _FOLD_TEXT_LIMIT:
                return None
            return left + right
    return None


def _kwarg(call: ast.Call, name: str) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _arg(call: ast.Call, index: int) -> ast.expr | None:
    return call.args[index] if index < len(call.args) else None


def _has_crypto_import(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0].lower() in _CRYPTO_IMPORT_ROOTS:
                    return True
        elif (
            isinstance(node, ast.ImportFrom)
            and node.module
            and node.module.split(".")[0].lower() in _CRYPTO_IMPORT_ROOTS
        ):
            return True
    return False


def _collect_consts(
    tree: ast.AST, lines: dict[str, tuple[int, int]] | None = None
) -> dict[str, object]:
    """Module + function-level ``name = <literal>`` bindings, flattened; ``lines``
    (when given) receives where each name's literal was written: (line, column)."""
    consts: dict[str, object] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                value = _literal_value(node.value, consts)
                if value is not None:
                    consts[target.id] = value
                    if lines is not None:
                        lines[target.id] = (node.lineno, node.value.col_offset)
    return consts


def _collect_calls(node: ast.AST, scope: tuple[str, ...], out: list) -> None:
    """Every Call in the tree, in source (pre-)order, tagged with its
    enclosing-function scope key. Iterative: a deeply nested expression the parser
    accepts (a 2,000-term ``1+1+...``) must not overflow the Python stack."""
    stack: list[tuple[ast.AST, tuple[str, ...]]] = [
        (child, scope) for child in reversed(list(ast.iter_child_nodes(node)))
    ]
    while stack:
        current, current_scope = stack.pop()
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
            current_scope = current_scope + (current.name,)
        elif isinstance(current, ast.Call):
            out.append((current, current_scope))
        stack.extend(
            (child, current_scope)
            for child in reversed(list(ast.iter_child_nodes(current)))
        )


# --------------------------------------------------------------------------- #
# Per-usage records
# --------------------------------------------------------------------------- #


class _Asset:
    __slots__ = ("key", "name", "key_size", "mode", "curve", "primitive",
                 "context", "padding", "iterations", "scope", "location", "params",
                 "symbol", "calls")

    def __init__(self, key, name, key_size, mode, curve, primitive, context,
                 scope, location):
        self.key = key
        self.name = name
        self.key_size = key_size
        self.mode = mode
        self.curve = curve
        self.primitive = primitive
        self.context = context
        self.padding: str | None = None
        self.iterations: int | None = None
        self.params: dict[str, str] = {}  # KDF parameters as crypto:* properties
        self.symbol: str | None = None  # the callee that fixed it: its library
        # KDF call sites, one per call: (line, its crypto:* parameters, its callee)
        self.calls: list[tuple[int, dict[str, str], str | None]] = []
        self.scope = scope
        self.location = location


class _Material:
    __slots__ = ("kind", "location", "props", "line", "col")

    def __init__(self, kind, location, line=None, col=None):
        self.kind = kind
        self.location = location
        self.line: int | None = line  # a literal salt: the line that wrote it
        self.col: int | None = col  # ... and its 1-based column on that line
        # a static literal: crypto:staticSalt / staticIv, its length, usedBy
        self.props: dict[str, str] = {}


_LIBRARY = "pyca/cryptography"
SKIPPED_TOO_DEEP = "crypto:coverage:skippedPythonTooDeep"
_HASHLIB = "hashlib (stdlib)"
_HMAC = "hmac (stdlib)"


def _curve_name(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Call):
        for sym in _symbols(node.func):
            tail = sym.split(".")[-1]
            if tail in _CURVES:
                return tail
    return None


def _make_asset(key, key_size, mode, curve, context, scope, rel) -> _Asset | None:
    refined = _refine_key(key, key_size)
    info = algo_info(refined) or {}
    primitive = info.get("primitive", context)
    resolved_ks = key_size or info.get("key_size")
    name = _display_name(refined, key_size, mode)
    base = ALGORITHM_NORMALIZE.get(refined)
    if not base and not info:
        return None  # unknown token — never inventory a guess
    return _Asset(refined, name, resolved_ks, mode, curve, primitive, context,
                  scope, rel)


class TooDeepToParse(Exception):
    """A Python file whose syntax tree is too deep (or too large) to build: skipped and
    counted (``crypto:coverage:skippedPythonTooDeep``), never a failed scan."""


def _scan_file(
    path: Path, rel: str, text: str | None = None, external: dict | None = None
) -> tuple[list[_Asset], list[_Material]]:
    if text is None:
        text = read_text_safely(path)
    if text is None:
        return [], []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return [], []
    except (RecursionError, MemoryError) as exc:  # a 50,000-term ``1+1+...``
        raise TooDeepToParse(rel) from exc
    if not _has_crypto_import(tree):
        return [], []

    # constants imported from other project modules (``from .consts import ALG``), then this file's own
    consts = {name: d.value for name, d in (external or {}).items()}
    const_lines: dict[str, tuple[int, int]] = {}
    consts.update(_collect_consts(tree, const_lines))
    calls: list[tuple[ast.Call, tuple[str, ...]]] = []
    _collect_calls(tree, (), calls)

    # Pass 1: a Cipher combiner consumes its algorithm + mode sub-calls so they
    # are not also emitted standalone.
    consumed: set[int] = set()
    for call, _scope in calls:
        if _in(call.func, _CIPHER):
            algo_node = _arg(call, 0)
            mode_node = _arg(call, 1) or _kwarg(call, "mode")
            if isinstance(algo_node, ast.Call):
                consumed.add(id(algo_node))
            if isinstance(mode_node, ast.Call):
                consumed.add(id(mode_node))

    # Pass 2: collect padding facts per scope (a nested-call argument).
    pad_by_scope: dict[tuple[str, ...], list[tuple[str, str]]] = defaultdict(list)
    for call, scope in calls:
        pad = _rule(call.func, _PADDING)
        if pad:
            pad_by_scope[scope].append(pad)

    assets: dict[tuple[str, str], _Asset] = {}
    materials: dict[tuple[str, str, int, int], _Material] = {}

    def _emit_material(kind: str, line: int = 0, col: int = 0) -> _Material:
        """One material row per (kind, file); a literal salt gets a row per place it
        was written (line and column), so two salts in one file, even on one line,
        are two rows, each with its line."""
        return materials.setdefault(
            (kind, rel, line, col), _Material(kind, rel, line or None, col or None)
        )

    def _add_asset(asset: _Asset | None) -> _Asset | None:
        if asset is None:
            return None
        existing = assets.get((asset.name, rel))
        if existing is None:
            assets[(asset.name, rel)] = asset
            return asset
        return existing

    # Pass 3: emit assets + materials.
    for call, scope in calls:
        if id(call) in consumed:
            continue
        func = call.func

        if _in(func, _CIPHER):
            algo_node = _arg(call, 0)
            mode_node = _arg(call, 1) or _kwarg(call, "mode")
            algo_key = _rule(algo_node.func, _CIPHER_ALGO) if isinstance(
                algo_node, ast.Call) else None
            if not algo_key:
                continue
            mode = _rule(mode_node.func, _MODE) if isinstance(
                mode_node, ast.Call) else None
            asset = _add_asset(
                _make_asset(algo_key, None, mode, None, "cipher", scope, rel))
            # IV / nonce: a literal first argument of the mode constructor.
            if isinstance(mode_node, ast.Call) and mode:
                iv_node = _arg(mode_node, 0)
                iv = _literal_value(iv_node, consts)
                if isinstance(iv, (bytes, str)):
                    static = isinstance(iv_node, ast.Constant)
                    material = _emit_material(
                        "nonce" if mode in _NONCE_MODES else "initialization-vector",
                        iv_node.lineno if static and iv_node is not None else 0,
                        iv_node.col_offset + 1 if static and iv_node is not None else 0,
                    )
                    # an IV written into the call is static (a named constant is
                    # the misuse lane's: no double finding); its value is never
                    # recorded, only its length
                    if isinstance(iv_node, ast.Constant) and asset is not None:
                        material.props.update({
                            "crypto:staticIv": "true", "crypto:usedBy": asset.name,
                            "crypto:literalLength": str(len(iv)),
                        })
            continue

        algo_key = _rule(func, _CIPHER_ALGO)
        if algo_key:
            _add_asset(_make_asset(algo_key, None, None, None, "cipher", scope, rel))
            continue

        digest = _rule(func, _DIGEST)
        if digest:
            _add_asset(_make_asset(digest, None, None, None, "digest", scope, rel))
            continue
        if _in(func, _DIGEST_DYNAMIC):
            name = _literal_value(_arg(call, 0), consts)
            if isinstance(name, str):
                key = name.lower().replace("-", "").replace("_", "")
                from aibom.cbom.rules import LITERAL_ALGO_ALIASES

                canon = LITERAL_ALGO_ALIASES.get(key)
                if canon:
                    _add_asset(
                        _make_asset(canon, None, None, None, "digest", scope, rel))
            continue

        keygen = _rule(func, _KEYGEN)
        if keygen:
            base_key, context, ks_kw, reads_curve = keygen
            key_size = None
            if ks_kw:
                val = _literal_value(_kwarg(call, ks_kw), consts)
                if isinstance(val, int):
                    key_size = val
            curve = _curve_name(_arg(call, 0)) if reads_curve else None
            _add_asset(
                _make_asset(base_key, key_size, None, curve, context, scope, rel))
            continue

        kdf = _rule(func, _KDF)
        if kdf:
            base_key, context = kdf
            asset = _add_asset(
                _make_asset(base_key, None, None, None, context, scope, rel))
            if asset is not None:
                symbol = (_symbols(func) or (None,))[0]
                asset.symbol = asset.symbol or symbol
                params = _kdf_parameters(
                    call, func, base_key, asset, consts, const_lines, _emit_material
                )
                asset.calls.append((call.lineno, params, symbol))
            continue

        mac = _rule(func, _MAC)
        if mac:
            _add_asset(_make_asset(mac, None, None, None, "mac", scope, rel))
            continue

    # Pass 4: bind padding to the asset it parametrizes, within the same scope.
    for asset in assets.values():
        for pad_name, pad_kind in pad_by_scope.get(asset.scope, ()):
            if (pad_kind == "asym" and asset.primitive in ("pke", "signature")) or (
                pad_kind == "block" and asset.primitive == "block-cipher"
            ):
                asset.padding = pad_name

    # Pass 5: a KDF asset (one per algorithm and file) reports its weakest call's
    # parameter set, never a mix and never just the last call: legacy and modern
    # KDF code in one module is the migration case a CBOM must show.
    for asset in assets.values():
        if asset.calls:
            _settle_kdf(asset)

    return (
        sorted(assets.values(), key=lambda a: (a.name, a.location)),
        sorted(
            materials.values(),
            key=lambda m: (m.kind, m.location, m.line or 0, m.col or 0),
        ),
    )


def _param_node(call: ast.Call, keyword: str, index: int | None) -> ast.expr | None:
    node = _kwarg(call, keyword)
    if node is None and index is not None:
        node = _arg(call, index)
    return node


def _prf_name(node: ast.expr | None, consts: dict[str, object]) -> str | None:
    """The PRF of a PBKDF2 / HKDF: ``hashes.SHA256()`` / ``"sha256"`` -> HMAC-SHA256."""
    if isinstance(node, ast.Call):
        tail = _callee_path(node.func)[-1:] or [""]
        name = tail[0]
    else:
        value = _literal_value(node, consts)
        name = value if isinstance(value, str) else ""
    digest = name.upper().replace("_", "").replace("-", "")
    return f"HMAC-{digest}" if digest.startswith(("SHA", "MD5", "BLAKE")) else None


def _add_to_list(props: dict[str, str], key: str, value: str) -> None:
    items = [v for v in (props.get(key) or "").split(",") if v]
    if value not in items:
        items.append(value)
    props[key] = ",".join(items)


def _kdf_parameters(
    call, func, base_key, asset, consts, const_lines, emit_material
) -> dict[str, str]:
    """One KDF call's parameters (iterations, output length, salt length, scrypt
    n/r/p, Argon2 costs and variant, the PRF) as ``crypto:*`` properties. A literal
    salt of a password-based KDF becomes a static-salt material (its length and the
    line that wrote it, never its value)."""
    params: dict[str, str] = {}
    tails = [sym.split(".")[-1] for sym in _symbols(func)]
    spec = next((_KDF_PARAMS[t] for t in tails if t in _KDF_PARAMS), {})
    prf = _prf_name(_kwarg(call, "algorithm"), consts) if "prf" not in spec else None
    for name, (keyword, index) in spec.items():
        node = _param_node(call, keyword, index)
        if node is None:
            continue
        if name == "prf":
            prf = _prf_name(node, consts)
            continue
        value = _literal_value(node, consts)
        if name == "salt":
            if isinstance(value, (bytes, str)):
                params["crypto:saltLength"] = str(len(value))
                # where the literal is written: the constant's binding, else the
                # argument itself (line, 1-based column)
                line, col = (
                    const_lines.get(node.id, (node.lineno, node.col_offset))
                    if isinstance(node, ast.Name)
                    else (node.lineno, node.col_offset)
                )
                material = emit_material("salt", line, col + 1)
                if base_key in _PASSWORD_KDFS:
                    material.props["crypto:staticSalt"] = "true"
                    _add_to_list(material.props, "crypto:usedBy", asset.name)
                    material.props["crypto:literalLength"] = str(len(value))
            continue
        if name == "variant" and isinstance(node, ast.Attribute):
            params[_PROP_OF[name]] = f"Argon2{node.attr.lower()}"
            continue
        if isinstance(value, int) and not isinstance(value, bool):
            params[_PROP_OF[name]] = str(value)
    # only a KDF built on a PRF has one (PBKDF2, HKDF); scrypt and Argon2 take no hash
    # argument, so a stray
    # ``algorithm=`` keyword on them names no PRF (staging QA Q2-11)
    if prf and base_key not in ("scrypt", "argon2", "bcrypt"):
        params["crypto:kdfPrf"] = prf
    if base_key == "argon2" and "crypto:argon2Variant" not in params:
        params["crypto:argon2Variant"] = "Argon2id (library default)"
    return params


def _kdf_cost(key: str, params: dict[str, str]) -> float:
    """Raw cost of one call (lower = weaker), the tie-break between calls the OWASP
    tables cannot grade (e.g. only Argon2's memory is known); unreadable ranks last."""

    def num(prop: str) -> float | None:
        raw = params.get(prop, "")
        return float(raw) if raw.isdigit() else None

    if key == "pbkdf2":
        cost = num("crypto:iterations")
    elif key == "scrypt":
        cost = num("crypto:scryptN")
    elif key == "argon2":
        memory, time = num("crypto:argon2MemoryCost"), num("crypto:argon2TimeCost")
        cost = memory * time if memory is not None and time is not None else memory
    else:
        cost = None
    return float("inf") if cost is None else cost


def _weakness_rank(key: str, line: int, params: dict[str, str]) -> tuple:
    """Sort key of one KDF call, weakest first (second review of #491, M-B): its grade
    (below NIST, below OWASP, compliant; ungraded last), then its cost as a fraction
    of the OWASP minimum for its OWN PRF / pair (``weakness.kdf_call_grade``, the one
    table the finding also uses), then the raw cost, then the line. So SHA-256 at
    300,000 iterations ranks below SHA-512 at 210,000, and SHA-1 at 1,000,000 below
    SHA-256 at 600,000."""
    graded = kdf_call_grade(key, params)
    if graded is None:
        return (1, float("inf"), _kdf_cost(key, params), line)
    grade, ratio = graded
    return (-grade, ratio, _kdf_cost(key, params), line)


def _settle_kdf(asset: _Asset) -> None:
    """The asset's parameters and library are its weakest call's (ties: the first
    call); with several calls every call's parameters are listed by line
    (``crypto:kdfCalls``)."""
    line, weakest, symbol = min(
        asset.calls, key=lambda c: _weakness_rank(asset.key, c[0], c[1])
    )
    asset.params = dict(weakest)
    # the row names the library of the call it reports (second review n-a)
    asset.symbol = symbol or asset.symbol
    raw = weakest.get("crypto:iterations", "")
    asset.iterations = int(raw) if raw.isdigit() else None
    if len(asset.calls) > 1:
        asset.params["crypto:kdfWeakestLine"] = str(line)
        asset.params["crypto:kdfCalls"] = " | ".join(
            f"L{n} "
            + (
                " ".join(
                    f"{k.split(':', 1)[1]}={v}" for k, v in sorted(params.items())
                )
                or "library defaults"
            )
            for n, params, _symbol in sorted(asset.calls, key=lambda c: c[0])
        )


def _iter_py_files(walk: FileWalk) -> list[Path]:
    # a notebook is read as its code cells (see :mod:`aibom.cbom.notebook`)
    return walk.files(lambda p: p.suffix in (".py", ".ipynb"))


def _library_for(
    context: str, key: str | None = None, symbol: str | None = None
) -> str:
    if symbol and symbol.split(".")[0] == "hashes":  # pyca ``hashes.SHA256()``
        return _LIBRARY
    if context == "digest":
        return _HASHLIB
    if context == "mac":
        return _HMAC
    if key == "argon2":
        return "argon2-cffi"
    if symbol and symbol.startswith("hashlib."):
        return _HASHLIB
    return _LIBRARY


@cbom_register
class AstCryptoScanner(Scanner):
    """Python-AST crypto-API scanner (C1). Runs before the regex scanner
    (``order`` 8 < 10) so its argument-bound components are the ones the pipeline
    keeps when bom-refs collide."""

    name = "crypto_ast"
    order = 8
    level = 1

    def scan(self, ctx: ScanContext) -> None:
        walk = file_walk(ctx)
        too_deep: list[str] = []
        for path in _iter_py_files(walk):
            rel = walk.rel(path)
            text = walk.read_text(path)
            if text is None:
                continue
            external = project_index(ctx).scope_for(rel, "python", text)
            try:
                assets, materials = _scan_file(path, rel, text, external)
            except (TooDeepToParse, RecursionError):
                # one pathological file never fails the scan: it is skipped and named
                too_deep.append(rel)
                continue
            self._emit(ctx, assets, materials)
        if too_deep:
            ctx.properties[SKIPPED_TOO_DEEP] = str(len(too_deep))
            ctx.properties[SKIPPED_TOO_DEEP + "Files"] = ",".join(sorted(too_deep)[:20])

    @staticmethod
    def _emit(
        ctx: ScanContext, assets: list[_Asset], materials: list[_Material]
    ) -> None:
        """One file's components: its algorithm rows, then its material rows."""
        for asset in assets:
            props: dict[str, str] = {
                "crypto:assetType": "algorithm",
                "crypto:primitive": asset.primitive,
                "crypto:detectedBy": _library_for(
                    asset.context, asset.key, asset.symbol
                ),
                "crypto:detectionContext": asset.context,
                "crypto:detectionMethod": "ast",
                "crypto:confidence": "high",
                "discovery:source": asset.location,
            }
            info = algo_info(asset.key) or {}
            if "strength" in info:
                props["crypto:strength"] = info["strength"]
            props["crypto:quantumVulnerable"] = str(
                bool(info.get("quantum_vulnerable", False))
            ).lower()
            if asset.key_size:
                props["crypto:keySize"] = str(asset.key_size)
            if asset.mode:
                props["crypto:mode"] = asset.mode
            if asset.curve:
                props["crypto:curve"] = asset.curve
            if asset.padding:
                props["crypto:padding"] = asset.padding
            if asset.iterations:
                props["crypto:iterations"] = str(asset.iterations)
            props.update(asset.params)
            if asset.calls:
                # located at its calls (the occurrence pass would take the first
                # line naming it, e.g. an ``except ImportError: PBKDF2HMAC = None``)
                lines = sorted({n for n, _params, _symbol in asset.calls})
                # several calls: the row points at the weakest one (its parameters)
                props["crypto:line"] = asset.params.get(
                    "crypto:kdfWeakestLine", str(lines[0])
                )
                props["crypto:occurrences"] = ",".join(str(n) for n in lines)
            ctx.add_component(
                CryptoAssetComponent(
                    bom_ref=f"crypto-algo-{_slug(asset.name)}-{_slug(asset.location)}",
                    name=asset.name,
                    properties=props,
                )
            )

        # literals of one kind written on one line
        shared: dict[tuple[str, str, int], int] = defaultdict(int)
        for material in materials:
            if material.line:
                shared[(material.kind, material.location, material.line)] += 1
        for material in materials:
            mprops = {
                "crypto:assetType": "related-crypto-material",
                "crypto:materialKind": material.kind,
                "crypto:detectionMethod": "ast",
                "discovery:source": material.location,
                **material.props,
            }
            suffix = ""
            where = material.location
            if material.line:  # a literal salt: its own row, at its own place
                suffix = f"-l{material.line}c{material.col or 0}"
                mprops["crypto:line"] = str(material.line)
                mprops["crypto:occurrences"] = str(material.line)
                where = f"{material.location}:{material.line}"
                if shared[(material.kind, material.location, material.line)] > 1:
                    # two literals on one line: the column tells them apart
                    mprops["crypto:column"] = str(material.col)
                    where += f":{material.col}"
            ctx.add_component(
                CryptoAssetComponent(
                    bom_ref=(
                        f"crypto-material-{_slug(material.kind)}-"
                        f"{_slug(material.location)}{suffix}"
                    ),
                    # a literal's row names its line (and column when another
                    # literal shares it): rows a reader can tell apart
                    name=f"{material.kind} ({where})",
                    properties=mprops,
                )
            )


__all__ = ["AstCryptoScanner"]
