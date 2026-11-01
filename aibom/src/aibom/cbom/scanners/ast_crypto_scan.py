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
from typing import Any

from aibom.cbom.registry import cbom_register
from aibom.cbom.rules import ALGORITHM_NORMALIZE, algo_info
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

# Crypto module roots whose presence (as an import) gates the AST rules — a
# precision guard so a local ``generate_private_key`` in a non-crypto file is
# never mistaken for a crypto-API call.
_CRYPTO_IMPORT_ROOTS = frozenset(
    {"cryptography", "hashlib", "hmac", "ssl", "secrets", "nacl",
     "jwt", "jose", "crypto", "cryptodome", "openssl"}
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


def _literal_value(node: ast.expr | None, consts: dict[str, object]) -> object | None:
    """Resolve a node to a constant value, following simple ``b"x" * n`` /
    ``a + b`` literal arithmetic and module/function-level name bindings (the
    cross-statement following a line-regex cannot do). Returns None if not a
    compile-time literal."""
    if node is None:
        return None
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return consts.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mult, ast.Add)):
        left: Any = _literal_value(node.left, consts)
        right: Any = _literal_value(node.right, consts)
        if left is None or right is None:
            return None
        try:
            return left * right if isinstance(node.op, ast.Mult) else left + right
        except (TypeError, ValueError):
            return None
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


def _collect_consts(tree: ast.AST) -> dict[str, object]:
    """Module + function-level ``name = <literal>`` bindings, flattened."""
    consts: dict[str, object] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                value = _literal_value(node.value, consts)
                if value is not None:
                    consts[target.id] = value
    return consts


def _collect_calls(node: ast.AST, scope: tuple[str, ...], out: list) -> None:
    """Every Call in the tree, tagged with its enclosing-function scope key."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _collect_calls(child, scope + (child.name,), out)
        else:
            if isinstance(child, ast.Call):
                out.append((child, scope))
            _collect_calls(child, scope, out)


# --------------------------------------------------------------------------- #
# Per-usage records
# --------------------------------------------------------------------------- #


class _Asset:
    __slots__ = ("key", "name", "key_size", "mode", "curve", "primitive",
                 "context", "padding", "iterations", "scope", "location")

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
        self.scope = scope
        self.location = location


class _Material:
    __slots__ = ("kind", "location")

    def __init__(self, kind, location):
        self.kind = kind
        self.location = location


_LIBRARY = "pyca/cryptography"
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


def _scan_file(path: Path, rel: str) -> tuple[list[_Asset], list[_Material]]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
    except (SyntaxError, ValueError, OSError):
        return [], []
    if not _has_crypto_import(tree):
        return [], []

    consts = _collect_consts(tree)
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
    materials: dict[tuple[str, str], _Material] = {}

    def _emit_material(kind: str) -> None:
        materials.setdefault((kind, rel), _Material(kind, rel))

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
                iv = _literal_value(_arg(mode_node, 0), consts)
                if isinstance(iv, (bytes, str)):
                    _emit_material(
                        "nonce" if mode in _NONCE_MODES else "initialization-vector")
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
                iters = _literal_value(_kwarg(call, "iterations"), consts)
                if isinstance(iters, int):
                    asset.iterations = iters
                salt = _literal_value(_kwarg(call, "salt"), consts)
                if isinstance(salt, (bytes, str)):
                    _emit_material("salt")
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

    return (
        sorted(assets.values(), key=lambda a: (a.name, a.location)),
        sorted(materials.values(), key=lambda m: (m.kind, m.location)),
    )


def _iter_py_files(root: Path):
    for p in sorted(root.rglob("*.py")):
        if any(part in _IGNORE_DIRS for part in p.relative_to(root).parts):
            continue
        if not p.is_file():
            continue
        try:
            if p.stat().st_size > _MAX_BYTES:
                continue
        except OSError:
            continue
        yield p


def _library_for(context: str) -> str:
    if context == "digest":
        return _HASHLIB
    if context == "mac":
        return _HMAC
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
        for path in _iter_py_files(ctx.root):
            rel = path.relative_to(ctx.root).as_posix()
            assets, materials = _scan_file(path, rel)

            for asset in assets:
                props: dict[str, str] = {
                    "crypto:assetType": "algorithm",
                    "crypto:primitive": asset.primitive,
                    "crypto:detectedBy": _library_for(asset.context),
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
                ctx.add_component(
                    CryptoAssetComponent(
                        bom_ref=f"crypto-algo-{_slug(asset.name)}-{_slug(asset.location)}",
                        name=asset.name,
                        properties=props,
                    )
                )

            for material in materials:
                ctx.add_component(
                    CryptoAssetComponent(
                        bom_ref=(
                            f"crypto-material-{_slug(material.kind)}-"
                            f"{_slug(material.location)}"
                        ),
                        name=f"{material.kind} ({material.location})",
                        properties={
                            "crypto:assetType": "related-crypto-material",
                            "crypto:materialKind": material.kind,
                            "crypto:detectionMethod": "ast",
                            "discovery:source": material.location,
                        },
                    )
                )


__all__ = ["AstCryptoScanner"]
