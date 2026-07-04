"""CBOM scanner (C3): cryptographic **protocols** (TLS / SSH).

The third of the four CycloneDX 1.6 crypto-asset lanes (after C1's *algorithm*
and C2's *certificate / related-crypto-material* lanes). It inventories transport
crypto protocols in use, with the detail CycloneDX ``protocolProperties`` carries:

* **TLS / SSL** — a negotiated or pinned TLS context (``ssl.SSLContext``,
  ``PROTOCOL_TLS*``, ``set_ciphers``, ``wrap_socket``) plus any pinned protocol
  **version** (``TLSv1.0`` / ``ssl.TLSVersion.TLSv1`` / ``SSLv3`` …) and **cipher
  suites** (OpenSSL ``ECDHE-RSA-AES128-SHA`` or IANA ``TLS_..._WITH_...``);
* **SSH** — an SSH client/library usage (paramiko, ``SSHClient``, ``ssh://`` …).

Each detected protocol becomes ONE ``crypto_asset`` component per (type, file):
multiple version/cipher tokens in the same file collapse to a single protocol
asset carrying the **weakest** (lowest) pinned version, so the fixture's
``tls_config.py`` — which mentions ``TLSv1.0`` both as a string and as
``ssl.TLSVersion.TLSv1`` — yields exactly one TLS 1.0 asset, not two.

Lane discipline: this EMITS components only. The weak-protocol FLAG (TLS < 1.2)
is the scorer's job (C5/C8); the CycloneDX crypto-asset serialization is C4. The
inventory signal C5 reads is ``crypto:strength`` (``weak`` for TLS < 1.2 / any
SSL), mirroring the algorithm lane. Prose is never scanned: docstrings, block
comments and trailing line comments are blanked first, so a comment like
``# below the TLS 1.2 floor`` cannot inventory a phantom TLS 1.2 protocol.
"""

from __future__ import annotations

import re
from pathlib import Path

from aibom.cbom.registry import cbom_register
from aibom.cbom.rules import LANGUAGE_EXTENSIONS
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

# --------------------------------------------------------------------------- #
# Detection patterns. Versions normalize to a (family, minor) sort key so the
# weakest pinned version wins per file; SSL sorts below TLS (older / weaker).
# --------------------------------------------------------------------------- #

_F = re.IGNORECASE
# Pinned TLS version: ``TLSv1.0`` / ``TLSv1_2`` / ``ssl.TLSVersion.TLSv1`` (bare
# ``TLSv1`` => 1.0). Does NOT match ``PROTOCOL_TLS_CLIENT`` (no version digit).
_TLS_VERSION = re.compile(r"\bTLS[._]?v?1(?:[._]([0-3]))?\b", _F)
# Pinned SSL version: ``SSLv3`` / ``SSLv2`` (always weak).
_SSL_VERSION = re.compile(r"\bSSL[._]?v?([23])\b", _F)
# Generic TLS usage (no version pinned but a TLS context is configured).
_TLS_USE = re.compile(
    r"\bSSLContext\b|\bPROTOCOL_TLS\w*\b|\bPROTOCOL_SSL\w*\b|"
    r"\bcreate_default_context\b|\bwrap_socket\b|\bset_ciphers\b",
    _F,
)
# SSH usage (library / client / url). Narrow on purpose.
_SSH_USE = re.compile(
    r"\bparamiko\b|\bSSHClient\b|ssh://|\bOpenSSH\b|"
    r"golang\.org/x/crypto/ssh|\bNet::SSH\b|\bAsyncSSH\b",
    _F,
)
_SSH_VERSION = re.compile(r"\bSSH-(2\.0|1\.\d{1,2})\b")

# Cipher suites. OpenSSL hyphenated form (>=2 hyphen groups so a 2-token
# algorithm name like ``AES-256`` is NOT mistaken for a suite) + IANA form
# (requires a real cipher token / ``WITH`` so ``TLS_CIPHERS`` / ``TLS_CLIENT``
# variable names are NOT matched).
_CIPHER_OPENSSL = re.compile(
    r"\b(?:ECDHE|ECDH|DHE|DH|RSA|PSK|SRP|AECDH|ADH|AES|CAMELLIA|CHACHA20|SEED|IDEA)"
    r"(?:-[A-Z0-9]+){2,}\b"
)
_CIPHER_IANA = re.compile(
    r"\bTLS_(?:[A-Z0-9]+_)*WITH_[A-Z0-9_]+\b|\bTLS_(?:AES|CHACHA20|SM4)_[A-Z0-9_]+\b"
)

# Prose stripping (so comments / docstrings never inventory a protocol).
_TRIPLE_QUOTE = re.compile(r'""".*?"""|\'\'\'.*?\'\'\'', re.S)
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_PY_COMMENT = re.compile(r"#.*$", re.M)
# C-style ``//`` line comment, but keep ``://`` (so ``ssh://`` survives).
_C_LINE_COMMENT = re.compile(r"(?<!:)//.*$", re.M)


def _blank(match: re.Match[str]) -> str:
    return re.sub(r"[^\n]", " ", match.group(0))


def _strip_prose(text: str) -> str:
    text = _TRIPLE_QUOTE.sub(_blank, text)
    text = _BLOCK_COMMENT.sub(_blank, text)
    text = _PY_COMMENT.sub("", text)
    text = _C_LINE_COMMENT.sub("", text)
    return text


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "x"


def _iter_source_files(root: Path):
    for p in sorted(root.rglob("*")):
        if any(part in _IGNORE_DIRS for part in p.parts):
            continue
        if not p.is_file() or p.suffix.lower() not in LANGUAGE_EXTENSIONS:
            continue
        try:
            if p.stat().st_size > _MAX_BYTES:
                continue
        except OSError:
            continue
        yield p


class _TlsVersion:
    """A pinned TLS/SSL version: a sort key (family, minor) + display label."""

    __slots__ = ("sort", "label", "weak")

    def __init__(self, sort: tuple[int, int], label: str, weak: bool) -> None:
        self.sort = sort
        self.label = label
        self.weak = weak


def _tls_versions(code: str) -> list[_TlsVersion]:
    out: list[_TlsVersion] = []
    for m in _TLS_VERSION.finditer(code):
        minor = int(m.group(1)) if m.group(1) is not None else 0
        out.append(_TlsVersion((1, minor), f"1.{minor}", minor < 2))
    for m in _SSL_VERSION.finditer(code):
        ver = int(m.group(1))
        out.append(_TlsVersion((0, ver), f"SSLv{ver}", True))
    return out


@cbom_register
class ProtocolScanner(Scanner):
    name = "crypto_protocol"
    order = 30
    level = 1

    def scan(self, ctx: ScanContext) -> None:
        for path in _iter_source_files(ctx.root):
            rel = path.relative_to(ctx.root).as_posix()
            try:
                code = _strip_prose(path.read_text(encoding="utf-8", errors="ignore"))
            except OSError:
                continue
            self._emit_tls(ctx, rel, code)
            self._emit_ssh(ctx, rel, code)

    # --- TLS / SSL -------------------------------------------------------- #

    def _emit_tls(self, ctx: ScanContext, rel: str, code: str) -> None:
        versions = _tls_versions(code)
        if not versions and not _TLS_USE.search(code):
            return
        ciphers = sorted(
            {m.group(0) for m in _CIPHER_OPENSSL.finditer(code)}
            | {m.group(0) for m in _CIPHER_IANA.finditer(code)}
        )
        props: dict[str, str] = {
            "crypto:assetType": "protocol",
            "crypto:protocolType": "tls",
            "discovery:source": rel,
        }
        name = "TLS"
        if versions:
            weakest = min(versions, key=lambda v: v.sort)
            props["crypto:protocolVersion"] = weakest.label
            props["crypto:strength"] = "weak" if weakest.weak else "strong"
            name = f"TLS {weakest.label}"
        if ciphers:
            props["crypto:cipherSuite"] = ", ".join(ciphers)
        ctx.add_component(
            CryptoAssetComponent(
                bom_ref=f"crypto-protocol-tls-{_slug(rel)}", name=name, properties=props
            )
        )

    # --- SSH -------------------------------------------------------------- #

    def _emit_ssh(self, ctx: ScanContext, rel: str, code: str) -> None:
        if not _SSH_USE.search(code):
            return
        props: dict[str, str] = {
            "crypto:assetType": "protocol",
            "crypto:protocolType": "ssh",
            "discovery:source": rel,
        }
        name = "SSH"
        sver = _SSH_VERSION.search(code)
        if sver is not None:
            props["crypto:protocolVersion"] = sver.group(1)
            name = f"SSH {sver.group(1)}"
        ctx.add_component(
            CryptoAssetComponent(
                bom_ref=f"crypto-protocol-ssh-{_slug(rel)}", name=name, properties=props
            )
        )


__all__ = ["ProtocolScanner"]
