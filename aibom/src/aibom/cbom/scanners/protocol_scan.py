"""CBOM scanner (C3 + C5): cryptographic **protocols** (TLS / SSH / IPsec).

The third of the CycloneDX 1.6 crypto-asset lanes (after C1's *algorithm* and
C2's *certificate / related-crypto-material* lanes). It inventories transport
crypto protocols in use, with the detail CycloneDX ``protocolProperties`` carries:

* **TLS / SSL** — a negotiated or pinned TLS context (``ssl.SSLContext``,
  ``PROTOCOL_TLS*``, ``set_ciphers``, ``wrap_socket``) plus any pinned protocol
  **version** (``TLSv1.0`` / ``ssl.TLSVersion.TLSv1`` / ``SSLv3`` …) and **cipher
  suites** (OpenSSL ``ECDHE-RSA-AES128-SHA`` or IANA ``TLS_..._WITH_...``);
* **SSH** — an SSH client/library usage (paramiko, ``SSHClient``, ``ssh://`` …),
  with the pinned wire version (``SSH-2.0`` / ``SSH-1.5``);
* **IPsec / IKE** (C5) — strongSwan / libreswan config (``ipsec.conf`` /
  ``swanctl.conf`` / ``ipsec.secrets``) or source references, carrying the
  negotiated **IKE version** (``IKEv1`` / ``IKEv2``) and the transform / proposal
  tokens (``3des-md5-modp1024`` / ``aes256-sha256-modp3072``).

Each detected protocol becomes ONE ``crypto_asset`` component per (type, file):
multiple version/cipher tokens in the same file collapse to a single protocol
asset carrying the **weakest** (lowest) pinned version, so the fixture's
``tls_config.py`` — which mentions ``TLSv1.0`` both as a string and as
``ssl.TLSVersion.TLSv1`` — yields exactly one TLS 1.0 asset, not two.

Lane discipline: this EMITS components only + sets ``crypto:strength`` on the
protocol **version** (``weak`` for TLS < 1.2 / any SSL, SSH protocol 1.x, IKEv1).
The pure ``weak_finding`` predicate turns that into a ``WEAK_PROTOCOL`` flag and
C8 WEIGHTS it; the CycloneDX crypto-asset serialization is C9. The cipher-suite /
kex / transform *weakness catalog* (RC4/DES/modp1024 = SWEET32 / weak-DH) is a
separate predicate story (C13); C5 only CARRIES those tokens for it. Prose is
never scanned: docstrings, block comments and trailing line comments are blanked
first, so a comment like ``# below the TLS 1.2 floor`` cannot inventory a phantom
TLS 1.2 protocol.
"""

from __future__ import annotations

import re
from pathlib import Path

from aibom.cbom.registry import cbom_register
from aibom.cbom.rules import read_source, source_language
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
# SSH negotiated primitives — kex / host-key / cipher / MAC identifiers, as they
# appear in an ``ssh_config``/``sshd_config`` ``Ciphers``/``KexAlgorithms``/
# ``MACs``/``HostKeyAlgorithms`` line or a paramiko/asyncssh preferred-algorithm
# list. A curated allow-list (never a broad hyphen pattern) so it captures only
# real SSH algorithm tokens — the strong ones too, for inventory — and cannot
# mis-capture arbitrary hyphenated words. The C13 weakness predicate
# (:func:`aibom.cbom.weakness.cipher_suite_findings`) decides which are weak.
_SSH_ALGO = re.compile(
    r"\b(?:"
    # kex
    r"diffie-hellman-group(?:1|14|16|18|-exchange)(?:-sha(?:1|256|512))?|"
    r"curve25519-sha256(?:@libssh\.org)?|ecdh-sha2-nistp(?:256|384|521)|"
    r"sntrup761x25519-sha512(?:@openssh\.com)?|"
    # host keys
    r"ssh-rsa|ssh-dss|ssh-ed25519|rsa-sha2-(?:256|512)|"
    r"ecdsa-sha2-nistp(?:256|384|521)|"
    # ciphers
    r"(?:aes(?:128|192|256)|3des|blowfish|cast128|arcfour(?:128|256)?)"
    r"(?:-(?:cbc|ctr|gcm))?(?:@openssh\.com)?|arcfour|chacha20-poly1305@openssh\.com|"
    # MACs
    r"(?:hmac-(?:md5|sha1|sha2-256|sha2-512|ripemd160)|umac-(?:64|128))"
    r"(?:-etm)?(?:-96)?(?:@openssh\.com)?"
    r")\b",
    _F,
)

# IPsec / IKE. Config files are matched by name; source is matched by a narrow
# marker set (strongSwan/libreswan tooling, an explicit IKE version, or an
# ``ipsec`` reference). ESP/AH alone are too generic to key detection on.
_IPSEC_CONFIG_NAMES = frozenset(
    {"ipsec.conf", "ipsec.secrets", "swanctl.conf", "racoon.conf"}
)
_IPSEC_USE = re.compile(
    r"\bstrongswan\b|\blibreswan\b|\bcharon\b|\bracoon\b|\bIKEv[12]\b|"
    # strongSwan's legacy "stroke" interface only as a command ("ipsec stroke ...", "stroke up|down|statusall"):
    # a bare \bstroke\b matched every SVG/Recharts stroke= attribute in React charts.
    r"\bipsec\b|\bxfrm\b|\bipsec\s+stroke\b|\bstroke\s+(?:up|down|status|statusall|loglevel|listall)\b"
    # ipsec-tools' ``setkey`` only as the lowercase command (``setkey -f ...``): a
    # case-insensitive \bsetkey\b matched every Java/JS ``setKey(`` / ``.setkey(``
    # call (and POSIX crypt(3) ``setkey()``), which are not IPsec.
    r"|(?-i:(?<![.\w])setkey\b(?!\s*\())",
    _F,
)
# Negotiated IKE version: ``IKEv1`` / ``keyexchange=ikev2`` (bare token) — a
# config's ``version = 2`` line is a fallback used only inside a known IPsec file.
_IKE_VERSION = re.compile(r"\bIKEv([12])\b", _F)
_IKE_VERSION_CONF = re.compile(r"\bversion\s*=\s*([12])\b", _F)
# strongSwan / libreswan transform proposals: ``cipher-mac[-dhgroup]`` — e.g.
# ``3des-md5-modp1024``, ``aes256-sha256-modp3072``, ``aes256gcm16-sha256``.
_IPSEC_TRANSFORM = re.compile(
    r"\b(?:aes\w*|3des|des|null|chacha20\w*)-(?:sha\w*|md5|aesxcbc|poly1305)"
    r"(?:-(?:modp\d+|ecp\d+|x25519|curve25519))?\b",
    _F,
)

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
        if any(part in _IGNORE_DIRS for part in p.relative_to(root).parts):
            continue
        if not p.is_file() or source_language(p) is None:
            continue
        try:
            if p.stat().st_size > _MAX_BYTES:
                continue
        except OSError:
            continue
        yield p


def _iter_ipsec_configs(root: Path):
    """IPsec config files matched by name (``ipsec.conf`` / ``swanctl.conf`` …).

    These carry no code extension so :func:`_iter_source_files` skips them; the
    IPsec lane reads them directly for the IKE version + transform proposals.
    """
    for p in sorted(root.rglob("*")):
        if any(part in _IGNORE_DIRS for part in p.relative_to(root).parts):
            continue
        if not p.is_file() or p.name.lower() not in _IPSEC_CONFIG_NAMES:
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


# Pinned versions spelled as API constants the generic pattern cannot see (a letter or ``_`` glued to the version
# leaves no word boundary): Go ``tls.VersionTLS10`` / ``tls.VersionSSL30``, OpenSSL ``TLSv1_method()`` /
# ``TLSv1_1_client_method()`` / ``TLS1_VERSION`` / ``TLS1_1_VERSION`` / ``SSLv3_method()`` / ``SSL3_VERSION``.
_TLS_VERSION_API = re.compile(
    r"\bVersionTLS1([0-3])\b"
    r"|\bTLSv1(?:_([0-3]))?_(?:client_|server_)?method\b"
    r"|\bTLS1(?:_([0-3]))?_VERSION\b"
)
_SSL_VERSION_API = re.compile(r"\bVersionSSL30\b|\bSSLv3_(?:client_|server_)?method\b|\bSSL3_VERSION\b")


def _tls_versions(code: str) -> list[_TlsVersion]:
    out: list[_TlsVersion] = []
    for m in _TLS_VERSION.finditer(code):
        minor = int(m.group(1)) if m.group(1) is not None else 0
        out.append(_TlsVersion((1, minor), f"1.{minor}", minor < 2))
    for m in _TLS_VERSION_API.finditer(code):
        minor = int(next((g for g in m.groups() if g is not None), "0"))
        out.append(_TlsVersion((1, minor), f"1.{minor}", minor < 2))
    for _m in _SSL_VERSION_API.finditer(code):
        out.append(_TlsVersion((0, 3), "SSLv3", True))
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
                code = _strip_prose(read_source(path))
            except OSError:
                continue
            self._emit_tls(ctx, rel, code)
            self._emit_ssh(ctx, rel, code)
            # Source-level IPsec references (strongSwan/libreswan API, IKEv2 …).
            if _IPSEC_USE.search(code):
                self._emit_ipsec(ctx, rel, code, is_config=False)
        # Named IPsec config artifacts (ipsec.conf / swanctl.conf / …).
        for path in _iter_ipsec_configs(ctx.root):
            rel = path.relative_to(ctx.root).as_posix()
            try:
                code = _strip_prose(path.read_text(encoding="utf-8", errors="ignore"))
            except OSError:
                continue
            self._emit_ipsec(ctx, rel, code, is_config=True)

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
            version = sver.group(1)
            props["crypto:protocolVersion"] = version
            # SSH protocol 1.x is cryptographically broken (CVE-2001-0361);
            # SSH-2.0 is the current, strong wire protocol.
            props["crypto:strength"] = "weak" if version.startswith("1.") else "strong"
            name = f"SSH {version}"
        # Negotiated kex/host-key/cipher/MAC tokens (for the C13 weakness
        # predicate). Stored in the SAME crypto:cipherSuite bag as TLS suites /
        # IKE transforms so C9's cryptoRefArray emission stays uniform.
        algos = sorted({m.group(0) for m in _SSH_ALGO.finditer(code)})
        if algos:
            props["crypto:cipherSuite"] = ", ".join(algos)
        ctx.add_component(
            CryptoAssetComponent(
                bom_ref=f"crypto-protocol-ssh-{_slug(rel)}", name=name, properties=props
            )
        )

    # --- IPsec / IKE ------------------------------------------------------ #

    def _emit_ipsec(
        self, ctx: ScanContext, rel: str, code: str, *, is_config: bool
    ) -> None:
        props: dict[str, str] = {
            "crypto:assetType": "protocol",
            "crypto:protocolType": "ipsec",
            "discovery:source": rel,
        }
        name = "IPsec"

        ike = _IKE_VERSION.search(code)
        version_num = ike.group(1) if ike is not None else None
        if version_num is None and is_config:
            # A swanctl-style ``version = 2`` line — only trusted inside a known
            # IPsec config file, never in arbitrary source.
            conf = _IKE_VERSION_CONF.search(code)
            version_num = conf.group(1) if conf is not None else None
        if version_num is not None:
            props["crypto:protocolVersion"] = f"IKEv{version_num}"
            # IKEv1 is deprecated (RFC 9395); IKEv2 is the current, strong
            # keying protocol. Transform-level weakness (DES/MD5/modp1024) is
            # the C13 predicate's job — the version drives crypto:strength here.
            props["crypto:strength"] = "weak" if version_num == "1" else "strong"
            name = f"IPsec (IKEv{version_num})"

        transforms = sorted({m.group(0) for m in _IPSEC_TRANSFORM.finditer(code)})
        if transforms:
            props["crypto:cipherSuite"] = ", ".join(transforms)

        ctx.add_component(
            CryptoAssetComponent(
                bom_ref=f"crypto-protocol-ipsec-{_slug(rel)}",
                name=name,
                properties=props,
            )
        )


__all__ = ["ProtocolScanner"]
