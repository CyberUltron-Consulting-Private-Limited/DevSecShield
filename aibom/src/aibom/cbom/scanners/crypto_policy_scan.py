"""CBOM scanner (C11): cryptographic **policy / config files**.

Clean-room re-implementation of the cbomkit-theia ``javasecurity`` +
``opensslconf`` plugin technique (behavior learned from public docs + the config
file formats — never their Go source). Where :mod:`~aibom.cbom.scanners.protocol_scan`
reads TLS/SSH/IPsec from *source*, this lane reads the environment's crypto
**policy artifacts** — the files that constrain which algorithms and protocol
versions a runtime is allowed to negotiate:

* **``java.security``** — the JDK master security file. We parse
  ``jdk.tls.disabledAlgorithms`` + ``jdk.certpath.disabledAlgorithms`` (the
  denied-algorithm policy) and ``crypto.policy`` (limited / unlimited JCE
  jurisdiction). The union of disabled algorithm tokens rides on the emitted
  asset as ``crypto:disabledAlgorithms`` so the compliance lane can cross-check
  *disabled-but-used* (an algorithm the environment forbids yet the code uses).
* **``openssl.cnf`` / ``openssl.conf``** — the OpenSSL system config. We parse
  ``MinProtocol`` / ``MaxProtocol`` (the negotiated TLS floor/ceiling) and
  ``CipherString`` / ``Ciphersuites`` (the allowed suites). A ``MinProtocol``
  below TLS 1.2 makes the emitted protocol asset ``crypto:strength=weak`` so the
  existing ``weak_finding`` predicate flags it exactly like a source-pinned TLS
  1.0 context.

Each policy file becomes ONE ``protocol`` ``crypto_asset`` (assetType=protocol,
protocolType=tls) carrying ``crypto:policySource`` (``java-security`` /
``openssl-config``) — the "protocol / policy crypto-asset" the story calls for,
kept schema-valid by reusing the ``protocol`` assetType (there is no ``policy``
assetType in CycloneDX 1.6). Lane discipline: this EMITS components only; the
disabled-but-used verdict is a graph-queried compliance check (C11 in
:mod:`aibom.cbom.compliance`), and CycloneDX serialization is C9's render lane.
"""

from __future__ import annotations

import re
from pathlib import Path

from aibom.cbom.files import FileWalk, file_walk
from aibom.cbom.registry import cbom_register
from aibom.model.component import CryptoAssetComponent
from aibom.scan.registry import ScanContext, Scanner

# Policy artifacts are matched by exact filename (they carry no code extension,
# so the source-file iterators never see them) — deterministic, no guessing.
_JAVA_SECURITY_NAMES = frozenset({"java.security"})
_OPENSSL_CONFIG_NAMES = frozenset({"openssl.cnf", "openssl.conf"})

# java.security keys we read (case-sensitive — the JDK spells them lowercase).
_JS_DISABLED_KEYS = (
    "jdk.tls.disabledAlgorithms",
    "jdk.certpath.disabledAlgorithms",
)
_JS_POLICY_KEY = "crypto.policy"

# openssl.cnf directives we read (matched case-insensitively).
_OSSL_DIRECTIVE = re.compile(
    r"^\s*(MinProtocol|MaxProtocol|CipherString|Ciphersuites)\s*=\s*(.+?)\s*$",
    re.IGNORECASE,
)


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "x"


def _named_files(walk: FileWalk, names: frozenset[str]) -> list[Path]:
    return walk.files(lambda p: p.name.lower() in names)


def _logical_lines(text: str) -> list[str]:
    """Comment-stripped, continuation-joined logical lines.

    ``java.security`` and ``openssl.cnf`` both use ``#`` line comments and a
    trailing ``\\`` line continuation (java.security wraps long
    ``disabledAlgorithms`` values). This folds continuations into one logical
    line so a wrapped value is parsed whole.
    """
    out: list[str] = []
    buf = ""
    for raw in text.splitlines():
        line = raw.split("#", 1)[0]
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            buf += stripped[:-1]
            continue
        buf += line
        out.append(buf)
        buf = ""
    if buf:
        out.append(buf)
    return out


def _split_list(value: str) -> list[str]:
    return [t.strip() for t in value.split(",") if t.strip()]


# --------------------------------------------------------------------------- #
# TLS-version normalization: an ``openssl.cnf`` MinProtocol / a java.security
# disabled version token -> a display label + weak flag (< TLS 1.2 or any SSL).
# --------------------------------------------------------------------------- #

_MIN_PROTOCOL = re.compile(r"TLSv1(?:\.([0-3]))?|SSLv([23])", re.IGNORECASE)


def _protocol_floor(value: str) -> tuple[str, bool] | None:
    """Parse a MinProtocol value (``TLSv1.2`` / ``TLSv1`` / ``SSLv3`` / ``None``).

    Returns ``(label, weak)`` where ``weak`` is True for TLS < 1.2 or any SSL;
    returns ``None`` when no floor is pinned (``None`` / unrecognized).
    """
    m = _MIN_PROTOCOL.search(value)
    if m is None:
        return None
    if m.group(2) is not None:  # SSLv2 / SSLv3
        return (f"SSLv{m.group(2)}", True)
    minor = int(m.group(1)) if m.group(1) is not None else 0  # bare TLSv1 == 1.0
    return (f"1.{minor}", minor < 2)


@cbom_register
class CryptoPolicyScanner(Scanner):
    name = "crypto_policy"
    order = 35  # after the protocol inventory (30), before the weak flagger (40)
    level = 1

    def scan(self, ctx: ScanContext) -> None:
        walk = file_walk(ctx)
        for path in _named_files(walk, _JAVA_SECURITY_NAMES):
            rel = walk.rel(path)
            text = walk.read_text(path)
            if text is None:
                continue
            self._emit_java_security(ctx, rel, text)
        for path in _named_files(walk, _OPENSSL_CONFIG_NAMES):
            rel = walk.rel(path)
            text = walk.read_text(path)
            if text is None:
                continue
            self._emit_openssl(ctx, rel, text)

    # --- java.security ---------------------------------------------------- #

    def _emit_java_security(self, ctx: ScanContext, rel: str, text: str) -> None:
        disabled: list[str] = []
        crypto_policy: str | None = None
        for line in _logical_lines(text):
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if key in _JS_DISABLED_KEYS:
                for tok in _split_list(value):
                    if tok not in disabled:
                        disabled.append(tok)
            elif key == _JS_POLICY_KEY and value:
                crypto_policy = value

        if not disabled and crypto_policy is None:
            return  # a java.security with no crypto directives — nothing to emit

        props: dict[str, str] = {
            "crypto:assetType": "protocol",
            "crypto:protocolType": "tls",
            "crypto:policySource": "java-security",
            "discovery:source": rel,
        }
        if disabled:
            props["crypto:disabledAlgorithms"] = ", ".join(disabled)
        if crypto_policy is not None:
            props["crypto:cryptoPolicy"] = crypto_policy
        ctx.add_component(
            CryptoAssetComponent(
                bom_ref=f"crypto-policy-java-security-{_slug(rel)}",
                name="Java Security Policy (java.security)",
                properties=props,
            )
        )

    # --- openssl.cnf ------------------------------------------------------ #

    def _emit_openssl(self, ctx: ScanContext, rel: str, text: str) -> None:
        min_proto: str | None = None
        max_proto: str | None = None
        ciphers: list[str] = []
        for line in _logical_lines(text):
            m = _OSSL_DIRECTIVE.match(line)
            if m is None:
                continue
            directive = m.group(1).lower()
            value = m.group(2).strip()
            if directive == "minprotocol":
                min_proto = value
            elif directive == "maxprotocol":
                max_proto = value
            elif directive in ("cipherstring", "ciphersuites"):
                for tok in value.split(":"):
                    tok = tok.strip()
                    if tok and tok not in ciphers:
                        ciphers.append(tok)

        if min_proto is None and max_proto is None and not ciphers:
            return  # an openssl.cnf with no TLS-policy directives

        props: dict[str, str] = {
            "crypto:assetType": "protocol",
            "crypto:protocolType": "tls",
            "crypto:policySource": "openssl-config",
            "discovery:source": rel,
        }
        name = "OpenSSL TLS Policy"
        floor = _protocol_floor(min_proto) if min_proto else None
        if floor is not None:
            label, weak = floor
            props["crypto:protocolVersion"] = label
            props["crypto:strength"] = "weak" if weak else "strong"
            name = f"OpenSSL TLS Policy {label}"
        if max_proto:
            props["crypto:maxProtocolVersion"] = max_proto
        if ciphers:
            props["crypto:cipherSuite"] = ", ".join(sorted(ciphers))
        ctx.add_component(
            CryptoAssetComponent(
                bom_ref=f"crypto-policy-openssl-{_slug(rel)}",
                name=name,
                properties=props,
            )
        )


__all__ = ["CryptoPolicyScanner"]
