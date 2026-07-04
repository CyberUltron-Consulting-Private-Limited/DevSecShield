#!/usr/bin/env python3
"""bench/cbom/normalize.py — bridge the CBOMkit + ours crypto vocabularies.

The CBOM benchmark compares OUR source-code crypto scanner against IBM's
``cbomkit-theia`` oracle. Both emit CycloneDX 1.6 ``cryptographic-asset``
components, but they detect crypto *differently* and label it *differently*:

* cbomkit-theia is a FILESYSTEM scanner — it extracts crypto from certificates,
  OpenSSL configs, keys and secrets it finds on disk (it explicitly does NOT do
  source-code scanning). So from a ``cert.pem`` it yields the bare algorithm
  families baked into the cert (``RSA``, ``SHA256``, the composite ``SHA256-RSA``
  signature algorithm) and the cert subject CN as the certificate name.
* OURS is a SOURCE-CODE scanner — it yields the parametrized algorithm usages it
  finds in the code (``RSA-2048``, ``AES-GCM``, ``AES-ECB``, ``TLS 1.0`` …) and
  names the certificate by its file (``cert.pem``).

A raw set-difference is therefore mostly vocabulary noise. We extract from each
tool a canonical set keyed by

    CANONICAL KEY = (canonical_name, asset_class)

so the diff compares *the same crypto asset*. NOT product code — lives only
under ``bench/cbom/``.

ASSET CLASSES (the shared vocabulary, = CycloneDX 1.6 crypto ``assetType`` plus
``secret``/``library`` for the non-crypto-asset components):

    algorithm | certificate | protocol | related-crypto-material | secret | library

CANONICALISATION (documented, applied so the two tools' labels collapse to one):
 * ``canon_name`` — lower-case; drop a parenthetical file annotation
   (``private-key (crypto_app.py)`` -> ``private-key``, ``hashlib (stdlib)`` ->
   ``hashlib``); collapse ``_``/space to ``-``; and remove a hyphen that sits
   BETWEEN A LETTER AND A DIGIT only (``SHA-256`` -> ``sha256``, ``RSA-2048`` ->
   ``rsa2048``, ``AES-128`` -> ``aes128``) while KEEPING a hyphen between two
   letter groups (``aes-gcm``, ``3des-cbc``, ``sha256-rsa`` stay). So cbomkit's
   ``SHA256`` and our ``SHA-256`` collapse to one key.
 * For a CERTIFICATE we key on its ``subjectName`` when present (both tools then
   agree on ``synthetic-crypto-app.test``), not the display name.
 * ``crypto_family_root`` — strip trailing key-size digits and cipher-mode
   tokens to the algorithm FAMILY (``rsa2048`` -> ``rsa``, ``aes-gcm`` -> ``aes``,
   ``3des-cbc`` -> ``3des``). Used by the diff to reconcile cbomkit's bare family
   pick (``RSA``) against our finer-grained usage (``RSA-2048``).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ASSET_CLASSES = {
    "algorithm",
    "certificate",
    "protocol",
    "related-crypto-material",
    "secret",
    "library",
}

# cipher block/stream modes — stripped to reach the algorithm family root.
_MODE_TOKENS = {
    "gcm", "ecb", "cbc", "cfb", "ofb", "ctr", "ccm", "xts", "siv", "ocb", "eax",
}
_SECRET_HINT = re.compile(
    r"(api[_-]?key|secret|token|credential|password|passwd)", re.IGNORECASE
)
# a hyphen between a letter and a digit (either order) — the only hyphen we drop.
_LETTER_DIGIT_DASH = re.compile(r"(?<=[a-z])-(?=\d)|(?<=\d)-(?=[a-z])")
_PAREN_SUFFIX = re.compile(r"\s*\([^)]*\)\s*$")


def canon_name(raw: str) -> str:
    """Lower-case; drop a trailing ``(...)`` annotation; collapse separators;
    fuse a letter-digit hyphen so ``SHA-256`` and ``SHA256`` are one key."""
    n = (raw or "").strip()
    n = re.sub(r"^pkg:[^/]+/", "", n)          # pkg:pypi/x -> x (defensive)
    n = _PAREN_SUFFIX.sub("", n)                # "private-key (file.py)" -> private-key
    low = n.lower().strip()
    low = re.sub(r"[\s_]+", "-", low)           # spaces / underscores -> hyphen
    low = re.sub(r"-{2,}", "-", low).strip("-")
    low = _LETTER_DIGIT_DASH.sub("", low)       # sha-256 -> sha256, rsa-2048 -> rsa2048
    return low


def crypto_family_root(name: str) -> str:
    """Strip trailing key-size digits + cipher-mode tokens to the family root.

    ``rsa2048`` -> ``rsa``; ``aes-gcm`` -> ``aes``; ``aes128-ecb`` -> ``aes``;
    ``3des-cbc`` -> ``3des`` (a leading digit-group is kept — it is part of the
    family name, not a key size)."""
    root = canon_name(name)
    parts = [p for p in root.split("-") if p and p not in _MODE_TOKENS]
    cleaned = []
    for p in parts:
        # drop a pure key-size number, and trailing digits on a token (rsa2048),
        # but keep a leading-digit family token like "3des".
        if p.isdigit():
            continue
        if p[0].isalpha():
            p = re.sub(r"\d+$", "", p)
        cleaned.append(p)
    return "-".join(cleaned) or root


def _asset_class(comp: dict) -> str | None:
    """Map a CycloneDX component to one of ASSET_CLASSES (or None to skip)."""
    cp = comp.get("cryptoProperties")
    if cp:
        at = cp.get("assetType")
        if at in ASSET_CLASSES:
            return at
        return "algorithm"  # unknown crypto assetType -> treat as algorithm
    ctype = comp.get("type")
    if ctype == "library":
        return "library"
    if _SECRET_HINT.search((comp.get("name") or "")):
        return "secret"
    return None


def _key_name(comp: dict, klass: str) -> str:
    """Canonical name for the comparison; a certificate keys on its subject CN."""
    if klass == "certificate":
        cp = comp.get("cryptoProperties") or {}
        subj = (cp.get("certificateProperties") or {}).get("subjectName")
        if subj:
            return canon_name(subj)
    return canon_name(comp.get("name") or (comp.get("purl") or ""))


def from_cyclonedx(path: Path, *, crypto_only: bool = False) -> set:
    """Both cbomkit-theia and ours emit CycloneDX ``components[]``."""
    doc = json.loads(Path(path).read_text())
    out: set = set()
    for c in (doc.get("components") or []):
        klass = _asset_class(c)
        if klass is None:
            continue
        if crypto_only and klass in {"library"}:
            continue
        nm = _key_name(c, klass)
        if nm:
            out.add((nm, klass))
    return out


def normalize(path: Path, tool: str) -> set:
    """``tool`` in {``cbomkit``, ``ours``}; both are CycloneDX. Libraries are
    excluded from the crypto diff (neither tool's crypto-asset inventory)."""
    return from_cyclonedx(path, crypto_only=True)


# --------------------------------------------------------------------------- #
# Crypto-LIBRARY lane (B1) — for the cdxgen oracle.
#
# cdxgen (@cyclonedx/cdxgen, the reference CycloneDX generator) is a
# dependency-graph SBOM tool: with ``--include-crypto`` it resolves and emits the
# project's library components (``type: library``). It does NOT, in this
# environment, emit source-code algorithm crypto-assets (its atom code-slicer is
# unavailable headless), so it is a *crypto-library* oracle, complementary to the
# cbomkit-theia *filesystem* oracle and to our *source-code* algorithm lane.
#
# cdxgen resolves the FULL dependency graph (crypto + non-crypto, e.g.
# ``typing-extensions``), so the library lane is scoped to KNOWN crypto libraries
# via a bench-local allowlist (mirrors — but does not import — the product's
# ``CRYPTO_LIBRARY_PACKAGES`` map). A non-crypto dependency is out of scope for a
# CRYPTO bom benchmark, not a missed crypto asset.
# --------------------------------------------------------------------------- #

# Canonical crypto-library names (lower-case; purl/name collapse to these). Kept
# in sync by hand with the product's crypto-library set — bench copy, no import.
_CRYPTO_LIB_NAMES = frozenset(
    {
        "cryptography", "pyopenssl", "pycryptodome", "pycryptodomex", "pycrypto",
        "pynacl", "nacl", "bcrypt", "argon2-cffi", "argon2", "passlib", "pyjwt",
        "jwt", "python-jose", "jose", "ecdsa", "hashlib", "ssl", "secrets", "hmac",
        "libsodium", "libsodium-wrappers", "sodium", "openssl", "bouncycastle",
        "bcprov", "node-forge", "forge", "crypto-js", "elliptic", "tweetnacl",
        "sshpk", "ring", "rustls", "libressl", "wolfssl", "mbedtls", "gnutls",
    }
)

_PURL_NAME = re.compile(r"pkg:[^/]+/(.+)")


def canon_lib(comp: dict) -> str:
    """Canonical library name for the crypto-library diff.

    Prefers the purl coordinate (``pkg:pypi/cryptography@42.0.5`` -> ``cryptography``);
    strips a scope/vendor prefix (``pyca/cryptography`` -> ``cryptography``,
    ``@scope/name`` -> ``name``); drops a trailing ``(stdlib)`` annotation and a
    version; lower-cases. So cdxgen's purl-derived ``cryptography`` and our label
    ``pyca/cryptography`` collapse to one key."""
    purl = comp.get("purl") or ""
    name = ""
    m = _PURL_NAME.match(purl)
    if m:
        name = m.group(1)
        name = re.split(r"[@?#]", name, maxsplit=1)[0]   # drop @version / qualifiers
    if not name:
        name = comp.get("name") or ""
    name = _PAREN_SUFFIX.sub("", name).strip()     # "hashlib (stdlib)" -> hashlib
    name = name.split("/")[-1]                      # pyca/cryptography, @scope/n -> n
    return name.lower()


def crypto_libraries(path: Path) -> set:
    """Extract the set of ``(canon_lib, "library")`` for KNOWN crypto libraries
    from a CycloneDX doc (cdxgen or ours). Non-crypto dependencies are skipped —
    they are out of scope for the crypto-library benchmark lane, not misses."""
    doc = json.loads(Path(path).read_text())
    out: set = set()
    for c in (doc.get("components") or []):
        if c.get("type") != "library":
            continue
        nm = canon_lib(c)
        if nm and nm in _CRYPTO_LIB_NAMES:
            out.add((nm, "library"))
    return out


# binary certificate / key file suffixes — a filesystem oracle "decomposes" these
# into their embedded algorithm + key-material; a source-code lane inventories the
# file itself as a certificate / key asset instead.
_CERT_KEY_SUFFIX = (
    ".cer", ".crt", ".der", ".pem", ".key", ".priv", ".pub",
    ".p12", ".pfx", ".jks", ".p7b", ".p8",
)


def evidence_index(path: Path) -> dict[tuple[str, str], list[str]]:
    """(canon_name, asset_class) -> the evidence file locations the tool recorded.

    Used by the diff's cert/key-decomposition reconciliation (R3): an oracle
    crypto asset whose evidence is ENTIRELY binary cert/key files is the oracle
    decomposing that binary, not a source-code asset we missed."""
    doc = json.loads(Path(path).read_text())
    out: dict[tuple[str, str], list[str]] = {}
    for c in (doc.get("components") or []):
        klass = _asset_class(c)
        if klass is None or klass == "library":
            continue
        nm = _key_name(c, klass)
        if not nm:
            continue
        locs = [
            o.get("location", "")
            for o in (c.get("evidence", {}).get("occurrences") or [])
            if o.get("location")
        ]
        out.setdefault((nm, klass), []).extend(locs)
    return out


def all_cert_key_evidence(locations: list[str]) -> bool:
    """True iff every recorded evidence location is a binary cert/key file."""
    if not locations:
        return False
    return all(loc.lower().endswith(_CERT_KEY_SUFFIX) for loc in locations)


if __name__ == "__main__":  # quick CLI: normalize.py <tool> <file>
    tool, file = sys.argv[1], sys.argv[2]
    s = normalize(Path(file), tool)
    for nm, tc in sorted(s):
        print(f"{tc:24} {nm}")
    print(f"--- {len(s)} crypto assets ({tool}) ---", file=sys.stderr)
