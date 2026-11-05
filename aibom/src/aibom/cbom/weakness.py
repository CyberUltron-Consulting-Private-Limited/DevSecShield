"""Weak-crypto detection (C5) — the predicate, reconciled from the worker.

Lane discipline: the C1/C2/C3 scanners INVENTORY crypto assets (each
``crypto_asset`` component carries ``crypto:strength`` / ``crypto:mode`` /
``crypto:keySize`` / protocol version); this module turns that inventory into a
**finding** — a ``(code, severity, message)`` triple — and the C5 scanner
(:mod:`aibom.cbom.scanners.weak_algorithm_scan`) raises it as a ``Flag``. The C8
scorer later WEIGHTS those flags. Nothing here scores or serializes.

The authoritative "what is weak" corpus is the worker ``cbom_agent``'s
``WEAK_ALGORITHMS`` table, ported into :mod:`aibom.cbom.rules`. A component is
weak-by-algorithm iff its canonical key is in that table — which faithfully
includes the *moderate*-strength-but-deprecated members (3DES, Blowfish) the
worker flagged with a High impact, so ``strength == "weak"`` alone is NOT the
test. Three orthogonal weaknesses are detected on top of the algorithm corpus:
an ECB cipher mode, a sub-2048-bit asymmetric key, and a weak protocol version
(TLS < 1.2 / SSL — the ``crypto:strength=="weak"`` signal C3 sets).

All weak-crypto findings are SARIF ``error`` (== High impact), matching the
acceptance criterion "weak crypto -> high".
"""

from __future__ import annotations

import re
from datetime import date, timedelta

from aibom.cbom.rules import ALGORITHM_NORMALIZE, WEAK_ALGORITHMS
from aibom.model.component import AIComponent

# Flag codes this lane emits (the set the C8 scorer weights and the charts read).
WEAK_ALGORITHM = "WEAK_ALGORITHM"
WEAK_CIPHER_MODE = "WEAK_CIPHER_MODE"
WEAK_KEY_SIZE = "WEAK_KEY_SIZE"
WEAK_PROTOCOL = "WEAK_PROTOCOL"
# An X.509 certificate past its notValidAfter date (C8: "expired cert -> high").
EXPIRED_CERTIFICATE = "EXPIRED_CERTIFICATE"
_NEAR_EXPIRY_DAYS = 90
CERT_NEAR_EXPIRY = "CERT_NEAR_EXPIRY"
# C4 certificate-depth weaknesses (distinct from the algorithm-asset codes above
# so the scorer/charts can attribute them to the certificate lane):
#   * a certificate signed with a broken digest (MD2/MD4/MD5/SHA-1) — forgeable;
#   * a certificate whose public key is below the asymmetric floor;
#   * a self-signed *leaf* (BasicConstraints CA:FALSE) — a production trust smell.
WEAK_CERTIFICATE_SIGNATURE = "WEAK_CERTIFICATE_SIGNATURE"
WEAK_CERTIFICATE_KEY = "WEAK_CERTIFICATE_KEY"
WEAK_CERT_SIGNATURE = WEAK_CERTIFICATE_SIGNATURE
WEAK_CERT_KEY_SIZE = WEAK_CERTIFICATE_KEY
SELF_SIGNED_LEAF = "SELF_SIGNED_LEAF"
# C6 related-crypto-material misuse codes (source-derived; see
# :mod:`aibom.cbom.misuse` for detection). Each is a present-day break:
#   * WEAK_RNG      — key/IV/nonce/salt from a non-crypto PRNG (CWE-338);
#   * STATIC_IV     — a constant/predictable IV or nonce reaching a cipher (CWE-329);
#   * REUSED_NONCE  — the same static IV/nonce securing >1 encryption (CWE-323);
#   * HARDCODED_KEY — a symmetric key embedded as a source literal (CWE-321).
WEAK_RNG = "WEAK_RNG"
STATIC_IV = "STATIC_IV"
REUSED_NONCE = "REUSED_NONCE"
HARDCODED_KEY = "HARDCODED_KEY"
# C13 cipher-suite / SSH-algo / IKE-transform negotiation weakness. Distinct from
# WEAK_PROTOCOL (which flags the *version*: TLS < 1.2 / SSH-1.x / IKEv1) — this
# flags the negotiated *primitives* a protocol carries in its
# ``crypto:cipherSuite`` bag even on a modern version (e.g. TLS 1.2 that still
# offers RC4 / 3DES / NULL / anon / EXPORT suites, an SSH server that keeps
# ssh-rsa / diffie-hellman-group1-sha1 / arcfour, or an IKE proposal on a weak
# MODP DH group). See :func:`cipher_suite_findings`.
WEAK_CIPHER_SUITE = "WEAK_CIPHER_SUITE"
# C16 weak asymmetric ENCRYPTION padding (CWE-780). RSA used for encryption with
# PKCS#1 v1.5 (Bleichenbacher / ROBOT padding oracle), textbook/raw, or no
# padding is a present-day break. Deliberately gated on the crypto OPERATION: a
# PKCS#1 v1.5 *signature* is FIPS 186-5-approved and must NEVER be flagged.
WEAK_PADDING = "WEAK_PADDING"

WEAK_CRYPTO_CODES = frozenset(
    {
        WEAK_ALGORITHM, WEAK_CIPHER_MODE, WEAK_KEY_SIZE, WEAK_PROTOCOL,
        WEAK_RNG, STATIC_IV, REUSED_NONCE, HARDCODED_KEY, WEAK_CIPHER_SUITE,
        WEAK_PADDING,
    }
)

_SEV = "error"  # SARIF error == High impact (mirrors the secret scanner).
_SEV_MED = "warning"  # SARIF warning == Medium impact (a smell, not a break).

# Broken message digests inside a certificate signatureAlgorithm name. A cert
# signed with any of these is forgeable via collision (chosen-prefix), so the
# whole certificate is untrustworthy regardless of its key strength.
_BROKEN_SIG_DIGESTS = ("md2", "md4", "md5", "sha1")

# Reverse of ALGORITHM_NORMALIZE: a display name (upper) -> canonical key. Built
# from the same table the scanner names assets with, so it never drifts. e.g.
# "3DES" -> "3des", "RSA-1024" -> "rsa-1024", "MD5" -> "md5".
_DISPLAY_TO_KEY: dict[str, str] = {
    disp.upper(): key for key, disp in ALGORITHM_NORMALIZE.items()
}

# Cipher-mode suffixes the scanner appends to a display name (e.g. "AES-256-GCM",
# "3DES-CBC"); stripped to recover the base algorithm display name.
_MODE_SUFFIXES = ("-GCM", "-CBC", "-ECB", "-CTR", "-CFB", "-OFB", "-XTS", "-CCM")

# Minimum acceptable asymmetric key size (bits). NIST SP 800-57 / 800-131A
# disallow RSA/DSA/DH below 2048.
_MIN_ASYMMETRIC_BITS = 2048
# Public-key algorithms whose strength is the modulus size (RSA / DSA); EC keys are sized by their curve instead.
_MODULUS_PK_TOKENS = ("rsa", "dsa")

# PQC / stateful-hash signature + KEM families whose ``crypto:keySize`` carries a
# NIST *parameter set* (FALCON-512, ML-KEM-768), NOT an integer-factorization /
# discrete-log modulus — so the 2048-bit RSA floor must NOT apply to them (a
# 128-bit-secure FALCON-512 is not an "undersized RSA key"). Matched by name so
# the guard is order-independent of the C7 nistQuantumSecurityLevel enrichment.
_PQC_NAME_TOKENS = (
    "ML-KEM", "MLKEM", "KYBER", "ML-DSA", "MLDSA", "DILITHIUM",
    "SLH-DSA", "SPHINCS", "FALCON", "FN-DSA", "XMSS", "LMS", "HSS", "HYBRID",
)


def _is_pqc_name(name: str) -> bool:
    upper = name.upper()
    return any(tok in upper for tok in _PQC_NAME_TOKENS)

# Per-protocol-family rationale for a WEAK_PROTOCOL finding, so the message names
# the right deprecated version + migration target instead of a TLS-only string.
_WEAK_PROTOCOL_RATIONALE: dict[str, str] = {
    "tls": "TLS below 1.2 / SSL is deprecated (RFC 8996); negotiate TLS 1.2+ "
    "(prefer 1.3).",
    "ssh": "SSH protocol 1.x is cryptographically broken (CVE-2001-0361); use "
    "SSH-2.0 only.",
    "ipsec": "IKEv1 is deprecated (RFC 9395); migrate the tunnel to IKEv2.",
    "ike": "IKEv1 is deprecated (RFC 9395); migrate the tunnel to IKEv2.",
}
_WEAK_PROTOCOL_RATIONALE_DEFAULT = (
    "a deprecated protocol version is in use; migrate to the current, "
    "non-deprecated version."
)


def _base_key(name: str) -> str | None:
    """Recover the canonical algorithm key from a crypto_asset display name.

    Strips a trailing cipher-mode suffix, then maps the remainder back through
    the normalization table. Returns ``None`` when the name is not a known
    algorithm (e.g. a parametrized variant the table does not enumerate).
    """
    upper = name.upper()
    for suffix in _MODE_SUFFIXES:
        if upper.endswith(suffix):
            upper = upper[: -len(suffix)]
            break
    return _DISPLAY_TO_KEY.get(upper)


def _inferred(props: dict[str, str]) -> bool:
    """The algorithm is a guess, not read from the code at this call (``crypto:resolution`` ``inferred …``: a field
    default a setter may override, the module's one configured transformation for a ``String`` parameter). It is
    inventoried for review with ``crypto:confidence=medium`` and raises no finding: a guess is no evidence of a
    weakness, and a wrong guess would put a High finding on code that does not use the algorithm."""
    return str(props.get("crypto:resolution") or "").startswith("inferred")


def _key_size(props: dict[str, str]) -> int | None:
    raw = props.get("crypto:keySize")
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def weak_finding(component: AIComponent) -> tuple[str, str, str] | None:
    """Return ``(code, severity, message)`` if ``component`` is weak crypto, else None.

    Pure: depends only on the component's ``crypto:`` properties and display
    name. One finding per component (the most salient weakness wins).
    """
    if component.kind != "crypto_asset":
        return None
    props = component.properties or {}
    asset_type = props.get("crypto:assetType")
    name = component.name

    if asset_type == "protocol":
        if props.get("crypto:strength") == "weak":
            version = props.get("crypto:protocolVersion")
            ver = f" {version}" if version else ""
            rationale = _WEAK_PROTOCOL_RATIONALE.get(
                props.get("crypto:protocolType", ""),
                _WEAK_PROTOCOL_RATIONALE_DEFAULT,
            )
            return (
                WEAK_PROTOCOL,
                _SEV,
                f"Weak transport protocol {name}{ver}: {rationale}",
            )
        return None

    if asset_type != "algorithm":
        # Certificates / related-crypto-material are not algorithm-weakness
        # findings; C5 leaves them to their own (later) checks.
        return None
    if props.get("crypto:derived") == "true":
        # A derived row (the inner hash of a composite, the hash a hardcoded key is derived through) has no
        # finding of its own: the component it was derived from carries it.
        return None
    if _inferred(props):
        return None
    if props.get("crypto:nonSecurityUse") == "true" and props.get("crypto:primitive") == "hash":
        # A hash used only to name or check content (a cache key, an ETag, a checksum; ``usedforsecurity=False``)
        # with no secret input: collisions there are not an attack on a secret. Inventoried, not flagged.
        return None

    # 1) Deprecated/broken algorithm by canonical corpus (covers MD5, SHA-1, DES,
    #    RC2, RC4, RSA-512/1024 — strength "weak" — AND 3DES/Blowfish, which the
    #    worker rates "moderate" strength but still deprecates).
    key = _base_key(name)
    if key == "jwt-none":
        return (
            WEAK_ALGORITHM,
            _SEV,
            f"Unsigned JWT ({name}): alg=none or a decode with signature verification off accepts tokens "
            f"nobody signed, so any claim can be forged (CWE-347). Sign with HS256+/RS256/ES256/EdDSA and "
            f"pin the accepted algorithms on verify.",
        )
    if key is not None and key in WEAK_ALGORITHMS:
        return (
            WEAK_ALGORITHM,
            _SEV,
            f"Broken or deprecated algorithm {name}: superseded by modern "
            f"primitives (e.g. SHA-256/SHA-3, AES-GCM, RSA-3072+/ECDSA); "
            f"NIST SP 800-131A.",
        )

    # 2) ECB cipher mode — deterministic, leaks plaintext structure — even on an
    #    otherwise-strong cipher (e.g. AES-128-ECB).
    if props.get("crypto:mode", "").upper() == "ECB":
        return (
            WEAK_CIPHER_MODE,
            _SEV,
            f"Insecure ECB cipher mode on {name}: identical plaintext blocks "
            f"map to identical ciphertext; use an authenticated mode (GCM/CCM).",
        )

    # 3) Sub-2048-bit asymmetric key (a strong-named RSA/DSA/DH with a small key).
    #    Excludes PQC/stateful-hash families, whose keySize is a parameter set, not
    #    a modulus — FALCON-512 is a 128-bit-secure signature, not a weak RSA key.
    if props.get("crypto:primitive") in ("pke", "signature", "key-agree") and (
        not _is_pqc_name(name)
    ):
        bits = _key_size(props)
        if bits is not None and bits < _MIN_ASYMMETRIC_BITS:
            return (
                WEAK_KEY_SIZE,
                _SEV,
                f"Undersized asymmetric key on {name}: {bits}-bit is below the "
                f"{_MIN_ASYMMETRIC_BITS}-bit floor (NIST SP 800-57); use "
                f"RSA-3072+ or an elliptic-curve / PQC equivalent.",
            )

    # 3b) A signature built on a collision-broken digest (``SHA1withRSA``): the digest is listed as a derived row
    #     without a finding of its own, so the signature carries it. ``crypto:innerDigest`` is only set from a
    #     signature spelling: the hash of an RSA-OAEP encryption (``padding.OAEP(algorithm=hashes.SHA1())``) is a
    #     derived row too, but OAEP rests on no collision resistance, so it is not a digest here.
    digest = props.get("crypto:innerDigest") or ""
    inner = _base_key(digest)
    if props.get("crypto:primitive") in ("pke", "signature") and inner in _BROKEN_SIG_DIGESTS:
        return (
            WEAK_ALGORITHM,
            _SEV,
            f"{name} signature over a {digest} digest: {digest} collisions let a signature be reused for a "
            f"forged message (NIST SP 800-131A disallows it for signatures); sign with SHA-256 or stronger.",
        )
    if props.get("crypto:primitive") in ("mac", "kdf") and inner in ("md2", "md4", "md5"):
        # HMAC-SHA1 / PBKDF2-HMAC-SHA1 remain approved; an MD-family hash is not an approved hash at all.
        return (
            WEAK_ALGORITHM,
            _SEV,
            f"{name} built on {digest}: {digest} is not an approved hash function (NIST SP 800-131A); use "
            f"HMAC-SHA256 or stronger.",
        )

    # 4) Fallback: any asset the inventory already marked weak that the corpus
    #    lookup missed (a parametrized variant not in the normalization table).
    if props.get("crypto:strength") == "weak":
        return (
            WEAK_ALGORITHM,
            _SEV,
            f"Weak algorithm {name}: flagged by the crypto inventory as weak; "
            f"migrate to a modern primitive.",
        )

    return None


# RSA encryption paddings with no chosen-ciphertext security. PKCS#1 v1.5
# encryption is the Bleichenbacher/ROBOT padding oracle (CWE-780); textbook/raw/
# none is deterministic RSA with no semantic security. OAEP / PSS are safe and
# never listed. (Only ``pkcs1v15`` is currently emitted by the pyca padding rule;
# the others future-proof the predicate and mirror the C16 story wording.)
_WEAK_ENCRYPTION_PADDINGS = frozenset({"pkcs1v15", "none", "textbook", "raw"})


def weak_padding_finding(component: AIComponent) -> tuple[str, str, str] | None:
    """Return a ``WEAK_PADDING`` finding for insecure RSA *encryption* padding (C16).

    Pure predicate over the ``crypto:padding`` + ``crypto:operation`` props the C1
    detection lane emits. Fires ONLY when an RSA (``pke``) asset is used for
    encryption/decryption with a padding that has no chosen-ciphertext security
    (PKCS#1 v1.5 = Bleichenbacher/ROBOT, or textbook/none). A PKCS#1 v1.5
    *signature* is FIPS 186-5-approved, so the operation gate means a signature —
    or any usage whose operation could not be proven to be encryption — is never
    flagged (zero false positives on the frozen ``synthetic-crypto-dataflow``
    ``rsa_pkcs1v15_sign`` fixture). Returns ``None`` for any other component.
    """
    if component.kind != "crypto_asset":
        return None
    props = component.properties or {}
    if props.get("crypto:assetType") != "algorithm":
        return None
    if props.get("crypto:primitive") != "pke" or _inferred(props):
        return None
    padding = (props.get("crypto:padding") or "").lower()
    if padding not in _WEAK_ENCRYPTION_PADDINGS:
        return None
    # The operation gate: only proven encryption/decryption is a weakness.
    if props.get("crypto:operation") != "encrypt":
        return None
    return (
        WEAK_PADDING,
        _SEV,
        f"Insecure RSA encryption padding on {component.name}: PKCS#1 v1.5 (or "
        f"textbook/raw) RSA encryption is a chosen-ciphertext / padding-oracle "
        f"break (Bleichenbacher, ROBOT; CWE-780). Use RSA-OAEP for encryption, or "
        f"a hybrid KEM (ML-KEM / ECIES). Note: PKCS#1 v1.5 *signatures* remain "
        f"FIPS 186-5-approved and are not flagged.",
    )


def material_misuse_findings(component: AIComponent) -> list[tuple[str, str, str]]:
    """Return every crypto-material misuse flag on a related-crypto-material asset (C6).

    Pure predicate over the ``crypto:`` misuse props the C6 misuse scanner
    (:mod:`aibom.cbom.scanners.crypto_misuse_scan`) emitted — never re-scans
    source. Returns an empty list for any non-material component, so the flag
    scanner can call it on every asset unconditionally. Misuses stack: material
    from a weak RNG that is also a static, reused IV raises all three.
    """
    if component.kind != "crypto_asset":
        return []
    props = component.properties or {}
    if props.get("crypto:assetType") != "related-crypto-material":
        return []
    kind = props.get("crypto:materialKind", "material")
    if kind in ("unknown", "other"):
        kind = "material"
    name = component.name
    findings: list[tuple[str, str, str]] = []

    if props.get("crypto:weakRng") == "true":
        src = props.get("crypto:generatedBy", "a non-cryptographic PRNG")
        findings.append(
            (
                WEAK_RNG,
                _SEV,
                f"Weak RNG for crypto material {name}: {src} is not a CSPRNG "
                f"(CWE-338); the {kind} is predictable. Use os.urandom / "
                f"secrets / crypto.randomBytes / a platform CSPRNG.",
            )
        )
    # A reused nonce is strictly worse than a merely-static one, so REUSED_NONCE
    # supersedes STATIC_IV on the same asset (no double IV finding).
    if props.get("crypto:reused") == "true":
        findings.append(
            (
                REUSED_NONCE,
                _SEV,
                f"Reused nonce/IV {name}: the same constant {kind} secures more "
                f"than one encryption (CWE-323) — catastrophic for GCM/CTR "
                f"(nonce reuse breaks confidentiality and integrity). Derive a "
                f"fresh random nonce per message.",
            )
        )
    elif props.get("crypto:staticIv") == "true":
        findings.append(
            (
                STATIC_IV,
                _SEV,
                f"Static IV/nonce {name}: a constant, predictable {kind} reaches "
                f"a cipher (CWE-329); it defeats CBC/CTR semantic security. Use a "
                f"fresh random IV per message.",
            )
        )
    if props.get("crypto:hardcoded") == "true" and kind in (
        "secret-key",
        "private-key",
        "key",
    ):
        derived = props.get("crypto:derivedWith")
        how = (f"derived from a constant through {derived}, so it is fixed by the source and the "
               f"derivation is not a key-derivation function" if derived else "embedded as a source literal")
        findings.append(
            (
                HARDCODED_KEY,
                _SEV,
                f"Hardcoded key {name}: a symmetric/private key is {how} "
                f"(CWE-321); anyone with the code has the key. "
                f"Load key material from a secret manager / KMS, never source.",
            )
        )
    elif props.get("crypto:historyOnly") == "true" and kind in ("secret-key", "private-key", "key"):
        # "Scan git history for keys" (aibom.cbom.githistory): a key file committed and later deleted is still in
        # every clone. It was reported as clean inventory (no finding, "Info"), so the option the customer turned on
        # to find exactly these keys showed nothing on the results page (lab UI run u2, round 5).
        commit = (props.get("crypto:gitCommit") or "")[:12]
        where = f" (commit {commit})" if commit else ""
        findings.append(
            (
                HARDCODED_KEY,
                _SEV,
                f"Key in git history {name}: this {kind} file was committed{where} and later deleted, but every "
                f"clone of the repository still holds it (CWE-540, CWE-321). Treat the key as exposed: rotate it, "
                f"then remove it from the history (git filter-repo) and from every fork and mirror.",
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# C13 — cipher-suite / SSH-algo / IKE-transform negotiation weakness catalog.
#
# A clean-room predicate over the ``crypto:cipherSuite`` bag the C3/C5 protocol
# scanner emits (TLS OpenSSL/IANA suite names, SSH kex/host-key/cipher/MAC
# tokens, or strongSwan/IKE transform proposals). Each token is classified
# against a corpus of primitives disallowed by modern baselines (PCI-DSS 4.0,
# NIST SP 800-52r2, BSI TR-02102), every class carrying a public attack/CVE
# name. The predicate is a peer of :func:`weak_finding` — the scanner EMITS the
# tokens, this QUERIES them; the C8 scorer WEIGHTS the resulting flag.
#
# SCOPE (matches the C5/C6 zero-frozen-delta discipline): the HARD breaks are
# flagged here — NULL / anonymous / EXPORT / RC4 / RC2 / DES / 3DES ciphers, MD5
# MACs, weak SSH kex+host-key+cipher+MAC, and weak (≤1536-bit) IKE MODP DH
# groups. Plain CBC-mode-with-SHA-1 TLS suites (Lucky13/BEAST) are a documented
# softer tier deferred to a follow-up so the frozen ``synthetic-crypto-app``
# oracle (whose only suite is ``ECDHE-RSA-AES128-SHA``, CBC-SHA1) stays at zero
# delta — exactly how C6 deferred WEAK_PADDING off ``rsa_pkcs1v15_sign``.
# --------------------------------------------------------------------------- #

# A cipherSuite value is a bag of tokens joined by ``, `` (TLS/IKE) or ``:``
# (OpenSSL CipherString). Split on either so every token is classified alone.
_SUITE_TOKEN_SPLIT = re.compile(r"[,:]\s*|\s+")

# Token-class matchers. Each is a compiled regex evaluated against the LOWERCASED
# token; boundaries (``(?:^|[_-])`` … ``(?:[_-]|$)``) keep a fragment like ``des``
# from matching inside ``aes`` / ``ides`` and ``rc2`` from ``rc256``. Order is
# irrelevant — every matching class contributes its rationale (weaknesses stack
# within a suite, e.g. ``3des-md5-modp1024`` = SWEET32 + MD5 + Logjam).
_NULL_CIPHER = re.compile(r"(?:^|[_-])e?null(?:[_-]|$)")
_ANON_KX = re.compile(r"(?:^|[_-])(?:adh|aecdh|anon)(?:[_-]|$)")
_EXPORT_GRADE = re.compile(r"(?:^|[_-])exp(?:ort)?(?:40|56|1024)?(?:[_-]|$)")
_RC4_STREAM = re.compile(r"(?:^|[_-])(?:rc4|arcfour(?:128|256)?)(?:[-_@]|$)")
_RC2_BLOCK = re.compile(r"(?:^|[_-])rc2(?:[_-]|$)")
# 3DES first (superset of the ``des`` fragment), so single-DES only fires on the
# genuinely 56-bit cipher, never on a Triple-DES token.
_TRIPLE_DES = re.compile(r"(?:3des|des[-_]?ede3?|des[-_]?cbc3|desede)")
_SINGLE_DES = re.compile(r"(?:^|[_-])des(?:40|56)?(?:[-_](?:cbc|ede))?(?:[_-]|$)")
_MD5_MAC = re.compile(r"(?:^|[_-])(?:hmac[-_])?md5(?:[-_]96)?(?:[-_@]|$)")
# Weak IKE/IPsec MODP Diffie-Hellman groups (768/1024/1536-bit = DH group
# 1/2/5) — Logjam CVE-2015-4000. modp2048+ (group 14+) is not flagged.
_WEAK_MODP = re.compile(r"(?:^|[_-])modp[-_]?(?:768|1024|1536)(?:[_-]|$)")
# SSH-only weak primitives (evaluated only when protocolType == "ssh").
_SSH_DSS_HOSTKEY = re.compile(r"(?:^|[_-])ssh-dss(?:[_-]|$)")
_SSH_RSA_SHA1_HOSTKEY = re.compile(r"^ssh-rsa$")  # SHA-1 sig; rsa-sha2-* is fine
_SSH_WEAK_KEX = re.compile(
    r"diffie-hellman-group(?:1|-exchange)-sha1|diffie-hellman-group1-sha1"
)
_SSH_WEAK_CIPHER = re.compile(r"(?:^|[_-])(?:blowfish|cast128)(?:[-_]cbc)?(?:[_-]|$)")
_SSH_WEAK_MAC = re.compile(r"(?:^|[_-])umac-64(?:[-_@]|$)")


def _suite_token_attacks(token: str, ptype: str) -> list[str]:
    """Return the attack/CVE rationale(s) that make a single suite token weak.

    ``token`` is a raw cipherSuite entry (already prose-free — the scanner strips
    comments before emitting). ``ptype`` is the ``crypto:protocolType`` so the
    SSH-only host-key/kex/cipher/MAC rules apply only to SSH assets. An empty
    list means the token is acceptable under the modern baselines.
    """
    t = token.strip().lower()
    if not t:
        return []
    reasons: list[str] = []
    if _NULL_CIPHER.search(t):
        reasons.append("NULL cipher — no encryption/integrity")
    if _ANON_KX.search(t):
        reasons.append("anonymous key exchange — unauthenticated, enables MITM")
    if _EXPORT_GRADE.search(t):
        reasons.append("EXPORT-grade key strength — FREAK/Logjam "
                       "(CVE-2015-0204/CVE-2015-4000)")
    if _RC4_STREAM.search(t):
        reasons.append("RC4 stream cipher — biased keystream, prohibited by RFC 7465")
    if _RC2_BLOCK.search(t):
        reasons.append("RC2 — weak 40/64-bit export-era block cipher")
    if _TRIPLE_DES.search(t):
        reasons.append("Triple-DES 64-bit block cipher — SWEET32 (CVE-2016-2183)")
    elif _SINGLE_DES.search(t):
        reasons.append("single DES — 56-bit key, brute-forceable")
    if _MD5_MAC.search(t):
        reasons.append("MD5 MAC/PRF — collision-broken digest")
    if _WEAK_MODP.search(t):
        reasons.append("weak MODP DH group (≤1536-bit, group 1/2/5) — Logjam")
    if ptype == "ssh":
        if _SSH_DSS_HOSTKEY.search(t):
            reasons.append("ssh-dss host key — 1024-bit DSA, weak")
        if _SSH_RSA_SHA1_HOSTKEY.search(t):
            reasons.append("ssh-rsa host key — SHA-1 signature; use rsa-sha2-256/512")
        if _SSH_WEAK_KEX.search(t):
            reasons.append("weak SSH kex — DH group 1 / SHA-1")
        if _SSH_WEAK_CIPHER.search(t):
            reasons.append(
                "64-bit-block SSH cipher (Blowfish/CAST-128) — SWEET32-class"
            )
        if _SSH_WEAK_MAC.search(t):
            reasons.append("UMAC-64 — truncated 64-bit MAC")
    return reasons


def cipher_suite_findings(component: AIComponent) -> list[tuple[str, str, str]]:
    """Return a ``WEAK_CIPHER_SUITE`` finding if a protocol offers weak suites (C13).

    Pure predicate over the emitted ``crypto:cipherSuite`` bag on a *protocol*
    crypto-asset. Tokenizes the bag, classifies each token via
    :func:`_suite_token_attacks`, and if any are weak returns ONE aggregated
    High-severity finding naming the offending tokens + attacks (one flag per
    asset keeps the count/chart contract clean, mirroring ``weak_finding``).
    Returns an empty list for any non-protocol component or a clean suite, so the
    scanner can call it on every asset unconditionally. Never re-scans source.
    """
    if component.kind != "crypto_asset":
        return []
    props = component.properties or {}
    if props.get("crypto:assetType") != "protocol":
        return []
    bag = props.get("crypto:cipherSuite", "")
    if not bag:
        return []
    ptype = props.get("crypto:protocolType", "")
    # Preserve first-seen token order; dedupe so a repeated token is named once.
    weak: dict[str, list[str]] = {}
    for raw in _SUITE_TOKEN_SPLIT.split(bag):
        tok = raw.strip()
        if not tok or tok in weak:
            continue
        attacks = _suite_token_attacks(tok, ptype)
        if attacks:
            weak[tok] = attacks
    if not weak:
        return []
    detail = "; ".join(f"{tok} ({', '.join(reasons)})" for tok, reasons in weak.items())
    return [
        (
            WEAK_CIPHER_SUITE,
            _SEV,
            f"Weak cryptographic suite(s) on {component.name}: {detail}. Disable "
            f"these and offer only AEAD suites (TLS 1.2+ ECDHE + AES-GCM/"
            f"ChaCha20-Poly1305; SSH curve25519 + aes-gcm + hmac-sha2; IKEv2 "
            f"aes-gcm + modp2048+/ECP) per PCI-DSS 4.0 / NIST SP 800-52r2.",
        )
    ]


def _sig_digest_is_broken(sig_alg: str) -> bool:
    """A certificate signatureAlgorithm built on a collision-broken digest."""
    return _weak_cert_hash(sig_alg) is not None


# Signature-algorithm OIDs that x509 readers sometimes leave unnamed, and the broken digest each uses.
_BROKEN_SIG_OIDS = {
    "1.2.840.113549.1.1.2": "MD2",    # md2WithRSAEncryption
    "1.2.840.113549.1.1.3": "MD4",    # md4WithRSAEncryption
    "1.2.840.113549.1.1.4": "MD5",    # md5WithRSAEncryption
    "1.2.840.113549.1.1.5": "SHA-1",  # sha1WithRSAEncryption
    "1.3.14.3.2.29": "SHA-1",         # sha1WithRSA (OIW)
    "1.2.840.10040.4.3": "SHA-1",     # dsa-with-sha1
    "1.2.840.10045.4.1": "SHA-1",     # ecdsa-with-SHA1
}


def _weak_cert_hash(sig_alg: str) -> str | None:
    """The collision-broken digest a certificate signatureAlgorithm uses ('MD5', 'SHA-1', ...), or None."""
    oid = _BROKEN_SIG_OIDS.get(str(sig_alg or "").strip())
    if oid:
        return oid
    low = str(sig_alg or "").lower().replace("-", "").replace("_", "")  # "SHA-1" / "sha_1" spell sha1 too
    for digest in _BROKEN_SIG_DIGESTS:
        if digest in low:
            return {"sha1": "SHA-1"}.get(digest, digest.upper())
    return None


def certificate_findings(component: AIComponent) -> list[tuple[str, str, str]]:
    """Return every certificate-depth weakness on a certificate asset (C4).

    Pure, and orthogonal to :func:`cert_expiry_finding` — a certificate can be
    *both* expired and signed with SHA-1 with an undersized key, and every such
    finding is raised so the scorer stacks them (mirroring the weights file's
    "expired+weak cert" rationale). Returns an empty list for any non-certificate
    component, so the scanner can call it on every asset unconditionally.
    """
    if component.kind != "crypto_asset":
        return []
    props = component.properties or {}
    if props.get("crypto:assetType") != "certificate":
        return []
    name = component.name
    findings: list[tuple[str, str, str]] = []

    # 1) Broken signature digest (MD2/MD4/MD5/SHA-1) -> the cert is forgeable.
    sig_alg = props.get("crypto:signatureAlgorithm", "")
    if sig_alg and _sig_digest_is_broken(sig_alg):
        findings.append(
            (
                WEAK_CERTIFICATE_SIGNATURE,
                _SEV,
                f"Certificate {name} is signed with {sig_alg}: MD5/SHA-1 digests "
                f"are collision-broken (chosen-prefix), so the certificate can be "
                f"forged; reissue with a SHA-256+ signature.",
            )
        )

    # 2) Undersized public key. RSA/DSA below the 2048-bit floor (NIST SP 800-57);
    #    an EC curve below a 224-bit field (< 112-bit strength) is equally weak.
    bits = _key_size(props)
    if bits is not None:
        pk = props.get("crypto:publicKeyAlgorithm", "").lower()
        is_ec = pk.startswith("ec") or bool(props.get("crypto:curve"))
        floor = 224 if is_ec else _MIN_ASYMMETRIC_BITS
        if bits < floor:
            findings.append(
                (
                    WEAK_CERTIFICATE_KEY,
                    _SEV,
                    f"Certificate {name} has an undersized {bits}-bit public key "
                    f"(floor {floor}-bit, NIST SP 800-57); reissue with "
                    f"RSA-3072+ or a P-256+ / PQC key.",
                )
            )

    # 3) Self-signed leaf: a self-signed cert that is explicitly NOT a CA is an
    #    end-entity trusting itself — a production trust smell (a real root CA is
    #    self-signed but carries BasicConstraints CA:TRUE, so is not flagged).
    if (
        props.get("crypto:selfSigned") == "true"
        and props.get("crypto:isCertificateAuthority") == "false"
    ):
        findings.append(
            (
                SELF_SIGNED_LEAF,
                _SEV_MED,
                f"Self-signed leaf certificate {name} (BasicConstraints CA:FALSE): "
                f"an end-entity certificate acting as its own trust anchor; issue "
                f"it from a proper CA before relying on it in production.",
            )
        )
    return findings


def _cert_not_after_date(raw: str) -> date | None:
    """Parse a certificate ``crypto:notValidAfter`` value to a date.

    C2 captures it as an ISO-8601 ``YYYY-MM-DDThh:mm:ssZ`` string; only the
    date is needed for an expiry comparison. Returns ``None`` (never raises) on a
    malformed value, so a garbled cert can never crash the scan.
    """
    if not raw:
        return None
    try:
        return date.fromisoformat(raw[:10])
    except ValueError:
        return None


def cert_expiry_finding(
    component: AIComponent, today: date
) -> tuple[str, str, str] | None:
    """Return an ``EXPIRED_CERTIFICATE`` finding if the cert is past expiry, else None.

    Pure: depends only on the component's ``crypto:notValidAfter`` property and
    the supplied ``today`` reference date (the scanner passes ``date.today()``;
    tests pass a fixed date so the predicate stays deterministic). SARIF
    ``error`` (== High impact), matching the criterion "expired cert -> high".
    A certificate with no parseable expiry, or one still valid, is not flagged.
    """
    if component.kind != "crypto_asset":
        return None
    props = component.properties or {}
    if props.get("crypto:assetType") != "certificate":
        return None
    not_after = _cert_not_after_date(props.get("crypto:notValidAfter", ""))
    if not_after is None or not_after >= today:
        return None
    return (
        EXPIRED_CERTIFICATE,
        _SEV,
        f"Expired X.509 certificate {component.name}: notValidAfter "
        f"{not_after.isoformat()} is in the past; rotate/reissue and re-pin "
        f"trust anchors before relying on it.",
    )


def cert_weakness_findings(
    component: AIComponent,
    today: date,
    near_expiry_days: int = _NEAR_EXPIRY_DAYS,
) -> list[tuple[str, str, str]]:
    """All certificate-weakness findings for one crypto asset (C4 catalog).

    Unlike the single-verdict :func:`weak_finding` (algorithm / protocol), a
    certificate can be weak on several orthogonal axes at once — a legacy cert can
    be BOTH SHA-1-signed AND RSA-1024 AND expiring — so this returns a list and
    the caller stacks the flags (the C8 scorer sums their weights per component).

    Findings (deterministic order): validity band first (EXPIRED_CERTIFICATE High,
    else CERT_NEAR_EXPIRY Medium when within ``near_expiry_days``), then a weak
    signature hash (High), then an undersized RSA/DSA key (High). Non-certificate
    assets return ``[]``. Pure: reads only ``crypto:`` properties + ``today``.
    """
    if component.kind != "crypto_asset":
        return []
    props = component.properties or {}
    if props.get("crypto:assetType") != "certificate":
        return []
    name = component.name
    findings: list[tuple[str, str, str]] = []

    # 1) Validity band — hard-expired (reuse the existing predicate) OR near-expiry.
    expired = cert_expiry_finding(component, today)
    if expired is not None:
        findings.append(expired)
    else:
        not_after = _cert_not_after_date(props.get("crypto:notValidAfter", ""))
        if (
            not_after is not None
            and not_after >= today
            and not_after < today + timedelta(days=near_expiry_days)
        ):
            days_left = (not_after - today).days
            findings.append(
                (
                    CERT_NEAR_EXPIRY,
                    _SEV_MED,
                    f"Certificate {name} expires in {days_left} day(s) "
                    f"(notValidAfter {not_after.isoformat()}); schedule "
                    f"rotation before it lapses to avoid an outage.",
                )
            )

    # 2) Collision-broken signature hash (MD2/MD4/MD5/SHA-1).
    sig_alg = props.get("crypto:signatureAlgorithm", "")
    weak_hash = _weak_cert_hash(sig_alg) if sig_alg else None
    if weak_hash is not None:
        findings.append(
            (
                WEAK_CERT_SIGNATURE,
                _SEV,
                f"Certificate {name} is signed with {weak_hash} "
                f"({sig_alg}): a collision-broken hash (CA/Browser Forum SHA-1 "
                f"sunset; NIST SP 800-131A); reissue with SHA-256+.",
            )
        )

    # 3) Undersized RSA/DSA certificate key (< 2048), which WEAK_KEY_SIZE skips
    #    because it gates on assetType == "algorithm".
    pk_alg = props.get("crypto:publicKeyAlgorithm", "").lower()
    if any(tok in pk_alg for tok in _MODULUS_PK_TOKENS):
        bits = _key_size(props)
        if bits is not None and bits < _MIN_ASYMMETRIC_BITS:
            findings.append(
                (
                    WEAK_CERT_KEY_SIZE,
                    _SEV,
                    f"Certificate {name} has an undersized {bits}-bit key: "
                    f"below the {_MIN_ASYMMETRIC_BITS}-bit RSA/DSA floor "
                    f"(NIST SP 800-57); reissue with RSA-3072+ or ECDSA P-256.",
                )
            )

    return findings


__all__ = [
    "WEAK_ALGORITHM",
    "WEAK_CIPHER_MODE",
    "WEAK_KEY_SIZE",
    "WEAK_PROTOCOL",
    "EXPIRED_CERTIFICATE",
    "WEAK_CERTIFICATE_SIGNATURE",
    "WEAK_CERTIFICATE_KEY",
    "SELF_SIGNED_LEAF",
    "WEAK_RNG",
    "STATIC_IV",
    "REUSED_NONCE",
    "HARDCODED_KEY",
    "WEAK_CIPHER_SUITE",
    "WEAK_PADDING",
    "WEAK_CRYPTO_CODES",
    "weak_finding",
    "weak_padding_finding",
    "cert_expiry_finding",
    "certificate_findings",
    "material_misuse_findings",
    "cipher_suite_findings",
]
