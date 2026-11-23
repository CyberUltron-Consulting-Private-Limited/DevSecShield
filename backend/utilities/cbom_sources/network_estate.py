"""Network evidence of the team's CBOM Sources collections, shaped for D7 (Network, TLS and Crypto Protocol Assessment).

Reads the rows of each source's latest completed collection (``cert_estate.EstateInputs`` on the team view, loaded
once by ``load_team_cbom_view``) and returns plain records the PDF prints:

* ``tls_endpoints``   one record per ``host:port`` (plus SNI when the probe used one): the newest observation wins,
                      the other sources that probed it are listed (``also_seen``); full accepted-suite list per
                      protocol version with the prober's completeness flags, groups, chain, and a letter grade;
* ``ssh_endpoints``   host keys, key exchange, ciphers and MACs per endpoint (same de-duplication);
* ``appliance_configs`` Cisco IOS / ASA, FortiOS, PAN-OS, F5 BIG-IP TLS / SSH / IKE / IPsec settings with findings;
* ``ike_endpoints``   IKE gateways the probe answered (chosen proposal, weak transforms accepted, PQ support);
* ``ot_endpoints``    OPC UA endpoints (security modes, policies, user tokens) and Modbus/TCP ports. Modbus is
                      port-open evidence only: no Modbus request is ever sent (SOW 7.2 excludes active OT testing).

Rows of a source that has been deleted are left out everywhere and counted (``deleted_rows``), so a deleted source is
never "current". Pure: no database, no clock, no network.

Grade rubric (``RUBRIC``), modelled on the Qualys SSL Labs SSL Server Rating Guide (2009, updates to 2020):
score = 0.3 x protocol + 0.3 x key exchange + 0.4 x cipher strength, letters A >= 80, B >= 65, C >= 50, D >= 35,
E >= 20, F below; then caps. It is computed only from what the probe observed; an endpoint whose suite enumeration
was not complete gets its grade marked provisional (``*``).
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from backend.utilities.cbom_sources.cert_estate import inputs_of, is_deleted, thumbprint

TLS_VERSIONS = ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")
STARTTLS_PREFIX = "starttls-"
_CHAIN = re.compile(r"#chain\[(\d+)\]")
# IANA TLS Supported Groups names of the classical groups (https://www.iana.org/assignments/tls-parameters,
# registry 8); post-quantum and hybrid group names are spelled by algid (CB-04 single source)
_IANA_GROUPS = {name.casefold(): name for name in (
    "x25519", "x448", "secp256r1", "secp384r1", "secp521r1", "ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144",
    "ffdhe8192", "brainpoolP256r1tls13", "brainpoolP384r1tls13", "brainpoolP512r1tls13")}
_GROUP_ALIASES = {"prime256v1": "secp256r1", "p-256": "secp256r1", "p-384": "secp384r1", "p-521": "secp521r1"}


def _post_quantum(name: Any, namespace: str | None = None) -> bool:
    """A pure or hybrid post-quantum key exchange (algid decides: CB-04)."""
    from backend.utilities.cbom_sources import algid

    text = str(name or "")
    found = algid.ssh_kex(text) if namespace == "ssh_kex" else algid.resolve(text)
    return found is not None and found.quantum in ("safe", "hybrid")

# ----------------------------------------------------------------------------- rubric
PROTOCOL_SCORE = {"SSLv2": 0, "SSLv3": 80, "TLSv1.0": 90, "TLSv1.1": 95, "TLSv1.2": 100, "TLSv1.3": 100}
GRADE_BANDS = ((80, "A"), (65, "B"), (50, "C"), (35, "D"), (20, "E"), (0, "F"))
RUBRIC = (
    ("Protocol (30 %)", "Average of the best and the worst version offered: TLS 1.3 / 1.2 = 100, TLS 1.1 = 95, "
                        "TLS 1.0 = 90, SSL 3 = 80, SSL 2 = 0."),
    ("Key exchange (30 %)", "Strength of the negotiated key exchange in RSA-equivalent bits: < 512 = 20, < 1024 = 40, "
                            "< 2048 = 80, < 4096 = 90, >= 4096 = 100 (X25519 / P-256 count as 3072, P-384 / P-521 / "
                            "X448 as 7680, a finite-field DH group as its modulus size, a post-quantum hybrid group as "
                            "100). Static RSA key exchange counts the certificate key. When the probe recorded no key "
                            "exchange it scores 80 (the < 2048 tier), the grade is capped at B and the endpoint says "
                            "'key exchange not recorded'."),
    ("Cipher strength (40 %)", "Average of the strongest and the weakest accepted suite: 0 bits (NULL) = 0, < 128 = 20, "
                               "< 256 = 80, >= 256 = 100 (3DES counts 112 bits, RC4 128)."),
    ("Letter", "A >= 80, B >= 65, C >= 50, D >= 35, E >= 20, else F; then the caps below (the lowest cap wins)."),
    ("Cap F", "SSL 2 offered; a NULL, EXPORT or anonymous suite accepted; certificate RSA key < 1024 bits."),
    ("Cap C", "SSL 3 offered; RC4 accepted; DES or 3DES (64-bit block, SWEET32) accepted."),
    ("Cap B", "TLS 1.0 or 1.1 offered; no forward secrecy for every client (static RSA key exchange accepted, or no "
              "ECDHE / DHE suite); CBC-only on TLS 1.2 without TLS 1.3; certificate RSA key < 2048 or EC key < 224 "
              "bits."),
    ("Trust T", "The leaf certificate is expired or self-signed: the grade is T and the letter it would have without "
                "the trust issue is shown beside it."),
    ("Provisional", "A grade followed by * was computed on an incomplete suite enumeration (handshake budget used up "
                    "or a version not read); the endpoint may accept more suites than listed."),
)


@dataclass(frozen=True)
class Grade:
    letter: str  # A..F, "T" (trust), "-" (no TLS)
    score: int | None
    provisional: bool = False
    caps: tuple[str, ...] = ()
    untrusted_letter: str = ""  # the letter ignoring trust when ``letter`` is "T"

    @property
    def text(self) -> str:
        if self.letter == "-":
            return "no TLS"
        base = self.letter + ("*" if self.provisional else "")
        return f"{base} (if trusted: {self.untrusted_letter})" if self.letter == "T" else base


def _suite_bits(name: str) -> int:
    upper = name.upper()
    if "WITH_NULL" in upper or "_NULL_" in upper or upper.endswith("_NULL") or "NULL-" in upper or "ENULL" in upper:
        return 0
    if "EXPORT" in upper or "EXP-" in upper:
        return 40
    if "DES40" in upper:
        return 40
    if "3DES" in upper or "DES-CBC3" in upper or "DES_EDE" in upper:
        return 112
    if re.search(r"(^|[_-])DES([_-]|$)", upper) or "DES_CBC" in upper:
        return 56
    if "RC4" in upper:
        return 128
    if "256" in upper or "CHACHA20" in upper:
        return 256
    if "128" in upper or "SEED" in upper or "IDEA" in upper:
        return 128
    return 128


def _band(score: float) -> str:
    return next(letter for floor, letter in GRADE_BANDS if score >= floor)


_ORDER = "ABCDEF"


def _worse(a: str, b: str) -> str:
    return a if _ORDER.index(a) >= _ORDER.index(b) else b


# RSA-equivalent strength of a named elliptic-curve / Edwards group (NIST SP 800-57 Part 1 Table 2)
_CURVE_RSA_BITS = {"x25519": 3072, "secp256r1": 3072, "p-256": 3072, "prime256v1": 3072, "brainpoolp256r1": 3072,
                   "brainpoolp256r1tls13": 3072, "secp224r1": 2048, "p-224": 2048, "x448": 7680, "secp384r1": 7680,
                   "p-384": 7680, "brainpoolp384r1": 7680, "brainpoolp384r1tls13": 7680, "secp521r1": 15360,
                   "p-521": 15360, "brainpoolp512r1": 15360, "brainpoolp512r1tls13": 15360}
_FFDHE = re.compile(r"^ffdhe(\d{4})$")
_BITS = re.compile(r"(\d{2,5})\s*bits?\b")


def _ec_rsa_bits(bits: int) -> int:
    return 15360 if bits >= 512 else 7680 if bits >= 384 else 3072 if bits >= 250 else 2048 if bits >= 224 else 1024


def _kx_bits(facts: Mapping[str, Any], static_rsa: bool, leaf_bits: int | None) -> int | None:
    """RSA-equivalent bits of the key exchange, or None when the probe recorded none. Exact tokens, never
    substrings: "DH, 2560 bits" is a 2560-bit finite-field group, not P-256 (OpenSSL ``Server Temp Key`` forms:
    "X25519, 253 bits", "ECDH, P-256, 256 bits", "ECDH, prime256v1, 256 bits", "DH, 2048 bits")."""
    if static_rsa and leaf_bits:
        return leaf_bits
    group = norm_group(facts.get("negotiated_group") or "")
    temp = str(facts.get("server_temp_key") or "")
    parts = [p.strip() for p in temp.split(",") if p.strip()]
    if _post_quantum(group) or any(_post_quantum(p) for p in parts[:2]):
        return 15360
    fold = group.casefold()
    if fold in _CURVE_RSA_BITS:
        return _CURVE_RSA_BITS[fold]
    match = _FFDHE.match(fold)
    if match:
        return int(match.group(1))
    if parts:
        kind = parts[0].casefold()
        named = next((p.casefold() for p in parts[1:] if p.casefold() in _CURVE_RSA_BITS), "")
        size = next((int(m.group(1)) for p in parts if (m := _BITS.search(p.casefold()))), None)
        if kind in _CURVE_RSA_BITS:
            return _CURVE_RSA_BITS[kind]
        if kind in ("dh", "dhe", "ffdh"):
            return size
        if kind in ("ecdh", "ecdhe"):
            return _CURVE_RSA_BITS[named] if named else (_ec_rsa_bits(size) if size else None)
    return None


def kx_score(bits: int | None) -> int:
    """The key-exchange part of the score; an unrecorded key exchange scores the < 2048 tier (80)."""
    if bits is None:
        return 80
    return 20 if bits < 512 else 40 if bits < 1024 else 80 if bits < 2048 else 90 if bits < 4096 else 100


_WEAK_RULES = (  # (reason, test on the upper-case IANA / OpenSSL suite name); the grade caps read the same list
    ("NULL cipher", lambda n: _suite_bits(n) == 0),
    ("EXPORT", lambda n: "EXPORT" in n or "EXP-" in n),
    ("anonymous key exchange", lambda n: "_ANON_" in n or n.startswith(("ADH", "AECDH"))),
    ("RC4", lambda n: "RC4" in n),
    ("64-bit block (DES / 3DES)", lambda n: _suite_bits(n) in (56, 112)),
)


def weak_by_name(names: Iterable[str]) -> dict[str, list[str]]:
    """Weak suites by reason, from the suite names alone (``_WEAK_RULES``)."""
    out: dict[str, list[str]] = {}
    for name in names:
        upper = str(name).upper()
        for reason, test in _WEAK_RULES:
            if test(upper):
                out.setdefault(reason, [])
                if name not in out[reason]:
                    out[reason].append(str(name))
    return out


def grade_tls(facts: Mapping[str, Any], as_of: Any = None) -> Grade:
    """The SSL Labs-style grade of one probed TLS endpoint (see ``RUBRIC``); ``as_of`` (a date) decides whether the
    leaf certificate has expired (no clock is read here)."""
    if facts.get("tls") is False or facts.get("tls_offered") is False or facts.get("plaintext_only"):
        return Grade("-", None)
    versions = facts.get("versions") if isinstance(facts.get("versions"), Mapping) else {}
    offered = [v for v in TLS_VERSIONS if versions.get(v) is True]
    if not offered and facts.get("negotiated_version") in PROTOCOL_SCORE:
        offered = [str(facts["negotiated_version"])]
    suites = accepted_suites(facts)
    names = [n for items in suites.values() for n in items] or [str(s) for s in facts.get("ciphers") or []]
    if not names and facts.get("negotiated_cipher"):
        names = [str(facts["negotiated_cipher"])]
    if not offered or not names:
        return Grade("-", None, caps=("not enough handshake data to grade",))
    protocol = (PROTOCOL_SCORE[offered[-1]] + PROTOCOL_SCORE[offered[0]]) / 2
    leaf = facts.get("leaf") if isinstance(facts.get("leaf"), Mapping) else {}
    leaf_bits = _int(leaf.get("key_size"))
    weak = facts.get("weak_ciphers_accepted") if isinstance(facts.get("weak_ciphers_accepted"), Mapping) else {}
    static_rsa = bool(weak.get("static_rsa")) or any(re.match(r"TLS_RSA_WITH", n) for n in names)
    kx = _kx_bits(facts, static_rsa and not any("ECDHE" in n or "DHE" in n for n in names), leaf_bits)
    bits = [_suite_bits(n) for n in names]
    strong, weakest = max(bits), min(bits)
    cipher = sum((0 if b == 0 else 20 if b < 128 else 80 if b < 256 else 100) for b in (strong, weakest)) / 2
    score = round(0.3 * protocol + 0.3 * kx_score(kx) + 0.4 * cipher)
    letter, caps = _band(score), []

    def cap(to: str, why: str) -> None:
        nonlocal letter
        if _worse(to, letter) == to and to != letter:
            letter = to
        caps.append(why)

    upper = [n.upper() for n in names]
    by_reason = weak_by_name(names)
    if "SSLv2" in offered:
        cap("F", "SSL 2 offered")
    if any(r in by_reason for r in ("NULL cipher", "EXPORT", "anonymous key exchange")):
        cap("F", "NULL, EXPORT or anonymous suite accepted")
    if leaf_bits and str(leaf.get("key_alg") or "").upper().startswith("RSA") and leaf_bits < 1024:
        cap("F", f"certificate RSA key {leaf_bits} bits")
    if "SSLv3" in offered:
        cap("C", "SSL 3 offered")
    if "RC4" in by_reason:
        cap("C", "RC4 accepted")
    if "64-bit block (DES / 3DES)" in by_reason:
        cap("C", "DES / 3DES (64-bit block) accepted")
    if kx is None:
        cap("B", "key exchange not recorded (scored as < 2048 bits)")
    elif kx < 1024:
        cap("F", f"key exchange {kx} bits")
    if "TLSv1.0" in offered or "TLSv1.1" in offered:
        cap("B", "TLS 1.0 / 1.1 offered")
    has_fs = any("ECDHE" in n or "DHE" in n or n.startswith(("TLS_AES_", "TLS_CHACHA20_")) for n in upper)
    if static_rsa or not has_fs:
        cap("B", "no forward secrecy for every client (static RSA key exchange accepted)")
    tls12 = [n.upper() for n in suites.get("TLSv1.2", [])]
    if tls12 and not any("GCM" in n or "CHACHA20" in n or "CCM" in n for n in tls12) and "TLSv1.3" not in offered:
        cap("B", "no AEAD suite (CBC only)")
    key_alg = str(leaf.get("key_alg") or "").upper()
    if leaf_bits and ((key_alg.startswith("RSA") and leaf_bits < 2048) or (key_alg.startswith("EC") and leaf_bits < 224)):
        cap("B", f"certificate {key_alg or 'key'} {leaf_bits} bits")
    enumeration = facts.get("enumeration") if isinstance(facts.get("enumeration"), Mapping) else {}
    complete_map = facts.get("cipher_suites_complete") if isinstance(facts.get("cipher_suites_complete"), Mapping) \
        else {}
    provisional = enumeration.get("complete") is False or any(v is False for v in complete_map.values())
    trust = []
    if leaf.get("self_signed") is True:
        trust.append("self-signed leaf certificate")
    if _expired(leaf.get("not_after"), as_of):
        trust.append("expired leaf certificate")
    if trust:
        return Grade("T", score, provisional, tuple(caps + trust), untrusted_letter=letter)
    return Grade(letter, score, provisional, tuple(caps))


def _expired(not_after: Any, as_of: Any) -> bool:
    import datetime as _dt

    if as_of is None or not not_after:
        return False
    try:
        return _dt.date.fromisoformat(str(not_after)[:10]) < (as_of.date() if isinstance(as_of, _dt.datetime) else as_of)
    except ValueError:
        return False


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def norm_group(name: Any) -> str:
    text = str(name or "").strip()
    fold = text.casefold()
    fold = _GROUP_ALIASES.get(fold, fold)
    if fold in _IANA_GROUPS:
        return _IANA_GROUPS[fold]
    if _post_quantum(text):
        from backend.utilities.cbom_sources import algid

        found = algid.resolve(text)
        return found.name if found is not None and found.name else text
    return text


def accepted_suites(facts: Mapping[str, Any]) -> dict[str, list[str]]:
    """Accepted cipher suites per protocol version (IANA names), as the probe recorded them."""
    raw = facts.get("cipher_suites") if isinstance(facts.get("cipher_suites"), Mapping) else {}
    out: dict[str, list[str]] = {}
    for version in TLS_VERSIONS:
        items = raw.get(version)
        if not isinstance(items, (list, tuple)):
            continue
        names = []
        for item in items:
            name = item.get("name") if isinstance(item, Mapping) else item
            if name and str(name) not in names:
                names.append(str(name))
        if names:
            out[version] = names
    return out


# ----------------------------------------------------------------------------- de-duplication
def _rows(view: Any, node_types: Iterable[str]) -> tuple[list[Any], int]:
    wanted = set(node_types)
    rows, deleted = [], 0
    for item in inputs_of(view).rows:
        if str(getattr(item, "node_type", "")) not in wanted:
            continue
        if is_deleted(item.collection):
            deleted += 1
            continue
        rows.append(item)
    return rows, deleted


def endpoint_key(item: Any) -> str:
    """``host:port`` (the location without its ``#fragment``), plus ``/sni`` when the probe sent one."""
    location = str(item.row.get("location") or "") if isinstance(item.row, Mapping) else ""
    base = location.split("#", 1)[0] or str(getattr(item, "target", "") or "")
    facts = item.facts if isinstance(item.facts, Mapping) else {}
    sni = str(facts.get("sni") or facts.get("server_name") or "").strip()
    return f"{base}/{sni}" if sni and sni not in base else base


@dataclass(frozen=True)
class Observed:
    """The newest observation of one endpoint, and the other sources that saw it."""

    key: str
    item: Any
    also_seen: tuple[str, ...] = ()

    @property
    def facts(self) -> Mapping[str, Any]:
        return self.item.facts if isinstance(self.item.facts, Mapping) else {}

    @property
    def source(self) -> str:
        return str(self.item.collection.label)

    @property
    def codes(self) -> tuple[str, ...]:
        row = self.item.row if isinstance(self.item.row, Mapping) else {}
        return tuple(str(c) for c in (row.get("collector_codes") or row.get("finding_codes") or []))

    @property
    def impact(self) -> str:
        row = self.item.row if isinstance(self.item.row, Mapping) else {}
        return str(row.get("impact") or "")


def dedupe(items: Sequence[Any], key=endpoint_key) -> list[Observed]:
    groups: dict[str, list[Any]] = {}
    for item in items:
        groups.setdefault(key(item), []).append(item)
    out = []
    for k, members in groups.items():
        members = sorted(members, key=lambda i: (i.collection.observed_at, i.collection.job_id), reverse=True)
        others = tuple(dict.fromkeys(m.collection.label for m in members[1:] if m.collection.label
                                     != members[0].collection.label))
        out.append(Observed(k, members[0], others))
    out.sort(key=lambda o: _sort_key(o.key))
    return out


def _sort_key(key: str) -> tuple:
    host, _sep, rest = key.partition(":")
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return (0, tuple(int(p) for p in parts), _int(rest.split("/")[0]) or 0, key)
    return (1, (), 0, key.casefold())


# ----------------------------------------------------------------------------- TLS
@dataclass(frozen=True)
class ChainCert:
    index: int
    subject: str
    issuer: str
    not_after: str
    thumbprint: str
    key: str


@dataclass(frozen=True)
class TlsEndpoint:
    observed: Observed
    service: str
    starttls: bool
    grade: Grade
    suites: Mapping[str, Sequence[str]]
    suites_complete: Mapping[str, bool]
    groups: tuple[str, ...]
    chain: tuple[ChainCert, ...] = ()
    not_read: tuple[str, ...] = field(default=())

    @property
    def key(self) -> str:
        return self.observed.key


def chain_index(certs: Sequence[Any]) -> dict[str, tuple[ChainCert, ...]]:
    """``host:port`` -> the certificates its handshake presented, by chain position (``#chain[i]`` locations). Built
    once per document in one pass over the certificate rows, so the lookup per endpoint is a dict read (a
    5,000-endpoint, 10,000-certificate estate is linear, not quadratic)."""
    found: dict[str, dict[int, ChainCert]] = {}
    for item in certs:
        location = str(item.row.get("location") or "")
        match = _CHAIN.search(location)
        if not match:
            continue
        slots = found.setdefault(location.split("#", 1)[0], {})
        index = int(match.group(1))
        if index in slots:
            continue  # the first row read for this position wins (rows come newest collection first per source)
        facts = item.facts if isinstance(item.facts, Mapping) else {}
        key = f"{facts.get('key_alg') or ''} {facts.get('key_size') or facts.get('curve') or ''}".strip()
        slots[index] = ChainCert(index, str(facts.get("subject") or ""), str(facts.get("issuer") or ""),
                                 str(facts.get("not_after") or ""), thumbprint(facts), key)
    return {endpoint: tuple(slots[i] for i in sorted(slots)) for endpoint, slots in found.items()}


def tls_endpoints(view: Any) -> tuple[list[TlsEndpoint], int]:
    """(unique TLS endpoints, rows left out because their source was deleted)."""
    rows, deleted = _rows(view, ("tls_endpoint",))
    certs, _d = _rows(view, ("certificate",))
    certs.sort(key=lambda i: (i.collection.observed_at, i.collection.job_id), reverse=True)  # newest read wins
    chains = chain_index(certs)
    out = []
    for observed in dedupe(rows):
        facts = observed.facts
        service = str(facts.get("service") or facts.get("protocol_label") or "tls")
        groups = [norm_group(g) for g in (facts.get("groups") or []) if g]
        if facts.get("negotiated_group") and norm_group(facts["negotiated_group"]) not in groups:
            groups.insert(0, norm_group(facts["negotiated_group"]))
        complete = facts.get("cipher_suites_complete") if isinstance(facts.get("cipher_suites_complete"), Mapping) \
            else {}
        enumeration = facts.get("enumeration") if isinstance(facts.get("enumeration"), Mapping) else {}
        out.append(TlsEndpoint(
            observed=observed, service=service, starttls=service.startswith(STARTTLS_PREFIX),
            grade=grade_tls(facts, getattr(view, "as_of", None)), suites=accepted_suites(facts),
            suites_complete={str(k): bool(v) for k, v in complete.items()}, groups=tuple(dict.fromkeys(groups)),
            chain=chains.get(observed.key.split("/", 1)[0], ()),
            not_read=tuple(str(x) for x in (enumeration.get("not_complete") or [])[:12])))
    return out, deleted


def tls_net(endpoint: TlsEndpoint, evidence: str) -> dict[str, Any]:
    """The endpoint as a posture fact with a ``net`` block (the vocabulary of the D7 tables)."""
    facts = endpoint.observed.facts
    versions = facts.get("versions") if isinstance(facts.get("versions"), Mapping) else {}
    key_map = (("SSLv3", "SSLv3"), ("TLSv1.0", "1.0"), ("TLSv1.1", "1.1"), ("TLSv1.2", "1.2"), ("TLSv1.3", "1.3"))
    protocols = {short: ("offered" if versions.get(name) is True else "not_offered" if versions.get(name) is False
                         else "unknown") for name, short in key_map}
    offered = [name for name, _s in key_map if versions.get(name) is True]

    def label(name: str) -> str:
        return name.replace("TLSv", "TLS ") if name.startswith("TLSv") else name

    weak_map = facts.get("weak_ciphers_accepted") if isinstance(facts.get("weak_ciphers_accepted"), Mapping) else {}
    # the probe's weak classes and the name rules the grade caps on (RC4, 3DES, NULL, EXPORT, anon), one row per suite
    reasons: dict[str, list[str]] = {}
    for reason, suites in sorted(weak_map.items()):
        for suite in suites if isinstance(suites, (list, tuple)) else ():
            reasons.setdefault(str(suite), []).append(str(reason).replace("_", " "))
    for reason, suites in weak_by_name([n for items in endpoint.suites.values() for n in items]).items():
        for suite in suites:
            if reason not in reasons.setdefault(suite, []):
                reasons[suite].append(reason)
    weak = [{"suite": suite, "reasons": why} for suite, why in reasons.items()]
    leaf = facts.get("leaf") if isinstance(facts.get("leaf"), Mapping) else {}
    scsv = facts.get("fallback_scsv")
    downgrade = "" if scsv is None else ("TLS_FALLBACK_SCSV supported" if scsv else "TLS_FALLBACK_SCSV not supported")
    if facts.get("downgrade_exposed") is True:
        downgrade = "downgrade exposed"
    net: dict[str, Any] = {
        "endpoint": endpoint.key, "evidence": evidence, "protocols": protocols,
        "min": label(offered[0]) if offered else "", "max": label(offered[-1]) if offered else "",
        "weak_suites": weak, "kx": {"curves": list(endpoint.groups)},
        "fs": "RSA key exchange accepted" if weak_map.get("static_rsa") else "",
        "downgrade": downgrade, "grade": endpoint.grade.text,
    }
    if facts.get("tls") is False or facts.get("tls_offered") is False:
        net["min"] = net["max"] = "no TLS"
    if leaf:
        net["certificate"] = {
            "subject": leaf.get("subject") or "", "issuer": leaf.get("issuer") or "",
            "not_before": leaf.get("not_before") or "", "not_after": leaf.get("not_after") or "",
            "signature_algorithm": leaf.get("sig_alg") or "", "key_size": leaf.get("key_size") or "",
            "chain": f"{len(endpoint.chain) or facts.get('chain_length') or 1} certificate(s) presented",
        }
    seen = endpoint.observed.source + (f" (also: {', '.join(endpoint.observed.also_seen)})"
                                       if endpoint.observed.also_seen else "")
    return {"id": f"sources-endpoint:{endpoint.key}", "kind": "tls_endpoint", "address": endpoint.key,
            "name": str(endpoint.observed.item.row.get("title") or endpoint.key), "evidence": evidence, "net": net,
            "finding_codes": list(endpoint.observed.codes), "impact": endpoint.observed.impact, "location": seen}


# ----------------------------------------------------------------------------- SSH
def ssh_endpoints(view: Any) -> tuple[list[Observed], int]:
    rows, deleted = _rows(view, ("ssh_endpoint",))
    return dedupe(rows), deleted


def ssh_host_keys(observed: Observed) -> list[str]:
    facts = observed.facts
    keys = facts.get("host_keys") if isinstance(facts.get("host_keys"), list) else []
    out = []
    for key in keys:
        if isinstance(key, Mapping):
            fp = str(key.get("fingerprint") or "")
            out.append(f"{key.get('type') or '?'} {key.get('bits') or ''}".strip() + (f" {fp}" if fp else ""))
    if not out and isinstance(facts.get("host_key"), Mapping):
        hk = facts["host_key"]
        out.append(f"{hk.get('key_type') or '?'} {hk.get('bits') or ''}".strip())
    return out


def ssh_pq_kex(observed: Observed) -> bool:
    return any(_post_quantum(k, "ssh_kex") for k in observed.facts.get("kex") or [])


def _union(*lists: Any) -> list[str]:
    out: list[str] = []
    for items in lists:
        for item in items or []:
            if str(item) not in out:
                out.append(str(item))
    return out


def ssh_algorithms(observed: Observed) -> dict[str, list[str]]:
    facts = observed.facts
    return {
        "kex": [k for k in _union(facts.get("kex")) if not k.startswith(("ext-info", "kex-strict"))],
        "host_key_algs": _union(facts.get("host_key_algs")),
        "ciphers": _union(facts.get("ciphers_c2s"), facts.get("ciphers_s2c"), facts.get("ciphers")),
        "macs": _union(facts.get("macs_c2s"), facts.get("macs_s2c"), facts.get("macs")),
    }


# ----------------------------------------------------------------------------- appliances, IKE, OT
APPLIANCE_KINDS = {"tls": "TLS", "ssh": "SSH", "ike_policy": "IKE proposal", "ipsec_policy": "IPsec transform"}


def appliance_configs(view: Any) -> tuple[list[Observed], int]:
    rows, deleted = _rows(view, ("appliance_config",))

    def key(item: Any) -> str:
        facts = item.facts if isinstance(item.facts, Mapping) else {}
        return f"{facts.get('appliance') or item.target or ''}|{facts.get('kind') or ''}|{facts.get('section') or ''}"

    out = dedupe(rows, key)
    out.sort(key=lambda o: (_sort_key(str(o.facts.get("appliance") or "")), str(o.facts.get("kind") or ""),
                            str(o.facts.get("section") or "")))
    return out, deleted


def appliance_settings(observed: Observed) -> str:
    facts = observed.facts
    kind = str(facts.get("kind") or "")
    parts: list[str] = []

    def add(label: str, value: Any) -> None:
        if isinstance(value, (list, tuple)):
            value = ", ".join(str(v) for v in value)
        if value not in (None, "", []):
            parts.append(f"{label}: {value}")

    if kind == "tls":
        add("protocols", facts.get("protocols"))
        add("ciphers", facts.get("ciphers"))
        add("cipher group", facts.get("cipher_group"))
    elif kind == "ssh":
        add("versions", facts.get("versions"))
        add("kex", facts.get("kex"))
        add("ciphers", facts.get("ciphers"))
        add("MACs", facts.get("macs"))
        add("DH min bits", facts.get("dh_min_bits"))
    elif kind in ("ike_policy", "ipsec_policy"):
        add("IKE version", facts.get("version"))
        add("encryption", facts.get("encryption"))
        add("integrity", facts.get("integrity"))
        add("DH groups", facts.get("groups"))
        add("PFS", facts.get("pfs"))
        add("lifetime", facts.get("lifetime"))
    else:
        for k, v in sorted(facts.items()):
            if k not in ("vendor", "vendor_label", "appliance", "section", "kind") and isinstance(v, (str, int, list)):
                add(k, v)
    return "; ".join(parts)


def ike_endpoints(view: Any) -> tuple[list[Observed], int]:
    rows, deleted = _rows(view, ("ike_endpoint",))
    return dedupe(rows), deleted


def ike_summary(observed: Observed) -> dict[str, str]:
    facts = observed.facts
    v2 = facts.get("ikev2") if isinstance(facts.get("ikev2"), Mapping) else {}
    v1 = facts.get("ikev1") if isinstance(facts.get("ikev1"), Mapping) else {}
    versions = [name for name, side in (("IKEv2", v2), ("IKEv1", v1)) if side.get("supported")]
    chosen = v2.get("chosen") if isinstance(v2.get("chosen"), Mapping) else {}
    chosen_text = ", ".join(f"{k} {v}" for k, v in chosen.items() if v) or (
        ", ".join(f"{k} {v}" for k, v in (v1.get("chosen") or {}).items() if v)
        if isinstance(v1.get("chosen"), Mapping) else str(v1.get("chosen") or ""))
    weak = []
    for name, side in (("IKEv2", v2), ("IKEv1", v1)):
        for cls, state in (side.get("weak") or {}).items() if isinstance(side.get("weak"), Mapping) else ():
            accepted = state.get("accepted") if isinstance(state, Mapping) else None
            if accepted:
                weak.append(f"{name} {cls}: {', '.join(str(a) for a in accepted)}")
    pq = v2.get("pq") if isinstance(v2.get("pq"), Mapping) else {}
    return {
        "versions": ", ".join(versions) or "none answered",
        "chosen": chosen_text,
        "weak": "; ".join(weak),
        "aggressive": "accepted" if v1.get("aggressive") is True or v1.get("aggressive_mode") is True else "",
        "pq": ("yes" + (f" ({pq.get('method')})" if pq.get("method") else "")) if pq.get("supported") else
              ("no" if pq else "not tested"),
        "unknown": "; ".join(str(u) for u in (facts.get("unknown") or [])[:4]),
    }


def ot_endpoints(view: Any) -> tuple[list[Observed], list[Observed], int]:
    """(OPC UA endpoints, Modbus/TCP endpoints, rows of deleted sources)."""
    rows, deleted = _rows(view, ("ot_endpoint",))
    found = dedupe(rows)
    opcua = [o for o in found if str(o.facts.get("service") or o.item.row.get("protocol_version") or "") == "opcua"]
    modbus = [o for o in found if str(o.facts.get("service") or "") == "modbus"]
    return opcua, modbus, deleted


def opcua_summary(observed: Observed) -> dict[str, str]:
    facts = observed.facts
    endpoints = facts.get("endpoints") if isinstance(facts.get("endpoints"), list) else []
    tokens: list[str] = []
    for ep in endpoints:
        for token in (ep.get("user_tokens") or []) if isinstance(ep, Mapping) else []:
            text = str(token.get("type") or token.get("token_type") or token) if isinstance(token, Mapping) else str(token)
            if text not in tokens:
                tokens.append(text)
    policies = [str(p).rsplit("#", 1)[-1] for p in facts.get("policies") or []]
    return {
        "application": str(facts.get("application_name") or facts.get("application_uri") or ""),
        "modes": ", ".join(str(m) for m in facts.get("modes") or []) or (
            "discovery refused" if facts.get("discovery") == "refused" else ""),
        "policies": ", ".join(policies),
        "tokens": ", ".join(tokens[:8]),
        "endpoints": str(len(endpoints)),
    }


__all__ = ["chain_index", "kx_score", "weak_by_name", "APPLIANCE_KINDS", "GRADE_BANDS", "PROTOCOL_SCORE", "RUBRIC", "ChainCert", "Grade", "Observed",
           "TlsEndpoint", "accepted_suites", "appliance_configs", "appliance_settings", "dedupe", "endpoint_key",
           "grade_tls", "ike_endpoints", "ike_summary", "norm_group", "opcua_summary", "ot_endpoints",
           "ssh_algorithms", "ssh_endpoints", "ssh_host_keys", "ssh_pq_kex", "tls_endpoints", "tls_net"]
