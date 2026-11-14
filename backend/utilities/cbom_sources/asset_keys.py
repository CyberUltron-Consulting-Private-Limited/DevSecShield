"""Cross-source asset keys (CB-21): engine step 3 "Correlate". One certificate, endpoint or cloud resource seen by
several collectors (a network prober, a Linux file, a Windows store, AWS ACM, CT logs, a code scan) is ONE asset.

Two keys, two jobs (both PURE: a later store recomputes them in backfills from stored facts alone):

* ``observation_key(row, source_ref)``: per source, what drift, waves and remediation assignments compare across runs
  (``identity.stable_key("node", source_ref, identity.node_identity(row))``; a renewal keeps it, "renewed"). It is
  ``identity``'s key, re-exported unchanged: CB-21 never moves it.
* ``asset_key(observation) -> str | None | NOT_CORRELATED``: across sources, what the team view, the roll-ups
  (CB-24/CB-25), the register (CB-19/CB-23) and the estate store (CB-20) count by. Strings are
  ``<kind>:<40 hex>`` (``cert:``, ``ep:``, ``cloud:``), at most 46 characters.
  - ``None``: the asset has no cross-source identity by nature (an algorithm, a library, a config file, a local key):
    it is identified within its own source (``observation_key``).
  - ``NOT_CORRELATED``: correlation is required but absent (a certificate with nothing identifying, a cloud resource
    declared in code with no link to the deployed resource). Falsy, not a string; ``.reason`` is qgrade's Q0 reason
    ``not_correlated``. Never use it as a key.

Certificate link keys (``link_keys``), strongest first; the asset key is the strongest one an observation has:
  1. ``serial``: serial + notAfter day. A serial of 64 bits or more (16+ hex digits; CA/B Forum certificates carry
     at least 64 random bits) needs no issuer, so ACM's Issuer "Amazon" and the node's RFC 4514 DN agree (DA-P3); a
     shorter serial (a private CA counting 1, 2, 3...) also needs the same normalised issuer DN.
  2. ``sha256``: the DER fingerprint. 3. ``sha1``: a Windows thumbprint (only Windows reports it).
  4. ``dn`` (weak): normalised subject DN + issuer DN + notAfter to the second (Windows has no serial or NotBefore).
  5. ``cn`` (weak): subject CN + issuer CN + notAfter to the second (code scans carry CN-only names).
Per observation, every source that reads the serial (prober, files, ACM, CT, IdP metadata) gets the same key without
help. A Windows row or a code row joins through ``correlate``: observations sharing any link key are one asset, keyed
by the strongest key in the group, except that two groups with different serials (or, through a weak key, different
fingerprints) are never joined: a DN match never merges two different certificates.

Endpoints: ``host:port`` (IPv6 bracketed and compressed, IPv4-mapped IPv6 as IPv4, host names lower case without the
trailing dot). Cloud resources: the ARN (exact), the Azure resource id or Key Vault object id (case-insensitive),
the GCP resource name. Code IaC rows that declare a cloud resource (``facts.cloud_resource``) are NOT_CORRELATED:
CloudFormation logical-id correlation needs the stack mapping and tags no collector reads yet (follow-up).
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from functools import cached_property, lru_cache
from typing import Any, Iterable, Mapping, Sequence

KEY_VERSION = "ak1"  # part of every hashed key: a rule change bumps it, so stored keys can be told apart
UTC = _dt.timezone.utc

CERT_TYPES = frozenset({"certificate", "k8s_certificate"})
ENDPOINT_TYPES = frozenset({"tls_endpoint", "ssh_endpoint", "database_tls", "k8s_ingress_tls", "load_balancer_tls",
                            "cdn_tls", "api_tls"})
LONG_SERIAL_HEX = 16  # 64 bits
STRONG = ("serial", "sha256", "sha1")
_RANK = {"serial": 0, "sha256": 1, "sha1": 2, "dn": 3, "cn": 4, "endpoint": 0, "cloud": 0}
_PREFIX = {"endpoint": "ep", "cloud": "cloud"}


class NotCorrelated:
    """Correlation required but absent (qgrade Q0 ``not_correlated``). A falsy singleton, never a key."""

    _instance: "NotCorrelated | None" = None
    reason = "not_correlated"

    def __new__(cls) -> "NotCorrelated":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __bool__(self) -> bool:
        return False

    def __repr__(self) -> str:
        return "NOT_CORRELATED"


NOT_CORRELATED = NotCorrelated()


@dataclass(frozen=True)
class Observation:
    """What one collector saw: the node asset type (or a code row's ``asset_type``), its facts and where."""

    kind: str
    facts: Mapping[str, Any] = field(default_factory=dict)
    location: str = ""
    target: str = ""
    origin: str = "sources"  # "sources" | "code"
    cdx_type: str = ""


@dataclass(frozen=True)
class LinkKey:
    basis: str  # serial | sha256 | sha1 | dn | cn | endpoint | cloud
    value: str

    @property
    def strong(self) -> bool:
        return self.basis not in ("dn", "cn")

    @cached_property
    def key(self) -> str:
        prefix = _PREFIX.get(self.basis, "cert")
        digest = hashlib.sha256(f"{KEY_VERSION}|{self.basis}|{self.value}".encode("utf-8", "replace")).hexdigest()
        return f"{prefix}:{digest[:40]}"


# ----------------------------------------------------------------------------- reading any observation shape
def observation(obj: Any) -> Observation:
    """An ``Observation`` from itself, a ``CbomCollectedAsset`` (or any object with ``asset_type``/``facts``), a
    ``collections_view.SourcesRow`` or a mapping (``asset_type``/``type``, ``facts``, ``location``, ``target``)."""
    if isinstance(obj, Observation):
        return obj
    if isinstance(obj, Mapping):
        facts = obj.get("facts")
        return Observation(kind=str(obj.get("asset_type") or obj.get("type") or obj.get("algorithm_type") or ""),
                           facts=facts if isinstance(facts, Mapping) else {},
                           location=str(obj.get("location") or ""), target=str(obj.get("target") or ""),
                           origin=str(obj.get("origin") if isinstance(obj.get("origin"), str) else "sources"),
                           cdx_type=str(obj.get("cdx_type") or ""))
    facts = getattr(obj, "facts", None)
    if hasattr(obj, "node_type"):  # collections_view.SourcesRow
        row = getattr(obj, "row", None) or {}
        return Observation(kind=str(obj.node_type or ""), facts=facts if isinstance(facts, Mapping) else {},
                           location=str(row.get("location") or ""), target=str(getattr(obj, "target", "") or ""),
                           cdx_type="certificate" if row.get("algorithm_type") == "certificate" else "")
    return Observation(kind=str(getattr(obj, "asset_type", "") or ""), facts=facts if isinstance(facts, Mapping) else {},
                       location=str(getattr(obj, "location", "") or ""), target=str(getattr(obj, "target", "") or ""),
                       cdx_type=str(getattr(obj, "cdx_type", "") or ""))


def is_certificate(obs: Observation) -> bool:
    return obs.kind in CERT_TYPES or obs.cdx_type == "certificate"


# ----------------------------------------------------------------------------- normalisation
_HEX = re.compile(r"^[0-9a-f]+$")
_FRACTION = re.compile(r"(\.\d{1,6})\d*")


def norm_serial(value: Any) -> str:
    """Hex serial, lower case, no separators or leading zeros ("0A:1B" -> "a1b"); "" if it is not hex."""
    if isinstance(value, int) and not isinstance(value, bool):
        return format(value, "x") if value >= 0 else ""
    text = re.sub(r"[\s:\-]", "", str(value or "").lower())
    text = text[2:] if text.startswith("0x") else text
    if not text or not _HEX.match(text):
        return ""
    return text.lstrip("0") or "0"


def norm_fingerprint(value: Any, size: int) -> str:
    text = re.sub(r"[\s:]", "", str(value or "").lower())
    return text if len(text) == size and _HEX.match(text) else ""


def utc_second(value: Any) -> str:
    """"YYYY-MM-DDTHH:MM:SS" in UTC from a datetime or ISO text (``Z``, offsets, 7-digit .NET fractions); ""."""
    moment: _dt.datetime | None = value if isinstance(value, _dt.datetime) else None
    if moment is None:
        text = str(value or "").strip().replace(" ", "T", 1)
        if not text:
            return ""
        text = _FRACTION.sub(r"\1", text)
        text = text[:-1] + "+00:00" if text[-1:] in ("Z", "z") else text
        try:
            moment = _dt.datetime.fromisoformat(text)
        except ValueError:
            return ""
    if moment.tzinfo is not None:
        moment = moment.astimezone(UTC).replace(tzinfo=None)
    return moment.strftime("%Y-%m-%dT%H:%M:%S")


_DN_ALIASES = {"E": "EMAILADDRESS", "EMAIL": "EMAILADDRESS", "1.2.840.113549.1.9.1": "EMAILADDRESS", "S": "ST",
               "2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
               "2.5.4.5": "SERIALNUMBER", "0.9.2342.19200300.100.1.25": "DC", "0.9.2342.19200300.100.1.1": "UID"}
_ATTR = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$|^(?:OID\.)?\d+(?:\.\d+)+$", re.IGNORECASE)


def _split_rdns(text: str) -> list[str]:
    """RFC 4514 / .NET (", " separated, values quoted or backslash-escaped) or OpenSSL "/C=US/O=x/CN=y"."""
    if text.startswith("/") and "=" in text:
        return [p for p in re.split(r"(?<!\\)/", text[1:]) if p]
    if "\\" not in text and '"' not in text:  # the common case: nothing quoted or escaped
        return [p for p in (x.strip() for x in _SEPARATORS.split(text)) if p]
    parts, buf, quoted, escaped = [], [], False, False
    for ch in text:
        if escaped:
            buf.append("\\" + ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == '"':
            quoted = not quoted
            buf.append(ch)
        elif ch in ",;+" and not quoted:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return [p for p in (x.strip() for x in parts) if p]


_SEPARATORS = re.compile(r"[,;+]")


def _unescape(value: str) -> str:
    value = value.strip()
    if "\\" not in value and '"' not in value:
        return value
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    raw = bytearray()
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value):
            pair = value[i + 1:i + 3]
            if len(pair) == 2 and re.match(r"^[0-9A-Fa-f]{2}$", pair):
                raw.append(int(pair, 16))
                i += 3
                continue
            raw.extend(value[i + 1].encode())
            i += 2
            continue
        raw.extend(ch.encode())
        i += 1
    return raw.decode("utf-8", "replace")


def dn_pairs(value: Any) -> tuple[tuple[str, str], ...] | None:
    """(ATTR, value) pairs in written order, values casefolded with whitespace collapsed; None if not a DN."""
    return _dn_pairs(value if isinstance(value, str) else str(value or ""))


@lru_cache(maxsize=65_536)  # issuer DNs repeat across a whole estate; subjects across sources
def _dn_pairs(raw: str) -> tuple[tuple[str, str], ...] | None:
    text = " ".join(raw.split())
    if not text or "=" not in text:
        return None
    pairs = []
    for part in _split_rdns(text):
        attr, sep, val = part.partition("=")
        attr = attr.strip().upper()
        if not sep or not _ATTR.match(attr):
            return None
        attr = attr[4:] if attr.startswith("OID.") else attr
        pairs.append((_DN_ALIASES.get(attr, attr), " ".join(_unescape(val).split()).casefold()))
    return tuple(pairs) or None


def norm_dn(value: Any) -> str:
    """Order-insensitive DN ("c=us,cn=x,o=y"); text that is not a DN is casefolded with whitespace collapsed."""
    return _dn_forms(value if isinstance(value, str) else str(value or ""))[0]


def dn_cn(value: Any) -> str:
    """The first CN of a DN, or the whole (casefolded) text when it is not a DN (code scans name the CN only)."""
    return _dn_forms(value if isinstance(value, str) else str(value or ""))[1]


@lru_cache(maxsize=65_536)
def _dn_forms(raw: str) -> tuple[str, str, bool]:
    """(normalised DN, CN, is a DN) of one name."""
    pairs = _dn_pairs(raw)
    if pairs is None:
        text = " ".join(raw.split()).casefold()
        return text, text, False
    return (",".join(f"{a.lower()}={v}" for a, v in sorted(pairs)),
            next((v for a, v in pairs if a == "CN"), ""), True)


def endpoint_host_port(value: Any) -> str | None:
    """"host:port" ("[v6]:port") of an endpoint location, or None when it has no parseable host and port."""
    text = str(value or "").strip().split("#", 1)[0]
    if "://" in text:
        text = text.split("://", 1)[1].split("/", 1)[0]
    match = re.fullmatch(r"\[([^\]]+)\]:(\d{1,5})", text)
    if match:
        host, port = match.group(1), match.group(2)
    elif text.count(":") == 1:
        host, port = text.split(":")
    else:
        return None
    if not port.isdigit() or not 0 < int(port) < 65536:
        return None
    host = host.strip()
    try:
        zone = ""
        if "%" in host:
            host, zone = host.split("%", 1)
            zone = "%" + zone.casefold()
        ip = ipaddress.ip_address(host)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if isinstance(ip, ipaddress.IPv6Address):
            return f"[{ip.compressed}{zone}]:{int(port)}"
        if match:  # "[10.0.0.5]:443"
            return f"{ip.compressed}:{int(port)}"
        return f"{ip.compressed}:{int(port)}"
    except ValueError:
        if match:
            return None  # brackets hold IPv6 addresses only
    name = host.casefold().rstrip(".")
    if not name or not re.fullmatch(r"[a-z0-9_*]([a-z0-9_.*-]*[a-z0-9_])?", name):
        return None
    return f"{name}:{int(port)}"


_AZURE_KV = re.compile(r"^https://[^/]+\.vault(?:core)?\.azure\.net/", re.IGNORECASE)
_GCP = re.compile(r"^projects/[^/]+/(locations|global|zones|regions)/")


def cloud_resource_id(value: Any) -> str:
    """The ARN (exact), Azure resource / Key Vault object id (casefolded) or GCP resource name; "" otherwise."""
    text = str(value or "").strip()
    if text.startswith("arn:") and text.count(":") >= 5:
        return text
    if text.casefold().startswith("/subscriptions/") or _AZURE_KV.match(text):
        return text.casefold()
    if _GCP.match(text):
        return text
    return ""


# ----------------------------------------------------------------------------- keys
def _cert_links(facts: Mapping[str, Any]) -> list[LinkKey]:
    out: list[LinkKey] = []
    after = utc_second(facts.get("not_after"))
    subject_raw, issuer_raw = facts.get("subject"), facts.get("issuer")
    subject_dn, subject_cn, subject_is_dn = _dn_forms(subject_raw if isinstance(subject_raw, str) else str(subject_raw or ""))
    issuer_dn, issuer_cn, issuer_is_dn = _dn_forms(issuer_raw if isinstance(issuer_raw, str) else str(issuer_raw or ""))
    serial = norm_serial(facts.get("serial") if facts.get("serial") not in (None, "") else facts.get("serial_number"))
    if serial and after:
        if len(serial) >= LONG_SERIAL_HEX:
            out.append(LinkKey("serial", f"{serial}|{after[:10]}"))
        elif issuer_is_dn:
            out.append(LinkKey("serial", f"{serial}|{after[:10]}|{issuer_dn}"))
    sha256 = norm_fingerprint(facts.get("fingerprint_sha256"), 64)
    if sha256:
        out.append(LinkKey("sha256", sha256))
    sha1 = norm_fingerprint(facts.get("thumbprint") or facts.get("fingerprint_sha1"), 40)
    if sha1:
        out.append(LinkKey("sha1", sha1))
    if after and subject_is_dn and issuer_is_dn:
        out.append(LinkKey("dn", f"{subject_dn}|{issuer_dn}|{after}"))
    if after and subject_cn:
        out.append(LinkKey("cn", f"{subject_cn}|{issuer_cn}|{after}"))
    return out


def link_keys(obj: Any) -> tuple[LinkKey, ...]:
    """Every key that can prove two observations are one asset, strongest first (empty when there is none)."""
    obs = observation(obj)
    facts = obs.facts
    if is_certificate(obs):
        return tuple(_cert_links(facts))
    if obs.origin == "code":
        return ()  # a code location is a file path: only certificates correlate from code today
    out: list[LinkKey] = []
    if obs.kind in ENDPOINT_TYPES:
        where = endpoint_host_port(obs.location)
        if where is None and facts.get("port") and obs.target:
            where = endpoint_host_port(f"[{obs.target}]:{facts.get('port')}" if ":" in str(obs.target)
                                       else f"{obs.target}:{facts.get('port')}")
        if where:
            out.append(LinkKey("endpoint", where))
    cloud = cloud_resource_id(facts.get("identity")) or cloud_resource_id(obs.location)
    if cloud:
        out.append(LinkKey("cloud", cloud))
    return tuple(out)


def _requires_correlation(obs: Observation) -> bool:
    return is_certificate(obs) or (obs.origin == "code" and bool(obs.facts.get("cloud_resource")))


def asset_key(obj: Any) -> str | None | NotCorrelated:
    """The cross-source key of one observation (pure). See the module docstring for the three kinds of answer."""
    obs = observation(obj)
    links = link_keys(obs)
    if links:
        return min(links, key=lambda k: _RANK[k.basis]).key
    return NOT_CORRELATED if _requires_correlation(obs) else None


def key_basis(obj: Any) -> str | None:
    """Which link key the asset key was made from (``serial``, ``sha256``, ``dn``, ``endpoint``...), or None."""
    links = link_keys(obj)
    return min(links, key=lambda k: _RANK[k.basis]).basis if links else None


def correlation_missing(obj: Any) -> bool:
    """True when correlation is required but absent (feeds ``qgrade.GradeInput.correlation_missing``)."""
    return asset_key(obj) is NOT_CORRELATED


def code_certificate(subject: Any, issuer: Any, not_before: Any = None, not_after: Any = None, *,
                     serial: Any = None, fingerprint_sha256: Any = None) -> Observation:
    """A code-scan certificate (``cbom_json`` certificateProperties / ``crypto:*`` properties) as an observation."""
    facts = {"subject": subject, "issuer": issuer, "not_before": not_before, "not_after": not_after,
             "serial": serial, "fingerprint_sha256": fingerprint_sha256}
    return Observation(kind="certificate", facts=facts, origin="code")


def code_certificate_key(subject: Any, issuer: Any, not_before: Any = None, not_after: Any = None, **kw: Any) -> str | None:
    key = asset_key(code_certificate(subject, issuer, not_before, not_after, **kw))
    return key if isinstance(key, str) else None


def observation_key(row: Any, source_ref: str) -> str:
    """The per-source key drift, waves and remediation assignments use (``identity``'s, unchanged)."""
    from backend.utilities.cbom_sources import identity as ID

    return ID.stable_key("node", source_ref, ID.node_identity(row))


def code_observation_key(row: Mapping[str, Any], source_ref: str) -> str:
    from backend.utilities.cbom_sources import identity as ID

    return ID.stable_key("code", source_ref, ID.code_identity(row))


# ----------------------------------------------------------------------------- correlation over a set
@dataclass
class Correlation:
    """``keys[i]``: the asset key of observation i (str, None or NOT_CORRELATED); ``aliases[i]``: every link-key
    string of its group (another view, e.g. a code row, that computes one of them is the same asset)."""

    keys: list[Any]
    aliases: list[frozenset[str]]


def correlate_detail(observations: Sequence[Any]) -> Correlation:
    """Group observations that share a link key (strong keys first); each group is keyed by its strongest key. PURE
    and independent of input order, except where one weak-only observation matches two different certificates (it
    joins one of them, never both)."""
    links = [link_keys(o) for o in observations]
    n = len(observations)
    parent = list(range(n))
    serials: dict[int, set[str]] = {}
    sha256s: dict[int, set[str]] = {}
    for i, keys in enumerate(links):
        serials[i] = {k.value for k in keys if k.basis == "serial"}
        sha256s[i] = {k.value for k in keys if k.basis == "sha256"}

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def join(a: int, b: int, strong: bool) -> bool:
        ra, rb = find(a), find(b)
        if ra == rb:
            return True
        if serials[ra] and serials[rb] and not serials[ra] & serials[rb]:
            return False
        if not strong and sha256s[ra] and sha256s[rb] and not sha256s[ra] & sha256s[rb]:
            return False
        ra, rb = min(ra, rb), max(ra, rb)
        parent[rb] = ra
        serials[ra] |= serials.pop(rb)
        sha256s[ra] |= sha256s.pop(rb)
        return True

    # every link key -> its observations, in a canonical order so the result does not depend on input order
    order = sorted(range(n), key=lambda i: tuple(sorted(k.key for k in links[i])))
    by_link: dict[tuple[int, str, str], list[int]] = {}
    for i in order:
        for k in links[i]:
            by_link.setdefault((_RANK[k.basis], k.basis, k.key), []).append(i)
    for (_rank, basis, _key), members in sorted(by_link.items()):
        strong = basis not in ("dn", "cn")
        roots: list[int] = []  # one per group this key could not join (almost always one)
        for i in members:
            for r in roots:
                if join(r, i, strong):
                    break
            else:
                roots.append(i)
    groups: dict[int, list[int]] = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(i)
    keys: list[Any] = [None] * n
    aliases: list[frozenset[str]] = [frozenset()] * n
    for members in groups.values():
        group_links = [k for i in members for k in links[i]]
        if not group_links:
            for i in members:
                keys[i] = asset_key(observations[i])
            continue
        best = min(group_links, key=lambda k: (_RANK[k.basis], k.key)).key
        names = frozenset(k.key for k in group_links)
        for i in members:
            keys[i], aliases[i] = best, names
    return Correlation(keys=keys, aliases=aliases)


def correlate(observations: Sequence[Any]) -> list[Any]:
    """The asset key of each observation once the set is correlated (same order as the input)."""
    return correlate_detail(observations).keys


def distinct_assets(observations: Iterable[Any]) -> int:
    """How many assets a set of observations is (each NOT_CORRELATED / None observation counts as its own)."""
    keys = correlate(list(observations))
    return len({k for k in keys if isinstance(k, str)}) + sum(1 for k in keys if not isinstance(k, str))


__all__ = ["CERT_TYPES", "Correlation", "ENDPOINT_TYPES", "KEY_VERSION", "LinkKey", "NOT_CORRELATED", "NotCorrelated",
           "Observation", "asset_key", "cloud_resource_id", "code_certificate", "code_certificate_key",
           "code_observation_key", "correlate", "correlate_detail", "correlation_missing", "distinct_assets",
           "dn_cn", "endpoint_host_port", "is_certificate", "key_basis", "link_keys", "norm_dn", "norm_serial",
           "observation", "observation_key", "utc_second"]
