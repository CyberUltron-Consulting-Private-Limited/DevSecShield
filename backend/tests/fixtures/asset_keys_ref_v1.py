"""FROZEN reference: ``asset_keys`` exactly as merged in #137 (dev 6c5647e08), before the CB-21 perf follow-up.
Tests compare the optimised module with it (same keys, aliases and contested keys). Never edit; never import from
product code."""
from __future__ import annotations

import datetime as _dt
import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Iterable, Mapping, Sequence

KEY_VERSION = "ak1"  # part of every hashed key: a rule change bumps it, so stored keys can be told apart
UTC = _dt.timezone.utc

CERT_TYPES = frozenset({"certificate", "k8s_certificate"})
ENDPOINT_TYPES = frozenset({"tls_endpoint", "ssh_endpoint", "database_tls", "k8s_ingress_tls", "load_balancer_tls",
                            "cdn_tls", "api_tls"})
LONG_SERIAL_HEX = 12  # 48 bits: a 64-bit random serial is shorter only with two leading zero bytes (1 in 65,536)
STRONG = ("serial", "sha256", "sha1")
WEAK = frozenset({"dn", "cnb", "cn"})
_RANK = {"serial": 0, "sha256": 1, "sha1": 2, "dn": 3, "cnb": 4, "cn": 5, "endpoint": 0, "cloud": 0, "group": 9}
_SCHEME_PORT = {"https": 443, "http": 80, "wss": 443, "ws": 80, "ldaps": 636, "ldap": 389, "ssh": 22, "sftp": 22,
                "smtps": 465, "smtp": 25, "imaps": 993, "pop3s": 995, "ftps": 990, "rdp": 3389, "postgres": 5432,
                "postgresql": 5432, "mysql": 3306, "mssql": 1433, "sqlserver": 1433, "mongodb": 27017, "redis": 6379,
                "rediss": 6379, "amqps": 5671, "mqtts": 8883, "kafka": 9092}
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
    scope: str = ""  # where a private address is unique: the source ref (``identity.job_source_ref``)


@dataclass(frozen=True, slots=True)
class LinkKey:
    basis: str  # serial | sha256 | sha1 | dn | cnb | cn | endpoint | cloud | group
    value: str
    key: str = field(init=False, compare=False, repr=False)  # "<kind>:<40 hex>", computed once

    def __post_init__(self) -> None:
        prefix = _PREFIX.get(self.basis, "cert")
        digest = hashlib.sha256(f"{KEY_VERSION}|{self.basis}|{self.value}".encode("utf-8", "replace")).hexdigest()
        object.__setattr__(self, "key", f"{prefix}:{digest[:40]}")

    @property
    def strong(self) -> bool:
        return self.basis not in WEAK


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
                           cdx_type=str(obj.get("cdx_type") or ""), scope=str(obj.get("scope") or ""))
    facts = getattr(obj, "facts", None)
    if hasattr(obj, "node_type"):  # collections_view.SourcesRow
        row = getattr(obj, "row", None) or {}
        return Observation(kind=str(obj.node_type or ""), facts=facts if isinstance(facts, Mapping) else {},
                           location=str(row.get("location") or ""), target=str(getattr(obj, "target", "") or ""),
                           cdx_type="certificate" if row.get("algorithm_type") == "certificate" else "",
                           scope=str(getattr(getattr(obj, "collection", None), "source_ref", "") or ""))
    return Observation(kind=str(getattr(obj, "asset_type", "") or ""), facts=facts if isinstance(facts, Mapping) else {},
                       location=str(getattr(obj, "location", "") or ""), target=str(getattr(obj, "target", "") or ""),
                       cdx_type=str(getattr(obj, "cdx_type", "") or ""), scope=str(getattr(obj, "scope", "") or ""))


def is_certificate(obs: Observation) -> bool:
    return obs.kind in CERT_TYPES or obs.cdx_type == "certificate"


# ----------------------------------------------------------------------------- normalisation
_HEX = re.compile(r"^[0-9a-f]+$")
_FRACTION = re.compile(r"(\.\d{1,6})\d*")


def norm_serial(value: Any) -> str:
    """Hex serial, lower case, no separators or leading zeros ("0A:1B" -> "a1b"); "" if it is not hex."""
    if isinstance(value, int) and not isinstance(value, bool):
        return format(value, "x") if value >= 0 else ""
    text = str(value or "").strip().lower()
    if text.startswith("-"):
        return ""  # a negative serial (malformed certificate) never equals its absolute value
    text = re.sub(r"[\s:\-]", "", text)
    text = text[2:] if text.startswith("0x") else text
    if not text or not _HEX.match(text):
        return ""
    return text.lstrip("0") or "0"


def norm_fingerprint(value: Any, size: int) -> str:
    text = str(value or "").lower()
    if len(text) == size and _HEX.match(text):
        return text
    text = re.sub(r"[\s:]", "", text)
    return text if len(text) == size and _HEX.match(text) else ""


def utc_second(value: Any) -> str:
    """"YYYY-MM-DDTHH:MM:SS" in UTC from a datetime or ISO text (``Z``, offsets, 7-digit .NET fractions); ""."""
    if isinstance(value, _dt.datetime):
        return _second(value)
    return _utc_text(value if isinstance(value, str) else str(value or ""))


@lru_cache(maxsize=65_536)  # an estate has few distinct validity instants
def _utc_text(raw: str) -> str:
    text = raw.strip().replace(" ", "T", 1)
    if not text:
        return ""
    text = _FRACTION.sub(r"\1", text)
    text = text[:-1] + "+00:00" if text[-1:] in ("Z", "z") else text
    try:
        return _second(_dt.datetime.fromisoformat(text))
    except ValueError:
        return ""


def _second(moment: _dt.datetime) -> str:
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
        scheme, text = text.split("://", 1)
        text = text.split("/", 1)[0].split("?", 1)[0].rsplit("@", 1)[-1]
        default = _SCHEME_PORT.get(scheme.strip().lower())
        if default and not re.search(r"(^[^:\[]*|\])(:\d+)$", text):
            text = f"{text}:{default}"
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


_AZURE_KV = re.compile(r"^https://[^/]+\.(?:vault|vaultcore|managedhsm)\.(?:azure\.net|azure\.cn|usgovcloudapi\.net|"
                       r"microsoftazure\.de)(?::443)?/(keys|secrets|certificates)/([^/?#]+)", re.IGNORECASE)
_GCP = re.compile(r"^(?://[a-z0-9.-]+\.googleapis\.com/)?(projects/[^/]+/.+)$", re.IGNORECASE)


def cloud_resource_id(value: Any) -> str:
    """The ARN (exact), Azure resource id or Key Vault object id without its version (casefolded, any Azure cloud), or
    the GCP resource name with any ``//service.googleapis.com/`` prefix dropped; "" otherwise."""
    text = str(value or "").strip()
    if text.startswith("arn:") and text.count(":") >= 5:
        return text
    if text.casefold().startswith("/subscriptions/"):
        return text.casefold().rstrip("/")
    vault = _AZURE_KV.match(text)
    if vault:
        host = text.split("/", 3)[2].split(":", 1)[0]
        return f"https://{host}/{vault.group(1)}/{vault.group(2)}".casefold()
    gcp = _GCP.match(text)
    if gcp:
        return gcp.group(1).rstrip("/")
    return ""


def _endpoint_value(obs: Observation) -> str | None:
    """The endpoint link value: host:port, scoped to the observation's source for a non-unique (private, loopback,
    link-local) address; None when such an address has no scope."""
    facts = obs.facts
    where = endpoint_host_port(obs.location)
    if where is None and facts.get("port") and obs.target:
        where = endpoint_host_port(f"[{obs.target}]:{facts.get('port')}" if ":" in str(obs.target)
                                   else f"{obs.target}:{facts.get('port')}")
    if where is None:
        return None
    host = where.rsplit(":", 1)[0].strip("[]").split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return where
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified:
        return f"{where}@{obs.scope}" if obs.scope else None
    return where


# ----------------------------------------------------------------------------- keys
_CERT_FIELDS = ("serial", "serial_number", "fingerprint_sha256", "thumbprint", "fingerprint_sha1", "subject", "issuer",
                "not_before", "not_after")


def _cert_links(facts: Mapping[str, Any]) -> list[LinkKey]:
    return list(_cert_analysis(facts)[0])


def _cert_analysis(facts: Mapping[str, Any]) -> tuple[tuple[LinkKey, ...], dict[str, frozenset[str]]]:
    """(link keys, conflict attributes) of one certificate observation (memoised: one certificate is usually seen
    by several sources and a CA in every chain). The result is shared: never mutate it."""
    fields = tuple(facts.get(name) for name in _CERT_FIELDS)
    try:
        return _cert_analysis_of(fields)
    except TypeError:  # an unhashable fact value: no memo
        return _cert_analysis_of.__wrapped__(fields)


@lru_cache(maxsize=65_536)
def _cert_analysis_of(fields: tuple[Any, ...]) -> tuple[tuple[LinkKey, ...], dict[str, frozenset[str]]]:
    facts = dict(zip(_CERT_FIELDS, fields))
    out: list[LinkKey] = []
    after = utc_second(facts.get("not_after"))
    subject_raw, issuer_raw = facts.get("subject"), facts.get("issuer")
    subject_dn, subject_cn, subject_is_dn = _dn_forms(subject_raw if isinstance(subject_raw, str) else str(subject_raw or ""))
    issuer_dn, issuer_cn, issuer_is_dn = _dn_forms(issuer_raw if isinstance(issuer_raw, str) else str(issuer_raw or ""))
    serial = norm_serial(facts.get("serial") if facts.get("serial") not in (None, "") else facts.get("serial_number"))
    if serial and after:
        if len(serial) >= LONG_SERIAL_HEX:
            out.append(LinkKey("serial", f"{serial}|{after[:10]}"))
        elif issuer_is_dn:  # a counting CA: same-named test CAs all start at 1, so the subject is part of it
            out.append(LinkKey("serial", f"{serial}|{after[:10]}|{issuer_dn}|{subject_dn if subject_is_dn else ''}"))
    sha256 = norm_fingerprint(facts.get("fingerprint_sha256"), 64)
    if sha256:
        out.append(LinkKey("sha256", sha256))
    sha1 = norm_fingerprint(facts.get("thumbprint") or facts.get("fingerprint_sha1"), 40)
    if sha1:
        out.append(LinkKey("sha1", sha1))
    if after and subject_is_dn and issuer_is_dn:
        out.append(LinkKey("dn", f"{subject_dn}|{issuer_dn}|{after}"))
    before = utc_second(facts.get("not_before"))
    if after and subject_cn and before:
        out.append(LinkKey("cnb", f"{subject_cn}|{issuer_cn}|{before}|{after}"))
    if after and subject_cn:
        out.append(LinkKey("cn", f"{subject_cn}|{issuer_cn}|{after}"))
    # what two observations of one certificate can never disagree on (absent when the observation does not say)
    values = (("serial", serial), ("sha256", sha256), ("sha1", sha1), ("issuer", issuer_dn if issuer_is_dn else ""),
              ("not_before", before))
    return tuple(out), {name: frozenset((value,)) for name, value in values if value}


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
        where = _endpoint_value(obs)
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
    """A code-scan certificate's MATCH TOKEN for ``collections_view.resolve`` (not a stored key): its ``cnb`` key
    (CN, issuer CN, notBefore, notAfter) then, after "+", its ``cn`` key, which only matches a Sources certificate
    that has no notBefore (a Windows store row). Without a notBefore it is the ``cn`` key alone. None when the row
    has no subject CN or notAfter. ``asset_key(code_certificate(...))`` is the stored key."""
    links = {k.basis: k.key for k in link_keys(code_certificate(subject, issuer, not_before, not_after, **kw))}
    if "cnb" in links:
        return f"{links['cnb']}+{links['cn']}"
    return links.get("cn")


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
    """``keys[i]``: the asset key of observation i (str, None or NOT_CORRELATED); ``aliases[i]``: the uncontested
    link keys of its group (a code row computing one of them is the same asset; a ``cn`` key only when no member has
    a notBefore, so a code row for another reissue of the same name and expiry is never matched)."""

    keys: list[Any]
    aliases: list[frozenset[str]]
    contested: frozenset[str] = frozenset()  # link keys shared by groups that disagree: they name no group


def _analysis(obs: Observation) -> tuple[tuple[LinkKey, ...], dict[str, frozenset[str]]]:
    if is_certificate(obs):
        return _cert_analysis(obs.facts)
    return link_keys(obs), {}


def correlate_detail(observations: Sequence[Any]) -> Correlation:
    """Correlate a set of observations (PURE, independent of input order, linear): see the module docstring."""
    obs = [observation(o) for o in observations]
    analysed = [_analysis(o) for o in obs]
    links = [a[0] for a in analysed]
    n = len(obs)
    parent = list(range(n))
    attrs: dict[int, dict[str, frozenset[str]]] = {i: a[1] for i, a in enumerate(analysed)}

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    by_link: dict[LinkKey, list[int]] = {}
    for i, keys in enumerate(links):
        for k in keys:
            by_link.setdefault(k, []).append(i)
    shared = sorted(((_RANK[k.basis], k.basis, k.value, members) for k, members in by_link.items() if len(members) > 1),
                    key=lambda b: b[:3])
    for _rank, _basis, _value, members in shared:
        roots = sorted({find(i) for i in members})
        if len(roots) < 2:
            continue
        # all or nothing: the bucket joins only when no two of its groups disagree on an attribute both carry
        merged: dict[str, frozenset[str]] = {}
        compatible = True
        for r in roots:
            for name, values in attrs[r].items():
                held = merged.get(name)
                if held is None:
                    merged[name] = values
                elif not held & values:
                    compatible = False
                    break
                else:
                    merged[name] = held | values
            if not compatible:
                break
        if not compatible:
            continue
        head = roots[0]
        for r in roots[1:]:
            parent[r] = head
        attrs[head] = merged
    groups: dict[int, list[int]] = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(i)
    contested = frozenset(LinkKey(basis, value).key for _r, basis, value, members in shared
                          if len({find(i) for i in members}) > 1)
    keys: list[Any] = [None] * n
    aliases: list[frozenset[str]] = [frozenset()] * n
    for root, members in groups.items():
        group_links = {k.key: k for i in members for k in links[i]}
        if not group_links:
            for i in members:
                keys[i] = asset_key(obs[i])
            continue
        clear = [k for k in group_links.values() if k.key not in contested]
        if clear:
            best = min(clear, key=lambda k: (_RANK[k.basis], k.key)).key
        else:  # every key it has is shared with a certificate it disagrees with: a key of its own
            best = LinkKey("group", "|".join(sorted(group_links))).key
        has_before = "not_before" in attrs[root]
        names = frozenset(k.key for k in clear if not (k.basis == "cn" and has_before))
        for i in members:
            keys[i], aliases[i] = best, names
    return Correlation(keys=keys, aliases=aliases, contested=contested)


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
