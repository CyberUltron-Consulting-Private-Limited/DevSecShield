"""OpenSSL cipher-string evaluator. Pure, total, no module-level cache."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass

from aibom.cbom.posture.context import PostureSink
from aibom.cbom.posture.defaults import (
    DefaultsRegistry,
    load_registry,
    read_data_bytes,
)
from aibom.cbom.posture.model import EncryptionFact
from aibom.cbom.weakness import cipher_suite_findings
from aibom.model.component import CryptoAssetComponent

_MAX_CHARS = 4096
_MAX_TOKENS = 512
_MAX_UNRESOLVED = 20
_TOKEN_CHARS = 64
_SUITE_CAP = 256
_CACHE_LIMIT = 1024
_LIST_SEPS = frozenset(":, \t\r\n")
_TLS13_SEPS = frozenset(": \t\r\n")
_PREFIXES = frozenset("!-+")


@dataclass(frozen=True, slots=True)
class CipherResult:
    suites: tuple[str, ...]
    explicit: tuple[str, ...]
    unresolved: tuple[str, ...]
    complete: bool
    seclevel: int | None
    truncated: bool


@dataclass(frozen=True, slots=True)
class GroupInfo:
    name: str
    bits: int


@dataclass(frozen=True, slots=True)
class GroupResult:
    groups: tuple[str, ...]
    weak: tuple[GroupInfo, ...]
    unresolved: tuple[str, ...]
    complete: bool


@dataclass(frozen=True, slots=True)
class _Suite:
    iana: str
    code: int
    kx: str
    au: str
    enc: str
    enc_mode: str
    enc_bits: int
    mac: str
    minimum: str
    classes: frozenset[str]
    bits: int
    tls13: bool


@dataclass(frozen=True, slots=True)
class _Group:
    name: str
    bits: int


@dataclass(frozen=True, slots=True)
class _Catalog:
    suites: tuple[_Suite, ...]
    by_name: Mapping[str, _Suite]
    keywords: Mapping[str, Mapping[str, tuple[object, ...]]]
    seclevels: Mapping[int, tuple[int, frozenset[str]]]
    groups: tuple[_Group, ...]
    by_group: Mapping[str, _Group]
    codes: Mapping[str, int]


_EMPTY_CIPHER = CipherResult((), (), (), False, None, False)
_EMPTY_GROUP = GroupResult((), (), (), False)


def evaluate_cipher_list(spec: str, reg: DefaultsRegistry) -> CipherResult:
    """Expand a TLS 1.2-and-earlier OpenSSL cipher string."""
    try:
        if not isinstance(reg, DefaultsRegistry):
            return _EMPTY_CIPHER
        return _cipher_list(spec, _shipped_catalog())
    except Exception:
        return _EMPTY_CIPHER


def evaluate_tls13_suites(spec: str, reg: DefaultsRegistry) -> CipherResult:
    """Accept only TLS 1.3 suite names from the cipher registry."""
    try:
        if not isinstance(reg, DefaultsRegistry):
            return _EMPTY_CIPHER
        return _tls13(spec, _shipped_catalog())
    except Exception:
        return _EMPTY_CIPHER


def classify_groups(spec: str, reg: DefaultsRegistry) -> GroupResult:
    """Resolve a curve or group list. Groups under 224 bits are weak."""
    try:
        if not isinstance(reg, DefaultsRegistry):
            return _EMPTY_GROUP
        return _groups(spec, _shipped_catalog())
    except Exception:
        return _EMPTY_GROUP


def cap_suites(names: Iterable[str]) -> tuple[tuple[str, ...], bool]:
    """Keep every suite the weakness predicate flags, then fill to 256."""
    try:
        return _cap(names, _shipped_catalog().codes)
    except Exception:
        return (), False


class CipherEvaluator:
    """One evaluator per scan. Memoized by ``(kind, spec)``, not object identity."""

    def __init__(
        self,
        reg: DefaultsRegistry,
        *,
        cipher_document: Mapping[str, object] | None = None,
        group_document: Mapping[str, object] | None = None,
    ) -> None:
        if not isinstance(reg, DefaultsRegistry):
            raise TypeError("reg must be a DefaultsRegistry")
        self._reg = reg
        ciphers = (
            cipher_document
            if cipher_document is not None
            else _load_document("cipher_suites.json")
        )
        groups = (
            group_document
            if group_document is not None
            else _load_document("named_groups.json")
        )
        self._catalog = _catalog_from(ciphers, groups)
        self._cache: dict[tuple[str, str], CipherResult | GroupResult] = {}
        self._order: list[tuple[str, str]] = []

    def cipher_list(self, spec: str) -> CipherResult:
        found = self._memo("list", spec, lambda: _cipher_list(spec, self._catalog))
        if not isinstance(found, CipherResult):
            return _EMPTY_CIPHER
        return found

    def tls13_suites(self, spec: str) -> CipherResult:
        found = self._memo("tls13", spec, lambda: _tls13(spec, self._catalog))
        if not isinstance(found, CipherResult):
            return _EMPTY_CIPHER
        return found

    def groups(self, spec: str) -> GroupResult:
        found = self._memo("groups", spec, lambda: _groups(spec, self._catalog))
        if not isinstance(found, GroupResult):
            return _EMPTY_GROUP
        return found

    def _memo(
        self,
        kind: str,
        spec: str,
        build: Callable[[], CipherResult | GroupResult],
    ) -> CipherResult | GroupResult:
        key = (kind, spec if isinstance(spec, str) else "")
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        try:
            value = build()
        except Exception:
            value = _EMPTY_CIPHER if kind != "groups" else _EMPTY_GROUP
        self._cache[key] = value
        self._order.append(key)
        if len(self._order) > _CACHE_LIMIT:
            self._cache.pop(self._order.pop(0), None)
        return value


_WEAK_TLS = frozenset({"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"})


def _basis_value(fact: EncryptionFact, name: str) -> str | None:
    return next(
        (item.value for item in fact.basis if item.name == name and item.value),
        None,
    )


def protocol_asset(fact: EncryptionFact) -> CryptoAssetComponent | None:
    """A TLS protocol asset for a recorded cipher list or protocol floor."""
    suite = _basis_value(fact, "cipher_suite")
    floor = _basis_value(fact, "protocol_min")
    if suite is None and floor is None:
        return None
    ssh = fact.kind == "ssh_service"
    props = {
        "crypto:assetType": "protocol",
        "crypto:factId": fact.id,
        "crypto:protocolType": "ssh" if ssh else "tls",
        "discovery:source": fact.path,
    }
    if suite:
        props["crypto:cipherSuite"] = suite
    listen = _basis_value(fact, "listen_declared")
    if listen:
        props["crypto:listen"] = listen
    endpoint = _basis_value(fact, "endpoint")
    if endpoint:
        props["crypto:endpoint"] = endpoint
    if floor:
        props["crypto:protocolVersion"] = floor
        if floor in _WEAK_TLS or (ssh and floor == "SSH-1"):
            props["crypto:strength"] = "weak"
    return CryptoAssetComponent(
        bom_ref=f"crypto-proto-{fact.id}",
        name="SSH" if ssh else "TLS",
        properties=props,
    )


def proxy_protocol_asset(fact: EncryptionFact) -> CryptoAssetComponent | None:
    """Outbound Apache ``SSLProxyProtocol`` floor. It does not replace the listener."""
    floor = _basis_value(fact, "proxy_protocol_min")
    if not floor:
        return None
    props = {
        "crypto:assetType": "protocol",
        "crypto:factId": fact.id,
        "crypto:policyName": "SSLProxyProtocol",
        "crypto:protocolType": "tls",
        "crypto:protocolVersion": floor,
        "discovery:source": fact.path,
    }
    if floor in _WEAK_TLS:
        props["crypto:strength"] = "weak"
    return CryptoAssetComponent(
        bom_ref=f"crypto-proto-proxy-{fact.id}",
        name="TLS",
        properties=props,
    )


def evaluator_for(sink: PostureSink) -> CipherEvaluator:
    """Return the scan's evaluator, building it once from ``load_registry()``."""
    current = sink.ciphers
    if isinstance(current, CipherEvaluator):
        return current
    evaluator = CipherEvaluator(load_registry())
    sink.ciphers = evaluator
    return evaluator


def _shipped_catalog() -> _Catalog:
    return _catalog_from(
        _load_document("cipher_suites.json"),
        _load_document("named_groups.json"),
    )


def _load_document(name: str) -> dict[str, object]:
    raw = json.loads(read_data_bytes(name))
    return _as_dict(raw)


def _catalog_from(
    ciphers: Mapping[str, object], groups: Mapping[str, object]
) -> _Catalog:
    suites: list[_Suite] = []
    by_name: dict[str, _Suite] = {}
    for raw in _as_list(ciphers.get("rows")):
        suite = _suite_from(raw)
        if suite is None:
            continue
        suites.append(suite)
        for name in _names_of(raw, suite.iana):
            by_name.setdefault(name, suite)
    parsed_groups: list[_Group] = []
    by_group: dict[str, _Group] = {}
    for raw in _as_list(groups.get("rows")):
        group = _group_from(raw)
        if group is None:
            continue
        parsed_groups.append(group)
        by_group.setdefault(group.name.casefold(), group)
        for alias in _str_tuple(_as_dict(raw).get("aliases")):
            by_group.setdefault(alias.casefold(), group)
    return _Catalog(
        suites=tuple(suites),
        by_name=by_name,
        keywords=_keywords(ciphers.get("keywords")),
        seclevels=_seclevels(ciphers.get("seclevels")),
        groups=tuple(parsed_groups),
        by_group=by_group,
        codes={suite.iana: suite.code for suite in suites},
    )


def _suite_from(raw: object) -> _Suite | None:
    row = _as_dict(raw)
    if row.get("kind") == "suite_set":
        return None
    iana = row.get("iana")
    code = row.get("code")
    if not isinstance(iana, str) or not iana or isinstance(code, bool):
        return None
    if not isinstance(code, int):
        return None
    classes = _str_tuple(row.get("classes"))
    enc_bits = row.get("enc_bits")
    bits = row.get("bits")
    return _Suite(
        iana=iana,
        code=code,
        kx=_text(row.get("kx")),
        au=_text(row.get("au")),
        enc=_text(row.get("enc")),
        enc_mode=_text(row.get("enc_mode")),
        enc_bits=_whole(enc_bits),
        mac=_text(row.get("mac")),
        minimum=_text(row.get("min")),
        classes=frozenset(classes),
        bits=_whole(bits),
        tls13=row.get("tls13") is True,
    )


def _names_of(raw: object, iana: str) -> tuple[str, ...]:
    row = _as_dict(raw)
    names = [iana, *_str_tuple(row.get("openssl")), *_str_tuple(row.get("aliases"))]
    return tuple(name for name in names if name)


def _group_from(raw: object) -> _Group | None:
    row = _as_dict(raw)
    name = row.get("name")
    bits = row.get("bits")
    if not isinstance(name, str) or not name:
        return None
    if isinstance(bits, bool) or not isinstance(bits, int):
        return None
    return _Group(name=name, bits=bits)


def _keywords(raw: object) -> dict[str, dict[str, tuple[object, ...]]]:
    out: dict[str, dict[str, tuple[object, ...]]] = {}
    for name, spec in _as_dict(raw).items():
        fields: dict[str, tuple[object, ...]] = {}
        for key, allowed in _as_dict(spec).items():
            if isinstance(allowed, list):
                fields[key] = tuple(allowed)
        if fields:
            out[name] = fields
    return out


def _seclevels(raw: object) -> dict[int, tuple[int, frozenset[str]]]:
    out: dict[int, tuple[int, frozenset[str]]] = {}
    for key, spec in _as_dict(raw).items():
        if not key.isdigit():
            continue
        body = _as_dict(spec)
        floor = body.get("min_bits")
        if isinstance(floor, bool) or not isinstance(floor, int):
            floor = 0
        out[int(key)] = (floor, frozenset(_str_tuple(body.get("deny"))))
    return out


def _cipher_list(spec: object, catalog: _Catalog) -> CipherResult:
    text, limited = _clip(spec)
    tokens = _tokenize(text, _LIST_SEPS)
    if len(tokens) > _MAX_TOKENS:
        tokens = tokens[:_MAX_TOKENS]
        limited = True
    chosen: list[str] = []
    present: set[str] = set()
    deleted: set[str] = set()
    explicit: list[str] = []
    unresolved: list[str] = []
    seclevel: int | None = None
    complete = not limited
    for index, token in enumerate(tokens):
        if token == "@STRENGTH":
            continue
        if token.startswith("@SECLEVEL="):
            level = _seclevel_value(token)
            if level is None:
                complete = _unresolved(token, unresolved)
            else:
                seclevel = level
            continue
        if token.startswith("@"):
            complete = _unresolved(token, unresolved)
            continue
        prefix, body = _split_prefix(token)
        if body == "DEFAULT":
            if index == 0 and prefix == "":
                _expand_default(catalog, chosen, present, deleted)
            else:
                complete = _unresolved(token, unresolved)
            continue
        matched = _match_body(body, catalog)
        if matched is None:
            complete = _unresolved(token, unresolved)
            continue
        if prefix == "" and body in catalog.by_name:
            _remember(explicit, catalog.by_name[body].iana)
        _apply_prefix(prefix, matched, chosen, present, deleted)
    if seclevel is not None:
        _apply_seclevel(seclevel, chosen, present, catalog)
    chosen = [name for name in chosen if not _is_tls13(name, catalog)]
    present = set(chosen)
    ordered = tuple(sorted(chosen, key=lambda name: catalog.codes.get(name, 0)))
    kept, truncated = _cap(ordered, catalog.codes)
    named = tuple(name for name in explicit if name in present)
    return CipherResult(kept, named, tuple(unresolved), complete, seclevel, truncated)


def _expand_default(
    catalog: _Catalog,
    chosen: list[str],
    present: set[str],
    deleted: set[str],
) -> None:
    for token in ("ALL", "!COMPLEMENTOFDEFAULT", "!eNULL"):
        prefix, body = _split_prefix(token)
        matched = _match_body(body, catalog)
        if matched is None:
            continue
        _apply_prefix(prefix, matched, chosen, present, deleted)


def _tls13(spec: object, catalog: _Catalog) -> CipherResult:
    text, limited = _clip(spec)
    tokens = _tokenize(text, _TLS13_SEPS)
    if len(tokens) > _MAX_TOKENS:
        tokens = tokens[:_MAX_TOKENS]
        limited = True
    chosen: list[_Suite] = []
    seen: set[str] = set()
    explicit: list[str] = []
    unresolved: list[str] = []
    complete = not limited
    allowed = {suite.iana: suite for suite in catalog.suites if suite.tls13}
    for token in tokens:
        suite = allowed.get(token)
        if suite is None:
            complete = _unresolved(token, unresolved)
            continue
        _remember(explicit, suite.iana)
        if suite.iana not in seen:
            seen.add(suite.iana)
            chosen.append(suite)
    ordered = tuple(suite.iana for suite in sorted(chosen, key=lambda item: item.code))
    kept, truncated = _cap(ordered, catalog.codes)
    return CipherResult(
        kept, tuple(explicit), tuple(unresolved), complete, None, truncated
    )


def _groups(spec: object, catalog: _Catalog) -> GroupResult:
    text, limited = _clip(spec)
    tokens = _tokenize(text, _LIST_SEPS)
    if len(tokens) > _MAX_TOKENS:
        tokens = tokens[:_MAX_TOKENS]
        limited = True
    found: dict[str, _Group] = {}
    unresolved: list[str] = []
    complete = not limited
    for token in tokens:
        if token.casefold() == "auto":
            continue
        group = catalog.by_group.get(token.casefold())
        if group is None:
            complete = _unresolved(token, unresolved)
            continue
        found.setdefault(group.name, group)
    names = tuple(sorted(found))
    weak = tuple(
        GroupInfo(group.name, group.bits)
        for group in sorted(
            (item for item in found.values() if item.bits < 224),
            key=lambda item: item.name,
        )
    )
    return GroupResult(names, weak, tuple(unresolved), complete)


def _apply_prefix(
    prefix: str,
    matched: tuple[_Suite, ...],
    chosen: list[str],
    present: set[str],
    deleted: set[str],
) -> None:
    matched_ids = {suite.iana for suite in matched}
    if prefix == "!":
        deleted.update(matched_ids)
        _drop(chosen, present, matched_ids)
        return
    if prefix == "-":
        _drop(chosen, present, matched_ids)
        return
    if prefix == "+":
        moved = [name for name in chosen if name in matched_ids]
        if not moved:
            return
        staying = [name for name in chosen if name not in matched_ids]
        chosen[:] = staying + moved
        return
    for suite in matched:
        if suite.tls13 or suite.iana in deleted or suite.iana in present:
            continue
        chosen.append(suite.iana)
        present.add(suite.iana)


def _apply_seclevel(
    level: int,
    chosen: list[str],
    present: set[str],
    catalog: _Catalog,
) -> None:
    rule = catalog.seclevels.get(level)
    if rule is None:
        return
    floor, deny = rule
    by_iana = {suite.iana: suite for suite in catalog.suites}
    blocked: set[str] = set()
    for name in chosen:
        suite = by_iana.get(name)
        if suite is None:
            continue
        if suite.bits < floor or suite.classes & deny:
            blocked.add(name)
    _drop(chosen, present, blocked)


def _match_body(body: str, catalog: _Catalog) -> tuple[_Suite, ...] | None:
    if not body:
        return None
    exact = catalog.by_name.get(body)
    if exact is not None:
        return (exact,)
    keyword = catalog.keywords.get(body)
    if keyword is not None:
        return tuple(
            suite for suite in catalog.suites if _keyword_match(suite, keyword)
        )
    if "+" not in body:
        return None
    parts = body.split("+")
    specs = []
    for part in parts:
        spec = catalog.keywords.get(part)
        if spec is None:
            return None
        specs.append(spec)
    return tuple(
        suite
        for suite in catalog.suites
        if all(_keyword_match(suite, spec) for spec in specs)
    )


def _keyword_match(suite: _Suite, spec: Mapping[str, tuple[object, ...]]) -> bool:
    for key, allowed in spec.items():
        have = _suite_field(suite, key)
        if isinstance(have, frozenset):
            if not any(item in allowed for item in have):
                return False
        elif have not in allowed:
            return False
    return True


def _suite_field(suite: _Suite, key: str) -> object:
    if key == "classes":
        return suite.classes
    if key == "kx":
        return suite.kx
    if key == "au":
        return suite.au
    if key == "enc":
        return suite.enc
    if key == "enc_mode":
        return suite.enc_mode
    if key == "enc_bits":
        return suite.enc_bits
    if key == "mac":
        return suite.mac
    if key == "min":
        return suite.minimum
    if key == "bits":
        return suite.bits
    return None


def _cap(
    names: Iterable[str], codes: Mapping[str, int]
) -> tuple[tuple[str, ...], bool]:
    unique: list[str] = []
    seen: set[str] = set()
    for name in names:
        if not isinstance(name, str) or not name or name in seen:
            continue
        seen.add(name)
        unique.append(name)
    weak = [name for name in unique if _predicate_flags(name)]
    rest = [name for name in unique if name not in set(weak)]
    rest.sort(key=lambda name: _code_key(name, codes))
    room = max(0, _SUITE_CAP - len(weak))
    kept = weak + rest[:room]
    kept.sort(key=lambda name: _code_key(name, codes))
    return tuple(kept), len(kept) < len(unique)


def _predicate_flags(name: str) -> bool:
    component = CryptoAssetComponent(
        bom_ref="cap",
        name="tls",
        properties={
            "crypto:assetType": "protocol",
            "crypto:protocolType": "tls",
            "crypto:cipherSuite": name,
        },
    )
    return bool(cipher_suite_findings(component))


def _code_key(name: str, codes: Mapping[str, int]) -> tuple[int, int, str]:
    code = codes.get(name)
    if code is None:
        return (1, 0, name)
    return (0, code, name)


def _is_tls13(name: str, catalog: _Catalog) -> bool:
    suite = catalog.by_name.get(name)
    return suite is not None and suite.tls13


def _clip(spec: object) -> tuple[str, bool]:
    if not isinstance(spec, str):
        return "", True
    if len(spec) > _MAX_CHARS:
        return spec[:_MAX_CHARS], True
    return spec, False


def _tokenize(text: str, separators: frozenset[str]) -> list[str]:
    tokens: list[str] = []
    buf: list[str] = []
    for char in text:
        if char in separators:
            if buf:
                tokens.append("".join(buf))
                buf = []
            continue
        buf.append(char)
    if buf:
        tokens.append("".join(buf))
    return tokens


def _split_prefix(token: str) -> tuple[str, str]:
    if token[:1] in _PREFIXES:
        return token[0], token[1:]
    return "", token


def _seclevel_value(token: str) -> int | None:
    raw = token[len("@SECLEVEL=") :]
    if not raw.isdigit() or len(raw) > 4:
        return None
    value = int(raw)
    if value > 5:
        return None
    return value


def _unresolved(token: str, found: list[str]) -> bool:
    if len(found) < _MAX_UNRESOLVED:
        found.append(_sanitize(token))
    return False


def _whole(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return value


def _sanitize(token: str) -> str:
    chars: list[str] = []
    for char in token:
        chars.append(char if 32 <= ord(char) <= 126 else "?")
        if len(chars) == _TOKEN_CHARS:
            break
    return "".join(chars)


def _remember(found: list[str], name: str) -> None:
    if name not in found:
        found.append(name)


def _drop(chosen: list[str], present: set[str], blocked: set[str]) -> None:
    if not blocked:
        return
    chosen[:] = [name for name in chosen if name not in blocked]
    present.difference_update(blocked)


def _as_dict(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    return {key: item for key, item in value.items() if isinstance(key, str)}


def _as_list(value: object) -> list[object]:
    if not isinstance(value, list):
        return []
    return list(value)


def _str_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _text(value: object) -> str:
    if isinstance(value, str):
        return value
    return ""
