"""Inventory sources and the normalised ``Target`` (F1 contract, section 3).

A source yields ``Target``s; ``normalize`` turns one raw row (CSV, JSON, API, AWS) into a ``Target`` or raises
``InventoryError`` with a message that is safe to show (it never echoes a tag value or attribute).  The same input
always gives the same ``Target`` and the same ``fingerprint``, so a re-import that changes nothing writes nothing.

* CSV: a header row is required.  Columns (any case): ``external_id``, ``kind``, ``address``, ``addresses``
  (space/semicolon separated), ``hostname``, ``account_id``, ``region``, ``platform``, ``tags`` (``k=v;k2=v2``),
  ``tag:<key>``, ``handle:<ssm|salt|awx>``, ``attr:<name>``.  Unknown columns are refused (a typo must not silently
  drop a tag a policy depends on).
* JSON: a list of objects, or ``{"targets": [...]}``; each object has the ``Target`` field names.
* ``external_id`` defaults to the hostname, else the address; ``kind`` defaults to ``linux_host``.
"""
from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any, ClassVar, Iterable, Iterator, Mapping, Protocol

from backend.utilities.cbom_sources import targets as T
from backend.utilities.cbom_sources.fleet.models import TARGET_KINDS

MAX_IMPORT_BYTES = 10 * 1024 * 1024
MAX_IMPORT_ROWS = 10_000
MAX_API_TARGETS = 1_000
MAX_ERRORS = 100
MAX_TAGS = 64
MAX_ADDRESSES = 32
MAX_ATTRIBUTES_BYTES = 4096
HANDLE_KEYS = ("ssm", "salt", "awx")
_FIELDS = ("external_id", "kind", "address", "addresses", "hostname", "tags", "account_id", "region", "platform",
           "handles", "attributes")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_TAG_KEY = re.compile(r"^[^\x00-\x1f\x7f]{1,128}$")
_SHORT = re.compile(r"^[A-Za-z0-9._:/@+=-]{1,64}$")


class InventoryError(ValueError):
    """``code`` is machine-readable; ``str(err)`` is safe to show (no tag values, no secrets)."""

    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code


@dataclass(frozen=True)
class Target:
    external_id: str
    kind: str
    address: str | None
    addresses: tuple[str, ...]
    hostname: str | None
    tags: Mapping[str, str]
    account_id: str | None
    region: str | None
    platform: str | None
    handles: Mapping[str, str]
    attributes: Mapping[str, Any]

    def canonical(self) -> dict[str, Any]:
        return {"external_id": self.external_id, "kind": self.kind, "address": self.address,
                "addresses": list(self.addresses), "hostname": self.hostname, "tags": dict(sorted(self.tags.items())),
                "account_id": self.account_id, "region": self.region, "platform": self.platform,
                "handles": dict(sorted(self.handles.items())), "attributes": _sorted(self.attributes)}

    def fingerprint(self) -> str:
        blob = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(blob.encode()).hexdigest()


class InventorySource(Protocol):
    kind: ClassVar[str]  # "aws" | "csv" | "json" | "api"

    def discover(self) -> Iterable[Target]: ...


def _sorted(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): _sorted(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (list, tuple)):
        return [_sorted(v) for v in value]
    return value


def _text(value: Any, name: str, limit: int, *, required: bool = False) -> str | None:
    if value is None or (isinstance(value, str) and value.strip() == ""):
        if required:
            raise InventoryError("missing_field", f"{name} is required")
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise InventoryError("bad_field", f"{name} must be text")
    text = str(value).strip()
    if _CONTROL.search(text):
        raise InventoryError("bad_field", f"{name} contains control characters")
    if len(text) > limit:
        raise InventoryError("bad_field", f"{name} is longer than {limit} characters")
    return text


def _ip(text: str) -> str | None:
    try:
        address = ipaddress.ip_address(text.strip().strip("[]"))
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return str(address)


def _host_or_ip(value: str, name: str) -> tuple[str | None, str | None]:
    """(ip, hostname): exactly one is set."""
    ip = _ip(value)
    if ip:
        return ip, None
    try:
        kind, host, _canonical = T.parse_line(value)
    except T.TargetError:
        raise InventoryError("bad_address", f"{name} is not an IP address or host name") from None
    if kind != "host":
        raise InventoryError("bad_address", f"{name} must be one address, not a range")
    return None, str(host)


def _tag_rank(folded: str, raw: str) -> tuple[bool, str, str]:
    """Which of several raw keys that fold to ``folded`` keeps its value (lower wins): the key already written in
    lower case, then the smallest in code-point order.  The order the tags arrive in never matters."""
    return raw.strip() != folded, raw.strip(), raw


def _tag_pairs(text: str) -> dict[str, str]:
    """``k=v;k2=v2`` → ``{k: v, k2: v2}`` with the keys as written (``_tags`` folds them)."""
    pairs: dict[str, str] = {}
    for part in text.split(";"):
        if not part.strip():
            continue
        key, sep, val = part.partition("=")
        if not sep:
            raise InventoryError("bad_tags", "tags must look like key=value;key2=value2")
        pairs[key] = val
    return pairs


def _tags(value: Any) -> dict[str, str]:
    """Tags with lower-cased keys.  Keys that differ only in case are folded by ``_tag_rank``, whatever their order."""
    if value is None or value == "":
        return {}
    if isinstance(value, str):  # "k=v;k2=v2" (CSV)
        value = _tag_pairs(value)
    if isinstance(value, list):  # AWS shape [{"Key": .., "Value": ..}]
        try:
            value = {str(item.get("Key", item.get("key"))): item.get("Value", item.get("value", "")) for item in value}
        except AttributeError:
            raise InventoryError("bad_tags", "tags must be an object of key: value") from None
    if not isinstance(value, Mapping):
        raise InventoryError("bad_tags", "tags must be an object of key: value")
    out: dict[str, str] = {}
    winner: dict[str, str] = {}  # folded key -> the raw key whose value it keeps
    for raw_key, raw_val in value.items():
        key = str(raw_key).strip().lower()
        if not _TAG_KEY.match(key):
            raise InventoryError("bad_tags", "a tag key is empty, longer than 128 characters or has control characters")
        if raw_val is None:
            raw_val = ""
        if isinstance(raw_val, bool):
            raw_val = "true" if raw_val else "false"
        if not isinstance(raw_val, (str, int, float)):
            raise InventoryError("bad_tags", f"tag {key[:40]!r}: the value must be text")
        val = str(raw_val).strip()
        if len(val) > 256 or _CONTROL.search(val):
            raise InventoryError("bad_tags", f"tag {key[:40]!r}: the value is longer than 256 characters or has control "
                                             "characters")
        # every value is checked first, so an error never depends on the order either
        if key in winner and _tag_rank(key, winner[key]) <= _tag_rank(key, str(raw_key)):
            continue  # keys that differ only in case (AWS allows Env and env): the same one wins in any input order
        winner[key] = str(raw_key)
        out[key] = val
    if len(out) > MAX_TAGS:
        raise InventoryError("bad_tags", f"more than {MAX_TAGS} tags")
    return out


def _addresses(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    items = re.split(r"[\s;,]+", value.strip()) if isinstance(value, str) else value
    if not isinstance(items, (list, tuple)):
        raise InventoryError("bad_address", "addresses must be a list of IP addresses")
    out: list[str] = []
    for item in items:
        if item in (None, ""):
            continue
        ip = _ip(str(item))
        if ip is None:
            raise InventoryError("bad_address", "addresses must be IP addresses (one per entry)")
        out.append(ip)
    return out


def _handles(value: Any) -> dict[str, str]:
    if not value:
        return {}
    if not isinstance(value, Mapping):
        raise InventoryError("bad_handles", "handles must be an object such as {\"ssm\": \"i-0abc\"}")
    out = {}
    for key, val in value.items():
        if key not in HANDLE_KEYS:
            raise InventoryError("bad_handles", f"handles: unknown key {str(key)[:20]!r} (ssm, salt or awx)")
        text = _text(val, f"handles.{key}", 255)
        if text:
            out[str(key)] = text
    return out


def _attributes(value: Any) -> dict[str, Any]:
    if not value:
        return {}
    if not isinstance(value, Mapping):
        raise InventoryError("bad_attributes", "attributes must be an object")
    clean: dict[str, Any] = {}
    for key, val in value.items():
        if isinstance(val, (str, int, float, bool)) or val is None:
            clean[str(key)[:64]] = val
        elif isinstance(val, (list, tuple)) and all(isinstance(v, (str, int, float, bool)) for v in val):
            clean[str(key)[:64]] = list(val)
        else:
            raise InventoryError("bad_attributes", f"attribute {str(key)[:40]!r}: only text, numbers, booleans or lists "
                                                   "of them")
    if len(json.dumps(clean, default=str)) > MAX_ATTRIBUTES_BYTES:
        raise InventoryError("bad_attributes", f"attributes are larger than {MAX_ATTRIBUTES_BYTES} bytes")
    return clean


def normalize(raw: Mapping[str, Any]) -> Target:
    """One row → ``Target``.  Raises InventoryError (safe message)."""
    if not isinstance(raw, Mapping):
        raise InventoryError("bad_row", "each target must be an object")
    unknown = sorted(set(raw) - set(_FIELDS))
    if unknown:
        raise InventoryError("bad_row", f"unknown field {str(unknown[0])[:40]!r}")
    kind = _text(raw.get("kind"), "kind", 24) or "linux_host"
    if kind not in TARGET_KINDS:
        raise InventoryError("bad_kind", f"kind must be one of {', '.join(TARGET_KINDS)}")
    addresses = _addresses(raw.get("addresses"))
    address = hostname = None
    if raw.get("address") not in (None, ""):
        ip, host = _host_or_ip(_text(raw.get("address"), "address", 253) or "", "address")
        address = ip or host
        if ip:
            addresses.insert(0, ip)
        elif host:
            hostname = host
    if raw.get("hostname") not in (None, ""):
        ip, host = _host_or_ip(_text(raw.get("hostname"), "hostname", 253) or "", "hostname")
        if ip:
            raise InventoryError("bad_address", "hostname is an IP address; put it in address")
        hostname = host
    unique = list(dict.fromkeys(addresses))
    if len(unique) > MAX_ADDRESSES:
        raise InventoryError("bad_address", f"more than {MAX_ADDRESSES} addresses")
    if address is None and unique:
        address = unique[0]
    external_id = _text(raw.get("external_id"), "external_id", 255) or hostname or address
    if not external_id:
        raise InventoryError("missing_field", "external_id is required (or an address or hostname)")
    account_id = _text(raw.get("account_id"), "account_id", 32)
    region = _text(raw.get("region"), "region", 32)
    for name, value in (("account_id", account_id), ("region", region)):
        if value is not None and not _SHORT.match(value):
            raise InventoryError("bad_field", f"{name} may use letters, digits and . _ : / @ + = -")
    return Target(external_id=external_id, kind=kind, address=address, addresses=tuple(unique), hostname=hostname,
                  tags=_tags(raw.get("tags")), account_id=account_id, region=region,
                  platform=_text(raw.get("platform"), "platform", 64), handles=_handles(raw.get("handles")),
                  attributes=_attributes(raw.get("attributes")))


@dataclass
class Parsed:
    """Rows of one import: the valid targets (first occurrence of each external_id) and the errors (≤ 100)."""
    targets: list[Target] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    error_count: int = 0
    rows: int = 0

    def error(self, row: int, message: str) -> None:
        self.error_count += 1
        if len(self.errors) < MAX_ERRORS:
            self.errors.append({"row": row, "error": message[:300]})


def _collect(rows: Iterator[tuple[int, Mapping[str, Any]]], limit: int) -> Parsed:
    out = Parsed()
    seen: dict[str, int] = {}
    for number, raw in rows:
        out.rows += 1
        if out.rows > limit:
            raise InventoryError("too_many_rows", f"more than {limit:,} targets; split the file")
        try:
            target = normalize(raw)
        except InventoryError as exc:
            out.error(number, str(exc))
            continue
        if target.external_id in seen:
            out.error(number, f"duplicate external_id (first on row {seen[target.external_id]})")
            continue
        seen[target.external_id] = number
        out.targets.append(target)
    return out


def _csv_rows(text: str) -> Iterator[tuple[int, dict[str, Any]]]:
    reader = csv.reader(io.StringIO(text.lstrip("﻿")))
    header: list[str] | None = None
    for number, cells in enumerate(reader, start=1):
        if not any(c.strip() for c in cells):
            continue
        if header is None:
            header = [c.strip() for c in cells]
            names = [c.lower() if ":" not in c else f"{c.partition(':')[0].strip().lower()}:{c.partition(':')[2].strip()}"
                     for c in header]
            if len(set(names)) != len(names):  # which copy would win would depend on the column order
                dup = next(n for n in names if names.count(n) > 1)
                raise InventoryError("bad_header", f"column {dup[:40]!r} appears twice")
            for column in header:
                low = column.lower()
                if low in _FIELDS and low not in ("handles", "attributes"):
                    continue
                prefix, sep, rest = column.partition(":")
                if sep and prefix.lower() in ("tag", "handle", "attr") and rest.strip():
                    continue
                raise InventoryError("bad_header", f"unknown column {column[:40]!r}: use external_id, kind, address, "
                                                   "addresses, hostname, account_id, region, platform, tags, "
                                                   "tag:<key>, handle:<ssm|salt|awx> or attr:<name>")
            continue
        row: dict[str, Any] = {}
        tags: dict[str, Any] = {}
        handles: dict[str, Any] = {}
        attrs: dict[str, Any] = {}
        for column, cell in zip(header, cells):
            value = cell.strip()
            low = column.lower()
            prefix, sep, rest = column.partition(":")
            if sep and prefix.lower() == "tag":
                if value != "":
                    tags[rest.strip()] = value
            elif sep and prefix.lower() == "handle":
                if value:
                    handles[rest.strip().lower()] = value
            elif sep and prefix.lower() == "attr":
                if value:
                    attrs[rest.strip()] = value
            elif low == "tags":
                if value:
                    row["tags"] = value
            elif value:
                row[low] = value
        if tags:  # keys as written: a tag:<key> column wins over the same key in the tags column; _tags folds case
            row["tags"] = {**(_tag_pairs(row["tags"]) if row.get("tags") else {}), **tags}
        if handles:
            row["handles"] = handles
        if attrs:
            row["attributes"] = attrs
        yield number, row
    if header is None:
        raise InventoryError("empty", "the file has no header row and no targets")


def parse_csv(content: str, limit: int = MAX_IMPORT_ROWS) -> Parsed:
    try:
        return _collect(_csv_rows(content), limit)
    except csv.Error as exc:
        raise InventoryError("bad_csv", f"not a valid CSV file: {str(exc)[:120]}") from None


def parse_json(content: str | Any, limit: int = MAX_IMPORT_ROWS) -> Parsed:
    data = content
    if isinstance(content, str):
        try:
            data = json.loads(content)
        except ValueError:
            raise InventoryError("bad_json", "not valid JSON") from None
    if isinstance(data, Mapping):
        data = data.get("targets")
    if not isinstance(data, list):
        raise InventoryError("bad_json", "expected a list of targets or {\"targets\": [...]}")
    if len(data) > limit:
        raise InventoryError("too_many_rows", f"more than {limit:,} targets; split the file")
    return _collect(((i, row) for i, row in enumerate(data, start=1)), limit)


class StaticInventorySource:
    """CSV / JSON / API: the targets were given to us (already parsed)."""

    def __init__(self, kind: str, targets: list[Target]):
        self.kind, self._targets = kind, targets

    def discover(self) -> Iterable[Target]:
        return list(self._targets)
