"""Parse and count scan targets: IPs, CIDRs, ``a-b`` ranges and hostnames.

Counting is interval arithmetic over integer addresses, never enumeration, so a /16 costs the same
CPU as a /32.  Every limit below exists to stop a typo (``10.0.0.0/8``, an IPv6 /64) from turning
into a huge scan or a huge credit charge.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

MAX_LINES = 1000
MAX_ADDRESSES_PER_SOURCE = 262_144  # four /16s
MAX_V4_PREFIX = 16  # a line may be at most a /16 (65,536 addresses)
MAX_V6_PREFIX = 112  # ...or an IPv6 /112 (65,536 addresses)
MAX_RANGE = 65_536
BLOCK = 256  # credits for network ranges are charged per /24 (IPv4) or /120 (IPv6)

_HEADER_WORDS = {"ip", "ips", "host", "hosts", "hostname", "address", "addresses", "target", "targets", "name"}
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")

Interval = tuple[int, int, int]  # (ip version, first address, last address), inclusive


class TargetError(ValueError):
    """A line that cannot be parsed.  ``str(err)`` is safe to show to the user."""


@dataclass
class ParsedTargets:
    intervals: list[Interval] = field(default_factory=list)  # merged and sorted
    hostnames: list[str] = field(default_factory=list)  # normalised, deduplicated
    normalized: list[str] = field(default_factory=list)  # canonical lines in input order
    raw_size: int = 0  # addresses before merging (for the per-source cap)


def clean_lines(value: str | list[str] | None) -> list[str]:
    """Split, strip CR/BOM/whitespace, drop blanks and ``#`` comments, take the first CSV column."""
    if value is None:
        return []
    raw = value.splitlines() if isinstance(value, str) else [str(v) for v in value]
    out: list[str] = []
    for index, line in enumerate(raw):
        text = line.replace("﻿", "").replace("\r", "").replace("\x00", "")
        if "#" in text:
            text = text.split("#", 1)[0]
        if "," in text or ";" in text or "\t" in text:
            text = re.split(r"[,;\t]", text, maxsplit=1)[0]
        text = text.strip().strip('"').strip("'").strip()
        if not text:
            continue
        if index == 0 and not out and text.lower() in _HEADER_WORDS:
            continue  # a CSV header row
        out.append(text)
    return out


def _as_v4_if_mapped(address: ipaddress.IPv4Address | ipaddress.IPv6Address):
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _normalize_hostname(text: str) -> str:
    name = text.strip().lower().rstrip(".")
    if not name:
        raise TargetError("empty hostname")
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise TargetError(f"{text!r} is not a valid hostname") from exc
    if len(name) > 253:
        raise TargetError(f"{text[:40]!r}... is longer than 253 characters")
    labels = name.split(".")
    if not all(_LABEL_RE.match(label) for label in labels):
        raise TargetError(f"{text[:64]!r} is not an IP address, CIDR range or hostname")
    if labels[-1].isdigit():
        raise TargetError(f"{text[:64]!r} looks like a malformed IP address")
    return name


def parse_line(text: str, *, max_v4_prefix: int = MAX_V4_PREFIX, max_v6_prefix: int = MAX_V6_PREFIX):
    """Return ``("net", Interval, canonical)`` or ``("host", name, name)``.  Raises TargetError."""
    if "-" in text and "/" not in text and any(ch.isdigit() for ch in text.split("-", 1)[0][-1:]):
        first, _, last = text.partition("-")
        try:
            start = _as_v4_if_mapped(ipaddress.ip_address(first.strip()))
            end = _as_v4_if_mapped(ipaddress.ip_address(last.strip()))
        except ValueError:
            start = end = None
        if start is not None and end is not None:
            if start.version != end.version:
                raise TargetError(f"{text!r}: both ends of a range must be the same IP version")
            if int(end) < int(start):
                raise TargetError(f"{text!r}: the range ends before it starts")
            size = int(end) - int(start) + 1
            if size > MAX_RANGE:
                raise TargetError(f"{text!r} has {size:,} addresses; split it into ranges of at most {MAX_RANGE:,}")
            return ("net", (start.version, int(start), int(end)), f"{start}-{end}")
    if "/" in text or ":" in text or re.fullmatch(r"[0-9.]+", text):
        try:
            network = ipaddress.ip_network(text, strict=True)
        except ValueError as exc:
            message = str(exc)
            if "has host bits set" in message:
                loose = ipaddress.ip_network(text, strict=False)
                raise TargetError(f"{text!r} has host bits set; did you mean {loose}?") from exc
            raise TargetError(f"{text!r} is not a valid IP address or CIDR range") from exc
        first = _as_v4_if_mapped(network.network_address)
        if first.version == 4 and network.version == 6:  # an IPv4-mapped IPv6 network
            prefix = network.prefixlen - 96
            network = ipaddress.ip_network(f"{first}/{max(prefix, 0)}", strict=False)
        limit = max_v4_prefix if network.version == 4 else max_v6_prefix
        if network.prefixlen < limit:
            raise TargetError(
                f"{text!r} is larger than /{limit} ({network.num_addresses:,} addresses); split it into /{limit} ranges"
            )
        start = int(network.network_address)
        canonical = str(network.network_address) if network.num_addresses == 1 else str(network)  # 10.0.0.1, not 10.0.0.1/32
        return ("net", (network.version, start, start + network.num_addresses - 1), canonical)
    name = _normalize_hostname(text)
    return ("host", name, name)


def merge(intervals: list[Interval]) -> list[Interval]:
    out: list[Interval] = []
    for version, start, end in sorted(intervals):
        if out and out[-1][0] == version and start <= out[-1][2] + 1:
            prev = out[-1]
            out[-1] = (version, prev[1], max(prev[2], end))
        else:
            out.append((version, start, end))
    return out


def subtract(intervals: list[Interval], removed: list[Interval]) -> list[Interval]:
    """``intervals`` minus ``removed`` (both merged and sorted)."""
    result: list[Interval] = []
    removed = merge(removed)
    for version, start, end in merge(intervals):
        pieces = [(start, end)]
        for r_version, r_start, r_end in removed:
            if r_version != version:
                continue
            next_pieces = []
            for p_start, p_end in pieces:
                if r_end < p_start or r_start > p_end:
                    next_pieces.append((p_start, p_end))
                    continue
                if r_start > p_start:
                    next_pieces.append((p_start, r_start - 1))
                if r_end < p_end:
                    next_pieces.append((r_end + 1, p_end))
            pieces = next_pieces
            if not pieces:
                break
        result.extend((version, s, e) for s, e in pieces)
    return merge(result)


def size(intervals: list[Interval]) -> int:
    return sum(end - start + 1 for _, start, end in intervals)


def count_blocks(intervals: list[Interval], block: int = BLOCK) -> int:
    """Distinct /24 (IPv4) or /120 (IPv6) blocks that hold at least one address."""
    total = 0
    last: tuple[int, int] | None = None
    for version, start, end in merge(intervals):
        first_block, last_block = start // block, end // block
        if last is not None and last[0] == version and last[1] == first_block:
            first_block += 1
        if last_block >= first_block:
            total += last_block - first_block + 1
        last = (version, last_block)
    return total


def parse_targets(
    value: str | list[str] | None,
    *,
    max_lines: int = MAX_LINES,
    max_addresses: int = MAX_ADDRESSES_PER_SOURCE,
    allow_hostnames: bool = True,
    allow_empty: bool = False,
) -> ParsedTargets:
    lines = clean_lines(value)
    if not lines and not allow_empty:
        raise TargetError("Add at least one IP address, CIDR range or hostname")
    if len(lines) > max_lines:
        raise TargetError(f"{len(lines):,} lines; the limit is {max_lines:,} per source")
    parsed = ParsedTargets()
    seen_hosts: set[str] = set()
    seen_lines: set[str] = set()
    raw: list[Interval] = []
    for number, line in enumerate(lines, start=1):
        try:
            kind, value_, canonical = parse_line(line)
        except TargetError as exc:
            raise TargetError(f"Line {number}: {exc}") from None
        if canonical in seen_lines:
            continue
        seen_lines.add(canonical)
        parsed.normalized.append(canonical)
        if kind == "host":
            if not allow_hostnames:
                raise TargetError(f"Line {number}: {line!r} must be an IP address or CIDR range")
            if value_ not in seen_hosts:
                seen_hosts.add(value_)
                parsed.hostnames.append(value_)
        else:
            raw.append(value_)
            parsed.raw_size += value_[2] - value_[1] + 1
    if parsed.raw_size > max_addresses:
        raise TargetError(f"{parsed.raw_size:,} addresses; the limit is {max_addresses:,} per source")
    parsed.intervals = merge(raw)
    return parsed


def in_scope(targets: ParsedTargets, exclusions: ParsedTargets | None) -> tuple[list[Interval], list[str]]:
    """Addresses and hostnames left after the never-scan list (hostnames match exactly)."""
    if exclusions is None:
        return targets.intervals, list(targets.hostnames)
    intervals = subtract(targets.intervals, exclusions.intervals)
    excluded_hosts = set(exclusions.hostnames)
    return intervals, [h for h in targets.hostnames if h not in excluded_hosts]


def count_in_scope(targets: ParsedTargets, exclusions: ParsedTargets | None) -> int:
    intervals, hosts = in_scope(targets, exclusions)
    return size(intervals) + len(hosts)


def sample_targets(targets: ParsedTargets, exclusions: ParsedTargets | None, n: int = 5) -> list[str]:
    """Up to ``n`` addresses or hostnames for a connection test (skips a network address when possible)."""
    intervals, hosts = in_scope(targets, exclusions)
    out: list[str] = []
    for version, start, end in intervals:
        first = start + 1 if end - start >= 3 else start
        for value in range(first, min(end, first + n - len(out) - 1) + 1):
            out.append(str(ipaddress.ip_address(value)) if version == 4 else str(ipaddress.IPv6Address(value)))
            if len(out) >= n:
                return out
    for host in hosts:
        if len(out) >= n:
            break
        out.append(host)
    return out


def parse_exclusions(value: str | list[str] | None) -> ParsedTargets:
    """Never-scan lists may be large networks (a /8 is a valid thing to never scan)."""
    lines = clean_lines(value)
    parsed = ParsedTargets()
    raw: list[Interval] = []
    seen: set[str] = set()
    for number, line in enumerate(lines, start=1):
        try:
            kind, value_, canonical = parse_line(line, max_v4_prefix=0, max_v6_prefix=0)
        except TargetError as exc:
            raise TargetError(f"Never-scan line {number}: {exc}") from None
        if canonical in seen:
            continue
        seen.add(canonical)
        parsed.normalized.append(canonical)
        if kind == "host":
            parsed.hostnames.append(value_)
        else:
            raw.append(value_)
    parsed.intervals = merge(raw)
    return parsed
