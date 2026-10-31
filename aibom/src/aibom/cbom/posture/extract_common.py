"""Shared fact builder. Lookups stay on this object's own dictionaries."""

from __future__ import annotations

import re
from collections.abc import Iterable

from aibom.cbom.posture.model import path_context as label_path
from aibom.cbom.posture.verdict import LayerResult


class FactBuilder:
    def __init__(self) -> None:
        self.refs: set[str] = set()
        self.by_ref: dict[str, object] = {}

    def add(self, ref: str, component: object) -> None:
        self.refs.add(ref)
        self.by_ref[ref] = component

    def has(self, ref: str) -> bool:
        return ref in self.refs


def path_context(rel: str) -> str:
    return label_path(rel)


_LISTEN = re.compile(r"^[A-Za-z0-9._:*\[\]]{1,64}$")


_UNSPECIFIED = frozenset({"0.0.0.0", "::", "[::]", "*", "_"})
_HOST_REFUSED = set("*$~{%")


def valid_host(token: str) -> str | None:
    """A literal host. Wildcards, variables, and unspecified addresses are omitted."""
    text = token.strip()
    if not text or not text.isascii() or any(char.isspace() for char in text):
        return None
    if text[0] in "~*.":
        return None
    lowered = text.lower().rstrip(".")
    if not lowered or lowered in _UNSPECIFIED:
        return None
    if any(char in lowered for char in _HOST_REFUSED):
        return None
    return lowered


def listen_endpoint(token: str) -> tuple[str | None, int | None]:
    """Host and port of one listen or bind token. ``unix:`` yields neither."""
    text = token.strip()
    if not text or text.lower().startswith("unix:"):
        return None, None
    if text.startswith("["):
        end = text.find("]")
        if end < 0:
            return None, None
        rest = text[end + 1 :]
        if not rest:
            port: int | None = 80
        elif rest.startswith(":"):
            port = _port_number(rest[1:])
        else:
            port = None
        return valid_host(text[: end + 1]), port
    if ":" in text:
        host, _, raw = text.rpartition(":")
        return valid_host(host), _port_number(raw)
    return None, _port_number(text)


def endpoint_list(pairs: Iterable[str]) -> tuple[str, ...]:
    """At most eight sorted ``host:port`` candidates."""
    return tuple(sorted({item for item in pairs if item})[:8])


def _port_number(raw: str) -> int | None:
    if not raw.isdigit() or (len(raw) > 1 and raw.startswith("0")):
        return None
    value = int(raw)
    if 1 <= value <= 65535:
        return value
    return None


def listen_label(tokens: Iterable[str]) -> str | None:
    """Sorted unique TLS listen tokens. A variable or Unix-domain path is omitted."""
    kept = sorted(
        {token.strip() for token in tokens if _LISTEN.fullmatch(token.strip())}
    )
    if not kept:
        return None
    return ",".join(kept[:8])


def listener_reader(*, plaintext: bool, redirect: bool) -> LayerResult:
    """One reader shared by every extractor. A redirect is not plaintext."""
    if redirect:
        return LayerResult("ENCRYPTED_DECLARED")
    if plaintext:
        return LayerResult("NOT_ENCRYPTED")
    return LayerResult("UNKNOWN", "attribute_not_modeled")
