"""Encryption fact records and the redaction rule. No file access."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final, Literal

Verdict = Literal[
    "ENCRYPTED_DECLARED",
    "ENCRYPTED_PROVIDER_DEFAULT",
    "NOT_ENCRYPTED",
    "UNKNOWN",
]
Layer = Literal["application", "database", "volume", "service", "backup", "transport"]
PathContext = Literal["production_like", "non_production_hint"]

HIDDEN_SUBSTRINGS: Final[tuple[str, ...]] = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "access_key",
    "private_key",
    "credential",
    "connection_string",
    "encryption_key",
    "key_material",
)

_NON_PRODUCTION = frozenset(
    {
        "test",
        "tests",
        "__tests__",
        "spec",
        "fixtures",
        "testdata",
        "example",
        "examples",
        "sample",
        "samples",
        "docs",
        "e2e",
        "dev",
        "local",
        "sandbox",
    }
)


def is_hidden_path(path: str) -> bool:
    """True when any dotted segment contains a hidden substring."""
    for segment in path.replace("/", ".").split("."):
        lowered = segment.casefold()
        if any(token in lowered for token in HIDDEN_SUBSTRINGS):
            return True
    return False


def path_context(rel: str) -> PathContext:
    parts = {part.casefold() for part in rel.split("/") if part}
    if parts & _NON_PRODUCTION:
        return "non_production_hint"
    return "production_like"


def fact_id(kind: str, provider: str, native_type: str, address: str, path: str) -> str:
    """Stable SHA-256 prefix. Independent of host and PYTHONHASHSEED."""
    raw = "\n".join((kind, provider, native_type, address, path)).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


@dataclass(frozen=True, slots=True)
class BasisEntry:
    name: str
    value: str | None = None
    unknown_reason: str | None = None


@dataclass(frozen=True, slots=True)
class Linkage:
    system: str | None = None
    owner: str | None = None
    data_classification: str | None = None
    data_lifetime: str | None = None
    owner_hint: str | None = None
    source: str | None = None


@dataclass(frozen=True, slots=True)
class DisabledResource:
    address: str
    path: str
    line: int


@dataclass(frozen=True, slots=True)
class DataTable:
    name: str
    data_version: int
    valid_as_of: str
    sha256: str


@dataclass(frozen=True, slots=True)
class ConfigContext:
    pins: Mapping[str, tuple[int, ...]]
    compose_services: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ImportRecord:
    path: str
    tool: str
    tool_version: str | None = None
    scan_started: str | None = None
    scan_finished: str | None = None


@dataclass(frozen=True, slots=True)
class EncryptionFact:
    id: str
    kind: str
    provider: str
    native_type: str
    address: str
    path: str
    line: int
    format: str
    layers: Mapping[str, str]
    verdict: str
    basis: tuple[BasisEntry, ...] = ()
    default_row: str | None = None
    key_management: str = "unspecified"
    key_ref: str | None = None
    unknown_reason: str | None = None
    path_context: PathContext = "production_like"
    linkage: Linkage = field(default_factory=Linkage)
    finding_codes: tuple[str, ...] = ()
