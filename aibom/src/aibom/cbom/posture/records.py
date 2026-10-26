"""Reduced records. An attribute outside the consulted set is not readable."""

from __future__ import annotations

from dataclasses import dataclass

from aibom.cbom.posture.resolve import Absent, Value


@dataclass(frozen=True, slots=True)
class AttrView:
    values: dict[str, Value]
    consulted: frozenset[str]

    def get(self, path: str) -> Value:
        if path not in self.consulted:
            raise KeyError(path)
        return self.values.get(path, Absent())


@dataclass(frozen=True, slots=True)
class RawRecord:
    address: str
    path: str
    line: int
    native_type: str


@dataclass(frozen=True, slots=True)
class ResourceRecord:
    address: str
    path: str
    line: int
    native_type: str
    attrs: AttrView
