"""Shared fact builder. Lookups stay on this object's own dictionaries."""

from __future__ import annotations

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


def listener_reader(*, plaintext: bool, redirect: bool) -> LayerResult:
    """One reader shared by every extractor. A redirect is not plaintext."""
    if redirect:
        return LayerResult("ENCRYPTED_DECLARED")
    if plaintext:
        return LayerResult("NOT_ENCRYPTED")
    return LayerResult("UNKNOWN", "attribute_not_modeled")
