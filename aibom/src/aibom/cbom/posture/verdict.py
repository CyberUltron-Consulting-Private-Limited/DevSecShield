"""Verdict engine. First matching step of the decision table wins."""

from __future__ import annotations

from dataclasses import dataclass

from aibom.cbom.posture.resolve import Absent, Resolved, Unresolved, Value

AT_REST = ("application", "database", "volume", "service", "backup")
_ENABLE = frozenset({True, "true", "on", "enabled"})
_DISABLE = frozenset({False, "false", "off", "disabled"})


@dataclass(frozen=True, slots=True)
class LayerCase:
    sources: tuple[Value, ...] = ()
    self_hosted: bool = False
    effect: str | None = None
    assessable: bool = False
    version_dependent: bool = False
    version_pinned: bool = False
    override_value: Value | None = None
    override_elsewhere: bool = False
    as_absent: frozenset[object] = frozenset()
    row_id: str | None = None
    caveat: str = ""


@dataclass(frozen=True, slots=True)
class LayerResult:
    verdict: str
    reason: str | None = None
    default_row: str | None = None
    caveat: str = ""


def _class_of(value: object, as_absent: frozenset[object]) -> str:
    if value in as_absent:
        return "ABSENT"
    if value in _ENABLE:
        return "ENABLE"
    if value in _DISABLE:
        return "DISABLE"
    return "OTHER"


def assess_layer(case: LayerCase) -> LayerResult:
    if not case.sources:
        return LayerResult("UNKNOWN", "attribute_not_modeled")
    for source in case.sources:
        if isinstance(source, Unresolved):
            return LayerResult("UNKNOWN", source.reason)
    classes: list[str] = []
    for source in case.sources:
        if isinstance(source, Absent):
            classes.append("ABSENT")
        elif isinstance(source, Resolved):
            classes.append(_class_of(source.value, case.as_absent))
    if "ENABLE" in classes and "DISABLE" in classes:
        return LayerResult("UNKNOWN", "attribute_not_modeled")
    if "ENABLE" in classes:
        return LayerResult("ENCRYPTED_DECLARED")
    if "DISABLE" in classes:
        return LayerResult("NOT_ENCRYPTED", caveat=case.caveat)
    if classes and set(classes) == {"OTHER"}:
        return LayerResult("UNKNOWN", "attribute_not_modeled")
    if case.self_hosted:
        return LayerResult("UNKNOWN", "layer_not_observable")
    if case.row_id is None:
        return LayerResult("UNKNOWN", "default_unknown")
    if case.version_dependent and not case.version_pinned:
        return LayerResult("UNKNOWN", "provider_version_dependent")
    if case.override_elsewhere and case.override_value is None:
        return LayerResult("UNKNOWN", "default_unknown")
    if isinstance(case.override_value, Unresolved):
        return LayerResult("UNKNOWN", case.override_value.reason)
    if isinstance(case.override_value, Resolved):
        kind = _class_of(case.override_value.value, case.as_absent)
        if kind == "ENABLE":
            return LayerResult("ENCRYPTED_DECLARED", default_row=case.row_id)
        if kind == "DISABLE":
            return LayerResult("NOT_ENCRYPTED", default_row=case.row_id)
        return LayerResult("UNKNOWN", "attribute_not_modeled")
    if case.effect == "ENCRYPTED":
        return LayerResult("ENCRYPTED_PROVIDER_DEFAULT", default_row=case.row_id)
    if case.effect == "NOT_ENCRYPTED" and case.assessable:
        return LayerResult("NOT_ENCRYPTED", default_row=case.row_id, caveat=case.caveat)
    return LayerResult("UNKNOWN", "default_unknown")


def resource_verdict(layers: dict[str, str], *, transport_only: bool) -> str | None:
    if transport_only:
        return layers.get("transport")
    at_rest = [layers[name] for name in AT_REST if name in layers]
    if not at_rest:
        return None
    if "ENCRYPTED_DECLARED" in at_rest:
        return "ENCRYPTED_DECLARED"
    if "ENCRYPTED_PROVIDER_DEFAULT" in at_rest:
        return "ENCRYPTED_PROVIDER_DEFAULT"
    if "UNKNOWN" in at_rest:
        return "UNKNOWN"
    return "NOT_ENCRYPTED"


def tri_state(verdict: str | None) -> str:
    if verdict in {"ENCRYPTED_DECLARED", "ENCRYPTED_PROVIDER_DEFAULT"}:
        return "pass"
    if verdict == "NOT_ENCRYPTED":
        return "fail"
    return "not_bom_evidenceable"


def coverage(states: list[str]) -> float | None:
    passed = sum(1 for item in states if item == "pass")
    failed = sum(1 for item in states if item == "fail")
    if passed + failed == 0:
        return None
    return passed / (passed + failed)
