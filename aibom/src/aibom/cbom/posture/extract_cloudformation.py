"""CloudFormation encryption facts. Verdicts use the Terraform helper."""

from __future__ import annotations

from collections.abc import Callable, Mapping

from aibom.cbom.posture.coverage import TypeRule, load_coverage
from aibom.cbom.posture.extract_terraform import assess_sources, build_encryption_fact
from aibom.cbom.posture.jsonsafe import parse_json
from aibom.cbom.posture.model import EncryptionFact
from aibom.cbom.posture.resolve import Absent, Value, resolve_expr
from aibom.cbom.posture.yamlsafe import parse_yaml


def extract_cloudformation(text: str, path: str) -> tuple[EncryptionFact, ...]:
    """Facts for template resources whose Type is in the coverage table."""
    loaded = _load(text, path)
    if loaded is None:
        return ()
    document, lines = loaded
    facts: list[EncryptionFact] = []
    for address, native, props, line in _resources(document, lines):
        rule = _match(native, props)
        if rule is None or not rule.layers:
            continue
        facts.append(
            build_encryption_fact(
                rule,
                _getter(props),
                address=address,
                path=path,
                line=line,
                form="cloudformation",
                native_type=native,
                syntax="cloudformation",
                assess=assess_sources,
            )
        )
    return tuple(facts)


def _load(
    text: str, path: str
) -> tuple[object, Mapping[tuple[str, ...], int]] | None:
    stripped = text.lstrip()
    if path.endswith(".json") or stripped.startswith(("{", "[")):
        parsed = parse_json(text, path=path)
        if parsed is None:
            return None
        return parsed.value, parsed.key_lines
    documents = parse_yaml(text, path=path)
    if not documents:
        return None
    return documents[0], {}


def _resources(
    document: object, lines: Mapping[tuple[str, ...], int]
) -> list[tuple[str, str, Mapping[str, object], int]]:
    if not isinstance(document, dict):
        return []
    raw = document.get("Resources")
    if not isinstance(raw, dict):
        return []
    found: list[tuple[str, str, Mapping[str, object], int]] = []
    for key, body in raw.items():
        if not isinstance(body, dict):
            continue
        native = body.get("Type")
        if not isinstance(native, str) or not native:
            continue
        props = body.get("Properties")
        mapping = _as_map(props)
        line = lines.get(("Resources", str(key)), 1)
        found.append((str(key), native, mapping, line if line > 0 else 1))
    return found


def _as_map(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    return {str(key): item for key, item in value.items()}


def _match(native: str, props: Mapping[str, object]) -> TypeRule | None:
    specific: list[TypeRule] = []
    plain: list[TypeRule] = []
    for rule in _cfn_index().get(native, ()):
        if not rule.cfn_when:
            plain.append(rule)
            continue
        if all(props.get(key) == want for key, want in rule.cfn_when.items()):
            specific.append(rule)
    if specific:
        return specific[0]
    if plain:
        return plain[0]
    return None


def _cfn_index() -> dict[str, tuple[TypeRule, ...]]:
    grouped: dict[str, list[TypeRule]] = {}
    for rule in load_coverage().rules:
        for name in rule.native.get("cloudformation", ()):
            if isinstance(name, str):
                grouped.setdefault(name, []).append(rule)
    return {key: tuple(value) for key, value in grouped.items()}


def _getter(props: Mapping[str, object]) -> Callable[[str], Value]:
    def get(path: str) -> Value:
        return _cfn_value(props, path)

    return get


def _cfn_value(props: Mapping[str, object], path: str) -> Value:
    current: object = props
    for part in path.split("."):
        if not part:
            continue
        if not isinstance(current, Mapping) or part not in current:
            return Absent()
        current = current[part]
    if isinstance(current, Mapping):
        return resolve_expr({str(key): value for key, value in current.items()})
    return resolve_expr(current)
