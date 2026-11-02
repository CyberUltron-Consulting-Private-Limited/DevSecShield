"""CloudFormation encryption facts. Verdicts use the Terraform helper."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import replace

from aibom.cbom.posture.coverage import TypeRule, load_coverage
from aibom.cbom.posture.extract_terraform import (
    apply_aws_rotation_value,
    assess_sources,
    build_encryption_fact,
)
from aibom.cbom.posture.jsonsafe import parse_json
from aibom.cbom.posture.model import BasisEntry, EncryptionFact
from aibom.cbom.posture.resolve import Absent, Value, resolve_expr
from aibom.cbom.posture.tls_policy import (
    policy_floor_note,
    protocol_for_policy,
    weak_suite_for_policy,
)
from aibom.cbom.posture.yamlsafe import LineDict, parse_yaml


def extract_cloudformation(text: str, path: str) -> tuple[EncryptionFact, ...]:
    """Facts for template resources whose Type is in the coverage table."""
    loaded = _load(text, path)
    if loaded is None:
        return ()
    document, lines = loaded
    facts: list[EncryptionFact] = []
    for address, native, props, line in _resources(document, lines):
        rule = _match(native, props)
        if rule is None:
            continue
        if not rule.layers and native != "AWS::KMS::Key":
            continue
        fact = build_encryption_fact(
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
        if native == "AWS::KMS::Key":
            fact = apply_aws_rotation_value(
                fact,
                _cfn_value(props, "EnableKeyRotation"),
                usage=_cfn_value(props, "KeyUsage"),
                spec=_cfn_value(props, "KeySpec"),
            )
        fact = _apply_tls_policy(fact, native, props)
        deciding = _deciding_line(document, lines, address, fact.basis)
        fact = replace(fact, line=deciding or fact.line)
        facts.append(fact)
    return tuple(facts)


# Basis entries that name a decision, not a property: the properties that carry it.
_BASIS_PROPS: dict[str, tuple[str, ...]] = {"rotation": ("EnableKeyRotation",)}


def _property_line(
    document: object, lines: Mapping[tuple[str, ...], int], resource: str, path: str
) -> int | None:
    """Source line of ``Resources.<resource>.Properties.<path>`` (JSON key map or YAML key lines)."""
    parts = [part for part in path.split(".") if part]
    if not parts:
        return None
    if lines:
        return lines.get(("Resources", resource, "Properties", *parts))
    node: object = document
    for key in ("Resources", resource, "Properties", *parts[:-1]):
        node = node.get(key) if isinstance(node, dict) else None
    if isinstance(node, LineDict):
        return node.key_lines.get(parts[-1])
    return None


def _deciding_line(
    document: object, lines: Mapping[tuple[str, ...], int], resource: str, basis: tuple[BasisEntry, ...]
) -> int | None:
    """The property named LAST in the basis that is written in the template (``StorageEncrypted: false``), like
    the Terraform extractor; None when no basis property is written."""
    line: int | None = None
    for entry in basis:
        for name in _BASIS_PROPS.get(entry.name, (entry.name,)):
            found = _property_line(document, lines, resource, name)
            if found:
                line = found
                break
    return line


def _apply_tls_policy(
    fact: EncryptionFact, native: str, props: Mapping[str, object]
) -> EncryptionFact:
    if native == "AWS::CloudFront::Distribution":
        path = ("DistributionConfig", "ViewerCertificate", "MinimumProtocolVersion")
    elif native == "AWS::ElasticLoadBalancingV2::Listener":
        path = ("SslPolicy",)
    else:
        return fact
    name = _nested(props, path)
    present = _present(props, path)
    if not isinstance(name, str) or not name:
        if present:
            return replace(
                fact,
                basis=fact.basis
                + (BasisEntry("ssl_policy", None, "unresolved_expression"),),
            )
        if native != "AWS::ElasticLoadBalancingV2::Listener":
            return fact
        protocol = _nested(props, ("Protocol",))
        if not isinstance(protocol, str) or protocol.upper() != "HTTPS":
            return fact
        name = "ELBSecurityPolicy-2016-08"
    floor = protocol_for_policy(name)
    if floor is None:
        return replace(
            fact,
            basis=fact.basis + (BasisEntry("ssl_policy", None, "default_unknown"),),
        )
    notes: list[BasisEntry] = [
        BasisEntry("policy", name),
        BasisEntry("protocol_min", floor),
    ]
    inferred = policy_floor_note(name)
    if inferred is not None:
        notes.append(inferred)
    suite = weak_suite_for_policy(name)
    if suite is not None:
        notes.append(BasisEntry("cipher_suite", suite))
    return replace(fact, basis=fact.basis + tuple(notes))


def _present(value: object, path: tuple[str, ...]) -> bool:
    current = value
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return False
        current = current[key]
    return True


def _nested(value: object, path: tuple[str, ...]) -> object:
    current = value
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


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
        line = lines.get(("Resources", str(key))) or (
            raw.key_lines.get(str(key)) if isinstance(raw, LineDict) else None
        ) or 1
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
