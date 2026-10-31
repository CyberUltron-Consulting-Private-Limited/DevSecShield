"""Terraform encryption facts. Unregistered: scan_crypto does not import this."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Protocol

from aibom.cbom.posture.codec import make_fact_id
from aibom.cbom.posture.coverage import LayerRule, Source, TypeRule, load_coverage
from aibom.cbom.posture.defaults import DefaultRow, load_registry
from aibom.cbom.posture.hcl import (
    Block,
    Body,
    Lit,
    Obj,
    Ref,
    parse_hcl,
)
from aibom.cbom.posture.hcl import (
    Tuple as HclTuple,
)
from aibom.cbom.posture.hcl import (
    Unresolved as HclUnresolved,
)
from aibom.cbom.posture.model import BasisEntry, EncryptionFact, path_context
from aibom.cbom.posture.resolve import (
    Absent,
    Resolved,
    Unresolved,
    Value,
    gcp_binding_exposure,
    policy_exposure,
    resolve_expr,
)
from aibom.cbom.posture.tls_policy import protocol_for_policy, weak_suite_for_policy
from aibom.cbom.posture.verdict import (
    LayerCase,
    LayerResult,
    assess_layer,
    resource_verdict,
)

_EMPTY: frozenset[object] = frozenset()
_ROOTS = frozenset({"local", "module", "data", "each", "count"})
_TRANSPORT_ONLY = frozenset({"tls_endpoint", "ssh_service"})
_ORDER = (
    "application",
    "database",
    "volume",
    "service",
    "backup",
    "transport",
)


class _Assessor(Protocol):
    def __call__(
        self,
        sources: tuple[Value, ...],
        row: DefaultRow | None,
        *,
        self_hosted: bool = False,
        as_absent: frozenset[object] = _EMPTY,
        version_dependent: bool = False,
    ) -> LayerResult: ...


@dataclass(frozen=True, slots=True)
class _Choice:
    row: DefaultRow | None
    reason: str | None = None
    version_dependent: bool = False


def assess_sources(
    sources: tuple[Value, ...],
    row: DefaultRow | None,
    *,
    self_hosted: bool = False,
    as_absent: frozenset[object] = _EMPTY,
    version_dependent: bool = False,
) -> LayerResult:
    """One decision for a layer. Callers pass the coverage default row."""
    effect = None
    assessable = False
    row_id = None
    caveat = ""
    bounded = False
    if row is not None:
        effect = row.effect
        assessable = row.assessable_as_unencrypted
        row_id = row.id
        caveat = row.caveat
        bounded = row.versions.min is not None or row.versions.max_exclusive is not None
    return assess_layer(
        LayerCase(
            sources=sources,
            self_hosted=self_hosted,
            effect=effect,
            assessable=assessable,
            version_dependent=version_dependent or bounded,
            row_id=row_id,
            caveat=caveat,
            as_absent=as_absent,
        )
    )


def extract_terraform(text: str, path: str) -> tuple[EncryptionFact, ...]:
    """Facts for resource blocks whose type is in the coverage table."""
    body = parse_hcl(text, path=path)
    if body is None:
        return ()
    rules = _terraform_index()
    facts: list[EncryptionFact] = []
    for block in body.blocks:
        if block.type != "resource" or len(block.labels) != 2:
            continue
        native, name = block.labels
        rule = rules.get(native)
        if rule is None:
            continue
        if _count_zero(block.body):
            continue
        signal = _kms_policy_signal(native, block.body)
        notes = _gcp_binding_notes(native, block.body)
        if signal is not None:
            notes = (signal, *notes)
        has_literal = _literal_key_policy(native, block.body)
        tracked = notes or has_literal or _key_rotation_row(native)
        if not rule.layers and not tracked:
            continue
        fact = build_encryption_fact(
            rule,
            _bound(block.body),
            address=f"{native}.{name}",
            path=path,
            line=block.line if block.line > 0 else 1,
            form="terraform",
            native_type=native,
            syntax="terraform",
        )
        if notes:
            fact = replace(fact, basis=fact.basis + notes)
        if _gcp_members_unresolved(native, block.body):
            fact = replace(
                fact, verdict="UNKNOWN", unknown_reason="unresolved_expression"
            )
        fact = _apply_key_rotation(fact, native, block.body)
        fact = _apply_purge_protection(fact, native, block.body)
        fact = _record_declared_spec(fact, native, block.body)
        fact = _apply_tls_policy(fact, native, block.body)
        fact = _ensure_kms_rollup_layers(fact, native)
        facts.append(fact)
    return tuple(facts)


def _ensure_kms_rollup_layers(fact: EncryptionFact, native: str) -> EncryptionFact:
    """Signal-only GCP KMS blocks still carry one layer for posture rollup."""
    if fact.layers:
        return fact
    if native == "google_kms_crypto_key":
        layers = {"rotation": "UNKNOWN"}
    elif _gcp_member_attr(native) is not None:
        layers = {"service": "UNKNOWN"}
    else:
        return fact
    verdict = resource_verdict(layers, transport_only=False) or "UNKNOWN"
    reason = fact.unknown_reason or "default_unknown"
    return replace(fact, layers=layers, verdict=verdict, unknown_reason=reason)


def _kms_policy_signal(native: str, body: Body) -> BasisEntry | None:
    """A literal key policy that is public raises KMS_KEY_POLICY_PUBLIC."""
    if native != "aws_kms_key":
        return None
    value = _hcl_value(body, "policy")
    if not isinstance(value, Resolved) or not isinstance(value.value, str):
        return None
    try:
        document = json.loads(value.value)
    except json.JSONDecodeError:
        return None
    statements = document.get("Statement") if isinstance(document, dict) else None
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return None
    for statement in statements:
        if isinstance(statement, dict) and policy_exposure(statement) == "public":
            return BasisEntry("signal", "KMS_KEY_POLICY_PUBLIC")
    return None


def _key_rotation_row(native: str) -> bool:
    return native in {
        "aws_kms_key",
        "google_kms_crypto_key",
        "azurerm_key_vault_key",
    }


def _apply_key_rotation(
    fact: EncryptionFact, native: str, body: Body
) -> EncryptionFact:
    """Omitted Google rotation stays unknown. Azure key rotation is not applicable."""
    if native == "aws_kms_key":
        return _apply_aws_rotation(fact, body)
    if native == "azurerm_key_vault_key":
        return replace(
            fact, basis=fact.basis + (BasisEntry("rotation", "not_applicable"),)
        )
    if native != "google_kms_crypto_key":
        return fact
    value = _hcl_value(body, "rotation_period")
    if isinstance(value, Resolved):
        return fact
    reason = (
        "unresolved_expression" if isinstance(value, Unresolved) else "default_unknown"
    )
    return replace(fact, verdict="UNKNOWN", unknown_reason=reason)


def _apply_aws_rotation(fact: EncryptionFact, body: Body) -> EncryptionFact:
    """Absent or false rotation raises the reviewed AWS finding. A variable does not."""
    return apply_aws_rotation_value(
        fact,
        _hcl_value(body, "enable_key_rotation"),
        usage=_hcl_value(body, "key_usage"),
        spec=_hcl_value(body, "customer_master_key_spec"),
    )


def apply_aws_rotation_value(
    fact: EncryptionFact,
    value: Value,
    *,
    usage: Value,
    spec: Value,
) -> EncryptionFact:
    """Shared by Terraform and CloudFormation. An unresolved value raises nothing."""
    notes: list[BasisEntry] = []
    if isinstance(spec, Resolved) and isinstance(spec.value, str) and spec.value:
        notes.append(BasisEntry("key_spec", spec.value))
    if isinstance(usage, Resolved) and isinstance(usage.value, str) and usage.value:
        notes.append(BasisEntry("key_usage", usage.value))
    if notes:
        fact = replace(fact, basis=fact.basis + tuple(notes))
    asymmetric = (
        isinstance(usage, Resolved) and usage.value not in {None, "ENCRYPT_DECRYPT"}
    ) or (
        isinstance(spec, Resolved) and spec.value not in {None, "SYMMETRIC_DEFAULT"}
    )
    if asymmetric:
        return replace(
            fact, basis=fact.basis + (BasisEntry("rotation", "not_applicable"),)
        )
    if isinstance(value, Unresolved):
        return replace(
            fact, verdict="UNKNOWN", unknown_reason="unresolved_expression"
        )
    if isinstance(value, Resolved) and value.value is True:
        return replace(fact, basis=fact.basis + (BasisEntry("rotation", "enabled"),))
    notes = [
        BasisEntry("signal", "KMS_KEY_ROTATION_DISABLED"),
        BasisEntry("rotation", "disabled"),
    ]
    reason = fact.unknown_reason
    verdict = fact.verdict
    if not isinstance(value, Resolved):
        notes.append(BasisEntry("rotation_default_row", "aws.kms.enable_key_rotation"))
        verdict = "UNKNOWN"
        reason = "default_unknown"
    return replace(
        fact,
        basis=fact.basis + tuple(notes),
        verdict=verdict,
        unknown_reason=reason,
    )


_PURGE_ROWS = {
    "azurerm_key_vault": "azure.keyvault.purge_protection",
    "azurerm_key_vault_managed_hardware_security_module": (
        "azure.keyvault_hsm.purge_protection"
    ),
}


def _apply_purge_protection(
    fact: EncryptionFact, native: str, body: Body
) -> EncryptionFact:
    """An omitted or false purge-protection flag raises the reviewed Azure finding."""
    row = _PURGE_ROWS.get(native)
    if row is None:
        return fact
    value = _hcl_value(body, "purge_protection_enabled")
    if isinstance(value, Unresolved):
        return replace(
            fact, verdict="UNKNOWN", unknown_reason="unresolved_expression"
        )
    if isinstance(value, Resolved) and value.value is True:
        return replace(
            fact, basis=fact.basis + (BasisEntry("purge_protection", "enabled"),)
        )
    notes = [
        BasisEntry("signal", "KMS_KEY_DELETION_UNPROTECTED"),
        BasisEntry("purge_protection", "disabled"),
    ]
    verdict = fact.verdict
    reason = fact.unknown_reason
    if not isinstance(value, Resolved):
        notes.append(BasisEntry("purge_protection_default_row", row))
        if verdict not in {"ENCRYPTED_DECLARED", "NOT_ENCRYPTED"}:
            verdict = "UNKNOWN"
            reason = "default_unknown"
    return replace(
        fact,
        basis=fact.basis + tuple(notes),
        verdict=verdict,
        unknown_reason=reason,
    )


_DECLARED_SPEC = {
    "azurerm_key_vault_key": "key_type",
    "google_kms_crypto_key": "version_template.algorithm",
}


def _record_declared_spec(
    fact: EncryptionFact, native: str, body: Body
) -> EncryptionFact:
    """Attach a key_specs.json id when the declared type matches that row."""
    attr = _DECLARED_SPEC.get(native)
    if attr is None or any(item.name == "key_spec" for item in fact.basis):
        return fact
    value = _hcl_value(body, attr)
    if not isinstance(value, Resolved) or not isinstance(value.value, str):
        return fact
    spec = value.value
    if spec == "RSA" and _size_mismatch(body, 2048):
        return fact
    if spec == "EC" and _size_mismatch(body, 256):
        return fact
    if spec not in {"RSA", "EC", "GOOGLE_SYMMETRIC_ENCRYPTION"}:
        return fact
    return replace(fact, basis=fact.basis + (BasisEntry("key_spec", spec),))


_AZURE_WEB = frozenset({"azurerm_linux_web_app", "azurerm_windows_web_app"})
_AZURE_TLS = {"1.0": "TLSv1.0", "1.1": "TLSv1.1", "1.2": "TLSv1.2", "1.3": "TLSv1.3"}
_TLS_ATTR = {
    "aws_cloudfront_distribution": "viewer_certificate.minimum_protocol_version",
}
_LISTENER_DEFAULT = "ELBSecurityPolicy-2016-08"


def _apply_tls_policy(
    fact: EncryptionFact, native: str, body: Body
) -> EncryptionFact:
    if native == "google_compute_ssl_policy":
        return _gcp_ssl_policy(fact, body)
    if native in _AZURE_WEB:
        return _azure_tls(fact, body)
    if native == "aws_lb_listener":
        return _listener_policy(fact, body)
    attr = _TLS_ATTR.get(native)
    if attr is None:
        return fact
    value = _hcl_value(body, attr)
    if not isinstance(value, Resolved) or not isinstance(value.value, str):
        return fact
    return _named_policy(fact, value.value)


def _listener_policy(fact: EncryptionFact, body: Body) -> EncryptionFact:
    value = _hcl_value(body, "ssl_policy")
    protocol = (_literal(body, "protocol") or "").upper()
    if isinstance(value, Resolved) and isinstance(value.value, str):
        return _named_policy(fact, value.value)
    if isinstance(value, Absent) and protocol == "HTTPS":
        return _named_policy(fact, _LISTENER_DEFAULT)
    if protocol == "HTTPS":
        return replace(
            fact,
            basis=fact.basis
            + (BasisEntry("ssl_policy", None, "unresolved_expression"),),
        )
    return fact


def _named_policy(fact: EncryptionFact, name: str | None) -> EncryptionFact:
    if name is None:
        return fact
    floor = protocol_for_policy(name)
    if floor is None:
        return replace(
            fact,
            basis=fact.basis + (BasisEntry("ssl_policy", None, "default_unknown"),),
        )
    notes = [BasisEntry("policy", name), BasisEntry("protocol_min", floor)]
    suite = weak_suite_for_policy(name)
    if suite is not None:
        notes.append(BasisEntry("cipher_suite", suite))
    return replace(fact, basis=fact.basis + tuple(notes))


def _gcp_ssl_policy(fact: EncryptionFact, body: Body) -> EncryptionFact:
    profile = _literal(body, "profile") or "COMPATIBLE"
    configured = _literal(body, "min_tls_version") or "TLS_1_0"
    floor = protocol_for_policy(profile, configured)
    if floor is None:
        return replace(
            fact,
            basis=fact.basis + (BasisEntry("ssl_policy", None, "default_unknown"),),
        )
    return replace(
        fact,
        basis=fact.basis
        + (BasisEntry("policy", profile), BasisEntry("protocol_min", floor)),
    )


def _azure_tls(fact: EncryptionFact, body: Body) -> EncryptionFact:
    raw = _literal(body, "site_config.minimum_tls_version") or "1.2"
    floor = _AZURE_TLS.get(raw)
    if floor is None:
        return replace(
            fact,
            basis=fact.basis + (BasisEntry("ssl_policy", None, "default_unknown"),),
        )
    return replace(
        fact,
        basis=fact.basis
        + (BasisEntry("policy", raw), BasisEntry("protocol_min", floor)),
    )


def _literal(body: Body, name: str) -> str | None:
    value = _hcl_value(body, name)
    if isinstance(value, Resolved) and isinstance(value.value, str):
        return value.value
    return None


def _size_mismatch(body: Body, expected: int) -> bool:
    value = _hcl_value(body, "key_size")
    return isinstance(value, Resolved) and value.value != expected


def _gcp_member_attr(native: str) -> str | None:
    return {
        "google_kms_crypto_key_iam_binding": "members",
        "google_kms_crypto_key_iam_member": "member",
    }.get(native)


def _literal_key_policy(native: str, body: Body) -> bool:
    if native == "aws_kms_key":
        return isinstance(_hcl_value(body, "policy"), Resolved)
    attr = _gcp_member_attr(native)
    if attr is None:
        return False
    return isinstance(_hcl_value(body, attr), (Resolved, Unresolved))


def _gcp_members_unresolved(native: str, body: Body) -> bool:
    attr = _gcp_member_attr(native)
    return attr is not None and isinstance(_hcl_value(body, attr), Unresolved)


def _gcp_binding_notes(native: str, body: Body) -> tuple[BasisEntry, ...]:
    """allUsers stays public even when a condition block is present."""
    attr = _gcp_member_attr(native)
    if attr is None:
        return ()
    value = _hcl_value(body, attr)
    if not isinstance(value, Resolved):
        return ()
    conditional = _block(body, "condition") is not None
    exposure, _flag = gcp_binding_exposure(
        value.value, object() if conditional else None
    )
    notes: list[BasisEntry] = []
    if exposure == "public":
        notes.append(BasisEntry("signal", "KMS_KEY_POLICY_PUBLIC"))
    if conditional and exposure == "public":
        notes.append(BasisEntry("exposure_conditional", "true"))
    return tuple(notes)


def build_encryption_fact(
    rule: TypeRule,
    get: Callable[[str], Value],
    *,
    address: str,
    path: str,
    line: int,
    form: str,
    native_type: str,
    syntax: str,
    assess: _Assessor | None = None,
) -> EncryptionFact:
    """Assess every layer of one coverage rule and roll the verdicts up."""
    decide = assess or assess_sources
    results: dict[str, LayerResult] = {}
    basis: list[BasisEntry] = []
    for name, layer in rule.layers.items():
        result, entries = _coverage_layer(layer, get, syntax, decide)
        results[name] = result
        basis.extend(entries)
    verdict, default_row, reason = _rollup(results, rule.kind)
    kind = rule.kind or ""
    return EncryptionFact(
        id=make_fact_id(kind, rule.provider, native_type, address, path),
        kind=kind,
        provider=rule.provider,
        native_type=native_type,
        address=address,
        path=path,
        line=line if line > 0 else 1,
        format=form,
        layers={name: item.verdict for name, item in results.items()},
        verdict=verdict,
        basis=tuple(basis[:40]),
        default_row=default_row,
        unknown_reason=reason,
        path_context=path_context(path),
    )


def _coverage_layer(
    layer: LayerRule,
    get: Callable[[str], Value],
    syntax: str,
    assess: _Assessor,
) -> tuple[LayerResult, tuple[BasisEntry, ...]]:
    values: list[Value] = []
    basis: list[BasisEntry] = []
    tokens: set[object] = set()
    for source in layer.sources:
        if source.reader is not None:
            continue
        attr = _attr_path(source, syntax)
        if not attr:
            continue
        value = get(attr)
        values.append(value)
        tokens.update(_tokens(source.as_absent))
        basis.extend(_basis(attr, value))
    if not values:
        return assess((), None, self_hosted=layer.self_hosted), ()
    choice = _choose_row(layer, get, syntax)
    absent = all(isinstance(item, Absent) for item in values)
    if choice.reason and absent:
        forced = assess(
            (Unresolved(choice.reason),),
            None,
            self_hosted=layer.self_hosted,
        )
        return forced, tuple(basis)
    decided = assess(
        tuple(values),
        choice.row,
        self_hosted=layer.self_hosted,
        as_absent=frozenset(tokens),
        version_dependent=choice.version_dependent,
    )
    return decided, tuple(basis)


def _choose_row(
    layer: LayerRule, get: Callable[[str], Value], syntax: str
) -> _Choice:
    if not layer.default_row:
        return _Choice(None)
    named = load_registry().by_id.get(layer.default_row)
    if named is None:
        return _Choice(None, "default_unknown")
    matched: list[DefaultRow] = []
    unresolved: str | None = None
    for row in _siblings(named):
        status = _when(row, get, syntax)
        if status == "skip":
            continue
        if status:
            unresolved = status
            continue
        if _blocked(row, get, syntax):
            continue
        matched.append(row)
    if not matched:
        return _Choice(None, unresolved or "default_unknown")
    if len({row.effect for row in matched}) > 1:
        return _Choice(matched[0], version_dependent=True)
    return _Choice(matched[0])


def _siblings(named: DefaultRow) -> tuple[DefaultRow, ...]:
    types = set(named.type)
    rows = [
        row
        for row in load_registry().rows
        if row.provider == named.provider
        and row.attribute == named.attribute
        and types & set(row.type)
    ]
    return tuple(rows) or (named,)


def _when(row: DefaultRow, get: Callable[[str], Value], syntax: str) -> str | None:
    clause = row.when.get(syntax, {})
    if not clause:
        return None
    for attr, allowed in clause.items():
        value = get(attr)
        if isinstance(value, Unresolved):
            return value.reason
        if isinstance(value, Absent):
            literal: object = None
        elif isinstance(value, Resolved):
            literal = value.value
        else:
            return "unresolved_expression"
        if not _allowed(literal, allowed):
            return "skip"
    return None


def _allowed(literal: object, allowed: tuple[object, ...]) -> bool:
    if literal in allowed:
        return True
    if not isinstance(literal, str):
        return False
    folded = literal.casefold()
    return any(isinstance(item, str) and item.casefold() == folded for item in allowed)


def _blocked(row: DefaultRow, get: Callable[[str], Value], syntax: str) -> bool:
    paths = row.unless_attrs.get(syntax, ())
    return any(not isinstance(get(path), Absent) for path in paths)


def _attr_path(source: Source, syntax: str) -> str | None:
    if syntax == "terraform":
        return source.tf
    if syntax == "cloudformation":
        return source.cfn
    return None


def _tokens(words: frozenset[str]) -> frozenset[object]:
    found: set[object] = set(words)
    folded = {word.casefold() for word in words}
    if "false" in folded:
        found.add(False)
    if "true" in folded:
        found.add(True)
    return frozenset(found)


def _basis(name: str, value: Value) -> tuple[BasisEntry, ...]:
    if isinstance(value, Resolved):
        return (BasisEntry(name, _show(value.value)),)
    if isinstance(value, Unresolved):
        return (BasisEntry(name, None, value.reason),)
    return ()


def _show(value: object) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    return str(value)[:128]


def _rollup(
    results: dict[str, LayerResult], kind: str | None
) -> tuple[str, str | None, str | None]:
    layers = {name: item.verdict for name, item in results.items()}
    transport_only = kind in _TRANSPORT_ONLY
    verdict = resource_verdict(layers, transport_only=transport_only) or ""
    names = ("transport",) if transport_only else _ORDER
    default_row: str | None = None
    reason: str | None = None
    for name in names:
        item = results.get(name)
        if item is None or item.verdict != verdict:
            continue
        default_row = item.default_row
        reason = item.reason
        break
    if verdict != "UNKNOWN":
        reason = None
    return verdict, default_row, reason


def _terraform_index() -> dict[str, TypeRule]:
    found: dict[str, TypeRule] = {}
    for rule in load_coverage().rules:
        for name in rule.native.get("terraform", ()):
            if isinstance(name, str) and name not in found:
                found[name] = rule
    return found


def _bound(body: Body) -> Callable[[str], Value]:
    def get(item: str) -> Value:
        return _hcl_value(body, item)

    return get


def _count_zero(body: Body) -> bool:
    expr = _attr_expr(body, "count")
    if expr is None:
        return False
    value = resolve_expr(_adapt(expr))
    if not isinstance(value, Resolved) or isinstance(value.value, bool):
        return False
    return value.value == 0


def _hcl_value(body: Body, path: str) -> Value:
    found = _find(body, [part for part in path.split(".") if part])
    if found is None:
        return Absent()
    if isinstance(found, Block):
        return Unresolved("unresolved_expression")
    return resolve_expr(_adapt(found))


def _find(body: Body, parts: list[str]) -> object | None:
    if not parts:
        return None
    name, rest = parts[0], parts[1:]
    expr = _attr_expr(body, name)
    if expr is not None:
        return _into(expr, rest)
    block = _block(body, name)
    if block is None:
        return None
    if not rest:
        return block
    return _find(block.body, rest)


def _into(expr: object, parts: list[str]) -> object | None:
    if not parts:
        return expr
    if isinstance(expr, Obj):
        child = _obj(expr, parts[0])
        if child is None:
            return None
        return _into(child, parts[1:])
    if isinstance(expr, Block):
        return _find(expr.body, parts)
    return None


def _attr_expr(body: Body, name: str) -> object | None:
    found = None
    for attr in body.attrs:
        if attr.name == name:
            found = attr.expr
    return found


def _block(body: Body, name: str) -> Block | None:
    found = None
    for block in body.blocks:
        if block.type == name:
            found = block
    return found


def _obj(obj: Obj, name: str) -> object | None:
    for key, value in obj.items:
        if key == name or (isinstance(key, Lit) and key.value == name):
            return value
    return None


def _adapt(expr: object) -> object:
    if isinstance(expr, Lit):
        return expr.value
    if isinstance(expr, Ref):
        return _ref(expr)
    if isinstance(expr, HclUnresolved):
        return expr
    if isinstance(expr, HclTuple):
        return tuple(_adapt(item) for item in expr.items)
    if isinstance(expr, Obj):
        return {_key(key): _adapt(value) for key, value in expr.items}
    return expr


def _ref(expr: Ref) -> HclUnresolved:
    if expr.root == "var" and len(expr.steps) == 1 and isinstance(expr.steps[0], str):
        return HclUnresolved("variable", expr.steps[0], ())
    if expr.root in _ROOTS:
        return HclUnresolved(expr.root, expr.root, expr.steps)
    return HclUnresolved("call", expr.root, expr.steps)


def _key(key: object) -> str:
    if isinstance(key, str):
        return key
    if isinstance(key, Lit) and isinstance(key.value, str):
        return key.value
    return str(key)
