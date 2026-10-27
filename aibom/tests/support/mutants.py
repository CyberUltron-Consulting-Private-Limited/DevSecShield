"""In-process mutants for the posture engine.

Each function patches one behaviour through ``monkeypatch``. Source files are
not rewritten. M19, M20, and M54 belong to the backend package.
"""

from __future__ import annotations

import importlib
import sys
from collections.abc import Callable
from dataclasses import replace
from types import MappingProxyType
from typing import Any

Mutant = Callable[[Any], None]


def patch_symbol(monkeypatch: Any, qualname: str, replacement: Any) -> None:
    """Replace ``qualname`` and every already-imported binding of that object."""
    module_name, attr = qualname.rsplit(".", 1)
    module = importlib.import_module(module_name)
    original = getattr(module, attr)
    monkeypatch.setattr(module, attr, replacement)
    for loaded in list(sys.modules.values()):
        if loaded is None:
            continue
        try:
            current = getattr(loaded, attr)
        except Exception:
            continue
        if current is original:
            monkeypatch.setattr(loaded, attr, replacement, raising=False)


def apply(monkeypatch: Any, mutant_id: str) -> None:
    """Apply one named mutant. Unknown ids raise ``KeyError``."""
    MUTANTS[mutant_id](monkeypatch)


def _absent_as_disable(monkeypatch: Any) -> None:
    from aibom.cbom.posture.resolve import Absent, Resolved
    from aibom.cbom.posture.verdict import assess_layer

    def wrapped(case: Any) -> Any:
        sources = tuple(
            Resolved(False) if isinstance(item, Absent) else item
            for item in case.sources
        )
        if sources != case.sources:
            case = replace(case, sources=sources)
        return assess_layer(case)

    patch_symbol(monkeypatch, "aibom.cbom.posture.verdict.assess_layer", wrapped)


def m01(monkeypatch: Any) -> None:
    """Flip ``aws.kinesis.encryption_type`` to an encrypting effect."""
    from aibom.cbom.posture.defaults import load_registry

    def wrapped() -> Any:
        reg = load_registry()
        rows = tuple(
            replace(row, effect="ENCRYPTED")
            if row.id == "aws.kinesis.encryption_type"
            else row
            for row in reg.rows
        )
        by_id = {row.id: row for row in rows}
        return replace(reg, rows=rows, by_id=MappingProxyType(by_id))

    patch_symbol(monkeypatch, "aibom.cbom.posture.defaults.load_registry", wrapped)


def m02(monkeypatch: Any) -> None:
    """Map an UNKNOWN verdict to ``pass``."""
    from aibom.cbom.posture.verdict import tri_state

    def wrapped(verdict: str | None) -> str:
        if verdict in {None, "UNKNOWN"}:
            return "pass"
        return tri_state(verdict)

    patch_symbol(monkeypatch, "aibom.cbom.posture.verdict.tri_state", wrapped)


def m03(monkeypatch: Any) -> None:
    """Resolve an overridden variable to its default."""
    from aibom.cbom.posture.resolve import Resolved, Unresolved, _hcl

    def wrapped(node: Any, scope: Any) -> Any:
        result = _hcl(node, scope)
        if isinstance(result, Unresolved) and result.reason == "variable_overridden":
            decl = (scope.variables or {}).get(node.raw_span)
            if decl is not None and isinstance(decl.default, Resolved):
                return decl.default
        return result

    patch_symbol(monkeypatch, "aibom.cbom.posture.resolve._hcl", wrapped)


def m04(monkeypatch: Any) -> None:
    """Treat an absent attribute as a disabling literal."""
    _absent_as_disable(monkeypatch)


def m05(monkeypatch: Any) -> None:
    """Evaluate sources in reverse order (inline before a companion)."""
    from aibom.cbom.posture.extract_terraform import assess_sources

    def wrapped(sources: tuple[Any, ...], row: Any, **kwargs: Any) -> Any:
        return assess_sources(tuple(reversed(sources)), row, **kwargs)

    patch_symbol(
        monkeypatch, "aibom.cbom.posture.extract_terraform.assess_sources", wrapped
    )


def m06(monkeypatch: Any) -> None:
    """Ignore the permanence of a ``!`` cipher prefix."""
    from aibom.cbom.posture.ciphers import _apply_prefix

    def wrapped(
        prefix: str, matched: Any, chosen: Any, present: Any, deleted: Any
    ) -> None:
        if prefix == "!":
            _apply_prefix("-", matched, chosen, present, deleted)
            return
        _apply_prefix(prefix, matched, chosen, present, deleted)

    patch_symbol(monkeypatch, "aibom.cbom.posture.ciphers._apply_prefix", wrapped)


def m07(monkeypatch: Any) -> None:
    """Treat a ``-`` cipher prefix like ``!``."""
    from aibom.cbom.posture.ciphers import _apply_prefix

    def wrapped(
        prefix: str, matched: Any, chosen: Any, present: Any, deleted: Any
    ) -> None:
        if prefix == "-":
            _apply_prefix("!", matched, chosen, present, deleted)
            return
        _apply_prefix(prefix, matched, chosen, present, deleted)

    patch_symbol(monkeypatch, "aibom.cbom.posture.ciphers._apply_prefix", wrapped)


def m08(monkeypatch: Any) -> None:
    """Skip the final security-level filter."""
    def wrapped(*_args: Any, **_kwargs: Any) -> None:
        return None

    patch_symbol(monkeypatch, "aibom.cbom.posture.ciphers._apply_seclevel", wrapped)


def m09(monkeypatch: Any) -> None:
    """Emit facts for ``count = 0`` resources."""
    def wrapped(_body: Any) -> bool:
        return False

    patch_symbol(
        monkeypatch, "aibom.cbom.posture.extract_terraform._count_zero", wrapped
    )


def m10(monkeypatch: Any) -> None:
    """Use the last EncryptionConfiguration provider instead of the first."""
    from aibom.cbom.posture.extract_kubernetes import _first_provider

    def wrapped(raw: object) -> Any:
        if not isinstance(raw, list):
            return None
        found = None
        for item in raw:
            hit = _first_provider([item])
            if hit is not None:
                found = hit
        return found

    patch_symbol(
        monkeypatch, "aibom.cbom.posture.extract_kubernetes._first_provider", wrapped
    )


def m11(monkeypatch: Any) -> None:
    """Invert the pg_hba loopback test."""
    from aibom.cbom.posture.extract_databases import _loopback

    def wrapped(address: str | None) -> bool:
        return not _loopback(address)

    patch_symbol(monkeypatch, "aibom.cbom.posture.extract_databases._loopback", wrapped)


def m12(monkeypatch: Any) -> None:
    """Accept XML SYSTEM identifiers."""
    def wrapped(_blanked: str) -> bool:
        return False

    patch_symbol(monkeypatch, "aibom.cbom.posture.xmlsafe._unsafe_doctype", wrapped)


def m13(monkeypatch: Any) -> None:
    """Disable the YAML alias cap."""
    from aibom.cbom.posture.yamlsafe import parse_yaml

    def wrapped(*args: Any, **kwargs: Any) -> Any:
        kwargs["alias_limit"] = 10**12
        return parse_yaml(*args, **kwargs)

    patch_symbol(monkeypatch, "aibom.cbom.posture.yamlsafe.parse_yaml", wrapped)


def m14(monkeypatch: Any) -> None:
    """Disable redaction by attribute name."""
    def wrapped(_path: str) -> bool:
        return False

    patch_symbol(monkeypatch, "aibom.cbom.posture.model.is_hidden_path", wrapped)


def m15(monkeypatch: Any) -> None:
    """Omit the path from the fact id."""
    from aibom.cbom.posture.model import fact_id

    def wrapped(
        kind: str, provider: str, native_type: str, address: str, path: str
    ) -> str:
        del path
        return fact_id(kind, provider, native_type, address, "")

    patch_symbol(monkeypatch, "aibom.cbom.posture.model.fact_id", wrapped)


def m16(monkeypatch: Any) -> None:
    """Sort posture facts in reverse."""
    from aibom.cbom.posture.assemble import build_posture_block

    def wrapped(result: Any) -> dict[str, Any]:
        block = build_posture_block(result)
        block["facts"] = list(reversed(block["facts"]))
        return block

    patch_symbol(
        monkeypatch, "aibom.cbom.posture.assemble.build_posture_block", wrapped
    )


def m17(monkeypatch: Any) -> None:
    """Ignore ``scale.max_raw`` and calibrate from the flag weights."""
    from aibom.score.scorer import _calibration_cap

    def wrapped(weights: dict[str, float], scale: dict[str, Any]) -> float:
        stripped = dict(scale)
        stripped.pop("max_raw", None)
        return _calibration_cap(weights, stripped)

    patch_symbol(monkeypatch, "aibom.score.scorer._calibration_cap", wrapped)


def m18(monkeypatch: Any) -> None:
    """Keep facts without findings ahead of facts that have findings."""
    from aibom.cbom.posture.assemble import build_posture_block

    def wrapped(result: Any) -> dict[str, Any]:
        block = build_posture_block(result)
        facts = list(block["facts"])
        facts.sort(key=lambda row: len(row.get("finding_codes") or []) > 0)
        block["facts"] = facts
        return block

    patch_symbol(
        monkeypatch, "aibom.cbom.posture.assemble.build_posture_block", wrapped
    )


def m21(monkeypatch: Any) -> None:
    """Treat a literal that is neither enabling nor disabling as enabling."""
    from aibom.cbom.posture.verdict import _class_of

    def wrapped(value: object, as_absent: frozenset[object]) -> str:
        kind = _class_of(value, as_absent)
        return "ENABLE" if kind == "OTHER" else kind

    patch_symbol(monkeypatch, "aibom.cbom.posture.verdict._class_of", wrapped)


def m22(monkeypatch: Any) -> None:
    """Rank provider-default encryption above a declared setting."""
    from aibom.cbom.posture.verdict import AT_REST, resource_verdict

    def wrapped(layers: dict[str, str], *, transport_only: bool) -> str | None:
        if not transport_only:
            at_rest = [layers[name] for name in AT_REST if name in layers]
            if "ENCRYPTED_PROVIDER_DEFAULT" in at_rest:
                return "ENCRYPTED_PROVIDER_DEFAULT"
        return resource_verdict(layers, transport_only=transport_only)

    patch_symbol(monkeypatch, "aibom.cbom.posture.verdict.resource_verdict", wrapped)


def m23(monkeypatch: Any) -> None:
    """Resolve a variable with no default to Absent."""
    from aibom.cbom.posture.resolve import Absent, Unresolved, _hcl

    def wrapped(node: Any, scope: Any) -> Any:
        result = _hcl(node, scope)
        if isinstance(result, Unresolved) and result.reason == "variable_no_default":
            return Absent()
        return result

    patch_symbol(monkeypatch, "aibom.cbom.posture.resolve._hcl", wrapped)


def m24(monkeypatch: Any) -> None:
    """Turn an unpinned version into a provider default instead of UNKNOWN."""
    from aibom.cbom.posture.verdict import LayerResult, assess_layer

    def wrapped(case: Any) -> Any:
        result = assess_layer(case)
        if result.reason == "provider_version_dependent":
            return LayerResult("ENCRYPTED_PROVIDER_DEFAULT", default_row=case.row_id)
        return result

    patch_symbol(monkeypatch, "aibom.cbom.posture.verdict.assess_layer", wrapped)


def m25(monkeypatch: Any) -> None:
    """Ignore ``assessable_as_unencrypted`` and still emit NOT_ENCRYPTED."""
    from aibom.cbom.posture.verdict import LayerResult, assess_layer

    def wrapped(case: Any) -> Any:
        result = assess_layer(case)
        if (
            case.effect == "NOT_ENCRYPTED"
            and not case.assessable
            and result.verdict == "UNKNOWN"
        ):
            return LayerResult(
                "NOT_ENCRYPTED", default_row=case.row_id, caveat=case.caveat
            )
        return result

    patch_symbol(monkeypatch, "aibom.cbom.posture.verdict.assess_layer", wrapped)


def m26(monkeypatch: Any) -> None:
    """Ignore a listener redirect, so plaintext stays NOT_ENCRYPTED."""
    from aibom.cbom.posture.extract_common import listener_reader

    def wrapped(*, plaintext: bool, redirect: bool) -> Any:
        del redirect
        return listener_reader(plaintext=plaintext, redirect=False)

    patch_symbol(
        monkeypatch,
        "aibom.cbom.posture.extract_common.listener_reader",
        wrapped,
    )


def m28(monkeypatch: Any) -> None:
    """Walk the file index again on every call."""
    from aibom.cbom.posture.context import PostureSink

    original = PostureSink.index

    def wrapped(self: Any) -> Any:
        self._index = None
        return original(self)

    monkeypatch.setattr(PostureSink, "index", wrapped)


def m29(monkeypatch: Any) -> None:
    """Store a diagnostic again when the same key is added twice."""
    from aibom.cbom.posture.diagnostics import Diagnostic, DiagnosticSink

    def wrapped(
        self: DiagnosticSink, code: str, path: str, line: int = 0
    ) -> Diagnostic:
        item = Diagnostic(code, path, line)
        self.totals[code] = self.totals.get(code, 0) + 1
        self._stored.append(item)
        return item

    monkeypatch.setattr(DiagnosticSink, "add", wrapped)


def m30(monkeypatch: Any) -> None:
    """Swallow a Celery time-limit exception inside the lane guard."""
    from contextlib import contextmanager

    from aibom.cbom.posture.context import PostureSink

    @contextmanager
    def wrapped(self: Any, lane: str) -> Any:
        try:
            yield
        except Exception:
            self.failed_lanes.add(lane)
            self.diagnostics.add("internal_error", "", 0)

    monkeypatch.setattr(PostureSink, "guard", wrapped)


def m31(monkeypatch: Any) -> None:
    """Scan JSON strings with the first-draft backtracking expression."""
    import re

    from aibom.cbom.posture.jsonsafe import json_scan

    draft = re.compile(r'"(?:\\"|[^"])*"')

    def wrapped(text: str, *args: Any, **kwargs: Any) -> Any:
        list(draft.finditer(text))
        return json_scan(text, *args, **kwargs)

    patch_symbol(monkeypatch, "aibom.cbom.posture.jsonsafe.json_scan", wrapped)


def m32(monkeypatch: Any) -> None:
    """Drop the slash look-ahead in the HCL tokenizer."""
    import re

    from aibom.cbom.posture import hcl

    bad = re.compile(hcl._TOKEN_RE.pattern.replace("/(?![*/])", "/", 1))
    monkeypatch.setattr(hcl, "_TOKEN_RE", bad)
    monkeypatch.setattr(hcl, "TOKEN_PATTERNS", (bad,))
    monkeypatch.setattr(hcl, "ALL_PATTERNS", hcl.LINE_PATTERNS + (bad,))


def m36(monkeypatch: Any) -> None:
    """Raise a verdict-derived finding for an UNKNOWN verdict."""
    from aibom.cbom.posture.findings import derive_findings

    def wrapped(fact: object, scored: Any) -> tuple[str, ...]:
        codes = list(derive_findings(fact, scored))
        if getattr(fact, "verdict", None) == "UNKNOWN":
            if scored.get("at_rest"):
                codes.append("UNENCRYPTED_AT_REST")
            if scored.get("in_transit"):
                codes.append("UNENCRYPTED_IN_TRANSIT")
            if scored.get("plaintext_listener"):
                codes.append("PLAINTEXT_LISTENER")
        return tuple(sorted(set(codes)))

    patch_symbol(monkeypatch, "aibom.cbom.posture.findings.derive_findings", wrapped)


def m37(monkeypatch: Any) -> None:
    """Count a ``reject`` pg_hba record as plaintext."""
    from aibom.cbom.posture.extract_databases import _plaintext

    def wrapped(row: Any) -> bool:
        _kind, _address, method, _line = row
        if method == "reject":
            return True
        return _plaintext(row)

    patch_symbol(
        monkeypatch, "aibom.cbom.posture.extract_databases._plaintext", wrapped
    )


def m44(monkeypatch: Any) -> None:
    """Raise a finding-default code when the governing attribute is unresolved."""
    from aibom.cbom.posture.findings import derive_findings

    def wrapped(fact: object, scored: Any) -> tuple[str, ...]:
        opened = dict(scored)
        for key in list(opened):
            if str(key).endswith(":unresolved"):
                opened[key] = False
        return derive_findings(fact, opened)

    patch_symbol(monkeypatch, "aibom.cbom.posture.findings.derive_findings", wrapped)


def _missing(seam: str) -> Mutant:
    def apply_missing(monkeypatch: Any) -> None:
        del monkeypatch
        raise LookupError(seam)

    return apply_missing


MUTANTS: dict[str, Mutant] = {
    "M01": m01,
    "M02": m02,
    "M03": m03,
    "M04": m04,
    "M05": m05,
    "M06": m06,
    "M07": m07,
    "M08": m08,
    "M09": m09,
    "M10": m10,
    "M11": m11,
    "M12": m12,
    "M13": m13,
    "M14": m14,
    "M15": m15,
    "M16": m16,
    "M17": m17,
    "M18": m18,
    "M21": m21,
    "M22": m22,
    "M23": m23,
    "M24": m24,
    "M25": m25,
    "M26": m26,
    "M27": _missing("governor validates every fitting build"),
    "M28": m28,
    "M29": m29,
    "M30": m30,
    "M31": m31,
    "M32": m32,
    "M33": _missing("blank_spans dead-opener set"),
    "M34": _missing("governor pre-prune"),
    "M35": _missing("phase-1 record keeps the parse tree"),
    "M36": m36,
    "M37": m37,
    "M38": _missing("GCP condition block"),
    "M39": _missing("YAML drain of a capped document"),
    "M40": _missing("YAML line-carrying constructors"),
    "M41": _missing("read_included budget"),
    "M42": _missing("CycloneDX family map"),
    "M43": _missing("refs redaction lists"),
    "M44": m44,
    "M45": _missing("import field clipping"),
    "M46": _missing("Apache unprefixed token"),
    "M47": _missing("included file analysed as an entry"),
    "M48": _missing("absent pg_hba.conf"),
    "M49": _missing("loopback-only pg_hba.conf"),
    "M50": _missing("coverage consulted paths"),
    "M51": _missing("override value"),
    "M52": _missing("policy document condition blocks"),
    "M53": _missing("crypto:listen candidates"),
}
