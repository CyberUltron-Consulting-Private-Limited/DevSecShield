"""Disabled certificate verification. One fact per file and pattern."""

from __future__ import annotations

import re

from aibom.cbom.posture.codec import make_fact_id
from aibom.cbom.posture.defaults import PatternSpec, load_registry
from aibom.cbom.posture.model import BasisEntry, EncryptionFact

_LINE_CAP = 20


def _hit(spec: PatternSpec, line: str) -> bool:
    if spec.matcher == "literal" and spec.pattern:
        return spec.pattern in line
    if spec.matcher != "command_flag" or spec.command is None:
        return False
    if spec.command not in line.split():
        return False
    tokens = set(line.split())
    shorts = {f"-{flag}" for flag in spec.short_flags}
    longs = {f"--{flag}" for flag in spec.long_flags}
    return bool(tokens & shorts or tokens & longs)


def _window_hits(spec: PatternSpec, tail: re.Pattern[str], lines: list[str]) -> list[int]:
    """``anchor_window``: a line holding the literal ``anchor`` whose next ``window`` lines (itself included) match
    the ``tail`` pattern (linted and compiled by the registry loader), e.g. a ``ServerCertificateValidationCallback``
    assigned ``(…) => true`` or a HostnameVerifier ``verify(…, SSLSession …)`` whose body is ``return true;``. The
    anchor line is reported."""
    if not spec.anchor:
        return []
    return [
        number for number, line in enumerate(lines, 1)
        if spec.anchor in line and any(tail.search(nxt) for nxt in lines[number - 1:number - 1 + spec.window])
    ]


def detect_verification(text: str, path: str) -> tuple[EncryptionFact, ...]:
    """Transport stays UNKNOWN. The explicit signal is recorded on the basis."""
    facts: list[EncryptionFact] = []
    lines = text.splitlines()
    registry = load_registry()
    # The loader compiles each anchor_window tail, in row order, into ``line_patterns``.
    windowed = [s.id for s in registry.patterns if s.matcher == "anchor_window"]
    tails = dict(zip(windowed, registry.line_patterns, strict=True))
    for spec in registry.patterns:
        if spec.matcher == "anchor_window":
            matched = _window_hits(spec, tails[spec.id], lines) if spec.id in tails else []
        else:
            matched = [number for number, line in enumerate(lines, 1) if _hit(spec, line)]
        if not matched:
            continue
        shown = ",".join(str(number) for number in matched[:_LINE_CAP])
        facts.append(
            EncryptionFact(
                id=make_fact_id("tls_endpoint", "code", spec.id, path, path),
                kind="tls_endpoint",
                provider="code",
                native_type=spec.id,
                address=spec.id,
                path=path,
                line=matched[0],
                format="code",
                layers={"transport": "UNKNOWN"},
                verdict="UNKNOWN",
                unknown_reason="attribute_not_modeled",
                basis=(
                    BasisEntry("signal", "TLS_VERIFICATION_DISABLED"),
                    BasisEntry("match_lines", shown),
                    BasisEntry("match_count", str(len(matched))),
                ),
            )
        )
    return tuple(facts)
