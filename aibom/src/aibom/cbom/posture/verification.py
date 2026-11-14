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
        if matched:
            facts.append(_fact(spec.id, path, matched))
    if path.endswith(".java"):
        # CB-27: an X509TrustManager whose checkServerTrusted does nothing accepts
        # every server certificate. A line pattern cannot see an empty method body
        # (the comment inside it, the brace on the next line), so the Java reader
        # decides it (aibom.cbom.java_flow.noop_trust_checks).
        from aibom.cbom.java_flow import noop_trust_checks

        matched = noop_trust_checks(text)
        if matched:
            facts.append(_fact(JAVA_NOOP_TRUST_MANAGER, path, matched))
    return tuple(facts)


JAVA_NOOP_TRUST_MANAGER = "java.trust_manager_noop"


def _fact(pattern_id: str, path: str, matched: list[int]) -> EncryptionFact:
    shown = ",".join(str(number) for number in matched[:_LINE_CAP])
    return EncryptionFact(
        id=make_fact_id("tls_endpoint", "code", pattern_id, path, path),
        kind="tls_endpoint",
        provider="code",
        native_type=pattern_id,
        address=pattern_id,
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
