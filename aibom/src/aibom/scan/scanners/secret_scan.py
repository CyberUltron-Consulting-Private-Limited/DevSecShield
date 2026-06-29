"""Scanner: hardcoded secrets (API keys / tokens) in source.

Detects common credential patterns — provider API keys (``sk-``, ``sk-ant-``,
``hf_``), AWS access-key IDs (``AKIA…``), and generic high-entropy
``NAME = "value"`` assignments where NAME hints at a credential — and emits one
:class:`SecretComponent` per UNIQUE secret value plus a ``HARDCODED_SECRET``
flag (SARIF ``error`` level = High impact downstream).

Dedup is by the secret VALUE, so a key matched by several patterns (e.g. an
``sk-…`` literal assigned to ``OPENAI_API_KEY``, which both the explicit and the
generic rule hit) is reported exactly once.

Lanes (``aibom/contract/lanes``): scanners EMIT components + flags, never score.
"""

from __future__ import annotations

import math
import re
from pathlib import Path

from aibom.model.component import SecretComponent
from aibom.scan.registry import ScanContext, Scanner, register

_SRC_EXT = frozenset(
    {
        ".py",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".env",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".txt",
        ".sh",
        ".bash",
        ".cfg",
        ".ini",
        ".go",
        ".rb",
        ".java",
    }
)
_IGNORE_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        "dist",
        "build",
        ".next",
        ".mypy_cache",
        ".pytest_cache",
    }
)
_MAX_BYTES = 1_500_000

# Explicit provider-credential patterns -> (kind label, compiled regex).
_PROVIDER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("anthropic_api_key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{16,}")),
    ("openai_api_key", re.compile(r"sk-(?!ant-)[A-Za-z0-9_\-]{12,}")),
    ("huggingface_token", re.compile(r"hf_[A-Za-z0-9]{16,}")),
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}")),
)
# Generic: NAME = "value" / NAME: "value" where NAME hints at a credential.
_GENERIC_ASSIGN = re.compile(
    r"""(?P<name>[A-Za-z][A-Za-z0-9_]*"""
    r"""(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|APIKEY)[A-Za-z0-9_]*)"""
    r"""\s*[:=]\s*['"](?P<val>[^'"\s]{20,})['"]""",
    re.IGNORECASE,
)
# Values that are obviously NOT secrets (env indirection / templating).
_PLACEHOLDER = re.compile(
    r"\$\{|os\.environ|getenv|<[^>]+>|process\.env|change[_-]?me", re.IGNORECASE
)
# A generic-rule VALUE that is itself a NAME / path is a *reference to where a
# secret lives* (an env-var name to read, a file path, a label key), NOT a literal
# secret. Real credentials are random high-entropy tokens, not readable names.
# Removes the dominant FP class on real repos (e.g. chroma's `apiKeyEnvVar =
# "CHROMA_OPENAI_API_KEY"`, label `kubernetes.io/hostname`, path `/x/y.htpasswd`).
# A real random token (`sk-…`, hex, mixed-case base64) does not match any branch.
_NOT_SECRET_VALUE = re.compile(
    r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+"   # SCREAMING_SNAKE env-var name (CHROMA_API_KEY)
    r"|[a-z][a-z0-9]*(?:_[a-z0-9]+)+"  # snake_case identifier (custom_field)
    r"|[~./]?[\w.\-]+(?:/[\w.\-]+)+"   # file path / label key (/x/y.htpasswd)
)

# Test fixtures carry mock / sequential dummy keys (sk-1234567890abcdef) that are
# not production secret leaks; a deployable-artifact scan skips them by convention.
_TEST_DIRS = frozenset(
    {"test", "tests", "__tests__", "__mocks__", "spec", "specs", "testdata"}
)
_TEST_FILE_RE = re.compile(
    r"(?:^test_|_test\.|\.test\.|\.spec\.|_spec\.)", re.IGNORECASE
)


def _is_test_file(rel: Path) -> bool:
    """True if ``rel`` (path RELATIVE to the scan root) is a test file/dir — so a
    fixture whose repo lives under an outer ``tests/`` dir is unaffected (its own
    root has no test segment)."""
    if _TEST_FILE_RE.search(rel.name):
        return True
    return any(part in _TEST_DIRS for part in rel.parts[:-1])


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _source_files(root: Path):
    for p in sorted(root.rglob("*")):
        if any(part in _IGNORE_DIRS for part in p.parts):
            continue
        if not p.is_file() or p.suffix.lower() not in _SRC_EXT:
            continue
        if _is_test_file(p.relative_to(root)):
            continue
        try:
            if p.stat().st_size > _MAX_BYTES:
                continue
        except OSError:
            continue
        yield p


def _mask(value: str) -> str:
    return value[:6] + "…" + f"({len(value)} chars)" if len(value) > 8 else "***"


def _detect(text: str) -> list[tuple[str, str]]:
    """Return (kind, value) hits in one file's text (pre-dedup)."""
    hits: list[tuple[str, str]] = []
    for kind, pat in _PROVIDER_PATTERNS:
        for m in pat.findall(text):
            hits.append((kind, m))
    for m in _GENERIC_ASSIGN.finditer(text):
        val = m.group("val")
        # reject env-indirection placeholders AND values that are themselves a
        # NAME / path (env-var name, identifier, file path) rather than a literal.
        if _PLACEHOLDER.search(val) or _NOT_SECRET_VALUE.fullmatch(val):
            continue
        # generic rule needs real entropy so config strings ("Apache-2.0") don't trip it
        if _shannon_entropy(val) >= 3.0:
            hits.append(("generic_credential", val))
    return hits


@register
class SecretScanner(Scanner):
    name = "secret"
    order = 30
    level = 1

    def matches(self, root: Path) -> bool:
        return True

    def scan(self, ctx: ScanContext) -> None:
        # Dedup by secret VALUE so a key matched by multiple rules is one finding.
        seen: dict[str, dict] = {}
        for path in _source_files(ctx.root):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = path.relative_to(ctx.root).as_posix()
            for kind, value in _detect(text):
                if value not in seen:
                    seen[value] = {"kind": kind, "location": rel}

        for value, info in sorted(seen.items()):
            digest = abs(hash(value)) % (10**10)
            bom_ref = f"secret-{digest}"
            comp = SecretComponent(
                bom_ref=bom_ref,
                name=info["kind"],
                properties={
                    "secret:kind": info["kind"],
                    "secret:masked": _mask(value),
                    "discovery:source": info["location"],
                },
            )
            ctx.add_component(comp)
            ctx.add_flag(
                "HARDCODED_SECRET",
                bom_ref,
                severity="error",  # SARIF error == High impact
                message=(
                    f"Hardcoded {info['kind']} detected in {info['location']} "
                    f"({_mask(value)}); move it to a secret manager / env var."
                ),
            )


__all__ = ["SecretScanner"]
