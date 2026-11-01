"""Where each inventoried asset occurs in its file: line numbers only, plus the language of the file.

The detectors keep one row per (asset, file) and most of them drop the line. This late pass (after every
emitter) re-reads each file once, re-runs the same detector to find the lines that produced the asset, and falls
back to a code-only token match. It writes ``crypto:line`` (first occurrence), ``crypto:occurrences`` (up to
``MAX_OCCURRENCES`` line numbers, comma separated), ``crypto:occurrenceCount`` and ``crypto:language``.
``discovery:source`` stays the bare path, so bom-refs and team-rollup identities do not change.

No source text is stored here: code windows are read later by the host adapter (and redacted there), never put
into the CycloneDX document. Files are only read when they resolve inside the scan root (no symlink escape) and
look like text.
"""

from __future__ import annotations

import re
from pathlib import Path

from aibom.cbom.detect import detect_crypto, strip_noncode
from aibom.cbom.rules import (
    ALGORITHM_NORMALIZE,
    CRYPTO_IMPORT_MODULES,
    CRYPTO_IMPORT_MODULES_BY_LANG,
    DETECTOR_LANGUAGES,
    LANGUAGE_EXTENSIONS,
    source_language,
)

MAX_OCCURRENCES = 25
MAX_BYTES = 2_000_000

# Language labels for files the algorithm detectors do not parse (manifests, IaC, keys) - display only.
_EXTRA_LANG = {
    ".tf": "terraform", ".hcl": "terraform", ".yaml": "yaml", ".yml": "yaml", ".json": "json", ".xml": "xml",
    ".toml": "toml", ".gradle": "groovy", ".csproj": "xml", ".config": "xml", ".pem": "pem", ".crt": "pem",
    ".cer": "pem", ".key": "pem", ".conf": "config", ".cfg": "config", ".ini": "config", ".properties": "config",
    ".lock": "lockfile", ".sum": "lockfile", ".mod": "go-mod", ".txt": "text", ".sh": "shell", ".tsx": "typescript",
    ".ts": "typescript", ".swift": "swift", ".m": "objective-c", ".vue": "javascript",
}
_LOCK_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "cargo.lock", "go.sum", "poetry.lock",
               "pipfile.lock", "composer.lock", "gemfile.lock", "packages.lock.json", "gradle.lockfile"}
_COMMENT = re.compile(r"^\s*(#|//|\*|/\*|--|;|<!--)")
_IMPORT = re.compile(r"^\s*(?:import|from|require|use|using|#include|require_once)\b|\brequire\(", re.I)


def language_of(rel: str) -> str | None:
    name = rel.rsplit("/", 1)[-1].lower()
    if name in _LOCK_NAMES:
        return "lockfile"
    if name == "go.mod":
        return "go-mod"
    if name.startswith("requirements") and name.endswith(".txt"):
        return "pip-requirements"
    if name == "dockerfile":
        return "dockerfile"
    suffix = Path(name).suffix
    if suffix in (".ts", ".tsx"):
        return "typescript"
    return LANGUAGE_EXTENSIONS.get(suffix) or _EXTRA_LANG.get(suffix)


def safe_file(root: Path, rel: str) -> Path | None:
    """The file ``rel`` under ``root`` if it is a regular file that resolves inside the root (no absolute paths,
    no ``..``, no symlink pointing outside) and is not too large."""
    if not rel or rel.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", rel) or "\x00" in rel:
        return None
    parts = Path(rel).parts
    if any(p == ".." for p in parts):
        return None
    try:
        base = root.resolve()
        path = (root / rel)
        real = path.resolve()
        real.relative_to(base)
        if not real.is_file() or real.stat().st_size > MAX_BYTES:
            return None
    except (OSError, ValueError, RuntimeError):
        return None
    return real


def read_text(path: Path) -> str | None:
    """Decoded text, or None for binary files. Line endings are kept exactly (no universal newlines)."""
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return raw.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if b"\x00" in raw[:8192]:
        return None
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    return raw.decode("utf-8", errors="replace")


def split_lines(text: str) -> list[str]:
    """One splitter for every line number the CBOM reports: ``\\n`` only (``\\r`` stays on the line)."""
    return text.split("\n")


def _alnum(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _code_lines(text: str) -> list[str]:
    """Lines with docstrings/block comments blanked (line count preserved) and comment-only lines emptied."""
    lines = split_lines(strip_noncode(text))
    return ["" if _COMMENT.match(ln) else ln for ln in lines]


class _FileIndex:
    """Per-file cache: code lines and detector hits by display name."""

    def __init__(self, text: str, lang: str | None):
        from aibom.cbom.scanners.algorithm_scan import _display_name, _refine_key

        self.lines = _code_lines(text)
        self.raw_count = len(split_lines(text))
        self.by_name: dict[str, list[int]] = {}
        self.libraries: set[str] = set()
        if lang:  # crypto libraries this file imports (the same module table the library scanner uses)
            modules = CRYPTO_IMPORT_MODULES_BY_LANG.get(lang, CRYPTO_IMPORT_MODULES)
            for line in self.lines:
                if not _IMPORT.search(line):
                    continue
                low = line.lower()
                for module, label in modules.items():
                    if re.search(rf"(?<![a-z0-9_./]){re.escape(module)}(?![a-z0-9_])", low):
                        self.libraries.add(label)
        if lang in DETECTOR_LANGUAGES:
            for det in detect_crypto(text, lang):
                refined = _refine_key(det.key, det.key_size)
                name = _display_name(refined, det.key_size, det.mode, det.parameter, det.variant)
                self.by_name.setdefault(name.lower(), []).append(det.line_no)
                base = str(ALGORITHM_NORMALIZE.get(refined, refined)).lower()
                if base != name.lower():
                    self.by_name.setdefault(base, []).append(det.line_no)

    def token_lines(self, tokens: list[str]) -> list[int]:
        out: list[int] = []
        for tok in tokens:
            t = _alnum(tok)
            if len(t) < 3:
                continue
            for i, line in enumerate(self.lines, start=1):
                if line and t in _alnum(line):
                    out.append(i)
            if out:
                break
        return out


def _tokens_for(name: str, props: dict[str, str]) -> list[str]:
    """Search tokens, most specific first, for a component whose detector kept no line."""
    asset_type = props.get("crypto:assetType")
    if props.get("crypto:role") == "library":
        pkg = re.sub(r"\s*\(.*?\)\s*$", "", name.split("@", 1)[0])  # "hashlib (stdlib)" -> "hashlib"
        return [pkg, pkg.rsplit(":", 1)[-1], pkg.rsplit("/", 1)[-1], pkg.split(" ", 1)[0]]
    if props.get("crypto:customImplementation") == "true":  # recognised by its constants (S-box, round consts)
        return ["0x63, 0x7c, 0x77", "0x428a2f98", "0xd76aa478", "sbox", "s_box"]
    if asset_type in ("certificate", "related-crypto-material") and props.get("crypto:materialKind") not in (
            "key", "iv", "nonce", "salt", "seed"):
        return ["-----BEGIN", name]
    base = re.split(r"[\s(]", name, maxsplit=1)[0]
    first = re.split(r"[-_/]", base, maxsplit=1)[0]
    return [name, base, first]


def annotate(root: Path, components: list) -> dict[str, int]:
    """Write line properties onto ``components`` (in place). Returns counters for the scan summary log."""
    root = Path(root)
    cache: dict[str, _FileIndex | None] = {}
    stats = {"located": 0, "unlocated": 0, "unreadable": 0}
    for comp in components:
        if comp.kind not in ("crypto_asset", "framework"):
            continue
        props = dict(comp.properties or {})
        if props.get("crypto:role") not in (None, "library") and comp.kind == "framework":
            continue
        rel = props.get("discovery:source") or props.get("crypto:source") or ""
        known: list[int] = []
        m = re.match(r"^(?P<path>.+?):(?P<line>\d+)$", rel)
        if m:  # some sources already carry path:line (key specs, Kubernetes)
            rel, known = m.group("path"), [int(m.group("line"))]
        if props.get("crypto:line", "").isdigit():
            known = [int(props["crypto:line"])]
        if not rel:
            continue
        lang = language_of(rel)
        if lang:
            props["crypto:language"] = lang
        lines = known
        if rel not in cache and comp.kind == "crypto_asset":
            path = safe_file(root, rel)
            text = read_text(path) if path else None
            cache[rel] = _FileIndex(text, source_language(path)) if text else None
        if not lines:
            if rel not in cache:
                path = safe_file(root, rel)
                text = read_text(path) if path else None
                cache[rel] = _FileIndex(text, source_language(path)) if text else None
            idx = cache[rel]
            if idx is None:
                stats["unreadable"] += 1
                comp.properties = props
                continue
            lines = idx.by_name.get(comp.name.lower(), [])
            if not lines and props.get("crypto:assetType") == "algorithm":
                info_name = comp.name.split("-", 1)[0].lower()
                lines = idx.by_name.get(info_name, [])
            if not lines:
                lines = idx.token_lines(_tokens_for(comp.name, props))
        idx_libs = cache.get(rel).libraries if cache.get(rel) is not None and comp.kind == "crypto_asset" else set()
        if idx_libs:
            props["crypto:libraries"] = ",".join(sorted(idx_libs))
        lines = sorted(set(lines))
        if lines:
            props["crypto:line"] = str(lines[0])
            props["crypto:occurrences"] = ",".join(str(n) for n in lines[:MAX_OCCURRENCES])
            props["crypto:occurrenceCount"] = str(len(lines))
            stats["located"] += 1
        else:
            stats["unlocated"] += 1
        comp.properties = props
    return stats


__all__ = ["annotate", "language_of", "safe_file", "read_text", "split_lines", "MAX_OCCURRENCES"]
