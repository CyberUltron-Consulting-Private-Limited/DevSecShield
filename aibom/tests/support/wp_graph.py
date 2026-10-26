"""Import-edge checker for the posture work-package graph.

``OWNER`` maps a path relative to ``aibom/src/aibom/cbom/`` to a work-package
id. ``EDGES`` is the package order from design section 13.3: an edge
``A -> B`` means A is finished before B, so B may import A. ``PAIRS`` may
import each other. A module that does not exist yet is skipped.
"""

from __future__ import annotations

import ast
from pathlib import Path

OWNER: dict[str, str] = {
    "posture/__init__.py": "WP1",
    "posture/limits.py": "WP1",
    "posture/diagnostics.py": "WP1",
    "posture/safeio.py": "WP1",
    "posture/context.py": "WP1",
    "posture/model.py": "WP1",
    "posture/codec.py": "WP1",
    "posture/hcl.py": "WP2",
    "posture/yamlsafe.py": "WP2",
    "posture/xmlsafe.py": "WP2",
    "posture/jsonsafe.py": "WP2",
    "posture/directives.py": "WP2",
    "posture/sqllabels.py": "WP2",
    "posture/textscan.py": "WP2",
    "posture/tomlsafe.py": "WP2",
    "posture/codeowners.py": "WP2",
    "posture/globmatch.py": "WP2",
    "posture/defaults.py": "WP3",
    "posture/coverage.py": "WP3",
    "posture/resolve.py": "WP4",
    "posture/verdict.py": "WP4",
    "posture/records.py": "WP4",
    "posture/findings.py": "WP4",
    "posture/extract_common.py": "WP4",
    "data/provider_defaults_aws.json": "WP5a",
    "data/provider_defaults_azure.json": "WP5b",
    "data/provider_defaults_gcp.json": "WP5b",
    "data/provider_defaults_k8s.json": "WP5b",
    "data/provider_defaults_software.json": "WP5b",
    "data/coverage_table.json": "WP5c",
    "data/tls_policies.json": "WP5d",
    "data/cipher_suites.json": "WP5d",
    "data/named_groups.json": "WP5d",
    "data/key_specs.json": "WP5e",
    "data/datastore_images.json": "WP5e",
    "data/verification_patterns.json": "WP5e",
    "data/named_vulnerabilities.json": "WP5e",
    "data/tls_import_formats.json": "WP5e",
    "data/key_policy_conditions.json": "WP5e",
    "posture/extract_terraform.py": "WP6a",
    "posture/extract_cloudformation.py": "WP6a",
    "posture/extract_kubernetes.py": "WP6b",
    "posture/extract_compose.py": "WP6b",
    "posture/extract_servers.py": "WP6c",
    "posture/dhparam.py": "WP6c",
    "posture/extract_databases.py": "WP6d",
    "posture/verification.py": "WP6e",
    "posture/business.py": "WP6f",
    "posture/tls_import.py": "WP6g",
    "posture/tls_import_testssl.py": "WP6g",
    "posture/tls_import_sslyze.py": "WP6g",
    "posture/tls_import_nmap.py": "WP6g",
    "posture/ciphers.py": "WP6h",
    "posture/assemble.py": "WP7",
    "posture/bomcheck.py": "WP7",
    "scanners/posture_iac_scan.py": "WP7",
    "scanners/posture_server_scan.py": "WP7",
    "scanners/posture_database_scan.py": "WP7",
    "scanners/posture_tls_import_scan.py": "WP7",
    "scanners/posture_verification_scan.py": "WP7",
    "scanners/posture_linkage_scan.py": "WP7",
    "scanners/posture_findings_scan.py": "WP7",
}

EDGES: tuple[tuple[str, str], ...] = (
    ("WP0", "WP1"),
    ("WP1", "WP2"),
    ("WP1", "WP3"),
    ("WP2", "WP4"),
    ("WP3", "WP4"),
    ("WP4", "WP5a"),
    ("WP4", "WP5b"),
    ("WP4", "WP5c"),
    ("WP4", "WP5d"),
    ("WP4", "WP5e"),
    ("WP5a", "WP5f"),
    ("WP5b", "WP5f"),
    ("WP5c", "WP5f"),
    ("WP5d", "WP5f"),
    ("WP5e", "WP5f"),
    ("WP5a", "WP8a"),
    ("WP5b", "WP8a"),
    ("WP5c", "WP8a"),
    ("WP5d", "WP8a"),
    ("WP5e", "WP8a"),
    ("WP5a", "WP8b"),
    ("WP5b", "WP8b"),
    ("WP5c", "WP8b"),
    ("WP5d", "WP8b"),
    ("WP5e", "WP8b"),
    ("WP5a", "WP8c"),
    ("WP5b", "WP8c"),
    ("WP5c", "WP8c"),
    ("WP5d", "WP8c"),
    ("WP5e", "WP8c"),
    ("WP5a", "WP8d"),
    ("WP5b", "WP8d"),
    ("WP5c", "WP8d"),
    ("WP5d", "WP8d"),
    ("WP5e", "WP8d"),
    ("WP5a", "WP8e"),
    ("WP5b", "WP8e"),
    ("WP5c", "WP8e"),
    ("WP5d", "WP8e"),
    ("WP5e", "WP8e"),
    ("WP5d", "WP6h"),
    ("WP5d", "WP6g"),
    ("WP5e", "WP6g"),
    ("WP6h", "WP6g"),
    ("WP8e", "WP6g"),
    ("WP5a", "WP6a"),
    ("WP5b", "WP6a"),
    ("WP5c", "WP6a"),
    ("WP5d", "WP6a"),
    ("WP5e", "WP6a"),
    ("WP8a", "WP6a"),
    ("WP8b", "WP6a"),
    ("WP5b", "WP6b"),
    ("WP5c", "WP6b"),
    ("WP5d", "WP6b"),
    ("WP5e", "WP6b"),
    ("WP6h", "WP6b"),
    ("WP8c", "WP6b"),
    ("WP5b", "WP6c"),
    ("WP5d", "WP6c"),
    ("WP6h", "WP6c"),
    ("WP8d", "WP6c"),
    ("WP5b", "WP6d"),
    ("WP6h", "WP6d"),
    ("WP8d", "WP6d"),
    ("WP5e", "WP6e"),
    ("WP8d", "WP6e"),
    ("WP8e", "WP6f"),
    ("WP6a", "WP7"),
    ("WP6b", "WP7"),
    ("WP6c", "WP7"),
    ("WP6d", "WP7"),
    ("WP6e", "WP7"),
    ("WP6f", "WP7"),
    ("WP6g", "WP7"),
    ("WP6h", "WP7"),
    ("WP5f", "WP7"),
    ("WP7", "WP7b"),
    ("WP7b", "WP9"),
    ("WP7b", "WP10"),
    ("WP7b", "WP15"),
    ("WP10", "WP10b"),
    ("WP10b", "WP11a"),
    ("WP10b", "WP11b"),
    ("WP10b", "WP11c"),
    ("WP11a", "WP12"),
    ("WP11b", "WP12"),
    ("WP11c", "WP12"),
    ("WP11a", "WP13"),
    ("WP11b", "WP13"),
    ("WP11c", "WP13"),
    ("WP12", "WP14"),
    ("WP13", "WP14"),
    ("WP9", "WP14"),
    ("WP14", "WP16"),
    ("WP15", "WP16"),
)

PAIRS: frozenset[frozenset[str]] = frozenset(
    {frozenset({"WP7", "WP7b"}), frozenset({"WP12", "WP13"})}
)

PACKAGES: frozenset[str] = frozenset(
    {
        "WP0",
        "WP1",
        "WP2",
        "WP3",
        "WP4",
        "WP5a",
        "WP5b",
        "WP5c",
        "WP5d",
        "WP5e",
        "WP5f",
        "WP6a",
        "WP6b",
        "WP6c",
        "WP6d",
        "WP6e",
        "WP6f",
        "WP6g",
        "WP6h",
        "WP7",
        "WP7b",
        "WP8a",
        "WP8b",
        "WP8c",
        "WP8d",
        "WP8e",
        "WP9",
        "WP10",
        "WP10b",
        "WP11a",
        "WP11b",
        "WP11c",
        "WP12",
        "WP13",
        "WP14",
        "WP15",
        "WP16",
    }
)

_PREFIXES = ("aibom.cbom.posture", "aibom.cbom.scanners")


def ancestors(wp: str) -> set[str]:
    """Packages that precede ``wp``, directly or through other packages."""
    incoming: dict[str, set[str]] = {}
    for src, dst in EDGES:
        incoming.setdefault(dst, set()).add(src)
    seen: set[str] = set()
    stack = list(incoming.get(wp, ()))
    while stack:
        item = stack.pop()
        if item in seen:
            continue
        seen.add(item)
        stack.extend(incoming.get(item, ()))
    return seen


def _paired(left: str, right: str) -> bool:
    return frozenset({left, right}) in PAIRS


def _rel_of(module: str) -> str | None:
    if module.startswith("aibom.cbom.posture."):
        name = module.removeprefix("aibom.cbom.posture.")
        if "." in name:
            return None
        return f"posture/{name}.py"
    if module.startswith("aibom.cbom.scanners.posture_"):
        name = module.removeprefix("aibom.cbom.scanners.")
        if "." in name:
            return None
        return f"scanners/{name}.py"
    return None


def _package_of(path: Path, root: Path) -> str:
    rel = path.relative_to(root).as_posix()
    if rel.startswith("posture/"):
        return "aibom.cbom.posture"
    if rel.startswith("scanners/"):
        return "aibom.cbom.scanners"
    return "aibom.cbom"


def _exists(root: Path, module: str) -> bool:
    rel = _rel_of(module)
    return rel is not None and (root / rel).is_file()


def project_imports(path: Path, root: Path | None = None) -> list[str]:
    """Relative paths of posture modules imported by ``path``."""
    tree_root = root or path.parents[1]
    if path.parent.name == "scanners":
        tree_root = root or path.parents[1]
    text = path.read_text(encoding="utf-8")
    parsed = ast.parse(text)
    found: list[str] = []

    def add(module: str | None) -> None:
        if module is None:
            return
        rel = _rel_of(module)
        if rel is not None:
            found.append(rel)

    for node in ast.walk(parsed):
        if isinstance(node, ast.Import):
            for alias in node.names:
                add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            base = node.module
            if node.level:
                pkg_parts = _package_of(path, tree_root).split(".")
                climb = node.level - 1
                if climb:
                    pkg_parts = pkg_parts[:-climb]
                extra = base.split(".") if base else []
                base = ".".join(pkg_parts + extra)
            if base is None:
                continue
            if not base.startswith(_PREFIXES):
                continue
            names = [alias.name for alias in node.names]
            added_sub = False
            for name in names:
                candidate = f"{base}.{name}"
                if _exists(tree_root, candidate):
                    add(candidate)
                    added_sub = True
            if not added_sub:
                add(base)
    return found


def _cycles(root: Path) -> list[str]:
    present = [
        rel
        for rel in OWNER
        if rel.endswith(".py") and (root / rel).is_file()
    ]
    graph = {
        rel: [item for item in project_imports(root / rel, root) if item in present]
        for rel in present
    }
    lines: list[str] = []
    visiting: list[str] = []
    seen: set[str] = set()

    def walk(node: str) -> None:
        if node in visiting:
            cycle = visiting[visiting.index(node) :] + [node]
            lines.append("cycle " + " -> ".join(cycle))
            return
        if node in seen:
            return
        visiting.append(node)
        for nxt in graph.get(node, ()):
            if nxt in graph:
                walk(nxt)
        visiting.pop()
        seen.add(node)

    for node in sorted(graph):
        walk(node)
    return lines


def violations(root: Path) -> list[str]:
    """Forward imports, unowned modules, and import cycles under ``root``."""
    lines: list[str] = []
    for file_path in sorted(root.rglob("*.py")):
        rel = file_path.relative_to(root).as_posix()
        if not (rel.startswith("posture/") or rel.startswith("scanners/posture_")):
            continue
        owner = OWNER.get(rel)
        if owner is None:
            lines.append(f"{rel} (none) has no owner")
            continue
        allowed = ancestors(owner) | {owner}
        for target in project_imports(file_path, root):
            target_owner = OWNER.get(target)
            if target_owner is None:
                lines.append(f"{rel} ({owner}) imports {target} (none)")
                continue
            if target_owner in allowed or _paired(owner, target_owner):
                continue
            lines.append(f"{rel} ({owner}) imports {target} ({target_owner})")
    lines.extend(_cycles(root))
    return lines


def edges_are_acyclic() -> bool:
    seen: set[str] = set()
    stack: set[str] = set()
    outgoing: dict[str, list[str]] = {}
    for src, dst in EDGES:
        outgoing.setdefault(src, []).append(dst)

    def walk(node: str) -> bool:
        if node in stack:
            return False
        if node in seen:
            return True
        stack.add(node)
        for nxt in outgoing.get(node, ()):
            if not walk(nxt):
                return False
        stack.remove(node)
        seen.add(node)
        return True

    return all(walk(node) for node in outgoing)
