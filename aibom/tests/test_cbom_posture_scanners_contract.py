"""Scanner registration contract for the seven posture scanners."""

from __future__ import annotations

import ast
import importlib
import inspect
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "aibom" / "cbom" / "scanners"
REPO = ROOT.parent
NAMES = (
    "posture_iac",
    "posture_server",
    "posture_database",
    "posture_tls_import",
    "posture_verification",
    "posture_linkage",
    "posture_findings",
)
ROLES = {
    "posture_iac": ("extractor", 31),
    "posture_server": ("extractor", 32),
    "posture_database": ("extractor", 33),
    "posture_tls_import": ("extractor", 34),
    "posture_verification": ("extractor", 36),
    "posture_linkage": ("enricher", 38),
    "posture_findings": ("flagger", 45),
}
_NAME = re.compile(r'^\s+name = "([a-z_]+)"\s*$', re.M)
_ORDER = re.compile(r"^\s+order = (\d+)\b", re.M)
_SKIP = {".venv", "node_modules", ".worktrees", "__pycache__", ".git"}


def _decorator_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _literal_map(node: ast.ClassDef) -> dict[str, object]:
    found: dict[str, object] = {}
    for item in node.body:
        if not isinstance(item, ast.AnnAssign) and not isinstance(item, ast.Assign):
            continue
        targets = [item.target] if isinstance(item, ast.AnnAssign) else item.targets
        if len(targets) != 1 or not isinstance(targets[0], ast.Name):
            continue
        value = item.value
        if isinstance(value, ast.Constant):
            found[targets[0].id] = value.value
    return found


def registration_problems(source: str) -> list[str]:
    """Problems in one scanner module. An empty list means the module is valid."""
    problems: list[str] = []
    if len(_NAME.findall(source)) != 1:
        problems.append("name line")
    if len(_ORDER.findall(source)) != 1:
        problems.append("order line")
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [*problems, f"syntax {exc}"]
    classes = [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and any(_decorator_name(dec) == "cbom_register" for dec in node.decorator_list)
    ]
    if len(classes) != 1:
        problems.append(f"decorated classes {len(classes)}")
        return problems
    fields = _literal_map(classes[0])
    for key in ("name", "order", "level"):
        if key not in fields:
            problems.append(f"missing {key}")
    return problems


def _scan_import_problems(tree: ast.AST) -> list[str]:
    problems: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name
                if name == "aibom.scan" or (
                    name.startswith("aibom.scan.") and name != "aibom.scan.registry"
                ):
                    problems.append(name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            module = node.module
            if module == "aibom.scan":
                bad = [alias.name for alias in node.names if alias.name != "registry"]
                problems.extend(f"aibom.scan.{item}" for item in bad)
            elif module.startswith("aibom.scan.") and module != "aibom.scan.registry":
                problems.append(module)
    return problems


def _posture_import(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("aibom.cbom.posture") or (
                    alias.name.startswith("aibom.cbom.scanners.posture_")
                ):
                    return True
        elif isinstance(node, ast.ImportFrom) and node.module:
            module = node.module
            if module.startswith("aibom.cbom.posture"):
                return True
            names = [alias.name for alias in node.names]
            if module == "aibom.cbom" and "posture" in names:
                return True
            if module == "aibom.cbom.scanners" and any(
                alias.name.startswith("posture_") for alias in node.names
            ):
                return True
    return False


def test_registration() -> None:
    init = (SRC / "__init__.py").read_text(encoding="utf-8")
    imported = re.findall(r"from aibom\.cbom\.scanners import \((.*?)\)", init, re.S)
    assert len(imported) == 1
    modules = re.findall(r"\b([a-z_]+_scan)\b", imported[0])
    exported = re.findall(r'"([a-z_]+_scan)"', init.split("__all__", 1)[1])
    assert modules == sorted(modules)
    assert modules == exported
    assert len(modules) == 20  # 19 detectors (incl. the images / binaries / firmware lane) + the occurrence pass
    for name in NAMES:
        source = (SRC / f"{name}_scan.py").read_text(encoding="utf-8")
        assert registration_problems(source) == []
        assert f"{name}_scan" in modules
    from aibom.cbom.registry import ordered_cbom_scanners

    importlib.import_module("aibom.cbom.scanners")
    found = [scanner.name for scanner in ordered_cbom_scanners()]
    assert len(found) == 20
    assert set(NAMES) <= set(found)


def test_registration_control_catches_a_second_class_and_a_missing_level() -> None:
    two = (
        'name = "a"\norder = 1\n'
        "@cbom_register\nclass A:\n"
        '    name = "a"\n    order = 1\n    level = 1\n'
        "@cbom_register\nclass B:\n"
        '    name = "b"\n    order = 2\n    level = 1\n'
    )
    assert "decorated classes" in " ".join(registration_problems(two))
    missing = '@cbom_register\nclass A:\n    name = "a"\n    order = 1\n'
    assert registration_problems(missing) == ["missing level"]


def test_posture_modules_import_only_scan_registry() -> None:
    roots = [ROOT / "src" / "aibom" / "cbom" / "posture", SRC]
    for root in roots:
        for path in root.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            if path.name.startswith("posture_") or root.name == "posture":
                tree = ast.parse(path.read_text(encoding="utf-8"))
                assert _scan_import_problems(tree) == [], path.name


def test_scan_import_control() -> None:
    bad = ast.parse("import aibom.scan.pipeline\n")
    good = ast.parse("from aibom.scan.registry import Scanner\n")
    assert _scan_import_problems(bad) == ["aibom.scan.pipeline"]
    assert _scan_import_problems(good) == []


def test_only_cbom_code_imports_posture() -> None:
    offenders: list[str] = []
    bases = (
        REPO / "aibom" / "src",
        REPO / "backend",
        REPO / "RabbitMQ",
        REPO / "bench",
        REPO / "e2e",
    )
    for base in bases:
        if not base.is_dir():
            continue
        for path in base.rglob("*.py"):
            if _SKIP & set(path.parts) or "tests" in path.parts:
                continue
            if "aibom/cbom" in path.as_posix():
                continue
            if path.name == "cbom_devsecshield.py":
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except (SyntaxError, UnicodeDecodeError):
                continue
            if _posture_import(tree):
                offenders.append(str(path.relative_to(REPO)))
    assert offenders == []


def test_posture_import_control(tmp_path: Path) -> None:
    outside = tmp_path / "outside.py"
    outside.write_text("import aibom.cbom.posture\n", encoding="utf-8")
    inside = tmp_path / "tests" / "ok.py"
    inside.parent.mkdir()
    inside.write_text("import aibom.cbom.posture\n", encoding="utf-8")
    assert _posture_import(ast.parse(outside.read_text(encoding="utf-8"))) is True
    assert "tests" in inside.parts


def _band_problem(role: object, order: object) -> str:
    if role == "flagger" and not (isinstance(order, int) and 41 <= order <= 49):
        return "flagger band"
    if role != "flagger" and isinstance(order, int) and order >= 40:
        return "early band"
    return ""


def test_order_bands_and_roles() -> None:
    for name, (role, order) in ROLES.items():
        source = (SRC / f"{name}_scan.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        classes = [node for node in tree.body if isinstance(node, ast.ClassDef)]
        fields = _literal_map(classes[-1])
        assert fields["posture_role"] == role
        assert fields["order"] == order
        assert fields["level"] == 1
        assert _band_problem(role, order) == ""


def test_order_band_control() -> None:
    assert _band_problem("flagger", 31) == "flagger band"


def test_level_equivalence_on_the_committed_terraform_tree() -> None:
    from aibom.cbom.pipeline import scan_crypto

    tree = ROOT / "tests" / "fixtures" / "synthetic-config-aws-tf"
    low = scan_crypto(tree, level=1)
    high = scan_crypto(tree, level=4)
    low_json = json.dumps(low.to_dict(), sort_keys=True)
    high_json = json.dumps(high.to_dict(), sort_keys=True)
    assert low_json == high_json
    assert low.posture == high.posture


def test_aibom_lane_does_not_load_posture() -> None:
    script = (
        "import json, sys\n"
        "import aibom.scan.pipeline\n"
        "import aibom.scan.registry as registry\n"
        "bad = sorted(\n"
        "    name for name in sys.modules if name.startswith('aibom.cbom.posture')\n"
        ")\n"
        "names = sorted(scanner.name for scanner in registry.SCANNERS)\n"
        "print(json.dumps({'modules': bad, 'names': names}))\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(proc.stdout)
    assert payload["modules"] == []
    assert set(NAMES).isdisjoint(payload["names"])


def test_importing_the_cbom_pipeline_does_load_posture() -> None:
    script = (
        "import json, sys\n"
        "import aibom.cbom.pipeline\n"
        "bad = sorted(\n"
        "    name for name in sys.modules if name.startswith('aibom.cbom.posture')\n"
        ")\n"
        "print(json.dumps(bad))\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
    )
    assert json.loads(proc.stdout)


def test_adapter_signature_is_unchanged() -> None:
    from aibom.integrations.cbom_devsecshield import scan_crypto_to_devsecshield

    signature = ROOT / "tests" / "fixtures" / "frozen_goldens" / "adapter_signature.txt"
    frozen = signature.read_text(encoding="utf-8").strip()
    assert str(inspect.signature(scan_crypto_to_devsecshield)) == frozen
    worker_path = REPO / "RabbitMQ" / "worker" / "scan_worker.py"
    worker = worker_path.read_text(encoding="utf-8")
    tree = ast.parse(worker)
    assert _posture_import(tree) is False
