"""Lock the posture documents to the shipped tables.

Run this file as a script to regenerate the generated documents.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

from aibom.cbom.posture import LANE_NAMES
from aibom.cbom.posture import limits as limits_mod
from aibom.cbom.posture.extract_databases import DB_SETTINGS
from aibom.cbom.posture.safeio import SKIP_DIRS, classify_name

REPO = Path(__file__).resolve().parents[2]
DOCS = REPO / "docs" / "cbom-posture"
DATA = REPO / "aibom" / "src" / "aibom" / "cbom" / "data" / "coverage_table.json"
SCANNERS = REPO / "aibom" / "src" / "aibom" / "cbom" / "scanners"
TEXT = REPO / "backend" / "utilities" / "pdf" / "cbom_posture_text.py"

FILE_CLASS_PATHS = (
    "main.tf",
    "main.tf.json",
    "dev.tfvars",
    "Dockerfile",
    "docker-compose.yml",
    "sshd_config",
    "postgresql.conf",
    "pg_hba.conf",
    "my.cnf",
    "mongod.conf",
    "elasticsearch.yml",
    "redis.conf",
    "crypttab",
    "schema.sql",
    "CODEOWNERS",
    "cbom-mapping.yaml",
    "nginx.conf",
    "httpd.conf",
    "haproxy.cfg",
    "envoy.yaml",
    "server.xml",
    "app.py",
    "deploy.sh",
)
SYNTAXES = ("terraform", "cloudformation", "kubernetes", "compose")
EXTRA_REASONS = {
    "conflicting_declaration": (
        "Two declarations disagree",
        "Keep the declaration that is applied and remove the other.",
    ),
    "import_observation": (
        "An imported result recorded an observation without a verdict",
        "Read the customer's tool output for this host.",
    ),
}


def _cell(value: object) -> str:
    text = str(value).replace("|", "/")
    return text if text else "-"


def _join(values: object) -> str:
    if not isinstance(values, list) or not values:
        return "-"
    return ", ".join(_cell(item) for item in values)


def render_table(headers: tuple[str, ...], rows: list[tuple[str, ...]]) -> str:
    head = "| " + " | ".join(headers) + " |"
    rule = "| " + " | ".join("---" for _ in headers) + " |"
    body = ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join([head, rule, *body])


def anchored(anchor: str, headers: tuple[str, ...], rows: list[tuple[str, ...]]) -> str:
    return f"<!-- table:{anchor} -->\n" + render_table(headers, rows)


def parse_table(text: str, anchor: str) -> list[tuple[str, ...]]:
    marker = f"<!-- table:{anchor} -->"
    start = text.index(marker)
    rows: list[tuple[str, ...]] = []
    header = False
    for line in text[start:].splitlines()[1:]:
        if not line.startswith("|"):
            if header:
                break
            continue
        cells = tuple(part.strip() for part in line.strip().strip("|").split("|"))
        if all(set(cell) <= set("-: ") and cell for cell in cells):
            continue
        if not header:
            header = True
            continue
        rows.append(cells)
    return rows


def limit_rows() -> list[tuple[str, str]]:
    rows = []
    for name, value in vars(limits_mod).items():
        if name.isupper() and isinstance(value, int):
            rows.append((name, str(value)))
    return sorted(rows)


def coverage_rows() -> list[tuple[str, ...]]:
    payload = json.loads(DATA.read_text(encoding="utf-8"))
    rows = []
    for row in payload["rows"]:
        native = row.get("native") or {}
        rows.append(
            (
                _cell(row["id"]),
                _cell(row.get("provider", "")),
                _cell(row.get("kind", "")),
                *(_join(native.get(key)) for key in SYNTAXES),
            )
        )
    return sorted(rows)


def db_rows() -> list[tuple[str, str, str]]:
    return sorted(
        (_cell(software), _cell(setting), _cell(treatment))
        for (software, setting), treatment in DB_SETTINGS.items()
    )


def file_class_rows() -> list[tuple[str, str]]:
    return [(path, classify_name(path) or "-") for path in FILE_CLASS_PATHS]


def skip_rows() -> list[tuple[str, ...]]:
    return [(name,) for name in sorted(SKIP_DIRS)]


def scanner_rows() -> list[tuple[str, str]]:
    found = []
    for path in sorted(SCANNERS.glob("posture_*_scan.py")):
        text = path.read_text(encoding="utf-8")
        name = re.search(r'^    name = "([^"]+)"', text, re.M)
        order = re.search(r"^    order = (\d+)", text, re.M)
        assert name is not None and order is not None
        found.append((name.group(1), order.group(1)))
    return sorted(found, key=lambda row: int(row[1]))


def _assigned(tree: ast.Module, name: str) -> ast.AST:
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = [item.id for item in node.targets if isinstance(item, ast.Name)]
            if name in targets:
                return node.value
    raise AssertionError(name)


def reason_rows() -> list[tuple[str, str, str]]:
    tree = ast.parse(TEXT.read_text(encoding="utf-8"))
    keys = ast.literal_eval(_assigned(tree, "UNKNOWN_REASONS"))
    labels = ast.literal_eval(_assigned(tree, "UNKNOWN_LABELS"))
    checks = ast.literal_eval(_assigned(tree, "UNKNOWN_CHECKS"))
    rows = [(_cell(key), _cell(labels[key]), _cell(checks[key])) for key in keys]
    for key, (label, check) in sorted(EXTRA_REASONS.items()):
        rows.append((_cell(key), _cell(label), _cell(check)))
    return rows


def engine_reason_literals() -> set[str]:
    root = REPO / "aibom" / "src" / "aibom" / "cbom" / "posture"
    pattern = re.compile(
        r'unknown_reason\s*=\s*"([a-z0-9_]+)"'
        r'|LayerResult\(\s*"UNKNOWN"\s*,\s*"([a-z0-9_]+)"'
    )
    found: set[str] = set()
    for path in root.glob("*.py"):
        for match in pattern.finditer(path.read_text(encoding="utf-8")):
            found.add(next(group for group in match.groups() if group))
    return found


def limits_doc() -> str:
    return (
        "# Limits\n\n"
        "These integers are the posture lane limits. "
        "Units are bytes, files, nodes, lines, or steps. "
        "The serialized posture block cap is `POSTURE_BLOCK_BYTES`. "
        "A separate 15 MiB adapter-dict budget is described in the design "
        "and is not a constant in `limits.py`.\n\n"
        + anchored("limits", ("name", "value"), limit_rows())
        + "\n"
    )


def unknown_doc() -> str:
    return (
        "# Unknown reasons\n\n"
        "An UNKNOWN verdict is not evidenceable from the BOM. "
        "The manual check is what a person records. "
        "`non_production_hint` is a path label and is not one of these reasons.\n\n"
        + anchored(
            "unknown-reasons",
            ("reason", "label", "manual check"),
            reason_rows(),
        )
        + "\n"
    )


def formats_doc() -> str:
    parts = [
        "# Supported formats\n",
        "File names select a class. The coverage table then names the "
        "native types the verdict engine consults. "
        "Terraform and CloudFormation names for one row share one semantic rule.\n",
        "## File classes\n",
        anchored("file-classes", ("path", "class"), file_class_rows()),
        "\n## Skipped directories\n",
        "These directory names are skipped at any depth.\n",
        anchored("skip-dirs", ("name",), skip_rows()),
        "\n## Database settings\n",
        anchored(
            "db-settings",
            ("software", "setting", "treatment"),
            db_rows(),
        ),
        "\n## Coverage table\n",
        anchored(
            "coverage",
            ("id", "provider", "kind", *SYNTAXES),
            coverage_rows(),
        ),
        "",
    ]
    return "\n".join(parts) + "\n"


def write_generated() -> None:
    DOCS.mkdir(parents=True, exist_ok=True)
    (DOCS / "limits.md").write_text(limits_doc(), encoding="utf-8")
    (DOCS / "unknown-reasons.md").write_text(unknown_doc(), encoding="utf-8")
    (DOCS / "supported-formats.md").write_text(formats_doc(), encoding="utf-8")


def _doc(name: str) -> str:
    return (DOCS / name).read_text(encoding="utf-8")


def test_limits_table_matches_limits_py() -> None:
    assert parse_table(_doc("limits.md"), "limits") == limit_rows()


def test_unknown_reasons_match_the_authored_vocabulary() -> None:
    rows = parse_table(_doc("unknown-reasons.md"), "unknown-reasons")
    assert rows == reason_rows()
    documented = {row[0] for row in rows}
    assert engine_reason_literals() <= documented


def test_supported_formats_match_the_shipped_tables() -> None:
    text = _doc("supported-formats.md")
    assert parse_table(text, "file-classes") == file_class_rows()
    assert parse_table(text, "skip-dirs") == skip_rows()
    assert parse_table(text, "db-settings") == db_rows()
    assert parse_table(text, "coverage") == coverage_rows()


def test_readme_lists_the_seven_lanes() -> None:
    text = _doc("README.md")
    assert parse_table(text, "lanes") == scanner_rows()
    assert tuple(row[0] for row in scanner_rows()) == LANE_NAMES
    for verdict in (
        "ENCRYPTED_DECLARED",
        "ENCRYPTED_PROVIDER_DEFAULT",
        "NOT_ENCRYPTED",
        "UNKNOWN",
    ):
        assert verdict in text
    assert "scan_crypto" in text


def test_prose_documents_name_the_required_topics() -> None:
    mapping = _doc("business-mapping.md")
    for field in ("system", "owner", "data_classification", "data_lifetime"):
        assert field in mapping
    assert "CODEOWNERS" in mapping
    assert "10,000" in mapping
    registry = _doc("defaults-registry.md")
    assert "importlib.resources" in registry
    assert "valid_as_of" in registry
    assert "clean-room" in registry
    airgap = _doc("airgap.md")
    assert "AWS_ENDPOINT_URL_S3" in airgap
    assert "has not been run" in airgap
    limits = _doc("known-limitations.md")
    for phrase in (
        "Pulumi",
        "Ansible",
        "Helm",
        "locals",
        "Kustomize",
        "stream",
        "max_raw",
        "112",
    ):
        assert phrase in limits


def test_posture_docs_have_no_images() -> None:
    for path in DOCS.glob("*.md"):
        assert "![" not in path.read_text(encoding="utf-8")


if __name__ == "__main__":
    write_generated()
