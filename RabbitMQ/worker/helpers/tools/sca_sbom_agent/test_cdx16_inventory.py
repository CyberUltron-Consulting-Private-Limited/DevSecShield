"""FIX-C1 (SOW D4, audit G-D4-1 / G-D4-2 / G-D4-4): inventory coverage and the CycloneDX 1.6 document.

* Syft runs with ``python.guess-unpinned-requirements`` (range requirements are kept; peva3/SmarterRouter's 17
  ``>=`` requirements were all dropped) and writes CycloneDX 1.6, not Syft 1.5x's default 1.7.
* cdxgen runs from the pinned binary in the image, never ``npx --yes`` (a download at scan time), never installs
  the scanned project's dependencies, and is not limited to Python.
* The assembled SBOM is CycloneDX 1.6, valid against the official 1.6.2 JSON schema, with the dependency graph
  (every component reachable from the subject), DevSecShield and its version in ``metadata.tools``, the real scan
  time, and the repository (never its clone credentials) as the subject.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parents[4]

# peva3/SmarterRouter requirements.txt (MIT), commit 3e705e3: 17 requirements, every one a ">=" range
SMARTERROUTER_REQUIREMENTS = """fastapi>=0.109.0
uvicorn[standard]>=0.27.0
httpx>=0.26.0
sqlalchemy>=2.0.25
pydantic>=2.5.0
pydantic-settings>=2.1.0
pytest>=7.4.0
pytest-asyncio>=0.23.0
pytest-cov>=4.1.0
ruff>=0.1.0
mypy>=1.8.0
pandas>=2.2.0
pytest-mock>=3.12.0
prometheus-client>=0.19.0
respx>=0.21.0
pyyaml>=6.0
redis>=5.0.0
"""


def _schema_errors(doc: dict) -> list[str]:
    """Errors against the published CycloneDX 1.6.2 JSON schema (backend/tests/fixtures, sha256-checked)."""
    path = _REPO / "backend" / "tests" / "support" / "cyclonedx_schema.py"
    spec = importlib.util.spec_from_file_location("_cdx_schema_oracle", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.json_errors(doc)


def _reachable(doc: dict) -> set[str]:
    root = doc["metadata"]["component"]["bom-ref"]
    edges = {d["ref"]: d.get("dependsOn") or [] for d in doc.get("dependencies") or []}
    seen, todo = set(), [root]
    while todo:
        ref = todo.pop()
        for kid in edges.get(ref, []):
            if kid not in seen:
                seen.add(kid)
                todo.append(kid)
    return seen


# ---------------------------------------------------------------- Syft -------------------------------------------

def test_syft_config_guesses_unpinned_python_requirements_and_writes_cdx16():
    from helpers.tools.sca_sbom_agent import syft

    text = syft.SYFT_CONFIG.read_text()
    assert "guess-unpinned-requirements: true" in text
    assert "check-for-app-update: false" in text
    cmd = syft.syft_command("/src", "/tmp/out.cdx.json")
    assert cmd[:2] == ["syft", "dir:/src"]
    assert ["-c", str(syft.SYFT_CONFIG)] == cmd[2:4]
    assert "cyclonedx-json@1.6=/tmp/out.cdx.json" in cmd
    assert "syft-json=/tmp/out.cdx.json.native.json" in cmd
    env = syft.syft_env()
    assert env["SYFT_PYTHON_GUESS_UNPINNED_REQUIREMENTS"] == "true"
    assert env["SYFT_CHECK_FOR_APP_UPDATE"] == "false"


def test_version_constraints_mark_ranges_not_pins(tmp_path):
    from helpers.tools.sca_sbom_agent.syft import version_constraints

    cdx = tmp_path / "x.cdx.json"
    cdx.write_text("{}")
    (tmp_path / "x.cdx.json.native.json").write_text(json.dumps({"artifacts": [
        {"purl": "pkg:pypi/fastapi@0.109.0", "metadata": {"versionConstraint": ">=0.109.0"}},
        {"purl": "pkg:pypi/flask@2.0.1", "metadata": {"versionConstraint": "==2.0.1"}},
        {"purl": "pkg:pypi/anthropic@0.49", "metadata": {"versionConstraint": ">=0.49,<1"}},
        {"purl": "pkg:pypi/requests@2.31.0", "metadata": {}},
    ]}))
    assert version_constraints(cdx) == {"pkg:pypi/fastapi@0.109.0": ">=0.109.0",
                                        "pkg:pypi/anthropic@0.49": ">=0.49,<1"}


def _syft_binary() -> str | None:
    return os.environ.get("SYFT_BIN") or shutil.which("syft")


@pytest.mark.skipif(_syft_binary() is None, reason="syft is not installed here (the scan-worker image has it)")
def test_real_syft_keeps_all_17_smarterrouter_requirements(tmp_path):
    from helpers.tools.sca_sbom_agent import syft

    (tmp_path / "requirements.txt").write_text(SMARTERROUTER_REQUIREMENTS)
    out = tmp_path / "out.cdx.json"
    cmd = syft.syft_command(tmp_path, out)
    cmd[0] = _syft_binary()
    subprocess.run(cmd, check=True, env=syft.syft_env(), timeout=300, capture_output=True)
    doc = json.loads(out.read_text())
    assert doc["specVersion"] == "1.6"
    pypi = sorted(c["name"] for c in doc["components"] if str(c.get("purl", "")).startswith("pkg:pypi/"))
    assert len(pypi) == 17, pypi
    assert len(syft.version_constraints(out)) == 17


# ---------------------------------------------------------------- cdxgen -----------------------------------------

def test_cdxgen_uses_the_installed_binary_never_npx(tmp_path):
    from helpers.tools.sca_sbom_agent import cdxgen_run

    def which(name):
        return "/usr/bin/npx" if name == "npx" else None

    with patch.object(cdxgen_run.shutil, "which", side_effect=which), \
            patch.object(cdxgen_run, "run_tool") as run_tool, patch.dict(os.environ, {"CDXGEN_BIN": ""}):
        assert cdxgen_run.run_cdxgen(tmp_path) is None
    run_tool.assert_not_called()

    cmd = cdxgen_run.cdxgen_command("/usr/local/bin/cdxgen", "/src", "/tmp/o.json")
    assert cmd[0] == "/usr/local/bin/cdxgen"
    assert "--no-install-deps" in cmd
    assert cmd[cmd.index("--spec-version") + 1] == "1.6"
    assert "-t" not in cmd and "npx" not in " ".join(cmd)
    assert cdxgen_run.cdxgen_env()["FETCH_LICENSE"] == "false"


def test_worker_image_installs_pinned_cdxgen():
    dockerfile = (_REPO / "RabbitMQ" / "worker" / "Dockerfile").read_text()
    lock = json.loads((_REPO / "RabbitMQ" / "worker" / "tools" / "cdxgen" / "package-lock.json").read_text())
    pinned = json.loads((_REPO / "RabbitMQ" / "worker" / "tools" / "cdxgen" / "package.json").read_text())
    version = pinned["dependencies"]["@cyclonedx/cdxgen"]
    assert version[0].isdigit(), "cdxgen must be an exact version"
    assert lock["packages"]["node_modules/@cyclonedx/cdxgen"]["version"] == version
    assert lock["packages"]["node_modules/@cyclonedx/cdxgen"]["integrity"].startswith("sha512-")
    assert "npm ci" in dockerfile and "--ignore-scripts" in dockerfile
    assert "NODE_SHA256_AMD64" in dockerfile and "sha256sum -c" in dockerfile
    assert "/usr/local/bin/cdxgen" in dockerfile and "cdxgen --version" in dockerfile


# ---------------------------------------------------------------- assembled document -----------------------------

def _syft_doc():
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.7",
        "metadata": {"tools": {"components": [{"type": "application", "author": "anchore", "name": "syft",
                                               "version": "1.57.0"}]},
                     "component": {"bom-ref": "af63", "type": "file", "name": "."}},
        "components": [
            {"bom-ref": "s1", "type": "library", "name": "fastapi", "version": "0.109.0",
             "purl": "pkg:pypi/fastapi@0.109.0"},
            {"bom-ref": "s2", "type": "library", "name": "starlette", "version": "0.35.1",
             "purl": "pkg:pypi/starlette@0.35.1"},
            {"bom-ref": "s3", "type": "library", "name": "actions/checkout", "version": "v4",
             "purl": "pkg:github/actions/checkout@v4"},
        ],
    }


def _cdxgen_doc():
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "metadata": {"tools": {"components": [{"type": "application", "name": "cdxgen", "version": "12.9.3",
                                               "publisher": "OWASP Foundation"}]},
                     "component": {"bom-ref": "pkg:application/repo@1", "name": "repo"}},
        "components": [
            {"bom-ref": "pkg:pypi/fastapi@0.109.0", "name": "fastapi", "version": "0.109.0",
             "purl": "pkg:pypi/fastapi@0.109.0"},
            {"bom-ref": "pkg:pypi/starlette@0.35.1", "name": "starlette", "version": "0.35.1",
             "purl": "pkg:pypi/starlette@0.35.1"},
        ],
        "dependencies": [
            {"ref": "pkg:application/repo@1", "dependsOn": ["pkg:pypi/fastapi@0.109.0"]},
            {"ref": "pkg:pypi/fastapi@0.109.0", "dependsOn": ["pkg:pypi/starlette@0.35.1"]},
            {"ref": "pkg:pypi/starlette@0.35.1", "dependsOn": []},
        ],
    }


def _assemble(monkeypatch, tmp_path):
    from helpers.tools.sca_sbom_agent.merge_inventory import assemble_cyclonedx, merge_cdx_components, \
        subject_from_repo

    monkeypatch.setenv("DSS_BUILD_VERSION", "2026.11.23-rc1")
    a, b = tmp_path / "syft.json", tmp_path / "cdxgen.json"
    a.write_text(json.dumps(_syft_doc()))
    b.write_text(json.dumps(_cdxgen_doc()))
    subject = subject_from_repo("https://x-access-token:placeholder-not-a-token@github.com/peva3/SmarterRouter.git", "main")
    return assemble_cyclonedx(
        merge_cdx_components(a, b), tools=["syft", "cdxgen"], subject=subject,
        source_docs=[_syft_doc(), _cdxgen_doc()], constraints={"pkg:pypi/fastapi@0.109.0": ">=0.109.0"},
    )


def test_assembled_sbom_is_valid_cyclonedx_16(monkeypatch, tmp_path):
    doc = _assemble(monkeypatch, tmp_path)
    assert doc["specVersion"] == "1.6"
    assert doc["$schema"] == "http://cyclonedx.org/schema/bom-1.6.schema.json"
    assert _schema_errors(doc) == []


def test_assembled_sbom_metadata_names_devsecshield_and_the_repository(monkeypatch, tmp_path):
    doc = _assemble(monkeypatch, tmp_path)
    meta = doc["metadata"]
    tools = {t["name"]: t.get("version") for t in meta["tools"]["components"]}
    assert tools == {"DevSecShield": "2026.11.23-rc1", "syft": "1.57.0", "cdxgen": "12.9.3"}
    stamped = datetime.strptime(meta["timestamp"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    assert abs((datetime.now(timezone.utc) - stamped).total_seconds()) < 120
    assert meta["component"]["name"] == "peva3/SmarterRouter"
    assert meta["component"]["purl"] == "pkg:github/peva3/SmarterRouter@main"
    assert "placeholder-not-a-token" not in json.dumps(doc) and "x-access-token" not in json.dumps(doc)
    assert meta["authors"] == [{"name": "DevSecShield"}]
    assert meta["lifecycles"] == [{"phase": "pre-build"}]


def test_assembled_sbom_dependency_graph_reaches_every_component(monkeypatch, tmp_path):
    doc = _assemble(monkeypatch, tmp_path)
    refs = {c["bom-ref"] for c in doc["components"]}
    assert refs == {"pkg:pypi/fastapi@0.109.0", "pkg:pypi/starlette@0.35.1", "pkg:github/actions/checkout@v4"}
    assert _reachable(doc) == refs
    deps = {d["ref"]: d.get("dependsOn") for d in doc["dependencies"]}
    root = doc["metadata"]["component"]["bom-ref"]
    # cdxgen's edges survive the join with Syft's (differently named) bom-refs; starlette is transitive
    assert deps["pkg:pypi/fastapi@0.109.0"] == ["pkg:pypi/starlette@0.35.1"]
    assert set(deps[root]) == {"pkg:pypi/fastapi@0.109.0", "pkg:github/actions/checkout@v4"}
    assert "pkg:github/actions/checkout@v4" not in deps  # its own dependencies are unknown: no entry


def test_guessed_versions_are_marked(monkeypatch, tmp_path):
    doc = _assemble(monkeypatch, tmp_path)
    fastapi = next(c for c in doc["components"] if c["name"] == "fastapi")
    props = {p["name"]: p["value"] for p in fastapi["properties"]}
    assert props == {"dss:version_source": "range_lower_bound", "dss:version_constraint": ">=0.109.0"}


def test_subject_without_a_repository_url_is_still_valid():
    from helpers.tools.sca_sbom_agent.merge_inventory import subject_from_repo

    subject = subject_from_repo(None, None, tempfile.mkdtemp(), fallback_name="uploaded-archive")
    assert subject["name"] == "uploaded-archive" and subject["bom-ref"].startswith("urn:dss:subject:")
