"""T-NOLLM: the team-wide CBOM deliverables stay fully in-house (WP4, plan 6.5, constraint L-9).

The product promise is "no language-model call, no third-party service, no new library".  Three
independent layers prove it with the standard library only (no ``pytest-socket``):

* T-NOLLM-1  STATIC.  An AST guard over EVERY new product file: imports (including function-level
  and ``TYPE_CHECKING`` ones, resolved relative imports and ``from x import y`` forms), dynamic
  imports, process spawning and the banned vocabulary.  Every top-level import must come from the
  standard library, ``reportlab`` or (per file kind) a short allow-list.
* T-NOLLM-2  CLOSURE.  A FRESH interpreter imports the modules and lists what ended up in
  ``sys.modules``: nothing forbidden may be pulled in transitively.  The router is measured three
  ways: with the auth/DB helpers stubbed (its OWN closure must be clean), with the real chain
  (only the known pre-existing exception set may appear) and a control that proves the probe sees
  a forbidden import when there is one.
* T-NOLLM-3  RUNTIME.  ``block_network`` replaces every socket connect/DNS entry point and
  ``subprocess.Popen`` with a function that raises; ``plant_tripwires`` replaces the SDK modules
  an LLM client would use with objects that raise on first touch.  All six builders run on every
  fixture variant under both, then the whole HTTP flow (manifest + six PDFs + error paths) runs
  under both.  ``test_cbom_deliverables_route.py`` applies the same guard to EVERY route test
  through an autouse fixture, so "all route tests" run guarded too.  Control tests prove each
  guard fires.

T-NOLLM-4 (the dependency manifests are unchanged versus the branch base) is the scripted git gate
of plan 6.7; it needs the base ref, so it lives in the verification script, not in this suite.
"""
from __future__ import annotations

import ast
import copy
import importlib
import json
import os
import socket
import subprocess
import sys
import textwrap
import types
from datetime import datetime, timezone
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from backend.utilities.dashboard.cbom_team_rollup import ScanHead, fold_scans  # noqa: E402

UTC = timezone.utc
NOW = datetime(2026, 10, 19, 12, 28, tzinfo=UTC)
FIXTURES = Path(__file__).resolve().parent / "fixtures"
_BACKEND = _REPO_ROOT / "backend"
_PDF = _BACKEND / "utilities" / "pdf"
_DASHBOARD = _BACKEND / "utilities" / "dashboard"
_ROUTERS = _BACKEND / "routers"

SLUGS = (
    "scope-baseline-register",
    "methodology-evidence-plan",
    "infrastructure-cloud-encryption-posture",
    "network-tls-protocol-assessment",
    "certificate-estate-register",
    "data-at-rest-encryption-assessment",
    "third-party-assurance-register",
    "pqc-migration-roadmap",
    "board-executive-report",
)
# Every product file this feature added.  The discovery below finds MORE automatically (a seventh
# renderer is guarded the day it is added); this list only proves the discovery did not shrink.
KNOWN_NEW_FILES = {
    "backend/routers/cbom_deliverables.py",
    "backend/utilities/dashboard/cbom_team_rollup.py",
    "backend/utilities/pdf/cbom_assurance_register_pdf.py",
    "backend/utilities/pdf/cbom_board_report_pdf.py",
    "backend/utilities/pdf/cbom_cert_register_pdf.py",
    "backend/utilities/pdf/cbom_deliverable_common.py",
    "backend/utilities/pdf/cbom_deliverable_text.py",
    "backend/utilities/pdf/cbom_deliverables.py",
    "backend/utilities/pdf/cbom_methodology_pdf.py",
    "backend/utilities/pdf/cbom_pqc_roadmap_pdf.py",
    "backend/utilities/pdf/cbom_scope_register_pdf.py",
}


def new_product_files() -> list[Path]:
    found = {
        *_PDF.glob("cbom_deliverable_*.py"),
        *_PDF.glob("cbom_*_pdf.py"),
        _PDF / "cbom_deliverables.py",
        _DASHBOARD / "cbom_team_rollup.py",
        _ROUTERS / "cbom_deliverables.py",
    }
    # cbom_pdf.py (the single-scan export) pre-dates this feature and is not guarded here
    return sorted(path for path in found if path.name != "cbom_pdf.py")


# ---------------------------------------------------------------------------------------------
# T-NOLLM-1: static AST guard
# ---------------------------------------------------------------------------------------------
FORBIDDEN_ROOTS = frozenset(
    {
        # model SDKs and generic HTTP clients (anything that can reach a hosted model)
        "boto3", "botocore", "openai", "anthropic", "instructor", "litellm",
        "requests", "httpx", "urllib3", "aiohttp",
        # raw network and process access in the standard library
        "socket", "ssl", "smtplib", "ftplib", "telnetlib", "imaplib", "poplib", "subprocess",
        # dynamic loading would let a module step around this very guard
        "importlib", "ctypes",
    }
)  # fmt: skip
FORBIDDEN_DOTTED = (
    "http.client",
    "http.server",
    "urllib.request",
    "backend.utilities.ai",
    "backend.routers",  # the router file may not import a sibling router (scans.py pulls the LLM)
)
FORBIDDEN_TOKENS = ("get_llm", "chatbedrock", "bedrock", "anthropic", "openai")
_STDLIB = frozenset(sys.stdlib_module_names)


def _is_under(name: str, prefix: str) -> bool:
    return name == prefix or name.startswith(prefix + ".")


def _package_of(path: Path) -> str:
    parts = path.relative_to(_REPO_ROOT).with_suffix("").parts
    return ".".join(parts[:-1])


def _import_names(node: ast.AST, package: str) -> list[tuple[str, bool]]:
    """Absolute dotted names a statement imports, each flagged ``True`` when it is a module that
    is actually imported (``from a import b`` imports ``a``; ``a.b`` is only a candidate)."""
    if isinstance(node, ast.Import):
        return [(alias.name, True) for alias in node.names]
    if isinstance(node, ast.ImportFrom):
        base = node.module or ""
        if node.level:
            anchor = package.split(".")
            anchor = anchor[: len(anchor) - (node.level - 1)]
            base = ".".join([*anchor, base] if base else anchor)
        names = [(base, True)]
        names += [(f"{base}.{alias.name}", False) for alias in node.names if alias.name != "*"]
        return names
    return []


def _call_problems(node: ast.Call) -> list[str]:
    func = node.func
    if isinstance(func, ast.Name) and func.id in {"__import__", "eval", "exec", "compile"}:
        return [f"call to {func.id}() on line {node.lineno}"]
    if isinstance(func, ast.Attribute):
        if func.attr == "import_module":
            return [f"dynamic import on line {node.lineno}"]
        owner = func.value.id if isinstance(func.value, ast.Name) else ""
        if owner == "os" and func.attr in {"system", "popen", "fork", "forkpty"}:
            return [f"os.{func.attr}() on line {node.lineno}"]
        if owner == "os" and func.attr.startswith(("exec", "spawn")):
            return [f"os.{func.attr}() on line {node.lineno}"]
    return []


def static_violations(
    source: str, *, package: str, allowed_roots: set[str], allowed_backend: tuple[str, ...]
) -> list[str]:
    problems: list[str] = []
    tree = ast.parse(source)
    for node in ast.walk(tree):
        for name, imported in _import_names(node, package):
            root = name.split(".")[0]
            forbidden = (
                root.startswith("langchain")
                or root in FORBIDDEN_ROOTS
                or any(_is_under(name, dotted) for dotted in FORBIDDEN_DOTTED)
            )
            if forbidden:
                problems.append(f"forbidden import {name!r}")
            elif imported and root not in allowed_roots:
                problems.append(f"import {name!r} is outside the allow-list")
            elif (
                imported
                and root == "backend"
                and not any(_is_under(name, prefix) for prefix in allowed_backend)
            ):
                problems.append(f"backend import {name!r} is outside the allow-list")
        if isinstance(node, ast.Call):
            problems += _call_problems(node)
    lowered = source.lower()
    problems += [f"banned token {token!r}" for token in FORBIDDEN_TOKENS if token in lowered]
    return problems


def _policy(path: Path) -> tuple[set[str], tuple[str, ...]]:
    roots = {*_STDLIB, "reportlab", "backend"}
    backend = ("backend.utilities.pdf", "backend.utilities.dashboard.cbom_team_rollup")
    if path.name == "cbom_team_rollup.py":
        roots |= {"sqlmodel"}  # imported lazily inside load_team_cbom_view
        backend += ("backend.new_models",)
        # the one finding rule and quantum-readiness definition every CBOM view shares (pure, stdlib only)
        backend += ("backend.utilities.cbom_sources.cbom_rows", "backend.utilities.cbom_sources.cbom_metrics")
        # the remediation plan (waves, owners, target dates; scan-node assets) read by the loader: database only, no AI
        backend += ("backend.utilities.cbom_sources.waves",)
    # CBOM Sources collections as CBOM results (M1x): stored assets and the latest-observation rule; database only
    backend += ("backend.utilities.cbom_sources.collections_view",)
    # cross-source asset keys (CB-21): pure, stdlib only, no AI
    backend += ("backend.utilities.cbom_sources.asset_keys",)
    if path.parent == _ROUTERS:
        roots |= {"fastapi", "starlette", "sqlmodel", "sqlalchemy", "rich"}
        backend += (
            "backend.get_db",
            "backend.new_models",
            "backend.utilities.auth.auth_utils",
            "backend.utilities.ratelimit",
            "backend.utilities.team",
        )
    return roots, backend


def test_discovery_finds_every_known_new_file():
    found = {path.relative_to(_REPO_ROOT).as_posix() for path in new_product_files()}
    assert found >= KNOWN_NEW_FILES, sorted(KNOWN_NEW_FILES - found)
    assert "backend/utilities/pdf/cbom_pdf.py" not in found


@pytest.mark.parametrize(
    "path", new_product_files(), ids=lambda p: p.relative_to(_REPO_ROOT).as_posix()
)
def test_new_product_files_pass_the_static_no_llm_guard(path):
    roots, backend = _policy(path)
    problems = static_violations(
        path.read_text(encoding="utf-8"),
        package=_package_of(path),
        allowed_roots=roots,
        allowed_backend=backend,
    )
    assert problems == [], f"{path.name}: {problems}"


_GOOD = "from __future__ import annotations\nimport json\nfrom reportlab.platypus import Spacer\n"
_BAD_SNIPPETS = {
    "boto3": "import boto3\n",
    "langchain": "from langchain_aws import ChatBedrock\n",
    "requests": "import requests\n",
    "httpx function-level": "def f():\n    import httpx\n",
    "type-checking import": "if TYPE_CHECKING:\n    import openai\n",
    "from-import of a banned submodule": "from urllib import request\n",
    "http.client": "import http.client\n",
    "socket": "import socket\n",
    "subprocess": "from subprocess import run\n",
    "ssl": "import ssl\n",
    "ai package": "from backend.utilities.ai.llm import get_llm\n",
    "scans router": "from backend.routers.scans import router\n",
    "relative import into the ai package": "from ..ai import llm\n",
    "importlib": "import importlib\n",
    "dynamic import": "m = __import__('boto3')\n",
    "import_module": "mod = loader.import_module('x')\n",
    "os.system": "import os\nos.system('curl http://x')\n",
    "eval": "eval('1+1')\n",
    "third-party import": "import numpy\n",
    "backend outside the allow-list": "from backend.utilities.scan import start_scan\n",
    "token in a comment": "# calls bedrock for a summary\n",
    "token in a string": "x = 'anthropic'\n",
}


@pytest.mark.parametrize("name", sorted(_BAD_SNIPPETS))
def test_static_guard_control_flags_a_violation(name):
    problems = static_violations(
        _BAD_SNIPPETS[name],
        package="backend.utilities.pdf",
        allowed_roots={*_STDLIB, "reportlab", "backend"},
        allowed_backend=("backend.utilities.pdf",),
    )
    assert problems, f"the guard missed: {name}"


def test_static_guard_control_accepts_a_clean_module():
    assert (
        static_violations(
            _GOOD,
            package="backend.utilities.pdf",
            allowed_roots={*_STDLIB, "reportlab", "backend"},
            allowed_backend=("backend.utilities.pdf",),
        )
        == []
    )


# ---------------------------------------------------------------------------------------------
# T-NOLLM-2: transitive closure in a fresh interpreter
# ---------------------------------------------------------------------------------------------
_PROBE_FORBIDDEN = [
    "boto3", "botocore", "langchain", "langchain_core", "langchain_aws", "langchain_openai",
    "openai", "anthropic", "instructor", "requests", "httpx", "urllib3", "aiohttp", "msal",
    "celery", "kombu", "pymongo", "smtplib", "ftplib",
]  # fmt: skip
_LLM_ONLY = frozenset(
    {
        "boto3", "botocore", "langchain", "langchain_core", "langchain_aws", "langchain_openai",
        "openai", "anthropic", "instructor", "litellm", "httpx", "aiohttp", "celery", "kombu",
    }
)  # fmt: skip
# The auth and DB helpers PRE-DATE this feature and legitimately load these (plan F-08, the
# ``certin`` router has the same footprint).  Nothing LLM-related may ever be in this set.
KNOWN_AUTH_CHAIN_EXCEPTION = frozenset({"msal", "pymongo", "requests", "smtplib", "urllib3"})

_PROBE_HEAD = """
import json, sys, types
try:
    import dotenv
    dotenv.load_dotenv = lambda *a, **k: False   # never read a real .env file
except ImportError:
    pass
FORBIDDEN = %r
"""
_PROBE_TAIL = """
roots = {name.split(".")[0] for name in sys.modules}
result = {
    "forbidden": sorted(r for r in roots if r in FORBIDDEN or r.startswith("langchain")),
    "ai_modules": sorted(m for m in sys.modules if m.startswith("backend.utilities.ai")),
    "scans_router": "backend.routers.scans" in sys.modules,
    "modules": len(sys.modules),
}
print("PROBE:" + json.dumps(result))
"""
_STUB_AUTH_AND_DB = """
auth = types.ModuleType("backend.utilities.auth.auth_utils")
async def get_user_from_header_or_raise_exception(engine, authorization=None, ignore=False):
    raise RuntimeError("stub")
auth.get_user_from_header_or_raise_exception = get_user_from_header_or_raise_exception
sys.modules["backend.utilities.auth.auth_utils"] = auth
database = types.ModuleType("backend.get_db")
database.get_db = lambda: None
sys.modules["backend.get_db"] = database
"""


def _module_name(path: Path) -> str:
    return ".".join(path.relative_to(_REPO_ROOT).with_suffix("").parts)


def _probe(body: str) -> dict:
    script = (_PROBE_HEAD % (_PROBE_FORBIDDEN,)) + textwrap.dedent(body) + _PROBE_TAIL
    env = {
        **os.environ,
        "PYTHONPATH": str(_REPO_ROOT),
        "JWT_SECRET_KEY": "probe-secret",
        "JWT_REFRESH_SECRET_KEY": "probe-refresh",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    done = subprocess.run(
        [sys.executable, "-c", script],
        env=env,
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=240,
        check=False,
    )
    assert done.returncode == 0, done.stderr[-3000:]
    lines = [line for line in done.stdout.splitlines() if line.startswith("PROBE:")]
    assert lines, done.stdout[-2000:] + done.stderr[-2000:]
    return json.loads(lines[-1][len("PROBE:") :])


def _import_statements(paths: list[Path]) -> str:
    return "\n".join(f"importlib.import_module({_module_name(p)!r})" for p in paths)


def test_pure_modules_pull_in_nothing_forbidden():
    pure = [p for p in new_product_files() if p.parent != _ROUTERS]
    assert len(pure) >= 10
    result = _probe("import importlib\n" + _import_statements(pure))
    assert result["forbidden"] == []
    assert result["ai_modules"] == []
    assert result["scans_router"] is False


def test_router_own_closure_is_clean_with_the_auth_and_db_helpers_stubbed():
    router = _ROUTERS / "cbom_deliverables.py"
    result = _probe(_STUB_AUTH_AND_DB + "\nimport importlib\n" + _import_statements([router]))
    assert result["forbidden"] == []
    assert result["ai_modules"] == []
    assert result["scans_router"] is False


def test_router_with_the_real_auth_chain_only_adds_the_known_exception_set():
    router = _ROUTERS / "cbom_deliverables.py"
    result = _probe("import importlib\n" + _import_statements([router]))
    assert set(result["forbidden"]) <= KNOWN_AUTH_CHAIN_EXCEPTION, result["forbidden"]
    assert not (set(result["forbidden"]) & _LLM_ONLY)
    assert result["ai_modules"] == []
    assert result["scans_router"] is False


def test_closure_probe_control_sees_a_forbidden_import():
    result = _probe("import requests, json\n")
    assert "requests" in result["forbidden"]
    langchain = _probe("import types\nsys.modules['langchain_planted'] = types.ModuleType('x')\n")
    assert langchain["forbidden"] == ["langchain_planted"]


# ---------------------------------------------------------------------------------------------
# T-NOLLM-3: runtime guard (reused by test_cbom_deliverables_route.py)
# ---------------------------------------------------------------------------------------------
TRIPWIRE_MODULES = (
    "boto3",
    "botocore",
    "openai",
    "anthropic",
    "langchain",
    "langchain_aws",
    "langchain_core",
    "requests",
    "httpx",
)


class _Tripwire(types.ModuleType):
    """A stand-in module: ANY attribute access means product code reached for the SDK."""

    def __getattr__(self, name: str):
        raise AssertionError(f"forbidden module {self.__name__!r} was used (attribute {name!r})")


def _refuse(*_args, **_kwargs):
    raise AssertionError("network/process access attempted")


def block_network(monkeypatch) -> None:
    """Every way to open a connection, resolve a name or start a process raises.

    Socket CREATION is left alone on purpose: asyncio's self-pipe and the in-process test
    client need ``socket.socketpair()``; they never connect anywhere.
    """
    for name in ("connect", "connect_ex"):
        monkeypatch.setattr(socket.socket, name, _refuse)
    for name in ("create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        monkeypatch.setattr(socket, name, _refuse)
    monkeypatch.setattr(subprocess, "Popen", _refuse)


def plant_tripwires(monkeypatch) -> None:
    for name in TRIPWIRE_MODULES:
        monkeypatch.setitem(sys.modules, name, _Tripwire(name))


def test_runtime_guard_control_blocks_connections_names_and_processes(monkeypatch):
    block_network(monkeypatch)
    with pytest.raises(AssertionError, match="network/process access attempted"):
        socket.create_connection(("127.0.0.1", 9))
    sock = socket.socket()  # creating a socket is allowed; using it to connect is not
    try:
        with pytest.raises(AssertionError, match="network/process access attempted"):
            sock.connect(("127.0.0.1", 9))
        with pytest.raises(AssertionError, match="network/process access attempted"):
            sock.connect_ex(("127.0.0.1", 9))
    finally:
        sock.close()
    for resolver in (socket.getaddrinfo, socket.gethostbyname, socket.gethostbyname_ex):
        with pytest.raises(AssertionError, match="network/process access attempted"):
            resolver("example.invalid")
    with pytest.raises(AssertionError, match="network/process access attempted"):
        subprocess.Popen([sys.executable, "-c", "pass"])
    with pytest.raises(AssertionError, match="network/process access attempted"):
        subprocess.run([sys.executable, "-c", "pass"], check=False)


def test_runtime_guard_control_tripwires_fire_on_first_touch(monkeypatch):
    plant_tripwires(monkeypatch)
    for name in TRIPWIRE_MODULES:
        module = importlib.import_module(name)
        with pytest.raises(AssertionError, match=f"forbidden module '{name}'"):
            module.client  # noqa: B018 - the attribute access IS the test
        with pytest.raises(AssertionError):
            _ = module.Session


def test_runtime_guard_is_fully_undone_after_use():
    original_connect = socket.socket.connect
    original_popen = subprocess.Popen
    original = {name: sys.modules.get(name) for name in TRIPWIRE_MODULES}
    with pytest.MonkeyPatch.context() as patch:
        block_network(patch)
        plant_tripwires(patch)
        assert subprocess.Popen is not original_popen
    assert socket.socket.connect is original_connect
    assert subprocess.Popen is original_popen
    assert {name: sys.modules.get(name) for name in TRIPWIRE_MODULES} == original


# ---------------------------------------------------------------------------------------------
# Fixture variants: full / legacy / empty / hostile
# ---------------------------------------------------------------------------------------------
HOSTILE = (
    '<img src="file:///etc/hostname"><font color="red">x</font> &lt;b&gt; \x00\u202e\U0001f600 '
    + "A" * 2000
)


def _ts(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _fold(scans: list[dict], *, team_id: int = 1, name: str = "E2E Demo Team"):
    heads = [
        ScanHead(
            id=s["id"],
            team_id=s["team_id"],
            scan_type=s["scan_type"],
            title=s["title"],
            status=s["status"],
            created_at=_ts(s["created_at"]),
            last_updated=_ts(s["last_updated"]),
            scan_metadata=s["scan_metadata"],
        )
        for s in scans
    ]
    blobs = {s["id"]: s["scan_data"] for s in scans}
    return fold_scans(
        heads,
        lambda ids: {i: blobs[i] for i in ids if i in blobs},
        team_id=team_id,
        team_name=name,
        now=NOW,
    )


def _team_one_scans() -> list[dict]:
    data = json.loads((FIXTURES / "cbom_team_rollup_scans.json").read_text(encoding="utf-8"))
    return [s for s in data["scans"] if s["team_id"] == 1 and s["scan_type"] == "cbom"]


def _make_hostile(scans: list[dict]) -> list[dict]:
    hostile = copy.deepcopy(scans)
    for scan in hostile:
        scan["title"] = scan["title"] + HOSTILE[:80]
        blob = scan["scan_data"]
        if not isinstance(blob, dict):
            continue
        for row in blob.get("results") or []:
            if isinstance(row, dict):
                row["title"] = str(row.get("title", "")) + HOSTILE[:120]
                row["location"] = str(row.get("location", "")) + HOSTILE[:120]
                row["description"] = HOSTILE
        components = (blob.get("cbom_json") or {}).get("components") or []
        for component in components:
            if not isinstance(component, dict):
                continue
            component["name"] = str(component.get("name", "")) + HOSTILE[:100]
            for prop in component.get("properties") or []:
                if prop.get("name") in {"crypto:subjectName", "crypto:issuerName"}:
                    prop["value"] = HOSTILE
    return hostile


def build_variants() -> dict:
    scans = _team_one_scans()
    legacy = [s for s in scans if s["id"] == 8]
    return {
        "full": _fold(scans),
        "legacy-only": _fold(legacy),
        "empty": _fold([], team_id=3, name="Empty Team"),
        "hostile": _fold(_make_hostile(scans), name=HOSTILE[:60]),
    }


_VARIANTS = build_variants()


def test_the_variants_are_what_their_names_say():
    full, legacy, empty, hostile = (
        _VARIANTS[k] for k in ("full", "legacy-only", "empty", "hostile")
    )
    assert (full.included, len(full.sources), full.fidelity_summary) == (8, 7, "mixed")
    assert (legacy.included, legacy.fidelity_summary) == (1, "reduced")
    assert empty.is_empty
    assert hostile.included == 8 and hostile.certs


@pytest.mark.parametrize("variant", sorted(_VARIANTS))
@pytest.mark.parametrize("slug", SLUGS)
def test_every_builder_runs_on_every_variant_under_the_runtime_guard(monkeypatch, variant, slug):
    from backend.utilities.pdf.cbom_deliverables import DELIVERABLES

    block_network(monkeypatch)
    plant_tripwires(monkeypatch)
    pdf = DELIVERABLES[slug].build(_VARIANTS[variant])
    assert isinstance(pdf, bytes) and pdf.startswith(b"%PDF-") and len(pdf) > 3000


def test_the_whole_http_flow_runs_under_the_runtime_guard(tmp_path, monkeypatch):
    """Manifest, six PDFs and three error paths through the real app, SQLite and real auth."""
    route_tests = importlib.import_module("backend.tests.test_cbom_deliverables_route")
    world = route_tests.build_world(tmp_path)
    block_network(monkeypatch)
    plant_tripwires(monkeypatch)
    api = route_tests.make_api(world, monkeypatch)
    try:
        manifest = api.get("/1/cbom/deliverables")
        assert manifest.status_code == 200
        assert [d["slug"] for d in manifest.json()["deliverables"]] == list(SLUGS)
        for slug in SLUGS:
            response = api.get(f"/1/cbom/deliverables/{slug}")
            assert response.status_code == 200, slug
            assert response.headers["content-type"] == "application/pdf"
            assert response.content.startswith(b"%PDF-")
        assert api.get("/1/cbom/deliverables/not-a-document").status_code == 404
        assert api.get("/1/cbom/deliverables", who="bob").status_code == 403
        assert api.get("/1/cbom/deliverables", who=None).status_code == 401
    finally:
        route_tests.routes.limiter.requests.clear()
