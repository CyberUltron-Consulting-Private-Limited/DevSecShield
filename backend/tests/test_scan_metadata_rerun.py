"""Lab UI r1 F4: "Run again" on a failed SAST scan (language Python) opened the new scan with "Select language".
GET /{team}/{type}/scan/{id} returned scan_metadata without the options utilities/db/metadata.py stores (app_lang,
exclude_path_arrays, repo_type; environment, iac_contexts; include_vendored, scan_history; sbom_file_used), so
frontend utils/scanRerun.ts rerunPrefill found nothing.  The stored, non-secret options now come back for all five
code scan types; a repository token never does, whatever an older row holds.

Browser check after a rebuild: r1 bin/run scan_meta.js (scan_metadata of the failed SAST scan) and run_again.js
(the new scan's language shows Python)."""
from __future__ import annotations

import json
import os
import re
import sys
import types
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("GIT_ALLOWED_HOSTS", "")

from backend.utilities.dashboard.scan_metadata import get_scan_metadata, rerun_options  # noqa: E402
from backend.utilities.db.metadata import get_scan_metadata_for_type  # noqa: E402
from backend.utilities.db.schemas import StartScanPayload  # noqa: E402

PAT = "glpat-Canary-r1-f4-0123456789"
CODE_TYPES = ("sast", "iac", "sbom_sca", "cbom", "ai_bom")


def _scan(meta, data=None):
    return types.SimpleNamespace(scan_metadata=meta, scan_data=data or {})


def _payload(scan_type: str) -> StartScanPayload:
    repo = {"mode": "gitlab", "repo_url": "https://gitlab.com/acme/payments", "PAT": PAT, "branch": "release"}
    body = {
        "sast": {"repo_context": repo, "app_lang": "python", "exclude_path_arrays": [["vendor"], ["tests", "fixtures"]]},
        "iac": {"repo_context": repo, "environment": "production",
                "iac_contexts": [{"mode": "terraform", "include_path_arrays": [["envs", "prod"]]}]},
        "sbom_sca": {"repo_context": repo},
        "cbom": {"repo_context": repo, "scan_binaries": True, "include_vendored": True, "scan_history": True},
        "ai_bom": {"repo_context": repo, "scan_binaries": True},
    }[scan_type]
    return StartScanPayload.model_validate({scan_type: body})


def _frontend_option_keys() -> dict[str, list[str]]:
    """OPTION_KEYS of frontend utils/scanRerun.ts: what Run again copies into the new scan's sidebar."""
    src = (_REPO_ROOT / "frontend" / "utils" / "scanRerun.ts").read_text()
    block = src[src.index("const OPTION_KEYS"):]
    block = block[:block.index("};")]
    return {m.group(1): re.findall(r'"([a-z_]+)"', m.group(2)) for m in re.finditer(r"(\w+): \[([^\]]*)\]", block)}


@pytest.mark.parametrize("scan_type", CODE_TYPES)
def test_get_returns_what_run_again_copies(scan_type):
    stored = get_scan_metadata_for_type(scan_type, _payload(scan_type))  # what the start stored
    out = get_scan_metadata(scan_type, _scan(stored))  # what GET /{team}/{type}/scan/{id} returns
    assert out["repo_type"] == "gitlab" and out["repo_url"] == "https://gitlab.com/acme/payments"
    assert out["branch"] == "release"
    for key in _frontend_option_keys()[scan_type]:  # before: app_lang, environment, iac_contexts ... missing
        assert key in out and out[key] == stored[key], key
    assert PAT not in json.dumps(out, default=str)


def test_sast_language_and_exclusions_come_back():
    out = get_scan_metadata("sast", _scan(get_scan_metadata_for_type("sast", _payload("sast"))))
    assert out["app_lang"] == "python" and out["exclude_path_arrays"] == [["vendor"], ["tests", "fixtures"]]


def test_an_sbom_file_scan_says_so():  # Run again asks for the SBOM file again, not a repository token
    out = get_scan_metadata("sbom_sca", _scan({"zip_file_used": False, "sbom_file_used": True}))
    assert out["sbom_file_used"] is True


@pytest.mark.parametrize("scan_type", CODE_TYPES)
def test_no_secret_is_ever_returned(scan_type):
    secrets = {"PAT": "ghp_SECRET1", "pat": "SECRET2", "token": "SECRET3", "access_token": "SECRET4",
               "password": "SECRET5", "api_key": "SECRET6", "client_secret": "SECRET7", "headers": {"x": "SECRET8"},
               "repo_context": {"mode": "github", "PAT": "SECRET9"}}
    meta = {**get_scan_metadata_for_type(scan_type, _payload(scan_type)), **secrets,
            "iac_contexts": [{"mode": "terraform", "include_path_arrays": [], "auth_token": "SECRET10"}],
            "exclude_path_arrays": [["src"]]}
    out = json.dumps(get_scan_metadata(scan_type, _scan(meta)), default=str)
    for n in range(1, 11):
        assert f"SECRET{n}" not in out, n
    assert PAT not in out
    leaked = {k for k in ("PAT", "pat", "token", "password", "api_key", "headers", "repo_context")
              if f'"{k}"' in out}
    assert not leaked


def test_rerun_options_never_names_a_secret_key():
    assert rerun_options("sast", {"app_lang": "java", "PAT": "x"}) == {"repo_type": None, "app_lang": "java",
                                                                       "exclude_path_arrays": None}
    assert rerun_options("dast", {"auth": {"password": "x"}}) == {}
