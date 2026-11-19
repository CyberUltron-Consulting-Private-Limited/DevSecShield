"""#443 follow-up (R-promo3 review of #442, findings 2 and 4).

#443 changed what a SAST exclude / IaC include path pattern means: before, a pattern's last name matched any name
STARTING with it ("k8s" also matched "k8s-prod", "test" also "tests"); now names are whole and "*" is a glob.
- Saved patterns kept their text, so "Run again" on an older scan (and a CI/CD integration saved before #443) would
  silently narrow IaC includes and loosen SAST excludes. They now come back as the glob that matches the same files
  ("k8s" -> "k8s*"), visibly; anything saved since stores "path_pattern_v" (no deploy-time cutoff, R-pp/R-pp2 of #468).
- The CI/CD settings page shows pre-#443 excludes translated, so saving it keeps what the integration skipped.
- An exclude made only of "*" / "**" removed every file and the scan analysed nothing. It is now refused when a scan
  starts, when CI/CD settings are saved, and when a CI/CD run reads older saved settings.
"""
from __future__ import annotations

import asyncio
import io
import os
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("GIT_ALLOWED_HOSTS", "")

from backend.utilities.cicd.schemas import SastScanSettingsData  # noqa: E402
from backend.utilities.dashboard.scan_metadata import rerun_options  # noqa: E402
from backend.utilities.db.schemas import StartSastScanData  # noqa: E402
from backend.utilities.scan.path_patterns import (  # noqa: E402
    PATH_PATTERN_VERSION, check_excludes, cicd_sast_excludes, cicd_settings_for_form, legacy_to_glob,
    matches_everything, saved_with_prefix_meaning)

NEW = {"path_pattern_v": PATH_PATTERN_VERSION}


@pytest.mark.parametrize("pattern", [["*"], ["**"], ["**", "*"], ["**/*"], [" ** "], ["*", "**", "***"]])
def test_a_pattern_of_only_stars_matches_everything(pattern):
    assert matches_everything(pattern)


@pytest.mark.parametrize("pattern", [["tests"], ["*.min.js"], ["**", "vendor"], ["src", "*"], [".tf"], [], [""], ["/"]])
def test_a_pattern_naming_something_does_not(pattern):
    assert not matches_everything(pattern)


@pytest.mark.parametrize("legacy, glob", [
    (["k8s"], ["k8s*"]),                    # matched k8s-prod/ before #443
    (["infra"], ["infra*"]),                # matched infrastructure/
    (["test"], ["test*"]),                  # SAST exclude: skipped tests/ before
    (["deploy/k8s"], ["deploy", "k8s*"]),   # one box "a/b": "/deploy/k8s" searched, so deploy was whole
    (["deploy", "k8s"], ["*deploy", "k8s*"]),       # two boxes: "deploy/k8s" unanchored, mydeploy/k8s-prod matched
    (["deploy", "k8s", "base"], ["*deploy", "k8s*"]),  # three or more: the old code dropped the last box
    ([".tf"], ["*.tf*"]),                   # the bare text anywhere: also prod.tfvars
    ([".min"], ["*.min*"]),                 # app.min.js
    (["charts*"], ["charts*"]),             # already a prefix
    (["src/"], ["src", "*"]),               # a trailing slash: src was a whole folder name (R-pp second pass)
    (["deploy", "k8s/"], ["*deploy", "k8s", "*"]),
    ([".tf/"], ["*.tf", "*"]),              # a folder name ending with .tf
    (["/deploy", "k8s"], ["deploy", "k8s*"]),  # a leading slash anchored the first name
    (["a//b"], []),                         # "//" never occurs in a path: matched nothing
    (["deploy", "/k8s"], []),
    ([], []),
])
def test_a_legacy_pattern_becomes_the_glob_matching_the_same_names(legacy, glob):
    assert legacy_to_glob(legacy) == glob


def test_starting_a_sast_scan_refuses_an_exclude_that_matches_every_file():
    with pytest.raises(ValidationError, match="matches every file"):
        StartSastScanData(app_lang="python", zip_file_used=True, exclude_path_arrays=[["tests"], ["**"]])
    ok = StartSastScanData(app_lang="python", zip_file_used=True, exclude_path_arrays=[["tests"], ["**", "*.min.js"]])
    assert ok.exclude_path_arrays == [["tests"], ["**", "*.min.js"]]


def test_saving_cicd_sast_settings_refuses_it_and_records_the_pattern_version():
    with pytest.raises(ValidationError, match="matches every file"):
        SastScanSettingsData(app_lang="python", exclude_path_arrays=[["*"]])
    saved = SastScanSettingsData(app_lang="python", exclude_path_arrays=[["test"]]).model_dump()
    assert saved["path_pattern_v"] == PATH_PATTERN_VERSION


def test_a_cicd_run_translates_settings_saved_before_443_and_keeps_newer_ones():
    assert cicd_sast_excludes({"exclude_path_arrays": [["test"], ["deploy", "k8s"]]}) == [["test*"], ["*deploy", "k8s*"]]
    assert cicd_sast_excludes({"exclude_path_arrays": [["test"]], "path_pattern_v": PATH_PATTERN_VERSION}) == [["test"]]
    assert cicd_sast_excludes({"app_lang": "python"}) is None
    with pytest.raises(ValueError, match="matches every file"):
        cicd_sast_excludes({"exclude_path_arrays": [["**"]], "path_pattern_v": PATH_PATTERN_VERSION})


def test_which_saved_patterns_have_the_prefix_meaning():
    assert saved_with_prefix_meaning({})
    assert saved_with_prefix_meaning(None)
    assert saved_with_prefix_meaning({"path_pattern_v": 1})
    assert not saved_with_prefix_meaning(NEW)


def test_run_again_on_an_older_sast_scan_shows_the_translated_excludes():
    meta = {"app_lang": "python", "exclude_path_arrays": [["test"], [".min.js"]]}
    assert rerun_options("sast", meta)["exclude_path_arrays"] == [["test*"], ["*.min.js*"]]
    assert rerun_options("sast", meta)["path_patterns_rewritten"] is True  # the notice explains the rewrite
    newer = rerun_options("sast", {**meta, **NEW})
    assert newer["exclude_path_arrays"] == [["test"], [".min.js"]] and "path_patterns_rewritten" not in newer
    unchanged = rerun_options("sast", {"app_lang": "python", "exclude_path_arrays": [["tests*"]]})
    assert "path_patterns_rewritten" not in unchanged  # nothing to explain


def test_run_again_on_an_older_iac_scan_shows_the_translated_includes():
    meta = {"environment": "staging", "iac_contexts": [
        {"mode": "k8s", "include_path_arrays": [["k8s"], ["deploy/charts"]]},
        {"mode": "terraform", "include_path_arrays": []}]}
    out = rerun_options("iac", meta)["iac_contexts"]
    assert out[0] == {"mode": "k8s", "include_path_arrays": [["k8s*"], ["deploy", "charts*"]]}
    assert out[1] == {"mode": "terraform", "include_path_arrays": []}
    assert meta["iac_contexts"][0]["include_path_arrays"] == [["k8s"], ["deploy/charts"]]  # stored row untouched
    assert rerun_options("iac", {**meta, **NEW})["iac_contexts"][0]["include_path_arrays"] == [["k8s"], ["deploy/charts"]]
    # a context without includes is left as it is: no rewrite, no "rewritten" flag (R-pp2 second pass)
    bare = rerun_options("iac", {"iac_contexts": [{"mode": "k8s"}, {"mode": "helm", "include_path_arrays": None}]})
    assert bare["iac_contexts"] == [{"mode": "k8s"}, {"mode": "helm", "include_path_arrays": None}]
    assert "path_patterns_rewritten" not in bare


def test_the_cicd_settings_page_shows_older_excludes_translated():
    """Saving the page records the version, so it must show (and save back) what the excludes meant (R-pp2 #2)."""
    stored = {"sast": {"app_lang": "python", "exclude_path_arrays": [["test"]]}, "cbom": {"scan_binaries": True}}
    shown = cicd_settings_for_form(stored)
    assert shown["sast"]["exclude_path_arrays"] == [["test*"]]
    assert shown["cbom"] == {"scan_binaries": True}
    assert stored["sast"]["exclude_path_arrays"] == [["test"]]  # the row is not changed
    newer = {"sast": {"app_lang": "python", "exclude_path_arrays": [["test"]], **NEW}}
    assert cicd_settings_for_form(newer) == newer
    assert cicd_settings_for_form(None) == {}
    # saving what the page showed keeps the meaning: the run uses test* both before and after the save
    resaved = SastScanSettingsData(**{k: v for k, v in shown["sast"].items()}).model_dump()
    assert cicd_sast_excludes(stored["sast"]) == cicd_sast_excludes(resaved) == [["test*"]]


def test_the_client_cannot_set_the_pattern_version():
    saved = SastScanSettingsData(app_lang="python", exclude_path_arrays=[["test"]], path_pattern_v=1).model_dump()
    assert saved["path_pattern_v"] == PATH_PATTERN_VERSION


def test_a_refused_cicd_run_is_a_400_before_the_zip_is_stored(monkeypatch):
    """R-pp #4: the broad except turned the 400 into a 500, after the upload."""
    from fastapi import HTTPException
    from backend.utilities.cicd import format_input

    async def ok_zip(_upload):
        return b"PK\x03\x04"
    monkeypatch.setattr(format_input, "validate_zip_file", ok_zip)
    monkeypatch.setattr(format_input, "upload_file", lambda *_: pytest.fail("the zip was stored"))
    with pytest.raises(HTTPException) as refused:
        asyncio.run(format_input.format_cicd_input(
            scan_settings={"sast": {"app_lang": "python", "exclude_path_arrays": [["**"]], **NEW}},
            scan_type="sast", uploaded_file=io.BytesIO(b"")))
    assert refused.value.status_code == 400 and "matches every file" in refused.value.detail


def test_check_excludes_accepts_none_and_empty():
    check_excludes(None)
    check_excludes([])


def test_the_cicd_integration_route_returns_the_settings_as_the_form_shows_them():
    """The GET the settings page reads goes through cicd_settings_for_form (R-pp second pass, nit 4)."""
    route = (_REPO_ROOT / "backend" / "routers" / "cicd.py").read_text(encoding="utf-8")
    assert '"scan_settings": cicd_settings_for_form(integration.scan_settings)' in route
    assert '"scan_settings": integration.scan_settings' not in route
