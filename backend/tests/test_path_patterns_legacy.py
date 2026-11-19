"""#443 follow-up (R-promo3 review of #442, findings 2 and 4).

#443 changed what a SAST exclude / IaC include path pattern means: before, a pattern's last name matched any name
STARTING with it ("k8s" also matched "k8s-prod", "test" also "tests"); now names are whole and "*" is a glob.
- Saved patterns kept their text, so "Run again" on an older scan (and a CI/CD integration saved before #443) would
  silently narrow IaC includes and loosen SAST excludes. They now come back as the glob that matches the same files
  ("k8s" -> "k8s*"), visibly; scans started since store "path_pattern_v".
- An exclude made only of "*" / "**" removed every file and the scan analysed nothing. It is now refused when a scan
  starts, when CI/CD settings are saved, and when a CI/CD run reads older saved settings.
"""
from __future__ import annotations

import datetime
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
    GLOB_MEANING_SINCE, PATH_PATTERN_VERSION, check_excludes, cicd_sast_excludes, legacy_to_glob,
    matches_everything, saved_with_prefix_meaning)

BEFORE = GLOB_MEANING_SINCE - datetime.timedelta(days=3)
AFTER = GLOB_MEANING_SINCE + datetime.timedelta(hours=1)


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
    (["deploy", "k8s"], ["deploy", "k8s*"]),
    (["deploy/k8s"], ["deploy", "k8s*"]),   # a box holding "a/b" is two names
    ([".tf"], [".tf"]),                     # ".ext" already means "names ending with"
    (["charts*"], ["charts*"]),             # already a prefix
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
    assert cicd_sast_excludes({"exclude_path_arrays": [["test"], ["deploy", "k8s"]]}) == [["test*"], ["deploy", "k8s*"]]
    assert cicd_sast_excludes({"exclude_path_arrays": [["test"]], "path_pattern_v": PATH_PATTERN_VERSION}) == [["test"]]
    assert cicd_sast_excludes({"app_lang": "python"}) is None
    with pytest.raises(ValueError, match="matches every file"):
        cicd_sast_excludes({"exclude_path_arrays": [["**"]], "path_pattern_v": PATH_PATTERN_VERSION})


def test_which_saved_scans_have_the_prefix_meaning():
    assert saved_with_prefix_meaning({}, BEFORE)
    assert saved_with_prefix_meaning({}, BEFORE.replace(tzinfo=None))     # DateTime columns are naive UTC
    assert saved_with_prefix_meaning({}, None)                             # unknown start: an old row
    assert not saved_with_prefix_meaning({}, AFTER)                        # glob meaning already deployed
    assert not saved_with_prefix_meaning({"path_pattern_v": PATH_PATTERN_VERSION}, BEFORE)


def test_run_again_on_an_older_sast_scan_shows_the_translated_excludes():
    meta = {"app_lang": "python", "exclude_path_arrays": [["test"], [".min.js"]]}
    assert rerun_options("sast", meta, BEFORE)["exclude_path_arrays"] == [["test*"], [".min.js"]]
    assert rerun_options("sast", meta, AFTER)["exclude_path_arrays"] == [["test"], [".min.js"]]
    assert rerun_options("sast", {**meta, "path_pattern_v": 2}, BEFORE)["exclude_path_arrays"] == [["test"], [".min.js"]]


def test_run_again_on_an_older_iac_scan_shows_the_translated_includes():
    meta = {"environment": "staging", "iac_contexts": [
        {"mode": "k8s", "include_path_arrays": [["k8s"], ["deploy", "charts"]]},
        {"mode": "terraform", "include_path_arrays": []}]}
    out = rerun_options("iac", meta, BEFORE)["iac_contexts"]
    assert out[0] == {"mode": "k8s", "include_path_arrays": [["k8s*"], ["deploy", "charts*"]]}
    assert out[1] == {"mode": "terraform", "include_path_arrays": []}
    assert meta["iac_contexts"][0]["include_path_arrays"] == [["k8s"], ["deploy", "charts"]]  # stored row untouched
    assert rerun_options("iac", meta, AFTER)["iac_contexts"][0]["include_path_arrays"] == [["k8s"], ["deploy", "charts"]]


def test_check_excludes_accepts_none_and_empty():
    check_excludes(None)
    check_excludes([])
