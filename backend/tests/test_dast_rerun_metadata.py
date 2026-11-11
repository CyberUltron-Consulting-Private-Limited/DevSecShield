"""X1 M2 (Nov 11): a failed DAST scan had no "Run again"; the new button copies the failed scan's settings from
GET /{team}/dast/scan/{id} scan_metadata (frontend utils/dastRerun.ts).  That response carried the target URL, the
login form and the speed, but not the URL limit, the extra URLs or the include/exclude patterns, so a re-run lost
them.  They come back now; the password is never stored and never returned, whatever an older row holds."""
from __future__ import annotations

import json
import os
import sys
import types
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("GIT_ALLOWED_HOSTS", "")

from backend.utilities.dashboard.scan_metadata import get_scan_metadata  # noqa: E402
from backend.utilities.db.metadata import get_scan_metadata_for_type  # noqa: E402
from backend.utilities.db.schemas import StartScanPayload  # noqa: E402

PASSWORD = "Canary-x1-m2-Pa55word"
AUTH = {
    "login_url": "https://shop.example/login",
    "xpath_of_username_field": "//input[@name='user']",
    "xpath_of_password_field": "//input[@name='pass']",
    "username": "alice",
    "password": PASSWORD,
    "xpath_of_submit_button": "//button[@type='submit']",
}


def _payload() -> StartScanPayload:
    return StartScanPayload.model_validate({"dast": {
        "target_url": "https://shop.example", "auth": AUTH, "scan_speed": "slow", "max_urls": 250,
        "additional_urls_to_scan": ["https://shop.example/admin"], "exclude_url_patterns": ["/logout"],
    }})


def test_run_again_gets_every_start_option_back():
    stored = get_scan_metadata_for_type("dast", _payload())
    out = get_scan_metadata("dast", types.SimpleNamespace(scan_metadata=stored, scan_data={}))
    assert out["target_url"] == "https://shop.example" and out["scan_speed"] == "slow"
    assert out["max_urls"] == 250  # before: missing, a re-run fell back to 100
    assert out["additional_urls_to_scan"] == ["https://shop.example/admin"]
    assert out["exclude_url_patterns"] == ["/logout"] and out["include_url_patterns"] is None
    assert out["auth"] == {k: v for k, v in AUTH.items() if k != "password"}


def test_the_password_is_never_stored_or_returned():
    stored = get_scan_metadata_for_type("dast", _payload())
    assert PASSWORD not in json.dumps(stored)
    # an older row (or a profile run) that still holds a password, under any spelling
    legacy = dict(stored, auth=dict(AUTH, Password=PASSWORD, auth_token=PASSWORD))
    out = get_scan_metadata("dast", types.SimpleNamespace(scan_metadata=legacy, scan_data={}))
    assert PASSWORD not in json.dumps(out)
    assert out["auth"]["xpath_of_password_field"] == "//input[@name='pass']"  # the XPath is not a secret
