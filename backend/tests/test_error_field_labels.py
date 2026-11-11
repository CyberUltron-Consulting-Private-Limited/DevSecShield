"""X1 (Nov 11): a refused CBOM source or integration said "config.hosts: ..." or "config.Line 1: ..." (the request
path of the field, with an internal "config." prefix) instead of the field's name as the form shows it. Errors now
name the field by its label ("Hosts: ...", "URL: ...") and a whole-form error has no prefix at all."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "p1-labels-secret-not-for-production-use")

from backend.routers.cbom_sources import _validate_config  # noqa: E402
from backend.utilities.cbom_sources.http import field_label, format_errors  # noqa: E402


@pytest.mark.parametrize("loc, msg, out", [
    (("body", "config", "hosts"), "Value error, Line 1: 'x!!' is not a host", "Hosts: Line 1: 'x!!' is not a host"),
    (("body", "config", "url"), "must be https", "URL: must be https"),
    (("body", "config", "ports", 0), "too big", "Ports: too big"),
    (("body", "config"), "Value error, Line 1: bad", "Line 1: bad"),
    (("body", "ssh_port"), "too big", "Ssh port: too big"),
])
def test_errors_name_the_field_by_its_label(loc, msg, out):
    assert format_errors([{"loc": loc, "msg": msg}]) == out


def test_labels():
    assert field_label("proxy_ca_pem") == "Proxy CA certificate" and field_label("max_hosts") == "Max hosts"


def test_a_refused_server_source_has_no_config_prefix():
    with pytest.raises(HTTPException) as info:
        _validate_config("linux_servers", {"hosts": "not a host!!"})
    assert info.value.status_code == 400
    assert not info.value.detail.lower().startswith("config"), info.value.detail  # before: "config.Line 1: ..."
    assert "config." not in info.value.detail
