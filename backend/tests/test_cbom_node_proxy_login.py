"""#199: a scan node behind a proxy that needs a login. ZeroShield stores the proxy user name only (``proxy_user``);
the password stays on the node's host (``ZS_PROXY_AUTH_FILE``, created by the install command with ``read -s``),
so it is never sent to ZeroShield, stored, returned or logged. A proxy URL with a login inside is still refused, and
the refusal now says where the login goes instead of only "must not contain a user name or password".

Real routers on SQLite (the harness of test_cbom_sources_api.py).
"""
from __future__ import annotations

import pytest

from tests import test_cbom_sources_api as H

api, world = H.api, H.world  # the harness's fixtures: SQLite + real routers + real JWTs
SECRET = "Pr0xy-s3cret"


def _node(api, **extra):
    return api("POST", "/1/cbom/sources/nodes", json={"name": "dc-proxy-01", "segment": "Data centre",
                                                      "proxy_url": "http://proxy.bank.local:8080", **extra})


def test_199_the_proxy_user_is_stored_and_shown(api, world):
    r = _node(api, proxy_user="svc-zs")
    assert r.status_code == 201, r.text  # dev: 400 (no such field)
    node = r.json()["node"]
    assert node["proxy_user"] == "svc-zs" and node["proxy_url"] == "http://proxy.bank.local:8080"
    listed = api("GET", "/1/cbom/sources/nodes").json()
    assert [n["proxy_user"] for n in listed["nodes"]] == ["svc-zs"]
    edited = api("PATCH", f"/1/cbom/sources/nodes/{node['id']}", json={"proxy_user": "svc-zs2"})
    assert edited.status_code == 200, edited.text
    assert edited.json()["node"]["proxy_user"] == "svc-zs2"
    cleared = api("PATCH", f"/1/cbom/sources/nodes/{node['id']}", json={"proxy_user": None})
    assert cleared.json()["node"]["proxy_user"] is None


def test_199_a_login_in_the_proxy_url_is_refused_and_says_where_it_goes(api, world, capsys):
    r = api("POST", "/1/cbom/sources/nodes", json={"name": "dc-proxy-02",
                                                   "proxy_url": f"http://svc-zs:{SECRET}@proxy.bank.local:8080"})
    assert r.status_code == 400
    detail = r.json()["detail"]
    assert "Proxy user" in detail and "stays on the scan node" in detail  # dev: "...must not contain a user name..."
    assert SECRET not in r.text and SECRET not in capsys.readouterr().out


def test_199_a_password_is_never_accepted(api, world, capsys):
    r = _node(api, proxy_user="svc-zs", proxy_password=SECRET)
    assert r.status_code == 400 and SECRET not in r.text and SECRET not in capsys.readouterr().out


@pytest.mark.parametrize("user", ["svc:zs", "svc zs", "", "a" * 129, "svc\nzs", "svc'zs", "svc$zs"])
def test_199_a_proxy_user_that_would_break_the_login_line_or_the_command_is_refused(api, world, user):
    r = _node(api, proxy_user=user)
    assert r.status_code == 400, (user, r.text)
    assert "Proxy user" in r.json()["detail"]


def test_199_a_domain_user_is_accepted(api, world):
    r = _node(api, proxy_user="CORP\\svc-zs")
    assert r.status_code == 201, r.text
    assert r.json()["node"]["proxy_user"] == "CORP\\svc-zs"
