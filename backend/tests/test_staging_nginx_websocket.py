"""The staging nginx passes WebSocket upgrades through (owner's guide item 1: a Next.js dev server's
/_next/webpack-hmr needs it; production pages do not, but an upgrade must never be silently dropped).

Proven live on Nov 11 with nginx:1.27-alpine in front of a stub upstream: the old template answered 200 to an
Upgrade request (headers stripped), the new one 101 Switching Protocols; plain requests still reach the upstream
with no Connection header, so keep-alive is unchanged."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

NGINX = Path(__file__).resolve().parents[2] / "deploy" / "staging" / "nginx"


@pytest.mark.parametrize("name", ["http.conf.template", "https.conf.template"])
def test_every_proxied_location_forwards_websocket_upgrades(name):
    text = (NGINX / name).read_text()
    assert re.search(r"map \$http_upgrade \$connection_upgrade \{\s*default upgrade;\s*''\s+'';\s*\}", text), name
    locations = re.findall(r"location / \{(.*?)\n    \}", text, flags=re.S)
    proxied = [body for body in locations if "proxy_pass" in body]
    assert len(proxied) == 2, name  # frontend and API
    for body in proxied:
        assert "proxy_http_version 1.1;" in body
        assert "proxy_set_header Upgrade $http_upgrade;" in body
        assert "proxy_set_header Connection $connection_upgrade;" in body
    assert 'proxy_set_header Connection "";' not in text  # the old header stripped every upgrade
