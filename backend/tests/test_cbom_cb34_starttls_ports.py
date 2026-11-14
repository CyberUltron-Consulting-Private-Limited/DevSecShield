"""CB-34: STARTTLS breadth.  The scan node speaks POP3 STLS, FTP AUTH TLS and XMPP StartTLS (client and
server-to-server streams) next to SMTP/submission, IMAP, LDAP, PostgreSQL and MySQL (scan_node tests:
test_starttls_breadth.py, real local servers).  The team's port list must accept them, and a new team's defaults
probe the two mail ports that answer STARTTLS without any setup (IMAP 143, POP3 110).  FTP and XMPP stay opt-in:
XMPP needs the server's XMPP domain, which the node takes from the team's SNI host names."""
from __future__ import annotations

import pytest
import test_cbom_sources_api as SA  # noqa: E402

from backend.utilities.cbom_sources import schemas, settings

api, world = SA.api, SA.world  # the shared fixtures (pytest finds them by name in this module)

NEW = ("starttls-pop3", "starttls-ftp", "starttls-xmpp", "starttls-xmpp-server")


@pytest.mark.parametrize("proto", NEW)
def test_the_port_list_accepts_each_new_starttls_protocol(proto):
    assert schemas.PortItem(port=110, protocol=proto).protocol == proto
    assert proto in settings.PORT_PROTOCOLS


def test_a_new_teams_defaults_probe_imap_and_pop3_starttls_but_not_ftp_or_xmpp():
    defaults = {(p["port"], p["protocol"]) for p in settings.DEFAULT_PORTS}
    assert {(143, "starttls-imap"), (110, "starttls-pop3")} <= defaults
    assert not any(p["protocol"] in ("starttls-ftp", "starttls-xmpp", "starttls-xmpp-server")
                   for p in settings.DEFAULT_PORTS)
    assert all(p["protocol"] in settings.PORT_PROTOCOLS for p in settings.DEFAULT_PORTS)
    assert len(settings.DEFAULT_PORTS) <= settings.MAX_PORTS


def test_a_team_saves_the_new_protocols_and_reads_them_back(api, world):
    ports = [{"port": 110, "protocol": "starttls-pop3", "label": "POP3 STLS"},
             {"port": 21, "protocol": "starttls-ftp", "label": "FTP AUTH TLS"},
             {"port": 5222, "protocol": "starttls-xmpp", "label": "XMPP"},
             {"port": 5269, "protocol": "starttls-xmpp-server", "label": "XMPP s2s"}]
    ok = api("PATCH", "/1/cbom/sources/settings", json={"ports": ports})
    assert ok.status_code == 200, ok.text
    saved = api("GET", "/1/cbom/sources/settings").json()["settings"]["ports"]
    assert [(p["port"], p["protocol"]) for p in saved] == [(p["port"], p["protocol"]) for p in ports]
    bad = api("PATCH", "/1/cbom/sources/settings", json={"ports": [{"port": 21, "protocol": "starttls-ftps"}]})
    assert bad.status_code in (400, 422)
