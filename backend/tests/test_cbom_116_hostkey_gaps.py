"""#116: the Linux source's host-key coverage notes ("ssh host keys", "ssh host keys: <path>") can only have missed
ssh_host_key rows.  Without a NODE_CHECK_TYPES entry a note covers the whole target, so one refused HostKey line
would stop every asset of that server from ever being reported removed or resolved."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from backend.utilities.cbom_sources import drift as D


def test_host_key_notes_cover_only_host_keys():
    for check in ("ssh host keys", "ssh host keys: HostKey relative/key", "ssh host keys: /srv/hidden.pub",
                  "ssh host keys: Include /opt/sshd/extra.conf", "ssh host keys: Include"):
        assert D._node_check_types(check) == (("ssh_host_key",), False), check


def test_other_checks_are_unchanged():
    assert D._node_check_types("sshd configuration") == (("ssh_server_config",), True)
    assert D._node_check_types("listening_sockets") is None
