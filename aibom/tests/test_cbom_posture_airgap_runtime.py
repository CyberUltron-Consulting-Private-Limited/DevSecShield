"""A posture scan must not open a socket or start a process."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from support.airgap import NetworkBlocked, block_network  # noqa: E402


def test_scan_crypto_runs_while_the_network_is_blocked(tmp_path: Path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "main.tf").write_text(
        'resource "aws_db_instance" "plain" {\n  storage_encrypted = false\n}\n',
        encoding="utf-8",
    )
    with block_network():
        result = scan_crypto(tmp_path)
    facts = [
        comp
        for comp in result.components
        if (comp.properties or {}).get("crypto:factSchema") == "1"
    ]
    assert facts


def test_a_socket_inside_the_guard_is_caught() -> None:
    import socket

    with block_network(), pytest.raises(NetworkBlocked):
        socket.socket()


def test_a_process_inside_the_guard_is_caught() -> None:
    import os

    with block_network(), pytest.raises(NetworkBlocked):
        os.system("true")
