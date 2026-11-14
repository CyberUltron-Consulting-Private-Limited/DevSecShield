"""CB-09: the scan node reads host names as IDNA 2008 (UTS #46 non-transitional) A-labels, as the backend stores them.

Before, ``socket.getaddrinfo``, Python ``ssl`` and the hand-built ClientHello encoded a Unicode name with Python's
IDNA 2003 codec (``faß.lab`` -> ``fass.lab``, a different host), and ``NeverScan`` compared names as typed, so a
listed ``bücher.example`` did not block ``xn--bcher-kva.example``.
"""
from __future__ import annotations

import socket
import subprocess

import pytest

from zs_scan_node import netutil
from zs_scan_node import tlsprobe as T
from zs_scan_node.netutil import Blocked, NeverScan, expand_targets, resolve_checked


def test_never_scan_compares_a_labels_both_ways():
    assert NeverScan(["bücher.example"]).blocks_host("xn--bcher-kva.example")
    assert NeverScan(["xn--bcher-kva.example"]).blocks_host("bücher.example")
    assert NeverScan(["Bücher.Example."]).blocks_host("BÜCHER.example")
    assert not NeverScan(["bücher.example"]).blocks_host("bucher.example")


def test_never_scan_of_a_deviation_name_keeps_its_idna_2003_form_out_too():
    assert NeverScan(["xn--fa-hia.lab"]).blocks_host("fass.lab")  # what IDNA 2003 software calls faß.lab
    assert NeverScan(["faß.lab"]).blocks_host("fass.lab")
    assert NeverScan(["fass.lab"]).blocks_host("xn--fa-hia.lab")
    assert not NeverScan(["fass.lab"]).blocks_host("xn--bcher-kva.lab")


def test_resolution_asks_for_the_idna_2008_name(monkeypatch):
    asked: list[str] = []

    def fake(name, *_a, **_k):
        asked.append(name)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.45", 0))]

    monkeypatch.setattr(netutil.socket, "getaddrinfo", fake)
    assert netutil.resolve("faß.lab") == ["10.0.0.45"]
    assert resolve_checked("Faß.lab", NeverScan([])) == ["10.0.0.45"]
    targets, skipped = expand_targets(["faß.lab"], NeverScan([]))
    assert asked == ["xn--fa-hia.lab"] * 3
    assert [t.label for t in targets] == ["xn--fa-hia.lab"] and skipped == []


def test_a_name_listed_by_its_unicode_form_is_not_looked_up_or_scanned(monkeypatch):
    monkeypatch.setattr(netutil.socket, "getaddrinfo", lambda *a, **k: pytest.fail("a listed name was looked up"))
    with pytest.raises(Blocked):
        resolve_checked("xn--bcher-kva.example", NeverScan(["bücher.example"]))
    targets, skipped = expand_targets(["fass.lab"], NeverScan(["faß.lab"]))
    assert targets == [] and skipped == ["fass.lab"]


def test_a_name_with_a_zero_width_joiner_is_refused_without_a_lookup(monkeypatch):
    monkeypatch.setattr(netutil.socket, "getaddrinfo", lambda *a, **k: pytest.fail("refused name was looked up"))
    with pytest.raises(OSError, match="zero-width"):
        resolve_checked("a‍b.lab", NeverScan([]))
    targets, _skipped = expand_targets(["a‍b.lab"], NeverScan([]))
    assert targets[0].ip is None and "zero-width" in targets[0].error


def test_the_client_hello_carries_the_idna_2008_sni():
    hello = T.build_client_hello(T.TLS12, [0xC02F], sni="faß.lab")
    assert b"xn--fa-hia.lab" in hello and b"fass.lab" not in hello


def test_openssl_and_python_ssl_get_the_idna_2008_sni(monkeypatch):
    seen: dict = {}

    def fake_run(cmd, **_kwargs):
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 1, b"", b"")

    monkeypatch.setattr(T.subprocess, "run", fake_run)
    T.s_client("10.0.0.45", 443, "tls", "faß.lab")
    assert seen["cmd"][seen["cmd"].index("-servername") + 1] == "xn--fa-hia.lab"

    class _Ctx:
        def __init__(self, *_a):
            self.check_hostname, self.verify_mode = False, None

        def set_ciphers(self, *_a):
            pass

        def wrap_socket(self, sock, server_hostname=None):
            seen["server_hostname"] = server_hostname
            raise OSError("stop here")

    class _Sock:
        def settimeout(self, *_a):
            pass

        def close(self):
            pass

    monkeypatch.setattr(T.ssl, "SSLContext", _Ctx)
    monkeypatch.setattr(T, "open_tls_socket", lambda *a, **k: (_Sock(), None))
    T.python_handshake("10.0.0.45", 443, "tls", "faß.lab")
    assert seen["server_hostname"] == "xn--fa-hia.lab"
