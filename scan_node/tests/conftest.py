"""Shared fixtures for the scan node tests."""
from __future__ import annotations

import pytest

from zs_scan_node import netutil


@pytest.fixture(autouse=True)
def _fresh_never_scan_resolver(monkeypatch):
    """The node looks up never-scan host names on one resolver per process (netutil.name_resolver).  Each test gets
    its own, so an answer one test's fake DNS gave is never what another test sees; its threads are stopped after."""
    make = getattr(netutil, "NameResolver", None)
    if make is None:  # code from before the node-wide resolver (used to show new tests failing first)
        yield
        return
    resolver = make()
    monkeypatch.setattr(netutil, "_RESOLVER", resolver)
    yield
    resolver.close()
