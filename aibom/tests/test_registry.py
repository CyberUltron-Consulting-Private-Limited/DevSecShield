"""Registry seams: self-registering scanners + stateless reporter registry."""

from __future__ import annotations

import pytest

import aibom.emit  # noqa: F401  (import populates the reporter registry)
import aibom.scan.scanners  # noqa: F401  (import populates the scanner registry)
from aibom.emit.registry import BaseReporter, available_formats, get_reporter
from aibom.scan.registry import SCANNERS, Scanner, ordered_scanners


def test_two_scanners_registered() -> None:
    names = {s.name for s in SCANNERS}
    assert {"requirements", "model-repo"} <= names
    assert all(isinstance(s, Scanner) for s in SCANNERS)


def test_scanner_order_is_explicit_not_import_order() -> None:
    """Framework producer must run before the model-repo linker."""
    ordered = [s.name for s in ordered_scanners()]
    assert ordered.index("requirements") < ordered.index("model-repo")


def test_three_reporters_registered() -> None:
    assert set(available_formats()) == {"cyclonedx", "spdx", "sarif"}
    for fmt in available_formats():
        reporter = get_reporter(fmt)
        assert isinstance(reporter, BaseReporter)
        assert reporter.format == fmt


def test_unknown_format_raises() -> None:
    with pytest.raises(KeyError):
        get_reporter("nope")
