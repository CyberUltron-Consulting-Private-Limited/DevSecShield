"""Context guard and the plain-ScanContext refusal."""

from pathlib import Path

from aibom.cbom.posture.context import CbomScanContext, posture_sink
from aibom.scan.registry import ScanContext


class SoftTimeLimitExceeded(Exception):
    pass


def test_plain_scan_context_is_refused(tmp_path: Path) -> None:
    try:
        posture_sink(ScanContext(tmp_path))
    except TypeError:
        return
    raise AssertionError("expected TypeError")


def test_guard_reraises_time_limits_by_class_name(tmp_path: Path) -> None:
    sink = CbomScanContext(tmp_path).posture
    try:
        with sink.guard("posture_iac"):
            raise SoftTimeLimitExceeded("stop")
    except SoftTimeLimitExceeded:
        return
    raise AssertionError("time limit was swallowed")


def test_guard_records_internal_error(tmp_path: Path) -> None:
    sink = CbomScanContext(tmp_path).posture
    with sink.guard("posture_iac"):
        raise RuntimeError("boom")
    assert "posture_iac" in sink.failed_lanes
    assert sink.diagnostics.totals["internal_error"] == 1
