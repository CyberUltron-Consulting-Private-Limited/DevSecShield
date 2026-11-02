"""The CBOM "scan vendored and build directories" option: off by default, carried into the scan metadata."""
from __future__ import annotations

from backend.utilities.db.metadata import get_scan_metadata_for_type
from backend.utilities.db.schemas import StartCBOMScanData, StartScanPayload


def test_include_vendored_defaults_off() -> None:
    data = StartCBOMScanData(zip_file_used=True)
    assert data.include_vendored is False


def test_include_vendored_round_trips_into_scan_metadata() -> None:
    payload = StartScanPayload.model_validate_json(
        '{"cbom": {"zip_file_used": true, "include_vendored": true}}'
    )
    assert payload.cbom is not None and payload.cbom.include_vendored is True
    meta = get_scan_metadata_for_type("cbom", payload)
    assert meta["include_vendored"] is True


def test_old_payload_without_the_field_still_validates() -> None:
    payload = StartScanPayload.model_validate_json('{"cbom": {"zip_file_used": true, "scan_binaries": false}}')
    assert get_scan_metadata_for_type("cbom", payload)["include_vendored"] is False
