"""WP13: the opt-in "scan git history for keys" repository option, and CI/CD CBOM scans carrying
``include_vendored`` / ``scan_binaries`` from the integration's scan settings to the worker.

Both options are sent to the worker only when on, so a default scan's kwargs stay what an older worker accepts.
"""
from __future__ import annotations

import asyncio
import io
import zipfile

import pytest
from fastapi import UploadFile

from backend.utilities.cicd import format_input as cicd_format
from backend.utilities.cicd.schemas import CbomScanSettingsData, CicdScanSettingsData
from backend.utilities.db.metadata import get_scan_metadata_for_type
from backend.utilities.db.schemas import StartCBOMScanData, StartScanPayload
from backend.utilities.scan.format_input import format_input_for_scan

REPO = '"repo_context": {"mode": "github", "repo_url": "https://github.com/o/r", "PAT": ""}'


def _kwargs(payload_json: str) -> dict:
    payload = StartScanPayload.model_validate_json(payload_json)
    return asyncio.run(format_input_for_scan("cbom", payload))


# --- scan git history (repository scans) ------------------------------------------------------
def test_scan_history_defaults_off_and_is_not_sent() -> None:
    assert StartCBOMScanData(zip_file_used=True).scan_history is False
    kwargs = _kwargs(f'{{"cbom": {{{REPO}}}}}')
    assert "repo_dict_context" in kwargs and "scan_history" not in kwargs
    assert get_scan_metadata_for_type("cbom", StartScanPayload.model_validate_json(
        f'{{"cbom": {{{REPO}}}}}'))["scan_history"] is False


def test_scan_history_on_reaches_the_worker_kwargs_and_the_metadata() -> None:
    body = f'{{"cbom": {{{REPO}, "scan_history": true}}}}'
    assert _kwargs(body)["scan_history"] is True
    assert get_scan_metadata_for_type("cbom", StartScanPayload.model_validate_json(body))["scan_history"] is True


def test_scan_history_is_ignored_for_an_uploaded_archive(monkeypatch) -> None:
    from backend.utilities.scan import format_input as scan_format

    monkeypatch.setattr(scan_format, "upload_file", lambda _io, **_kw: {"bucket": "b", "object_name": "o"})
    payload = StartScanPayload.model_validate_json('{"cbom": {"zip_file_used": true, "scan_history": true}}')
    archive = io.BytesIO()  # a real archive: zip uploads are checked (test_zip_upload_must_be_zip.py)
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("main.py", "import hashlib\n")
    upload = UploadFile(file=io.BytesIO(archive.getvalue()), filename="x.zip")
    kwargs = asyncio.run(format_input_for_scan("cbom", payload, upload))
    assert "zip_dict_context" in kwargs and "scan_history" not in kwargs
    assert get_scan_metadata_for_type("cbom", payload)["scan_history"] is False


# --- CI/CD CBOM scan settings -------------------------------------------------------------------
def _ci_kwargs(monkeypatch, settings: dict | None) -> dict:
    monkeypatch.setattr(cicd_format, "upload_file", lambda _io, **_kw: {"bucket": "b", "object_name": "o"})

    async def _valid(_upload):
        return b"PK\x03\x04zip"

    monkeypatch.setattr(cicd_format, "validate_zip_file", _valid)
    upload = UploadFile(file=io.BytesIO(b"PK\x03\x04zip"), filename="ci.zip")
    return asyncio.run(cicd_format.format_cicd_input(scan_settings=settings, scan_type="cbom", uploaded_file=upload))


def test_ci_settings_model_carries_include_vendored_with_default_off() -> None:
    assert CbomScanSettingsData().include_vendored is False
    stored = CicdScanSettingsData(cbom=CbomScanSettingsData(include_vendored=True, scan_binaries=True)).model_dump()
    assert stored["cbom"] == {"scan_binaries": True, "include_vendored": True}


@pytest.mark.parametrize(
    ("settings", "expected"),
    [
        (None, {"scan_binaries": False}),
        ({"cbom": {"scan_binaries": False}}, {"scan_binaries": False}),  # settings saved before this option
        ({"cbom": {"scan_binaries": True, "include_vendored": False}}, {"scan_binaries": True}),
        ({"cbom": {"scan_binaries": False, "include_vendored": True}}, {"scan_binaries": False,
                                                                        "include_vendored": True}),
    ],
)
def test_ci_cbom_kwargs_carry_both_options(monkeypatch, settings, expected) -> None:
    kwargs = _ci_kwargs(monkeypatch, settings)
    assert kwargs.pop("zip_dict_context") == {"bucket_name": "b", "object_name": "o"}
    assert kwargs == expected
