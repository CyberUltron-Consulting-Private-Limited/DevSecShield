"""A "zip file" scan upload that is not a zip archive is refused with 400 before anything is stored or queued.

Found on the local production stack (round 5, L1): scan-worker log "Error in cbom_estimation task: Error in
initializing CBOMAgent: Error in getting directory from zip context: File is not a zip file". The trigger is the
zip mode of format_input_for_scan (SAST, IaC, SCA + SBOM, CBOM, AI-BOM): any uploaded bytes were stored and passed
to the worker as a zip, so a CycloneDX JSON or tarball picked in zip mode failed only inside the worker task.

Run (repo root): backend/.venv/bin/python -m pytest backend/tests/test_zip_upload_must_be_zip.py -q -p no:cacheprovider
"""
import asyncio
import io
import zipfile

import pytest
from fastapi import HTTPException

from backend.utilities.db import schemas
from backend.utilities.scan import format_input


class Upload:
    def __init__(self, data: bytes):
        self.data = data

    async def read(self) -> bytes:
        return self.data


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("app.py", "import hashlib\nhashlib.md5(b'x')\n")
    return buf.getvalue()


def _cbom_payload() -> schemas.StartScanPayload:
    return schemas.StartScanPayload.model_validate({"cbom": {"zip_file_used": True}})


@pytest.mark.parametrize("data", [b'{"bomFormat": "CycloneDX", "specVersion": "1.6"}', b"\x1f\x8b\x08\x00tarball"])
def test_a_non_zip_upload_in_zip_mode_is_refused_before_storage(monkeypatch, data):
    stored = []
    monkeypatch.setattr(format_input, "upload_file", lambda *a, **k: stored.append(a) or {"bucket": "b", "object_name": "o"})
    with pytest.raises(HTTPException) as err:
        asyncio.run(format_input.format_input_for_scan(scan_type="cbom", start_scan_payload=_cbom_payload(),
                                                       uploaded_file=Upload(data)))
    assert err.value.status_code == 400 and "not a zip archive" in err.value.detail
    assert stored == []


def test_a_zip_upload_is_stored_and_passed_on(monkeypatch):
    monkeypatch.setattr(format_input, "upload_file", lambda *a, **k: {"bucket": "b", "object_name": "o"})
    kwargs = asyncio.run(format_input.format_input_for_scan(scan_type="cbom", start_scan_payload=_cbom_payload(),
                                                            uploaded_file=Upload(_zip_bytes())))
    assert kwargs["zip_dict_context"] == {"bucket_name": "b", "object_name": "o"}


def test_every_zip_mode_checks_the_archive():
    source = open(format_input.__file__).read()
    assert source.count("bytes_io_zip_file_object = BytesIO(uploaded_file_bytes)") == \
        source.count("_require_zip(uploaded_file_bytes)\n                    bytes_io_zip_file_object") == 5
