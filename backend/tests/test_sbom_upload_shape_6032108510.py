"""Review 6032108510 (PR #489, second review) m4: an uploaded SBOM file of the wrong shape is
refused by the API with 422 and a plain reason, before it is stored or queued.

Before: format_input.py only checked "is JSON" and 50 MB, so ``{"spdxVersion": "SPDX-2.3",
"packages": 5}`` was stored, queued and failed in the worker with "'int' object is not
iterable". The reviewer's hostile set (qa/489b/spdx-hostile.json) is reproduced here.

Run (repo root): backend/.venv/bin/python -m pytest backend/tests/test_sbom_upload_shape_6032108510.py -q
"""
import asyncio
import io
import json

import pytest
from fastapi import HTTPException, UploadFile

from backend.utilities.db.schemas import StartSBOMScanData, StartScanPayload
from backend.utilities.scan import format_input

SPDX2 = {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "d",
         "packages": [{"SPDXID": "SPDXRef-a", "name": "a", "versionInfo": "1"}]}
SPDX3 = {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": []}
CDX = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}


@pytest.fixture
def uploads(monkeypatch):
    stored = []
    monkeypatch.setattr(format_input, "upload_file",
                        lambda f, extension=".zip": stored.append(f.read()) or {"bucket": "b", "object_name": "o"})
    return stored


def _start(body: bytes):
    payload = StartScanPayload(sbom_sca=StartSBOMScanData(sbom_file_used=True))
    return asyncio.run(format_input.format_input_for_scan(
        scan_type="sbom_sca", start_scan_payload=payload,
        uploaded_file=UploadFile(file=io.BytesIO(body), filename="sbom.json")))


@pytest.mark.parametrize("doc, reason", [
    ({**SPDX2, "packages": 5}, "'packages' must be an array"),
    ({**SPDX2, "packages": "abc"}, "'packages' must be an array"),
    ({**SPDX2, "relationships": 7}, "'relationships' must be an array"),
    ({**SPDX2, "documentDescribes": 3}, "'documentDescribes' must be an array"),
    ({**SPDX3, "@graph": {"a": 1}}, "'@graph' must be an array"),
    ({**CDX, "components": {"a": 1}}, "'components' must be an array"),
    ({**CDX, "metadata": []}, "'metadata' must be an object"),
    ({"hello": "world"}, "neither a CycloneDX"),
    ([1, 2], "must be a JSON object"),
])
def test_wrong_shape_is_refused_with_422_and_never_stored(uploads, doc, reason):
    with pytest.raises(HTTPException) as err:
        _start(json.dumps(doc).encode())
    assert err.value.status_code == 422
    assert reason in err.value.detail
    assert uploads == []


@pytest.mark.parametrize("doc", [SPDX2, SPDX3, CDX,
                                 # wrong types inside a package are the worker's to tolerate and count
                                 {**SPDX2, "packages": [{"SPDXID": "x", "name": {"a": 1}, "externalRefs": 4}, 5]}])
def test_readable_sboms_are_accepted(uploads, doc):
    kwargs = _start(json.dumps(doc).encode())
    assert kwargs["file_dict_context"] == {"bucket_name": "b", "object_name": "o"}
    assert json.loads(uploads[0]) == doc


def test_invalid_json_stays_400(uploads):
    with pytest.raises(HTTPException) as err:
        _start(b"{not json")
    assert err.value.status_code == 400 and uploads == []


def test_shape_check_matches_the_worker_format_test():
    from backend.utilities.scan.sbom_upload import sbom_shape_error

    assert sbom_shape_error({"spdxVersion": "SPDX-2.2"}) is None
    assert sbom_shape_error({"@context": ["https://spdx.org/rdf/3.0.0/spdx-context.jsonld"]}) is None
    assert sbom_shape_error({"bomFormat": "cyclonedx"}) is not None
