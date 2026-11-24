"""SOW D5 (review 6036875286 of PR #495): the SPDX 3.0 and SARIF 2.1.0 files the API
serves for an AI BOM scan (``GET /{team}/ai_bom/scan/{id}/spdx`` / ``/sarif`` and the
evidence pack, ``backend/utilities/compliance/served_artifacts.py``) still conform: the
SPDX document to the official SPDX 3.0.1 JSON schema and SHACL model, the SARIF log to
the SARIF 2.1.0 schema. The backend module is standard library only and loaded by path.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib

import pytest

from aibom.emit.validate import validate_sarif, validate_spdx
from aibom.integrations.devsecshield import scan_to_devsecshield

_TESTS = pathlib.Path(__file__).resolve().parent
_FIXTURE = _TESTS / "fixtures" / "aibom-bank-router"
_SHACL = (
    _TESTS / "fixtures" / "spdx-3.0.1-shacl"
)  # official model + context, unmodified
_SERVED = (
    pathlib.Path(__file__).resolve().parents[2]
    / "backend/utilities/compliance/served_artifacts.py"
)


def _shacl_conforms(doc: dict) -> tuple[bool, str]:
    rdflib = pytest.importorskip("rdflib")
    pyshacl = pytest.importorskip("pyshacl")
    context = json.loads((_SHACL / "spdx-context.jsonld").read_text(encoding="utf-8"))
    data = dict(
        doc, **{"@context": context["@context"]}
    )  # offline: the context, inlined
    graph = rdflib.Graph().parse(data=json.dumps(data), format="json-ld")
    shapes = rdflib.Graph().parse(str(_SHACL / "spdx-model.ttl"), format="turtle")
    conforms, _report, text = pyshacl.validate(
        graph,
        shacl_graph=shapes,
        ont_graph=shapes,
        inference="none",
        advanced=True,
        allow_warnings=True,
    )
    return bool(conforms), text


def _served():
    spec = importlib.util.spec_from_file_location("served_artifacts", _SERVED)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def scan_data() -> dict:
    return scan_to_devsecshield(_FIXTURE, level=4)


def test_the_served_spdx_conforms_to_the_spdx_301_schema_and_shacl_model(scan_data):
    body = _served().stored_artifact(scan_data, "spdx")
    doc = json.loads(body)
    assert doc == scan_data["ai_bom_spdx"]  # the stored document, unchanged
    assert validate_spdx(doc) == []
    conforms, text = _shacl_conforms(doc)
    assert conforms, text


def test_the_served_sarif_conforms_to_the_sarif_210_schema(scan_data):
    body = _served().stored_artifact(scan_data, "sarif")
    doc = json.loads(body)
    assert doc == scan_data["ai_bom_sarif"]
    assert validate_sarif(doc) == []
    assert body.endswith(b"\n") and body == _served().stored_artifact(
        scan_data, "sarif"
    )
