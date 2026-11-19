"""Finding statuses join back to scan_data exactly, or the report refuses to filter by status."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_pdf_export_smoke as smoke  # noqa: E402

from backend.utilities.celery.create_findings import create_findings_in_mongo_db  # noqa: E402
from backend.utilities.db import finding_rows as fr  # noqa: E402
from backend.utilities.pdf.combined import generate_pdf_for_type, prepare_pdf_export_payload  # noqa: E402
from backend.utilities.pdf.report_context import ReportContext  # noqa: E402
from backend.utilities.pdf.report_options import parse_report_options  # noqa: E402
from support.pdf_text import pdf_pages_text  # noqa: E402

TYPES = ("sast", "iac", "dast", "sbom_sca", "mcp", "llm", "cbom", "ai_bom")


class _Cursor:
    def __init__(self, docs):
        self.docs = docs

    def sort(self, key, direction):
        assert key == "_id" and direction == 1
        return self

    def max_time_ms(self, ms):
        return self

    def __iter__(self):
        return iter(self.docs)


class FakeCollection:
    def __init__(self, fail: bool = False):
        self.docs: list[dict] = []
        self.fail = fail

    def delete_many(self, query):
        self.docs = [d for d in self.docs if d["scan_id"] != query["scan_id"]]

    def insert_many(self, docs):
        for doc in docs:
            # a BSON round trip, as Mongo stores it
            self.docs.append(json.loads(json.dumps(dict(doc), default=str)))

    def find(self, query, projection=None):
        if self.fail:
            raise ConnectionError("mongo down")
        return _Cursor([d for d in self.docs if d["scan_id"] == query["scan_id"]])


class FakeDb(dict):
    def __init__(self, fail: bool = False):
        super().__init__(scan_findings=FakeCollection(fail))


def _mcp_payload():
    vuln = {"title": "Tool poisoning", "impact": "High", "description": "same text", "suggested_fix": "pin"}
    return {"results": {
        "tools": [{"tool_name": "a", "vulnerabilities": [copy.deepcopy(vuln)]},
                  {"tool_name": "b", "vulnerabilities": [copy.deepcopy(vuln)]}],
        "prompts": [], "resources": [],
    }}


def _llm_payload():
    return {"results": {"vulnerabilities": [{"title": "Prompt injection", "impact": "High", "description": "d"}]}}


def _payload(scan_type):
    if scan_type == "mcp":
        return _mcp_payload()
    if scan_type == "llm":
        return _llm_payload()
    payload = smoke._worker_persist_payload(scan_type)
    return payload if isinstance(payload, dict) and "results" in payload else {"results": payload}


@pytest.mark.parametrize("scan_type", TYPES)
def test_mongo_rows_are_exactly_what_the_writer_stores(scan_type):
    payload = _payload(scan_type)
    db = FakeDb()
    create_findings_in_mongo_db(7, copy.deepcopy(payload), scan_type, db)
    stored = [d["finding_data"] for d in db["scan_findings"].docs]
    assert stored, scan_type
    expected = json.loads(json.dumps(fr.mongo_rows(scan_type, payload), default=str))
    assert stored == expected


def test_mongo_rows_do_not_change_the_payload():
    payload = _payload("sast")
    before = copy.deepcopy(payload)
    fr.mongo_rows("sast", payload)
    assert payload == before


@pytest.mark.parametrize("scan_type", TYPES)
def test_read_statuses_round_trip(scan_type):
    payload = _payload(scan_type)
    db = FakeDb()
    create_findings_in_mongo_db(7, copy.deepcopy(payload), scan_type, db)
    docs = db["scan_findings"].docs
    for i, doc in enumerate(docs):
        doc["finding_status"] = ("fixed", "ignored", "in_progress", "not_started")[i % 4]
    statuses = fr.read_statuses(7, scan_type, payload, mongo_db=db)
    assert statuses == [d["finding_status"] for d in docs]


def test_exact_duplicates_keep_their_own_statuses_in_order():
    payload = _mcp_payload()  # the same vulnerability on two tools: identical stored rows but for nothing
    db = FakeDb()
    create_findings_in_mongo_db(3, copy.deepcopy(payload), "mcp", db)
    db["scan_findings"].docs[0]["finding_status"] = "fixed"
    db["scan_findings"].docs[1]["finding_status"] = "ignored"
    assert fr.read_statuses(3, "mcp", payload, mongo_db=db) == ["fixed", "ignored"]


def test_rows_differing_only_in_description_match_their_own_document():
    payload = {"results": [{"logical_component_title": "api", "vulnerabilities": [
        {"title": "SQLi", "impact": "High", "location": "a.py:1", "description": "one"},
        {"title": "SQLi", "impact": "High", "location": "a.py:1", "description": "two"},
    ]}]}
    db = FakeDb()
    create_findings_in_mongo_db(4, copy.deepcopy(payload), "sast", db)
    docs = db["scan_findings"].docs
    docs.reverse()  # even out of order, the fingerprint decides
    docs[0]["finding_status"] = "fixed"  # this is "two"
    assert fr.read_statuses(4, "sast", payload, mongo_db=db) == ["not_started", "fixed"]


def test_no_documents_refuses():
    with pytest.raises(fr.StatusesUnavailable):
        fr.read_statuses(5, "sast", _payload("sast"), mongo_db=FakeDb())


def test_partial_insert_refuses():
    payload = _mcp_payload()
    db = FakeDb()
    create_findings_in_mongo_db(5, copy.deepcopy(payload), "mcp", db)
    db["scan_findings"].docs.pop()
    with pytest.raises(fr.StatusesUnavailable):
        fr.read_statuses(5, "mcp", payload, mongo_db=db)


def test_documents_from_another_run_refuse():
    old = _payload("iac")
    db = FakeDb()
    create_findings_in_mongo_db(6, copy.deepcopy(old), "iac", db)
    new = copy.deepcopy(old)
    new["results"][0]["title"] = "changed by a rescan"
    with pytest.raises(fr.StatusesUnavailable):
        fr.read_statuses(6, "iac", new, mongo_db=db)


def test_legacy_payloads_have_no_stored_rows():
    semgrep = {"results": {"results": [{"check_id": "x", "path": "a.py"}], "version": "1"}}
    with pytest.raises(fr.StatusesUnavailable):
        fr.read_statuses(1, "sast", semgrep, mongo_db=FakeDb())
    legacy_mcp = {"results": {"final_issues": [{"issue_code": "X"}]}}
    with pytest.raises(fr.StatusesUnavailable):
        fr.read_statuses(1, "mcp", legacy_mcp, mongo_db=FakeDb())


def test_mongo_failure_is_store_down():
    with pytest.raises(fr.StatusStoreDown):
        fr.read_statuses(1, "sast", _payload("sast"), mongo_db=FakeDb(fail=True))


def test_status_filter_in_the_pdf(tmp_path):
    payload = {"results": [{"logical_component_title": "api", "vulnerabilities": [
        {"title": "Fixed one", "impact": "High", "location": "a.py:1", "description": "d"},
        {"title": "Open one", "impact": "High", "location": "b.py:2", "description": "d"},
        {"title": "Ignored one", "impact": "Low", "location": "c.py:3", "description": "d"},
    ]}]}
    db = FakeDb()
    create_findings_in_mongo_db(9, copy.deepcopy(payload), "sast", db)
    for doc, status in zip(db["scan_findings"].docs, ("fixed", "not_started", "ignored")):
        doc["finding_status"] = status
    statuses = fr.read_statuses(9, "sast", payload, mongo_db=db)
    opts = parse_report_options({"statuses": "not_started,in_progress"}, "scan", scan_type="sast")
    out = tmp_path / "s.pdf"
    generate_pdf_for_type("sast", prepare_pdf_export_payload("sast", payload), str(out),
                          ctx=ReportContext(options=opts, row_statuses=statuses))
    text = "\n".join(pdf_pages_text(out.read_bytes()))
    assert "Open one" in text and "Fixed one" not in text and "Ignored one" not in text
    assert "#2" in text
    assert "excluded: 1 Fixed, 1 Ignored" in text
    assert "Showing 1 of 3 findings" in text
    # the priority note names only what the report shows
    assert "Priority action: 1 High" in text


def test_the_status_read_has_a_client_side_deadline(monkeypatch):
    """max_time_ms only bounds work on the server: an unresponsive server held an export ~55 s before the 503.
    The read runs inside pymongo.timeout(STATUS_READ_MS), which bounds selection, connection and the query."""
    import contextlib

    import pymongo

    seen = []

    @contextlib.contextmanager
    def deadline(seconds):
        seen.append(seconds)
        yield

    monkeypatch.setattr(pymongo, "timeout", deadline)
    payload = _payload("sast")
    db = FakeDb()
    create_findings_in_mongo_db(9, copy.deepcopy(payload), "sast", db)
    assert fr.read_statuses(9, "sast", payload, mongo_db=db)
    assert seen == [fr.STATUS_READ_MS / 1000]
