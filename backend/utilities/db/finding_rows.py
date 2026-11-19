"""The finding rows a scan stores in Mongo, and their statuses joined back to ``scan_data``.

``create_findings_in_mongo_db`` writes one Mongo document per finding row of ``scan_data``, in
order, copying the row (plus a few fields: SAST ``logical_component_title``, MCP ``type``, SBOM
title/description normalisation). Nothing later edits ``finding_data``; triage edits only the
status fields. So a PDF can attach each row's status by matching the stored copies exactly:

* ``mongo_rows`` produces exactly what the writer stores, in the writer's order (the writer keeps
  its own walk; ``tests/test_finding_rows.py`` pins the two to the same rows for every type);
* ``join_statuses`` pairs each expected row with a stored document by canonical-JSON
  fingerprint, in insertion order within equal fingerprints (exact duplicates pair by position);
* anything short of a complete, exact pairing raises ``StatusesUnavailable``: a report never
  guesses a status.
"""

from __future__ import annotations

import copy
import json
from collections import defaultdict, deque
from typing import Any

from backend.utilities.celery.sbom_finding_normalize import normalize_sbom_finding_data

DEFAULT_STATUS = "not_started"
STATUS_READ_MS = 5000


class StatusesUnavailable(Exception):
    """The stored findings don't match this scan's rows (missing, partial or different)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class StatusStoreDown(Exception):
    """Mongo could not be read."""


def mongo_rows(scan_type: str, scan_results: dict) -> list[dict]:
    """The ``finding_data`` documents the writer stores for these results, in insertion order.

    Raises ``KeyError``/``TypeError`` on payload shapes the writer cannot ingest (it raises there
    too, so such scans have no stored findings). Rows are copies: ``scan_results`` is not changed.
    """
    results = scan_results["results"]
    if scan_type == "sast":
        rows = []
        for item in results:
            component = item["logical_component_title"]
            for vulnerability in item["vulnerabilities"]:
                row = copy.deepcopy(vulnerability)
                row["logical_component_title"] = component
                rows.append(row)
        return rows
    if scan_type in ("iac", "dast", "cbom", "ai_bom"):
        return [copy.deepcopy(v) for v in results]
    if scan_type == "sbom_sca":
        return [normalize_sbom_finding_data(copy.deepcopy(v)) for v in results]
    if scan_type == "mcp":
        rows = []
        for group, kind in (("tools", "tool"), ("prompts", "prompt"), ("resources", "resource")):
            for entry in results[group]:
                for vulnerability in entry["vulnerabilities"]:
                    row = copy.deepcopy(vulnerability)
                    row["type"] = kind
                    rows.append(row)
        return rows
    if scan_type == "llm":
        return [copy.deepcopy(v) for v in results["vulnerabilities"]]
    raise KeyError(f"no stored findings for scan type {scan_type!r}")


def row_count(scan_type: str, scan_data: Any) -> int:
    """How many finding rows a scan's results hold (no copies); 0 for shapes the writer does not ingest. Used to
    decide whether a PDF build is large enough to take an export slot, so an estimate is never needed."""
    try:
        results = scan_data["results"]
        if scan_type == "sast":
            return sum(len(item["vulnerabilities"]) for item in results)
        if scan_type == "mcp":
            return sum(len(entry["vulnerabilities"]) for group in ("tools", "prompts", "resources")
                       for entry in results[group])
        if scan_type == "llm":
            return len(results["vulnerabilities"])
        return len(results)
    except (KeyError, TypeError, AttributeError):
        return 0


def fingerprint(row: Any) -> str:
    return json.dumps(row, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)


def join_statuses(expected: list[dict], documents: list[dict]) -> list[str]:
    """One status per expected row, in order. ``documents`` must be in insertion order."""
    if not expected:
        return []
    if not documents:
        raise StatusesUnavailable("no stored findings")
    if len(documents) != len(expected):
        raise StatusesUnavailable(f"{len(documents)} stored findings for {len(expected)} rows")
    queues: dict[str, deque] = defaultdict(deque)
    for doc in documents:
        queues[fingerprint(doc.get("finding_data"))].append(doc.get("finding_status") or DEFAULT_STATUS)
    statuses = []
    for row in expected:
        queue = queues.get(fingerprint(row))
        if not queue:
            raise StatusesUnavailable("a stored finding does not match this scan's rows")
        statuses.append(queue.popleft())
    return statuses


def read_statuses(scan_id: int, scan_type: str, scan_results: dict, *, mongo_db=None) -> list[str]:
    """Statuses for every stored row of this scan, aligned with ``mongo_rows`` order."""
    try:
        expected = mongo_rows(scan_type, scan_results)
    except (KeyError, TypeError, AttributeError) as exc:
        raise StatusesUnavailable("this scan's findings are not stored") from exc
    try:
        if mongo_db is None:
            from backend.get_db import get_mongo_client_db  # noqa: PLC0415

            mongo_db = get_mongo_client_db()
        # A client-side deadline (server selection, connection and the query): max_time_ms alone only bounds work
        # on the server, so an unresponsive server would hold the export for pymongo's own timeouts (~55 s seen).
        import pymongo  # noqa: PLC0415

        with pymongo.timeout(STATUS_READ_MS / 1000):
            cursor = (mongo_db["scan_findings"]
                      .find({"scan_id": scan_id}, {"finding_data": 1, "finding_status": 1})
                      .sort("_id", 1))
            documents = list(cursor)
    except StatusesUnavailable:
        raise
    except Exception as exc:  # noqa: BLE001 - any Mongo failure is "statuses unavailable right now"
        raise StatusStoreDown(type(exc).__name__) from exc
    # A BSON round trip turns tuples into lists; the JSON payloads hold none, but be exact anyway.
    expected = json.loads(json.dumps(expected, default=str))
    return join_statuses(expected, documents)
