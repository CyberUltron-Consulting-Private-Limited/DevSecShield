"""Two CBOM Sources sources reading ONE AWS account (staging team 1, Sources run #57, 24 Nov 2026; staging QA Q3-01).

``fixtures/cbom_sources_two_aws_roles.json`` holds the run's assets API items (coverage rows left out; the account id,
an RDS host id and resource names replaced): source "stgqa-aws-ap-south-1" (job 520) and source "aws-pca-test"
(job 521) read the same account with two IAM roles, 229 assets each.  Each asset is judged by the real classifier and
turned into a results[] row by the real ``collections_view.node_row``, as ``load_sources_result`` would.

Unique resources in the fixture (by ARN): KMS keys 19, storage settings 65 (10 not encrypted, one EKS cluster), Glue
catalog 1, load balancer listeners 21, CloudFront distributions 3, secrets 73, private CAs 2, EC2 key pairs 29.
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from backend.utilities.cbom_sources import classify as C
from backend.utilities.cbom_sources.collections_view import (
    Collection,
    SourcesRow,
    code_impacts,
    link_certificates,
    node_row,
)

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "cbom_sources_two_aws_roles.json"
FIRST_DONE = dt.datetime(2026, 11, 24, 5, 44, 10, tzinfo=dt.timezone.utc)  # job 520 finished
SECOND_DONE = dt.datetime(2026, 11, 24, 5, 44, 40, tzinfo=dt.timezone.utc)  # job 521 finished 30 s later
SOURCES = {520: ("stgqa-aws-ap-south-1", "src-aws-a"), 521: ("aws-pca-test", "src-aws-b")}
RUN_ID = 57


def items() -> list[dict[str, Any]]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))["items"]


def collections(*, deleted: tuple[int, ...] = ()) -> dict[int, Collection]:
    out = {}
    for job, (name, ref) in SOURCES.items():
        mine = [i for i in items() if i["job_id"] == job]
        out[job] = Collection(run_id=RUN_ID, job_id=job, source_ref=ref, source_name=name,
                              source_kind="" if job in deleted else "aws_account",
                              observed_at=FIRST_DONE if job == 520 else SECOND_DONE, asset_count=len(mine))
    return out


def build(*, deleted: tuple[int, ...] = (), jobs: tuple[int, ...] = (520, 521),
          start_id: int = 70000) -> tuple[list[SourcesRow], list[Collection]]:
    """``(rows, collections)`` for ``cbom_team_rollup.merge_collections``; ``deleted``: jobs whose source was deleted."""
    colls = collections(deleted=deleted)
    rows: list[SourcesRow] = []
    asset_id = start_id
    for index, item in enumerate(items()):
        if item["job_id"] not in jobs:
            continue
        asset_id += 1
        collection = colls[item["job_id"]]
        judged = C.classify(item["type"], item.get("algorithm"), item.get("key_size"), item.get("protocol"),
                            item["facts"], FIRST_DONE.replace(tzinfo=None))
        stored = SimpleNamespace(
            id=asset_id, asset_type=item["type"], cdx_type=judged["cdx_type"], name=item.get("name"),
            algorithm=item.get("algorithm"), location=item["location"], key_size=item.get("key_size"),
            protocol=item.get("protocol"), quantum_vulnerable=judged["quantum_vulnerable"], facts=item["facts"])
        view = {"impact": judged["impact"], "finding_codes": judged["finding_codes"], "finding": judged["finding"],
                "impacts": judged["impacts"]}
        rows.append(SourcesRow(row=node_row(stored, collection, view), collection=collection,
                               identity=f"node|{collection.source_ref}|key|{index}", node_type=item["type"],
                               target=item.get("target"), facts=dict(item["facts"]),
                               asset_key=f"{collection.source_ref}-{index}", code_impacts=code_impacts(view)))
    link_certificates(rows)  # as load_sources_result does
    return rows, [colls[j] for j in jobs]
