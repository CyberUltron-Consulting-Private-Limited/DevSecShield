"""Staging QA Q3-01 on the run surfaces: one run whose two jobs read one AWS account counts each resource once.

Staging team 1, Sources run #57 (two IAM roles on one account): the assets API listed 464 rows for 229 resources
(storage_encryption 130 for 65, KMS 38 for 19, load balancer listeners 42 for 21, secrets 146 for 73, CloudFront 6
for 3) and the run posture counted every one twice.  The run list, its totals and facets, the run posture, the
heat map and the results dashboard now read the run's rows folded by ``resource_identity.run_fold`` (the newest job
kept, the other source in ``also_seen``).  Rule P: every surface reads the same rows, so their counts agree.

Fixture: ``fixtures/cbom_sources_two_aws_roles.json`` (the run's own assets API items), judged by the real
classifier and stored in SQLite.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import sys
from collections import Counter
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from sqlmodel import Session, SQLModel, create_engine  # noqa: E402

from backend.new_models import (  # noqa: E402
    CbomCollectedAsset,
    CbomCollectionJob,
    CbomCollectionRun,
    CbomCollectionSource,
    Team,
)
from backend.tests.support import two_aws_roles as AWS2  # noqa: E402
from backend.utilities.cbom_sources import classify as C  # noqa: E402
from backend.utilities.cbom_sources import heatmap as HM  # noqa: E402
from backend.utilities.cbom_sources import inventory as INV  # noqa: E402
from backend.utilities.cbom_sources import posture as POSTURE  # noqa: E402
from backend.utilities.cbom_sources import run_assets as RA  # noqa: E402

DONE = {520: dt.datetime(2026, 11, 24, 5, 44, 10), 521: dt.datetime(2026, 11, 24, 5, 44, 40)}
UNIQUE = {"cdn_tls": 3, "certificate": 13, "storage_encryption": 65, "public_key": 29, "cloud_secret": 73,
          "kms_key": 19, "identity_provider": 1, "signing_key": 1, "cloud_ca": 2, "load_balancer_tls": 21,
          "database_config": 1, "glue_catalog": 1}  # unique ARNs per type in the fixture (one source's 229)


def _store(engine, *, deleted_second: bool = False, only: tuple[int, ...] = (520, 521)) -> int:
    with Session(engine) as s:
        s.add(Team(id=1, name="Staging", credit_balance=0.0))
        run = CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id="q3-run-57", status="done",
                                finished_at=DONE[521], kb_version="kb", classifier_version="c")
        s.add(run)
        s.commit()
        jobs = {}
        for job_no, (name, ref) in AWS2.SOURCES.items():
            if job_no not in only:
                continue
            src = CbomCollectionSource(team_id=1, owner_user_id=1, kind="aws_account", name=name,
                                       name_lower=name.lower(), source_uid=ref)
            s.add(src)
            s.commit()
            job = CbomCollectionJob(team_id=1, run_id=run.id, source_id=src.id, kind="collect", status="success",
                                    outcome="ok", attempts=1, finished_at=DONE[job_no],
                                    params={"source_uid": ref, "kind": "aws_account", "source_name": name},
                                    result={"counts": {"ok": 1, "partial": 0, "failed": 0, "skipped": 0}})
            s.add(job)
            s.commit()
            jobs[job_no] = (job, src)
        for item in AWS2.items():
            if item["job_id"] not in jobs:
                continue
            job, src = jobs[item["job_id"]]
            judged = C.classify(item["type"], item.get("algorithm"), item.get("key_size"), item.get("protocol"),
                                item["facts"], DONE[520])
            s.add(CbomCollectedAsset(
                team_id=1, run_id=run.id, job_id=job.id, source_id=src.id, attempt=1,
                asset_key=hashlib.sha256(f"{src.source_uid}|{item['type']}|{item['location']}".encode()).hexdigest(),
                asset_type=item["type"], cdx_type=judged["cdx_type"], target=item.get("target"),
                location=item["location"], name=item.get("name"), algorithm=item.get("algorithm"),
                key_size=item.get("key_size"), protocol=item.get("protocol"),
                quantum_vulnerable=judged["quantum_vulnerable"], impact=judged["impact"],
                finding=judged["finding"], finding_codes=judged["finding_codes"], facts=item["facts"],
                created_at=DONE[item["job_id"]]))
        s.commit()
        if deleted_second:
            s.delete(jobs[521][1])
            s.commit()
        return int(run.id)


@pytest.fixture()
def engine(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'q3.db'}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    return engine


def _list(session, run_id, **kw):
    return INV.list_assets(session, team_id=1, run_id=run_id, page_size=1000, **kw)


def test_run_fold_keeps_the_oldest_source_and_names_the_other(engine):
    """Review 6058574998 F2: the kept row is the OLDEST source's (stgqa-aws-ap-south-1, created first), whichever job
    finished last, so the resource's remediation key does not flip from run to run."""
    from backend.utilities.cbom_sources import resource_identity as RI

    run_id = _store(engine)
    with Session(engine) as s:
        fold = RI.run_fold(s, 1, run_id)
        assert len(fold.dropped) == sum(UNIQUE.values()) == 229  # ACM certificates too: one ARN, one certificate
        kept = {r.id: r for r in s.exec(__import__("sqlmodel").select(CbomCollectedAsset)).all()}
        jobs = {kept[k].job_id for k in fold.dropped.values()}
        assert len(jobs) == 1  # every kept row is one job's: the oldest source's
        assert set(fold.also_seen.values()) == {("aws-pca-test",)}


def test_run_assets_list_each_resource_once(engine):
    run_id = _store(engine)
    with Session(engine) as s:
        out = _list(s, run_id)
        types = Counter(i["type"] for i in out["items"])
        assert dict(types) == UNIQUE
        assert out["total"] == out["all_total"] == len(out["items"]) == 229
        assert out["facets"]["type"]["kms_key"] == 19 and out["facets"]["type"]["storage_encryption"] == 65
        assert out["folded"] == 229
        kms = next(i for i in out["items"] if i["type"] == "kms_key")
        assert kms["source_name"] == "stgqa-aws-ap-south-1" and kms["also_seen"] == ["aws-pca-test"]  # oldest kept


def test_run_posture_counts_equal_the_run_list(engine):
    run_id = _store(engine)
    with Session(engine) as s:
        posture = POSTURE.run_posture(s, team_id=1, run_id=run_id, risk_model=None)
        listed = _list(s, run_id)
        assert posture["assets"] == len([i for i in listed["items"] if i["type"] != "coverage"]) == 229
        impacts = Counter(i["impact"] for i in listed["items"] if i["impact"])
        assert posture["impacts"] == {k: impacts.get(k, 0) for k in ("Critical", "High", "Medium", "Low")}
        page = RA.list_run_assets(s, team_id=1, run=s.get(CbomCollectionRun, run_id),
                                  params={"page_size": 1000}, view="findings")
        assert page["findings_total"] == page["total"] == sum(impacts.values())


def test_run_heatmap_counts_each_resource_once(engine):
    run_id = _store(engine)
    with Session(engine) as s:
        hm = HM.run_heatmap(s, 1, run_id, by="type")
        posture = POSTURE.run_posture(s, team_id=1, run_id=run_id, risk_model=None)
        by_type = Counter()
        for cell in hm["cells"]:
            by_type[cell["column"]] += cell["count"]
        assert sum(by_type.values()) == posture["assets"] == 229
        assert by_type["kms_key"] == 19 and by_type["cloud_secret"] == 73


def test_a_run_with_one_job_is_never_folded(engine):
    run_id = _store(engine, only=(520,))
    with Session(engine) as s:
        assert _list(s, run_id)["total"] == 229


def test_a_deleted_source_never_hides_the_live_read(engine):
    run_id = _store(engine, deleted_second=True)
    with Session(engine) as s:
        out = _list(s, run_id)
        kms = [i for i in out["items"] if i["type"] == "kms_key"]
        assert len(kms) == 19 and {i["source_name"] for i in kms} == {"stgqa-aws-ap-south-1"}
        assert {tuple(i["also_seen"]) for i in kms} == {()}  # a deleted source is never named
