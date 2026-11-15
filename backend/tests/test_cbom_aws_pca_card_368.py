"""#368 (a): an AWS Private CA source is read by the AWS account source it names (aws_collect reads acm-pca in each
of the account's regions), but the source itself never recorded anything: after a run of its account (212 assets,
no Private CA in ap-south-1) the card could not say whether the CAs were read. Each AWS Private CA source now serves
``pca_read``, the ACM PCA part of its account's newest finished collection: per region whether acm-pca was read and
how many private CAs were found (``arn:aws:acm-pca:`` assets only; an RDS CA is also a ``cloud_ca`` and is not one),
or "not read" with the reason.  Real routers, SQLite (``test_cbom_sources_api`` world)."""
from __future__ import annotations

import datetime as dt

from sqlmodel import Session

from test_cbom_sources_api import api, world  # noqa: F401  (fixtures)
from backend.new_models import CbomCollectedAsset, CbomCollectionJob, CbomCollectionSource

ACCOUNT = "123456789012"
NOW = dt.datetime(2026, 11, 15, 6, 22, 40)


def _sources(engine, *, regions=("ap-south-1", "us-east-1")):
    with Session(engine) as s:
        aws = CbomCollectionSource(team_id=1, owner_user_id=1, kind="aws_account", name="stgqa-aws", name_lower="stgqa-aws",
                                   config={"role_arn": f"arn:aws:iam::{ACCOUNT}:role/ZeroShieldCBOMReader",
                                           "regions": list(regions), "scope": "account"},
                                   last_test_status="passed")
        s.add(aws)
        s.flush()
        pca = CbomCollectionSource(team_id=1, owner_user_id=1, kind="ca_connector", name="pca", name_lower="pca",
                                   config={"provider": "aws_private_ca", "aws_source_id": aws.id})
        other = CbomCollectionSource(team_id=1, owner_user_id=1, kind="ca_connector", name="venafi", name_lower="venafi",
                                     config={"provider": "venafi", "api_url": "https://venafi.example.com"})
        s.add(pca)
        s.add(other)
        s.commit()
        return aws.id, pca.id, other.id


def _job(engine, source_id: int, targets: list[dict], *, status="success", outcome="ok", error=None, cas=(), finished=NOW):
    with Session(engine) as s:
        job = CbomCollectionJob(team_id=1, source_id=source_id, kind="collect", status=status, outcome=outcome,
                                attempts=1, finished_at=finished, created_at=finished, error=error,
                                result={"targets": targets, "summary": f"{len(targets)} account-regions"})
        s.add(job)
        s.flush()
        rows = [("cloud_ca", f"arn:aws:acm-pca:{r}:{ACCOUNT}:certificate-authority/{n}") for n, r in enumerate(cas)]
        rows.append(("cloud_ca", f"arn:aws:rds:ap-south-1:{ACCOUNT}:db:proxy#ca"))  # an RDS CA, not a private CA
        rows.append(("cloud_ca", f"arn:aws:acm-pca:us-east-1:{ACCOUNT}:certificate-authority/old"))  # earlier attempt
        for i, (atype, loc) in enumerate(rows):
            s.add(CbomCollectedAsset(team_id=1, job_id=job.id, source_id=source_id, attempt=2 if loc.endswith("/old") else 1,
                                     asset_key=f"k{job.id}-{i}", asset_type=atype, cdx_type="x", target=f"aws:{ACCOUNT}",
                                     location=loc, name="ca", facts={}, created_at=finished))
        s.commit()
        return job.id


def _target(region: str, status="ok", pca="ok", error=None) -> dict:
    services = {"kms": "ok", "acm": "ok", "acm-pca": pca} if pca else {}
    return {"target": f"aws:{ACCOUNT}/{region}", "status": status, "error": error, "services": services}


def _get(api, sid):  # noqa: F811  (the API fixtures)
    one = api("GET", f"/1/cbom/sources/items/{sid}").json()["source"]
    listed = {s["id"]: s for s in api("GET", "/1/cbom/sources/items").json()["sources"]}
    assert listed[sid].get("pca_read") == one.get("pca_read")  # list == get
    return one


def test_a_private_ca_whose_account_was_never_collected_has_no_read(api, world):  # noqa: F811  (the API fixtures)
    engine, _ = world
    _aws, pca, other = _sources(engine)
    assert _get(api, pca)["pca_read"] is None
    assert "pca_read" not in _get(api, other)  # only AWS Private CA sources carry it


def test_the_accounts_last_collection_says_per_region_what_acm_pca_found(api, world):  # noqa: F811  (the API fixtures)
    engine, _ = world
    aws, pca, _ = _sources(engine)
    job = _job(engine, aws, [_target("ap-south-1"), _target("us-east-1"), {"target": f"aws:{ACCOUNT}/global",
               "status": "ok", "services": {"iam": "ok"}}], cas=["us-east-1", "us-east-1"])
    read = _get(api, pca)["pca_read"]
    assert read == {
        "account_source_id": aws, "job_id": job, "run_id": None, "at": "2026-11-15T06:22:40Z", "status": "read",
        "cas": 2, "reason": None,
        "regions": [{"region": "ap-south-1", "status": "ok", "cas": 0, "error": None},
                    {"region": "us-east-1", "status": "ok", "cas": 2, "error": None}],
    }


def test_a_region_where_acm_pca_was_denied_is_partial_with_the_reason(api, world):  # noqa: F811  (the API fixtures)
    engine, _ = world
    aws, pca, _ = _sources(engine)
    _job(engine, aws, [_target("ap-south-1"), _target("us-east-1", status="error", pca="denied",
                                                       error="acm-pca: denied AccessDeniedException")], outcome="partial")
    read = _get(api, pca)["pca_read"]
    assert read["status"] == "partial" and read["cas"] == 0
    assert read["regions"][1] == {"region": "us-east-1", "status": "denied", "cas": 0,
                                  "error": "acm-pca: denied AccessDeniedException"}


def test_an_account_that_could_not_be_read_says_not_read_and_why(api, world):  # noqa: F811  (the API fixtures)
    engine, _ = world
    aws, pca, _ = _sources(engine)
    _job(engine, aws, [_target("ap-south-1", status="auth_failed", pca=None, error="AccessDenied")], status="success",
         outcome="failed")
    read = _get(api, pca)["pca_read"]
    assert read["status"] == "not_read" and read["regions"] == [
        {"region": "ap-south-1", "status": "not_read", "cas": 0, "error": "AccessDenied"}]
    # a job that failed before it read any region: the job's own error is the reason
    _job(engine, aws, [], status="failure", outcome=None, error="AWS role could not be assumed",
         finished=NOW + dt.timedelta(minutes=5))
    read = _get(api, pca)["pca_read"]
    assert read["status"] == "not_read" and read["regions"] == [] and read["reason"] == "AWS role could not be assumed"


def test_a_private_ca_whose_account_was_removed_has_no_read(api, world):  # noqa: F811  (the API fixtures)
    engine, _ = world
    aws, pca, _ = _sources(engine)
    _job(engine, aws, [_target("ap-south-1")])
    with Session(engine) as s:
        src = s.get(CbomCollectionSource, pca)
        src.config = {"provider": "aws_private_ca", "aws_source_id": 99999}
        s.add(src)
        s.commit()
    assert _get(api, pca)["pca_read"] is None
