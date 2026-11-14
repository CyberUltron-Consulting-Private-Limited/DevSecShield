"""F1 scale run: a moto organisation of 1,000 accounts x 3 regions collected by a 20-worker cloud pool.

Not part of the default suite (it takes minutes); run it on purpose:

    cd backend && CBOM_SCALE_TEST=1 CBOM_TEST_PG_URL=postgresql+psycopg2://... PYTHONPATH=.. \\
        uv run --with pytest --with moto python -m pytest tests/test_cbom_cloud_pool_scale.py -q -s

Knobs: CBOM_SCALE_ACCOUNTS (1000), CBOM_SCALE_REGIONS (us-east-1,eu-west-1,ap-south-1), CBOM_SCALE_WORKERS (20),
CBOM_SCALE_SERVICES (``light``: each slice reads KMS keys in its region and IAM roles for ``global`` through moto;
``all``: every service of the real collector.  moto keeps every account x region x service backend in memory, the EC2
one alone several MB: ``all`` measured 1.7 GB peak for 100 accounts x 3 regions, so 1,000 x 3 does not fit a 7 GB
machine).
Prints wall time, jobs/s, failures and peak memory; every account gets one KMS key in the first region, so the stored
KMS assets are checked against what was planted.
"""
from __future__ import annotations

import os
import resource
import sys
import threading
import time
from pathlib import Path

import pytest

if os.environ.get("CBOM_SCALE_TEST") != "1":
    pytest.skip("scale run: set CBOM_SCALE_TEST=1", allow_module_level=True)

sys.path.insert(0, str(Path(__file__).parent))
import test_cbom_cloud_pool_f1 as F  # noqa: E402

from sqlalchemy import func  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

from backend.new_models import CbomCollectedAsset, CbomCollectionJob, CbomCollectionRun  # noqa: E402
from backend.workers import cbom_cloud_worker as W  # noqa: E402

ACCOUNTS = int(os.environ.get("CBOM_SCALE_ACCOUNTS", "1000"))
REGIONS = os.environ.get("CBOM_SCALE_REGIONS", "us-east-1,eu-west-1,ap-south-1").split(",")
WORKERS = int(os.environ.get("CBOM_SCALE_WORKERS", "20"))


def _light_region(acct, region, label, emit, cfg):
    for key in acct.client("kms", region).list_keys()["Keys"]:
        arn = key["KeyArn"]
        emit({"type": "kms_key", "target": label, "location": arn, "name": key["KeyId"], "algorithm": "SYMMETRIC_DEFAULT",
              "key_size": 256, "facts": {"key_spec": "SYMMETRIC_DEFAULT", "identity": arn}})
    return [("kms", "ok", None)]


def _light_global(acct, label, emit):
    acct.client("iam", "global").list_roles()
    return [("iam", "ok", None)]


def test_scale_thousand_accounts_three_regions_twenty_workers(org, tmp_path, monkeypatch):
    import boto3

    from backend.utilities.cbom_sources import aws_collect as AC

    services = os.environ.get("CBOM_SCALE_SERVICES", "light")
    if services == "light":
        monkeypatch.setattr(AC, "_region_services", _light_region)
        monkeypatch.setattr(AC, "_global_services", _light_global)

    client, mgmt = org
    kind = "pg" if F.PG else "sqlite"
    engine = F._make_engine(kind, tmp_path)
    monkeypatch.setenv("CBOM_CLOUD_TEAM_MAX_CONCURRENCY", str(WORKERS))
    monkeypatch.setattr(W, "IDLE_SLEEP_S", 0.2)
    W._stop.clear()
    W._release.clear()
    t0 = time.monotonic()
    F._members(client, ACCOUNTS - 1)
    accounts = [a["Id"] for p in client.get_paginator("list_accounts").paginate() for a in p["Accounts"]]
    sts = boto3.client("sts", region_name="us-east-1")
    for acct in accounts:  # one KMS key per account, created as that account
        creds = sts.assume_role(RoleArn=f"arn:aws:iam::{acct}:role/ZeroShieldCBOMReader", RoleSessionName="seed",
                                ExternalId="seed-ext")["Credentials"]
        boto3.client("kms", region_name=REGIONS[0], aws_access_key_id=creds["AccessKeyId"],
                     aws_secret_access_key=creds["SecretAccessKey"],
                     aws_session_token=creds["SessionToken"]).create_key(Description=f"k-{acct}")
    seeded = time.monotonic() - t0
    user = F._team(engine, 1, credits=10_000.0)
    with Session(engine) as s:
        from backend.new_models import CbomCollectionSource

        s.add(CbomCollectionSource(
            team_id=1, owner_user_id=user, kind="aws_account", name="org", name_lower="org",
            config={"scope": "organization", "role_arn": f"arn:aws:iam::{mgmt}:role/ZeroShieldCBOMReader",
                    "regions": REGIONS},
            last_test_status="passed", last_test_result={"member_accounts": ACCOUNTS}))
        s.commit()
    run_id = F._queue(engine, 1, user, "scale-run-0001")
    threads = [threading.Thread(target=W.worker_loop, args=(engine, f"s{i}"), name=f"s{i}") for i in range(WORKERS)]
    started = time.monotonic()
    for t in threads:
        t.start()
    fanned = None
    while time.monotonic() - started < 6 * 3600:
        with Session(engine) as s:
            run = s.get(CbomCollectionRun, run_id)
            if fanned is None and s.exec(select(func.count()).select_from(CbomCollectionJob)
                                         .where(CbomCollectionJob.kind == "slice")).one():
                fanned = time.monotonic() - started
            if run.status in ("done", "partial", "failed", "cancelled"):
                break
        time.sleep(1)
    wall = time.monotonic() - started
    W._stop.set()
    for t in threads:
        t.join(60)
    with Session(engine) as s:
        parent = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.kind == "collect")).one()
        slices = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.kind == "slice")).all()
        kms = s.exec(select(func.count()).select_from(CbomCollectedAsset)
                     .where(CbomCollectedAsset.asset_type == "kms_key")).one()
        assets = s.exec(select(func.count()).select_from(CbomCollectedAsset)).one()
        run = s.get(CbomCollectionRun, run_id)
    failed = [j for j in slices if j.status != "success"]
    retried = [j for j in slices if j.attempts > 1]
    counts = parent.result["counts"]
    collect_s = wall - (fanned or 0)
    print(f"\nSCALE [{kind}] services={services} accounts={ACCOUNTS} regions={len(REGIONS)} workers={WORKERS} "
          f"seed_s={seeded:.0f}\n"
          f"  slices={len(slices)} (account x [global + {len(REGIONS)} regions]) wall_s={wall:.1f} "
          f"fan_out_s={fanned:.1f} jobs_per_s={len(slices) / collect_s:.2f}\n"
          f"  slice_failures={len(failed)} retried={len(retried)} target_counts={counts}\n"
          f"  run={run.status} parent={parent.status}/{parent.outcome} assets={assets} kms_keys={kms} "
          f"org={parent.result['fanout'].get('org')} slice_ms_max={parent.result['fanout'].get('slice_ms_max')} "
          f"max_rss_mb={resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024}")
    assert len(slices) == ACCOUNTS * (len(REGIONS) + 1)
    assert not failed and counts["total"] == len(slices) and counts["failed"] == 0
    assert kms == ACCOUNTS and parent.asset_count == assets
    assert run.status in ("done", "partial") and not parent.refunded
    if kind == "pg":
        from sqlmodel import SQLModel

        SQLModel.metadata.drop_all(engine)


org = F.org
