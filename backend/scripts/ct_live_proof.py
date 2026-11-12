"""Live proof of CT discovery: the product collects real Certificate Transparency answers, end to end, and writes what
it STORED, for an independent comparison (bench/ct/live_compare.py) with the provider's raw answer.

Runs on a GitHub runner (cbom-ct-live.yml); the development box has no internet.  Product path, on SQLite: the API
creates the ct_logs source and the run (credits charged from the estimate), the cloud worker claims the job and calls
the provider over the internet, the API stores and classifies the assets.  Output: one JSON file with every stored
row of the run and the job's result.

    CBOM_CT_DISCOVERY=1 CBOM_CT_PROVIDER=certspotter PYTHONPATH=. \\
        python backend/scripts/ct_live_proof.py --domains zeroshield.ai,example.com --out collector.json
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
os.environ.setdefault("JWT_SECRET_KEY", "ct-live-proof-only-not-a-secret-0123456789")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "ct-live-proof-only-not-a-secret-refresh-0123")
os.environ["CBOM_CT_DISCOVERY"] = "1"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--domains", required=True)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--expected-issuers", default="")
    args = parser.parse_args()
    if not os.environ.get("ENCRYPTION_KEY"):
        from cryptography.fernet import Fernet

        os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode()

    from fastapi.testclient import TestClient
    from sqlmodel import Session, SQLModel, create_engine, select

    from backend.main import app
    from backend.new_models import CbomCollectedAsset, CbomCollectionJob, CbomCollectionRun, Team, TeamMembership, User
    from backend.routers import cbom_node, cbom_vendor_public
    from backend.utilities.auth import auth_utils
    from backend.utilities.cbom_sources import http as cbom_http
    from backend.workers import cbom_cloud_worker

    folder = Path(tempfile.mkdtemp(prefix="ct-live-"))
    engine = create_engine(f"sqlite:///{folder / 'ct.db'}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    email = "ct-live@proof.test"
    with Session(engine) as s:
        s.add(Team(id=1, name="CT live proof", credit_balance=100.0))
        s.commit()
        user = User(email=email, password="x", first_name="ct", last_name="proof", profile_photo=None, session_active=True,
                    default_team_id=1)
        s.add(user)
        s.commit()
        s.refresh(user)
        s.add(TeamMembership(team_id=1, user_id=user.id, role="admin"))
        s.commit()
    for module in (cbom_http, cbom_node, cbom_vendor_public):
        module.get_db = lambda: engine  # type: ignore[attr-defined]
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {auth_utils.create_access_token(email)}"}
    base = "/1/cbom/sources"
    domains = [d.strip() for d in args.domains.split(",") if d.strip()]
    issuers = [i.strip() for i in args.expected_issuers.split(",") if i.strip()]
    created = client.post(f"{base}/items", headers=headers, json={
        "kind": "ct_logs", "name": "Certificate Transparency",
        "config": {"domains": domains, "include_subdomains": True, "expected_issuers": issuers}})
    created.raise_for_status()
    estimate = client.post(f"{base}/estimate", headers=headers, json={"include": {"cloud": True}}).json()
    run = client.post(f"{base}/runs", headers=headers, json={"include": {"cloud": True}, "client_request_id": "ct-live-1",
                                                             "expected_credits": estimate["total_credits"]})
    run.raise_for_status()
    started = time.monotonic()
    while cbom_cloud_worker.run_once(engine, "gha-ct-live"):
        pass
    wall = round(time.monotonic() - started, 2)
    with Session(engine) as s:
        run_row = s.get(CbomCollectionRun, run.json()["run"]["id"])
        job = s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run_row.id)).one()
        rows = s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.job_id == job.id,
                                                       CbomCollectedAsset.attempt == job.attempts)).all()
        stored = [{"asset_type": r.asset_type, "target": r.target, "location": r.location, "name": r.name,
                   "algorithm": r.algorithm, "key_size": r.key_size, "impact": r.impact,
                   "finding_codes": r.finding_codes, "facts": r.facts} for r in rows]
        out = {"captured_at": dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"), "domains": domains,
               "provider_env": os.environ.get("CBOM_CT_PROVIDER"), "estimate": estimate["total_credits"],
               "run": {"id": run_row.id, "status": run_row.status, "charged_c": run_row.credits_charged_c,
                       "refunded_c": run_row.credits_refunded_c},
               "job": {"status": job.status, "outcome": job.outcome, "error": job.error, "asset_count": job.asset_count,
                       "result": job.result, "wall_s": wall},
               "rows": stored}
    args.out.write_text(json.dumps(out, indent=1, sort_keys=True, default=str) + "\n")
    certs = sum(1 for r in stored if r["asset_type"] == "certificate")
    print(f"job {job.status}/{job.outcome}: {certs} certificates stored, {len(stored) - certs} coverage rows, "
          f"{wall} s; provider calls {job.result.get('provider_calls')}; charged {run_row.credits_charged_c / 100} credits")
    return 0 if job.status == "success" else 1


if __name__ == "__main__":
    sys.exit(main())
