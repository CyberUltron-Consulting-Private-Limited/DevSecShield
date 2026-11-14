"""F1.2 inventory scale proof against PostgreSQL (see run.sh, which creates the schema with the real migrations).

Scenarios, each timed end to end:
* ``import_1k`` / ``import_10k``: N targets as CSV through ``POST /{team}/cbom/sources/fleet/inventory/import`` (the
  real route: auth, body cap, parsing, policy evaluation, upsert), then the same file again (must be a no-op:
  0 created, 0 updated, N unchanged, no row_version change), then 10% of the rows with a changed tag (must update
  exactly those);
* ``aws_1k``: 1,000 EC2 instances in 3 regions (moto), discovered by the AWS inventory source through the role with the
  external-ID check, saved by the sync (``fleet.sync.run_sync``), then synced again (must be a no-op).

Acceptance (PARALLEL-PLAN F1.2): 1,000 targets imported in < 2 min; re-import idempotent.  Exit 1 if any check fails.

    PYTHONPATH=<root> python bench/f1_inventory/bench.py --db postgresql://... --out report.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("CBOM_FLEET_INVENTORY", "1")
os.environ.setdefault("CBOM_FLEET_POLICIES", "1")

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine  # noqa: E402

from backend.main import app  # noqa: E402
from backend.new_models import CbomCollectionSource, Team, TeamMembership, User  # noqa: E402
from backend.utilities.auth import auth_utils  # noqa: E402
from backend.utilities.cbom_sources import http as cbom_http  # noqa: E402
from backend.utilities.cbom_sources.fleet import sync as SYNC  # noqa: E402
from backend.utilities.cbom_sources.fleet.models import FLEET_MODELS, CbomInventorySource  # noqa: E402

EMAIL = "bench-admin@f12.test"
LIMIT_S = 120.0
checks: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    checks.append((name, bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL'} {name} {detail}", flush=True)


def schema_parity(engine) -> None:
    """Every fleet table and column the models declare exists after `alembic upgrade head`."""
    with engine.connect() as conn:
        for model in FLEET_MODELS:
            table = model.__tablename__
            cols = {r[0] for r in conn.execute(text(
                "SELECT column_name FROM information_schema.columns WHERE table_name = :t"), {"t": table})}
            want = {c.name for c in model.__table__.columns}
            check(f"schema {table}", cols == want, f"missing={sorted(want - cols)} extra={sorted(cols - want)}")
        for table, column in (("cbomcollectionsource", "managed_by_policy_id"), ("cbomcollectionsource", "credential_id"),
                              ("cbomcollectionsource", "batch_key"), ("cbomcollectionschedule", "policy_id")):
            n = conn.execute(text("SELECT count(*) FROM information_schema.columns WHERE table_name = :t AND "
                                  "column_name = :c"), {"t": table, "c": column}).scalar()
            check(f"schema {table}.{column}", n == 1)


def seed(engine) -> None:
    with Session(engine) as s:
        s.add(Team(id=1, name="Bench Bank", credit_balance=1000.0))
        s.commit()
        user = User(email=EMAIL, password="x", first_name="bench", last_name="admin", profile_photo=None,
                    session_active=True, default_team_id=1)
        s.add(user)
        s.commit()
        s.refresh(user)
        s.add(TeamMembership(team_id=1, user_id=user.id, role="admin"))
        s.commit()


def csv_rows(n: int, *, prefix: str, changed_every: int = 0) -> str:
    lines = ["external_id,kind,address,hostname,tag:env,tag:team,tag:app"]
    for i in range(n):
        env = "stage" if changed_every and i % changed_every == 0 else "prod"
        lines.append(f"{prefix}-{i:06d},linux_host,10.{i // 62500}.{i // 250 % 250}.{i % 250 + 1},"
                     f"{prefix}-{i:06d}.bank.local,{env},payments,app{i % 37}")
    return "\n".join(lines) + "\n"


def versions(engine, prefix: str) -> dict[str, int]:
    with engine.connect() as conn:
        return {r[0]: r[1] for r in conn.execute(text(
            "SELECT external_id, row_version FROM cbominventorytarget WHERE team_id = 1 AND external_id LIKE :p"),
            {"p": f"{prefix}-%"})}


def import_scenario(client, headers, engine, n: int, name: str) -> dict:
    out: dict = {"targets": n}
    content = csv_rows(n, prefix=name)
    t0 = time.monotonic()
    r = client.post("/1/cbom/sources/fleet/inventory/import", headers=headers,
                    json={"format": "csv", "content": content, "inventory_source_id": None})
    out["first_s"] = round(time.monotonic() - t0, 3)
    first = r.json()
    out["first"] = {k: first.get(k) for k in ("created", "updated", "unchanged", "missing", "error_count")}
    check(f"{name} first import < {LIMIT_S:.0f} s", r.status_code == 200 and out["first_s"] < LIMIT_S,
          f"{out['first_s']} s, {out['first']}")
    check(f"{name} first import created all", first.get("created") == n)
    before = versions(engine, name)
    t0 = time.monotonic()
    again = client.post("/1/cbom/sources/fleet/inventory/import", headers=headers,
                        json={"format": "csv", "content": content}).json()
    out["reimport_s"] = round(time.monotonic() - t0, 3)
    out["reimport"] = {k: again.get(k) for k in ("created", "updated", "unchanged", "missing")}
    check(f"{name} re-import is a no-op", (again["created"], again["updated"], again["unchanged"], again["missing"])
          == (0, 0, n, 0) and versions(engine, name) == before, f"{out['reimport_s']} s, {out['reimport']}")
    t0 = time.monotonic()
    changed = client.post("/1/cbom/sources/fleet/inventory/import", headers=headers,
                          json={"format": "csv", "content": csv_rows(n, prefix=name, changed_every=10)}).json()
    out["change10_s"] = round(time.monotonic() - t0, 3)
    out["change10"] = {k: changed.get(k) for k in ("created", "updated", "unchanged", "missing")}
    check(f"{name} 10% changed updates exactly those", (changed["created"], changed["updated"], changed["unchanged"])
          == (0, n // 10, n - n // 10), f"{out['change10_s']} s, {out['change10']}")
    with engine.connect() as conn:
        total, distinct = conn.execute(text("SELECT count(*), count(DISTINCT external_id) FROM cbominventorytarget "
                                            "WHERE team_id = 1 AND external_id LIKE :p"), {"p": f"{name}-%"}).one()
    check(f"{name} no duplicates", total == distinct == n, f"rows={total}")
    return out


def aws_scenario(engine, n: int = 1000) -> dict:
    import boto3
    import moto
    from botocore.exceptions import ClientError

    from backend.utilities.cbom_sources.fleet import aws_inventory

    account = "123456789012"
    role = f"arn:aws:iam::{account}:role/DevSecShieldScannerReadOnlyRole"
    regions = ["us-east-1", "us-west-2", "eu-west-1"]

    class Guard:
        def __init__(self, client):
            self._c = client

        def assume_role(self, **kw):
            if "ExternalId" not in kw:
                raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "AssumeRole")
            return self._c.assume_role(**kw)

        def __getattr__(self, name):
            return getattr(self._c, name)

    class Sess:
        def __init__(self):
            self._s = boto3.session.Session(aws_access_key_id="zs", aws_secret_access_key="zs", region_name="us-east-1")

        def client(self, service, **kw):
            c = self._s.client(service, **kw)
            return Guard(c) if service == "sts" else c

    out: dict = {"instances": n, "regions": regions}
    with moto.mock_aws():
        boto3.client("iam", region_name="us-east-1").create_role(RoleName="DevSecShieldScannerReadOnlyRole",
                                                                  AssumeRolePolicyDocument="{}")
        t0 = time.monotonic()
        per = [n // 3 + (1 if i < n % 3 else 0) for i in range(3)]
        for region, count in zip(regions, per):
            ec2 = boto3.client("ec2", region_name=region)
            image = next(i["ImageId"] for i in ec2.describe_images(Owners=["amazon"])["Images"] if not i.get("Platform"))
            made = 0
            while made < count:
                k = min(250, count - made)
                ec2.run_instances(ImageId=image, MinCount=k, MaxCount=k, InstanceType="t3.micro", TagSpecifications=[
                    {"ResourceType": "instance", "Tags": [{"Key": "env", "Value": "prod"},
                                                          {"Key": "Project", "Value": "DevSecShield"}]}])
                made += k
        out["moto_setup_s"] = round(time.monotonic() - t0, 3)
        aws_inventory._boto = lambda **kw: (Sess(), None)  # the bench's own process: ZeroShield's principal = moto
        with Session(engine) as s:
            acct = CbomCollectionSource(team_id=1, owner_user_id=1, kind="aws_account", name="bench-aws",
                                        name_lower="bench-aws", config={"role_arn": role, "regions": regions},
                                        last_test_status="passed")
            s.add(acct)
            s.commit()
            src = CbomInventorySource(team_id=1, kind="aws", name="bench-aws",
                                      config={"aws_account_source_id": acct.id, "regions": regions,
                                              "services": ["ec2"]})
            s.add(src)
            s.commit()
            src_id = src.id
        t0 = time.monotonic()
        first = SYNC.run_sync(engine, src_id)
        out["first_sync_s"] = round(time.monotonic() - t0, 3)
        out["first"] = {k: first.get(k) for k in ("status", "created", "updated", "unchanged", "missing")}
        check("aws_1k first sync < 120 s and created all", first["status"] == "ok" and first["created"] == n
              and out["first_sync_s"] < LIMIT_S, f"{out['first_sync_s']} s, {out['first']}")
        t0 = time.monotonic()
        again = SYNC.run_sync(engine, src_id)
        out["resync_s"] = round(time.monotonic() - t0, 3)
        out["resync"] = {k: again.get(k) for k in ("status", "created", "updated", "unchanged", "missing")}
        check("aws_1k re-sync is a no-op", (again["created"], again["updated"], again["unchanged"], again["missing"])
              == (0, 0, n, 0), f"{out['resync_s']} s, {out['resync']}")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--db", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    engine = create_engine(args.db, pool_pre_ping=True)
    SQLModel.metadata.create_all(engine)  # no-op for tables the migrations made; only checked below
    schema_parity(engine)
    seed(engine)
    cbom_http.get_db = lambda: engine  # the routes' engine (authorize reads it from this module)
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {auth_utils.create_access_token(EMAIL)}"}
    report = {"database": "postgresql 15 (docker postgres:15-alpine)", "python": sys.version.split()[0],
              "cpus": os.cpu_count()}
    report["import_1k"] = import_scenario(client, headers, engine, 1000, "k1")
    report["import_10k"] = import_scenario(client, headers, engine, 10_000, "k10")
    report["aws_1k"] = aws_scenario(engine)
    report["checks"] = [{"check": c, "ok": ok, "detail": d} for c, ok, d in checks]
    report["ok"] = all(ok for _c, ok, _d in checks)
    Path(args.out).write_text(json.dumps(report, indent=2))
    print(json.dumps({k: v for k, v in report.items() if k != "checks"}, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
