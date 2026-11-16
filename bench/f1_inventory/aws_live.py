"""F1.2 live proof: AWS discovery through a real read-only role, across every enabled region (read-only, creates nothing).

    source <credentials file that exports AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY>   # never printed
    PYTHONPATH=<root> python bench/f1_inventory/aws_live.py --role-name DevSecShieldScannerReadOnlyRole --out live.json

What it does, with the product's own code (``fleet.aws_inventory``, ``fleet.store``, ``fleet.policy``):
1. The production pre-check (``AwsInventorySource.discover``): the role must REFUSE AssumeRole without the team's
   external ID.  A role without that condition is refused here by design; the refusal is recorded.
2. ``discover_account`` below the pre-check, through the same ``aws_collect._Account`` (AssumeRole with an external
   ID, then a check that the assumed identity is in the role's account), every requested service in every enabled
   region plus one region that is not enabled (it must show up as a coverage gap, never as silence).
3. The same discovery a second time: the digest (external ids + fingerprints) must be identical.
4. Both discoveries saved through ``store.upsert`` into a throwaway SQLite database: the second save must report
   0 created, 0 updated, N unchanged.
5. Tag policies evaluated on the real targets in 20 shuffled policy orders: every Decision identical.

Only list/describe calls are made.  The report holds counts, coverage and timings; the identifiers of resources are
reported only for resources tagged ``zs-lab=sandbox`` (ours); any other identifier is replaced by a short hash.
Credentials are read from the environment into ZeroShield's ``CBOM_AWS_*`` names inside this process only.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import random
import sys
import time
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def _mask(value: str) -> str:
    return "h:" + hashlib.sha256(value.encode()).hexdigest()[:12]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--role-name", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--regions", default="enabled", help="'enabled' (every enabled region) or a comma list")
    ap.add_argument("--extra-region", default="me-south-1", help="a region expected NOT to be enabled (coverage gap)")
    args = ap.parse_args()

    key, secret = os.environ.pop("AWS_ACCESS_KEY_ID", ""), os.environ.pop("AWS_SECRET_ACCESS_KEY", "")
    os.environ.pop("AWS_SESSION_TOKEN", None)
    if not (key and secret):
        print("no credentials in the environment", file=sys.stderr)
        return 2
    os.environ["CBOM_AWS_ACCESS_KEY_ID"], os.environ["CBOM_AWS_SECRET_ACCESS_KEY"] = key, secret
    del key, secret

    from sqlmodel import Session, SQLModel, create_engine

    from backend.utilities.cbom_sources.aws_collect import _Account
    from backend.utilities.cbom_sources.aws_validate import _boto, _code
    from backend.utilities.cbom_sources.fleet import store
    from backend.utilities.cbom_sources.fleet.aws_inventory import SERVICES, AwsInventorySource, discover_account
    from backend.utilities.cbom_sources.fleet.inventory_sources import InventoryError
    from backend.utilities.cbom_sources.fleet.models import CbomInventorySource
    from backend.utilities.cbom_sources.fleet.policy import PolicyEngine

    report: dict = {"started_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "checks": []}

    def check(name: str, ok: bool, detail: str = "") -> None:
        report["checks"].append({"check": name, "pass": bool(ok), "detail": detail})
        print(f"{'PASS' if ok else 'FAIL'} {name} {detail}", flush=True)

    base, cfg = _boto(retries=5, mode="adaptive")
    account = str(base.client("sts", region_name="us-east-1", config=cfg).get_caller_identity()["Account"])
    role_arn = f"arn:aws:iam::{account}:role/{args.role_name}"
    report["account"] = "…" + account[-4:]
    report["role"] = args.role_name

    # 1. the production pre-check
    probe = AwsInventorySource(team_id=0, role_arn=role_arn, external_id="zs-f12-live-" + os.urandom(6).hex(),
                               regions=["us-east-1"], services=["ec2"])
    try:
        probe.discover()
        report["precheck"] = {"result": "passed (the role requires an external ID)"}
    except InventoryError as exc:
        report["precheck"] = {"result": "refused", "code": exc.code, "message": str(exc)}
    print("pre-check:", report["precheck"], flush=True)

    # 2. below the pre-check: the same _Account, every service, every enabled region (+ one that is not enabled)
    acct = _Account(base, cfg, role_arn, "zs-f12-live-" + os.urandom(6).hex(), 0)
    try:
        acct.assume("us-east-1")
    except Exception as exc:  # noqa: BLE001 - recorded and reported; nothing else is tried
        report["assume"] = {"result": "failed", "code": _code(exc)}
        Path(args.out).write_text(json.dumps(report, indent=2))
        print("AssumeRole failed:", _code(exc), file=sys.stderr)
        return 1
    report["assume"] = {"result": "ok"}
    if args.regions == "enabled":
        regions_info = acct.client("ec2", "us-east-1").describe_regions(AllRegions=True)["Regions"]
        enabled = sorted(r["RegionName"] for r in regions_info if r.get("OptInStatus") != "not-opted-in")
        disabled = sorted(r["RegionName"] for r in regions_info if r.get("OptInStatus") == "not-opted-in")
    else:
        enabled, disabled = sorted(r.strip() for r in args.regions.split(",") if r.strip()), []
    extra = [args.extra_region] if args.extra_region in disabled else []
    regions = enabled + extra
    report["regions"] = {"enabled": enabled, "not_enabled_probe": extra, "not_enabled_total": len(disabled)}

    from backend.utilities.cbom_sources.fleet.aws_inventory import Discovery

    runs = []
    report["region_seconds"] = {}
    for attempt in (1, 2):
        started = time.monotonic()
        found = Discovery(account_id=acct.account)
        for region in regions:  # one region at a time, so a slow region shows up in the progress and the report
            t0 = time.monotonic()
            part = discover_account(acct, [region], list(SERVICES))
            found.targets += part.targets
            found.coverage.update(part.coverage)
            found.errors += part.errors
            report["region_seconds"].setdefault(region, []).append(round(time.monotonic() - t0, 1))
            print(f"  run {attempt} {region}: {len(part.targets)} targets, {part.coverage[region]} "
                  f"in {time.monotonic() - t0:.1f}s", flush=True)
            Path(args.out).write_text(json.dumps(report, indent=2, default=str))  # partial, in case it is stopped
        took = time.monotonic() - started
        runs.append((found, took))
        print(f"discovery {attempt}: {len(found.targets)} targets in {took:.1f}s", flush=True)
    first, second = runs[0][0], runs[1][0]
    report["discovery"] = {
        "seconds": [round(t, 1) for _f, t in runs],
        "targets": len(first.targets),
        "calls_scope": f"{len(regions)} regions x {len(SERVICES)} services",
        "by_kind": dict(sorted(Counter(t.kind for t in first.targets).items())),
        "by_region_service": {r: {s: {"status": st, "targets": sum(1 for t in first.targets if t.region == r
                                                                   and (t.attributes or {}).get("service") == s)}
                                  for s, st in svc.items()} for r, svc in first.coverage.items()},
        "normalise_errors": [{"external_id": _mask(e["external_id"]), "error": e["error"]} for e in first.errors],
    }
    statuses = Counter(st for svc in first.coverage.values() for st in svc.values())
    report["discovery"]["coverage_statuses"] = dict(statuses)
    check("every region x service has a status", all(len(first.coverage[r]) == len(SERVICES) for r in regions),
          f"{len(regions)} regions")
    if extra:
        gap = set(first.coverage[extra[0]].values())
        took = report["region_seconds"][extra[0]]
        check("a region that is not enabled is a gap, not silence",
              bool(gap) and "ok" not in gap and not any(t.region == extra[0] for t in first.targets),
              f"{extra[0]}: {sorted(gap)} in {took} s")
    check("discovery is repeatable (same digest twice)", store.digest(first.targets) == store.digest(second.targets),
          f"{store.digest(first.targets)[:12]} vs {store.digest(second.targets)[:12]}")
    check("same coverage twice", first.coverage == second.coverage)
    sandbox = [t for t in first.targets if (t.tags or {}).get("zs-lab") == "sandbox"]
    report["sandbox_targets"] = [{"external_id": t.external_id, "kind": t.kind, "region": t.region,
                                  "tags": {k: v for k, v in t.tags.items() if k in ("project", "zs-lab", "zs-owner", "env")}}
                                 for t in sorted(sandbox, key=lambda t: t.external_id)]

    # 3-4. saved twice through the product's upsert (throwaway SQLite)
    import backend.new_models  # noqa: F401 - every table the fleet rows refer to

    db = create_engine("sqlite://")
    SQLModel.metadata.create_all(db)
    now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    with Session(db) as session:
        src = CbomInventorySource(team_id=1, owner_user_id=1, kind="aws", name="live", config={}, created_at=now,
                                  last_updated=now)
        session.add(src)
        session.flush()
        a = store.upsert(session, 1, src, first.targets, now, engine=None, snapshot=True)
        session.commit()
        later = now + dt.timedelta(minutes=5)
        b = store.upsert(session, 1, src, second.targets, later, engine=None, snapshot=True)
        session.commit()
    report["upsert"] = {"first": a.public(), "second": b.public()}
    for part in ("first", "second"):
        report["upsert"][part].pop("errors", None)
    check("first save creates every target", a.created == len(first.targets) and a.updated == 0,
          f"created={a.created}")
    check("second save is a no-op", (b.created, b.updated, b.missing) == (0, 0, 0) and b.unchanged == len(second.targets),
          f"created={b.created} updated={b.updated} unchanged={b.unchanged} missing={b.missing}")

    # 5. deterministic policy evaluation on the real targets
    def pol(pid: int, name: str, priority: int, selector: dict, action: dict) -> SimpleNamespace:
        return SimpleNamespace(id=pid, name=name, priority=priority, selector=selector, action=action, enabled=True,
                               deleted_at=None)

    ssh = {"transport": "ssh", "credential_id": 1, "node_id": 1}
    policies = [pol(1, "prod-weekly", 100, {"tag": "env", "op": "eq", "value": "prod"}, ssh),
                pol(2, "sandbox-never", 100, {"tag": "zs-lab", "op": "eq", "value": "sandbox"}, {"never_scan": True}),
                pol(3, "devsecshield", 50, {"tag": "project", "op": "exists"}, ssh),
                pol(4, "linux-ap-south", 50, {"all": [{"field": "kind", "op": "eq", "value": "linux_host"},
                                                      {"field": "region", "op": "prefix", "value": "ap-"}]}, ssh),
                pol(5, "everything", 0, {}, ssh)]
    baseline = {t.external_id: PolicyEngine(policies, None).evaluate(t) for t in first.targets}
    rng = random.Random(20261112)
    same = True
    for _ in range(20):
        shuffled = policies[:]
        rng.shuffle(shuffled)
        order = first.targets[:]
        rng.shuffle(order)
        engine = PolicyEngine(shuffled, None)
        same &= all(engine.evaluate(t) == baseline[t.external_id] for t in order)
    won = Counter((baseline[t].policy_id, baseline[t].action) for t in baseline)
    multi = sum(1 for d in baseline.values() if len(d.matched_policy_ids) > 1)
    report["policies"] = {"won": {f"{pid}:{act}": n for (pid, act), n in sorted(won.items(), key=str)},
                          "targets_matched_by_several": multi}
    check("decisions identical in 20 shuffled policy/target orders", same, f"{len(baseline)} targets")
    report["finished_at"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    report["result"] = "PASS" if all(c["pass"] for c in report["checks"]) else "FAIL"
    Path(args.out).write_text(json.dumps(report, indent=2, default=str))
    print(report["result"], flush=True)
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
