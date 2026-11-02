#!/usr/bin/env python3
"""Offline rehearsal of the seed and of the six PDFs - no Docker, no HTTP, no Postgres, no Mongo.

Runs the REAL ``seed_team.run_seed`` against a throw-away SQLite file and an in-memory Mongo stand-in,
then renders the six team-wide PDFs exactly as the router does (``load_team_cbom_view`` + the
registered ``build`` function) for the demo team, the empty team and (with ``--perf``) the perf team.
It also replays the attestation upload of spec 91 on scan 2 and renders document #10 again.

Purpose: let a developer check the seed, ``fixtures/expected.json`` and the PDF oracle without the
Docker stack - the output directory feeds ``selftest/oracle.spec.ts``::

    WT=<this worktree>
    bash e2e/fixtures/build_trees.sh                                   # trees under e2e/.work
    PYTHONPATH=$WT/aibom/src <aibom venv>/bin/python e2e/seed/scan_trees.py     # needs E2E_TREES_DIR/E2E_OUT_DIR
    PYTHONPATH=$WT <backend venv>/bin/python e2e/seed/dryrun_world.py --out /tmp/dss-dryrun
    E2E_SELFTEST_DIR=/tmp/dss-dryrun E2E_SEED_JSON=/tmp/dss-dryrun/seed.json \\
        E2E_TEST_DIR=$WT/e2e/selftest npx playwright test

It is NOT part of the stack and shares no state with it; the SQLite file lives in the output directory.
Everything that touches a database goes through the same code the stack runs.  Differences from the
stack: SQLite instead of Postgres (explicit ids work the same), a list-backed Mongo stand-in that only
implements ``delete_many`` / ``insert_many`` / ``count_documents`` (all that ``create_findings_in_mongo_db``
needs), and no HTTP layer (the HTTP contract is covered by ``backend/tests/test_cbom_deliverables_route.py``).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import timedelta
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))

# auth_utils / chatbot read these at import time.  Test values only; never real keys.
for key, value in {
    "JWT_SECRET_KEY": "dryrun-secret",
    "JWT_REFRESH_SECRET_KEY": "dryrun-refresh",
    "AWS_ACCESS_KEY_ID": "DUMMYDUMMYDUMMY",
    "AWS_SECRET_ACCESS_KEY": "dummydummydummy",
    "AWS_DEFAULT_REGION": "us-east-1",
    "RABBIT_ADMIN_USERNAME": "u",
    "RABBIT_ADMIN_PASSWORD": "p",
}.items():
    os.environ.setdefault(key, value)

import seed_team  # noqa: E402


class FakeCursor(list):
    """What ``collection.find()`` returns: iterable, sortable (no-op) and usable as a context manager."""

    def sort(self, *_args: Any, **_kwargs: Any) -> FakeCursor:
        return self

    def __enter__(self) -> FakeCursor:
        return self

    def __exit__(self, *_exc: Any) -> bool:
        return False


class FakeCollection:
    """The slice of a pymongo collection the seed and the scan routes use (list backed, exact-match queries)."""

    def __init__(self) -> None:
        self.docs: list[dict[str, Any]] = []

    @staticmethod
    def _matches(doc: dict[str, Any], query: dict[str, Any]) -> bool:
        return all(doc.get(k) == v for k, v in query.items())

    def delete_many(self, query: dict[str, Any]) -> Any:
        before = len(self.docs)
        self.docs = [d for d in self.docs if not self._matches(d, query)]
        return type("DeleteResult", (), {"deleted_count": before - len(self.docs)})()

    def insert_many(self, docs: list[dict[str, Any]]) -> None:
        from bson import ObjectId

        for doc in docs:
            doc.setdefault("_id", ObjectId())
        self.docs.extend(docs)

    def find(self, query: dict[str, Any] | None = None, *_args: Any, **_kwargs: Any) -> FakeCursor:
        return FakeCursor(d for d in self.docs if self._matches(d, query or {}))

    def find_one(self, query: dict[str, Any] | None = None, *_args: Any, **_kwargs: Any) -> dict[str, Any] | None:
        return next(iter(self.find(query)), None)

    def update_one(self, query: dict[str, Any], update: dict[str, Any], *_args: Any, **_kwargs: Any) -> Any:
        doc = self.find_one(query)
        if doc is not None:
            doc.update(update.get("$set", {}))
        changed = int(doc is not None)
        return type("UpdateResult", (), {"matched_count": changed, "modified_count": changed})()

    def count_documents(self, query: dict[str, Any]) -> int:
        return sum(1 for d in self.docs if self._matches(d, query))


class FakeMongo:
    def __init__(self) -> None:
        self.collections: dict[str, FakeCollection] = {}

    def __getitem__(self, name: str) -> FakeCollection:
        return self.collections.setdefault(name, FakeCollection())


def render_team(engine: Any, team_id: int, name: str, now: Any, out: Path) -> dict[str, Any]:
    from backend.utilities.dashboard.cbom_team_rollup import load_team_cbom_view
    from backend.utilities.pdf.cbom_deliverables import DELIVERABLES

    view = load_team_cbom_view(engine, team_id, now=now)
    out.mkdir(parents=True, exist_ok=True)
    for slug, spec in DELIVERABLES.items():
        (out / f"{spec.number:02d}-{slug}.pdf").write_bytes(spec.build(view))
    print(f"[dryrun] team {team_id} ({name}): {view.included} scans folded, {len(view.sources)} sources, "
          f"fidelity {view.fidelity_summary}, fingerprint {view.fingerprint} -> {out}")
    return {"included": view.included, "sources": len(view.sources), "fidelity": view.fidelity_summary,
            "fingerprint": view.fingerprint}  # fmt: skip


def attest(engine: Any, expected: dict[str, Any]) -> dict[str, Any]:
    """Replay what ``POST /{team}/cbom/scan/{id}/attestations`` stores (routers/certin.py)."""
    from sqlmodel import Session, select

    from backend.new_models import Scan
    from backend.utilities.compliance.certin_attest import recompute_compliance_for_scan, upsert_attestation

    spec = expected["attestation"]
    with Session(engine) as session:
        scan = session.exec(select(Scan).where(Scan.id == spec["scan"])).one()
        data = dict(scan.scan_data)
        attestations = upsert_attestation(
            data.get("attestations"),
            framework=spec["framework"],
            requirement_id=spec["requirement_id"],
            filename=spec["filename"],
            note=spec["note"],
        )
        updated = recompute_compliance_for_scan("cbom", data, attestations)
        scan.scan_data = updated
        session.add(scan)
        session.commit()
    return updated["attestations"][spec["framework"]][spec["requirement_id"]]


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--out", type=Path, required=True, help="output directory (created)")
    parser.add_argument("--work-dir", type=Path, default=ROOT / "e2e" / ".work",
                        help="directory holding out/*.scan_data.json and trees/ (default: e2e/.work)")  # fmt: skip
    parser.add_argument("--perf", action="store_true", help="also seed and render the perf team")
    parser.add_argument("--serve", type=int, metavar="PORT",
                        help="afterwards serve the REAL FastAPI app on 127.0.0.1:PORT")
    parser.add_argument("--cors", default="http://127.0.0.1:43100",
                        help="origin(s) the served API accepts (comma separated)")
    args = parser.parse_args()
    os.environ["CORS_ORIGINS"] = args.cors  # read once, when backend.main is imported

    from sqlmodel import SQLModel, create_engine

    import backend.new_models  # noqa: F401  (registers the tables)

    args.out.mkdir(parents=True, exist_ok=True)
    db_file = args.out / "dryrun.sqlite"
    if db_file.exists():
        db_file.unlink()
    engine = create_engine(f"sqlite:///{db_file}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)

    env = {
        "E2E_WORK_DIR": str(args.work_dir),
        "E2E_LEGACY_SCAN_DATA": str(ROOT / "backend" / "tests" / "fixtures" / "cbom_export_scandata.json"),
        "E2E_ADMIN_EMAIL": "e2e-admin@dss-e2e.test", "E2E_ADMIN_PASSWORD": "Adm1n-dry-run-pw!",
        "E2E_OTHER_EMAIL": "e2e-other@dss-e2e.test", "E2E_OTHER_PASSWORD": "0ther-dry-run-pw!",
        "E2E_EMPTY_EMAIL": "e2e-empty@dss-e2e.test", "E2E_EMPTY_PASSWORD": "Empty-dry-run-pw!",
        "DSS_DEV_MODE": "1",  # the fixed admin code only works in dev mode, exactly as on the e2e stack
        "LOCAL_DEV_VERIFICATION_EMAIL": "e2e-admin@dss-e2e.test", "LOCAL_DEV_VERIFICATION_CODE": "123456",
        "E2E_SEED_PERF": "1" if args.perf else "",
    }  # fmt: skip
    # auth_utils reads these when a code is checked
    os.environ.update({k: v for k, v in env.items() if k.startswith("LOCAL_DEV_") or k == "DSS_DEV_MODE"})
    if os.environ.get("E2E_SEED_NOW"):
        env["E2E_SEED_NOW"] = os.environ["E2E_SEED_NOW"]
    cfg = seed_team.config_from_env(env)
    cfg.seed_json = args.out / "seed.json"
    mongo = FakeMongo()
    try:
        seed_team.run_seed(engine, mongo, cfg)
    except seed_team.SeedError as exc:
        print(f"[dryrun] seed failed ({exc.code}): {exc}", file=sys.stderr)
        return exc.code

    expected = json.loads(cfg.expected_path.read_text(encoding="utf-8"))
    later = cfg.now + timedelta(minutes=2)  # the "download" happens a little after the seed
    summary = {"demo": render_team(engine, 1, "E2E Demo Team", later, args.out / "team1")}
    summary["empty"] = render_team(engine, 3, "Empty Team", later, args.out / "team3")
    if args.perf:
        summary["perf"] = render_team(engine, 4, "Perf Team", later, args.out / "team4")
    if args.serve:
        # The served database must stay pristine: spec 91 performs the attestation itself.
        (args.out / "dryrun.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return serve(engine, mongo, args.serve)
    meta = attest(engine, expected)
    summary["attestation"] = meta
    summary["demo_after_attestation"] = render_team(engine, 1, "E2E Demo Team", later, args.out / "team1-attested")
    (args.out / "dryrun.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"[dryrun] done; PDFs under {args.out} (seed.json, dryrun.json, dryrun.sqlite alongside)")
    return 0


def serve(engine: Any, mongo: FakeMongo, port: int) -> int:
    """Serve the real FastAPI app (all routers) on loopback until interrupted."""
    import uvicorn

    import backend.get_db as get_db_module

    # get_db() / get_mongo_client_db() return these module singletons when they are already set.
    get_db_module._pg_engine = engine
    get_db_module._mongo_db = mongo
    from backend.main import app

    print(f"[dryrun] serving the real app on http://127.0.0.1:{port} (Ctrl-C to stop)", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
    return 0


if __name__ == "__main__":
    tempfile.tempdir = None
    sys.exit(main())
