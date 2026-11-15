"""F3 scale proof: import N repositories (default 1,000) from a GitHub organisation, through the real provider client and
the real inventory sync, against the fake GitHub API (backend/tests/support/fake_scm.py) made deliberately slow and
hostile: per-page latency, a primary rate-limit budget that must be waited out, secondary limits with Retry-After, and
a 502. Then re-sync (idempotency) and a sync with a rename and a removal.

    PYTHONPATH=. JWT_SECRET_KEY=x JWT_REFRESH_SECRET_KEY=x python bench/scm/import_bench.py \
        --db postgresql://user@127.0.0.1:5432/bench --repos 1000 --latency 0.8 --out result.json

The target is < 5 minutes for 1,000 repositories. Prints one JSON document (and writes it to --out).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
os.environ.setdefault("JWT_SECRET_KEY", "bench-only")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "bench-only")
if not os.environ.get("ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet

    os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode()

from sqlalchemy import create_engine, func  # noqa: E402
from sqlmodel import Session, SQLModel, select  # noqa: E402

from backend.new_models import Team, TeamMembership, User  # noqa: E402
from backend.tests.support.fake_scm import FakeScmServer, FakeScmState, make_repos  # noqa: E402
from backend.utilities.cbom_sources.crypto import encrypt_secrets  # noqa: E402
from backend.utilities.scm import inventory as INV  # noqa: E402
from backend.utilities.scm.models import ScmConnection, ScmRepository  # noqa: E402

TOKEN = "bench-token"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True, help="SQLAlchemy URL of a throwaway database (tables are dropped)")
    ap.add_argument("--repos", type=int, default=1000)
    ap.add_argument("--latency", type=float, default=0.8, help="seconds the fake API takes per request")
    ap.add_argument("--rate-limit", type=int, default=6, help="requests per window before the API refuses")
    ap.add_argument("--rate-window", type=float, default=20.0, help="seconds per rate-limit window")
    ap.add_argument("--secondary-every", type=int, default=4, help="every Nth request is a secondary limit")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    engine = create_engine(args.db)
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        s.add(Team(id=1, name="Bench", credit_balance=1e6))
        s.commit()
        user = User(email="b@bench.test", password="x", first_name="b", last_name="b", profile_photo=None,
                    default_team_id=1)
        s.add(user)
        s.commit()
        s.add(TeamMembership(team_id=1, user_id=user.id, role="admin"))
        s.commit()

    state = FakeScmState(rate_limit=args.rate_limit, rate_window_s=args.rate_window,
                         secondary_every=args.secondary_every, fail_requests={3}, latency_s=args.latency)
    state.add_tokens(TOKEN)
    state.github_orgs["bank"] = make_repos("bank", args.repos)
    out: dict = {"repos": args.repos, "latency_s": args.latency, "rate_limit": f"{args.rate_limit}/{args.rate_window}s",
                 "secondary_every": args.secondary_every, "db": engine.dialect.name}
    with FakeScmServer(state) as srv:
        os.environ["GIT_ALLOWED_HOSTS"] = f"http://127.0.0.1:{srv.port}"
        with Session(engine) as s:
            conn = ScmConnection(team_id=1, owner_user_id=1, provider="github", auth_kind="token", name="bank",
                                 name_lower="bank", api_base=srv.url, scope_kind="org", scope_name="bank",
                                 filters={"exclude_topics": ["deprecated"]}, secret_encrypted=encrypt_secrets(
                                     {"token": TOKEN}), secret_fields=["token"], webhook_uid=os.urandom(16).hex())
            s.add(conn)
            s.commit()
            cid = conn.id
        t0 = time.monotonic()
        first = INV.sync_connection(engine, cid, max_wait_s=600)
        out["first_sync_s"] = round(time.monotonic() - t0, 2)
        out["first_sync"] = first
        t0 = time.monotonic()
        again = INV.sync_connection(engine, cid, max_wait_s=600)
        out["resync_s"] = round(time.monotonic() - t0, 2)
        out["resync"] = {k: again[k] for k in ("status", "added", "updated", "removed", "restored", "api_calls")}
        org = state.github_orgs["bank"]
        org[5] = {**org[5], "name": "renamed", "full_name": "bank/renamed"}
        org.pop(9)
        third = INV.sync_connection(engine, cid, max_wait_s=600)
        out["change_sync"] = {k: third[k] for k in ("status", "added", "updated", "removed")}
        with Session(engine) as s:
            out["rows"] = s.exec(select(func.count()).select_from(ScmRepository)).one()
            out["in_scope"] = s.exec(select(func.count()).select_from(ScmRepository)
                                     .where(ScmRepository.in_scope == True)).one()  # noqa: E712
        out["server"] = {"requests": len(state.requests), "responses": state.responses}
    out["target_s"] = 300
    out["pass"] = (out["first_sync_s"] < 300 and first["status"] == "ok" and first["added"] == args.repos
                   and out["resync"]["added"] == 0 and out["resync"]["updated"] == 0 and out["rows"] == args.repos
                   and out["change_sync"] == {"status": "ok", "added": 0, "updated": 1, "removed": 1})
    text = json.dumps(out, indent=2, default=str)
    print(text)
    if args.out:
        Path(args.out).write_text(text)
    SQLModel.metadata.drop_all(engine)
    return 0 if out["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
