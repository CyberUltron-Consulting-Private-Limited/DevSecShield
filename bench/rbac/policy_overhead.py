"""What the F4 route policy adds to a request: GET /team/{id} with and without its TeamPermission, on PostgreSQL.

    PYTHON_DOTENV_DISABLED=1 PYTHONPATH=. JWT_SECRET_KEY=x JWT_REFRESH_SECRET_KEY=y AWS_ACCESS_KEY_ID=x \
      AWS_SECRET_ACCESS_KEY=y AWS_DEFAULT_REGION=us-east-1 \
      backend/.venv/bin/python bench/rbac/policy_overhead.py postgresql+psycopg2://user@host:port/db [requests] \
        [users] [no-email-index]

``users`` (default 1,000) accounts exist besides the bench user, so the account lookup is measured on a realistic
table (the PR #42 architecture review measured 100,000: a sequential scan without ``ix_user_email``);
``no-email-index`` drops ix_user_email / ix_user_email_lower first, to show the difference on the same host.

Creates its tables in a fresh schema (dropped at the end), 1,000 teams and 5,000 memberships so the lookups are
index lookups on a non-trivial table, then times the same route through the real app (rate limiter, policy,
handler) twice: as declared, and with the policy's dependency overridden by a no-op.  Prints p50 / p95 / p99 and
the per-request difference.  In-process (TestClient), so it measures server work, not the network.
"""
import statistics
import sys
import time
import uuid

import sqlalchemy as sa
from sqlalchemy.schema import CreateSchema, DropSchema
from sqlmodel import Session, SQLModel, create_engine


def main() -> int:
    url = sys.argv[1]
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 2000
    n_users = max(1000, int(sys.argv[3])) if len(sys.argv) > 3 else 1000
    drop_index = len(sys.argv) > 4 and sys.argv[4] == "no-email-index"
    schema = f"rbac_bench_{uuid.uuid4().hex[:8]}"
    admin = create_engine(url)
    with admin.begin() as conn:
        conn.execute(CreateSchema(schema))  # a quoted identifier, never interpolated SQL
    engine = create_engine(url, pool_size=5, connect_args={"options": f"-csearch_path={schema}"})
    try:
        import contextlib
        import io

        with contextlib.redirect_stdout(io.StringIO()):
            from fastapi.testclient import TestClient

            from backend.main import app
            from backend.new_models import Team, TeamMembership, User
            from backend.routers import team as team_router
            from backend.utilities import ratelimit
            from backend.utilities.auth.auth_utils import create_access_token
            from backend.utilities.rbac.policy import TeamPermission
        SQLModel.metadata.create_all(engine)
        team_router.get_db = lambda: engine  # the router and its policy share this getter
        with Session(engine) as s:
            s.add_all([Team(id=i, name=f"t{i}") for i in range(1, 1001)])
            s.commit()
            s.add_all([User(id=i, email=f"u{i}@bench.test", password="x", first_name="u", last_name="b",
                            profile_photo=None, session_active=True, default_team_id=1 + i % 1000)
                       for i in range(1, 1001)])
            s.commit()
        if n_users > 1000:  # the rest in bulk (Core inserts): accounts with no membership, as on a real platform
            table = User.__table__
            with engine.begin() as conn:
                for start in range(1001, n_users + 1, 10000):
                    conn.execute(table.insert(), [
                        {"id": i, "email": f"u{i}@bench.test", "password": "x", "first_name": "u", "last_name": "b",
                         "session_active": True, "default_team_id": 1 + i % 1000, "token_version": 0,
                         "must_change_password": False}
                        for i in range(start, min(start + 10000, n_users + 1))])
        with engine.begin() as conn:
            if drop_index:
                conn.execute(sa.text("DROP INDEX IF EXISTS ix_user_email"))
                conn.execute(sa.text("DROP INDEX IF EXISTS ix_user_email_lower"))
            conn.execute(sa.text('ANALYZE "user"'))
        print(f"users={n_users} email index={'dropped' if drop_index else 'ix_user_email + ix_user_email_lower'}")
        with Session(engine) as s:
            s.add_all([TeamMembership(team_id=1 + (u * 7 + k) % 1000, user_id=u, role="member")
                       for u in range(1, 1001) for k in range(5)])
            s.commit()
        user = 500
        with Session(engine) as s:
            team_id = s.exec(sa.select(TeamMembership.team_id).where(TeamMembership.user_id == user)).first()[0]
        headers = {"Authorization": f"Bearer {create_access_token(f'u{user}@bench.test', version=0)}"}
        client = TestClient(app)
        route = next(r for r in app.routes if getattr(r, "path", "") == "/team/{team_id}" and "GET" in r.methods)
        policy = next(d.call for d in route.dependant.dependencies if isinstance(d.call, TeamPermission))

        def run(label: str) -> list[float]:
            times = []
            for i in range(n + 50):
                if i % 100 == 0:
                    ratelimit.reset_all()
                t0 = time.perf_counter()
                r = client.get(f"/team/{team_id}", headers=headers)
                dt = (time.perf_counter() - t0) * 1000
                assert r.status_code == 200, r.text
                if i >= 50:  # warm-up
                    times.append(dt)
            q = statistics.quantiles(times, n=100)
            print(f"{label:16s} n={n}  p50={q[49]:.2f} ms  p95={q[94]:.2f} ms  p99={q[98]:.2f} ms  mean={statistics.mean(times):.2f} ms")
            return times

        with_policy = run("with policy")

        async def allow():
            return None

        app.dependency_overrides[policy] = allow
        try:
            without = run("policy bypassed")
        finally:
            app.dependency_overrides.pop(policy, None)
        diff50 = statistics.median(with_policy) - statistics.median(without)
        print(f"policy cost per request (median difference): {diff50:.2f} ms")

        # the policy's own database work, timed alone (less noisy than two whole-request runs on a busy host)
        from backend.utilities.auth.auth_utils import access_token_claims
        from backend.utilities.rbac.policy import _load_principal

        claims = access_token_claims(headers["Authorization"].split()[1])
        alone = []
        for i in range(n + 50):
            t0 = time.perf_counter()
            principal, problem = _load_principal(engine, claims, team_id, False)
            dt_ms = (time.perf_counter() - t0) * 1000
            assert problem is None and principal.role == "member"
            if i >= 50:
                alone.append(dt_ms)
        q = statistics.quantiles(alone, n=100)
        print(f"policy lookups alone (account + membership) n={n}  p50={q[49]:.2f} ms  p95={q[94]:.2f} ms  "
              f"p99={q[98]:.2f} ms")
    finally:
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(DropSchema(schema, cascade=True))
        admin.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
