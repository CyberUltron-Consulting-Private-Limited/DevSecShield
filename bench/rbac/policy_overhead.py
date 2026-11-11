"""What the F4 route policy adds to a request: GET /team/{id} with and without its TeamPermission, on PostgreSQL.

    PYTHON_DOTENV_DISABLED=1 PYTHONPATH=. JWT_SECRET_KEY=x JWT_REFRESH_SECRET_KEY=y AWS_ACCESS_KEY_ID=x \
      AWS_SECRET_ACCESS_KEY=y AWS_DEFAULT_REGION=us-east-1 \
      backend/.venv/bin/python bench/rbac/policy_overhead.py postgresql+psycopg2://user@host:port/db [requests]

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
from sqlmodel import Session, SQLModel, create_engine


def main() -> int:
    url = sys.argv[1]
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 2000
    schema = f"rbac_bench_{uuid.uuid4().hex[:8]}"
    admin = create_engine(url)
    with admin.begin() as conn:
        conn.execute(sa.text(f'CREATE SCHEMA "{schema}"'))
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
    finally:
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(sa.text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
