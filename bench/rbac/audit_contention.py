"""Audit-log write path under concurrency (audit.record / record_now on PostgreSQL), per-team chains.

    PYTHON_DOTENV_DISABLED=1 PYTHONPATH=. JWT_SECRET_KEY=x JWT_REFRESH_SECRET_KEY=y \
      backend/.venv/bin/python bench/rbac/audit_contention.py postgresql+psycopg2://user@host:port/db

1) T writer threads (T = 1, 4, 8), each writing its own team's events in a loop for 6 s: events/s and latency.
2) One transaction recording 500 events for one team (PATCH /team/{id} intent=remove with 500 addresses) while
   another team's writer keeps writing: how long that other writer waits.
Adapted from the architecture review of PR #42 (scripts/audit_contention.py); runs in a fresh schema, dropped at the end.
"""
import statistics
import sys
import threading
import time
import uuid

from sqlalchemy import create_engine
from sqlalchemy.schema import CreateSchema, DropSchema
from sqlmodel import Session, SQLModel


def main() -> int:
    url = sys.argv[1]
    from backend.access_models import AuditEvent
    from backend.utilities.rbac import audit

    schema = f"audit_bench_{uuid.uuid4().hex[:8]}"
    admin = create_engine(url)
    with admin.begin() as conn:
        conn.execute(CreateSchema(schema))
    opts = {"options": f"-csearch_path={schema}"}

    def ev(i, team):
        return dict(action="scan.create", team_id=team, actor_user_id=i % 1000 + 1, actor_email=f"u{i}@example.com",
                    object_type="scan", object_id=i, ip="10.0.0.1", user_agent="bench",
                    details={"method": "POST", "route": "/{team_id}/scans"})

    def writers(t, secs=6):
        eng = create_engine(url, pool_size=t + 2, connect_args=opts)
        lat, stop = [], time.time() + secs

        def run(k):
            i = 0
            while time.time() < stop:
                t0 = time.perf_counter()
                audit.record_now(eng, **ev(i, 100001 + k))
                lat.append((time.perf_counter() - t0) * 1000)
                i += 1

        threads = [threading.Thread(target=run, args=(k,)) for k in range(t)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        lat.sort()
        q = lambda p: lat[int(p * (len(lat) - 1))]  # noqa: E731
        print(f"writers={t}: {len(lat) / secs:.0f} events/s, p50 {q(.5):.1f} ms, p99 {q(.99):.1f} ms, max {lat[-1]:.0f} ms")
        eng.dispose()

    def holder(n=500):
        eng = create_engine(url, pool_size=4, connect_args=opts)
        lat, done = [], threading.Event()

        def other():
            while not done.is_set():
                t0 = time.perf_counter()
                audit.record_now(eng, **ev(0, 104999))
                lat.append((time.perf_counter() - t0) * 1000)
                time.sleep(0.02)

        th = threading.Thread(target=other)
        th.start()
        time.sleep(0.5)
        t0 = time.perf_counter()
        with Session(eng) as s:
            for i in range(n):
                audit.record(s, **{**ev(i, 100002), "action": "team.members.remove"})
            s.commit()
        held = (time.perf_counter() - t0) * 1000
        time.sleep(0.5)
        done.set()
        th.join()
        print(f"one transaction recording {n} events of one team took ~{held:.0f} ms; another team's single audit "
              f"write meanwhile: max {max(lat):.0f} ms, median {statistics.median(lat):.1f} ms")
        eng.dispose()

    try:
        setup = create_engine(url, connect_args=opts)
        SQLModel.metadata.create_all(setup, tables=[AuditEvent.__table__])
        setup.dispose()
        for t in (1, 4, 8):
            writers(t)
        holder()
        check = create_engine(url, connect_args=opts)
        result = audit.verify_chain(check)
        print(f"verify_chain: ok={result['ok']} checked={result['checked']} chains={result['chains']}")
        check.dispose()
    finally:
        with admin.begin() as conn:
            conn.execute(DropSchema(schema, cascade=True))
        admin.dispose()
    return 0


if __name__ == "__main__":
    sys.exit(main())
