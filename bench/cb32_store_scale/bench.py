"""CB-32 bench: the estate store's hot queries at 1.5M assets per team, on PostgreSQL.

Seeds (server-side ``generate_series``, minutes not hours) one team with N estate assets (default 1,500,000) and a
second team with N/10 (so every query must stay inside its team), with:
* ``cbomestatesource``: 8 sources per team;
* ``cbomestateasset``: 40 % certificates, 20 % TLS endpoints, 40 % libraries / keys / settings; presence 90 % present,
  6 % removed, 4 % not read; CB-25 agility columns (5 fix classes, 5,000 systems, a few unknown-reason sets);
* ``cbomestateobservation``: one per asset plus a second source for every fourth asset (1.25 N);
* ``cbomcollectedasset``: the stored row of every tenth observation (disk; the pointer lookups probe the same index
  either way, and the drill-down keys are drawn from those);
* ``cbomriskregister``: one row per asset (Q1..Q4 / Q0 / none, 8 families, 50 applications, 3 exposures).
Then times the hot queries through the product functions (``estate``, ``risk_register``, ``agility_rollup``), REPS
times each with random cursors / filters / keys, and prints p50 / p95 / max in ms per query, plus the PostgreSQL plan
of each query when ``--explain``.

    PYTHONPATH=<tree> python bench/cb32_store_scale/bench.py --pg postgresql+psycopg2://... [--n 1500000] [--reps 30]
        [--seed | --no-seed] [--explain]
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import random
import statistics
import sys
import time

import sqlalchemy as sa
from sqlmodel import Session, SQLModel, create_engine

from backend.new_models import Team  # noqa: F401  (registers the tables)

NOW = dt.datetime(2026, 11, 14, 9, 0)
TEAMS = {1: 1.0, 2: 0.02}
SOURCES = 8


def seed(engine, n: int) -> None:
    from backend.utilities.cbom_sources import agility as AG

    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    with engine.begin() as c:
        for team, share in TEAMS.items():
            m = int(n * share)
            p = {"t": team, "m": m, "now": NOW, "ver": AG.version()}
            c.execute(sa.text("INSERT INTO team (id, name, credit_balance) VALUES (:t, 'bench' || :t, 0)"), p)
            c.execute(sa.text(
                "INSERT INTO cbomcollectionrun (id, team_id, owner_user_id, client_request_id, status, "
                "credits_charged_c, credits_refunded_c, created_at, finished_at, drift_at) "
                "VALUES (:t * 1000, :t, 1, 'bench', 'done', 0, 0, :now, :now, :now)"), p)
            c.execute(sa.text(
                "INSERT INTO cbomcollectionjob (id, team_id, run_id, kind, status, outcome, weight_c, refunded, "
                "attempts, asset_count, created_at, finished_at) SELECT :t * 1000 + s, :t, :t * 1000, 'collect', "
                "'success', 'ok', 0, false, 1, 0, :now, :now FROM generate_series(0, 7) s"), p)
            c.execute(sa.text(
                "INSERT INTO cbomestatesource (team_id, source_ref, source_name, source_kind, latest_job_id, "
                "latest_attempt, latest_run_id, latest_at, latest_status, latest_comparable, updated_at) "
                "SELECT :t, 'src' || s, 'Source ' || s, 'network', :t * 1000 + s, 1, :t * 1000, :now, 'success', "
                "true, :now FROM generate_series(0, 7) s"), p)
            c.execute(sa.text("""
                INSERT INTO cbomestateasset (team_id, asset_key, key_kind, key_basis, asset_type, label, presence,
                    presence_reason, first_seen_run_id, first_seen_at, updated_run_id, updated_at, fix_class,
                    fix_class_excl_pq, fix_floor, fix_reasons, fix_codes, fix_version, fix_at, system_key,
                    system_label, system_kind, fix_observations)
                SELECT :t,
                  (CASE WHEN i % 10 < 4 THEN 'cert:' WHEN i % 10 < 6 THEN 'ep:' ELSE 'obs:' END)
                    || md5(:t || '-' || i) || substr(md5('x' || i), 1, 8),
                  CASE WHEN i % 10 < 6 THEN 'cross' ELSE 'source' END,
                  CASE WHEN i % 10 < 4 THEN 'certificate' WHEN i % 10 < 6 THEN 'endpoint' END,
                  CASE WHEN i % 10 < 4 THEN 'certificate' WHEN i % 10 < 6 THEN 'tls_endpoint'
                       WHEN i % 10 < 8 THEN 'crypto_library' ELSE 'private_key' END,
                  'asset ' || i,
                  CASE WHEN i % 100 < 90 THEN 'present' WHEN i % 100 < 96 THEN 'removed' ELSE 'not_read' END,
                  CASE WHEN i % 100 >= 96 THEN 'Source 1: 10.0.0.7 did not answer' END,
                  :t * 1000, :now, :t * 1000, :now,
                  (ARRAY['config','library','code','hardware','unknown'])[1 + i % 5],
                  (ARRAY['config','library','code','hardware','unknown'])[1 + (i / 7) % 5],
                  'config', CASE WHEN i % 5 = 4 THEN (ARRAY['no_library_version','vendor_unknown'])[1 + i % 2] END,
                  'TLS_LEGACY', :ver, :now, 'sys-' || (i % 5000), 'System ' || (i % 5000), 'host', 1
                FROM generate_series(1, :m) i"""), p)
            c.execute(sa.text("""
                INSERT INTO cbomestateobservation (team_id, asset_key, source_ref, observation_key, row_key, asset_type,
                    target, location, occurrences, presence, presence_reason, seen_job_id, seen_attempt, seen_run_id,
                    seen_at, first_seen_run_id, state_run_id, updated_at, fix_class, fix_version, fix_job_id,
                    fix_attempt, fix_at, system_key, cert_cnb_key, cert_cn_key)
                SELECT a.team_id, a.asset_key, 'src' || ((i + k) % 8), substr(md5('o' || i || k), 1, 40),
                  md5('r' || i || '-' || k) || md5('s' || i || '-' || k), a.asset_type, '10.0.' || (i % 250) || '.1',
                  '10.0.' || (i % 250) || '.1:' || i, 1, a.presence, a.presence_reason, :t * 1000 + (i + k) % 8, 1,
                  :t * 1000, :now, :t * 1000, :t * 1000, :now, a.fix_class, :ver, :t * 1000 + (i + k) % 8, 1, :now,
                  a.system_key, CASE WHEN i % 10 < 4 THEN 'cnb:' || md5('c' || i) END,
                  CASE WHEN i % 10 < 4 THEN 'cn:' || md5('n' || i) END
                FROM generate_series(1, :m) i
                JOIN cbomestateasset a ON a.team_id = :t AND a.asset_key =
                  (CASE WHEN i % 10 < 4 THEN 'cert:' WHEN i % 10 < 6 THEN 'ep:' ELSE 'obs:' END)
                    || md5(:t || '-' || i) || substr(md5('x' || i), 1, 8)
                CROSS JOIN generate_series(0, 1) k
                WHERE k = 0 OR i % 4 = 0"""), p)
            c.execute(sa.text("""
                INSERT INTO cbomcollectedasset (team_id, run_id, job_id, attempt, asset_key, asset_type, cdx_type,
                    target, location, impact, finding_codes, facts, created_at)
                SELECT o.team_id, :t * 1000, CASE WHEN o.presence = 'present' THEN :t * 1000 + substr(o.source_ref, 4)::int
                    ELSE o.seen_job_id END, 1, o.row_key, o.asset_type, 'cryptographic-asset', o.target, o.location,
                  'Medium', '[]', '{}', :now
                FROM cbomestateobservation o WHERE o.team_id = :t AND o.id % 10 = 0
                ON CONFLICT DO NOTHING"""), p)
            c.execute(sa.text("""
                INSERT INTO cbomriskregister (team_id, item_key, item_kind, q_grade, q_rank, q_reason, label, asset_type,
                    family, source_ref, source_name, application, exposure, presence, sources, last_run_id,
                    last_observed_at, model_version, inputs_digest, grade_digest, updated_at)
                SELECT a.team_id, a.asset_key, 'asset', g.grade, g.rank,
                  CASE WHEN g.grade = 'Q0' THEN (ARRAY['unknown_verdict','not_correlated','mosca_missing'])[1 + i % 3]
                       WHEN g.grade IS NULL THEN 'not_graded' ELSE 'graded' END,
                  a.label, a.asset_type, (ARRAY['RSA','ECC','AES','SHA','DH','DSA','PQC','Other'])[1 + i % 8],
                  'src' || (i % 8), 'Source ' || (i % 8), 'app-' || (i % 50),
                  (ARRAY['internet','internal','unknown'])[1 + i % 3], a.presence, 1, :t * 1000, :now, 'qg1', 'abc',
                  'def', :now
                FROM (SELECT asset_key, team_id, label, asset_type, presence,
                             row_number() OVER (ORDER BY asset_key) i FROM cbomestateasset WHERE team_id = :t) a
                CROSS JOIN LATERAL (SELECT CASE WHEN a.i % 100 < 3 THEN 'Q1' WHEN a.i % 100 < 15 THEN 'Q2'
                    WHEN a.i % 100 < 45 THEN 'Q3' WHEN a.i % 100 < 80 THEN 'Q4' WHEN a.i % 100 < 95 THEN 'Q0' END grade,
                    CASE WHEN a.i % 100 < 3 THEN 1 WHEN a.i % 100 < 15 THEN 2 WHEN a.i % 100 < 45 THEN 3
                    WHEN a.i % 100 < 80 THEN 4 WHEN a.i % 100 < 95 THEN 5 ELSE 6 END rank) g"""), p)
    from backend.utilities.cbom_sources import qgrade as QG
    from backend.utilities.cbom_sources import risk_register as RR

    with Session(engine) as s:  # graded with the current model and the team's current inputs: the steady state
        for team in TEAMS:
            s.execute(sa.text("UPDATE cbomriskregister SET model_version = :m, inputs_digest = :d WHERE team_id = :t"),
                      {"m": QG.GRADE_MODEL_VERSION, "d": RR.team_inputs(s, team).digest, "t": team})
        s.commit()
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as c:
        c.execute(sa.text("VACUUM ANALYZE"))


def timed(fn, reps: int) -> dict:
    fn()  # warm the plan cache / buffers once
    out = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        out.append(1000 * (time.perf_counter() - t0))
    out.sort()
    return {"p50": round(statistics.median(out), 1), "p95": round(out[max(0, int(0.95 * len(out)) - 1)], 1),
            "max": round(out[-1], 1)}


def queries(engine, team: int) -> dict:
    from backend.utilities.cbom_sources import agility_rollup as AR
    from backend.utilities.cbom_sources import agility_store as AS
    from backend.utilities.cbom_sources import estate as E
    from backend.utilities.cbom_sources import risk_register as RR

    rnd = random.Random(7)
    with engine.connect() as c:
        keys = [k for k, in c.execute(sa.text(
            "SELECT o.asset_key FROM cbomestateobservation o JOIN cbomcollectedasset r ON r.team_id = o.team_id "
            "AND r.asset_key = o.row_key WHERE o.team_id = :t ORDER BY random() LIMIT 400"), {"t": team})]
        removed_keys = [k for k, in c.execute(sa.text(
            "SELECT asset_key FROM cbomestateasset WHERE team_id = :t AND presence = 'removed' LIMIT 100"),
            {"t": team})]

    def s(fn):
        def run():
            with Session(engine) as session:
                return fn(session)
        return run

    pick = lambda: rnd.choice(keys)  # noqa: E731
    q = {
        "estate.list (no filter)": s(lambda ses: E.list_estate(ses, team, after=pick(), limit=200)),
        "estate.list type=certificate": s(lambda ses: E.list_estate(ses, team, after=pick(), limit=200,
                                                                    asset_type="certificate")),
        "estate.list presence=removed": s(lambda ses: E.list_estate(ses, team, after=pick(), limit=200,
                                                                    presence="removed")),
        "estate.list presence=not_read": s(lambda ses: E.list_estate(ses, team, after=pick(), limit=200,
                                                                     presence="not_read")),
        "estate.list source=src3": s(lambda ses: E.list_estate(ses, team, after=pick(), limit=200, source="src3")),
        "estate.asset (drill-down)": s(lambda ses: E.get_estate_asset(ses, team, pick())),
        "estate.asset removed (drill-down)": s(lambda ses: E.get_estate_asset(ses, team, rnd.choice(removed_keys))),
        "estate.present_keys page 5000": s(lambda ses: [k for _i, k in zip(range(5000), E.present_keys(
            ses, team, [f"src{rnd.randrange(SOURCES)}"]))]),
        "register.list (default)": s(lambda ses: RR.list_register(ses, team, {}, after=None, limit=200)),
        "register.list next page": s(lambda ses: RR.list_register(ses, team, {}, after=(3, pick()), limit=200)),
        "register.list grade=Q1": s(lambda ses: RR.list_register(ses, team, {"grade": "Q1"}, after=None, limit=200)),
        "register.list source=src3": s(lambda ses: RR.list_register(ses, team, {"source": "src3"}, after=None,
                                                                    limit=200)),
        "register.list application=app-7": s(lambda ses: RR.list_register(ses, team, {"application": "app-7"},
                                                                          after=None, limit=200)),
        "register.list presence=removed": s(lambda ses: RR.list_register(ses, team, {"presence": "removed"},
                                                                         after=None, limit=200)),
        "register.summary": s(lambda ses: RR.summary(ses, team, NOW)),
        "register.item (drill-down)": s(lambda ses: RR.get_item(ses, team, pick())),
        "agility.heal (steady state)": s(lambda ses: (AS.heal(ses, team, NOW), ses.rollback())),
        "agility.rollup GROUP BY": s(lambda ses: AR.build_store(ses, team, now=NOW, healed=True)),
        "agility.page fix_class=code": s(lambda ses: AR._store_page(
            ses, team, fix_class="code", system=None, excl_pq=False, after=None, skip_store=False, limit=100,
            merged=frozenset())),
        "agility.page system=sys-42": s(lambda ses: AR._store_page(
            ses, team, fix_class=None, system="sys-42", excl_pq=False, after=None, skip_store=False, limit=100,
            merged=frozenset())),
    }
    return q


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pg", required=True)
    ap.add_argument("--n", type=int, default=1_500_000)
    ap.add_argument("--reps", type=int, default=30)
    ap.add_argument("--seed", action=argparse.BooleanOptionalAction, default=True)
    ap.add_argument("--only", default="")
    args = ap.parse_args()
    engine = create_engine(args.pg)
    if args.seed:
        t0 = time.perf_counter()
        seed(engine, args.n)
        print(json.dumps({"seeded": args.n, "s": round(time.perf_counter() - t0)}), flush=True)
    with engine.connect() as c:
        sizes = {t: c.execute(sa.text(f"SELECT pg_size_pretty(pg_total_relation_size('{t}'))")).scalar()
                 for t in ("cbomestateasset", "cbomestateobservation", "cbomriskregister", "cbomcollectedasset")}
    print(json.dumps({"sizes": sizes}), flush=True)
    for name, fn in queries(engine, 1).items():
        if args.only and args.only not in name:
            continue
        print(json.dumps({"query": name, **timed(fn, args.reps)}), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
