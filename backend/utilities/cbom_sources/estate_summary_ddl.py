"""CB-32 summary tables of the estate store, kept by database triggers in the writing transaction.

Three tables (``new_models``):
* ``cbomagilitygroup``: live classed assets per (system, fix class, class without PQ codes, unknown reasons), the
  agility roll-up's GROUP BY (``agility_rollup.build_store``);
* ``cbomregistersummary``: register rows per (grade, reason, family, presence), the register summary;
* ``cbomestatecount``: team counters (``COUNTS``).

Triggers (the only writers): ``cbomestateasset`` feeds the groups and the asset counters, ``cbomestateobservation``
the observation counter, ``cbomriskregister`` the register summary. PostgreSQL: statement-level triggers with
transition tables (one grouped delta per statement, rows locked in key order); SQLite: row-level triggers. Every
writer (estate writes, agility aggregation, register refresh, prune, team deletion, raw batched SQL) is covered, and a
rolled-back savepoint rolls its deltas back. ``rebuild`` recomputes a team's summaries from the base tables (the
migration, the CLI and the daily self-check use it).

No backend imports here: ``new_models`` calls ``install`` after ``create_all``.
"""
from __future__ import annotations

from typing import Any, Iterable

import sqlalchemy as sa

COUNTS = {
    # kind -> (table, condition on the row)
    "assets_live": ("cbomestateasset", "{p}presence <> 'removed'"),
    "not_correlated_live": ("cbomestateasset", "{p}presence <> 'removed' AND {p}key_kind = 'not_correlated'"),
    "observations_live": ("cbomestateobservation", "{p}presence <> 'removed'"),
}

# (summary table, source table, grouping expressions (name, expr), condition, extra latest-value columns, conflict
# columns)
_GROUPS = (
    ("cbomagilitygroup", "cbomestateasset",
     (("team_id", "{p}team_id"), ("system_key", "coalesce({p}system_key, '')"), ("fix_class", "{p}fix_class"),
      ("fix_class_excl_pq", "coalesce({p}fix_class_excl_pq, '')"), ("fix_reasons", "coalesce({p}fix_reasons, '')")),
     "{p}presence <> 'removed' AND {p}fix_class IS NOT NULL",
     (("system_label", "{p}system_label"), ("system_kind", "{p}system_kind"))),
    ("cbomregistersummary", "cbomriskregister",
     (("team_id", "{p}team_id"), ("q_grade", "coalesce({p}q_grade, '')"), ("q_reason", "{p}q_reason"),
      ("family", "coalesce({p}family, '')"), ("presence", "{p}presence")),
     "TRUE", ()),
)
TABLES = ("cbomestateasset", "cbomestateobservation", "cbomriskregister")
SUMMARIES = ("cbomagilitygroup", "cbomregistersummary", "cbomestatecount")


def _side(pg: bool, alias: str, sign: int, columns: Iterable[tuple[str, str]], cond: str) -> str:
    """One side of a delta: the rows of ``alias`` (a transition table on PostgreSQL, NEW/OLD on SQLite)."""
    p = "" if pg else f"{alias}."
    exprs = ", ".join(f"{expr.format(p=p)} AS {name}" for name, expr in columns)
    where = cond.format(p=p)
    return f"SELECT {exprs}, {sign} AS d FROM {alias} WHERE {where}" if pg else f"SELECT {exprs}, {sign} AS d WHERE {where}"


def _group_delta(pg: bool, sides: list[tuple[str, int]], summary: str, groups, cond: str, latest) -> str:
    keys = [name for name, _e in groups]
    parts = []
    for alias, sign in sides:  # latest values only from the new side
        side_cols = list(groups) + [(name, expr if sign > 0 else "NULL") for name, expr in latest]
        parts.append(_side(pg, alias, sign, side_cols, cond))
    latest_names = [name for name, _e in latest]
    select_latest = "".join(f", max({n}) AS {n}" for n in latest_names)
    set_latest = "".join(f", {n} = coalesce(excluded.{n}, {summary}.{n})" for n in latest_names)
    key_list = ", ".join(keys)
    return (f"INSERT INTO {summary} ({key_list}, n{''.join(', ' + n for n in latest_names)}) "
            f"SELECT {key_list}, sum(d){select_latest} FROM ({' UNION ALL '.join(parts)}) x WHERE TRUE "
            f"GROUP BY {key_list} HAVING sum(d) <> 0 ORDER BY {key_list} "
            f"ON CONFLICT ({key_list}) DO UPDATE SET n = {summary}.n + excluded.n{set_latest}")


def _count_delta(pg: bool, sides: list[tuple[str, int]], table: str) -> str | None:
    parts = []
    for kind, (source, cond) in COUNTS.items():
        if source != table:
            continue
        for alias, sign in sides:
            parts.append(_side(pg, alias, sign, (("team_id", "{p}team_id"), ("kind", f"'{kind}'")), cond))
    if not parts:
        return None
    return (f"INSERT INTO cbomestatecount (team_id, kind, n) SELECT team_id, kind, sum(d) FROM "
            f"({' UNION ALL '.join(parts)}) x WHERE TRUE GROUP BY team_id, kind HAVING sum(d) <> 0 "
            f"ORDER BY team_id, kind ON CONFLICT (team_id, kind) DO UPDATE SET n = cbomestatecount.n + excluded.n")


def _statements(pg: bool, table: str, op: str) -> list[str]:
    new, old = ("new_rows", "old_rows") if pg else ("NEW", "OLD")
    sides = {"INSERT": [(new, 1)], "UPDATE": [(old, -1), (new, 1)], "DELETE": [(old, -1)]}[op]
    out = [_group_delta(pg, sides, summary, groups, cond, latest)
           for summary, source, groups, cond, latest in _GROUPS if source == table]
    count = _count_delta(pg, sides, table)
    return out + ([count] if count else [])


def ddl(pg: bool) -> list[str]:
    """The trigger DDL for one dialect (drop-and-create, so installing twice is harmless)."""
    out: list[str] = []
    for table in TABLES:
        if pg:
            func = f"cbom_summary_{table}"
            body = []
            for op in ("INSERT", "UPDATE", "DELETE"):
                body.append(f"  IF TG_OP = '{op}' THEN\n" + "".join(f"    {s};\n" for s in _statements(True, table, op))
                            + "  END IF;")
            out.append(f"CREATE OR REPLACE FUNCTION {func}() RETURNS trigger LANGUAGE plpgsql AS $$\nBEGIN\n"
                       + "\n".join(body) + "\n  RETURN NULL;\nEND $$")
            for op, ref in (("INSERT", "NEW TABLE AS new_rows"), ("UPDATE", "OLD TABLE AS old_rows NEW TABLE AS new_rows"),
                            ("DELETE", "OLD TABLE AS old_rows")):
                name = f"tr_{table}_summary_{op.lower()}"
                out.append(f"DROP TRIGGER IF EXISTS {name} ON {table}")
                out.append(f"CREATE TRIGGER {name} AFTER {op} ON {table} REFERENCING {ref} FOR EACH STATEMENT "
                           f"EXECUTE FUNCTION {func}()")
        else:
            for op in ("INSERT", "UPDATE", "DELETE"):
                name = f"tr_{table}_summary_{op.lower()}"
                out.append(f"DROP TRIGGER IF EXISTS {name}")
                out.append(f"CREATE TRIGGER {name} AFTER {op} ON {table} FOR EACH ROW BEGIN\n"
                           + "".join(f"  {s};\n" for s in _statements(False, table, op)) + "END")
    return out


def drop_ddl(pg: bool) -> list[str]:
    out = []
    for table in TABLES:
        for op in ("insert", "update", "delete"):
            out.append(f"DROP TRIGGER IF EXISTS tr_{table}_summary_{op}" + (f" ON {table}" if pg else ""))
        if pg:
            out.append(f"DROP FUNCTION IF EXISTS cbom_summary_{table}()")
    return out


def install(connection: Any, *, only_if_tables: bool = False) -> bool:
    """Create the triggers. ``only_if_tables``: skip quietly unless every base and summary table exists (a
    ``create_all`` of an unrelated subset of tables)."""
    if only_if_tables:
        have = set(sa.inspect(connection).get_table_names())
        if not set(TABLES + SUMMARIES) <= have:
            return False
    pg = connection.dialect.name == "postgresql"
    for stmt in ddl(pg):
        connection.execute(sa.text(stmt))
    return True


def rebuild(connection: Any, team_id: int | None = None) -> dict[str, int]:
    """Recompute the summaries from the base tables (one team, or all). The caller commits."""
    where = "" if team_id is None else " AND team_id = :t"
    params = {} if team_id is None else {"t": team_id}
    for summary in SUMMARIES:
        connection.execute(sa.text(f"DELETE FROM {summary} WHERE TRUE{where}"), params)
    out = {}
    for summary, source, groups, cond, latest in _GROUPS:
        keys = [expr.format(p="") for _n, expr in groups]
        names = [n for n, _e in groups] + [n for n, _e in latest]
        extra = "".join(f", max({expr.format(p='')})" for _n, expr in latest)
        res = connection.execute(sa.text(
            f"INSERT INTO {summary} ({', '.join(names[:len(groups)])}, n{''.join(', ' + n for n, _e in latest)}) "
            f"SELECT {', '.join(keys)}, count(*){extra} FROM {source} WHERE {cond.format(p='')}{where} "
            f"GROUP BY {', '.join(keys)}"), params)
        out[summary] = int(res.rowcount or 0)
    for kind, (source, cond) in COUNTS.items():
        connection.execute(sa.text(
            f"INSERT INTO cbomestatecount (team_id, kind, n) SELECT team_id, '{kind}', count(*) FROM {source} "
            f"WHERE {cond.format(p='')}{where} GROUP BY team_id"), params)
    return out


def compare(connection: Any, team_id: int) -> list[str]:
    """What differs between the team's summaries and the base tables (empty when they agree)."""
    diffs = []
    for summary, source, groups, cond, _latest in _GROUPS:
        keys = [expr.format(p="") for _n, expr in groups]
        names = [n for n, _e in groups]
        live = {tuple(r[:-1]): int(r[-1]) for r in connection.execute(sa.text(
            f"SELECT {', '.join(keys)}, count(*) FROM {source} WHERE {cond.format(p='')} AND team_id = :t "
            f"GROUP BY {', '.join(keys)}"), {"t": team_id})}
        kept = {tuple(r[:-1]): int(r[-1]) for r in connection.execute(sa.text(
            f"SELECT {', '.join(names)}, n FROM {summary} WHERE team_id = :t AND n <> 0"), {"t": team_id})}
        if live != kept:
            diffs.append(summary)
    for kind, (source, cond) in COUNTS.items():
        live_n = connection.execute(sa.text(f"SELECT count(*) FROM {source} WHERE {cond.format(p='')} AND team_id = :t"),
                                    {"t": team_id}).scalar()
        kept_n = connection.execute(sa.text("SELECT coalesce(sum(n), 0) FROM cbomestatecount WHERE team_id = :t AND "
                                            "kind = :k"), {"t": team_id, "k": kind}).scalar()
        if int(live_n) != int(kept_n):
            diffs.append(f"cbomestatecount:{kind}")
    return diffs


# ----------------------------------------------------------------------------- readers
def agility_groups(session: Any, team_id: int) -> list[tuple]:
    """(system_key | None, system_label, system_kind, fix_class, fix_class_excl_pq | None, fix_reasons | None, n):
    what ``GROUP BY system_key, fix_class, fix_class_excl_pq, fix_reasons`` over the live classed assets gives."""
    return [(r[0] or None, r[1], r[2], r[3], r[4] or None, r[5] or None, int(r[6])) for r in session.execute(sa.text(
        "SELECT system_key, system_label, system_kind, fix_class, fix_class_excl_pq, fix_reasons, n "
        "FROM cbomagilitygroup WHERE team_id = :t AND n <> 0"), {"t": team_id}).all()]


def agility_total(session: Any, team_id: int, *, fix_class: str | None = None, excl_pq: bool = False,
                  system: str | None = None) -> int:
    """How many live classed assets match (the agility page's count)."""
    where, params = ["team_id = :t"], {"t": team_id}
    if fix_class:
        where.append(("fix_class_excl_pq" if excl_pq else "fix_class") + " = :c")
        params["c"] = fix_class
    if system:
        where.append("system_key = :s")
        params["s"] = system
    return int(session.execute(sa.text(f"SELECT coalesce(sum(n), 0) FROM cbomagilitygroup WHERE {' AND '.join(where)}"),
                               params).scalar() or 0)


def count(session: Any, team_id: int, kind: str) -> int:
    return int(session.execute(sa.text("SELECT coalesce(sum(n), 0) FROM cbomestatecount WHERE team_id = :t AND "
                                       "kind = :k"), {"t": team_id, "k": kind}).scalar() or 0)


def register_groups(session: Any, team_id: int) -> list[tuple]:
    """(q_grade | None, q_reason, family | None, presence, n) over the team's register rows."""
    return [(r[0] or None, r[1], r[2] or None, r[3], int(r[4])) for r in session.execute(sa.text(
        "SELECT q_grade, q_reason, family, presence, n FROM cbomregistersummary WHERE team_id = :t AND n <> 0"),
        {"t": team_id}).all()]


# ----------------------------------------------------------------------------- daily self-check
CHECK_EVERY_S = 24 * 3600
_last_check: list[float] = []


def check_due(engine: Any, now: Any = None) -> dict[str, int] | None:
    """At most once a day per process: compare every team's summaries with its base tables and rebuild a team whose
    summaries disagree (logged; the triggers make this a backstop, not the mechanism). None when not due."""
    import logging
    import time

    if _last_check and time.monotonic() - _last_check[0] < CHECK_EVERY_S:
        return None
    _last_check[:] = [time.monotonic()]
    out = {"teams": 0, "rebuilt": 0}
    with engine.connect() as conn:
        teams = [t for t, in conn.execute(sa.text("SELECT DISTINCT team_id FROM cbomestateasset UNION "
                                                  "SELECT DISTINCT team_id FROM cbomriskregister")).all()]
    for team in teams:
        with engine.begin() as conn:
            out["teams"] += 1
            diffs = compare(conn, team)
            if diffs:
                logging.getLogger(__name__).error("cbom estate summaries of team %s disagreed (%s): rebuilt", team,
                                                  ",".join(diffs))
                rebuild(conn, team)
                out["rebuilt"] += 1
    return out
