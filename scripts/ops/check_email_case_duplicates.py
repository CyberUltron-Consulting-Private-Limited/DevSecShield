#!/usr/bin/env python3
"""Report user accounts whose e-mail addresses differ only in letter case.

Sign-in looks an e-mail up case-insensitively (``auth_utils.user_by_email``: ``lower(email)``, lowest user id
first), so of two accounts ``Ana@x.com`` and ``ana@x.com`` only the one with the LOWER id can ever sign in; the
other keeps its teams, scans and integrations but is unreachable. This check finds those groups so an operator can
merge or retire them (docs/security/email-case-duplicates.md).

Run it on the backend host or container, with the backend's database settings (PG_USER, PG_USER_PASS, PG_DB,
PG_HOST, PG_PORT), from the repository root:

    PYTHONPATH=. backend/.venv/bin/python scripts/ops/check_email_case_duplicates.py          # counts only
    PYTHONPATH=. backend/.venv/bin/python scripts/ops/check_email_case_duplicates.py --ids    # + user ids per group

It prints COUNTS by default and, with ``--ids``, user ids; it never prints an e-mail address (the logs of a deploy
or a cron job are not the place for them; look the ids up in the database when you act on a group). Read-only.
Exit status: 0 no duplicates, 1 duplicates found, 2 the database could not be read.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))


def find_case_duplicates(session) -> list[list[int]]:
    """Groups of user ids (ascending; the first one is the account that signs in) sharing ``lower(email)``."""
    from sqlalchemy import func
    from sqlmodel import select

    from backend.new_models import User

    key = func.lower(User.email)
    keys = select(key).group_by(key).having(func.count(User.id) > 1).subquery()
    rows = session.exec(select(key, User.id).where(key.in_(select(keys))).order_by(key, User.id)).all()
    groups: dict[str, list[int]] = {}
    for folded, user_id in rows:
        groups.setdefault(folded, []).append(int(user_id))
    return sorted(groups.values())


def report(groups: list[list[int]], show_ids: bool) -> list[str]:
    if not groups:
        return ["No e-mail addresses differ only in case."]
    accounts = sum(len(g) for g in groups)
    lines = [
        f"{len(groups)} e-mail address(es) are shared by {accounts} accounts that differ only in letter case; "
        f"{accounts - len(groups)} of those accounts cannot sign in (the lowest user id of each group wins).",
    ]
    if show_ids:
        lines += [f"  group {n}: signs in as user {g[0]}; unreachable: {', '.join(map(str, g[1:]))}"
                  for n, g in enumerate(groups, 1)]
    else:
        lines.append("Run with --ids to list the user ids of each group (addresses are never printed).")
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--ids", action="store_true", help="also print the user ids of each group")
    args = parser.parse_args(argv)
    try:
        from sqlmodel import Session

        from backend.get_db import get_db

        with Session(get_db()) as session:
            groups = find_case_duplicates(session)
    except Exception as exc:  # no credentials or no database: say so without echoing connection details
        print(f"Could not read the user table ({exc.__class__.__name__}).", file=sys.stderr)
        return 2
    print("\n".join(report(groups, args.ids)))
    return 1 if groups else 0


if __name__ == "__main__":
    raise SystemExit(main())
