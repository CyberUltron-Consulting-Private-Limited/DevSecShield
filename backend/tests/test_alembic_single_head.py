"""The production migrations form one chain: exactly one head, no duplicate revision ids, every down_revision known.

Several feature branches add migrations in parallel (F1 contract, section 2). Two branches that both revise the same
head merge cleanly in git and leave alembic with two heads, and ``alembic upgrade head`` then refuses to run at
deploy time (docker-entrypoint.sh). This test reads ``versions/`` statically (no database, no alembic import), so it
fails in the PR that creates the second head.
"""
from __future__ import annotations

import ast
from pathlib import Path

VERSIONS = Path(__file__).resolve().parents[2] / "prod_database_migrations/migrations/versions"


def _assigned(tree: ast.Module, name: str):
    for node in tree.body:
        target = None
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target, value = node.target.id, node.value
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target, value = node.targets[0].id, node.value
        if target == name:
            return ast.literal_eval(value) if value is not None else None
    raise AssertionError(f"{name} not assigned")


def revisions() -> dict[str, tuple[str, ...]]:
    """{revision: (down_revisions...)} for every migration file."""
    out: dict[str, tuple[str, ...]] = {}
    seen_in: dict[str, str] = {}
    for path in sorted(VERSIONS.glob("*.py")):
        tree = ast.parse(path.read_text())
        rev = _assigned(tree, "revision")
        down = _assigned(tree, "down_revision")
        assert rev not in seen_in, f"revision {rev} is defined in both {seen_in[rev]} and {path.name}"
        seen_in[rev] = path.name
        out[rev] = tuple(down) if isinstance(down, (list, tuple)) else ((down,) if down else ())
    return out


def heads(graph: dict[str, tuple[str, ...]]) -> set[str]:
    revised = {d for downs in graph.values() for d in downs}
    return set(graph) - revised


def test_exactly_one_alembic_head():
    graph = revisions()
    found = heads(graph)
    assert len(found) == 1, (f"alembic has {len(found)} heads: {sorted(found)}. Merge dev into the branch and "
                             "re-chain the newer migration's down_revision to dev's head (F1 contract, section 2)")


def test_every_down_revision_exists_and_the_chain_reaches_the_root():
    graph = revisions()
    for rev, downs in graph.items():
        for down in downs:
            assert down in graph, f"{rev} revises {down}, which no migration defines"
    roots = [rev for rev, downs in graph.items() if not downs]
    assert len(roots) == 1, f"expected one initial migration, found {roots}"
    (head,) = heads(graph)
    walked, rev = [], head
    while rev is not None:
        walked.append(rev)
        downs = graph[rev]
        rev = downs[0] if downs else None
    assert walked[-1] == roots[0] and len(walked) == len(graph), "the chain from the head skips a migration"


def test_the_checker_sees_a_second_head():
    """The check itself: a branch that revises an old revision is reported as a second head."""
    graph = revisions()
    (head,) = heads(graph)
    some_old = next(rev for rev in graph if rev != head)
    graph["zz_parallel"] = (some_old,)
    assert heads(graph) == {head, "zz_parallel"}
