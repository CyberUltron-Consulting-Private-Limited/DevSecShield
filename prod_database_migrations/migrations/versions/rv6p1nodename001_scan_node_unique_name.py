"""cbom scan nodes: one name per team, whatever its case

Revision ID: rv6p1nodename001
Revises: wp8b0agent001
Create Date: 2026-11-11 06:00:00.000000

Creating a scan node checked for a node of the same name and then inserted, so two concurrent requests both passed the
check (X1 B1, Nov 11). A unique index on (team_id, lower(name)) now refuses the second; the API answers 409.

Existing duplicates are renamed first, deterministically: in each team the oldest node (lowest id) keeps the name, the
others get "-2", "-3", ... (the first suffix free in that team, the name cut to fit 64 characters), in id order.
The downgrade drops the index only; renamed nodes keep their new names.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'rv6p1nodename001'
down_revision: Union[str, Sequence[str], None] = 'wp8b0agent001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

INDEX = 'uq_cbomscannode_team_lower_name'
MAX_NAME = 64


def renames(rows: list[tuple[int, int, str]]) -> dict[int, str]:
    """{node id: new name} for every node whose (team, lower(name)) an older node of the team already has."""
    taken: dict[int, set[str]] = {}
    for _id, team_id, name in rows:
        taken.setdefault(team_id, set()).add(name.lower())
    seen: dict[int, set[str]] = {}
    out: dict[int, str] = {}
    for node_id, team_id, name in sorted(rows):
        team_seen = seen.setdefault(team_id, set())
        if name.lower() not in team_seen:
            team_seen.add(name.lower())
            continue
        for i in range(2, 10_000):
            suffix = f"-{i}"
            candidate = f"{name[:MAX_NAME - len(suffix)]}{suffix}"
            if candidate.lower() not in taken[team_id]:
                break
        taken[team_id].add(candidate.lower())
        team_seen.add(candidate.lower())
        out[node_id] = candidate
    return out


def upgrade() -> None:
    """Upgrade schema."""
    bind = op.get_bind()
    rows = [(r[0], r[1], r[2]) for r in bind.execute(sa.text('SELECT id, team_id, name FROM cbomscannode ORDER BY id'))]
    for node_id, name in renames(rows).items():
        bind.execute(sa.text('UPDATE cbomscannode SET name = :name WHERE id = :id'), {'name': name, 'id': node_id})
    op.create_index(INDEX, 'cbomscannode', ['team_id', sa.text('lower(name)')], unique=True)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(INDEX, table_name='cbomscannode')
