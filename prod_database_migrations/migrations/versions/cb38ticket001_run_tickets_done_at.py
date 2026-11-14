"""CB-38 PR-4: Jira tickets for CBOM Sources run findings, and remediation metrics

Revision ID: cb38ticket001
Revises: r6f14sshca002
Create Date: 2026-11-14 12:00:00.000000

* ``cbomremediationassignment.ticket_key`` / ``ticket_url``: the Jira issue opened for this asset. The assignment is
  keyed by the asset's stable identity, so one asset has one ticket across every run that saw it.
* ``cbomremediationassignment.done_at``: when the status last became ``done`` (cleared when it leaves ``done``); the
  mean time to remediate and the remediation velocity are computed from it.
* ``cbomcollectionsettings.jira_project_key`` / ``jira_issue_type``: the team's Jira project (key such as ``SEC`` or a
  numeric project id) and issue type for CBOM Sources tickets; set by a team admin.

All columns are nullable with no default, so the upgrade rewrites no rows. PostgreSQL: both directions run with
``lock_timeout`` 5 s (as r6f14sshca002), so a long transaction on either table makes the migration fail fast instead of
queueing every reader behind its ACCESS EXCLUSIVE lock. SQLite: the downgrade drops columns through batch mode.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'cb38ticket001'
down_revision: Union[str, Sequence[str], None] = 'r6f14sshca002'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

LOCK_TIMEOUT = "5s"
ASSIGNMENT = "cbomremediationassignment"
SETTINGS = "cbomcollectionsettings"


def _pg() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def _lock_timeout(value: str) -> str:
    """Set this transaction's lock_timeout (PostgreSQL); returns the value it had."""
    bind = op.get_bind()
    before = bind.execute(sa.select(sa.func.current_setting("lock_timeout"))).scalar()
    bind.execute(sa.select(sa.func.set_config("lock_timeout", value, True)))
    return str(before)


def upgrade() -> None:
    """Upgrade schema."""
    before = _lock_timeout(LOCK_TIMEOUT) if _pg() else None
    op.add_column(ASSIGNMENT, sa.Column('ticket_key', sa.String(length=64), nullable=True))
    op.add_column(ASSIGNMENT, sa.Column('ticket_url', sa.String(length=512), nullable=True))
    op.add_column(ASSIGNMENT, sa.Column('done_at', sa.DateTime(), nullable=True))
    op.add_column(SETTINGS, sa.Column('jira_project_key', sa.String(length=32), nullable=True))
    op.add_column(SETTINGS, sa.Column('jira_issue_type', sa.String(length=64), nullable=True))
    if before is not None:
        _lock_timeout(before)


def downgrade() -> None:
    """Downgrade schema."""
    before = _lock_timeout(LOCK_TIMEOUT) if _pg() else None
    with op.batch_alter_table(SETTINGS) as batch:
        batch.drop_column('jira_issue_type')
        batch.drop_column('jira_project_key')
    with op.batch_alter_table(ASSIGNMENT) as batch:
        batch.drop_column('done_at')
        batch.drop_column('ticket_url')
        batch.drop_column('ticket_key')
    if before is not None:
        _lock_timeout(before)
