"""CBOM Sources remediation plans and tickets on their resource's group key (PR #499, review 6060688856 follow-up)

Revision ID: q111remgroup001
Revises: q109certkey001
Create Date: 2026-11-25 19:30:00.000000

A resource two sources read (two IAM roles on one account) now has one remediation key, its group key
(``remediation_group.group_key``), whichever source's row a view shows. Plans and Jira tickets stored before that
sit on one source's own key. Upgrade: ``remediation_backfill.backfill_all`` copies each such resource's plan (the
primary ``remediation_group.resolve`` picks: the copy holding a ticket, else the first by key order) to its group
key, with the ticket holder's ticket. The originals are kept. Idempotent; each team in its own savepoint.

Downgrade: every record the upgrade inserted writes its current plan and ticket back to the original it was copied
from, and is deleted.

Chained after dev's head ``q109certkey001``. PR #504 adds ``q110linkuq001`` on the same parent: whichever of the two
merges second re-points its ``down_revision`` to the other (``test_alembic_single_head``).
"""
from typing import Sequence, Union

from alembic import op


revision: str = 'q111remgroup001'
down_revision: Union[str, Sequence[str], None] = 'q109certkey001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade data."""
    from backend.utilities.cbom_sources import remediation_backfill

    remediation_backfill.backfill_all(op.get_bind())


def downgrade() -> None:
    """Downgrade data."""
    from backend.utilities.cbom_sources import remediation_backfill

    remediation_backfill.backfill_all(op.get_bind(), reverse=True)
