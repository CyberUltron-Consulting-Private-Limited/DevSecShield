"""CBOM Sources remediation plans and tickets on their resource's group key (PR #499, review 6060688856 follow-up)

Revision ID: q111remgroup001
Revises: q110linkuq001
Create Date: 2026-11-25 19:30:00.000000

A resource two sources read (two IAM roles on one account) now has one remediation key, its group key
(``remediation_group.group_key``), whichever source's row a view shows. Plans and Jira tickets stored before that
sit on one source's own key. Upgrade: ``remediation_backfill.backfill_all`` copies each such resource's plan to its
group key, merged field by field as ``remediation_group.resolve`` shows it: the plan of the most recently updated
record that holds one, the ticket of the ticket holder. A blank record (status "open", no wave, owner, due date or
note: a released ticket claim's leftover) is not a plan and is never written to a group key (PR #499 review
6065677758 M1). The originals are kept, but once a group record exists it is the resource's final word
(``remediation_group.resolve``, round 7): a reset to blank made BEFORE the upgrade cannot be told from a leftover, so
q111 makes the older plan the resource's; those resources are logged per team ("blank newer than the plan copied")
and such a reset has to be made again after the upgrade. Idempotent; a group record that exists is never replaced;
each team in its own savepoint.

Downgrade: every record the upgrade inserted writes its current plan and ticket back to the original it was copied
from, and is deleted.

Chained after dev's head ``q110linkuq001`` (PR #504), one head (``test_alembic_single_head``).
"""
from typing import Sequence, Union

from alembic import op


revision: str = 'q111remgroup001'
down_revision: Union[str, Sequence[str], None] = 'q110linkuq001'
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
