"""CBOM Sources certificate identity: move the stored keys at deploy (staging QA2 Q1-09, #497 review M1)

Revision ID: q109certkey001
Revises: q102hist001
Create Date: 2026-11-25 10:30:00.000000

The certificate identity no longer reads a cloud certificate's free-text subject (a cloud certificate is its resource
id) and compares every other subject or issuer as a normalised DN: an attribute map (``{"CommonName": ...}``) as the
DN it denotes, attribute order and spacing ignored. The keys built from it changed for those certificates only: the
per-source observation key and, for a certificate with no cross-source key, its ``obs:`` estate key; the CB-21 cross
key of a certificate whose name was stored as an attribute map. Readers compute the new keys as soon as the release
serves, so the stored keys move here, before it does.

Upgrade: ``identity_migration.migrate_all``. Driven by the store: every estate observation is read with the
collected row it was made from (``seen_job_id`` / ``seen_attempt`` / ``row_key``), so a source whose latest
collection failed, a paused or deleted source and a ``not_read`` observation move too; each source's latest job adds
the assignment keys of rows the store never wrote. Set-based per team (temporary tables, ``UPDATE ... FROM``): the
observation keys, the remediation assignments (owner, status such as ``accepted_risk``, ticket), the estate asset rows
(renamed in place, first seen kept; merged into an existing row the earlier first seen wins), their observations,
risk register rows, open Q0 items and estate links. Measured on PostgreSQL 15: 4,000 certificates in about 3 s
(63 statements), 20,000 in 14-24 s. Each team is one savepoint, logged with its counts and time, and marked done in
``cbomopscounter`` (``identity_migration_qa2:team:<id>``, value: the highest job id covered, after which
``estate.record_run`` only looks at newer rows). ``lock_timeout`` 30 s: a team whose sources an older worker holds,
or that fails, is rolled back, logged with the reason and left to the scheduler's ``backfill_due``, so it never
blocks the deploy. Idempotent: a key already moved maps to nothing.

Downgrade: the same moves in reverse (back to the identity before Q1-09) and the marks cleared. Two assets the
upgrade merged (both keys were already stored) stay one row under the old key, with the earlier first seen.
"""
from typing import Sequence, Union

from alembic import op


revision: str = 'q109certkey001'
down_revision: Union[str, Sequence[str], None] = 'q102hist001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade data."""
    from backend.utilities.cbom_sources import identity_migration

    identity_migration.migrate_all(op.get_bind())


def downgrade() -> None:
    """Downgrade data."""
    from backend.utilities.cbom_sources import identity_migration

    identity_migration.migrate_all(op.get_bind(), reverse=True)
