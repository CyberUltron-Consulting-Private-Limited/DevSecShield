"""CBOM Sources certificate identity: move the stored keys at deploy (staging QA2 Q1-09, #497 review M1)

Revision ID: q109certkey001
Revises: q102hist001
Create Date: 2026-11-25 10:30:00.000000

The certificate identity no longer reads a cloud certificate's free-text subject (a cloud certificate is its resource
id) and compares a subject or issuer stored as an attribute map (``{"CommonName": ...}``) as the DN it denotes. The
keys built from it changed for those certificates only: the per-source observation key and, for a certificate with
no cross-source key, its ``obs:`` estate key; the CB-21 cross key of a certificate whose name was stored as an
attribute map. Readers compute the new keys as soon as the release serves, so the stored keys move here, before it
does, rather than on each source's next run (a paused or deleted source would never move, and until then its owner,
accepted risk and first-seen date would not be found).

Upgrade: ``identity_migration.migrate_all``: for every team, every source's latest stored job (deleted sources
included), the observation keys, the remediation assignments (owner, status such as ``accepted_risk``, ticket), the
estate asset rows (renamed in place, first seen kept; merged into an existing row the earlier first seen wins), their
observations, risk register rows, open Q0 items and estate links. Nothing is removed or inserted, so the register,
D12 and D13 keep their history. Each team is one savepoint, marked done in ``cbomopscounter``
(``identity_migration_qa2:team:<id>``); a team that fails is rolled back, logged and left to the scheduler's
``backfill_due``, so it never blocks the deploy. Idempotent: a key already moved maps to nothing.

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
