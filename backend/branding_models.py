"""The team's report branding: one client logo per team, drawn next to the ZeroShield logo on every PDF export.

Kept out of ``new_models.py`` so parallel tracks do not edit the same lines; ``new_models`` imports this module at
its end (as it does ``access_models``), so ``SQLModel.metadata`` (alembic, ``create_all`` in tests) sees the table.

The stored PNG is never the uploaded file: ``utilities/team/logo_image.normalize_logo`` decodes the upload, crops,
scales and re-encodes it (no metadata), and only that result is stored.  Reads:

* ``utilities/team/branding.load_report_branding``: the PDF routes, bytes and tone (one SELECT);
* ``GET /team/{team_id}/branding``: the metadata columns only, never the bytes;
* ``GET /team/{team_id}/branding/logo``: the bytes, for the settings preview.

``team_id`` is the primary key and a foreign key to ``team.id`` with ON DELETE CASCADE; team deletion also removes
the row explicitly (``routers/team.delete_team``).  The uploader is a plain int (deleting the account never blocks).
Times are naive UTC.
"""
import datetime

from sqlalchemy import CheckConstraint, LargeBinary
from sqlmodel import Column, DateTime, Field, SQLModel

__all__ = ["TeamBranding", "LOGO_TONES"]

LOGO_TONES = ("dark", "light")  # decides the chip the logo sits on (plan section 3, "Header" / "Masthead")


class TeamBranding(SQLModel, table=True):
    __tablename__ = "teambranding"
    __table_args__ = (CheckConstraint("logo_tone IN ('dark', 'light')", name="ck_teambranding_logo_tone"),)
    team_id: int = Field(primary_key=True, foreign_key="team.id", ondelete="CASCADE")
    logo_png: bytes = Field(sa_column=Column(LargeBinary, nullable=False))  # bytea on PostgreSQL; at most 300 KB
    logo_sha256: str = Field(max_length=64)  # hex SHA-256 of logo_png (the ETag of GET .../branding/logo)
    logo_width: int
    logo_height: int
    logo_bytes: int  # len(logo_png), so the metadata read never loads the bytes
    logo_tone: str = Field(max_length=8)  # "dark" | "light"
    has_alpha: bool  # False: stored as RGB (no soft mask in the PDF)
    updated_at: datetime.datetime = Field(sa_type=DateTime)
    updated_by_user_id: int | None = Field(default=None)
