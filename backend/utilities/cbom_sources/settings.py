"""Team settings row (created once, race-safe) and the scan-window clock."""
from __future__ import annotations

import datetime as _dt
import secrets
import zoneinfo

from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from backend.new_models import CbomCollectionSettings, CbomEvidenceArea
from backend.utilities.cbom_sources import targets as T
from backend.utilities.cbom_sources.evidence import AREAS

DEFAULT_PORTS = [
    {"port": 443, "protocol": "tls", "label": "HTTPS"},
    {"port": 8443, "protocol": "tls", "label": "HTTPS"},
    {"port": 636, "protocol": "tls", "label": "LDAPS"},
    {"port": 389, "protocol": "starttls-ldap", "label": "LDAP StartTLS"},
    {"port": 25, "protocol": "starttls-smtp", "label": "SMTP StartTLS"},
    {"port": 587, "protocol": "starttls-smtp", "label": "Submission"},
    {"port": 465, "protocol": "tls", "label": "SMTPS"},
    {"port": 993, "protocol": "tls", "label": "IMAPS"},
    {"port": 143, "protocol": "starttls-imap", "label": "IMAP StartTLS"},
    {"port": 995, "protocol": "tls", "label": "POP3S"},
    {"port": 110, "protocol": "starttls-pop3", "label": "POP3 STLS"},
    {"port": 5432, "protocol": "starttls-postgres", "label": "PostgreSQL"},
    {"port": 3306, "protocol": "starttls-mysql", "label": "MySQL"},
    {"port": 1433, "protocol": "tds", "label": "SQL Server"},
    {"port": 22, "protocol": "ssh", "label": "SSH"},
    {"port": 3389, "protocol": "rdp", "label": "RDP"},
    {"port": 500, "protocol": "ike", "label": "IKE"},
    {"port": 4500, "protocol": "ike", "label": "IKE NAT-T"},
    {"port": 9093, "protocol": "tls", "label": "Kafka"},
    {"port": 8883, "protocol": "tls", "label": "MQTT"},
]
PORT_PROTOCOLS = ("tls", "starttls-ldap", "starttls-smtp", "starttls-imap", "starttls-postgres", "starttls-mysql",
                  # CB-34: not in DEFAULT_PORTS.  FTP (21) answers AUTH TLS on most hosts but is a port a team adds on
                  # purpose; XMPP (5222 client, 5269 server-to-server) needs the server's XMPP domain, which the node
                  # takes from the team's SNI names for the address (an address alone gets host-unknown from most
                  # servers, reported as an error, never as "plaintext only")
                  "starttls-pop3", "starttls-ftp", "starttls-xmpp", "starttls-xmpp-server",
                  "tds", "ssh", "rdp", "ike",
                  # OT (not in DEFAULT_PORTS: a team adds them for its OT ranges; an address with one open is scanned
                  # in fragile mode by the node)
                  "opcua", "modbus", "modbus-tls")
MAX_PORTS = 64
MAX_SNI = 10_000
MAX_EXCLUSIONS = 500
MAX_DOMAINS = 200
_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I


def default_window() -> list[list[bool]]:
    """Weekdays 22:00 to 05:00: Mon-Fri evenings and the early hours of Tue-Sat (Monday is row 0)."""
    grid = [[False] * 24 for _ in range(7)]
    for day in range(5):
        grid[day][22] = grid[day][23] = True
        for hour in range(5):
            grid[day + 1][hour] = True
    return grid


def new_external_id() -> str:
    groups = ["".join(secrets.choice(_ALPHABET) for _ in range(4)) for _ in range(4)]
    return "zs-ext-" + "-".join(groups)


# CB-15: a team that starts using CBOM Sources requires signed scan nodes (every node since 1.1 signs its requests).
# A team that already has unsigned (legacy) nodes when its settings row is first made keeps them working instead
# (the toggle on Scan nodes turns the requirement on once they are upgraded). An operator can turn the default off
# for every new team (an on-prem estate of 1.0 nodes) with CBOM_NEW_TEAMS_REQUIRE_SIGNED_NODES=0.
NEW_TEAMS_REQUIRE_SIGNED_ENV = "CBOM_NEW_TEAMS_REQUIRE_SIGNED_NODES"


def new_team_requires_signed_nodes(session: Session, team_id: int) -> bool:
    """The ``require_signed_nodes`` a team's first settings row gets: True unless the operator turned the default off,
    or the team already has an enrolled scan node that does not sign (it would be refused at once)."""
    import os

    from backend.new_models import CbomScanNode

    if os.environ.get(NEW_TEAMS_REQUIRE_SIGNED_ENV, "1").strip().lower() in ("0", "false", "no", "off"):
        return False
    legacy = session.exec(select(CbomScanNode.id).where(
        CbomScanNode.team_id == team_id, CbomScanNode.enrolled_at.is_not(None),  # type: ignore[union-attr]
        CbomScanNode.signing_public_key.is_(None)).limit(1)).first()  # type: ignore[union-attr]
    return legacy is None


def get_or_create_settings(session: Session, team_id: int, *, commit: bool = True) -> CbomCollectionSettings:
    """The team's settings row, created on first use with ``INSERT ... ON CONFLICT (team_id) DO NOTHING``: never a
    rollback of the caller's work (security review S-9: a heartbeat that had just released a job lost the release
    when a concurrent request created the row first and this rolled back); a concurrent creator's row is read
    instead.  ``commit`` True (UI and API reads, so the AWS external id they show is stored at once); False (the
    scan-node paths): the row is committed with the caller's own commit, nothing else is committed early."""
    query = select(CbomCollectionSettings).where(CbomCollectionSettings.team_id == team_id)
    row = session.exec(query).first()
    if row is not None:
        return row
    fresh = CbomCollectionSettings(team_id=team_id, aws_external_id=new_external_id(), ports=list(DEFAULT_PORTS),
                                   scan_window=default_window(),
                                   require_signed_nodes=new_team_requires_signed_nodes(session, team_id))
    table = CbomCollectionSettings.__table__
    values = {c.name: getattr(fresh, c.name) for c in table.columns if c.name != "id"}
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        from sqlalchemy.dialects.postgresql import insert as dialect_insert
    else:
        from sqlalchemy.dialects.sqlite import insert as dialect_insert
    session.exec(dialect_insert(table).values(values)  # type: ignore[call-overload]
                 .on_conflict_do_nothing(index_elements=["team_id"]))
    if commit:
        session.commit()
    return session.exec(query.execution_options(populate_existing=True)).one()


def ensure_evidence_areas(session: Session, team_id: int) -> list[CbomEvidenceArea]:
    existing = session.exec(select(CbomEvidenceArea).where(CbomEvidenceArea.team_id == team_id)).all()
    have = {row.area_key for row in existing}
    missing = [key for key in AREAS if key not in have]
    if missing:
        for key in missing:
            session.add(CbomEvidenceArea(team_id=team_id, area_key=key))
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
        existing = session.exec(select(CbomEvidenceArea).where(CbomEvidenceArea.team_id == team_id)).all()
    order = list(AREAS)
    return sorted(existing, key=lambda row: order.index(row.area_key) if row.area_key in order else 99)


def team_exclusions(settings: CbomCollectionSettings) -> T.ParsedTargets:
    cidrs = [item.get("cidr", "") for item in (settings.network_exclusions or []) if isinstance(item, dict)]
    return T.parse_exclusions(cidrs)


def _grid(grid: list[list[bool]] | None) -> list[list[bool]] | None:
    if not grid or len(grid) != 7 or any(len(row) != 24 for row in grid):
        return None
    return grid


def window_allows(grid: list[list[bool]] | None, tz_name: str, now_utc: _dt.datetime) -> bool:
    grid = _grid(grid)
    if grid is None:
        return True
    local = now_utc.replace(tzinfo=_dt.timezone.utc).astimezone(zoneinfo.ZoneInfo(tz_name))
    return bool(grid[local.weekday()][local.hour])


def next_window_start(grid: list[list[bool]] | None, tz_name: str, now_utc: _dt.datetime) -> _dt.datetime | None:
    """Naive UTC start of the next allowed hour (``now`` when inside a window), or None if never."""
    grid = _grid(grid)
    if grid is None:
        return now_utc
    zone = zoneinfo.ZoneInfo(tz_name)
    local = now_utc.replace(tzinfo=_dt.timezone.utc).astimezone(zone)
    if grid[local.weekday()][local.hour]:
        return now_utc
    probe = local.replace(minute=0, second=0, microsecond=0)
    for _ in range(24 * 7 + 1):
        probe = (probe + _dt.timedelta(hours=1)).astimezone(zone)
        if grid[probe.weekday()][probe.hour]:
            return probe.astimezone(_dt.timezone.utc).replace(tzinfo=None)
    return None


def window_end(grid: list[list[bool]] | None, tz_name: str, now_utc: _dt.datetime) -> _dt.datetime | None:
    """Naive UTC end of the allowed window that contains ``now`` (None when there is no window limit
    or when every hour is allowed).  Callers only ask while ``window_allows`` is true."""
    grid = _grid(grid)
    if grid is None:
        return None
    zone = zoneinfo.ZoneInfo(tz_name)
    local = now_utc.replace(tzinfo=_dt.timezone.utc).astimezone(zone)
    probe = local.replace(minute=0, second=0, microsecond=0)
    for _ in range(24 * 7 + 1):
        probe = (probe + _dt.timedelta(hours=1)).astimezone(zone)
        if not grid[probe.weekday()][probe.hour]:
            return probe.astimezone(_dt.timezone.utc).replace(tzinfo=None)
    return None
